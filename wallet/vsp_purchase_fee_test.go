// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"maps"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/blockchain/stake"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/gcs/blockcf2"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
)

// TestVSPPurchaseTicketsFeeInputs checks, through PurchaseTickets, the inputs
// a purchase of two tickets reserves for their VSP fees once each fee is
// processed.  When Process fails, before or after the fee tx has outputs, or
// the VSP already holds a fee tx for the ticket, they are unlocked and
// unspent.  When Process pays with them, the fee txs spend them.  When it
// pays a fee tx a scheduled attempt made from other outputs, they are
// unlocked and unspent.  When the purchase stops after the first ticket's
// fee, because the second ticket fails to publish or the request is
// cancelled, the second ticket's inputs are unlocked too, and the error
// keeps the first ticket's fee error.
func TestVSPPurchaseTicketsFeeInputs(t *testing.T) {
	const (
		count  = 2
		output = 3e6 // a fee needs two of these
		quote  = 4e6
	)
	vspFeeHash := chainhash.Hash{0xfe}
	for _, tc := range []struct {
		name string
		// feeAddrErr is the VSP's error answer to a fee address request;
		// 0 quotes the fee.
		feeAddrErr types.ErrorCode
		// lock locks the wallet at the first fee address request, so the
		// fee tx gets outputs but no signatures.
		lock bool
		// attempt: at each ticket's first fee address request, a
		// scheduled attempt makes the job's fee tx from another output.
		attempt   bool
		wantSpent bool
		// feeFails: the fee is not paid, which the purchase may report as
		// an error alongside the tickets it published.
		feeFails bool
		// tickets is the number asked for; 0 asks for count.
		tickets int
		// heldLock: at the second ticket's publish, a concurrent purchase
		// locks the first ticket's fee inputs, which the fee step already
		// released; they must stay locked.
		heldLock bool
		// lockAtPublish locks the wallet once the first ticket is
		// published, so its fee address request cannot be signed.
		lockAtPublish bool
		// stop ends the purchase after the first ticket's fee: "publish"
		// fails the second ticket's publish, "cancel" cancels the request
		// at the first fee address request.
		stop string
	}{
		{name: "Process fails", feeAddrErr: types.ErrInternalError, feeFails: true},
		{name: "fee tx not signed", lock: true, feeFails: true},
		{name: "VSP holds the fee", feeAddrErr: types.ErrFeeAlreadyReceived},
		{name: "fee paid", wantSpent: true},
		{name: "scheduled attempt's fee tx paid", attempt: true},
		{name: "second ticket not published", feeAddrErr: types.ErrInternalError, feeFails: true, stop: "publish",
			tickets: 3, heldLock: true},
		{name: "second ticket not published, no fee errors", feeAddrErr: types.ErrFeeAlreadyReceived, stop: "publish"},
		{name: "purchase cancelled", feeAddrErr: types.ErrInternalError, feeFails: true, stop: "cancel"},
		// The first fee fails with errors.Locked, which must not become
		// the stopped purchase's kind.
		{name: "second ticket not published, wallet locked", lockAtPublish: true, feeFails: true, stop: "publish"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var (
				mu         sync.Mutex
				c          *VSPClient
				feeAddr    Address
				attemptOps []wire.OutPoint                 // inputs of the scheduled attempts
				seen       = make(map[chainhash.Hash]bool) // tickets asked a fee address
				reserved   map[outpoint]struct{}           // locked at the first fee address request
				held       map[outpoint]struct{}           // locked by the concurrent purchase
				paid       []*wire.MsgTx
			)
			// snapshot records the locked fee inputs; the caller holds mu.
			snapshot := func() {
				w := c.wallet
				w.lockedOutpointMu.Lock()
				reserved = maps.Clone(w.lockedOutpoints)
				w.lockedOutpointMu.Unlock()
				for _, op := range attemptOps {
					delete(reserved, outpoint{op.Hash, op.Index})
				}
			}
			feeAddress := func(body []byte) (int, any) {
				if reserved == nil {
					snapshot()
					w := c.wallet
					if tc.lock {
						w.Lock()
					}
					if tc.stop == "cancel" {
						cancel()
					}
				}
				var req types.FeeAddressRequest
				if err := json.Unmarshal(body, &req); err != nil {
					return apiError(types.ErrBadRequest)
				}
				ticketHash, err := chainhash.NewHashFromStr(req.TicketHash)
				if err != nil {
					return apiError(types.ErrBadRequest)
				}
				if !seen[*ticketHash] {
					seen[*ticketHash] = true
					c.mu.Lock()
					fp := c.jobs[*ticketHash]
					c.mu.Unlock()
					// Stop the reconcile the job scheduled 0 to 2 minutes
					// out, which would race the purchase's fee step.
					fp.stop()
					if tc.attempt {
						tx := wire.NewMsgTx()
						op := attemptOps[len(seen)-1]
						tx.AddTxIn(wire.NewTxIn(&op, 1e7, nil))
						err := c.wallet.CreateVspPayment(ctx, tx, quote, feeAddr, 0, 0)
						if err != nil {
							return apiError(types.ErrInternalError)
						}
						fp.mu.Lock()
						fp.feeTx, fp.feeHash = tx, tx.TxHash()
						fp.mu.Unlock()
					}
				}
				if tc.feeAddrErr != 0 {
					return apiError(tc.feeAddrErr)
				}
				return http.StatusOK, types.FeeAddressResponse{
					Timestamp:  time.Now().Unix(),
					FeeAddress: feeAddr.String(),
					FeeAmount:  quote,
					Expiration: time.Now().Add(time.Hour).Unix(),
					Request:    body,
				}
			}
			vsp := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				mu.Lock()
				defer mu.Unlock()
				switch path {
				case "/api/v3/vspinfo":
					// A fee estimate of about 0.048 VAR.
					return http.StatusOK, types.VspInfoResponse{FeePercentage: 50}
				case "/api/v3/feeaddress":
					return feeAddress(body)
				case "/api/v3/payfee":
					var req types.PayFeeRequest
					if err := json.Unmarshal(body, &req); err != nil {
						return apiError(types.ErrBadRequest)
					}
					raw, err := hex.DecodeString(req.FeeTx)
					if err != nil {
						return apiError(types.ErrBadRequest)
					}
					tx := new(wire.MsgTx)
					if err := tx.FromBytes(raw); err != nil {
						return apiError(types.ErrBadRequest)
					}
					paid = append(paid, tx)
					return http.StatusOK, types.PayFeeResponse{Request: body}
				case "/api/v3/ticketstatus":
					return http.StatusOK, types.TicketStatusResponse{
						FeeTxStatus: "received",
						FeeTxHash:   vspFeeHash.String(),
						Request:     body,
					}
				}
				return apiError(types.ErrInternalError)
			})
			w := vsp.wallet
			w.SetNetworkBackend(mockNetwork{})
			addr, err := w.NewExternalAddress(ctx, 0)
			if err != nil {
				t.Fatal(err)
			}

			// From StakeValidationHeight the wallet's fee estimate is above
			// 0, so the purchase reserves inputs for the fee.  The last
			// block funds the wallet with 24 outputs for the purchase and
			// one locked output for each scheduled attempt.
			fundAddr, err := w.NewInternalAddress(ctx, 0)
			if err != nil {
				t.Fatal(err)
			}
			ver, script := fundAddr.(Address).PaymentScript()
			fund := wire.NewMsgTx()
			fund.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{1}}, 1e8, nil))
			for range count {
				fund.AddTxOut(&wire.TxOut{Value: 1e7, Version: ver, PkScript: script})
			}
			for range 24 {
				fund.AddTxOut(&wire.TxOut{Value: output, Version: ver, PkScript: script})
			}
			var ops []wire.OutPoint
			for i := range count {
				op := wire.OutPoint{Hash: fund.TxHash(), Index: uint32(i)}
				w.LockOutpoint(&op.Hash, op.Index)
				ops = append(ops, op)
			}
			params := basicWalletConfig.Params
			tip := params.GenesisBlock.Header
			var forest SidechainForest
			var chain []*BlockNode
			for int64(tip.Height) < params.StakeValidationHeight {
				header := wire.BlockHeader{
					PrevBlock: tip.BlockHash(),
					Height:    tip.Height + 1,
					Bits:      params.PowLimitBits,
					SBits:     1e7,
					VoteBits:  1, // approve the parent, or its outputs are invalidated
				}
				filter, err := blockcf2.Regular(&wire.MsgBlock{Header: header}, nil)
				if err != nil {
					t.Fatal(err)
				}
				hash := header.BlockHash()
				chain = append(chain, NewBlockNode(&header, &hash, filter))
				tip = header
			}
			_, err = w.ChainSwitch(ctx, &forest, chain,
				map[chainhash.Hash][]*wire.MsgTx{tip.BlockHash(): {fund}})
			if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			c, feeAddr, attemptOps = vsp, addr.(Address), ops
			mu.Unlock()

			var n NetworkBackend = mockNetwork{}
			if tc.stop == "publish" {
				f := ticketPublishFails{failAt: 2, n: new(atomic.Int32)}
				if tc.lockAtPublish {
					f.first = func() {
						mu.Lock()
						snapshot()
						mu.Unlock()
						w.Lock()
					}
				}
				if tc.heldLock {
					f.second = func() {
						mu.Lock()
						defer mu.Unlock()
						held = make(map[outpoint]struct{})
						for op := range reserved {
							if !w.LockedOutpoint(&op.hash, op.index) {
								w.LockOutpoint(&op.hash, op.index)
								held[op] = struct{}{}
							}
						}
					}
				}
				n = f
			}
			buy := count
			if tc.tickets != 0 {
				buy = tc.tickets
			}
			resp, err := w.PurchaseTickets(ctx, n, &PurchaseTicketsRequest{
				Count:     buy,
				VSPClient: vsp,
			})
			if (err != nil && !tc.feeFails && tc.stop == "") || resp == nil {
				t.Fatal(err)
			}
			if tc.stop != "" {
				stopErr := errTicketPublish
				if tc.stop == "cancel" {
					stopErr = context.Canceled
				}
				switch {
				case !tc.feeFails:
					// Without fee errors, the error is as on main.
					if want := "wallet.PurchaseTickets: " + stopErr.Error(); err == nil || err.Error() != want {
						t.Errorf("PurchaseTickets: %v; want %q", err, want)
					}
				case !errors.Is(err, stopErr) ||
					!strings.Contains(err.Error(), resp.TicketHashes[0].String()):
					t.Errorf("PurchaseTickets: %v; want %v and the first ticket's fee error",
						err, stopErr)
				}
				// RPC handlers report every ticket as bought on
				// ErrVSPFeeNotPaid; the second was not published.
				if errors.Is(err, ErrVSPFeeNotPaid) {
					t.Errorf("PurchaseTickets: %v; want no ErrVSPFeeNotPaid", err)
				}
				// The stop errors here have no kind.
				var kind errors.Kind
				if errors.As(err, &kind) {
					t.Errorf("PurchaseTickets: %v; kind %v, want none", err, kind)
				}
				mu.Lock()
				feeSteps := len(seen)
				mu.Unlock()
				if feeSteps > 1 {
					t.Errorf("%d tickets asked for a fee address, want at most the first", feeSteps)
				}
			}
			// A stopped purchase reports only the first ticket, the one
			// it published.
			want := buy
			if tc.stop != "" {
				want = 1
			}
			if len(resp.Tickets) != want {
				t.Fatalf("%d tickets, want %d", len(resp.Tickets), want)
			}

			mu.Lock()
			defer mu.Unlock()
			if len(reserved) < buy {
				t.Fatalf("%d inputs reserved for %d fees", len(reserved), buy)
			}
			if tc.heldLock && len(held) == 0 {
				t.Fatal("no fee inputs released before the second ticket's publish")
			}
			for op := range held {
				if !w.LockedOutpoint(&op.hash, op.index) {
					t.Errorf("input %v:%d locked by another purchase was unlocked", op.hash, op.index)
				}
				delete(reserved, op)
			}
			unspent := testUnspentOutputs(ctx, t, w)
			for op := range reserved {
				if w.LockedOutpoint(&op.hash, op.index) {
					t.Errorf("reserved input %v:%d stays locked", op.hash, op.index)
				}
				if u := unspent[wire.OutPoint{Hash: op.hash, Index: op.index}]; u == tc.wantSpent {
					t.Errorf("reserved input %v:%d unspent = %v, want %v",
						op.hash, op.index, u, !tc.wantSpent)
				}
			}
			spends := make(map[outpoint]struct{})
			for _, tx := range paid {
				for _, in := range tx.TxIn {
					op := in.PreviousOutPoint
					spends[outpoint{op.Hash, op.Index}] = struct{}{}
				}
			}
			switch {
			case tc.wantSpent:
				// A fee tx may also spend another output to top up.
				for op := range reserved {
					if _, ok := spends[op]; !ok {
						t.Errorf("fee txs spend %v, not reserved input %v:%d",
							spends, op.hash, op.index)
					}
				}
			case tc.attempt:
				for _, op := range attemptOps {
					if _, ok := spends[outpoint{op.Hash, op.Index}]; !ok {
						t.Errorf("fee txs spend %v, not the attempt's input %v", spends, op)
					}
				}
			case len(paid) != 0:
				t.Errorf("%d fee txs paid, want none", len(paid))
			}
		})
	}
}

var errTicketPublish = errors.New("ticket publish failed")

// ticketPublishFails fails the publish of the failAt-th ticket, counted
// from 1, and publishes every other tx.  first and second, if set, run when
// the first and second ticket are published.
type ticketPublishFails struct {
	mockNetwork
	n             *atomic.Int32
	failAt        int32
	first, second func()
}

func (f ticketPublishFails) PublishTransactions(_ context.Context, txs ...*wire.MsgTx) error {
	for _, tx := range txs {
		if !stake.IsSStx(tx) {
			continue
		}
		i := f.n.Add(1)
		if i == 1 && f.first != nil {
			f.first()
		}
		if i == 2 && f.second != nil {
			f.second()
		}
		if i == f.failAt {
			return errTicketPublish
		}
	}
	return nil
}
