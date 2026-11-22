// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/decred/slog"
	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/gcs/blockcf2"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// vspLogLines collects what a logger writes.
type vspLogLines struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *vspLogLines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *vspLogLines) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// mineEmpty connects n empty blocks on top of the fixture's tip in one chain
// switch.
func (f *vspPaymentFixture) mineEmpty(ctx context.Context, t *testing.T, n int) {
	t.Helper()
	var nodes []*BlockNode
	for range n {
		header := wire.BlockHeader{
			PrevBlock: f.tip.BlockHash(),
			Height:    f.tip.Height + 1,
			Bits:      f.cfg.Params.PowLimitBits,
			SBits:     f.sbits,
			VoteBits:  1,
		}
		filter, err := blockcf2.Regular(&wire.MsgBlock{Header: header}, nil)
		if err != nil {
			t.Fatal(err)
		}
		hash := header.BlockHash()
		nodes = append(nodes, NewBlockNode(&header, &hash, filter))
		f.tip = header
	}
	if _, err := f.w.ChainSwitch(ctx, &f.forest, nodes, nil); err != nil {
		t.Fatal(err)
	}
}

// testJob returns the client's job for ticket.
func testJob(c *VSPClient, ticket *VSPTicket) *vspFeePayment {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.jobs[*ticket.Hash()]
}

// testHoldsUnmined reports whether the wallet holds hash as an unmined tx.
func testHoldsUnmined(ctx context.Context, t *testing.T, w *Wallet, hash chainhash.Hash) bool {
	t.Helper()
	var held bool
	err := walletdb.View(ctx, w.db, func(dbtx walletdb.ReadTx) error {
		recs, err := w.txStore.UnminedTxs(dbtx)
		for _, rec := range recs {
			held = held || rec.Hash == hash
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return held
}

// testFeeAddressReply is the fake VSP's fee quote for ticket.
func testFeeAddressReply(ticket *VSPTicket, body []byte) (int, any) {
	return http.StatusOK, types.FeeAddressResponse{
		Timestamp:  time.Now().Unix(),
		FeeAddress: ticket.votingAddr.String(),
		FeeAmount:  1e7,
		Expiration: time.Now().Add(time.Hour).Unix(),
		Request:    body,
	}
}

// testPaidFee returns the hash of the fee tx a payfee request carries.
func testPaidFee(body []byte) (chainhash.Hash, bool) {
	var req types.PayFeeRequest
	if json.Unmarshal(body, &req) != nil {
		return chainhash.Hash{}, false
	}
	raw, err := hex.DecodeString(req.FeeTx)
	tx := new(wire.MsgTx)
	if err != nil || tx.FromBytes(raw) != nil {
		return chainhash.Hash{}, false
	}
	return tx.TxHash(), true
}

// TestVSPPrunedTicketAbandonsFeeTx checks the fee tx of a ticket that leaves
// the wallet unmined.  The job's next attempt abandons it if it is unpublished,
// so its input is spendable again, however it is funded: by a separate output,
// by the split's fee output, or by the job from the wallet's outputs.  So is
// the job's own fee tx it still holds after a failed write of the VSP's, and
// its fee tx the VSP holds, which is abandoned once and not again.  A
// published fee tx is kept, and so is one another ticket's record names, and
// the fee tx of a ticket still in the wallet, expired or spent: only a ticket
// gone unmined is handled here.  The attempts that check the ticket first
// abandon it: a scheduled reconcile or confirm, and Process.  The ticket's
// VSP record stays.
func TestVSPPrunedTicketAbandonsFeeTx(t *testing.T) {
	for _, tc := range []struct {
		name    string
		funding string // "separate", "split" or "job"
		// ownKept leaves the job's fee tx in ownFeeHash: the VSP holds
		// another, and recording that one's hash failed.
		ownKept     bool
		vspNamesOwn bool // the VSP holds the job's fee tx
		published   bool
		otherTicket bool   // another ticket's record names the fee tx
		ticket      string // "pruned" (default), "kept", "expired" or "spent"
		// attempt is the job's next attempt: "reconcile" (default),
		// "confirm", or "process", a Process call while the record
		// reads started.
		attempt     string
		wantUnspent bool
		// wantSkips counts the hashes abandonFeeTx declines: one the
		// wallet does not hold, or one it published.
		wantSkips int
	}{
		{name: "separate output", funding: "separate", wantUnspent: true},
		{name: "separate output, confirm attempt", funding: "separate", attempt: "confirm", wantUnspent: true},
		{name: "separate output, Process", funding: "separate", attempt: "process", wantUnspent: true},
		{name: "split's fee output", funding: "split", wantUnspent: true},
		{name: "made by the job", funding: "job", wantUnspent: true},
		{name: "job's own fee tx after a failed write", funding: "separate", ownKept: true, wantUnspent: true,
			wantSkips: 1},
		{name: "VSP holds the job's fee tx", funding: "separate", ownKept: true, vspNamesOwn: true,
			wantUnspent: true},
		{name: "fee tx published", funding: "separate", published: true, wantSkips: 1},
		{name: "another ticket names the fee tx", funding: "separate", otherTicket: true, wantSkips: 1},
		{name: "ticket still in the wallet", funding: "separate", ticket: "kept"},
		{name: "ticket expired", funding: "separate", ticket: "expired"},
		{name: "ticket spent", funding: "separate", ticket: "spent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var ticket *VSPTicket
			vspHash := chainhash.Hash{0xfe}
			c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				// failVSPWrites lengthens the URL's path.
				switch path[strings.Index(path, "/api/v3/"):] {
				case "/api/v3/feeaddress":
					if tc.ownKept {
						return apiError(types.ErrFeeAlreadyReceived)
					}
					return testFeeAddressReply(ticket, body)
				case "/api/v3/payfee":
					return http.StatusOK, types.PayFeeResponse{Request: body}
				case "/api/v3/ticketstatus":
					return http.StatusOK, types.TicketStatusResponse{
						FeeTxStatus: "received",
						FeeTxHash:   vspHash.String(),
						Request:     body,
					}
				}
				return apiError(types.ErrInternalError)
			})
			w := c.wallet
			skips := &vspLogLines{}
			c.log = slog.NewBackend(skips).Logger("VSP")

			// op is the output the fee tx spends.
			var op *wire.OutPoint
			if tc.funding == "split" {
				addr, err := w.NewInternalAddress(ctx, 0)
				if err != nil {
					t.Fatal(err)
				}
				ver, script := addr.(Address).PaymentScript()
				split := wire.NewMsgTx()
				split.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{0x02}}, 2e8, nil))
				split.AddTxOut(&wire.TxOut{Value: 1e8, Version: ver, PkScript: script})
				split.AddTxOut(&wire.TxOut{Value: 1e8, Version: ver, PkScript: script})
				if err := w.AddTransaction(ctx, split, nil); err != nil {
					t.Fatal(err)
				}
				splitHash := split.TxHash()
				ticket = testVSPTicketSpending(ctx, t, c, wire.OutPoint{Hash: splitHash})
				op = &wire.OutPoint{Hash: splitHash, Index: 1}
			} else if tc.funding == "job" {
				// Coin selection takes only mined outputs.
				f := &vspPaymentFixture{w: w, cfg: basicWalletConfig,
					tip: basicWalletConfig.Params.GenesisBlock.Header}
				op = &wire.OutPoint{Hash: f.fund(ctx, t, true, 1e8).TxHash()}
				ticket = testVSPTicket(ctx, t, c, 1)
			} else {
				op = testWalletOutput(ctx, t, w, 2)
				ticket = testVSPTicket(ctx, t, c, 1)
			}
			before := testSpendable(ctx, t, w)

			var fp *vspFeePayment
			var feeHash chainhash.Hash
			switch {
			case tc.funding == "job":
				// The job funds the fee tx from op, the only output.
				if err := c.Process(ctx, ticket, nil); err != nil {
					t.Fatal(err)
				}
				fp = testJob(c, ticket)
				fp.stop()
				feeHash = fp.feeHash
			default:
				fee := wire.NewMsgTx()
				fee.AddTxIn(wire.NewTxIn(op, 1e8, nil))
				if err := w.CreateVspPayment(ctx, fee, 1e7, ticket.votingAddr, 0, 0); err != nil {
					t.Fatal(err)
				}
				feeHash = fee.TxHash()
				// Process takes a paid record under another URL for
				// another VSP's.
				record := ticket.UpdateFeePaid
				if tc.ownKept || tc.attempt == "process" {
					record = ticket.UpdateFeeStarted
				}
				if err := record(ctx, feeHash, c.URL, c.PubKey); err != nil {
					t.Fatal(err)
				}
				if tc.vspNamesOwn {
					vspHash = feeHash
					if err := c.Process(ctx, ticket, nil); err != nil {
						t.Fatal(err)
					}
					fp = testJob(c, ticket)
				} else if tc.ownKept {
					// The VSP names another fee tx, which the wallet
					// cannot record.
					url := c.URL
					failVSPWrites(c)
					if err := c.Process(ctx, ticket, nil); err == nil {
						t.Fatal("Process: want the failed write's error")
					}
					c.URL = url
					fp = testJob(c, ticket)
				} else {
					// The job a restart makes from the record.
					fp = c.feePayment(ctx, ticket, true)
				}
				fp.stop()
			}
			if !testHoldsUnmined(ctx, t, w, feeHash) {
				t.Fatal("no fee tx")
			}
			if tc.published {
				if err := w.SetPublished(ctx, &feeHash, true); err != nil {
					t.Fatal(err)
				}
			}
			if tc.otherTicket {
				other := testVSPTicket(ctx, t, c, 3)
				if err := other.UpdateFeeStarted(ctx, feeHash, c.URL, c.PubKey); err != nil {
					t.Fatal(err)
				}
			}

			switch tc.ticket {
			case "", "pruned":
				if err := w.AbandonTransaction(ctx, ticket.Hash()); err != nil {
					t.Fatal(err)
				}
			case "expired":
				f := &vspPaymentFixture{w: w, cfg: basicWalletConfig,
					tip: basicWalletConfig.Params.GenesisBlock.Header}
				// A ticket mined below height 2 counts as unmined.
				f.mineEmpty(ctx, t, 1)
				f.mine(ctx, t, ticket.rawTx)
				p := w.chainParams
				f.mineEmpty(ctx, t, int(p.TicketMaturity)+int(p.TicketExpiry)+1)
				if !ticket.Expired(ctx) || ticket.Pruned(ctx) {
					t.Fatal("the ticket is not expired")
				}
			case "spent":
				// Mined, then spent by an unmined tx.
				f := &vspPaymentFixture{w: w, cfg: basicWalletConfig,
					tip: basicWalletConfig.Params.GenesisBlock.Header}
				f.mine(ctx, t, ticket.rawTx)
				spender := wire.NewMsgTx()
				spender.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: *ticket.Hash(), Tree: wire.TxTreeStake}, 1e8, nil))
				spender.AddTxOut(&wire.TxOut{Value: 1e8, PkScript: []byte{0x51}})
				err := walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
					rec, err := udb.NewTxRecordFromMsgTx(spender, time.Now())
					if err != nil {
						return err
					}
					return w.txStore.InsertMemPoolTx(dbtx, rec)
				})
				if err != nil {
					t.Fatal(err)
				}
			}

			// The job's next attempt.
			skipsBefore := strings.Count(skips.String(), "not abandoning")
			var err error
			if tc.attempt == "process" {
				err = c.Process(ctx, ticket, nil)
			} else {
				next := fp.reconcilePayment
				if tc.attempt == "confirm" {
					next = fp.confirmPayment
				}
				fp.procMu.Lock()
				err = next()
				fp.procMu.Unlock()
			}
			fp.stop()
			if stopped := tc.ticket != "kept"; stopped != errors.Is(err, errStopped) {
				t.Fatalf("attempt: %v; want errStopped %v", err, stopped)
			}

			if n := strings.Count(skips.String(), "not abandoning") - skipsBefore; n != tc.wantSkips {
				t.Errorf("%d fee txs not abandoned, want %d:\n%s", n, tc.wantSkips, skips)
			}
			if unspent := testUnspentOutputs(ctx, t, w)[*op]; unspent != tc.wantUnspent {
				t.Fatalf("fee tx input unspent = %v, want %v", unspent, tc.wantUnspent)
			}
			if held := testHoldsUnmined(ctx, t, w, feeHash); held == tc.wantUnspent {
				t.Fatalf("wallet holds the fee tx = %v, want %v", held, !tc.wantUnspent)
			}
			// The split's ticket output comes back too.
			if after := testSpendable(ctx, t, w); tc.wantUnspent && tc.funding != "split" && after != before {
				t.Fatalf("spendable balance %v after the abandon, want %v as before the fee tx", after, before)
			}
			if _, err := ticket.VSPTicketInfo(ctx); err != nil {
				t.Fatalf("the ticket's VSP record: %v", err)
			}
		})
	}
}

// TestVSPTicketPrunedMidAttemptAbandonsFeeTx checks a ticket pruned while an
// attempt waits for the VSP's fee quote: the attempt makes the fee tx, and
// submitPayment's check abandons it before paying, through Process and
// through a scheduled reconcile.
func TestVSPTicketPrunedMidAttemptAbandonsFeeTx(t *testing.T) {
	for _, via := range []string{"Process", "reconcile"} {
		t.Run(via, func(t *testing.T) {
			ctx := context.Background()
			var ticket *VSPTicket
			var c *VSPClient
			var payfee atomic.Bool
			c = testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				switch path {
				case "/api/v3/feeaddress":
					if err := c.wallet.AbandonTransaction(ctx, ticket.Hash()); err != nil {
						t.Error(err)
					}
					return testFeeAddressReply(ticket, body)
				case "/api/v3/payfee":
					payfee.Store(true)
					return http.StatusOK, types.PayFeeResponse{Request: body}
				}
				return apiError(types.ErrInternalError)
			})
			w := c.wallet
			// Coin selection takes only mined outputs.
			f := &vspPaymentFixture{w: w, cfg: basicWalletConfig,
				tip: basicWalletConfig.Params.GenesisBlock.Header}
			op := wire.OutPoint{Hash: f.fund(ctx, t, true, 1e8).TxHash()}
			ticket = testVSPTicket(ctx, t, c, 1)

			var err error
			if via == "Process" {
				err = c.Process(ctx, ticket, nil)
			} else {
				fp := c.feePayment(ctx, ticket, false)
				fp.stop()
				fp.procMu.Lock()
				err = fp.reconcilePayment()
				fp.procMu.Unlock()
			}
			if !errors.Is(err, errStopped) {
				t.Fatalf("attempt: %v; want errStopped", err)
			}
			if fp := testJob(c, ticket); fp != nil {
				t.Fatal("the job is still listed")
			}
			info, err := ticket.VSPTicketInfo(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if payfee.Load() || testHoldsUnmined(ctx, t, w, info.FeeHash) || !testUnspentOutputs(ctx, t, w)[op] {
				t.Fatalf("paid %v; wallet holds the fee tx %v; want neither, and its input unspent",
					payfee.Load(), testHoldsUnmined(ctx, t, w, info.FeeHash))
			}
		})
	}
}

// TestVSPPrunedTicketResumesPayment checks that once a pruned ticket is mined
// after all, a Process call and the attempt it schedules resume its payment
// after the abandon: they record a fee the VSP holds and leave it to the VSP,
// and make a new fee tx when the VSP's fee errored or it never got the fee,
// even with the record paid.
func TestVSPPrunedTicketResumesPayment(t *testing.T) {
	for _, tc := range []struct {
		name      string
		paid      bool   // the record says paid, not started
		vspStatus string // the VSP's FeeTxStatus
		wantNew   bool   // a new fee tx is made and paid
	}{
		{name: "VSP holds the fee", paid: true, vspStatus: "received"},
		{name: "VSP's fee errored", paid: true, vspStatus: "error", wantNew: true},
		// makeFeeTx records the fee paid before payfee.
		{name: "payfee never reached the VSP", paid: true, vspStatus: "none", wantNew: true},
		{name: "fee never paid", vspStatus: "none", wantNew: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var ticket *VSPTicket
			var ownHash chainhash.Hash
			var paid atomic.Value // chainhash.Hash
			c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				switch path {
				case "/api/v3/feeaddress":
					if tc.vspStatus == "received" {
						return apiError(types.ErrFeeAlreadyReceived)
					}
					return testFeeAddressReply(ticket, body)
				case "/api/v3/payfee":
					hash, ok := testPaidFee(body)
					if !ok {
						return apiError(types.ErrBadRequest)
					}
					paid.Store(hash)
					return http.StatusOK, types.PayFeeResponse{Request: body}
				case "/api/v3/ticketstatus":
					return http.StatusOK, types.TicketStatusResponse{
						FeeTxStatus: tc.vspStatus,
						FeeTxHash:   ownHash.String(),
						Request:     body,
					}
				}
				return apiError(types.ErrInternalError)
			})
			w := c.wallet
			// Coin selection for the new fee tx takes only mined outputs.
			f := &vspPaymentFixture{w: w, cfg: basicWalletConfig,
				tip: basicWalletConfig.Params.GenesisBlock.Header}
			op := &wire.OutPoint{Hash: f.fund(ctx, t, true, 1e8).TxHash()}
			ticket = testVSPTicket(ctx, t, c, 1)
			fee := wire.NewMsgTx()
			fee.AddTxIn(wire.NewTxIn(op, 1e8, nil))
			if err := w.CreateVspPayment(ctx, fee, 1e7, ticket.votingAddr, 0, 0); err != nil {
				t.Fatal(err)
			}
			ownHash = fee.TxHash()
			record := ticket.UpdateFeeStarted
			if tc.paid {
				record = ticket.UpdateFeePaid
			}
			if err := record(ctx, ownHash, c.URL, c.PubKey); err != nil {
				t.Fatal(err)
			}

			// Pruned, and the job's attempt abandons the fee tx.
			fp := c.feePayment(ctx, ticket, tc.paid)
			fp.stop()
			if err := w.AbandonTransaction(ctx, ticket.Hash()); err != nil {
				t.Fatal(err)
			}
			fp.procMu.Lock()
			err := fp.reconcilePayment()
			fp.procMu.Unlock()
			if !errors.Is(err, errStopped) || testHoldsUnmined(ctx, t, w, ownHash) {
				t.Fatalf("reconcilePayment: %v; the fee tx is not abandoned", err)
			}

			// The ticket is mined after all.
			f.mine(ctx, t, ticket.rawTx)
			if ticket.Pruned(ctx) {
				t.Fatal("the mined ticket is not in the wallet")
			}
			if err := c.Process(ctx, ticket, nil); err != nil {
				t.Fatal(err)
			}
			// Process leaves an attempt scheduled; run it now.
			fp = testJob(c, ticket)
			if fp == nil || !timerSet(fp) {
				t.Fatal("Process left no attempt scheduled")
			}
			fp.stop()
			// confirmPayment schedules itself while the VSP holds the
			// fee, and leaves the job's first reconcile otherwise.
			next := fp.reconcilePayment
			if tc.vspStatus == "received" {
				next = fp.confirmPayment
			}
			fp.procMu.Lock()
			err = next()
			fp.procMu.Unlock()
			fp.stop()
			if err != nil {
				t.Fatal(err)
			}

			info, err := ticket.VSPTicketInfo(ctx)
			if err != nil {
				t.Fatal(err)
			}
			newHash, _ := paid.Load().(chainhash.Hash)
			if !tc.wantNew {
				if newHash != (chainhash.Hash{}) || info.FeeHash != ownHash {
					t.Fatalf("paid %v, record names %v; want no new fee tx and the VSP's %v",
						newHash, info.FeeHash, ownHash)
				}
				return
			}
			if newHash == (chainhash.Hash{}) || newHash == ownHash {
				t.Fatalf("paid fee tx %v, want a new one", newHash)
			}
			if info.FeeHash != newHash || !testHoldsUnmined(ctx, t, w, newHash) {
				t.Fatalf("record names %v, wallet holds the new %v: %v",
					info.FeeHash, newHash, testHoldsUnmined(ctx, t, w, newHash))
			}
		})
	}
}
