// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/wire"
)

// TestVSPFeeAlreadyReceivedAbandonsOwnFeeTx checks the job's own fee tx when
// Process learns that the VSP already holds a fee tx for the ticket.  If the
// VSP names another tx, the job's unpublished fee tx is abandoned, so its
// input is spendable again.  It is kept when the VSP names it, when it was
// published, and when the VSP's tx is not learned or recorded: the status
// request fails or names no fee tx, or recording its hash fails.  After an
// abandon, the account balance is back to what it was before the job's tx.  A tx the job knows only by its fee hash, which may be one
// the VSP named for another ticket, is kept.
func TestVSPFeeAlreadyReceivedAbandonsOwnFeeTx(t *testing.T) {
	for _, tc := range []struct {
		name        string
		vspNamesOwn bool // the VSP's fee tx is the job's
		published   bool
		hashOnly    bool                         // the job holds the tx's hash but not the tx
		status      func(body []byte) (int, any) // nil: the VSP's fee tx, received
		failWrites  bool                         // recording the VSP's hash fails
		otherTicket bool                         // another ticket's record names the job's fee tx
		retry       bool                         // the failed status or write then succeeds on the retry
		wantUnspent bool
	}{
		{name: "VSP names another fee tx", wantUnspent: true},
		{name: "VSP names the job's fee tx", vspNamesOwn: true},
		{name: "job's fee tx published", published: true},
		{name: "fee hash without the tx", hashOnly: true},
		{name: "status request fails", status: func([]byte) (int, any) {
			return apiError(types.ErrInternalError)
		}},
		{name: "VSP names no fee tx", status: func(body []byte) (int, any) {
			return http.StatusOK, types.TicketStatusResponse{FeeTxStatus: "received", Request: body}
		}},
		{name: "recording the VSP's hash fails", failWrites: true},
		{name: "another ticket names the job's fee tx", otherTicket: true},
		{name: "status request fails, then names another fee tx", status: func([]byte) (int, any) {
			return apiError(types.ErrInternalError)
		}, retry: true, wantUnspent: true},
		{name: "recording the VSP's hash fails, then succeeds", failWrites: true, retry: true, wantUnspent: true},
		{name: "VSP names no fee tx, then another", status: func(body []byte) (int, any) {
			return http.StatusOK, types.TicketStatusResponse{FeeTxStatus: "received", Request: body}
		}, retry: true, wantUnspent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			vspFeeHash := chainhash.Hash{0xfe}
			var healed atomic.Bool // the retry's status request succeeds
			c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				// failVSPWrites lengthens the URL's path.
				path = path[strings.Index(path, "/api/v3/"):]
				switch path {
				case "/api/v3/feeaddress":
					return apiError(types.ErrFeeAlreadyReceived)
				case "/api/v3/ticketstatus":
					if tc.status != nil && !healed.Load() {
						return tc.status(body)
					}
					return http.StatusOK, types.TicketStatusResponse{
						FeeTxStatus: "received",
						FeeTxHash:   vspFeeHash.String(),
						Request:     body,
					}
				}
				return apiError(types.ErrInternalError)
			})
			w := c.wallet
			ticket := testVSPTicket(ctx, t, c, 1)

			// A fee tx an earlier attempt made and recorded unpublished.
			op := testWalletOutput(ctx, t, w, 2)
			before := testSpendable(ctx, t, w)
			own := wire.NewMsgTx()
			own.AddTxIn(wire.NewTxIn(op, 1e8, nil))
			if err := w.CreateVspPayment(ctx, own, 1e7, ticket.votingAddr, 0, 0); err != nil {
				t.Fatal(err)
			}
			ownHash := own.TxHash()
			if tc.published {
				if err := w.SetPublished(ctx, &ownHash, true); err != nil {
					t.Fatal(err)
				}
			}
			if tc.vspNamesOwn {
				vspFeeHash = ownHash
			}
			fp := &vspFeePayment{
				client:  c,
				ctx:     ctx,
				ticket:  ticket,
				policy:  c.policy,
				params:  w.chainParams,
				feeTx:   own,
				feeHash: ownHash,
			}
			if tc.hashOnly {
				fp.feeTx = nil
			}
			c.jobs[*ticket.Hash()] = fp // stopped on cleanup
			if tc.otherTicket {
				other := testVSPTicket(ctx, t, c, 3)
				if err := other.UpdateFeeStarted(ctx, ownHash, c.URL, c.PubKey); err != nil {
					t.Fatal(err)
				}
			}
			url := c.URL
			if tc.failWrites {
				failVSPWrites(c)
			}

			err := c.Process(ctx, ticket, nil)
			if tc.retry {
				if err == nil {
					t.Fatal("Process: want an error")
				}
				// The scheduled retry, run now with the VSP and the
				// wallet's writes working again.  procMu holds off an
				// attempt whose timer fired before the stop.
				fp.stop()
				fp.procMu.Lock()
				healed.Store(true)
				c.URL = url
				err = fp.reconcilePayment()
				fp.procMu.Unlock()
			}
			if (tc.status != nil || tc.failWrites) && !tc.retry {
				// The VSP's tx is not learned; a retry is scheduled.
				if err == nil {
					t.Fatal("Process: want an error")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				info, err := ticket.VSPTicketInfo(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if info.FeeHash != vspFeeHash {
					t.Fatalf("fee hash %v, want the VSP's %v", info.FeeHash, vspFeeHash)
				}
			}
			if unspent := testUnspentOutputs(ctx, t, w)[*op]; unspent != tc.wantUnspent {
				t.Fatalf("own fee tx's input unspent = %v, want %v", unspent, tc.wantUnspent)
			}
			if after := testSpendable(ctx, t, w); tc.wantUnspent && after != before {
				t.Fatalf("spendable balance %v after the abandon, want %v as before the job's tx",
					after, before)
			}
		})
	}
}

// TestVSPFeeReceivedOwnHashLifetime checks the job's own fee tx hash that
// recordReceivedFee keeps across attempts, through Process and the scheduled
// reconcile.  The VSP replaces its fee tx only after the one it held errored,
// so the job's tx is abandoned when a later answer names another one, even
// after the VSP held it.  A Process call with an empty fee tx, as gRPC
// SyncVSPFailedTickets retries errored tickets, keeps the hash; one with a
// finished fee tx replaces it.
func TestVSPFeeReceivedOwnHashLifetime(t *testing.T) {
	for _, name := range []string{
		"VSP held the job's tx, later names another",
		"retry with an empty fee tx",
		"retry with a finished fee tx",
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			var (
				mu          sync.Mutex
				vspFeeHash  chainhash.Hash
				statusFails bool
			)
			c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				mu.Lock()
				defer mu.Unlock()
				switch path {
				case "/api/v3/feeaddress":
					return apiError(types.ErrFeeAlreadyReceived)
				case "/api/v3/ticketstatus":
					if statusFails {
						return apiError(types.ErrInternalError)
					}
					return http.StatusOK, types.TicketStatusResponse{
						FeeTxStatus: "received",
						FeeTxHash:   vspFeeHash.String(),
						Request:     body,
					}
				}
				return apiError(types.ErrInternalError)
			})
			w := c.wallet
			ticket := testVSPTicket(ctx, t, c, 1)
			// feeTx records an unpublished fee tx spending a new output.
			feeTx := func(id byte) (*wire.MsgTx, wire.OutPoint) {
				op := testWalletOutput(ctx, t, w, id)
				tx := wire.NewMsgTx()
				tx.AddTxIn(wire.NewTxIn(op, 1e8, nil))
				if err := w.CreateVspPayment(ctx, tx, 1e7, ticket.votingAddr, 0, 0); err != nil {
					t.Fatal(err)
				}
				return tx, *op
			}
			first, firstOp := feeTx(2)
			fp := &vspFeePayment{
				client:  c,
				ctx:     ctx,
				ticket:  ticket,
				policy:  c.policy,
				params:  w.chainParams,
				feeTx:   first,
				feeHash: first.TxHash(),
			}
			c.jobs[*ticket.Hash()] = fp // stopped on cleanup
			answer := func(feeHash chainhash.Hash, fails bool) {
				mu.Lock()
				vspFeeHash, statusFails = feeHash, fails
				mu.Unlock()
			}
			// process runs Process and cancels the attempt it scheduled.
			process := func(feeTx *wire.MsgTx) error {
				err := c.Process(ctx, ticket, feeTx)
				fp.stop()
				return err
			}
			unspent := func(op wire.OutPoint) bool {
				return testUnspentOutputs(ctx, t, w)[op]
			}

			switch name {
			case "VSP held the job's tx, later names another":
				answer(first.TxHash(), false)
				if err := process(nil); err != nil {
					t.Fatal(err)
				}
				if unspent(firstOp) {
					t.Fatal("the job's fee tx, which the VSP holds, was abandoned")
				}
				// The VSP's fee errored and it took another; the
				// scheduled reconcile learns it.
				answer(chainhash.Hash{0xfd}, false)
				fp.procMu.Lock()
				err := fp.reconcilePayment()
				fp.procMu.Unlock()
				fp.stop()
				if err != nil {
					t.Fatal(err)
				}
				if !unspent(firstOp) {
					t.Fatal("the job's fee tx the VSP dropped is still spending its input")
				}
			case "retry with an empty fee tx":
				answer(chainhash.Hash{}, true)
				if err := process(nil); err == nil {
					t.Fatal("Process: want the status error")
				}
				answer(chainhash.Hash{0xfd}, false)
				if err := process(new(wire.MsgTx)); err != nil {
					t.Fatal(err)
				}
				if !unspent(firstOp) {
					t.Fatal("the kept fee tx was not abandoned")
				}
			case "retry with a finished fee tx":
				answer(chainhash.Hash{}, true)
				if err := process(nil); err == nil {
					t.Fatal("Process: want the status error")
				}
				second, secondOp := feeTx(3)
				answer(chainhash.Hash{0xfd}, false)
				if err := process(second); err != nil {
					t.Fatal(err)
				}
				if !unspent(secondOp) {
					t.Fatal("the caller's fee tx was not abandoned")
				}
				// The first is left as is: a job keeps one hash.
				if unspent(firstOp) {
					t.Fatal("the first kept fee tx was abandoned too")
				}
			}
		})
	}
}

// testSpendable returns account 0's spendable balance at minconf 0, as
// getbalance reports it.
func testSpendable(ctx context.Context, t *testing.T, w *Wallet) dcrutil.Amount {
	t.Helper()
	bal, err := w.AccountBalance(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return bal.Spendable
}
