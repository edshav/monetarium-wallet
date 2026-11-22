// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"context"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/decred/slog"
	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// testRemovedTxs collects the wallet's removed-tx notifications.  removed
// returns those sent so far.
func testRemovedTxs(t *testing.T, w *Wallet) (removed func() map[chainhash.Hash]bool) {
	t.Helper()
	client := w.NtfnServer.RemovedTransactionNotifications()
	t.Cleanup(client.Done)
	var mu sync.Mutex
	got := make(map[chainhash.Hash]bool)
	go func() {
		for n := range client.C {
			mu.Lock()
			got[n.TxHash] = true
			mu.Unlock()
		}
	}()
	sentinel := chainhash.Hash{0xff, 0xee}
	return func() map[chainhash.Hash]bool {
		// Sent synchronously: once it is received, so is every earlier
		// notification.
		w.NtfnServer.notifyRemovedTransaction(sentinel)
		mu.Lock()
		defer mu.Unlock()
		out := make(map[chainhash.Hash]bool, len(got))
		for h := range got {
			if h != sentinel {
				out[h] = true
			}
		}
		return out
	}
}

// TestVSPOrphanFeeTxAbandonedOnBlock checks the unpublished fee tx of a VSP
// ticket that left the wallet while no fee job ran for it.  The next block
// connected once every block's txs are recorded abandons it, so its input is
// spendable again, and the ticket's record stays.  While a rescan point
// remains it is kept, as a ticket mined meanwhile may not be recorded yet.  It
// is kept while the ticket is still in the wallet, unmined or mined, when it
// is published, when the record of a ticket the wallet has names it, and when
// no record names it.  When records of two tickets both gone name it, it is
// abandoned.
func TestVSPOrphanFeeTxAbandonedOnBlock(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ticket      string // "pruned" (default), "kept" or "mined"
		rescanPoint bool   // the block connects during catch-up first
		published   bool
		other       string // another ticket's record names the fee tx: "held" or "gone"
		otherFirst  bool   // the other record comes first in the records' key order
		noRecord    bool   // no record names the fee tx
		wantRemoved bool
	}{
		{name: "ticket pruned", wantRemoved: true},
		{name: "ticket pruned during catch-up", rescanPoint: true, wantRemoved: true},
		{name: "ticket still unmined", ticket: "kept"},
		{name: "ticket mined", ticket: "mined"},
		{name: "fee tx published", published: true},
		{name: "a held ticket's record names it, first", other: "held", otherFirst: true},
		{name: "a held ticket's record names it, last", other: "held"},
		{name: "two gone tickets' records name it", other: "gone", wantRemoved: true},
		{name: "no record names it", noRecord: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
				t.Error("no VSP request expected")
				return apiError(types.ErrInternalError)
			})
			w := c.wallet
			f := &vspPaymentFixture{w: w, cfg: basicWalletConfig,
				tip: basicWalletConfig.Params.GenesisBlock.Header}
			// The fixture's blocks keep an unmined ticket only at its
			// price.
			const price = 1e8
			if tc.ticket == "kept" || tc.ticket == "mined" {
				f.sbits = price
			}
			op := testWalletOutput(ctx, t, w, 2)
			ticket := testVSPTicket(ctx, t, c, 1)
			// The other ticket is mined in the next block when held,
			// and pruned with the first when gone.  Records are visited
			// in ticket hash order, so the two swap roles to put the
			// other's record first or last.
			var other *VSPTicket
			if tc.other != "" {
				other = testVSPTicket(ctx, t, c, 3)
				if (bytes.Compare(other.Hash()[:], ticket.Hash()[:]) < 0) != tc.otherFirst {
					ticket, other = other, ticket
				}
			}
			before := testSpendable(ctx, t, w)
			fee := wire.NewMsgTx()
			fee.AddTxIn(wire.NewTxIn(op, 1e8, nil))
			if err := w.CreateVspPayment(ctx, fee, 1e7, ticket.votingAddr, 0, 0); err != nil {
				t.Fatal(err)
			}
			feeHash := fee.TxHash()
			if !tc.noRecord {
				if err := ticket.UpdateFeePaid(ctx, feeHash, c.URL, c.PubKey); err != nil {
					t.Fatal(err)
				}
			}
			if tc.published {
				if err := w.SetPublished(ctx, &feeHash, true); err != nil {
					t.Fatal(err)
				}
			}
			if other != nil {
				if err := other.UpdateFeePaid(ctx, feeHash, c.URL, c.PubKey); err != nil {
					t.Fatal(err)
				}
			}
			removed := testRemovedTxs(t, w)

			if tc.rescanPoint {
				// Headers only: the marker of recorded blocks stays.
				f.mineEmpty(ctx, t, 1)
				if !testHoldsUnmined(ctx, t, w, feeHash) {
					t.Fatal("fee tx abandoned while a rescan point remains")
				}
				// The rescan has recorded every block.
				err := walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
					tip, _ := w.txStore.MainChainTip(dbtx)
					return w.txStore.UpdateProcessedTxsBlockMarker(dbtx, &tip)
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			var block []*wire.MsgTx
			if tc.ticket == "mined" {
				block = append(block, ticket.rawTx)
			}
			if tc.other == "held" {
				block = append(block, other.rawTx)
			}
			f.mine(ctx, t, block...)
			if gone := ticket.Pruned(ctx); gone != (tc.ticket == "") {
				t.Fatalf("ticket pruned = %v", gone)
			}

			if held := testHoldsUnmined(ctx, t, w, feeHash); held == tc.wantRemoved {
				t.Fatalf("wallet holds the fee tx = %v, want %v", held, !tc.wantRemoved)
			}
			if unspent := testUnspentOutputs(ctx, t, w)[*op]; unspent != tc.wantRemoved {
				t.Fatalf("fee tx input unspent = %v, want %v", unspent, tc.wantRemoved)
			}
			notified := removed()
			if notified[feeHash] != tc.wantRemoved {
				t.Fatalf("removal notified = %v, want %v", notified[feeHash], tc.wantRemoved)
			}
			// The prune's own removal is still notified.
			if tc.ticket == "" && !notified[*ticket.Hash()] {
				t.Fatal("the pruned ticket's removal is not notified")
			}
			if after := testSpendable(ctx, t, w); tc.wantRemoved && after != before {
				t.Fatalf("spendable balance %v after the abandon, want %v as before the fee tx", after, before)
			}
			if !tc.noRecord {
				info, err := ticket.VSPTicketInfo(ctx)
				if err != nil || info.FeeHash != feeHash {
					t.Fatalf("the ticket's VSP record: %+v, %v", info, err)
				}
			}
		})
	}
}

// TestVSPOrphanFeeTxAmongOthers checks the pass with two unpublished fee txs:
// one a gone ticket's record names, which is removed, and one a held
// ticket's record names, which stays, in either key order; and two that gone
// tickets' records name, which are both removed in one pass.
func TestVSPOrphanFeeTxAmongOthers(t *testing.T) {
	for _, tc := range []struct {
		name        string
		orphanFirst bool
		bothGone    bool
	}{
		{name: "orphan first", orphanFirst: true},
		{name: "orphan last"},
		{name: "two orphans", bothGone: true},
	} {
		orphanFirst := tc.orphanFirst
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
				t.Error("no VSP request expected")
				return apiError(types.ErrInternalError)
			})
			w := c.wallet
			f := &vspPaymentFixture{w: w, cfg: basicWalletConfig,
				tip: basicWalletConfig.Params.GenesisBlock.Header}
			gone := testVSPTicket(ctx, t, c, 1)
			held := testVSPTicket(ctx, t, c, 3)
			var fees [2]*wire.MsgTx
			for i := range fees {
				op := testWalletOutput(ctx, t, w, byte(10+i))
				fees[i] = wire.NewMsgTx()
				fees[i].AddTxIn(wire.NewTxIn(op, 1e8, nil))
				if err := w.CreateVspPayment(ctx, fees[i], 1e7, gone.votingAddr, 0, 0); err != nil {
					t.Fatal(err)
				}
			}
			// The unpublished txs are visited in hash order.
			orphan, kept := fees[0].TxHash(), fees[1].TxHash()
			if (bytes.Compare(orphan[:], kept[:]) < 0) != orphanFirst {
				orphan, kept = kept, orphan
			}
			if err := gone.UpdateFeePaid(ctx, orphan, c.URL, c.PubKey); err != nil {
				t.Fatal(err)
			}
			if err := held.UpdateFeePaid(ctx, kept, c.URL, c.PubKey); err != nil {
				t.Fatal(err)
			}
			// gone is pruned for its price; held is mined, or pruned too.
			if tc.bothGone {
				removed := testRemovedTxs(t, w)
				f.mine(ctx, t)
				if testHoldsUnmined(ctx, t, w, orphan) || testHoldsUnmined(ctx, t, w, kept) {
					t.Fatal("an orphan fee tx is left")
				}
				if notified := removed(); !notified[orphan] || !notified[kept] {
					t.Fatalf("removals notified: %v and %v, want both", notified[orphan], notified[kept])
				}
				return
			}
			f.mine(ctx, t, held.rawTx)
			if !gone.Pruned(ctx) || held.Pruned(ctx) {
				t.Fatal("tickets not as set up")
			}
			if testHoldsUnmined(ctx, t, w, orphan) || !testHoldsUnmined(ctx, t, w, kept) {
				t.Fatalf("wallet holds the orphan %v and the held ticket's fee tx %v; want only the second",
					testHoldsUnmined(ctx, t, w, orphan), testHoldsUnmined(ctx, t, w, kept))
			}
		})
	}
}

// removeBeforeAbandonDB runs remove when AbandonTransaction opens its write,
// as the pass over VSP ticket records does when a block connects between a
// fee job's read and its abandon.
type removeBeforeAbandonDB struct {
	walletdb.DB
	remove func()
}

func (d *removeBeforeAbandonDB) BeginReadWriteTx() (walletdb.ReadWriteTx, error) {
	if d.remove != nil {
		pcs := make([]uintptr, 64)
		frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
		for {
			f, more := frames.Next()
			if strings.Contains(f.Function, ".(*Wallet).AbandonTransaction") {
				remove := d.remove
				d.remove = nil
				remove()
				break
			}
			if !more {
				break
			}
		}
	}
	return d.DB.BeginReadWriteTx()
}

// TestVSPAbandonFeeTxRemovedMeanwhile checks a fee job's abandon of a fee tx
// that changed between its read and its write.  One removed meanwhile, as by
// the pass over VSP ticket records, logs no error; one mined meanwhile does.
func TestVSPAbandonFeeTxRemovedMeanwhile(t *testing.T) {
	for _, mined := range []bool{false, true} {
		name := "removed"
		if mined {
			name = "mined"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
				t.Error("no VSP request expected")
				return apiError(types.ErrInternalError)
			})
			w := c.wallet
			logs := &vspLogLines{}
			c.log = slog.NewBackend(logs).Logger("VSP")
			op := testWalletOutput(ctx, t, w, 2)
			ticket := testVSPTicket(ctx, t, c, 1)
			fee := wire.NewMsgTx()
			fee.AddTxIn(wire.NewTxIn(op, 1e8, nil))
			if err := w.CreateVspPayment(ctx, fee, 1e7, ticket.votingAddr, 0, 0); err != nil {
				t.Fatal(err)
			}
			feeHash := fee.TxHash()
			f := &vspPaymentFixture{w: w, cfg: basicWalletConfig,
				tip: basicWalletConfig.Params.GenesisBlock.Header}
			d := &removeBeforeAbandonDB{DB: w.db}
			d.remove = func() {
				if mined {
					f.mine(ctx, t, fee)
					return
				}
				err := walletdb.Update(ctx, d.DB, func(dbtx walletdb.ReadWriteTx) error {
					ns := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)
					return w.txStore.RemoveUnconfirmed(ns, fee, &feeHash)
				})
				if err != nil {
					t.Error(err)
				}
			}
			w.db = d
			t.Cleanup(func() { w.db = d.DB })

			c.abandonFeeTx(ctx, ticket, feeHash)
			if d.remove != nil || testHoldsUnmined(ctx, t, w, feeHash) {
				t.Fatal("the fee tx did not change meanwhile")
			}
			if logged := strings.Contains(logs.String(), "[ERR]"); logged != mined {
				t.Fatalf("error logged = %v, want %v:\n%s", logged, mined, logs)
			}
		})
	}
}
