// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package spv

import (
	"context"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/txscript"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/wallet"
)

func published(t *testing.T, w *wallet.Wallet, tx *wire.MsgTx) bool {
	t.Helper()
	txs, err := w.UnminedTransactions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return slices.ContainsFunc(txs, func(u *wire.MsgTx) bool { return u.TxHash() == tx.TxHash() })
}

// notifications subscribes to w's transaction notifications and returns a
// function that waits for the next one and returns its unmined hashes.
func notifications(t *testing.T, w *wallet.Wallet) func() []chainhash.Hash {
	ntfns := w.NtfnServer.TransactionNotifications()
	t.Cleanup(ntfns.Done)
	c := make(chan *wallet.TransactionNotifications, 10)
	go func() {
		for n := range ntfns.C {
			c <- n
		}
	}()
	return func() []chainhash.Hash {
		t.Helper()
		select {
		case n := <-c:
			var hs []chainhash.Hash
			for _, s := range n.UnminedTransactions {
				hs = append(hs, *s.Hash)
			}
			return hs
		case <-time.After(10 * time.Second):
			t.Fatal("no transaction notification")
			return nil
		}
	}
}

// heldFee records fee as the wallet records a VSP fee: unpublished first,
// then added.
func heldFee(t *testing.T, w *wallet.Wallet, fee *wire.MsgTx) {
	t.Helper()
	ctx := context.Background()
	hash := fee.TxHash()
	if err := w.SetPublished(ctx, &hash, false); err != nil {
		t.Fatal(err)
	}
	if err := w.AddTransaction(ctx, fee, nil); err != nil {
		t.Fatal(err)
	}
	if published(t, w, fee) {
		t.Fatal("unpublished transaction counted as published")
	}
}

// TestHandleTxInvsMarksRelayedPublished checks that every transaction the
// wallet holds back as unpublished, recorded as the wallet records a VSP fee
// that spends its output and pays elsewhere, is marked published once a peer
// relays it, and that clients are notified of each once more for the change.
func TestHandleTxInvsMarksRelayedPublished(t *testing.T) {
	for _, ct := range []cointype.CoinType{cointype.CoinTypeVAR, 1} {
		t.Run(ct.String(), func(t *testing.T) {
			ctx := context.Background()
			w, version, script, syncer := txInvsWallet(t)
			var fees []*wire.MsgTx
			var owned []*wire.OutPoint
			for prev := byte(1); prev <= 2; prev++ {
				fund := payment(version, script, ct, prev)
				if err := w.AddTransaction(ctx, fund, nil); err != nil {
					t.Fatal(err)
				}
				fee := spendOf(t, w, fund, []byte{txscript.OP_TRUE}, nil)
				heldFee(t, w, fee)
				fees = append(fees, fee)
				owned = append(owned, &fee.TxIn[0].PreviousOutPoint)
			}

			next := notifications(t, w)
			rp := connectFakePeer(t, wire.SFNodeNetwork, nil, fees)
			syncer(owned...).handleTxInvs(ctx, rp, hashes(fees...))
			for i, fee := range fees {
				if !published(t, w, fee) {
					t.Fatalf("relayed transaction %d still unpublished", i)
				}
			}

			// Each fee is notified by AddTransaction and once more when
			// it is marked published; the sentinel ends the relay's
			// notifications.
			sentinel := payment(version, script, ct, 3)
			if err := w.AddTransaction(ctx, sentinel, nil); err != nil {
				t.Fatal(err)
			}
			count := make(map[chainhash.Hash]int)
			for {
				got := next()
				if len(got) != 1 {
					t.Fatalf("notified %v, want one transaction", got)
				}
				if got[0] == sentinel.TxHash() {
					break
				}
				count[got[0]]++
			}
			for i, fee := range fees {
				if n := count[fee.TxHash()]; n != 2 {
					t.Errorf("relayed transaction %d notified %d times, want 2", i, n)
				}
				delete(count, fee.TxHash())
			}
			if len(count) != 0 {
				t.Errorf("notified other transactions %v", count)
			}
		})
	}
}

// TestHandleTxInvsRelayedChangeSpendable checks that the change of a
// transaction the wallet holds back as unpublished, as a VSP fee with change,
// is neither selected nor counted spendable at minconf 0 until a peer relays
// it, and then is both, so coin selection and the balance agree.
func TestHandleTxInvsRelayedChangeSpendable(t *testing.T) {
	for _, ct := range []cointype.CoinType{cointype.CoinTypeVAR, 1} {
		t.Run(ct.String(), func(t *testing.T) {
			ctx := context.Background()
			w, version, script, syncer := txInvsWallet(t)
			fund := payment(version, script, ct, 1)
			if err := w.AddTransaction(ctx, fund, nil); err != nil {
				t.Fatal(err)
			}
			// Left unsigned, so the change is added before signing.
			fee := spendOf(t, w, fund, []byte{txscript.OP_TRUE}, []byte{})
			out := fee.TxOut[0]
			change := &wire.TxOut{Version: version, PkScript: script, CoinType: ct}
			if ct.IsSKA() {
				change.SKAValue = big.NewInt(9e17)
				out.SKAValue = new(big.Int).Sub(out.SKAValue, change.SKAValue)
			} else {
				change.Value = 9e7
				out.Value -= change.Value
			}
			fee.AddTxOut(change)
			fee.TxIn[0].SignatureScript = nil
			if sigErrs, _, err := w.SignTransaction(ctx, fee, txscript.SigHashAll, nil, nil, nil); err != nil || len(sigErrs) != 0 {
				t.Fatalf("sign: %v %v", err, sigErrs)
			}
			heldFee(t, w, fee)
			wantChange := big.NewInt(change.Value)
			if ct.IsSKA() {
				wantChange = change.SKAValue
			}

			// spendable returns the minconf 0 amount coin selection
			// offers and the one the balance counts spendable.
			spendable := func() (selected, balance *big.Int) {
				t.Helper()
				detail, err := w.SelectInputs(ctx, 0, cointype.Zero(),
					wallet.OutputSelectionPolicy{CoinType: ct})
				if err != nil {
					t.Fatal(err)
				}
				selected = big.NewInt(int64(detail.Amount))
				if ct.IsSKA() {
					selected = detail.SKAAmount.BigInt()
				}
				bals, err := w.AccountBalances(ctx, 0)
				if err != nil {
					t.Fatal(err)
				}
				balance = new(big.Int)
				for _, b := range bals {
					if b.Account != 0 {
						continue
					}
					cb := b.CoinTypeBalances[ct]
					balance.SetInt64(int64(cb.Spendable))
					if ct.IsSKA() {
						balance = cb.SKASpendable.BigInt()
					}
				}
				return selected, balance
			}

			if s, b := spendable(); s.Sign() != 0 || b.Sign() != 0 {
				t.Fatalf("change of an unpublished transaction spendable at minconf 0: selected %v, balance %v", s, b)
			}
			rp := connectFakePeer(t, wire.SFNodeNetwork, nil, []*wire.MsgTx{fee})
			syncer(&fee.TxIn[0].PreviousOutPoint).handleTxInvs(ctx, rp, hashes(fee))
			if s, b := spendable(); s.Cmp(wantChange) != 0 || b.Cmp(wantChange) != 0 {
				t.Fatalf("relayed change at minconf 0: selected %v, balance %v, want %v", s, b, wantChange)
			}
		})
	}
}

// TestHandleTxInvsForgedRelayStaysUnpublished checks that a transaction the
// wallet holds back as unpublished stays unpublished when an SPV peer relays
// it with a forged signature, which keeps its hash but fails AddTransaction:
// a relay that was not recorded proves nothing about the mempool.
func TestHandleTxInvsForgedRelayStaysUnpublished(t *testing.T) {
	for _, ct := range []cointype.CoinType{cointype.CoinTypeVAR, 1} {
		t.Run(ct.String(), func(t *testing.T) {
			ctx := context.Background()
			w, version, script, syncer := txInvsWallet(t)
			fund := payment(version, script, ct, 1)
			if err := w.AddTransaction(ctx, fund, nil); err != nil {
				t.Fatal(err)
			}
			fee := spendOf(t, w, fund, []byte{txscript.OP_TRUE}, nil)
			heldFee(t, w, fee)
			hash := fee.TxHash()
			// The signature script is witness data, so the hash is the fee's.
			forged := spendOf(t, w, fund, []byte{txscript.OP_TRUE}, []byte{txscript.OP_TRUE})
			if forged.TxHash() != hash {
				t.Fatal("forged transaction has another hash")
			}
			if err := w.AddTransaction(ctx, forged, nil); err == nil {
				t.Fatal("forged transaction accepted")
			}

			rp := connectFakePeer(t, 0, nil, []*wire.MsgTx{forged})
			syncer(&forged.TxIn[0].PreviousOutPoint).handleTxInvs(ctx, rp, hashes(forged))
			if published(t, w, fee) {
				t.Fatal("transaction marked published by a relay that failed to be recorded")
			}
		})
	}
}

// TestHandleTxInvsRelayOfPublishedNotifiesOnce checks that a relay of a
// transaction the wallet already holds as published notifies clients only
// once, from AddTransaction, as before relays marked transactions published.
func TestHandleTxInvsRelayOfPublishedNotifiesOnce(t *testing.T) {
	for _, ct := range []cointype.CoinType{cointype.CoinTypeVAR, 1} {
		t.Run(ct.String(), func(t *testing.T) {
			ctx := context.Background()
			w, version, script, syncer := txInvsWallet(t)
			fund := payment(version, script, ct, 1)
			if err := w.AddTransaction(ctx, fund, nil); err != nil {
				t.Fatal(err)
			}
			tx := spendOf(t, w, fund, []byte{txscript.OP_TRUE}, nil)
			if err := w.AddTransaction(ctx, tx, nil); err != nil {
				t.Fatal(err)
			}

			next := notifications(t, w)
			rp := connectFakePeer(t, wire.SFNodeNetwork, nil, []*wire.MsgTx{tx})
			syncer(&tx.TxIn[0].PreviousOutPoint).handleTxInvs(ctx, rp, hashes(tx))
			if got := next(); len(got) != 1 || got[0] != tx.TxHash() {
				t.Fatalf("notified %v, want %v", got, tx.TxHash())
			}

			// A second notification of the relayed transaction would come
			// before this one.
			other := payment(version, script, ct, 2)
			if err := w.AddTransaction(ctx, other, nil); err != nil {
				t.Fatal(err)
			}
			if got := next(); len(got) != 1 || got[0] != other.TxHash() {
				t.Fatalf("notified %v, want %v: %v was notified again", got, other.TxHash(), tx.TxHash())
			}
		})
	}
}
