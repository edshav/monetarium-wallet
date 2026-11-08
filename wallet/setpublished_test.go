// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/wire"
)

// TestSetPublishedNotifies checks that clients are notified of a transaction
// once it stops being unpublished, and not again when it is marked published
// a second time.
func TestSetPublishedNotifies(t *testing.T) {
	for _, ct := range []cointype.CoinType{cointype.CoinTypeVAR, 1} {
		t.Run(ct.String(), func(t *testing.T) {
			testSetPublishedNotifies(t, ct)
		})
	}
}

func testSetPublishedNotifies(t *testing.T, ct cointype.CoinType) {
	ctx := context.Background()
	cfg := basicWalletConfig
	w, teardown := testWallet(ctx, t, &cfg, nil)
	defer teardown()

	addr, err := w.NewExternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, script := addr.PaymentScript()
	payment := func(prev byte) *wire.MsgTx {
		tx := wire.NewMsgTx()
		tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{prev}}, 0, nil))
		if ct.IsSKA() {
			tx.AddTxOut(wire.NewTxOutSKA(big.NewInt(1e18), ct, script))
		} else {
			tx.AddTxOut(wire.NewTxOut(1e8, script))
		}
		return tx
	}

	// The wallet records a VSP fee this way: unpublished first, then added.
	tx := payment(1)
	hash := tx.TxHash()
	if err := w.SetPublished(ctx, &hash, false); err != nil {
		t.Fatal(err)
	}
	if err := w.AddTransaction(ctx, tx, nil); err != nil {
		t.Fatal(err)
	}

	ntfns := w.NtfnServer.TransactionNotifications()
	defer ntfns.Done()
	c := make(chan *TransactionNotifications, 10)
	go func() {
		for n := range ntfns.C {
			c <- n
		}
	}()
	next := func() []chainhash.Hash {
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

	if err := w.SetPublished(ctx, &hash, true); err != nil {
		t.Fatal(err)
	}
	if got := next(); len(got) != 1 || got[0] != hash {
		t.Fatalf("notified %v, want %v", got, hash)
	}

	// Nothing changes, so the next notification is the one of another
	// transaction.
	if err := w.SetPublished(ctx, &hash, true); err != nil {
		t.Fatal(err)
	}
	other := payment(2)
	if err := w.AddTransaction(ctx, other, nil); err != nil {
		t.Fatal(err)
	}
	if got := next(); len(got) != 1 || got[0] != other.TxHash() {
		t.Fatalf("notified %v, want %v: %v was notified again", got, other.TxHash(), hash)
	}
}

// TestSetPublishedWithoutTransaction checks that a flag left for a
// transaction the wallet never recorded, as when the fee path marks a fee
// unpublished and then fails to add it, is cleared without a notification.
func TestSetPublishedWithoutTransaction(t *testing.T) {
	ctx := context.Background()
	cfg := basicWalletConfig
	w, teardown := testWallet(ctx, t, &cfg, nil)
	defer teardown()

	ntfns := w.NtfnServer.TransactionNotifications()
	defer ntfns.Done()
	notified := make(chan struct{}, 1)
	go func() {
		for range ntfns.C {
			notified <- struct{}{}
		}
	}()

	hash := chainhash.Hash{1}
	if err := w.SetPublished(ctx, &hash, false); err != nil {
		t.Fatal(err)
	}
	if err := w.SetPublished(ctx, &hash, true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-notified:
		t.Fatal("notified a transaction the wallet does not hold")
	default:
	}
}
