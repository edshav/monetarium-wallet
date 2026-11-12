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
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// TestSetPublishedNotifies checks that clients are notified of a transaction
// once it stops being unpublished, not again when it is marked published a
// second time, and not when it is marked unpublished again.
func TestSetPublishedNotifies(t *testing.T) {
	for _, ct := range []cointype.CoinType{cointype.CoinTypeVAR, 1} {
		t.Run(ct.String(), func(t *testing.T) {
			testSetPublishedNotifies(t, ct)
		})
	}
}

// txNotifications subscribes to w's transaction notifications and returns a
// function that waits for the next one and returns its unmined hashes.
func txNotifications(t *testing.T, w *Wallet) func() []chainhash.Hash {
	ntfns := w.NtfnServer.TransactionNotifications()
	t.Cleanup(ntfns.Done)
	c := make(chan *TransactionNotifications, 10)
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

// walletPayment returns a function building a tx that pays a new address of
// w 1 coin of type ct from an output w does not own.
func walletPayment(ctx context.Context, t *testing.T, w *Wallet, ct cointype.CoinType) func(prev byte) *wire.MsgTx {
	addr, err := w.NewExternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, script := addr.PaymentScript()
	return func(prev byte) *wire.MsgTx {
		tx := wire.NewMsgTx()
		tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{prev}}, 0, nil))
		if ct.IsSKA() {
			tx.AddTxOut(wire.NewTxOutSKA(big.NewInt(1e18), ct, script))
		} else {
			tx.AddTxOut(wire.NewTxOut(1e8, script))
		}
		return tx
	}
}

func testSetPublishedNotifies(t *testing.T, ct cointype.CoinType) {
	ctx := context.Background()
	cfg := basicWalletConfig
	w, teardown := testWallet(ctx, t, &cfg, nil)
	defer teardown()
	payment := walletPayment(ctx, t, w, ct)

	// The wallet records a VSP fee this way: unpublished first, then added.
	tx := payment(1)
	hash := tx.TxHash()
	if err := w.SetPublished(ctx, &hash, false); err != nil {
		t.Fatal(err)
	}
	if err := w.AddTransaction(ctx, tx, nil); err != nil {
		t.Fatal(err)
	}

	next := txNotifications(t, w)

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

	// Marking the recorded transaction unpublished changes the flag but
	// notifies nothing.
	if err := w.SetPublished(ctx, &hash, false); err != nil {
		t.Fatal(err)
	}
	third := payment(3)
	if err := w.AddTransaction(ctx, third, nil); err != nil {
		t.Fatal(err)
	}
	if got := next(); len(got) != 1 || got[0] != third.TxHash() {
		t.Fatalf("notified %v, want %v: %v was notified when marked unpublished", got, third.TxHash(), hash)
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

	next := txNotifications(t, w)

	hash := chainhash.Hash{1}
	if err := w.SetPublished(ctx, &hash, false); err != nil {
		t.Fatal(err)
	}
	if err := w.SetPublished(ctx, &hash, true); err != nil {
		t.Fatal(err)
	}
	// A notification for the flag would come before this one.
	other := walletPayment(ctx, t, w, cointype.CoinTypeVAR)(2)
	if err := w.AddTransaction(ctx, other, nil); err != nil {
		t.Fatal(err)
	}
	if got := next(); len(got) != 1 || got[0] != other.TxHash() {
		t.Fatalf("notified %v, want %v: notified a transaction the wallet does not hold", got, other.TxHash())
	}
}

// TestSetPublishedUnreadableTransaction checks that a transaction whose
// unmined record cannot be read is still marked published, without a
// notification: the record only feeds the notification.
func TestSetPublishedUnreadableTransaction(t *testing.T) {
	ctx := context.Background()
	cfg := basicWalletConfig
	w, teardown := testWallet(ctx, t, &cfg, nil)
	defer teardown()

	next := txNotifications(t, w)

	hash := chainhash.Hash{1}
	if err := w.SetPublished(ctx, &hash, false); err != nil {
		t.Fatal(err)
	}
	// A record too short to decode, in the store's unmined bucket ("m").
	err := walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
		ns := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)
		return ns.NestedReadWriteBucket([]byte("m")).Put(hash[:], []byte{1})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetPublished(ctx, &hash, true); err != nil {
		t.Fatalf("SetPublished with an unreadable record: %v", err)
	}
	// The flag, in the store's unpublished bucket ("up"), is gone.
	err = walletdb.View(ctx, w.db, func(dbtx walletdb.ReadTx) error {
		ns := dbtx.ReadBucket(wtxmgrNamespaceKey)
		if ns.NestedReadBucket([]byte("up")).Get(hash[:]) != nil {
			return errors.New("still unpublished")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A notification for it would come before this one.
	other := walletPayment(ctx, t, w, cointype.CoinTypeVAR)(2)
	if err := w.AddTransaction(ctx, other, nil); err != nil {
		t.Fatal(err)
	}
	if got := next(); len(got) != 1 || got[0] != other.TxHash() {
		t.Fatalf("notified %v, want %v", got, other.TxHash())
	}
}
