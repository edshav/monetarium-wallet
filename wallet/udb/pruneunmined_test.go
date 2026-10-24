// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package udb

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// TestPruneUnminedDoubleSpends checks which unmined regular transactions
// PruneUnmined treats as double spends:
//   - an incoming payment whose inputs the wallet never owned is kept;
//   - a spend of a wallet credit that is still unspent is kept;
//   - a spend of a wallet credit that a mined transaction has spent is removed.
func TestPruneUnminedDoubleSpends(t *testing.T) {
	for _, ct := range []cointype.CoinType{cointype.CoinTypeVAR, cointype.CoinType(1)} {
		t.Run(ct.String(), func(t *testing.T) {
			testPruneUnminedDoubleSpends(t, ct)
		})
	}
}

func testPruneUnminedDoubleSpends(t *testing.T, ct cointype.CoinType) {
	ctx := context.Background()
	db, _, s, teardown, err := cloneDB(ctx, "prune_unmined_"+ct.String()+".kv")
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	addr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(make([]byte, 20), s.chainParams)
	if err != nil {
		t.Fatal(err)
	}
	_, pkScript := addr.PaymentScript()
	newTx := func(prevHash *chainhash.Hash, prevIndex uint32, amounts ...int64) *TxRecord {
		tx := wire.NewMsgTx()
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(prevHash, prevIndex, wire.TxTreeRegular), 0, nil))
		for _, v := range amounts {
			if ct.IsSKA() {
				tx.AddTxOut(wire.NewTxOutSKA(big.NewInt(v), ct, pkScript))
			} else {
				tx.AddTxOut(wire.NewTxOut(v, pkScript))
			}
		}
		rec, err := NewTxRecordFromMsgTx(tx, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}

	g := makeBlockGenerator()
	b1 := g.generate(dcrutil.BlockValid)
	b2 := g.generate(dcrutil.BlockValid)
	b1Hash, b2Hash := b1.BlockHash(), b2.BlockHash()

	// fund (mined in b1) creates two wallet credits from an outpoint the
	// wallet never owned.
	fund := newTx(&chainhash.Hash{0x01}, 0, 2e8, 2e8)
	// mined spends credit fund:0 and is mined in b2.
	mined := newTx(&fund.Hash, 0, 1e8)
	// orphan spends the same credit fund:0 and is never mined.
	orphan := newTx(&fund.Hash, 0, 1e8+1)
	// ownSpend spends credit fund:1, which nothing else spends.
	ownSpend := newTx(&fund.Hash, 1, 1e8)
	// incoming pays the wallet from an outpoint the wallet never owned.
	incoming := newTx(&chainhash.Hash{0x02}, 0, 5e7)

	var removed []*chainhash.Hash
	err = walletdb.Update(ctx, db, func(dbtx walletdb.ReadWriteTx) error {
		err := insertMainChainHeaders(s, dbtx, makeHeaderDataSlice(b1, b2), emptyFilters(2))
		if err != nil {
			return err
		}
		if err := s.InsertMinedTx(dbtx, fund, &b1Hash); err != nil {
			return err
		}
		for i := uint32(0); i < 2; i++ {
			if err := s.AddCredit(dbtx, fund, makeBlockMeta(b1), i, false, 0); err != nil {
				return err
			}
		}
		if err := s.InsertMinedTx(dbtx, mined, &b2Hash); err != nil {
			return err
		}
		// InsertMemPoolTx checks double spends only against unmined
		// inputs, so orphan is accepted although mined has spent its
		// input on chain.  This is the orphan state b9bbd77c prunes (it
		// arises after reorgs); the test builds it directly.
		for _, rec := range []*TxRecord{orphan, ownSpend, incoming} {
			if err := s.InsertMemPoolTx(dbtx, rec); err != nil {
				return err
			}
		}
		if err := s.AddCredit(dbtx, incoming, nil, 0, false, 0); err != nil {
			return err
		}

		removed, err = s.PruneUnmined(dbtx, 0, true)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(removed) != 1 || *removed[0] != orphan.Hash {
		t.Errorf("removed %v, want only orphan %v", removed, &orphan.Hash)
	}
	err = walletdb.View(ctx, db, func(dbtx walletdb.ReadTx) error {
		ns := dbtx.ReadBucket(wtxmgrBucketKey)
		for _, c := range []struct {
			name string
			rec  *TxRecord
			want bool
		}{
			{"incoming", incoming, true},
			{"ownSpend", ownSpend, true},
			{"orphan", orphan, false},
		} {
			if got := existsRawUnmined(ns, c.rec.Hash[:]) != nil; got != c.want {
				t.Errorf("%s unmined = %v, want %v", c.name, got, c.want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
