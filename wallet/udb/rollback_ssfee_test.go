// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package udb

import (
	"context"
	"testing"
	"time"

	"github.com/monetarium/monetarium-node/blockchain/stake"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/txscript"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// TestPruneUnminedRemovesDetachedSSFee checks that PruneUnmined removes the
// SSFee transactions a rollback detached, which can never be mined again,
// together with the unmined transactions spending them, and gives back the
// credits they spent.  The chain before the rollback to height 2:
//   - b1: fund pays the wallet; ssfeeKept is an SSFee paying the wallet;
//   - b2: ssfee is an SSFee paying the wallet; augment augments ssfeeKept;
//   - b3: child spends ssfee and fund; aug2 augments augment;
//   - b4: spendAug spends aug2.
//
// With remine, a header-only prune runs first and must keep every SSFee, since
// the new chain's transactions are not recorded yet.  Then siblings of b2 and
// b3 mine augment and aug2 again, and spendAug, the wallet's spend of aug2,
// stays unmined.
//
// The test is VAR only: restoring a spent SKA credit on rollback is #19.
func TestPruneUnminedRemovesDetachedSSFee(t *testing.T) {
	for _, remine := range []bool{false, true} {
		name := "detached"
		if remine {
			name = "remined"
		}
		t.Run(name, func(t *testing.T) {
			testPruneUnminedRemovesDetachedSSFee(t, remine)
		})
	}
}

func testPruneUnminedRemovesDetachedSSFee(t *testing.T, remine bool) {
	ctx := context.Background()
	db, _, s, teardown, err := cloneDB(ctx, "prune_detached_ssfee.kv")
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	addr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(make([]byte, 20), s.chainParams)
	if err != nil {
		t.Fatal(err)
	}
	_, p2pkh := addr.PaymentScript()
	ssgenScript := append([]byte{txscript.OP_SSGEN}, p2pkh...)
	newRec := func(version uint16, ins []wire.OutPoint, outs ...*wire.TxOut) *TxRecord {
		tx := wire.NewMsgTx()
		tx.Version = version
		for i := range ins {
			tx.AddTxIn(wire.NewTxIn(&ins[i], 0, nil))
		}
		for _, out := range outs {
			tx.AddTxOut(out)
		}
		rec, err := NewTxRecordFromMsgTx(tx, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	op := func(rec *TxRecord, index uint32, tree int8) wire.OutPoint {
		return wire.OutPoint{Hash: rec.Hash, Index: index, Tree: tree}
	}

	nullIn := []wire.OutPoint{{Index: wire.MaxPrevOutIndex, Tree: wire.TxTreeStake}}
	fund := newRec(1, []wire.OutPoint{{Hash: chainhash.Hash{0x01}}}, wire.NewTxOut(5e8, p2pkh))
	ssfeeKept := newRec(wire.TxVersionTreasury, nullIn,
		wire.NewTxOut(0, stake.CreateStakerSSFeeMarker(1, 0)), wire.NewTxOut(3e8, ssgenScript))
	ssfee := newRec(wire.TxVersionTreasury, nullIn,
		wire.NewTxOut(0, stake.CreateStakerSSFeeMarker(2, 0)), wire.NewTxOut(1e8, ssgenScript))
	augment := newRec(wire.TxVersionTreasury, []wire.OutPoint{op(ssfeeKept, 1, wire.TxTreeStake)},
		wire.NewTxOut(0, stake.CreateStakerSSFeeMarker(2, 1)), wire.NewTxOut(4e8, ssgenScript))
	child := newRec(1, []wire.OutPoint{op(ssfee, 1, wire.TxTreeStake), op(fund, 0, wire.TxTreeRegular)},
		wire.NewTxOut(6e8, p2pkh))
	aug2 := newRec(wire.TxVersionTreasury, []wire.OutPoint{op(augment, 1, wire.TxTreeStake)},
		wire.NewTxOut(0, stake.CreateStakerSSFeeMarker(3, 0)), wire.NewTxOut(5e8, ssgenScript))
	spendAug := newRec(1, []wire.OutPoint{op(aug2, 1, wire.TxTreeStake)}, wire.NewTxOut(5e8, p2pkh))
	for _, rec := range []*TxRecord{ssfeeKept, ssfee, augment, aug2} {
		if rec.TxType != stake.TxTypeSSFee {
			t.Fatalf("%v has type %v, want SSFee", &rec.Hash, rec.TxType)
		}
	}

	g := makeBlockGenerator()
	var headers []*wire.BlockHeader
	for i := 0; i < 4; i++ {
		headers = append(headers, g.generate(dcrutil.BlockValid))
	}
	var pruned []*chainhash.Hash
	err = walletdb.Update(ctx, db, func(dbtx walletdb.ReadWriteTx) error {
		err := insertMainChainHeaders(s, dbtx, makeHeaderDataSlice(headers...), emptyFilters(4))
		if err != nil {
			return err
		}
		mine := func(b *wire.BlockHeader, rec *TxRecord, credit uint32) error {
			h := b.BlockHash()
			if err := s.InsertMinedTx(dbtx, rec, &h); err != nil {
				return err
			}
			return s.AddCredit(dbtx, rec, makeBlockMeta(b), credit, false, 0)
		}
		for _, m := range []struct {
			b      *wire.BlockHeader
			rec    *TxRecord
			credit uint32
		}{
			{headers[0], fund, 0}, {headers[0], ssfeeKept, 1},
			{headers[1], ssfee, 1}, {headers[1], augment, 1},
			{headers[2], child, 0}, {headers[2], aug2, 1},
			{headers[3], spendAug, 0},
		} {
			if err := mine(m.b, m.rec, m.credit); err != nil {
				return err
			}
		}
		if err := s.Rollback(dbtx, 2); err != nil {
			return err
		}
		if remine {
			early, err := s.PruneUnmined(dbtx, 0, false)
			if err != nil {
				return err
			}
			if len(early) != 0 {
				t.Errorf("header-only prune removed %d transactions", len(early))
			}
			g = blockGenerator{lastHash: headers[0].BlockHash(), lastHeight: 1}
			b2 := g.generate(dcrutil.BlockValid | 1<<1)
			b3 := g.generate(dcrutil.BlockValid)
			err = insertMainChainHeaders(s, dbtx, makeHeaderDataSlice(b2, b3), emptyFilters(2))
			if err != nil {
				return err
			}
			if err := mine(b2, augment, 1); err != nil {
				return err
			}
			if err := mine(b3, aug2, 1); err != nil {
				return err
			}
		}
		pruned, err = s.PruneUnmined(dbtx, 0, true)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// PruneUnmined reports the SSFee transactions; their spenders go with
	// them through RemoveUnconfirmed, checked by the empty unmined bucket.
	wantPruned := []*TxRecord{ssfee, augment, aug2}
	var wantUnmined []*TxRecord
	wantUnspent := []*TxRecord{fund, ssfeeKept}
	wantBalance := dcrutil.Amount(5e8 + 3e8)
	if remine {
		wantPruned = []*TxRecord{ssfee}
		wantUnmined = []*TxRecord{spendAug}
		wantUnspent = []*TxRecord{fund, spendAug} // aug2:1 is spent by spendAug
		wantBalance = 5e8 + 5e8
	}
	gotPruned := make(map[chainhash.Hash]bool)
	for _, h := range pruned {
		gotPruned[*h] = true
	}
	if len(gotPruned) != len(wantPruned) {
		t.Errorf("pruned %d transactions, want %d", len(gotPruned), len(wantPruned))
	}
	for _, rec := range wantPruned {
		if !gotPruned[rec.Hash] {
			t.Errorf("%v not pruned", &rec.Hash)
		}
	}

	err = walletdb.View(ctx, db, func(dbtx walletdb.ReadTx) error {
		ns := dbtx.ReadBucket(wtxmgrBucketKey)
		// Each unmined transaction left has one input.
		for _, bucket := range [][]byte{bucketUnmined, bucketUnminedInputs} {
			n := 0
			c := ns.NestedReadBucket(bucket).ReadCursor()
			for k, _ := c.First(); k != nil; k, _ = c.Next() {
				n++
			}
			c.Close()
			if n != len(wantUnmined) {
				t.Errorf("bucket %q has %d keys, want %d", bucket, n, len(wantUnmined))
			}
		}
		for _, rec := range wantUnmined {
			if existsRawUnmined(ns, rec.Hash[:]) == nil {
				t.Errorf("%v is no longer unmined", &rec.Hash)
			}
		}
		balance, err := fetchMinedBalance(ns)
		if err != nil {
			return err
		}
		if balance != wantBalance {
			t.Errorf("mined balance %v, want %v", balance, wantBalance)
		}
		utxos, err := s.UnspentOutputs(dbtx, cointype.CoinTypeVAR)
		if err != nil {
			return err
		}
		got := make(map[chainhash.Hash]bool)
		for _, u := range utxos {
			got[u.Hash] = true
		}
		if len(utxos) != len(wantUnspent) {
			t.Errorf("%d unspent outputs, want %d", len(utxos), len(wantUnspent))
		}
		for _, rec := range wantUnspent {
			if !got[rec.Hash] {
				t.Errorf("credit of %v is not unspent", &rec.Hash)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
