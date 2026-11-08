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
	"github.com/monetarium/monetarium-node/txscript"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/wallet/txauthor"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// TestInputSourceSelectsEveryEligibleOutput checks that input selection with
// a target returns every eligible output the target needs, each once, and no
// other.  With minconf above zero it picks outputs at random first, then
// reads the rest: the random walk must not give up while eligible outputs
// remain, and both parts must apply the same filters.
func TestInputSourceSelectsEveryEligibleOutput(t *testing.T) {
	for _, ct := range []cointype.CoinType{cointype.CoinTypeVAR, cointype.CoinType(1)} {
		t.Run(ct.String(), func(t *testing.T) {
			testInputSourceSelectsEveryEligibleOutput(t, ct)
		})
	}
}

func testInputSourceSelectsEveryEligibleOutput(t *testing.T, ct cointype.CoinType) {
	ctx := context.Background()
	db, _, s, teardown, err := cloneDB(ctx, "inputsource_eligible_"+ct.String()+".kv")
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	addr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(make([]byte, 20), s.chainParams)
	if err != nil {
		t.Fatal(err)
	}
	_, pkScript := addr.PaymentScript()
	out := func(v int64, script []byte) *wire.TxOut {
		if ct.IsSKA() {
			return wire.NewTxOutSKA(big.NewInt(v), ct, script)
		}
		return wire.NewTxOut(v, script)
	}
	stake := func(opcode byte) []byte { return append([]byte{opcode}, pkScript...) }
	newRec := func(prev wire.OutPoint, outs ...*wire.TxOut) *TxRecord {
		tx := wire.NewMsgTx()
		tx.AddTxIn(wire.NewTxIn(&prev, 0, nil))
		for _, o := range outs {
			tx.AddTxOut(o)
		}
		rec, err := NewTxRecordFromMsgTx(tx, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	prev := func(n byte) wire.OutPoint {
		return wire.OutPoint{Hash: chainhash.Hash{n}, Tree: wire.TxTreeRegular}
	}
	op := func(rec *TxRecord, i uint32) wire.OutPoint {
		return wire.OutPoint{Hash: rec.Hash, Index: i, Tree: wire.TxTreeRegular}
	}
	coin := out(1e8, pkScript)

	// Credits of 1e8 in account 0, mined in block 1 (two confirmations at
	// tip 2) unless noted.  Five are eligible at both minconf 1 and 2, two of
	// them outputs of one tx.  Each of the others fails one filter.
	single := []*TxRecord{newRec(prev(1), coin), newRec(prev(2), coin), newRec(prev(3), coin)}
	pair := newRec(prev(4), coin, coin)
	unconfirmed := newRec(prev(6), coin) // block 2: eligible at minconf 1 only
	ineligible := []*TxRecord{
		newRec(wire.OutPoint{Index: wire.MaxPrevOutIndex}, coin), // immature coinbase
		newRec(prev(7), coin),                                // ignored
		newRec(prev(8), coin),                                // spent by an unmined tx
		newRec(prev(10), out(1e8, stake(txscript.OP_SSTX))),  // ticket
		newRec(prev(11), out(1e8, stake(txscript.OP_SSGEN))), // immature vote
		newRec(prev(12), out(1e8, stake(txscript.OP_TGEN))),  // immature treasury spend
		newRec(prev(13), out(1e8, []byte{txscript.OP_TRUE})), // unknown script class
	}
	ignored, spentUnmined := ineligible[1], ineligible[2]
	if !ct.IsSKA() {
		// AddCredit refuses an SKA credit of zero, so only VAR can store one.
		ineligible = append(ineligible, newRec(prev(9), out(0, pkScript)))
	}
	// A credit of the other coin type, in its own bucket.
	otherCoin := wire.NewTxOutSKA(big.NewInt(1e8), cointype.CoinType(1), pkScript)
	if ct.IsSKA() {
		otherCoin = wire.NewTxOut(1e8, pkScript)
	}
	ineligible = append(ineligible, newRec(prev(15), otherCoin))
	otherAcct := newRec(prev(5), coin)
	// Ticket change needs more than SStxChangeMaturity (1) confirmations, so
	// only minconf 1 can reach its check: block 2, one confirmation.
	ticketChange := newRec(prev(14), out(1e8, stake(txscript.OP_SSTXCHANGE)))
	spender := newRec(op(spentUnmined, 0), coin)

	eligible := map[wire.OutPoint]bool{op(pair, 0): true, op(pair, 1): true}
	for _, rec := range single {
		eligible[op(rec, 0)] = true
	}
	ignore := func(o *wire.OutPoint) bool { return *o == op(ignored, 0) }

	g := makeBlockGenerator()
	b1 := g.generate(dcrutil.BlockValid)
	b2 := g.generate(dcrutil.BlockValid)
	err = walletdb.Update(ctx, db, func(dbtx walletdb.ReadWriteTx) error {
		err := insertMainChainHeaders(s, dbtx, makeHeaderDataSlice(b1, b2), emptyFilters(2))
		if err != nil {
			return err
		}
		add := func(b *wire.BlockHeader, rec *TxRecord, account uint32) error {
			h := b.BlockHash()
			if err := s.InsertMinedTx(dbtx, rec, &h); err != nil {
				return err
			}
			for i := range rec.MsgTx.TxOut {
				if err := s.AddCredit(dbtx, rec, makeBlockMeta(b), uint32(i), false, account); err != nil {
					return err
				}
			}
			return nil
		}
		for _, rec := range append(append(single, pair), ineligible...) {
			if err := add(b1, rec, 0); err != nil {
				return err
			}
		}
		if err := add(b1, otherAcct, 1); err != nil {
			return err
		}
		for _, rec := range []*TxRecord{unconfirmed, ticketChange} {
			if err := add(b2, rec, 0); err != nil {
				return err
			}
		}
		return s.InsertMemPoolTx(dbtx, spender)
	})
	if err != nil {
		t.Fatal(err)
	}

	// The target needs every eligible credit, and the random part takes at
	// most half of the outputs, so most selections go on to the full read
	// and its filters and dedup.  The old walk came back short in 0.06-0.7%
	// of selections over this set; TestSelectInputsReachesTarget, with fewer
	// outputs, catches that reliably.
	for _, minConf := range []int32{2, 1} {
		want := make(map[wire.OutPoint]bool)
		for o := range eligible {
			want[o] = true
		}
		if minConf == 1 {
			want[op(unconfirmed, 0)] = true
		}
		total := int64(len(want)) * 1e8
		err = walletdb.View(ctx, db, func(dbtx walletdb.ReadTx) error {
			for run := 0; run < 2000; run++ {
				src := s.MakeInputSourceWithCoinType(dbtx, 0, minConf, 2, ignore, ct)
				var detail *txauthor.InputDetail
				var err error
				if ct.IsSKA() {
					detail, err = src.SelectInputs(0, cointype.NewSKAAmount(big.NewInt(total-1)))
				} else {
					detail, err = src.SelectInputs(dcrutil.Amount(total-1), cointype.Zero())
				}
				if err != nil {
					return err
				}
				got := make(map[wire.OutPoint]bool)
				for _, in := range detail.Inputs {
					o := in.PreviousOutPoint
					if !want[o] || got[o] {
						t.Fatalf("minconf %d run %d: selected %v, which is ineligible or repeated",
							minConf, run, o)
					}
					got[o] = true
					if ct.IsSKA() && (in.ValueIn != 0 || in.SKAValueIn == nil ||
						in.SKAValueIn.Cmp(big.NewInt(1e8)) != 0) {
						t.Fatalf("minconf %d run %d: input value %d, SKA value %v, want 0 and 1e8",
							minConf, run, in.ValueIn, in.SKAValueIn)
					}
				}
				if len(got) != len(want) {
					t.Fatalf("minconf %d run %d: selected %d inputs, want %d",
						minConf, run, len(got), len(want))
				}
				if ct.IsSKA() {
					if detail.Amount != 0 || detail.SKAAmount.BigInt().Cmp(big.NewInt(total)) != 0 {
						t.Fatalf("minconf %d run %d: amount %v, SKA amount %v, want 0 and %d",
							minConf, run, detail.Amount, detail.SKAAmount, total)
					}
				} else if int64(detail.Amount) != total {
					t.Fatalf("minconf %d run %d: amount %v, want %d", minConf, run, detail.Amount, total)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestRandomUTXOFindsSoleEligibleOutput checks that the random walk returns an
// output whenever one is eligible, also when it is the only one: RandomUTXO
// must return it and input selection must select it, at minconf 2 with every
// other output one confirmation short.
func TestRandomUTXOFindsSoleEligibleOutput(t *testing.T) {
	for _, ct := range []cointype.CoinType{cointype.CoinTypeVAR, cointype.CoinType(1)} {
		t.Run(ct.String(), func(t *testing.T) {
			testRandomUTXOFindsSoleEligibleOutput(t, ct)
		})
	}
}

func testRandomUTXOFindsSoleEligibleOutput(t *testing.T, ct cointype.CoinType) {
	ctx := context.Background()
	db, _, s, teardown, err := cloneDB(ctx, "random_utxo_sole_"+ct.String()+".kv")
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	addr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(make([]byte, 20), s.chainParams)
	if err != nil {
		t.Fatal(err)
	}
	_, pkScript := addr.PaymentScript()
	newRec := func(n byte) *TxRecord {
		tx := wire.NewMsgTx()
		tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{n}}, 0, nil))
		if ct.IsSKA() {
			tx.AddTxOut(wire.NewTxOutSKA(big.NewInt(1e8), ct, pkScript))
		} else {
			tx.AddTxOut(wire.NewTxOut(1e8, pkScript))
		}
		rec, err := NewTxRecordFromMsgTx(tx, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}

	// One credit in block 1 and four in block 2, at tip 2.
	sole := newRec(1)
	want := wire.OutPoint{Hash: sole.Hash, Tree: wire.TxTreeRegular}
	g := makeBlockGenerator()
	b1 := g.generate(dcrutil.BlockValid)
	b2 := g.generate(dcrutil.BlockValid)
	err = walletdb.Update(ctx, db, func(dbtx walletdb.ReadWriteTx) error {
		err := insertMainChainHeaders(s, dbtx, makeHeaderDataSlice(b1, b2), emptyFilters(2))
		if err != nil {
			return err
		}
		add := func(b *wire.BlockHeader, rec *TxRecord) error {
			h := b.BlockHash()
			if err := s.InsertMinedTx(dbtx, rec, &h); err != nil {
				return err
			}
			return s.AddCredit(dbtx, rec, makeBlockMeta(b), 0, false, 0)
		}
		if err := add(b1, sole); err != nil {
			return err
		}
		for n := byte(2); n <= 5; n++ {
			if err := add(b2, newRec(n)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The coin-flip walk missed the sole output in about a quarter of calls.
	err = walletdb.View(ctx, db, func(dbtx walletdb.ReadTx) error {
		for run := 0; run < 300; run++ {
			c, err := s.RandomUTXO(dbtx, 2, 2, ct)
			if err != nil {
				return err
			}
			if c == nil || c.OutPoint != want {
				t.Fatalf("run %d: RandomUTXO returned %v, want %v", run, c, want)
			}

			src := s.MakeInputSourceWithCoinType(dbtx, 0, 2, 2, nil, ct)
			var detail *txauthor.InputDetail
			if ct.IsSKA() {
				detail, err = src.SelectInputs(0, cointype.NewSKAAmount(big.NewInt(1e8-1)))
			} else {
				detail, err = src.SelectInputs(1e8-1, cointype.Zero())
			}
			if err != nil {
				return err
			}
			if len(detail.Inputs) != 1 || detail.Inputs[0].PreviousOutPoint != want {
				t.Fatalf("run %d: selected %d inputs, want only %v", run, len(detail.Inputs), want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestInputSourceSkipsUnminedCreditsSpentByUnminedTx checks that minconf 0
// input selection does not pick an unmined credit that another unmined
// transaction already spends.
func TestInputSourceSkipsUnminedCreditsSpentByUnminedTx(t *testing.T) {
	for _, ct := range []cointype.CoinType{cointype.CoinTypeVAR, cointype.CoinType(1)} {
		t.Run(ct.String(), func(t *testing.T) {
			testInputSourceSkipsUnminedCreditsSpentByUnminedTx(t, ct)
		})
	}
}

func testInputSourceSkipsUnminedCreditsSpentByUnminedTx(t *testing.T, ct cointype.CoinType) {
	ctx := context.Background()
	db, _, s, teardown, err := cloneDB(ctx, "inputsource_unmined_spent_"+ct.String()+".kv")
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	addr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(make([]byte, 20), s.chainParams)
	if err != nil {
		t.Fatal(err)
	}
	_, pkScript := addr.PaymentScript()
	txOut := func(v int64, pkScript []byte) *wire.TxOut {
		if ct.IsSKA() {
			return wire.NewTxOutSKA(big.NewInt(v), ct, pkScript)
		}
		return wire.NewTxOut(v, pkScript)
	}

	funding := wire.NewMsgTx()
	funding.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{0x01}, 0, wire.TxTreeRegular), 3e8, nil))
	funding.AddTxOut(txOut(1e8, pkScript))
	funding.AddTxOut(txOut(1e8, pkScript))
	fundingRec, err := NewTxRecordFromMsgTx(funding, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	spender := wire.NewMsgTx()
	spender.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&fundingRec.Hash, 0, wire.TxTreeRegular), 1e8, nil))
	spender.AddTxOut(txOut(9e7, []byte{0x6a}))
	spenderRec, err := NewTxRecordFromMsgTx(spender, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	err = walletdb.Update(ctx, db, func(dbtx walletdb.ReadWriteTx) error {
		if err := s.InsertMemPoolTx(dbtx, fundingRec); err != nil {
			return err
		}
		for i := uint32(0); i < 2; i++ {
			if err := s.AddCredit(dbtx, fundingRec, nil, i, false, 0); err != nil {
				return err
			}
		}
		return s.InsertMemPoolTx(dbtx, spenderRec)
	})
	if err != nil {
		t.Fatal(err)
	}

	err = walletdb.View(ctx, db, func(dbtx walletdb.ReadTx) error {
		src := s.MakeInputSourceWithCoinType(dbtx, 0, 0, 0, nil, ct)
		detail, err := src.SelectInputs(0, cointype.Zero())
		if err != nil {
			return err
		}
		var got []wire.OutPoint
		for _, in := range detail.Inputs {
			got = append(got, in.PreviousOutPoint)
		}
		want := wire.OutPoint{Hash: fundingRec.Hash, Index: 1, Tree: wire.TxTreeRegular}
		if len(got) != 1 || got[0] != want {
			t.Errorf("selected %v, want only %v", got, want)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
