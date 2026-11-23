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

// TestRollbackRestoresSpentSKACredit checks that rolling back a block that
// holds a wallet SKA spend puts the spent SKA credit back into the unspent
// set. The SKA companion of TestPruneUnminedRemovesDetachedSSFee: an SKA
// credit stores 0 in its credit value, so the amount-zero shortcut took
// every SKA credit as already removed, and the spent credit was never put
// back into the unspent set.
//
// Since c41bb4bb, main keeps the rolled-back spend itself: hasValidInputs
// counts an input as double-spent only when its credit carries the spent
// flag, and unspendRawCredit clears that flag for SKA credits too. The
// damage that remains is the credit missing from the unspent set:
//   - when the spend is mined again, existsUnspent finds no entry for the
//     credit, so no debit is recorded and the credit is never marked spent;
//   - when the spend instead leaves the wallet unmined (for example it is
//     abandoned), the credit never comes back, and its SKA amount drops out
//     of the balance and coin selection for good.
//
// The chain before the rollback:
//   - b1: skaFund pays the wallet a 9 SKA credit;
//   - b2: skaSpend spends it and pays an 8.5 SKA change to the wallet.
//
// After the rollback to keep only b1, skaSpend is unmined and spends
// skaFund:0. The unspent set then holds the fund credit, held by the
// unmined spend, next to the spend's change. Removing the unmined spend
// afterwards (for example, abandoning it) leaves the fund credit as the
// only unspent output, with its SKA amount and coin type intact.
func TestRollbackRestoresSpentSKACredit(t *testing.T) {
	ctx := context.Background()
	db, _, s, teardown, err := cloneDB(ctx, "rollback_ska_credit.kv")
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	skaType := cointype.CoinType(1)
	addr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(make([]byte, 20), s.chainParams)
	if err != nil {
		t.Fatal(err)
	}
	_, p2pkh := addr.PaymentScript()
	skaOut := func(v int64) *wire.TxOut {
		return wire.NewTxOutSKA(big.NewInt(v), skaType, p2pkh)
	}
	newRec := func(ins []wire.OutPoint, outs ...*wire.TxOut) *TxRecord {
		tx := wire.NewMsgTx()
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
	op := func(rec *TxRecord, index uint32) wire.OutPoint {
		return wire.OutPoint{Hash: rec.Hash, Index: index, Tree: wire.TxTreeRegular}
	}

	skaFund := newRec([]wire.OutPoint{{Hash: chainhash.Hash{0x01}}}, skaOut(9e8))
	skaSpend := newRec([]wire.OutPoint{op(skaFund, 0)}, skaOut(85e7))

	g := makeBlockGenerator()
	headers := []*wire.BlockHeader{g.generate(dcrutil.BlockValid), g.generate(dcrutil.BlockValid)}

	var pruned []*chainhash.Hash
	err = walletdb.Update(ctx, db, func(dbtx walletdb.ReadWriteTx) error {
		err := insertMainChainHeaders(s, dbtx, makeHeaderDataSlice(headers...), emptyFilters(2))
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
		if err := mine(headers[0], skaFund, 0); err != nil {
			return err
		}
		if err := mine(headers[1], skaSpend, 0); err != nil {
			return err
		}
		// A longer chain without b2 arrives: drop b2. skaSpend becomes
		// unmined, and the credit it spent must return to the unspent
		// set so PruneUnmined keeps seeing the spend's input.
		if err := s.Rollback(dbtx, 2); err != nil {
			return err
		}
		pruned, err = s.PruneUnmined(dbtx, 0, 0, true)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, h := range pruned {
		if *h == skaSpend.Hash {
			t.Errorf("%v pruned as orphaned, want it kept unmined", &skaSpend.Hash)
		}
	}

	err = walletdb.View(ctx, db, func(dbtx walletdb.ReadTx) error {
		ns := dbtx.ReadBucket(wtxmgrBucketKey)
		if existsRawUnmined(ns, skaSpend.Hash[:]) == nil {
			t.Errorf("%v is no longer unmined", &skaSpend.Hash)
		}
		utxos, err := s.UnspentOutputs(dbtx, skaType)
		if err != nil {
			return err
		}
		if len(utxos) != 1 {
			t.Errorf("%d unspent outputs, want 1 (the unmined change)", len(utxos))
			return nil
		}
		if utxos[0].Hash != skaSpend.Hash || utxos[0].Index != 0 {
			t.Errorf("unspent output %v:%d, want the change of %v:0",
				&utxos[0].Hash, utxos[0].Index, &skaSpend.Hash)
		}
		if utxos[0].SKAAmount.Cmp(cointype.SKAAmountFromInt64(85e7)) != 0 {
			t.Errorf("change SKAAmount %v, want 8.5 SKA (85e7 atoms)",
				utxos[0].SKAAmount)
		}
		if utxos[0].CoinType != skaType {
			t.Errorf("change CoinType %v, want %v", utxos[0].CoinType, skaType)
		}
		// The spent credit is back in the unspent set, held by the
		// unmined spend: the spend's input must not look orphaned.
		credKey := keyCredit(&skaFund.Hash, 0, &makeBlockMeta(headers[0]).Block)
		if existsRawCredit(ns, credKey) == nil {
			t.Errorf("credit of %v is gone from the credits bucket", &skaFund.Hash)
		}
		fundOp := canonicalOutPoint(&skaFund.Hash, 0)
		if existsRawUnspent(ns, fundOp, s.chainParams) == nil {
			t.Errorf("credit of %v is not in the unspent set after the rollback", &skaFund.Hash)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The user-visible consequence: once the unmined spend is removed —
	// for example when it is abandoned — the fund credit comes back as
	// the only unspent output, with its SKA amount and coin type intact.
	err = walletdb.Update(ctx, db, func(dbtx walletdb.ReadWriteTx) error {
		ns := dbtx.ReadWriteBucket(wtxmgrBucketKey)
		return s.RemoveUnconfirmed(ns, &skaSpend.MsgTx, &skaSpend.Hash)
	})
	if err != nil {
		t.Fatal(err)
	}

	err = walletdb.View(ctx, db, func(dbtx walletdb.ReadTx) error {
		utxos, err := s.UnspentOutputs(dbtx, skaType)
		if err != nil {
			return err
		}
		if len(utxos) != 1 || utxos[0].Hash != skaFund.Hash || utxos[0].Index != 0 {
			t.Errorf("after RemoveUnconfirmed: %d unspent outputs, want the fund "+
				"credit %v:0", len(utxos), &skaFund.Hash)
			return nil
		}
		if utxos[0].SKAAmount.Cmp(cointype.SKAAmountFromInt64(9e8)) != 0 {
			t.Errorf("fund credit SKAAmount %v, want 9 SKA (9e8 atoms)",
				utxos[0].SKAAmount)
		}
		if utxos[0].CoinType != skaType {
			t.Errorf("fund credit CoinType %v, want %v", utxos[0].CoinType, skaType)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestRollbackReminedSpendRecordsDebit checks the re-mine half of the
// rollback story.  Rolling back b2 makes the spend unmined and puts the
// spent fund credit back into the unspent set.  Mining the spend again,
// the usual outcome of a reorg, must find the credit there: record the
// debit, mark the fund credit spent, and leave only the spend's change
// unspent.  Without the restored credit, existsUnspent finds no entry for
// the input, so no debit is recorded and the credit is never marked spent.
//
// The chain:
//   - b1: skaFund pays the wallet a 9 SKA credit;
//   - b2: skaSpend spends skaFund:0 and pays an 8.5 SKA change to the
//     wallet, rolled back and mined again in a sibling b2'.
func TestRollbackReminedSpendRecordsDebit(t *testing.T) {
	ctx := context.Background()
	db, _, s, teardown, err := cloneDB(ctx, "rollback_ska_remine.kv")
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	skaType := cointype.CoinType(1)
	addr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(make([]byte, 20), s.chainParams)
	if err != nil {
		t.Fatal(err)
	}
	_, p2pkh := addr.PaymentScript()
	skaOut := func(v int64) *wire.TxOut {
		return wire.NewTxOutSKA(big.NewInt(v), skaType, p2pkh)
	}
	newRec := func(ins []wire.OutPoint, outs ...*wire.TxOut) *TxRecord {
		tx := wire.NewMsgTx()
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
	op := func(rec *TxRecord, index uint32) wire.OutPoint {
		return wire.OutPoint{Hash: rec.Hash, Index: index, Tree: wire.TxTreeRegular}
	}

	skaFund := newRec([]wire.OutPoint{{Hash: chainhash.Hash{0x01}}}, skaOut(9e8))
	skaSpend := newRec([]wire.OutPoint{op(skaFund, 0)}, skaOut(85e7))

	g := makeBlockGenerator()
	headers := []*wire.BlockHeader{g.generate(dcrutil.BlockValid), g.generate(dcrutil.BlockValid)}

	err = walletdb.Update(ctx, db, func(dbtx walletdb.ReadWriteTx) error {
		err := insertMainChainHeaders(s, dbtx, makeHeaderDataSlice(headers...), emptyFilters(2))
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
		if err := mine(headers[0], skaFund, 0); err != nil {
			return err
		}
		if err := mine(headers[1], skaSpend, 0); err != nil {
			return err
		}
		// A longer chain without b2 arrives: drop b2.  The spend becomes
		// unmined and the credit it spent returns to the unspent set.
		if err := s.Rollback(dbtx, 2); err != nil {
			return err
		}
		// The spend mines again in a sibling block at height 2.
		g = blockGenerator{lastHash: headers[0].BlockHash(), lastHeight: 1}
		b2re := g.generate(dcrutil.BlockValid)
		err = insertMainChainHeaders(s, dbtx, makeHeaderDataSlice(b2re), emptyFilters(1))
		if err != nil {
			return err
		}
		return mine(b2re, skaSpend, 0)
	})
	if err != nil {
		t.Fatal(err)
	}

	err = walletdb.View(ctx, db, func(dbtx walletdb.ReadTx) error {
		ns := dbtx.ReadBucket(wtxmgrBucketKey)
		// The re-mined spend records its debit on the fund credit.
		detSpend, err := s.TxDetails(ns, &skaSpend.Hash)
		if err != nil {
			return err
		}
		if len(detSpend.Debits) != 1 {
			t.Errorf("re-mined spend has %d debits, want 1 (the fund credit)",
				len(detSpend.Debits))
		} else {
			d := detSpend.Debits[0]
			if d.Index != 0 {
				t.Errorf("debit input index %d, want 0", d.Index)
			}
			if d.SKAAmount.Cmp(cointype.SKAAmountFromInt64(9e8)) != 0 {
				t.Errorf("debit SKAAmount %v, want 9 SKA (9e8 atoms)", d.SKAAmount)
			}
			if d.CoinType != skaType {
				t.Errorf("debit CoinType %v, want %v", d.CoinType, skaType)
			}
		}
		// The funding tx marks its credit spent again.
		detFund, err := s.TxDetails(ns, &skaFund.Hash)
		if err != nil {
			return err
		}
		if len(detFund.Credits) != 1 {
			t.Errorf("fund tx has %d credits, want 1", len(detFund.Credits))
			return nil
		}
		if !detFund.Credits[0].Spent {
			t.Errorf("fund credit is not marked spent after the re-mine")
		}
		// The unspent set holds only the spend's change; the fund credit
		// is spent, not unspent.
		utxos, err := s.UnspentOutputs(dbtx, skaType)
		if err != nil {
			return err
		}
		if len(utxos) != 1 || utxos[0].Hash != skaSpend.Hash || utxos[0].Index != 0 {
			t.Errorf("%d unspent outputs, want the change %v:0",
				len(utxos), &skaSpend.Hash)
			return nil
		}
		if utxos[0].SKAAmount.Cmp(cointype.SKAAmountFromInt64(85e7)) != 0 {
			t.Errorf("change SKAAmount %v, want 8.5 SKA (85e7 atoms)",
				utxos[0].SKAAmount)
		}
		fundOp := canonicalOutPoint(&skaFund.Hash, 0)
		if existsRawUnspent(ns, fundOp, s.chainParams) != nil {
			t.Errorf("credit of %v is in the unspent set after the re-mine",
				&skaFund.Hash)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestRollbackSameBlockFundAndSpend checks the existence check's own job
// in Rollback: a credit removed earlier in the same rollback is not put
// back into the unspent set.  A funding transaction and its spend mined
// in the same block are ordinary — for example a send that spends another
// wallet transaction's unmined change at minconf 0 — and both leave the
// wallet together when the block is rolled back.  Transactions are removed
// in block order, so the fund's credit is detached (and deleted) before
// the spend records its input: the spend's credit comes from the removed
// credits cache and no longer exists.  Putting it back anyway would leave
// an unspent entry pointing at a deleted credit, for VAR and SKA alike.
//
// The chain:
//   - b1: no wallet transactions;
//   - b2: fund pays the wallet a 9 credit, spend spends fund:0 and pays
//     an 8 credit change to the wallet; both rolled back together.
func TestRollbackSameBlockFundAndSpend(t *testing.T) {
	for _, ska := range []bool{false, true} {
		name := "var"
		if ska {
			name = "ska1"
		}
		t.Run(name, func(t *testing.T) {
			testRollbackSameBlockFundAndSpend(t, ska)
		})
	}
}

func testRollbackSameBlockFundAndSpend(t *testing.T, ska bool) {
	ctx := context.Background()
	db, _, s, teardown, err := cloneDB(ctx, "rollback_same_block_fund_spend.kv")
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	coinType := cointype.CoinTypeVAR
	out := func(v int64) *wire.TxOut {
		addr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(make([]byte, 20), s.chainParams)
		if err != nil {
			t.Fatal(err)
		}
		_, p2pkh := addr.PaymentScript()
		if ska {
			coinType = cointype.CoinType(1)
			return wire.NewTxOutSKA(big.NewInt(v), coinType, p2pkh)
		}
		return wire.NewTxOut(v, p2pkh)
	}
	newRec := func(ins []wire.OutPoint, outs ...*wire.TxOut) *TxRecord {
		tx := wire.NewMsgTx()
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
	op := func(rec *TxRecord, index uint32) wire.OutPoint {
		return wire.OutPoint{Hash: rec.Hash, Index: index, Tree: wire.TxTreeRegular}
	}

	fund := newRec([]wire.OutPoint{{Hash: chainhash.Hash{0x01}}}, out(9e8))
	spend := newRec([]wire.OutPoint{op(fund, 0)}, out(8e8))

	g := makeBlockGenerator()
	headers := []*wire.BlockHeader{g.generate(dcrutil.BlockValid), g.generate(dcrutil.BlockValid)}

	err = walletdb.Update(ctx, db, func(dbtx walletdb.ReadWriteTx) error {
		err := insertMainChainHeaders(s, dbtx, makeHeaderDataSlice(headers...), emptyFilters(2))
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
		// Fund and spend land in the same block.
		if err := mine(headers[1], fund, 0); err != nil {
			return err
		}
		if err := mine(headers[1], spend, 0); err != nil {
			return err
		}
		// A longer chain without b2 arrives: drop b2, fund and spend with it.
		return s.Rollback(dbtx, 2)
	})
	if err != nil {
		t.Fatal(err)
	}

	err = walletdb.View(ctx, db, func(dbtx walletdb.ReadTx) error {
		ns := dbtx.ReadBucket(wtxmgrBucketKey)
		// Neither credit is in the unspent set: the fund's credit was
		// detached earlier in the same rollback and no longer exists,
		// and the spend's change is an unmined credit.
		fundOp := canonicalOutPoint(&fund.Hash, 0)
		if existsRawUnspent(ns, fundOp, s.chainParams) != nil {
			t.Errorf("credit of %v is in the unspent set, but it was removed "+
				"earlier in the same rollback", &fund.Hash)
		}
		spendOp := canonicalOutPoint(&spend.Hash, 0)
		if existsRawUnspent(ns, spendOp, s.chainParams) != nil {
			t.Errorf("change of %v is in the unspent set, want it unmined",
				&spend.Hash)
		}
		// Both transactions are unmined with unmined credits.
		if existsRawUnmined(ns, fund.Hash[:]) == nil {
			t.Errorf("%v is not unmined", &fund.Hash)
		}
		if existsRawUnmined(ns, spend.Hash[:]) == nil {
			t.Errorf("%v is not unmined", &spend.Hash)
		}
		if existsRawUnminedCredit(ns, fundOp, s.chainParams) == nil {
			t.Errorf("credit of %v has no unmined credit", &fund.Hash)
		}
		if existsRawUnminedCredit(ns, spendOp, s.chainParams) == nil {
			t.Errorf("change of %v has no unmined credit", &spend.Hash)
		}
		// The fund's mined credit is gone; it was detached with b2.
		credKey := keyCredit(&fund.Hash, 0, &makeBlockMeta(headers[1]).Block)
		if existsRawCredit(ns, credKey) != nil {
			t.Errorf("credit of %v is still in the credits bucket after the "+
				"rollback", &fund.Hash)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
