// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package udb

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/monetarium/monetarium-node/blockchain/stake"
	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/txscript"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// TestSSFeeMatured checks the SSFee maturity boundary per network: ticket
// change maturity on mainnet and testnet, coinbase maturity for an output of
// a tx with an expiry and on networks where the treasury agenda can activate.
func TestSSFeeMatured(t *testing.T) {
	const h = 100
	tests := []struct {
		params    *chaincfg.Params
		hasExpiry bool
		maturity  uint16
	}{
		{chaincfg.MainNetParams(), false, chaincfg.MainNetParams().SStxChangeMaturity},
		{chaincfg.TestNet3Params(), false, chaincfg.TestNet3Params().SStxChangeMaturity},
		{chaincfg.MainNetParams(), true, chaincfg.MainNetParams().CoinbaseMaturity},
		{chaincfg.TestNet3Params(), true, chaincfg.TestNet3Params().CoinbaseMaturity},
		{chaincfg.SimNetParams(), false, chaincfg.SimNetParams().CoinbaseMaturity},
		{chaincfg.RegNetParams(), false, chaincfg.RegNetParams().CoinbaseMaturity},
	}
	for _, test := range tests {
		m := int32(test.maturity)
		if SSFeeMatured(test.params, test.hasExpiry, h, h+m-1) {
			t.Errorf("%s expiry=%v: mature at tip %d", test.params.Name, test.hasExpiry, h+m-1)
		}
		if !SSFeeMatured(test.params, test.hasExpiry, h, h+m) {
			t.Errorf("%s expiry=%v: immature at tip %d", test.params.Name, test.hasExpiry, h+m)
		}
	}
	if SSFeeMatured(chaincfg.MainNetParams(), false, -1, h) {
		t.Error("unmined SSFee output is mature")
	}
}

// TestSSFeeCreditMaturity checks input selection and balances for OP_SSGEN
// credits on testnet (ticket change maturity 1, coinbase maturity 16): an
// SSFee output is spendable at the ticket change boundary, while an SSFee
// output with an expiry and a non-SSFee (vote) output wait for coinbase
// maturity.
func TestSSFeeCreditMaturity(t *testing.T) {
	for _, ct := range []cointype.CoinType{cointype.CoinTypeVAR, cointype.CoinType(1)} {
		t.Run(ct.String(), func(t *testing.T) {
			testSSFeeCreditMaturity(t, ct)
		})
	}
}

func testSSFeeCreditMaturity(t *testing.T, ct cointype.CoinType) {
	ctx := context.Background()
	db, _, s, teardown, err := cloneDB(ctx, "ssfee_maturity_"+ct.String()+".kv")
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
	txOut := func(v int64, pkScript []byte) *wire.TxOut {
		if ct.IsSKA() {
			return wire.NewTxOutSKA(big.NewInt(v), ct, pkScript)
		}
		return wire.NewTxOut(v, pkScript)
	}
	newRec := func(prev wire.OutPoint, expiry uint32, outs ...*wire.TxOut) *TxRecord {
		tx := wire.NewMsgTx()
		tx.Version = wire.TxVersionTreasury // SSFee needs version 3
		tx.Expiry = expiry
		tx.AddTxIn(wire.NewTxIn(&prev, 0, nil))
		for _, out := range outs {
			tx.AddTxOut(out)
		}
		rec, err := NewTxRecordFromMsgTx(tx, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	null := wire.OutPoint{Index: wire.MaxPrevOutIndex, Tree: wire.TxTreeStake}
	ssfee := newRec(null, 0, txOut(0, stake.CreateStakerSSFeeMarker(1, 0)), txOut(1e8, ssgenScript))
	ssfeeExpiry := newRec(null, 10, txOut(0, stake.CreateStakerSSFeeMarker(1, 1)), txOut(2e8, ssgenScript))
	vote := newRec(wire.OutPoint{Hash: chainhash.Hash{0x01}, Tree: wire.TxTreeStake}, 0,
		txOut(4e8, ssgenScript))
	type credit struct {
		rec   *TxRecord
		index uint32
	}
	credits := []credit{{ssfee, 1}, {ssfeeExpiry, 1}, {vote, 0}}
	early := []*TxRecord{ssfee}
	if ct.IsSKA() {
		// A miner SSFee is SKA only.
		mf := newRec(null, 0, txOut(0, stake.CreateMinerSSFeeMarker(1)), txOut(8e8, ssgenScript))
		credits = append(credits, credit{mf, 1})
		early = append(early, mf)
	}
	for _, c := range credits {
		if c.rec != vote && c.rec.TxType != stake.TxTypeSSFee {
			t.Fatalf("%v has type %v, want SSFee", c.rec.Hash, c.rec.TxType)
		}
	}

	g := makeBlockGenerator()
	b1 := g.generate(dcrutil.BlockValid)
	err = walletdb.Update(ctx, db, func(dbtx walletdb.ReadWriteTx) error {
		err := insertMainChainHeaders(s, dbtx, makeHeaderDataSlice(b1), emptyFilters(1))
		if err != nil {
			return err
		}
		b1Hash := b1.BlockHash()
		for _, c := range credits {
			if err := s.InsertMinedTx(dbtx, c.rec, &b1Hash); err != nil {
				return err
			}
			if err := s.AddCredit(dbtx, c.rec, makeBlockMeta(b1), c.index, false, 0); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// extendTo mines empty blocks up to height tip.
	extendTo := func(tip int32) {
		var headers []*wire.BlockHeader
		for g.lastHeight < tip {
			headers = append(headers, g.generate(dcrutil.BlockValid))
		}
		err := walletdb.Update(ctx, db, func(dbtx walletdb.ReadWriteTx) error {
			return insertMainChainHeaders(s, dbtx, makeHeaderDataSlice(headers...),
				emptyFilters(len(headers)))
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// check compares the selected inputs and the spendable balances at the
	// current tip with the wanted credits.
	check := func(want ...*TxRecord) {
		t.Helper()
		var wantSum int64
		wantOps := make(map[chainhash.Hash]bool)
		for _, rec := range want {
			wantOps[rec.Hash] = true
			for _, out := range rec.MsgTx.TxOut {
				if ct.IsSKA() {
					wantSum += out.SKAValue.Int64()
				} else {
					wantSum += out.Value
				}
			}
		}
		spendable := func(b CoinBalance) int64 {
			if ct.IsSKA() {
				return b.SKASpendable.BigInt().Int64()
			}
			return int64(b.Spendable)
		}
		tip := g.lastHeight
		err := walletdb.View(ctx, db, func(dbtx walletdb.ReadTx) error {
			src := s.MakeInputSourceWithCoinType(dbtx, 0, 1, tip, nil, ct)
			detail, err := src.SelectInputs(0, cointype.Zero())
			if err != nil {
				return err
			}
			gotOps := make(map[chainhash.Hash]bool)
			for _, in := range detail.Inputs {
				gotOps[in.PreviousOutPoint.Hash] = true
			}
			if len(gotOps) != len(wantOps) {
				t.Errorf("tip %d: selected %d credits, want %d", tip, len(gotOps), len(wantOps))
			}
			for h := range wantOps {
				if !gotOps[h] {
					t.Errorf("tip %d: credit of %v not selected", tip, h)
				}
			}

			all, err := s.AccountBalances(dbtx, 1)
			if err != nil {
				return err
			}
			if got := spendable(all[0].CoinTypeBalances[ct]); got != wantSum {
				t.Errorf("tip %d: AccountBalances spendable %d, want %d", tip, got, wantSum)
			}
			one, err := s.AccountBalanceByCoinType(dbtx, 1, 0, ct)
			if err != nil {
				return err
			}
			if got := spendable(one); got != wantSum {
				t.Errorf("tip %d: AccountBalanceByCoinType spendable %d, want %d", tip, got, wantSum)
			}
			for _, c := range credits {
				cred := &Credit{
					OutPoint:  wire.OutPoint{Hash: c.rec.Hash, Index: c.index},
					BlockMeta: *makeBlockMeta(b1),
					HasExpiry: c.rec.MsgTx.Expiry != 0,
				}
				if got := s.StakeGenMatured(dbtx, cred, tip); got != wantOps[c.rec.Hash] {
					t.Errorf("tip %d: StakeGenMatured(%v) = %v", tip, c.rec.Hash, got)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	ticketChange := int32(s.chainParams.SStxChangeMaturity)
	coinbase := int32(s.chainParams.CoinbaseMaturity)

	extendTo(1 + ticketChange - 1)
	check()
	extendTo(1 + ticketChange)
	check(early...)
	extendTo(1 + coinbase - 1)
	check(early...)
	extendTo(1 + coinbase)
	var all []*TxRecord
	for _, c := range credits {
		all = append(all, c.rec)
	}
	check(all...)
}
