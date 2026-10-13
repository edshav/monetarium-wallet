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
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

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
