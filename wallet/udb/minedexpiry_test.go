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

// TestMinedCreditKeepsExpiry checks that a credit of a transaction with an
// expiry, recorded unmined and then mined, keeps its expiry flag: mond requires
// coinbase maturity to spend it.
func TestMinedCreditKeepsExpiry(t *testing.T) {
	for _, ct := range []cointype.CoinType{cointype.CoinTypeVAR, cointype.CoinType(1)} {
		t.Run(ct.String(), func(t *testing.T) {
			testMinedCreditKeepsExpiry(t, ct)
		})
	}
}

func testMinedCreditKeepsExpiry(t *testing.T, ct cointype.CoinType) {
	ctx := context.Background()
	db, _, s, teardown, err := cloneDB(ctx, "mined_expiry_"+ct.String()+".kv")
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	addr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(make([]byte, 20), s.chainParams)
	if err != nil {
		t.Fatal(err)
	}
	_, pkScript := addr.PaymentScript()
	tx := wire.NewMsgTx()
	tx.Expiry = 100
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{0x01}, 0, wire.TxTreeRegular), 0, nil))
	if ct.IsSKA() {
		tx.AddTxOut(wire.NewTxOutSKA(big.NewInt(1e8), ct, pkScript))
	} else {
		tx.AddTxOut(wire.NewTxOut(1e8, pkScript))
	}
	rec, err := NewTxRecordFromMsgTx(tx, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	g := makeBlockGenerator()
	b1 := g.generate(dcrutil.BlockValid)
	b1Hash := b1.BlockHash()
	err = walletdb.Update(ctx, db, func(dbtx walletdb.ReadWriteTx) error {
		if err := s.InsertMemPoolTx(dbtx, rec); err != nil {
			return err
		}
		if err := s.AddCredit(dbtx, rec, nil, 0, false, 0); err != nil {
			return err
		}
		err := insertMainChainHeaders(s, dbtx, makeHeaderDataSlice(b1), emptyFilters(1))
		if err != nil {
			return err
		}
		return s.InsertMinedTx(dbtx, rec, &b1Hash)
	})
	if err != nil {
		t.Fatal(err)
	}

	err = walletdb.View(ctx, db, func(dbtx walletdb.ReadTx) error {
		utxos, err := s.UnspentOutputs(dbtx, ct)
		if err != nil {
			return err
		}
		if len(utxos) != 1 || utxos[0].Height != 1 {
			t.Fatalf("unspent outputs %v, want one mined credit", utxos)
		}
		if !utxos[0].HasExpiry {
			t.Error("mined credit lost its expiry flag")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
