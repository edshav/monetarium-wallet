// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/monetarium/monetarium-node/blockchain/stake"
	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	gcs2 "github.com/monetarium/monetarium-node/gcs"
	"github.com/monetarium/monetarium-node/gcs/blockcf2"
	"github.com/monetarium/monetarium-node/txscript"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// TestUnspentOutputsSpendable checks that UnspentOutputs, which callers spend
// as is, leaves out tickets and every output a regular transaction may not
// spend yet.  On testnet an SSFee output and ticket change mature after one
// block, while coinbase, vote and expiring-tx outputs wait for coinbase
// maturity (16 blocks).
func TestUnspentOutputsSpendable(t *testing.T) {
	for _, ct := range []cointype.CoinType{cointype.CoinTypeVAR, cointype.CoinType(1)} {
		t.Run(ct.String(), func(t *testing.T) {
			testUnspentOutputsSpendable(t, ct)
		})
	}
}

func testUnspentOutputsSpendable(t *testing.T, ct cointype.CoinType) {
	ctx := context.Background()
	cfg := basicWalletConfig
	cfg.Params = chaincfg.TestNet3Params()
	w, teardown := testWallet(ctx, t, &cfg, nil)
	defer teardown()

	addr, err := w.NewExternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, p2pkh := addr.PaymentScript()
	tagged := func(op byte) []byte { return append([]byte{op}, p2pkh...) }
	txOut := func(v int64, pkScript []byte) *wire.TxOut {
		if ct.IsSKA() {
			return wire.NewTxOutSKA(big.NewInt(v), ct, pkScript)
		}
		return wire.NewTxOut(v, pkScript)
	}
	newRec := func(version uint16, prev wire.OutPoint, expiry uint32, outs ...*wire.TxOut) *udb.TxRecord {
		tx := wire.NewMsgTx()
		tx.Version = version
		tx.Expiry = expiry
		tx.AddTxIn(wire.NewTxIn(&prev, 0, nil))
		for _, out := range outs {
			tx.AddTxOut(out)
		}
		rec, err := udb.NewTxRecordFromMsgTx(tx, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	prev := func(b byte) wire.OutPoint { return wire.OutPoint{Hash: chainhash.Hash{b}} }
	null := wire.OutPoint{Index: wire.MaxPrevOutIndex}
	stakeNull := wire.OutPoint{Index: wire.MaxPrevOutIndex, Tree: wire.TxTreeStake}
	out := txOut(1e8, p2pkh)

	// Every credit but the unmined ones is mined in block 1.  first is the
	// lowest tip at which it may be spent, 0 for never.
	credits := []struct {
		name    string
		rec     *udb.TxRecord
		index   uint32
		first   int32
		unmined bool
	}{
		{"regular", newRec(1, prev(1), 0, out), 0, 1, false},
		{"ssfee", newRec(wire.TxVersionTreasury, stakeNull, 0,
			txOut(0, stake.CreateStakerSSFeeMarker(1, 0)),
			txOut(1e8, tagged(txscript.OP_SSGEN))), 1, 2, false},
		{"ticket change", newRec(1, prev(2), 0, txOut(1e8, tagged(txscript.OP_SSTXCHANGE))), 0, 2, false},
		{"ticket change with expiry", newRec(1, prev(9), 100, txOut(1e8, tagged(txscript.OP_SSTXCHANGE))), 0, 17, false},
		{"coinbase", newRec(1, null, 0, out), 0, 17, false},
		{"expiring tx", newRec(1, prev(3), 100, out), 0, 17, false},
		{"vote", newRec(1, prev(4), 0, txOut(1e8, tagged(txscript.OP_SSGEN))), 0, 17, false},
		{"revocation", newRec(1, prev(5), 0, txOut(1e8, tagged(txscript.OP_SSRTX))), 0, 17, false},
		{"treasury gen", newRec(1, prev(10), 0, txOut(1e8, tagged(txscript.OP_TGEN))), 0, 17, false},
		{"ticket", newRec(1, prev(6), 0, txOut(1e8, tagged(txscript.OP_SSTX))), 0, 0, false},
		{"unmined", newRec(1, prev(7), 0, out), 0, 1, true},
		{"unmined expiring tx", newRec(1, prev(8), 100, out), 0, 0, true},
	}

	var prevHash chainhash.Hash
	var height uint32
	err = walletdb.View(ctx, w.db, func(dbtx walletdb.ReadTx) error {
		prevHash, _ = w.txStore.MainChainTip(dbtx)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	extendTo := func(tip uint32) {
		t.Helper()
		err := walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
			ns := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)
			for height < tip {
				height++
				h := &wire.BlockHeader{PrevBlock: prevHash, VoteBits: 1, Height: height}
				// The store keeps the hash's bytes until commit, so each
				// block needs its own.
				hash := h.BlockHash()
				prevHash = hash
				f, err := gcs2.FromBytesV2(blockcf2.B, blockcf2.M, nil)
				if err != nil {
					return err
				}
				if err := w.txStore.ExtendMainChain(ns, h, &hash, f); err != nil {
					return err
				}
				if height != 1 {
					continue
				}
				meta := &udb.BlockMeta{Block: udb.Block{Hash: hash, Height: 1}}
				for _, c := range credits {
					var err error
					if c.unmined {
						err = w.txStore.InsertMemPoolTx(dbtx, c.rec)
					} else {
						err = w.txStore.InsertMinedTx(dbtx, c.rec, &hash)
					}
					if err != nil {
						return err
					}
					m := meta
					if c.unmined {
						m = nil
					}
					if err := w.txStore.AddCredit(dbtx, c.rec, m, c.index, false, 0); err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	for _, tip := range []uint32{1, 2, 16, 17} {
		extendTo(tip)
		// With no confirmations required, unmined credits are listed too.
		outputs, err := w.UnspentOutputs(ctx, OutputSelectionPolicy{
			RequiredConfirmations: 0,
			CoinType:              ct,
		})
		if err != nil {
			t.Fatal(err)
		}
		got := make(map[chainhash.Hash]bool)
		for _, o := range outputs {
			got[o.OutPoint.Hash] = true
		}
		for _, c := range credits {
			want := c.first != 0 && int32(tip) >= c.first
			if got[c.rec.Hash] != want {
				t.Errorf("tip %d: %s listed %v, want %v", tip, c.name, got[c.rec.Hash], want)
			}
		}
		if len(outputs) != len(got) {
			t.Errorf("tip %d: %d outputs for %d txs", tip, len(outputs), len(got))
		}
	}
}
