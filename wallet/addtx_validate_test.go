// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"math/big"
	"testing"

	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/gcs/blockcf2"
	"github.com/monetarium/monetarium-node/txscript"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
)

// TestAddTransactionValidatesOwnedInputs checks that an unmined tx spending an
// output of the wallet is recorded only when its input is signed by the wallet
// and its tree, coin type and declared values match the spent output.  A peer
// can relay such a tx without holding the keys.  A tx in a main chain block
// was validated by consensus and is not checked again.
func TestAddTransactionValidatesOwnedInputs(t *testing.T) {
	ctx := context.Background()
	cfg := basicWalletConfig
	w, teardown := testWallet(ctx, t, &cfg, nil)
	defer teardown()
	if err := w.Unlock(ctx, testPrivPass, nil); err != nil {
		t.Fatal(err)
	}
	addr, err := w.NewInternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	ver, script := addr.(Address).PaymentScript()
	stakeVer, stakeScript := addr.(stdaddr.StakeAddress).StakeChangeScript()
	ska, ska2 := cointype.CoinType(1), cointype.CoinType(2)
	skaValue := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)

	// mine extends the main chain by a block holding txs.
	var forest SidechainForest
	tip := cfg.Params.GenesisBlock.Header
	mine := func(t *testing.T, txs ...*wire.MsgTx) *chainhash.Hash {
		header := wire.BlockHeader{
			PrevBlock: tip.BlockHash(),
			Height:    tip.Height + 1,
			Bits:      cfg.Params.PowLimitBits,
		}
		filter, err := blockcf2.Regular(&wire.MsgBlock{Header: header}, nil)
		if err != nil {
			t.Fatal(err)
		}
		hash := header.BlockHash()
		node := NewBlockNode(&header, &hash, filter)
		_, err = w.ChainSwitch(ctx, &forest, []*BlockNode{node},
			map[chainhash.Hash][]*wire.MsgTx{hash: txs})
		if err != nil {
			t.Fatal(err)
		}
		tip = header
		return &hash
	}

	type testCase struct {
		name        string
		coinType    cointype.CoinType
		stake       bool              // spend a stake-tree output
		minedCredit bool              // the spent output is mined
		twoInputs   bool              // also spend a second owned output
		mutate      func(*wire.MsgTx) // before signing
		tamper      func(*wire.MsgTx) // after signing
		block       string            // "main" or "side": add the spend as mined
		reject      bool
	}

	var n byte
	// spend records a new output paid to the wallet and returns a tx
	// spending it, signed between mutate and tamper.
	spend := func(t *testing.T, tc *testCase) *wire.MsgTx {
		n++
		out := &wire.TxOut{Value: 1e8, Version: ver, PkScript: script}
		switch {
		case tc.coinType.IsSKA():
			out = &wire.TxOut{Version: ver, PkScript: script, CoinType: tc.coinType,
				SKAValue: new(big.Int).Set(skaValue)}
		case tc.stake:
			out = &wire.TxOut{Value: 1e8, Version: stakeVer, PkScript: stakeScript}
		}
		fund := wire.NewMsgTx()
		fund.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{n}}, 0, nil))
		fund.AddTxOut(out)
		if tc.twoInputs {
			fund.AddTxOut(out)
		}
		if tc.minedCredit {
			mine(t, fund)
		} else if err := w.AddTransaction(ctx, fund, nil); err != nil {
			t.Fatal(err)
		}

		tree := wire.TxTreeRegular
		if tc.stake {
			tree = wire.TxTreeStake
		}
		tx := wire.NewMsgTx()
		in := wire.NewTxIn(wire.NewOutPoint(fund.CachedTxHash(), 0, tree), out.Value, nil)
		if tc.coinType.IsSKA() {
			in.SKAValueIn = new(big.Int).Set(skaValue)
		}
		tx.AddTxIn(in)
		if tc.twoInputs {
			tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(fund.CachedTxHash(), 1, tree), out.Value, nil))
		}
		tx.AddTxOut(&wire.TxOut{Value: out.Value, Version: ver, PkScript: script,
			CoinType: out.CoinType, SKAValue: out.SKAValue})
		if tc.mutate != nil {
			tc.mutate(tx)
		}
		sigErrs, _, err := w.SignTransaction(ctx, tx, txscript.SigHashAll, nil, nil, nil)
		if err != nil || len(sigErrs) != 0 {
			t.Fatalf("sign: %v %v", err, sigErrs)
		}
		if tc.tamper != nil {
			tc.tamper(tx)
		}
		return tx
	}

	noSig := func(tx *wire.MsgTx) { tx.TxIn[0].SignatureScript = nil }
	tests := []testCase{
		{name: "valid VAR"},
		{name: "valid SKA", coinType: ska},
		{name: "valid VAR, mined credit", minedCredit: true},
		{name: "valid SKA, mined credit", coinType: ska, minedCredit: true},
		{name: "valid stake tree", stake: true},
		{name: "bad signature", tamper: func(tx *wire.MsgTx) {
			tx.TxIn[0].SignatureScript[len(tx.TxIn[0].SignatureScript)-1] ^= 1
		}, reject: true},
		{name: "no signature", tamper: noSig, reject: true},
		{name: "no signature, mined credit", minedCredit: true, tamper: noSig, reject: true},
		{name: "valid two inputs", twoInputs: true},
		{name: "second input not signed", twoInputs: true, tamper: func(tx *wire.MsgTx) {
			tx.TxIn[1].SignatureScript = nil
		}, reject: true},
		{name: "unparsable signature", tamper: func(tx *wire.MsgTx) {
			tx.TxIn[0].SignatureScript = []byte{txscript.OP_PUSHDATA1}
		}, reject: true},
		{name: "wrong ValueIn", mutate: func(tx *wire.MsgTx) {
			tx.TxIn[0].ValueIn++
		}, reject: true},
		{name: "ValueIn below the credit", mutate: func(tx *wire.MsgTx) {
			tx.TxIn[0].ValueIn--
		}, reject: true},
		{name: "wrong ValueIn, mined credit", minedCredit: true, mutate: func(tx *wire.MsgTx) {
			tx.TxIn[0].ValueIn++
		}, reject: true},
		{name: "regular tree claimed as stake", mutate: func(tx *wire.MsgTx) {
			tx.TxIn[0].PreviousOutPoint.Tree = wire.TxTreeStake
		}, reject: true},
		{name: "stake tree claimed as regular", stake: true, mutate: func(tx *wire.MsgTx) {
			tx.TxIn[0].PreviousOutPoint.Tree = wire.TxTreeRegular
		}, reject: true},
		{name: "SKA regular tree claimed as stake", coinType: ska, mutate: func(tx *wire.MsgTx) {
			tx.TxIn[0].PreviousOutPoint.Tree = wire.TxTreeStake
		}, reject: true},
		{name: "SKAValueIn on VAR input", mutate: func(tx *wire.MsgTx) {
			tx.TxIn[0].SKAValueIn = big.NewInt(1)
		}, reject: true},
		{name: "VAR input in SKA tx", mutate: func(tx *wire.MsgTx) {
			tx.TxOut[0].Value = 0
			tx.TxOut[0].CoinType = ska
			tx.TxOut[0].SKAValue = big.NewInt(1)
		}, reject: true},
		{name: "SKA input in VAR tx", coinType: ska, mutate: func(tx *wire.MsgTx) {
			tx.TxOut[0].CoinType = cointype.CoinTypeVAR
			tx.TxOut[0].SKAValue = nil
			tx.TxOut[0].Value = 1
		}, reject: true},
		{name: "SKA1 input in SKA2 tx", coinType: ska, mutate: func(tx *wire.MsgTx) {
			tx.TxOut[0].CoinType = ska2
		}, reject: true},
		{name: "SKAValueIn tampered after signing", coinType: ska, tamper: func(tx *wire.MsgTx) {
			tx.TxIn[0].SKAValueIn.Add(tx.TxIn[0].SKAValueIn, big.NewInt(1))
		}, reject: true},
		{name: "wrong SKAValueIn signed", coinType: ska, mutate: func(tx *wire.MsgTx) {
			tx.TxIn[0].SKAValueIn.Add(tx.TxIn[0].SKAValueIn, big.NewInt(1))
		}, reject: true},
		{name: "wrong SKAValueIn signed, mined credit", coinType: ska, minedCredit: true,
			mutate: func(tx *wire.MsgTx) {
				tx.TxIn[0].SKAValueIn.Add(tx.TxIn[0].SKAValueIn, big.NewInt(1))
			}, reject: true},
		{name: "no SKAValueIn", coinType: ska, mutate: func(tx *wire.MsgTx) {
			tx.TxIn[0].SKAValueIn = nil
		}, reject: true},
		{name: "ValueIn on SKA input", coinType: ska, mutate: func(tx *wire.MsgTx) {
			tx.TxIn[0].ValueIn = 1
		}, reject: true},
		{name: "no signature, in main chain block", tamper: noSig, block: "main"},
		{name: "no signature, in sidechain block", tamper: noSig, block: "side", reject: true},
	}
	for i := range tests {
		tc := &tests[i]
		t.Run(tc.name, func(t *testing.T) {
			tx := spend(t, tc)
			var blockHash *chainhash.Hash
			switch tc.block {
			case "main":
				blockHash = mine(t)
			case "side":
				blockHash = &chainhash.Hash{0xff}
			}
			err := w.AddTransaction(ctx, tx, blockHash)
			if !tc.reject {
				if err != nil {
					t.Fatalf("valid spend rejected: %v", err)
				}
				hash := tx.TxHash()
				if _, _, err := w.GetTransactionsByHashes(ctx, []*chainhash.Hash{&hash}); err != nil {
					t.Fatalf("valid spend not recorded: %v", err)
				}
				return
			}
			if !errors.Is(err, errors.ScriptFailure) {
				t.Fatalf("got %v, want ScriptFailure", err)
			}
		})
	}
}
