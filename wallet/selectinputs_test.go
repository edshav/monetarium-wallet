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
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/gcs/blockcf2"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/wallet/txauthor"
)

// TestSelectInputsReachesTarget checks that SelectInputs returns every output
// a target needs, each once.  Its random search could find nothing while
// eligible outputs remained, and selection then stopped short of the target.
func TestSelectInputsReachesTarget(t *testing.T) {
	for _, ct := range []cointype.CoinType{cointype.CoinTypeVAR, cointype.CoinType(1)} {
		t.Run(ct.String(), func(t *testing.T) {
			testSelectInputsReachesTarget(t, ct)
		})
	}
}

func testSelectInputsReachesTarget(t *testing.T, ct cointype.CoinType) {
	ctx := context.Background()
	cfg := basicWalletConfig
	w, teardown := testWallet(ctx, t, &cfg, nil)
	defer teardown()
	addr, err := w.NewInternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	ver, script := addr.(Address).PaymentScript()

	// mine extends the main chain by a block holding txs.  The block
	// approves its parent, so the parent's regular tree stays valid.
	var forest SidechainForest
	tip := cfg.Params.GenesisBlock.Header
	mine := func(txs ...*wire.MsgTx) {
		header := wire.BlockHeader{
			PrevBlock: tip.BlockHash(),
			VoteBits:  dcrutil.BlockValid,
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
	}

	// Four credits of 1e8 in one block, then a block on top of it.
	const n = 4
	var funds []*wire.MsgTx
	want := make(map[wire.OutPoint]bool)
	for i := byte(1); i <= n; i++ {
		out := &wire.TxOut{Value: 1e8, Version: ver, PkScript: script}
		if ct.IsSKA() {
			out = &wire.TxOut{Version: ver, PkScript: script, CoinType: ct, SKAValue: big.NewInt(1e8)}
		}
		fund := wire.NewMsgTx()
		fund.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{i}}, 0, nil))
		fund.AddTxOut(out)
		funds = append(funds, fund)
		want[*wire.NewOutPoint(fund.CachedTxHash(), 0, wire.TxTreeRegular)] = true
	}
	mine(funds...)
	mine()

	// Without the fix one selection in 12 to 17 came back short.
	policy := OutputSelectionPolicy{Account: 0, RequiredConfirmations: 1, CoinType: ct}
	for run := 0; run < 200; run++ {
		var detail *txauthor.InputDetail
		if ct.IsSKA() {
			detail, err = w.SelectInputs(ctx, 0, cointype.NewSKAAmount(big.NewInt(n*1e8-1)), policy)
		} else {
			detail, err = w.SelectInputs(ctx, n*1e8-1, cointype.Zero(), policy)
		}
		if err != nil {
			t.Fatal(err)
		}
		got := make(map[wire.OutPoint]bool)
		for _, in := range detail.Inputs {
			o := in.PreviousOutPoint
			if !want[o] || got[o] {
				t.Fatalf("run %d: selected %v, which is unknown or repeated", run, o)
			}
			got[o] = true
		}
		if len(got) != n {
			t.Fatalf("run %d: selected %d inputs, want %d", run, len(got), n)
		}
	}
}
