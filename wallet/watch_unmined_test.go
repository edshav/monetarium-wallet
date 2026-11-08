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
	"github.com/monetarium/monetarium-node/txscript/stdscript"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// filterNetwork records the tx filter the wallet loads, as a syncer does.
type filterNetwork struct {
	mockNetwork
	filter *RescanFilter
}

func (n *filterNetwork) LoadTxFilter(_ context.Context, reload bool, addrs []stdaddr.Address, outpoints []wire.OutPoint) error {
	if reload || n.filter == nil {
		n.filter = NewRescanFilter(nil, nil)
	}
	for _, a := range addrs {
		n.filter.AddAddress(a)
	}
	for i := range outpoints {
		n.filter.AddUnspentOutPoint(&outpoints[i])
	}
	return nil
}

// TestLoadActiveDataFiltersWatchesUnminedSpends reloads the wallet's tx
// filter, as at startup, while the wallet holds an unmined tx that spends a
// mined wallet output and pays only a foreign address, such as a VSP fee tx
// without change.  A block mining that tx reaches the wallet only if the
// filter selects it by an outpoint or an address, the checks of
// spv/rescan.go and of the node's tx filter in RPC mode; the wallet must then
// record it mined.  SPV's earlier cfilter match is not modeled: the block's
// cfilter holds the script of the spent wallet output.  A different tx spending the same output that is mined
// instead must reach the wallet too, which drops its own unmined spender.
func TestLoadActiveDataFiltersWatchesUnminedSpends(t *testing.T) {
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
	foreign, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(make([]byte, 20), cfg.Params)
	if err != nil {
		t.Fatal(err)
	}
	fVer, fScript := foreign.PaymentScript()
	ska := cointype.CoinType(1)
	skaValue := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)

	net := &filterNetwork{}
	// selected reports whether the loaded filter selects tx: an input
	// spending a watched outpoint or an output paying a watched address, the
	// checks of spv/rescan.go.  With no filter loaded every tx is selected.
	selected := func(tx *wire.MsgTx) bool {
		if net.filter == nil {
			return true
		}
		for _, in := range tx.TxIn {
			if net.filter.ExistsUnspentOutPoint(&in.PreviousOutPoint) {
				return true
			}
		}
		for _, out := range tx.TxOut {
			_, addrs := stdscript.ExtractAddrs(out.Version, out.PkScript, cfg.Params)
			for _, a := range addrs {
				if net.filter.ExistsAddress(a) {
					return true
				}
			}
		}
		return false
	}

	var forest SidechainForest
	tip := cfg.Params.GenesisBlock.Header
	// mine extends the main chain by a block holding txs, of which the wallet
	// is given those the filter selects.
	mine := func(t *testing.T, txs ...*wire.MsgTx) {
		t.Helper()
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
		var relevant []*wire.MsgTx
		for _, tx := range txs {
			if selected(tx) {
				relevant = append(relevant, tx)
			}
		}
		node := NewBlockNode(&header, &hash, filter)
		_, err = w.ChainSwitch(ctx, &forest, []*BlockNode{node},
			map[chainhash.Hash][]*wire.MsgTx{hash: relevant})
		if err != nil {
			t.Fatal(err)
		}
		tip = header
	}
	mined := func(t *testing.T, tx *wire.MsgTx) bool {
		t.Helper()
		_, height, err := w.TxBlock(ctx, tx.CachedTxHash())
		if errors.Is(err, errors.NotExist) {
			return false
		}
		if err != nil {
			t.Fatal(err)
		}
		return height != -1 // -1: held unmined
	}
	held := func(t *testing.T, tx *wire.MsgTx) (ok bool) {
		t.Helper()
		err := walletdb.View(ctx, w.db, func(dbtx walletdb.ReadTx) error {
			ok = w.txStore.ExistsTx(dbtx.ReadBucket(wtxmgrNamespaceKey), tx.CachedTxHash())
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	var n byte
	// spender mines an output paid to the wallet and returns a signed tx
	// spending it to the foreign address, with no change.
	spender := func(t *testing.T, coinType cointype.CoinType) *wire.MsgTx {
		t.Helper()
		n++
		out := &wire.TxOut{Value: 1e8, Version: ver, PkScript: script}
		if coinType.IsSKA() {
			out = &wire.TxOut{Version: ver, PkScript: script, CoinType: coinType,
				SKAValue: new(big.Int).Set(skaValue)}
		}
		fund := wire.NewMsgTx()
		fund.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{n}}, 0, nil))
		fund.AddTxOut(out)
		net.filter = nil
		mine(t, fund)

		tx := wire.NewMsgTx()
		in := wire.NewTxIn(wire.NewOutPoint(fund.CachedTxHash(), 0, wire.TxTreeRegular), out.Value, nil)
		if coinType.IsSKA() {
			in.SKAValueIn = new(big.Int).Set(skaValue)
		}
		tx.AddTxIn(in)
		pay := &wire.TxOut{Value: out.Value / 2, Version: fVer, PkScript: fScript, CoinType: coinType}
		if coinType.IsSKA() {
			pay.SKAValue = new(big.Int).Rsh(skaValue, 1)
		}
		tx.AddTxOut(pay)
		signAll(ctx, t, w, tx)
		return tx
	}
	record := func(t *testing.T, tx *wire.MsgTx, unpublished bool) {
		t.Helper()
		if unpublished {
			if err := w.SetPublished(ctx, tx.CachedTxHash(), false); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.AddTransaction(ctx, tx, nil); err != nil {
			t.Fatal(err)
		}
		if err := w.LoadActiveDataFilters(ctx, net, true); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name        string
		coinType    cointype.CoinType
		unpublished bool
	}{
		{name: "VAR, unpublished", unpublished: true},
		{name: "VAR, published"},
		{name: "SKA1, unpublished", coinType: ska, unpublished: true},
		{name: "SKA1, published", coinType: ska},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tx := spender(t, tc.coinType)
			record(t, tx, tc.unpublished)
			mine(t, tx)
			if !mined(t, tx) {
				t.Fatal("the change-less spender was not recorded mined after the reload")
			}
		})
	}

	t.Run("double spend mined instead", func(t *testing.T) {
		tx := spender(t, cointype.CoinTypeVAR)
		ds := tx.Copy()
		ds.TxOut[0].Value--
		ds.TxIn[0].SignatureScript = nil
		signAll(ctx, t, w, ds)
		record(t, tx, true)
		mine(t, ds)
		if !mined(t, ds) {
			t.Fatal("the mined double spend was not recorded")
		}
		if held(t, tx) {
			t.Fatal("the double-spent unmined spender was kept")
		}
	})
}

// signAll signs every input of tx with the wallet's keys.
func signAll(ctx context.Context, t *testing.T, w *Wallet, tx *wire.MsgTx) {
	t.Helper()
	sigErrs, _, err := w.SignTransaction(ctx, tx, txscript.SigHashAll, nil, nil, nil)
	if err != nil || len(sigErrs) != 0 {
		t.Fatalf("sign: %v %v", err, sigErrs)
	}
}
