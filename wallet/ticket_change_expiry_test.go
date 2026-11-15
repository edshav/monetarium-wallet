// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"testing"

	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/gcs/blockcf2"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
)

// TestTicketChangeExpiryMaturity checks the change output of a mined ticket
// with an expiry.  The node requires coinbase maturity before any output of a
// tx with an expiry is spent (ErrExpiryTxSpentEarly), ticket change included,
// so coin selection and the balance must not offer that change after ticket
// change maturity alone.  Change of a ticket without an expiry matures after
// SStxChangeMaturity, as before.
func TestTicketChangeExpiryMaturity(t *testing.T) {
	for _, expiry := range []uint32{0, 1000} {
		name := "no expiry"
		if expiry != 0 {
			name = "expiry"
		}
		t.Run(name, func(t *testing.T) { testTicketChangeExpiryMaturity(t, expiry) })
	}
}

func testTicketChangeExpiryMaturity(t *testing.T, expiry uint32) {
	const change = 1e8
	ctx := context.Background()
	w, teardown := testWallet(ctx, t, &basicWalletConfig, nil)
	t.Cleanup(teardown)
	params := w.chainParams

	addr, err := w.NewExternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	stakeAddr := addr.(stdaddr.StakeAddress)
	const price = 1e8
	ticket := wire.NewMsgTx()
	ticket.Expiry = expiry
	ticket.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{0xfe}}, price+change, nil))
	ver, script := stakeAddr.VotingRightsScript()
	ticket.AddTxOut(&wire.TxOut{Value: price, Version: ver, PkScript: script})
	ver, script = stakeAddr.RewardCommitmentScript(price+change, 0, 0)
	ticket.AddTxOut(&wire.TxOut{Version: ver, PkScript: script})
	ver, script = stakeAddr.StakeChangeScript()
	ticket.AddTxOut(&wire.TxOut{Value: change, Version: ver, PkScript: script})

	// Mine the ticket in block 1, then empty blocks one at a time.
	var forest SidechainForest
	tip := params.GenesisBlock.Header
	mine := func(txs ...*wire.MsgTx) {
		t.Helper()
		header := wire.BlockHeader{
			PrevBlock: tip.BlockHash(),
			Height:    tip.Height + 1,
			Bits:      params.PowLimitBits,
			SBits:     price,
			VoteBits:  1,
		}
		filter, err := blockcf2.Regular(&wire.MsgBlock{Header: header}, nil)
		if err != nil {
			t.Fatal(err)
		}
		hash := header.BlockHash()
		var relevant map[chainhash.Hash][]*wire.MsgTx
		if len(txs) > 0 {
			relevant = map[chainhash.Hash][]*wire.MsgTx{hash: txs}
		}
		if _, err := w.ChainSwitch(ctx, &forest, []*BlockNode{NewBlockNode(&header, &hash, filter)}, relevant); err != nil {
			t.Fatal(err)
		}
		tip = header
	}
	mine(ticket)

	// check asserts whether each path offers the ticket change.
	check := func(want bool) {
		t.Helper()
		bal, err := w.AccountBalance(ctx, 0, 1)
		if err != nil {
			t.Fatal(err)
		}
		coinBal, err := w.AccountBalanceByCoinType(ctx, 0, cointype.CoinTypeVAR, 1)
		if err != nil {
			t.Fatal(err)
		}
		wantAmt := dcrutil.Amount(0)
		if want {
			wantAmt = change
		}
		if bal.Spendable != wantAmt || coinBal.Spendable != wantAmt {
			t.Errorf("height %d: Spendable %v (AccountBalance), %v (AccountBalanceByCoinType), want %v",
				tip.Height, bal.Spendable, coinBal.Spendable, wantAmt)
		}
		// Total holds the ticket and its change at every height.
		if bal.Total != price+change || coinBal.Total != price+change {
			t.Errorf("height %d: Total %v (AccountBalance), %v (AccountBalanceByCoinType), want %v",
				tip.Height, bal.Total, coinBal.Total, dcrutil.Amount(price+change))
		}

		policy := OutputSelectionPolicy{Account: 0, RequiredConfirmations: 1, CoinType: cointype.CoinTypeVAR}
		detail, err := w.SelectInputs(ctx, change/2, cointype.Zero(), policy)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(detail.Inputs) != 0; got != want {
			t.Errorf("height %d: SelectInputs selected %d inputs, want the change: %v",
				tip.Height, len(detail.Inputs), want)
		}

		reserved, err := w.ReserveOutputsForAmount(ctx, 0, change/2, cointype.Zero(), 1, cointype.CoinTypeVAR)
		if want != (err == nil) || (err != nil && !errors.Is(err, errors.InsufficientBalance)) {
			t.Errorf("height %d: ReserveOutputsForAmount: %v, want the change: %v", tip.Height, err, want)
		}
		unlockInputs(w, reserved)

		all, err := w.reserveOutputs(ctx, 0, 1, cointype.CoinTypeVAR)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(all) != 0; got != want {
			t.Errorf("height %d: reserveOutputs reserved %d outputs, want the change: %v", tip.Height, len(all), want)
		}
		unlockInputs(w, all)
	}

	// At the ticket's own height ticket change maturity is not reached.
	check(false)
	// Ticket change maturity (one block on simnet) is reached at height 2.
	mine()
	check(expiry == 0)
	// Coinbase maturity is reached once the tip is CoinbaseMaturity blocks
	// past the ticket.
	for int32(tip.Height) < int32(params.CoinbaseMaturity) {
		mine()
	}
	check(expiry == 0)
	mine()
	check(true)
}

// unlockInputs unlocks the outpoints of inputs.
func unlockInputs(w *Wallet, inputs []Input) {
	for _, in := range inputs {
		w.UnlockOutpoint(&in.OutPoint.Hash, in.OutPoint.Index)
	}
}
