// Copyright (c) 2016 The btcsuite developers
// Copyright (c) 2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txauthor_test

import (
	"testing"

	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet/txauthor"
	"github.com/monetarium/monetarium-wallet/wallet/txrules"
	"github.com/monetarium/monetarium-wallet/wallet/txsizes"
	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/wire"
)

type AuthorTestChangeSource struct{}

func (src AuthorTestChangeSource) Script() ([]byte, uint16, error) {
	// Only length matters for these tests.
	return make([]byte, txsizes.P2PKHPkScriptSize), 0, nil
}

func (src AuthorTestChangeSource) ScriptSize() int {
	return txsizes.P2PKHPkScriptSize
}

func p2pkhOutputs(amounts ...dcrutil.Amount) []*wire.TxOut {
	v := make([]*wire.TxOut, 0, len(amounts))
	for _, a := range amounts {
		outScript := make([]byte, txsizes.P2PKHOutputSize)
		v = append(v, wire.NewTxOut(int64(a), outScript))
	}
	return v
}

func makeInputSource(unspents []*wire.TxOut) txauthor.InputSource {
	// Return outputs in order.
	currentTotal := dcrutil.Amount(0)
	currentInputs := make([]*wire.TxIn, 0, len(unspents))
	redeemScriptSizes := make([]int, 0, len(unspents))
	f := func(target dcrutil.Amount, targetSKA cointype.SKAAmount) (*txauthor.InputDetail, error) {
		for currentTotal < target && len(unspents) != 0 {
			u := unspents[0]
			unspents = unspents[1:]
			nextInput := wire.NewTxIn(&wire.OutPoint{}, u.Value, nil)
			currentTotal += dcrutil.Amount(u.Value)
			currentInputs = append(currentInputs, nextInput)
			redeemScriptSizes = append(redeemScriptSizes, txsizes.RedeemP2PKHSigScriptSize)
		}

		inputDetail := txauthor.InputDetail{
			Amount:            currentTotal,
			Inputs:            currentInputs,
			Scripts:           make([][]byte, len(currentInputs)),
			RedeemScriptSizes: redeemScriptSizes,
		}
		return &inputDetail, nil
	}
	return txauthor.InputSource(f)
}

func TestNewUnsignedTransaction(t *testing.T) {
	tests := []struct {
		UnspentOutputs   []*wire.TxOut
		Outputs          []*wire.TxOut
		RelayFee         cointype.SKAAmount
		ChangeAmount     dcrutil.Amount
		InputSourceError bool
		InputCount       int
	}{
		0: {
			UnspentOutputs:   p2pkhOutputs(1e8),
			Outputs:          p2pkhOutputs(1e8),
			RelayFee:         cointype.SKAAmountFromInt64(1e3),
			InputSourceError: true,
		},
		1: {
			UnspentOutputs: p2pkhOutputs(1e8),
			Outputs:        p2pkhOutputs(1e6),
			RelayFee:       cointype.SKAAmountFromInt64(1e3),
			ChangeAmount: 1e8 - 1e6 - txrules.FeeForSerializeSize(1e3,
				txsizes.EstimateSerializeSize([]int{txsizes.RedeemP2PKHSigScriptSize}, p2pkhOutputs(1e6), txsizes.P2PKHPkScriptSize)),
			InputCount: 1,
		},
		2: {
			UnspentOutputs: p2pkhOutputs(1e8),
			Outputs:        p2pkhOutputs(1e6),
			RelayFee:       cointype.SKAAmountFromInt64(1e4),
			ChangeAmount: 1e8 - 1e6 - txrules.FeeForSerializeSize(1e4,
				txsizes.EstimateSerializeSize([]int{txsizes.RedeemP2PKHSigScriptSize}, p2pkhOutputs(1e6), txsizes.P2PKHPkScriptSize)),
			InputCount: 1,
		},
		3: {
			UnspentOutputs: p2pkhOutputs(1e8),
			Outputs:        p2pkhOutputs(1e6, 1e6, 1e6),
			RelayFee:       cointype.SKAAmountFromInt64(1e4),
			ChangeAmount: 1e8 - 3e6 - txrules.FeeForSerializeSize(1e4,
				txsizes.EstimateSerializeSize([]int{txsizes.RedeemP2PKHSigScriptSize}, p2pkhOutputs(1e6, 1e6, 1e6), txsizes.P2PKHPkScriptSize)),
			InputCount: 1,
		},
		4: {
			UnspentOutputs: p2pkhOutputs(1e8),
			Outputs:        p2pkhOutputs(1e6, 1e6, 1e6),
			RelayFee:       cointype.SKAAmountFromInt64(2550),
			ChangeAmount: 1e8 - 3e6 - txrules.FeeForSerializeSize(2.55e3,
				txsizes.EstimateSerializeSize([]int{txsizes.RedeemP2PKHSigScriptSize}, p2pkhOutputs(1e6, 1e6, 1e6), txsizes.P2PKHPkScriptSize)),
			InputCount: 1,
		},

		// Test dust thresholds (606 for a 1e3 relay fee: a VAR output is 37
		// bytes on the wire, its coin type byte included).
		5: {
			UnspentOutputs: p2pkhOutputs(1e8),
			Outputs: p2pkhOutputs(1e8 - 605 - txrules.FeeForSerializeSize(1e3,
				txsizes.EstimateSerializeSize([]int{txsizes.RedeemP2PKHSigScriptSize}, p2pkhOutputs(0), txsizes.P2PKHPkScriptSize))),
			RelayFee:     cointype.SKAAmountFromInt64(1e3),
			ChangeAmount: 0,
			InputCount:   1,
		},
		6: {
			UnspentOutputs: p2pkhOutputs(1e8),
			Outputs: p2pkhOutputs(1e8 - 606 - txrules.FeeForSerializeSize(1e3,
				txsizes.EstimateSerializeSize([]int{txsizes.RedeemP2PKHSigScriptSize}, p2pkhOutputs(0), txsizes.P2PKHPkScriptSize))),
			RelayFee:     cointype.SKAAmountFromInt64(1e3),
			ChangeAmount: 606,
			InputCount:   1,
		},

		// Test dust thresholds (1545.3 for a 2.55e3 relay fee).
		7: {
			UnspentOutputs: p2pkhOutputs(1e8),
			Outputs: p2pkhOutputs(1e8 - 1545 - txrules.FeeForSerializeSize(2.55e3,
				txsizes.EstimateSerializeSize([]int{txsizes.RedeemP2PKHSigScriptSize}, p2pkhOutputs(0), txsizes.P2PKHPkScriptSize))),
			RelayFee:     cointype.SKAAmountFromInt64(2550),
			ChangeAmount: 0,
			InputCount:   1,
		},
		8: {
			UnspentOutputs: p2pkhOutputs(1e8),
			Outputs: p2pkhOutputs(1e8 - 1546 - txrules.FeeForSerializeSize(2.55e3,
				txsizes.EstimateSerializeSize([]int{txsizes.RedeemP2PKHSigScriptSize}, p2pkhOutputs(0), txsizes.P2PKHPkScriptSize))),
			RelayFee:     cointype.SKAAmountFromInt64(2550),
			ChangeAmount: 1546,
			InputCount:   1,
		},

		// Test two unspent outputs available but only one needed
		// (tested fee only includes one input rather than using a
		// serialize size for each).
		9: {
			UnspentOutputs: p2pkhOutputs(1e8, 1e8),
			Outputs: p2pkhOutputs(1e8 - 606 - txrules.FeeForSerializeSize(1e3,
				txsizes.EstimateSerializeSize([]int{txsizes.RedeemP2PKHSigScriptSize}, p2pkhOutputs(0), txsizes.P2PKHPkScriptSize))),
			RelayFee:     cointype.SKAAmountFromInt64(1e3),
			ChangeAmount: 606,
			InputCount:   1,
		},

		// Test that second output is not included to make the change
		// output not dust and be included in the transaction.
		//
		// It's debatable whether or not this is a good idea, but it's
		// how the function was written, so test it anyways.
		10: {
			UnspentOutputs: p2pkhOutputs(1e8, 1e8),
			Outputs: p2pkhOutputs(1e8 - 545 - txrules.FeeForSerializeSize(1e3,
				txsizes.EstimateSerializeSize([]int{txsizes.RedeemP2PKHSigScriptSize}, p2pkhOutputs(0), txsizes.P2PKHPkScriptSize))),
			RelayFee:     cointype.SKAAmountFromInt64(1e3),
			ChangeAmount: 0,
			InputCount:   1,
		},

		// Test two unspent outputs available where both are needed.
		11: {
			UnspentOutputs: p2pkhOutputs(1e8, 1e8),
			Outputs:        p2pkhOutputs(1e8),
			RelayFee:       cointype.SKAAmountFromInt64(1e3),
			ChangeAmount: 1e8 - txrules.FeeForSerializeSize(1e3,
				txsizes.EstimateSerializeSize([]int{txsizes.RedeemP2PKHSigScriptSize, txsizes.RedeemP2PKHSigScriptSize}, p2pkhOutputs(1e8), txsizes.P2PKHPkScriptSize)),
			InputCount: 2,
		},

		// Test that zero change outputs are not included
		// (ChangeAmount=0 means don't include any change output).
		12: {
			UnspentOutputs: p2pkhOutputs(1e8),
			Outputs:        p2pkhOutputs(1e8),
			RelayFee:       cointype.SKAAmountFromInt64(0),
			ChangeAmount:   0,
			InputCount:     1,
		},
	}

	var changeSource AuthorTestChangeSource

	for i, test := range tests {
		inputSource := makeInputSource(test.UnspentOutputs)
		tx, err := txauthor.NewUnsignedTransaction(test.Outputs, test.RelayFee, inputSource, changeSource, chaincfg.MainNetParams().MaxTxSize, -1)
		if err != nil {
			if !test.InputSourceError || !errors.Is(err, errors.InsufficientBalance) {
				t.Errorf("Test %d: Unexpected error: %v", i, err)
			}
			continue
		}
		if test.InputSourceError {
			t.Errorf("Test %d: authored a tx, expected InsufficientBalance", i)
			continue
		}
		if tx.ChangeIndex < 0 {
			if test.ChangeAmount != 0 {
				t.Errorf("Test %d: No change output added but expected output with amount %v",
					i, test.ChangeAmount)
				continue
			}
		} else {
			changeAmount := dcrutil.Amount(tx.Tx.TxOut[tx.ChangeIndex].Value)
			if test.ChangeAmount == 0 {
				t.Errorf("Test %d: Included change output with value %v but expected no change",
					i, changeAmount)
				continue
			}
			if changeAmount != test.ChangeAmount {
				t.Errorf("Test %d: Got change amount %v, Expected %v",
					i, changeAmount, test.ChangeAmount)
				continue
			}
		}
		if len(tx.Tx.TxIn) != test.InputCount {
			t.Errorf("Test %d: Used %d outputs from input source, Expected %d",
				i, len(tx.Tx.TxIn), test.InputCount)
		}
	}
}

// TestChangelessDeadZoneRescue exercises the band between "inputs cover
// outputs + change-less fee" and "inputs cover outputs + with-change fee".
// The input source is exhausted inside that band, and before the rescue the
// author failed InsufficientBalance even though a valid, relayable
// change-less transaction exists — user-visible as "reducing a Max-filled
// amount by a few atoms makes a SMALLER send insufficient". The rescue must
// author without a change output, keep the recipient amount untouched, and
// burn the whole leftover as fee (bounded overpay: less than the fee cost
// of carrying the change output). Below the change-less minimum the real
// InsufficientBalance verdict must be preserved.
func TestChangelessDeadZoneRescue(t *testing.T) {
	relayFee := cointype.SKAAmountFromInt64(1e3)
	amount := dcrutil.Amount(1e8)
	outputs := p2pkhOutputs(amount)
	inputSizes := []int{txsizes.RedeemP2PKHSigScriptSize}
	changelessFee := txrules.FeeForSerializeSize(1e3,
		txsizes.EstimateSerializeSize(inputSizes, outputs, 0))
	withChangeFee := txrules.FeeForSerializeSize(1e3,
		txsizes.EstimateSerializeSize(inputSizes, outputs, txsizes.P2PKHPkScriptSize))
	if changelessFee >= withChangeFee {
		t.Fatalf("test shape broken: changeless fee %v >= with-change fee %v",
			changelessFee, withChangeFee)
	}

	// One atom past the change-less minimum: inside the dead zone.
	leftover := changelessFee + 1
	if leftover >= withChangeFee {
		t.Fatalf("test shape broken: leftover %v >= with-change fee %v",
			leftover, withChangeFee)
	}
	unspents := p2pkhOutputs(amount + leftover)
	tx, err := txauthor.NewUnsignedTransaction(outputs, relayFee,
		makeInputSource(unspents), AuthorTestChangeSource{},
		chaincfg.MainNetParams().MaxTxSize, -1)
	if err != nil {
		t.Fatalf("dead-zone rescue failed: %v", err)
	}
	if tx.ChangeIndex >= 0 {
		t.Fatalf("rescue tx must have no change output, got index %d", tx.ChangeIndex)
	}
	if len(tx.Tx.TxOut) != 1 || tx.Tx.TxOut[0].Value != int64(amount) {
		t.Fatalf("recipient output mutated: %+v", tx.Tx.TxOut)
	}
	fee := tx.TotalInput - dcrutil.Amount(tx.Tx.TxOut[0].Value)
	if fee != leftover {
		t.Fatalf("fee = %v, want the whole leftover %v", fee, leftover)
	}
	checkRescued(t, tx, cointype.CoinTypeVAR, inputSizes, outputs)

	// One atom below the change-less minimum: not fundable in any shape —
	// the rescue must not relax the InsufficientBalance verdict.
	shortUnspents := p2pkhOutputs(amount + changelessFee - 1)
	_, err = txauthor.NewUnsignedTransaction(outputs, relayFee,
		makeInputSource(shortUnspents), AuthorTestChangeSource{},
		chaincfg.MainNetParams().MaxTxSize, -1)
	if !errors.Is(err, errors.InsufficientBalance) {
		t.Fatalf("below-minimum send: want InsufficientBalance, got %v", err)
	}
}
