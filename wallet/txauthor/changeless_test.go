// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txauthor_test

import (
	"math"
	"math/big"
	"testing"

	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet/txauthor"
	"github.com/monetarium/monetarium-wallet/wallet/txrules"
	"github.com/monetarium/monetarium-wallet/wallet/txsizes"
)

const skaCoin = cointype.CoinType(1)

func skaOutput(atoms *big.Int) *wire.TxOut {
	return &wire.TxOut{PkScript: make([]byte, txsizes.P2PKHOutputSize),
		CoinType: skaCoin, SKAValue: new(big.Int).Set(atoms)}
}

// skaInputSource returns one SKA input per amount, all of them whatever the
// target.
func skaInputSource(amounts ...*big.Int) txauthor.InputSource {
	detail := &txauthor.InputDetail{SKAAmount: cointype.Zero()}
	for _, atoms := range amounts {
		in := wire.NewTxIn(&wire.OutPoint{}, 0, nil)
		in.SKAValueIn = new(big.Int).Set(atoms)
		detail.SKAAmount = detail.SKAAmount.Add(cointype.NewSKAAmount(atoms))
		detail.Inputs = append(detail.Inputs, in)
		detail.Scripts = append(detail.Scripts, nil)
		detail.RedeemScriptSizes = append(detail.RedeemScriptSizes, txsizes.RedeemP2PKHSigScriptSize)
	}
	return func(dcrutil.Amount, cointype.SKAAmount) (*txauthor.InputDetail, error) {
		return detail, nil
	}
}

// checkRescued checks the fields of a rescued tx other than its amounts:
// the tx header, one previous script per input, and the size estimate of
// the change-less shape.
func checkRescued(t *testing.T, tx *txauthor.AuthoredTx, coinType cointype.CoinType,
	inputSizes []int, outputs []*wire.TxOut) {

	t.Helper()
	m := tx.Tx
	if m.Version != 1 || m.SerType != wire.TxSerializeFull || m.LockTime != 0 || m.Expiry != 0 {
		t.Fatalf("version %d, ser type %v, lock time %d, expiry %d; want 1, full, 0, 0",
			m.Version, m.SerType, m.LockTime, m.Expiry)
	}
	if len(m.TxIn) != len(inputSizes) || len(tx.PrevScripts) != len(inputSizes) {
		t.Fatalf("%d inputs, %d prev scripts; want %d", len(m.TxIn), len(tx.PrevScripts),
			len(inputSizes))
	}
	want := txsizes.EstimateSerializeSizeForCoinType(coinType, inputSizes, outputs, 0)
	if tx.EstimatedSignedSerializeSize != want {
		t.Fatalf("estimated size %d, want the change-less %d", tx.EstimatedSignedSerializeSize, want)
	}
}

// TestChangelessDeadZoneRescueSKA is the SKA counterpart of
// TestChangelessDeadZoneRescue, with amounts above int64.
func TestChangelessDeadZoneRescueSKA(t *testing.T) {
	relayFee := cointype.NewSKAAmount(big.NewInt(4e18)) // simnet SKA1, per kB
	amount := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	outputs := []*wire.TxOut{skaOutput(amount)}
	inputSizes := []int{txsizes.RedeemP2PKHSigScriptSize}
	changelessFee := txrules.FeeForSerializeSizeSKA(relayFee,
		txsizes.EstimateSerializeSizeSKA(inputSizes, outputs, 0)).BigInt()
	withChangeFee := txrules.FeeForSerializeSizeSKA(relayFee,
		txsizes.EstimateSerializeSizeSKA(inputSizes, outputs, txsizes.P2PKHPkScriptSize)).BigInt()
	// One atom past the change-less minimum: inside the dead zone.
	leftover := new(big.Int).Add(changelessFee, big.NewInt(1))
	if leftover.Cmp(withChangeFee) >= 0 {
		t.Fatalf("test shape broken: leftover %v >= with-change fee %v", leftover, withChangeFee)
	}
	maxTxSize := chaincfg.MainNetParams().MaxTxSize

	tx, err := txauthor.NewUnsignedTransaction(outputs, relayFee,
		skaInputSource(new(big.Int).Add(amount, leftover)), AuthorTestChangeSource{}, maxTxSize, -1)
	if err != nil {
		t.Fatalf("dead-zone rescue failed: %v", err)
	}
	if tx.ChangeIndex >= 0 || len(tx.Tx.TxOut) != 1 {
		t.Fatalf("want one output and no change, got %d outputs, change index %d",
			len(tx.Tx.TxOut), tx.ChangeIndex)
	}
	out := tx.Tx.TxOut[0]
	if out.CoinType != skaCoin || out.Value != 0 || out.SKAValue.Cmp(amount) != 0 {
		t.Fatalf("recipient output changed: %+v", out)
	}
	fee := new(big.Int).Sub(tx.SKATotalInput.BigInt(), out.SKAValue)
	if fee.Cmp(leftover) != 0 {
		t.Fatalf("fee = %v, want the whole leftover %v", fee, leftover)
	}
	checkRescued(t, tx, skaCoin, inputSizes, outputs)

	// One atom below the change-less minimum: not fundable in any shape.
	short := new(big.Int).Add(amount, changelessFee)
	short.Sub(short, big.NewInt(1))
	_, err = txauthor.NewUnsignedTransaction(outputs, relayFee,
		skaInputSource(short), AuthorTestChangeSource{}, maxTxSize, -1)
	if !errors.Is(err, errors.InsufficientBalance) {
		t.Fatalf("below-minimum send: want InsufficientBalance, got %v", err)
	}
}

// TestChangelessRescueSkipsSweep checks that a sweep too small to pay a
// change output fails instead of producing a tx with no outputs.
func TestChangelessRescueSkipsSweep(t *testing.T) {
	maxTxSize := chaincfg.MainNetParams().MaxTxSize
	t.Run("VAR", func(t *testing.T) {
		relayFee := cointype.SKAAmountFromInt64(1e3)
		inputSizes := []int{txsizes.RedeemP2PKHSigScriptSize}
		changelessFee := txrules.FeeForSerializeSize(1e3,
			txsizes.EstimateSerializeSize(inputSizes, nil, 0))
		_, err := txauthor.NewUnsignedSweepTransaction(cointype.CoinTypeVAR, relayFee,
			makeInputSource(p2pkhOutputs(changelessFee+1)), AuthorTestChangeSource{},
			maxTxSize)
		if !errors.Is(err, errors.InsufficientBalance) {
			t.Fatalf("want InsufficientBalance, got %v", err)
		}
	})
	t.Run("SKA1", func(t *testing.T) {
		// Enough inputs that the change-less fee, and so the swept total,
		// is above int64.
		const n = 16
		relayFee := cointype.NewSKAAmount(big.NewInt(4e18)) // simnet SKA1, per kB
		inputSizes := make([]int, n)
		for i := range inputSizes {
			inputSizes[i] = txsizes.RedeemP2PKHSigScriptSize
		}
		changelessFee := txrules.FeeForSerializeSizeSKA(relayFee,
			txsizes.EstimateSerializeSizeSKA(inputSizes, nil, 0)).BigInt()
		total := new(big.Int).Add(changelessFee, big.NewInt(1))
		if total.IsInt64() {
			t.Fatalf("test shape broken: swept total %v fits int64", total)
		}
		each, rem := new(big.Int).QuoRem(total, big.NewInt(n), new(big.Int))
		amounts := make([]*big.Int, n)
		for i := range amounts {
			amounts[i] = each
		}
		amounts[0] = new(big.Int).Add(each, rem)
		_, err := txauthor.NewUnsignedSweepTransaction(skaCoin, relayFee,
			skaInputSource(amounts...), AuthorTestChangeSource{}, maxTxSize)
		if !errors.Is(err, errors.InsufficientBalance) {
			t.Fatalf("want InsufficientBalance, got %v", err)
		}
	})
}

// TestRandomizeChangePositionWithoutChange checks that a tx without a change
// output, such as a rescued one, keeps its outputs in place.
func TestRandomizeChangePositionWithoutChange(t *testing.T) {
	outputs := p2pkhOutputs(1e8, 2e8)
	tx := &txauthor.AuthoredTx{Tx: &wire.MsgTx{TxOut: outputs[:2:2]}, ChangeIndex: -1}
	tx.RandomizeChangePosition()
	if tx.ChangeIndex != -1 || tx.Tx.TxOut[0].Value != 1e8 || tx.Tx.TxOut[1].Value != 2e8 {
		t.Fatalf("change index %d, outputs %v %v", tx.ChangeIndex,
			tx.Tx.TxOut[0].Value, tx.Tx.TxOut[1].Value)
	}
}

// TestChangelessRescueSizesAllInputs checks that the rescue prices the
// change-less tx for every input the source returned, not for the one-input
// first estimate, and that a leftover equal to that fee is rescued.
func TestChangelessRescueSizesAllInputs(t *testing.T) {
	twoInputs := []int{txsizes.RedeemP2PKHSigScriptSize, txsizes.RedeemP2PKHSigScriptSize}
	maxTxSize := chaincfg.MainNetParams().MaxTxSize
	skaAmount := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))

	for _, ct := range []struct {
		name     string
		coinType cointype.CoinType
		relayFee cointype.SKAAmount
		amount   *big.Int
	}{
		{"VAR", cointype.CoinTypeVAR, cointype.SKAAmountFromInt64(1e3), big.NewInt(1e8)},
		{"SKA1", skaCoin, cointype.NewSKAAmount(big.NewInt(4e18)), skaAmount},
	} {
		t.Run(ct.name, func(t *testing.T) {
			isSKA := ct.coinType.IsSKA()
			var outputs []*wire.TxOut
			if isSKA {
				outputs = []*wire.TxOut{skaOutput(ct.amount)}
			} else {
				outputs = p2pkhOutputs(dcrutil.Amount(ct.amount.Int64()))
			}
			changelessFee := txrules.FeeForSerializeSizeSKA(ct.relayFee,
				txsizes.EstimateSerializeSizeForCoinType(ct.coinType, twoInputs, outputs, 0)).BigInt()

			for _, tc := range []struct {
				leftover *big.Int
				rescued  bool
			}{
				{changelessFee, true},
				{new(big.Int).Sub(changelessFee, big.NewInt(1)), false},
			} {
				// Two inputs, so the source's total only covers the outputs in
				// a two-input tx.
				half := new(big.Int).Rsh(ct.amount, 1)
				second := new(big.Int).Add(half, tc.leftover)
				var src txauthor.InputSource
				if isSKA {
					src = skaInputSource(half, second)
				} else {
					src = makeInputSource(p2pkhOutputs(dcrutil.Amount(half.Int64()),
						dcrutil.Amount(second.Int64())))
				}
				tx, err := txauthor.NewUnsignedTransaction(outputs, ct.relayFee,
					src, AuthorTestChangeSource{}, maxTxSize, -1)
				if !tc.rescued {
					if !errors.Is(err, errors.InsufficientBalance) {
						t.Errorf("leftover %v: want InsufficientBalance, got %v", tc.leftover, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("leftover %v: %v", tc.leftover, err)
				}
				if tx.ChangeIndex >= 0 || len(tx.Tx.TxOut) != 1 {
					t.Fatalf("leftover %v: %d outputs, change index %d; want 1, none",
						tc.leftover, len(tx.Tx.TxOut), tx.ChangeIndex)
				}
				checkRescued(t, tx, ct.coinType, twoInputs, outputs)
			}
		})
	}
}

// TestChangelessRescueVARFeeOverflow checks that the rescue refuses a VAR
// change-less fee that does not fit int64. The relay fee is chosen so the
// one-input with-change fee of the first estimate fits int64 and the
// two-input change-less fee does not.
func TestChangelessRescueVARFeeOverflow(t *testing.T) {
	amount := dcrutil.Amount(1e8)
	outputs := p2pkhOutputs(amount)
	withChangeSize := txsizes.EstimateSerializeSize(
		[]int{txsizes.RedeemP2PKHSigScriptSize}, outputs, txsizes.P2PKHPkScriptSize)
	changelessSize := txsizes.EstimateSerializeSize(
		[]int{txsizes.RedeemP2PKHSigScriptSize, txsizes.RedeemP2PKHSigScriptSize}, outputs, 0)
	rate := new(big.Int).Mul(big.NewInt(math.MaxInt64), big.NewInt(1000))
	rate.Div(rate, big.NewInt(int64(changelessSize)))
	rate.Add(rate, big.NewInt(1000))
	relayFee := cointype.NewSKAAmount(rate)

	firstFee, err := txrules.FeeForSerializeSizeSKA(relayFee, withChangeSize).Int64()
	if err != nil || firstFee > math.MaxInt64-int64(amount) {
		t.Fatalf("test shape broken: first with-change fee %v (%v) does not fit", firstFee, err)
	}
	if _, err := txrules.FeeForSerializeSizeSKA(relayFee, changelessSize).Int64(); err == nil {
		t.Fatal("test shape broken: two-input change-less fee fits int64")
	}

	_, err = txauthor.NewUnsignedTransaction(outputs, relayFee,
		makeInputSource(p2pkhOutputs(amount/2, amount/2+1)), AuthorTestChangeSource{},
		chaincfg.MainNetParams().MaxTxSize, -1)
	if !errors.Is(err, errors.InsufficientBalance) {
		t.Fatalf("want InsufficientBalance, got %v", err)
	}
}

// TestChangelessRescueRespectsMaxTxSize checks that the rescue does not
// author a change-less tx larger than the size limit.
func TestChangelessRescueRespectsMaxTxSize(t *testing.T) {
	inputSizes := []int{txsizes.RedeemP2PKHSigScriptSize}
	t.Run("VAR", func(t *testing.T) {
		relayFee := cointype.SKAAmountFromInt64(1e3)
		amount := dcrutil.Amount(1e8)
		outputs := p2pkhOutputs(amount)
		changelessSize := txsizes.EstimateSerializeSize(inputSizes, outputs, 0)
		changelessFee := txrules.FeeForSerializeSize(1e3, changelessSize)
		_, err := txauthor.NewUnsignedTransaction(outputs, relayFee,
			makeInputSource(p2pkhOutputs(amount+changelessFee+1)), AuthorTestChangeSource{},
			changelessSize-1, -1)
		if !errors.Is(err, errors.InsufficientBalance) {
			t.Fatalf("want InsufficientBalance, got %v", err)
		}
	})
	t.Run("SKA1", func(t *testing.T) {
		relayFee := cointype.NewSKAAmount(big.NewInt(4e18)) // simnet SKA1, per kB
		amount := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
		outputs := []*wire.TxOut{skaOutput(amount)}
		changelessSize := txsizes.EstimateSerializeSizeSKA(inputSizes, outputs, 0)
		changelessFee := txrules.FeeForSerializeSizeSKA(relayFee, changelessSize).BigInt()
		input := new(big.Int).Add(amount, changelessFee)
		input.Add(input, big.NewInt(1))
		_, err := txauthor.NewUnsignedTransaction(outputs, relayFee,
			skaInputSource(input), AuthorTestChangeSource{}, changelessSize-1, -1)
		if !errors.Is(err, errors.InsufficientBalance) {
			t.Fatalf("want InsufficientBalance, got %v", err)
		}
	})
}
