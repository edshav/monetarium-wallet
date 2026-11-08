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
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet/txrules"
	"github.com/monetarium/monetarium-wallet/wallet/txsizes"
)

// TestNewUnsignedTransactionChangelessRescue sends, from a single wallet
// credit, an amount whose leftover covers the change-less fee but not the
// with-change fee. The wallet must author the tx without change and pay
// the whole leftover as fee; one atom less is InsufficientBalance.
func TestNewUnsignedTransactionChangelessRescue(t *testing.T) {
	ska1Amount, _ := new(big.Int).SetString("100000000000000000000", 10) // 100 SKA1, above int64
	for _, tc := range []struct {
		name     string
		coinType cointype.CoinType
		amount   *big.Int
	}{
		{"VAR", cointype.CoinTypeVAR, big.NewInt(1e8)},
		{"SKA1", cointype.CoinType(1), ska1Amount},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			cfg := basicWalletConfig
			w, teardown := testWallet(ctx, t, &cfg, nil)
			defer teardown()
			isSKA := tc.coinType.IsSKA()

			addr, err := w.NewExternalAddress(ctx, 0)
			if err != nil {
				t.Fatal(err)
			}
			ver, script := addr.(Address).PaymentScript()
			txOut := func(atoms *big.Int) *wire.TxOut {
				if isSKA {
					return &wire.TxOut{Version: ver, PkScript: script,
						CoinType: tc.coinType, SKAValue: new(big.Int).Set(atoms)}
				}
				return &wire.TxOut{Value: atoms.Int64(), Version: ver, PkScript: script}
			}

			relayFee := w.RelayFeeForCoinType(ctx, tc.coinType)
			outputs := []*wire.TxOut{txOut(tc.amount)}
			inputSizes := []int{txsizes.RedeemP2PKHSigScriptSize}
			changelessFee := txrules.FeeForSerializeSizeSKA(relayFee,
				txsizes.EstimateSerializeSizeForCoinType(tc.coinType, inputSizes, outputs, 0)).BigInt()
			withChangeFee := txrules.FeeForSerializeSizeSKA(relayFee,
				txsizes.EstimateSerializeSizeForCoinType(tc.coinType, inputSizes, outputs,
					txsizes.P2PKHPkScriptSize)).BigInt()
			leftover := new(big.Int).Add(changelessFee, big.NewInt(1))
			if leftover.Cmp(withChangeFee) >= 0 {
				t.Fatalf("test shape broken: leftover %v >= with-change fee %v", leftover, withChangeFee)
			}

			var n byte
			// author funds the wallet with one unmined credit worth
			// amount + leftover and sends amount from it.
			author := func(leftover *big.Int) (*wire.MsgTx, error) {
				n++
				fund := wire.NewMsgTx()
				fund.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{n}}, 0, nil))
				fund.AddTxOut(txOut(new(big.Int).Add(tc.amount, leftover)))
				if err := w.AddTransaction(ctx, fund, nil); err != nil {
					t.Fatal(err)
				}
				atx, err := w.NewUnsignedTransaction(ctx, []*wire.TxOut{txOut(tc.amount)},
					cointype.Zero(), 0, 0, OutputSelectionAlgorithmDefault, nil, nil)
				if err != nil {
					return nil, err
				}
				// Release the credit so the next case selects only its own.
				if err := w.AbandonTransaction(ctx, fund.CachedTxHash()); err != nil {
					t.Fatal(err)
				}
				if atx.ChangeIndex >= 0 {
					t.Fatalf("change index %d, want none", atx.ChangeIndex)
				}
				return atx.Tx, nil
			}

			tx, err := author(leftover)
			if err != nil {
				t.Fatalf("change-less rescue failed: %v", err)
			}
			if len(tx.TxIn) != 1 || len(tx.TxOut) != 1 {
				t.Fatalf("%d inputs, %d outputs; want 1, 1", len(tx.TxIn), len(tx.TxOut))
			}
			out := tx.TxOut[0]
			var fee *big.Int
			if isSKA {
				if out.CoinType != tc.coinType || out.Value != 0 || out.SKAValue.Cmp(tc.amount) != 0 {
					t.Fatalf("recipient output changed: %+v", out)
				}
				fee = new(big.Int).Sub(tx.TxIn[0].SKAValueIn, out.SKAValue)
			} else {
				if out.CoinType != tc.coinType || out.SKAValue != nil || out.Value != tc.amount.Int64() {
					t.Fatalf("recipient output changed: %+v", out)
				}
				fee = big.NewInt(tx.TxIn[0].ValueIn - out.Value)
			}
			if fee.Cmp(leftover) != 0 {
				t.Fatalf("fee = %v, want the whole leftover %v", fee, leftover)
			}

			// One atom below the change-less fee.
			_, err = author(new(big.Int).Sub(changelessFee, big.NewInt(1)))
			if !errors.Is(err, errors.InsufficientBalance) {
				t.Fatalf("below change-less fee: want InsufficientBalance, got %v", err)
			}
		})
	}
}
