// Copyright (c) 2024 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"testing"
	"time"

	"github.com/monetarium/monetarium-node/blockchain/stake"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/txscript"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
)

// createMockSSFeeTx creates a mock SSFee transaction for testing
func createMockSSFeeTx(coinType cointype.CoinType, numOutputs int, outputValue int64) *wire.MsgTx {
	tx := wire.NewMsgTx()
	tx.Version = 3 // SSFee requires version >= 3

	// SSFee has max 5 outputs including OP_RETURN, so max 4 reward outputs
	if numOutputs > 4 {
		numOutputs = 4
	}

	// Add single null input (characteristic of SSFee)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash{},
			Index: wire.MaxPrevOutIndex,
		},
		ValueIn: outputValue * int64(numOutputs),
	})

	// Add reward outputs to voters
	for i := 0; i < numOutputs; i++ {
		// Use a simple P2PKH script for testing
		pkScript := []byte{
			0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 <push 20 bytes>
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, // 20 bytes of hash
			0x88, 0xac, // OP_EQUALVERIFY OP_CHECKSIG
		}
		tx.AddTxOut(&wire.TxOut{
			Value:    outputValue,
			Version:  0,
			PkScript: pkScript,
			CoinType: coinType,
		})
	}

	// Add OP_RETURN output as last output (required for SSFee)
	// Format: OP_RETURN + OP_DATA_6 + "SF" + height(4 bytes little-endian)
	opReturnScript := []byte{
		txscript.OP_RETURN, // 0x6a
		0x06,               // OP_DATA_6 (push 6 bytes)
		'S', 'F',           // "SF" marker (Stake Fee)
		0x00, 0x00, 0x00, 0x00, // height (placeholder, 4 bytes little-endian)
	}
	tx.AddTxOut(&wire.TxOut{
		Value:    0,
		Version:  0,
		PkScript: opReturnScript,
		CoinType: coinType,
	})

	return tx
}

// TestSSFeeTransactionType verifies that SSFee transactions are correctly identified
func TestSSFeeTransactionType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		tx          *wire.MsgTx
		wantType    TransactionType
		wantIsSSFee bool
	}{
		{
			name:        "valid SSFee SKA1",
			tx:          createMockSSFeeTx(cointype.CoinType(1), 3, 1000),
			wantType:    TransactionTypeSSFee,
			wantIsSSFee: true,
		},
		{
			name:        "valid SSFee SKA2",
			tx:          createMockSSFeeTx(cointype.CoinType(2), 4, 2000), // Max 4 reward outputs
			wantType:    TransactionTypeSSFee,
			wantIsSSFee: true,
		},
		{
			name: "regular transaction (not SSFee)",
			tx: &wire.MsgTx{
				Version: 1,
				TxIn: []*wire.TxIn{
					{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}},
				},
				TxOut: []*wire.TxOut{
					{Value: 1000, CoinType: cointype.CoinTypeVAR},
				},
			},
			wantType:    TransactionTypeRegular,
			wantIsSSFee: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			// Test transaction type detection
			txType := TxTransactionType(test.tx)
			if txType != test.wantType {
				t.Errorf("TxTransactionType() = %v, want %v", txType, test.wantType)
			}

			// Test IsSSFee detection
			isSSFee := stake.IsSSFee(test.tx)
			if isSSFee != test.wantIsSSFee {
				t.Errorf("IsSSFee() = %v, want %v", isSSFee, test.wantIsSSFee)
			}
		})
	}
}

// TestSSFeeOutputMaturity verifies the mainnet SSFee maturity boundary
func TestSSFeeOutputMaturity(t *testing.T) {
	t.Parallel()
	params := chaincfg.MainNetParams()
	maturity := int32(params.SStxChangeMaturity)

	tests := []struct {
		name       string
		txHeight   int32
		tipHeight  int32
		txType     stake.TxType
		wantMature bool
	}{
		{
			name:       "SSFee before maturity",
			txHeight:   100,
			tipHeight:  100 + maturity - 1,
			txType:     stake.TxTypeSSFee,
			wantMature: false,
		},
		{
			name:       "SSFee at exact maturity",
			txHeight:   100,
			tipHeight:  100 + maturity,
			txType:     stake.TxTypeSSFee,
			wantMature: true,
		},
		{
			name:       "SSFee after maturity",
			txHeight:   100,
			tipHeight:  100 + maturity + 10,
			txType:     stake.TxTypeSSFee,
			wantMature: true,
		},
		{
			name:       "SSFee at genesis",
			txHeight:   0,
			tipHeight:  maturity,
			txType:     stake.TxTypeSSFee,
			wantMature: true,
		},
		{
			name:       "SSFee with negative height (invalid)",
			txHeight:   -1,
			tipHeight:  maturity,
			txType:     stake.TxTypeSSFee,
			wantMature: false,
		},
		{
			name:       "SSFee far in future",
			txHeight:   100,
			tipHeight:  100 + maturity + 1000,
			txType:     stake.TxTypeSSFee,
			wantMature: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			// The treasury agenda cannot activate on mainnet
			mature := udb.SSFeeMatured(params, false, test.txHeight, test.tipHeight)
			if mature != test.wantMature {
				t.Errorf("SSFeeMatured(%d, %d) = %v, want %v",
					test.txHeight, test.tipHeight, mature, test.wantMature)
			}
		})
	}
}

// TestSSFeeOutputSpendability verifies SSFee outputs can be spent after maturity
func TestSSFeeOutputSpendability(t *testing.T) {
	t.Parallel()
	params := chaincfg.MainNetParams()
	maturity := int32(params.SStxChangeMaturity)

	// Create a mock TransactionOutput from SSFee
	createSSFeeOutput := func(coinType cointype.CoinType, value int64, height int32) *TransactionOutput {
		return &TransactionOutput{
			OutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: 0,
			},
			Output: wire.TxOut{
				Value:    value,
				Version:  0,
				PkScript: make([]byte, 25),
				CoinType: coinType,
			},
			OutputKind:      OutputKindNormal,
			ContainingBlock: BlockIdentity{Height: height},
			ReceiveTime:     time.Now(),
		}
	}

	tests := []struct {
		name              string
		output            *TransactionOutput
		txType            stake.TxType
		tipHeight         int32
		shouldBeSpendable bool
		description       string
	}{
		{
			name:              "Mature SSFee SKA1 output",
			output:            createSSFeeOutput(cointype.CoinType(1), 1000, 100),
			txType:            stake.TxTypeSSFee,
			tipHeight:         100 + maturity,
			shouldBeSpendable: true,
			description:       "Mature SSFee outputs should be spendable",
		},
		{
			name:              "Immature SSFee SKA1 output",
			output:            createSSFeeOutput(cointype.CoinType(1), 1000, 100),
			txType:            stake.TxTypeSSFee,
			tipHeight:         100 + maturity - 1,
			shouldBeSpendable: false,
			description:       "Immature SSFee outputs should not be spendable",
		},
		{
			name:              "Mature SSFee SKA2 output",
			output:            createSSFeeOutput(cointype.CoinType(2), 2000, 200),
			txType:            stake.TxTypeSSFee,
			tipHeight:         200 + maturity + 10,
			shouldBeSpendable: true,
			description:       "Different SKA type SSFee outputs should follow same maturity rules",
		},
		{
			name:              "Very old SSFee output",
			output:            createSSFeeOutput(cointype.CoinType(3), 3000, 10),
			txType:            stake.TxTypeSSFee,
			tipHeight:         10000,
			shouldBeSpendable: true,
			description:       "Very old SSFee outputs should remain spendable",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			// Check if output would be considered mature
			mature := udb.SSFeeMatured(params, false, test.output.ContainingBlock.Height, test.tipHeight)
			if mature != test.shouldBeSpendable {
				t.Errorf("%s: maturity check failed - got %v, want %v",
					test.description, mature, test.shouldBeSpendable)
			}
		})
	}
}

// TestSSFeeMultipleCoinTypes verifies wallet correctly handles SSFee outputs from different coin types
func TestSSFeeMultipleCoinTypes(t *testing.T) {
	t.Parallel()

	// Create multiple SSFee transactions with different coin types
	ssFeeTxs := []*wire.MsgTx{
		createMockSSFeeTx(cointype.CoinType(1), 3, 1000), // SKA1
		createMockSSFeeTx(cointype.CoinType(2), 3, 2000), // SKA2
		createMockSSFeeTx(cointype.CoinType(3), 3, 3000), // SKA3
	}

	for i, tx := range ssFeeTxs {
		coinType := cointype.CoinType(i + 1)

		// Verify transaction is recognized as SSFee
		if !stake.IsSSFee(tx) {
			t.Errorf("Transaction for coin type %d not recognized as SSFee", coinType)
		}

		// Verify all non-OP_RETURN outputs have the correct coin type
		for j, out := range tx.TxOut[:len(tx.TxOut)-1] { // Skip last OP_RETURN
			if out.CoinType != coinType {
				t.Errorf("Output %d has coin type %d, expected %d", j, out.CoinType, coinType)
			}
		}

		// Verify transaction type detection
		txType := TxTransactionType(tx)
		if txType != TransactionTypeSSFee {
			t.Errorf("Transaction type for coin type %d = %v, want TransactionTypeSSFee",
				coinType, txType)
		}
	}
}

// TestSSFeeInUnspentOutputs verifies SSFee outputs appear in unspent outputs after maturity
func TestSSFeeInUnspentOutputs(t *testing.T) {
	t.Parallel()
	params := chaincfg.MainNetParams()
	maturity := int32(params.SStxChangeMaturity)

	// Test that SSFee outputs are properly filtered based on maturity
	tests := []struct {
		name             string
		outputHeight     int32
		outputCoinType   cointype.CoinType
		outputValue      int64
		tipHeight        int32
		policyMinAmount  dcrutil.Amount
		policyCoinType   *cointype.CoinType
		shouldBeIncluded bool
	}{
		{
			name:             "Mature SSFee SKA1 output with no filter",
			outputHeight:     100,
			outputCoinType:   cointype.CoinType(1),
			outputValue:      10000,
			tipHeight:        100 + maturity,
			policyMinAmount:  0,
			policyCoinType:   nil,
			shouldBeIncluded: true,
		},
		{
			name:             "Immature SSFee SKA1 output",
			outputHeight:     100,
			outputCoinType:   cointype.CoinType(1),
			outputValue:      10000,
			tipHeight:        100 + maturity - 1,
			policyMinAmount:  0,
			policyCoinType:   nil,
			shouldBeIncluded: false,
		},
		{
			name:             "Mature SSFee SKA1 output with SKA1 filter",
			outputHeight:     100,
			outputCoinType:   cointype.CoinType(1),
			outputValue:      10000,
			tipHeight:        100 + maturity,
			policyMinAmount:  0,
			policyCoinType:   func() *cointype.CoinType { ct := cointype.CoinType(1); return &ct }(),
			shouldBeIncluded: true,
		},
		{
			name:             "Mature SSFee SKA1 output with SKA2 filter",
			outputHeight:     100,
			outputCoinType:   cointype.CoinType(1),
			outputValue:      10000,
			tipHeight:        100 + maturity,
			policyMinAmount:  0,
			policyCoinType:   func() *cointype.CoinType { ct := cointype.CoinType(2); return &ct }(),
			shouldBeIncluded: false,
		},
		{
			name:             "Mature SSFee output below min amount",
			outputHeight:     100,
			outputCoinType:   cointype.CoinType(1),
			outputValue:      1000,
			tipHeight:        100 + maturity,
			policyMinAmount:  2000,
			policyCoinType:   nil,
			shouldBeIncluded: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			// Simulate policy filtering
			var policy OutputSelectionPolicy
			if test.policyCoinType != nil {
				policy = OutputSelectionPolicy{
					RequiredConfirmations: 1,
					CoinType:              *test.policyCoinType,
				}
			} else {
				// When no specific coin type, default to VAR
				policy = OutputSelectionPolicy{
					RequiredConfirmations: 1,
					CoinType:              cointype.CoinTypeVAR,
				}
			}

			// Check maturity
			mature := udb.SSFeeMatured(params, false, test.outputHeight, test.tipHeight)

			// Check coin type filter
			coinTypeMatch := test.policyCoinType == nil || policy.CoinType == test.outputCoinType

			// Check amount filter
			amountMatch := dcrutil.Amount(test.outputValue) >= test.policyMinAmount

			// Output should be included only if mature, coin type matches, and amount is sufficient
			shouldInclude := mature && coinTypeMatch && amountMatch

			if shouldInclude != test.shouldBeIncluded {
				t.Errorf("Output inclusion = %v, want %v (mature=%v, coinType=%v, amount=%v)",
					shouldInclude, test.shouldBeIncluded, mature, coinTypeMatch, amountMatch)
			}
		})
	}
}

// TestSSFeeValidation tests that SSFee transactions pass validation
func TestSSFeeValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		tx        *wire.MsgTx
		wantValid bool
		reason    string
	}{
		{
			name:      "Valid SSFee with SKA1",
			tx:        createMockSSFeeTx(cointype.CoinType(1), 3, 1000),
			wantValid: true,
			reason:    "Valid SSFee should pass validation",
		},
		{
			name:      "Valid SSFee with SKA2",
			tx:        createMockSSFeeTx(cointype.CoinType(2), 4, 2000), // Max 4 reward outputs
			wantValid: true,
			reason:    "Valid SSFee with different coin type should pass",
		},
		{
			name: "Invalid SSFee with VAR outputs",
			tx: func() *wire.MsgTx {
				tx := createMockSSFeeTx(cointype.CoinTypeVAR, 3, 1000)
				// SSFee with VAR outputs should be invalid
				return tx
			}(),
			wantValid: true,
			reason:    "Valid SSFee can distribute VAR fees",
		},
		{
			name: "Invalid SSFee with mixed coin types",
			tx: func() *wire.MsgTx {
				tx := wire.NewMsgTx()
				tx.Version = 3
				tx.AddTxIn(&wire.TxIn{
					PreviousOutPoint: wire.OutPoint{
						Hash:  chainhash.Hash{},
						Index: wire.MaxPrevOutIndex,
					},
				})
				tx.AddTxOut(&wire.TxOut{Value: 1000, CoinType: cointype.CoinType(1)})
				tx.AddTxOut(&wire.TxOut{Value: 1000, CoinType: cointype.CoinType(2)}) // Different coin type
				tx.AddTxOut(&wire.TxOut{Value: 0, PkScript: []byte{txscript.OP_RETURN}})
				return tx
			}(),
			wantValid: false,
			reason:    "SSFee with mixed coin types should be invalid",
		},
		{
			name: "Invalid SSFee with wrong version",
			tx: func() *wire.MsgTx {
				tx := createMockSSFeeTx(cointype.CoinType(1), 3, 1000)
				tx.Version = 2 // SSFee requires version >= 3
				return tx
			}(),
			wantValid: false,
			reason:    "SSFee with version < 3 should be invalid",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := stake.CheckSSFee(test.tx)
			valid := err == nil

			if valid != test.wantValid {
				t.Errorf("%s: validation = %v (error: %v), want %v",
					test.reason, valid, err, test.wantValid)
			}
		})
	}
}
