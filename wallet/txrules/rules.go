// Copyright (c) 2016 The btcsuite developers
// Copyright (c) 2016-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txrules

import (
	"fmt"
	"math/big"

	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/txscript"
	"github.com/monetarium/monetarium-node/txscript/stdscript"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
)

// StakeSubScriptType potentially transforms the provided script type by
// converting the various stake-specific script types to their associated sub
// type.  It will be returned unmodified otherwise.
func StakeSubScriptType(scriptType stdscript.ScriptType) (stdscript.ScriptType, bool) {
	switch scriptType {
	case stdscript.STStakeSubmissionPubKeyHash, stdscript.STStakeChangePubKeyHash,
		stdscript.STStakeGenPubKeyHash, stdscript.STStakeRevocationPubKeyHash,
		stdscript.STTreasuryGenPubKeyHash:

		return stdscript.STPubKeyHashEcdsaSecp256k1, true

	case stdscript.STStakeSubmissionScriptHash, stdscript.STStakeChangeScriptHash,
		stdscript.STStakeGenScriptHash, stdscript.STStakeRevocationScriptHash,
		stdscript.STTreasuryGenScriptHash:

		return stdscript.STScriptHash, true
	}

	return scriptType, false
}

// DefaultRelayFeePerKb is the default minimum relay fee policy for a mempool.
const DefaultRelayFeePerKb dcrutil.Amount = 0.0001 * 1e8

// IsDustAmount determines whether a transaction output value and script length would
// cause the output to be considered dust.  Transactions with dust outputs are
// not standard and are rejected by mempools with default policies.
//
// VAR-only: this function operates on int64 amounts and is unsuitable for SKA
// outputs (whose atom values can exceed math.MaxInt64). For SKA, use
// CheckOutput, which enforces cointype.MinSKADustAmount via SKAValue.
func IsDustAmount(amount dcrutil.Amount, scriptSize int, relayFeePerKb dcrutil.Amount) bool {
	return amount < DustThreshold(scriptSize, relayFeePerKb)
}

// DustThreshold returns the smallest VAR amount that is not dust for an
// output script of scriptSize bytes.
func DustThreshold(scriptSize int, relayFeePerKb dcrutil.Amount) dcrutil.Amount {
	// Calculate the total (estimated) cost to the network.  This is
	// calculated using the serialize size of the output plus the serial
	// size of a transaction input which redeems it.  The output is assumed
	// to be compressed P2PKH as this is the most common script type.  Use
	// the average size of a compressed P2PKH redeem input (165) rather than
	// the largest possible (txsizes.RedeemP2PKHInputSize).  The output size
	// is a VAR output's wire.TxOut.SerializeSize, as the node's dust check
	// counts it: coin type, value, script version and script.
	totalSize := 1 + 8 + 2 + wire.VarIntSerializeSize(uint64(scriptSize)) +
		scriptSize + 165

	// Dust is defined as an output value where the total cost to the network
	// (output size + input size) is greater than 1/3 of the relay fee.
	return dcrutil.Amount((int64(relayFeePerKb)*3*int64(totalSize) + 999) / 1000)
}

// IsDustOutput determines whether a transaction output is considered dust.
// Transactions with dust outputs are not standard and are rejected by mempools
// with default policies.
//
// VAR-only: this function reads output.Value (int64) and ignores SKAValue.
// For SKA outputs, use CheckOutput, which enforces cointype.MinSKADustAmount.
func IsDustOutput(output *wire.TxOut, relayFeePerKb dcrutil.Amount) bool {
	// Unspendable outputs which solely carry data are not checked for dust.
	if stdscript.IsNullDataScript(output.Version, output.PkScript) {
		return false
	}

	// All other unspendable outputs are considered dust.
	if txscript.IsUnspendable(output.Value, output.PkScript) {
		return true
	}

	return IsDustAmount(dcrutil.Amount(output.Value), len(output.PkScript),
		relayFeePerKb)
}

// CheckOutput performs simple consensus and policy tests on a transaction
// output.  Returns with errors.Invalid if output violates consensus rules, and
// errors.Policy if the output violates a non-consensus policy.
// Takes cointype.SKAAmount to support big.Int fees for SKA transactions.
func CheckOutput(output *wire.TxOut, relayFeePerKb cointype.SKAAmount) error {
	// For SKA outputs, use SKAValue for validation
	if output.CoinType.IsSKA() {
		// SKA uses big.Int (SKAValue), not int64 (Value)
		if output.SKAValue == nil || output.SKAValue.Sign() < 0 {
			return errors.E(errors.Invalid, "SKA transaction output amount is nil or negative")
		}
		// OP_RETURN data outputs (incl. SKA burn scripts from
		// chaincfg.CreateSKABurnScript) are provably unspendable; the
		// dust-as-network-burden rationale doesn't apply. Mirrors the VAR
		// IsDustOutput exemption above.
		if stdscript.IsNullDataScript(output.Version, output.PkScript) {
			return nil
		}
		// Minimum 30 atoms for SKA outputs (matches mempool dust threshold)
		if output.SKAValue.Cmp(cointype.MinSKADustAmount) < 0 {
			return errors.E(errors.Policy, "SKA transaction output amount below minimum (30 atoms)")
		}
		return nil
	}

	// VAR output validation - convert fee to int64. VAR fees always fit in
	// int64; an overflow here means the caller passed an SKA-shaped fee
	// rate by mistake, which would silently disable dust rejection if
	// allowed to fall through.
	relayFeeInt64, err := relayFeePerKb.Int64()
	if err != nil {
		return errors.E(errors.Invalid, fmt.Sprintf(
			"VAR fee overflow: %s exceeds int64 (%v)", relayFeePerKb.String(), err))
	}
	if output.Value < 0 {
		return errors.E(errors.Invalid, "transaction output amount is negative")
	}
	if dcrutil.Amount(output.Value) > dcrutil.Amount(cointype.MaxVARAmount) {
		return errors.E(errors.Invalid, "transaction output amount exceeds maximum value")
	}
	if IsDustOutput(output, dcrutil.Amount(relayFeeInt64)) {
		return errors.E(errors.Policy, "transaction output is dust")
	}
	return nil
}

// FeeForSerializeSize calculates the required fee for a transaction of some
// arbitrary size given a mempool's relay fee policy.
//
// VAR-only: this function uses int64 math and clamps at cointype.MaxVARAmount.
// For SKA, use FeeForSerializeSizeSKA, which preserves big.Int precision.
func FeeForSerializeSize(relayFeePerKb dcrutil.Amount, txSerializeSize int) dcrutil.Amount {
	fee := relayFeePerKb * dcrutil.Amount(txSerializeSize) / 1000

	if fee == 0 && relayFeePerKb > 0 {
		fee = relayFeePerKb
	}

	if fee < 0 || fee > dcrutil.Amount(cointype.MaxVARAmount) {
		fee = dcrutil.Amount(cointype.MaxVARAmount)
	}

	return fee
}

// FeeForSerializeSizeSKA calculates the required fee for a transaction using
// SKAAmount (big.Int) for full precision. Use this for SKA transactions.
func FeeForSerializeSizeSKA(relayFeePerKb cointype.SKAAmount, txSerializeSize int) cointype.SKAAmount {
	// fee = relayFeePerKb * txSerializeSize / 1000
	size := big.NewInt(int64(txSerializeSize))

	// Multiply: relayFeePerKb * txSerializeSize
	fee := new(big.Int).Mul(relayFeePerKb.BigInt(), size)
	// Divide by 1000
	fee.Div(fee, cointype.KilobyteInt)

	// Floor: when truncation drives the computed fee to zero, return one
	// fee-rate-per-kB. Use a defensive copy so the returned SKAAmount does
	// not alias relayFeePerKb's inner *big.Int.
	if fee.Sign() == 0 && relayFeePerKb.BigInt().Sign() > 0 {
		return cointype.NewSKAAmount(new(big.Int).Set(relayFeePerKb.BigInt()))
	}

	return cointype.NewSKAAmount(fee)
}

func sumOutputValues(outputs []*wire.TxOut) (totalOutput dcrutil.Amount) {
	for _, txOut := range outputs {
		totalOutput += dcrutil.Amount(txOut.Value)
	}
	return totalOutput
}

// GetCoinTypeFromOutputs determines the coin type of transaction outputs.
// Since transactions cannot mix coin types (all outputs must have the same coin type),
// this returns the coin type of the first output, or VAR if there are no outputs.
func GetCoinTypeFromOutputs(outputs []*wire.TxOut) cointype.CoinType {
	if len(outputs) == 0 {
		return cointype.CoinTypeVAR
	}
	// All outputs in a transaction must have the same coin type,
	// so we can simply return the coin type of the first output
	return outputs[0].CoinType
}

// ValidateCoinTypeUniformity returns an error if outputs do not all share the
// same coin type. Consensus rejects mixed-coin transactions, but wallet-layer
// aggregators that read txStore-resident MsgTx must verify the invariant
// locally as defense-in-depth before summing Value/SKAValue — a malformed tx
// reaching the wallet via SPV rescan or addtransaction RPC would otherwise
// silently mis-report balance.
func ValidateCoinTypeUniformity(outputs []*wire.TxOut) error {
	if len(outputs) <= 1 {
		return nil
	}
	first := outputs[0].CoinType
	for i, txOut := range outputs[1:] {
		if txOut.CoinType != first {
			return errors.E(errors.Invalid,
				fmt.Sprintf("output 0 coin type %d does not match output %d coin type %d",
					first, i+1, txOut.CoinType))
		}
	}
	return nil
}

// PaysHighFees checks whether the signed transaction pays insanely high fees.
// Transactons are defined to have a high fee if they have pay a fee rate that
// is 1000 time higher than the default fee.
//
// VAR-only: this function reads output.Value (int64) and ignores SKAValue.
// Passing a transaction with any SKA output is a programmer error and returns
// an errors.Bug error — callers must dispatch on coin type at the call site
// and route SKA transactions to PaysHighFeesSKA. Returning an error (rather
// than silently returning false) ensures any future caller that forgets the
// dispatch surfaces the bug immediately instead of bypassing the high-fee gate.
func PaysHighFees(totalInput dcrutil.Amount, tx *wire.MsgTx) (bool, error) {
	for _, txOut := range tx.TxOut {
		if txOut.CoinType.IsSKA() {
			return false, errors.E(errors.Bug,
				"txrules.PaysHighFees called with SKA outputs; use PaysHighFeesSKA")
		}
	}

	fee := totalInput - sumOutputValues(tx.TxOut)
	if fee <= 0 {
		// Impossible to determine
		return false, nil
	}

	maxFee := FeeForSerializeSize(1000*DefaultRelayFeePerKb, tx.SerializeSize())
	return fee > maxFee, nil
}

// TxPaysHighFees checks whether the signed transaction pays insanely high fees.
// Transactons are defined to have a high fee if they have pay a fee rate that
// is 1000 time higher than the default fee.  Total transaction input value is
// determined by summing the ValueIn fields of each input, and an error is returned
// if any input values were the null value.
//
// VAR-only: returns an Invalid error if any output is SKA — callers must use
// the SKA-aware path instead.
func TxPaysHighFees(tx *wire.MsgTx) (bool, error) {
	for _, txOut := range tx.TxOut {
		if txOut.CoinType.IsSKA() {
			return false, errors.E(errors.Bug,
				"TxPaysHighFees is VAR-only; use PaysHighFeesSKA for SKA transactions")
		}
	}
	var input dcrutil.Amount
	for i, in := range tx.TxIn {
		if in.ValueIn < 0 {
			err := errors.Errorf("transaction input %d does not "+
				"specify the input value", i)
			return false, errors.E(errors.Invalid, err)
		}
		input += dcrutil.Amount(in.ValueIn)
	}
	return PaysHighFees(input, tx)
}

// PaysHighFeesSKA checks whether an SKA transaction pays excessively high fees.
// SKA transactions are defined to have a high fee if they pay a fee rate that
// is MaxFeeMultiplier (default 2500) times higher than the per-coin MinRelayTxFee.
//
// Absolute floor: regardless of tx size, the maximum allowed fee never falls
// below MinRelayTxFee × MaxFeeMultiplier (the "minMaxFee" computed below). For
// SKA1 mainnet with MinRelayTxFee=4e18 and MaxFeeMultiplier=2500 that floor is
// 1e22 atoms (10000 SKA). The function therefore does not flag txs paying less
// than that absolute amount, even when their fee-rate per-kB is many multiples
// of MinRelayTxFee. This matches upstream Decred wallet's VAR PaysHighFees behavior at the
// small-tx end and is intentional — the gate is a sanity check on grossly
// overpaying transactions, not a fee-rate ceiling.
//
// Returns errors.Bug if the per-coin MinRelayTxFee is missing or non-positive
// — silently bypassing the high-fee gate on a misconfigured chain would let
// the wallet author SKA transactions paying any fee. Mirrors the explicit
// error contract on the VAR PaysHighFees path.
func PaysHighFeesSKA(totalInput *big.Int, tx *wire.MsgTx, chainParams *chaincfg.Params) (bool, error) {
	if totalInput == nil {
		return false, errors.E(errors.Bug, "PaysHighFeesSKA: nil totalInput")
	}
	if totalInput.Sign() < 0 {
		return false, errors.E(errors.Bug, "PaysHighFeesSKA: negative totalInput")
	}
	if totalInput.Sign() == 0 {
		return false, nil
	}

	// Determine coin type from outputs
	coinType := GetCoinTypeFromOutputs(tx.TxOut)

	// Look up per-coin config
	config, ok := chainParams.SKACoins[coinType]
	if !ok || config == nil || config.MinRelayTxFee == nil || config.MinRelayTxFee.Sign() <= 0 {
		return false, errors.E(errors.Bug, errors.Errorf(
			"PaysHighFeesSKA: missing or non-positive MinRelayTxFee for coin type %d", coinType))
	}

	// Sum SKA output values
	outputSum := new(big.Int)
	for _, txOut := range tx.TxOut {
		if txOut.CoinType.IsSKA() && txOut.SKAValue != nil {
			outputSum.Add(outputSum, txOut.SKAValue)
		}
	}

	// Calculate fee = inputs - outputs
	fee := new(big.Int).Sub(totalInput, outputSum)
	if fee.Sign() <= 0 {
		return false, nil
	}

	multiplier := config.EffectiveMaxFeeMultiplier()

	// Calculate max fee using big.Int: minRelayFee * multiplier * txSize / 1000
	txSize := int64(tx.SerializeSize())
	maxFee := new(big.Int).Mul(config.MinRelayTxFee, big.NewInt(multiplier))
	maxFee.Mul(maxFee, big.NewInt(txSize))
	maxFee.Div(maxFee, big.NewInt(1000))

	// Ensure minimum of the max fee rate itself (for very small transactions)
	minMaxFee := new(big.Int).Mul(config.MinRelayTxFee, big.NewInt(multiplier))
	if maxFee.Cmp(minMaxFee) < 0 {
		maxFee = minMaxFee
	}

	return fee.Cmp(maxFee) > 0, nil
}

// TxPaysHighFeesSKA checks whether an SKA transaction pays excessively high fees.
// Total SKA input value is determined by summing the SKAValueIn fields of each input.
// Returns an error if any SKA input is missing its value.
//
// SKA emission transactions are exempt: they have a single null input
// (SKAValueIn=nil) because no SKA exists yet to consume, and they pay zero
// fees by protocol — a fee in a coin that doesn't exist is impossible.
// The block validator unconditionally accepts a well-formed emission tx.
func TxPaysHighFeesSKA(tx *wire.MsgTx, chainParams *chaincfg.Params) (bool, error) {
	if wire.IsSKAEmissionTransaction(tx) {
		return false, nil
	}
	totalInput := new(big.Int)
	for i, in := range tx.TxIn {
		if in.SKAValueIn == nil {
			err := errors.Errorf("SKA transaction input %d does not "+
				"specify the SKA input value", i)
			return false, errors.E(errors.Invalid, err)
		}
		totalInput.Add(totalInput, in.SKAValueIn)
	}
	return PaysHighFeesSKA(totalInput, tx, chainParams)
}
