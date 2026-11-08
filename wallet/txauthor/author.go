// Copyright (c) 2016 The btcsuite developers
// Copyright (c) 2016-2024 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package txauthor provides transaction creation code for wallets.
package txauthor

import (
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet/txrules"
	"github.com/monetarium/monetarium-wallet/wallet/txsizes"
	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/crypto/rand"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/txscript"
	"github.com/monetarium/monetarium-node/txscript/sign"
	"github.com/monetarium/monetarium-node/wire"
)

const (
	// generatedTxVersion is the version of the transaction being generated.
	// It is defined as a constant here rather than using the wire.TxVersion
	// constant since a change in the transaction version will potentially
	// require changes to the generated transaction.  Thus, using the wire
	// constant for the generated transaction version could allow creation
	// of invalid transactions for the updated version.
	generatedTxVersion = 1
)

// InputDetail provides a detailed summary of transaction inputs
// referencing spendable outputs. This consists of the total spendable
// amount, the generated inputs, the redeem scripts and the full redeem
// script sizes.
type InputDetail struct {
	Amount            dcrutil.Amount
	SKAAmount         cointype.SKAAmount // For SKA coins that exceed int64
	Inputs            []*wire.TxIn
	Scripts           [][]byte
	RedeemScriptSizes []int
}

// InputSource provides transaction inputs referencing spendable outputs to
// construct a transaction outputting some target amount.  If the target amount
// can not be satisified, this can be signaled by returning a total amount less
// than the target or by returning a more detailed error.
//
// The two target arguments are coin-type-specific and mutually exclusive:
// pass `target` (dcrutil.Amount / int64 atoms) for VAR with `targetSKA` as
// cointype.Zero(); pass `targetSKA` (big.Int atoms) for SKA with `target` as
// 0. SKA targets cannot be truncated through int64 since SKA atoms can exceed
// math.MaxInt64 (AtomsPerCoin = 1e18).
type InputSource func(target dcrutil.Amount, targetSKA cointype.SKAAmount) (detail *InputDetail, err error)

// AuthoredTx holds the state of a newly-created transaction and the change
// output (if one was added).
type AuthoredTx struct {
	Tx                           *wire.MsgTx
	PrevScripts                  [][]byte
	TotalInput                   dcrutil.Amount
	SKATotalInput                cointype.SKAAmount // For SKA coins that exceed int64
	ChangeIndex                  int                // negative if no change
	EstimatedSignedSerializeSize int
}

// ChangeSource provides change output scripts and versions for
// transaction creation.
type ChangeSource interface {
	Script() (script []byte, version uint16, err error)
	ScriptSize() int
}

// nopChangeSource is a ChangeSource that produces no script. It is suitable
// for callers that have arranged for the inputs to sum to an exact target so
// no change output is ever required.
type nopChangeSource struct{}

func (nopChangeSource) Script() ([]byte, uint16, error) { return nil, 0, nil }
func (nopChangeSource) ScriptSize() int                  { return 0 }

// NewNopChangeSource returns a ChangeSource that never produces a change
// script. Pass it to NewUnsignedTransaction or NewUnsignedSweepTransaction
// when the caller knows no change output is needed (for example,
// exact-amount sends where the inputs sum to amount + fee).
func NewNopChangeSource() ChangeSource { return nopChangeSource{} }

// sumOutputValues sums the int64 Value field across outputs. VAR-only by
// construction: SKA outputs carry their value in SKAValue and have Value=0,
// so the int64 sum returned here is intentionally zero on the SKA path.
// Callers must dispatch on coin type and use sumSKAOutputValues for SKA.
func sumOutputValues(outputs []*wire.TxOut) (totalOutput dcrutil.Amount) {
	for _, txOut := range outputs {
		totalOutput += dcrutil.Amount(txOut.Value)
	}
	return totalOutput
}

// sumSKAOutputValues sums the SKAValue fields from transaction outputs.
// This is used for SKA transactions where amounts exceed int64.
func sumSKAOutputValues(outputs []*wire.TxOut) cointype.SKAAmount {
	total := cointype.Zero()
	for _, txOut := range outputs {
		if txOut.SKAValue != nil {
			total = total.Add(cointype.NewSKAAmount(txOut.SKAValue))
		}
	}
	return total
}

// NewUnsignedTransaction creates an unsigned transaction paying to one or more
// non-change outputs.  An appropriate transaction fee is included based on the
// transaction size.
//
// Transaction inputs are chosen from repeated calls to fetchInputs with
// increasing targets amounts.
//
// If any remaining output value can be returned to the wallet via a change
// output without violating mempool dust rules, a P2PKH change output is
// appended to the transaction outputs.  Since the change output may not be
// necessary, fetchChange.Script is called zero or one times to generate this
// script. This function must return a P2PKH script or smaller, otherwise fee
// estimation will be incorrect.
//
// subtractFeeFromAmountIdx selects the recipient output whose value is
// reduced by the transaction fee (Bitcoin Core's subtractfeefromamount
// behavior). Pass -1 to disable: inputs must then cover outputs + fee and
// the fee is paid out of change. When set to a valid output index, inputs
// only need to cover the requested output total; the recipient at outputs[idx]
// is *replaced* in the local outputs slice with a clone whose Value/SKAValue
// is reduced by the converged fee, so the caller's original *wire.TxOut is
// left untouched (safe to retry with the same slice). An error is returned
// if the post-subtraction amount falls at or below the dust threshold.
//
// If successful, the transaction, total input value spent, and all previous
// output scripts are returned.  If the input source was unable to provide
// enough input value to pay for every output any necessary fees, an
// InputSourceError is returned.
func NewUnsignedTransaction(outputs []*wire.TxOut, relayFeePerKb cointype.SKAAmount,
	fetchInputs InputSource, fetchChange ChangeSource, maxTxSize int,
	subtractFeeFromAmountIdx int) (*AuthoredTx, error) {

	coinType := cointype.CoinTypeVAR
	if len(outputs) > 0 {
		coinType = outputs[0].CoinType
		// All outputs in a single transaction must share the same coin
		// type; the node rejects mixed-coin transactions. Enforce here so
		// CLI tools that author transactions outside the wallet (e.g.
		// sweepaccount, movefunds) cannot bypass the wallet-level check
		// in validateAuthoredCoinTypes.
		for i := 1; i < len(outputs); i++ {
			if outputs[i].CoinType != coinType {
				return nil, errors.E(errors.Invalid, errors.Errorf(
					"all outputs must share the same coin type: outputs[0]=%d, outputs[%d]=%d",
					coinType, i, outputs[i].CoinType))
			}
		}
	}
	if subtractFeeFromAmountIdx >= 0 {
		if subtractFeeFromAmountIdx >= len(outputs) {
			return nil, errors.E(errors.Invalid, errors.Errorf(
				"subtractFeeFromAmountIdx %d out of range for %d outputs",
				subtractFeeFromAmountIdx, len(outputs)))
		}
	}
	return newUnsignedTransaction(coinType, outputs, relayFeePerKb,
		fetchInputs, fetchChange, maxTxSize, subtractFeeFromAmountIdx)
}

// NewUnsignedSweepTransaction creates an unsigned transaction with no
// non-change outputs of its own; the entire input value (minus fee) is
// returned to the change output. The coin type is supplied explicitly so the
// SKA fee/dust paths are taken even though the outputs slice is empty.
//
// fetchInputs is expected to return every spendable UTXO of the requested
// coin type in a single call (sweep semantics); standard incremental input
// sources will not produce a useful sweep tx.
//
// fetchChange must be a real change source whose Script produces the sweep
// destination — passing NewNopChangeSource here would produce a tx with no
// outputs.
func NewUnsignedSweepTransaction(coinType cointype.CoinType,
	relayFeePerKb cointype.SKAAmount, fetchInputs InputSource,
	fetchChange ChangeSource, maxTxSize int) (*AuthoredTx, error) {
	return newUnsignedTransaction(coinType, nil, relayFeePerKb,
		fetchInputs, fetchChange, maxTxSize, -1)
}

// newUnsignedTransaction is the shared implementation for
// NewUnsignedTransaction and NewUnsignedSweepTransaction. coinType is taken
// as an explicit parameter so empty-outputs sweeps still take the SKA paths
// for fee/dust/change construction.
//
// subtractFeeFromAmountIdx == -1 disables the subtractfeefromamount behavior;
// any other value names the output index whose Value/SKAValue will be reduced
// by the final fee. The recipient is replaced with a freshly allocated clone
// before the unsigned tx is constructed, so the caller's outputs slice
// retains its original *wire.TxOut values. The caller is responsible for
// ensuring the index is in range (NewUnsignedTransaction validates this;
// sweeps always pass -1).
func newUnsignedTransaction(coinType cointype.CoinType, outputs []*wire.TxOut,
	relayFeePerKb cointype.SKAAmount, fetchInputs InputSource,
	fetchChange ChangeSource, maxTxSize int,
	subtractFeeFromAmountIdx int) (*AuthoredTx, error) {

	const op errors.Op = "txauthor.NewUnsignedTransaction"

	isSKA := coinType.IsSKA()
	subtractFee := subtractFeeFromAmountIdx >= 0

	// For SKA, use big.Int amounts; for VAR, use int64
	targetAmount := sumOutputValues(outputs)
	targetSKAAmount := cointype.Zero()
	if isSKA {
		targetSKAAmount = sumSKAOutputValues(outputs)
	}

	scriptSizes := []int{txsizes.RedeemP2PKHSigScriptSize}
	// ScriptSize is cheap (no key derivation) and is needed up front for
	// fee estimation. The actual change script is fetched lazily inside
	// the hasChange branch below, so callers that never need change pay
	// no key-derivation cost.
	var changeScriptSize int
	if fetchChange != nil {
		changeScriptSize = fetchChange.ScriptSize()
	}
	var maxSignedSize int
	if isSKA {
		maxSignedSize = txsizes.EstimateSerializeSizeSKA(scriptSizes, outputs, changeScriptSize)
	} else {
		maxSignedSize = txsizes.EstimateSerializeSize(scriptSizes, outputs, changeScriptSize)
	}

	// Calculate initial fee for transaction size estimation using SKAAmount (big.Int).
	// SKA emission transactions have zero fees, but emission detection requires
	// the populated TxIn (the SKA marker lives in TxIn[0].SignatureScript), so
	// the determination only happens once inputs are fetched in the loop below.
	// The first iteration may overshoot the input target if this turns out to
	// be an emission tx; the loop's re-compute branch corrects it.
	targetFeeSKA := txrules.FeeForSerializeSizeSKA(relayFeePerKb, maxSignedSize)

	// Convert to dcrutil.Amount for VAR compatibility. VAR fees always fit
	// in int64 in normal operation; defensively check the SKAAmount→int64
	// conversion so a misconfigured per-coin-type relay fee produces a clear
	// error instead of silently miscomputed change.
	targetFee := dcrutil.Amount(0)
	if !isSKA {
		targetFeeInt64, err := targetFeeSKA.Int64()
		if err != nil {
			return nil, errors.E(op, errors.Invalid,
				"fee overflow: configured VAR relay fee rate produces a fee that exceeds int64")
		}
		targetFee = dcrutil.Amount(targetFeeInt64)
	}

	// Cap the grow-fee loop so a non-monotonic fetchInputs (returning
	// increasing-but-still-insufficient inputs across iterations) cannot
	// spin forever. In practice the loop converges in <=3 iterations; 32 is
	// generous safety margin without masking real input-source bugs.
	//
	// With subtractFee=true the loop always exits in the first iteration:
	// either the dust/cover-fee check below succeeds (then we fall through
	// to construct the tx) or it returns an error. The `continue` paths at
	// the bottom of the loop body only fire in the !subtractFee branches —
	// adding a `continue` inside the subtractFee block would re-enter the
	// recipient-clone step and double-subtract the fee.
	const maxFeeGrowIterations = 32
	for iter := 0; ; iter++ {
		if iter >= maxFeeGrowIterations {
			return nil, errors.E(op, errors.Invalid, errors.Errorf(
				"fee-grow loop exceeded %d iterations — input source is non-monotonic",
				maxFeeGrowIterations))
		}
		// Pass the coin-type-appropriate target. For VAR the big.Int
		// target is Zero so the input source only stops on int64 target;
		// for SKA the int64 target is 0 so the input source only stops on
		// big.Int target. This replaces the old "target=0 means everything"
		// hack which caused every SKA tx to co-spend all SKA UTXOs.
		//
		// In subtractfeefromamount mode the fee is paid by reducing the
		// recipient output, so inputs only need to cover the requested
		// output total — adding the fee here would cause the wallet to
		// over-select UTXOs (and could spuriously fail on InsufficientBalance
		// when the user has UTXOs covering the requested amount but not the
		// fee on top).
		var inputTarget dcrutil.Amount
		var inputTargetSKA cointype.SKAAmount
		if isSKA {
			if subtractFee {
				inputTargetSKA = targetSKAAmount
			} else {
				inputTargetSKA = targetSKAAmount.Add(targetFeeSKA)
			}
		} else {
			if subtractFee {
				inputTarget = targetAmount
			} else {
				inputTarget = targetAmount + targetFee
			}
			inputTargetSKA = cointype.Zero()
		}

		inputDetail, err := fetchInputs(inputTarget, inputTargetSKA)
		if err != nil {
			return nil, errors.E(op, err)
		}

		// Check if we have sufficient balance. In subtractfee mode the fee
		// is absorbed by the recipient output, so inputs ≥ targetAmount is
		// sufficient; the dust check on the post-subtraction recipient
		// amount happens after the fee stabilizes below.
		if isSKA {
			// For SKA, compare using big.Int (SKAAmount)
			required := targetSKAAmount
			if !subtractFee {
				required = targetSKAAmount.Add(targetFeeSKA)
			}
			if inputDetail.SKAAmount.Cmp(required) < 0 {
				// The source is exhausted (it returned everything it had,
				// short of outputs + fee-with-change). Before failing, try
				// the change-less shape — see changelessRescue.
				if !subtractFee {
					if tx := changelessRescue(coinType, outputs, relayFeePerKb,
						inputDetail, targetAmount, targetSKAAmount, maxTxSize); tx != nil {
						return tx, nil
					}
				}
				return nil, errors.E(op, errors.InsufficientBalance)
			}
		} else {
			required := targetAmount
			if !subtractFee {
				required = targetAmount + targetFee
			}
			if inputDetail.Amount < required {
				// Same change-less rescue as the SKA branch above.
				if !subtractFee {
					if tx := changelessRescue(coinType, outputs, relayFeePerKb,
						inputDetail, targetAmount, targetSKAAmount, maxTxSize); tx != nil {
						return tx, nil
					}
				}
				return nil, errors.E(op, errors.InsufficientBalance)
			}
		}

		scriptSizes := make([]int, 0, len(inputDetail.RedeemScriptSizes))
		scriptSizes = append(scriptSizes, inputDetail.RedeemScriptSizes...)

		if isSKA {
			maxSignedSize = txsizes.EstimateSerializeSizeSKA(scriptSizes, outputs, changeScriptSize)
		} else {
			maxSignedSize = txsizes.EstimateSerializeSize(scriptSizes, outputs, changeScriptSize)
		}

		// Calculate fee based on actual transaction size using SKAAmount (big.Int)
		// Check if this is an SKA emission transaction for final fee calculation
		tempTxWithInputs := &wire.MsgTx{
			SerType: wire.TxSerializeFull,
			Version: generatedTxVersion,
			TxIn:    inputDetail.Inputs,
			TxOut:   outputs,
		}
		// For SKA in subtractFee mode, the size estimate uses the
		// pre-subtraction recipient SKAValue. wire.TxOut for SKA is
		// length-prefixed by len(SKAValue.Bytes()), so when the converged
		// fee shrinks the recipient across a byte boundary the actually
		// signed tx is up to one byte smaller than the estimate. Net effect:
		// the user pays a fractionally higher effective fee rate — never
		// underpays. Do not "fix" this by recomputing the size after the
		// recipient clone; the conservatism is intentional and preserves
		// inputs ≥ outputs + fee under all SKA byte-length transitions.
		maxRequiredFeeSKA := txrules.FeeForSerializeSizeSKA(relayFeePerKb, maxSignedSize)
		if wire.IsSKAEmissionTransaction(tempTxWithInputs) {
			maxRequiredFeeSKA = cointype.Zero() // SKA emission transactions have zero fees
		}

		// Convert SKAAmount fee to dcrutil.Amount for VAR transactions.
		// Defensively check the conversion (see targetFee block above).
		var maxRequiredFee dcrutil.Amount
		if !isSKA {
			maxRequiredFeeInt64, err := maxRequiredFeeSKA.Int64()
			if err != nil {
				return nil, errors.E(op, errors.Invalid,
					"fee overflow: configured VAR relay fee rate produces a per-tx fee that exceeds int64")
			}
			maxRequiredFee = dcrutil.Amount(maxRequiredFeeInt64)
		}

		// Check remaining amount covers fees. In subtractfee mode the fee
		// is paid by reducing the recipient output (not by inputs covering
		// it on top), so we instead require that the recipient amount is
		// strictly larger than the fee plus the dust threshold; otherwise
		// the recipient would receive zero or a dust output.
		if subtractFee {
			if isSKA {
				recipientSKA := cointype.NewSKAAmount(outputs[subtractFeeFromAmountIdx].SKAValue)
				postFee := recipientSKA.Sub(maxRequiredFeeSKA)
				// Two strictly-disjoint branches: a non-positive postFee
				// means the recipient cannot pay the fee at all; a positive
				// postFee below the SKA dust threshold means it would
				// produce an unspendable output.
				if postFee.IsNegative() || postFee.IsZero() {
					return nil, errors.E(op, errors.Invalid, errors.Errorf(
						"subtractfeefromamount: recipient amount %s is less than fee %s",
						recipientSKA.BigInt().String(), maxRequiredFeeSKA.BigInt().String()))
				}
				if postFee.BigInt().Cmp(cointype.MinSKADustAmount) < 0 {
					return nil, errors.E(op, errors.Invalid, errors.Errorf(
						"subtractfeefromamount: recipient amount %s minus fee %s is below SKA dust threshold %s",
						recipientSKA.BigInt().String(), maxRequiredFeeSKA.BigInt().String(),
						cointype.MinSKADustAmount.String()))
				}
			} else {
				// Two strictly-disjoint branches: postFee <= 0 (recipient
				// cannot cover fee) is checked first, then dust. The dust
				// check below only sees a strictly positive postFee.
				recipient := dcrutil.Amount(outputs[subtractFeeFromAmountIdx].Value)
				postFee := recipient - maxRequiredFee
				if postFee <= 0 {
					return nil, errors.E(op, errors.Invalid, errors.Errorf(
						"subtractfeefromamount: recipient amount %v does not cover fee %v",
						recipient, maxRequiredFee))
				}
				dustFeeRateInt64, derr := relayFeePerKb.Int64()
				if derr != nil {
					return nil, errors.E(op, errors.Invalid,
						"fee overflow: configured VAR relay fee rate exceeds int64 in dust check")
				}
				// Use the recipient script's actual size for an accurate dust
				// check on the post-subtraction output.
				recipientScriptSize := len(outputs[subtractFeeFromAmountIdx].PkScript)
				if txrules.IsDustAmount(postFee, recipientScriptSize, dcrutil.Amount(dustFeeRateInt64)) {
					return nil, errors.E(op, errors.Invalid, errors.Errorf(
						"subtractfeefromamount: recipient amount %v minus fee %v is dust",
						recipient, maxRequiredFee))
				}
			}
		} else if isSKA {
			remainingSKA := inputDetail.SKAAmount.Sub(targetSKAAmount)
			if remainingSKA.Cmp(maxRequiredFeeSKA) < 0 {
				targetFeeSKA = maxRequiredFeeSKA
				continue
			}
		} else {
			remainingAmount := inputDetail.Amount - targetAmount
			if remainingAmount < maxRequiredFee {
				targetFee = maxRequiredFee
				continue
			}
		}

		if maxSignedSize > maxTxSize {
			return nil, errors.E(errors.Invalid, "signed tx size exceeds allowed maximum")
		}

		// In subtractfeefromamount mode, replace the recipient output with
		// a clone whose Value/SKAValue is reduced by the converged fee.
		// Cloning (rather than mutating outputs[idx] in place) keeps the
		// caller's *wire.TxOut intact, AND we copy the outputs slice so the
		// caller's slice header/elements are not mutated either — callers
		// that retry on error or reuse the slice see no silent corruption.
		// The dust check above guarantees the post-subtraction value is a
		// valid spendable output.
		if subtractFee {
			orig := outputs[subtractFeeFromAmountIdx]
			clone := &wire.TxOut{
				Value:    orig.Value,
				SKAValue: orig.SKAValue,
				CoinType: orig.CoinType,
				Version:  orig.Version,
				PkScript: orig.PkScript,
			}
			if isSKA {
				clone.SKAValue = cointype.NewSKAAmount(orig.SKAValue).
					Sub(maxRequiredFeeSKA).BigInt()
			} else {
				clone.Value = orig.Value - int64(maxRequiredFee)
			}
			localOutputs := make([]*wire.TxOut, len(outputs))
			copy(localOutputs, outputs)
			localOutputs[subtractFeeFromAmountIdx] = clone
			outputs = localOutputs
		}

		unsignedTransaction := &wire.MsgTx{
			SerType:  wire.TxSerializeFull,
			Version:  generatedTxVersion,
			TxIn:     inputDetail.Inputs,
			TxOut:    outputs,
			LockTime: 0,
			Expiry:   0,
		}
		changeIndex := -1

		// Calculate change amount based on coin type. In subtractfee mode
		// the fee was already absorbed by reducing the recipient output, so
		// change = inputs − requested target (no separate fee subtraction).
		// By conservation:
		//   inputs = (target − fee) + change + fee  ⇒  change = inputs − target.
		var changeAmount dcrutil.Amount
		var changeSKAAmount cointype.SKAAmount
		if isSKA {
			// SKA: use SKAAmount (big.Int) for full precision
			if subtractFee {
				changeSKAAmount = inputDetail.SKAAmount.Sub(targetSKAAmount)
			} else {
				changeSKAAmount = inputDetail.SKAAmount.Sub(targetSKAAmount).Sub(maxRequiredFeeSKA)
			}
		} else {
			// VAR: use dcrutil.Amount (int64)
			if subtractFee {
				changeAmount = inputDetail.Amount - targetAmount
			} else {
				changeAmount = inputDetail.Amount - targetAmount - maxRequiredFee
			}
		}

		// Check if change output should be added
		var hasChange bool
		if isSKA {
			// For SKA, minimum 30 atoms to avoid dust (28 atoms is minimal transfer fee).
			// TODO: Make MinSKADustAmount per-coin-type configurable via chaincfg.SKACoinConfig
			// if different SKA denominations require different dust thresholds.
			hasChange = !changeSKAAmount.IsNegative() && changeSKAAmount.BigInt().Cmp(cointype.MinSKADustAmount) >= 0
		} else {
			// For VAR, use dust check with fee rate converted to dcrutil.Amount.
			// Defensively guard the int64 conversion (see targetFee block above).
			dustFeeRateInt64, err := relayFeePerKb.Int64()
			if err != nil {
				return nil, errors.E(op, errors.Invalid,
					"fee overflow: configured VAR relay fee rate exceeds int64 in dust check")
			}
			hasChange = changeAmount != 0 && !txrules.IsDustAmount(changeAmount, changeScriptSize, dcrutil.Amount(dustFeeRateInt64))
		}

		if hasChange {
			if fetchChange == nil {
				return nil, errors.E(op, errors.Invalid,
					"change source required when change output would be created")
			}
			changeScript, changeScriptVersion, err := fetchChange.Script()
			if err != nil {
				return nil, errors.E(op, err)
			}
			if len(changeScript) > txscript.MaxScriptElementSize {
				return nil, errors.E(errors.Invalid, "script size exceed maximum bytes "+
					"pushable to the stack")
			}
			// Defense in depth against a future ChangeSource whose actual
			// script is larger than the size its ScriptSize() declared at
			// fee-estimation time. Fees were estimated using
			// `changeScriptSize` above; if the real script is wider, the
			// fee is silently underestimated. Fail loud here instead.
			if len(changeScript) > changeScriptSize {
				return nil, errors.E(errors.Invalid, errors.Errorf(
					"txauthor: change script size %d exceeds estimator-declared %d; "+
						"fee underestimated", len(changeScript), changeScriptSize))
			}

			change := &wire.TxOut{
				Version:  changeScriptVersion,
				PkScript: changeScript,
				CoinType: coinType,
			}

			// Set value based on coin type
			if isSKA {
				change.Value = 0 // SKA uses SKAValue, not Value
				change.SKAValue = changeSKAAmount.BigInt()
			} else {
				change.Value = int64(changeAmount)
			}

			l := len(outputs)
			unsignedTransaction.TxOut = append(outputs[:l:l], change)
			changeIndex = l
		} else {
			if isSKA {
				maxSignedSize = txsizes.EstimateSerializeSizeSKA(scriptSizes,
					unsignedTransaction.TxOut, 0)
			} else {
				maxSignedSize = txsizes.EstimateSerializeSize(scriptSizes,
					unsignedTransaction.TxOut, 0)
			}
		}
		return &AuthoredTx{
			Tx:                           unsignedTransaction,
			PrevScripts:                  inputDetail.Scripts,
			TotalInput:                   inputDetail.Amount,
			SKATotalInput:                inputDetail.SKAAmount,
			ChangeIndex:                  changeIndex,
			EstimatedSignedSerializeSize: maxSignedSize,
		}, nil
	}
}

// changelessRescue authors the transaction WITHOUT a change output when the
// input source is exhausted — it returned everything it had, which is short
// of outputs + fee-for-a-change-bearing-tx — but that total still covers the
// outputs plus the fee of the CHANGE-LESS serialization. The whole leftover
// (inputs − outputs) becomes the fee: at least the change-less minimum, and
// less than the with-change fee the caller just failed against.
//
// Without this, amounts in the narrow band between "spendable − sweepFee"
// and "spendable − changeFee" were unsendable with sender-pays-fee: the loop
// demanded the with-change fee, the source had no more inputs, and the
// authoring failed InsufficientBalance even though a perfectly valid and
// relayable change-less tx existed. User-visible absurdity: reduce a
// Max-filled amount by a few trailing digits (a handful of atoms — less
// than the fee difference) and "insufficient funds" appears for a SMALLER
// amount than the one that just worked.
//
// Returns nil when the shape doesn't apply — sweeps (no fixed outputs),
// empty selections, SKA emission transactions (zero-fee, miner-authored),
// an over-size serialization, or a leftover below the change-less fee —
// and the caller then fails with InsufficientBalance exactly as before.
// Never called in subtractfeefromamount mode (the fee comes out of the
// recipient there, so this shape cannot arise).
func changelessRescue(coinType cointype.CoinType, outputs []*wire.TxOut,
	relayFeePerKb cointype.SKAAmount, inputDetail *InputDetail,
	targetAmount dcrutil.Amount, targetSKAAmount cointype.SKAAmount,
	maxTxSize int) *AuthoredTx {

	if len(outputs) == 0 || len(inputDetail.Inputs) == 0 {
		return nil
	}
	isSKA := coinType.IsSKA()
	scriptSizes := append([]int(nil), inputDetail.RedeemScriptSizes...)
	var changelessSize int
	if isSKA {
		changelessSize = txsizes.EstimateSerializeSizeSKA(scriptSizes, outputs, 0)
	} else {
		changelessSize = txsizes.EstimateSerializeSize(scriptSizes, outputs, 0)
	}
	if changelessSize > maxTxSize {
		return nil
	}
	changelessFeeSKA := txrules.FeeForSerializeSizeSKA(relayFeePerKb, changelessSize)
	if isSKA {
		tempTx := &wire.MsgTx{
			SerType: wire.TxSerializeFull,
			Version: generatedTxVersion,
			TxIn:    inputDetail.Inputs,
			TxOut:   outputs,
		}
		if wire.IsSKAEmissionTransaction(tempTx) {
			return nil
		}
		remaining := inputDetail.SKAAmount.Sub(targetSKAAmount)
		if remaining.IsNegative() || remaining.Cmp(changelessFeeSKA) < 0 {
			return nil
		}
	} else {
		changelessFeeInt64, err := changelessFeeSKA.Int64()
		if err != nil {
			return nil
		}
		remaining := inputDetail.Amount - targetAmount
		if remaining < dcrutil.Amount(changelessFeeInt64) {
			return nil
		}
	}
	return &AuthoredTx{
		Tx: &wire.MsgTx{
			SerType:  wire.TxSerializeFull,
			Version:  generatedTxVersion,
			TxIn:     inputDetail.Inputs,
			TxOut:    outputs,
			LockTime: 0,
			Expiry:   0,
		},
		PrevScripts:                  inputDetail.Scripts,
		TotalInput:                   inputDetail.Amount,
		SKATotalInput:                inputDetail.SKAAmount,
		ChangeIndex:                  -1,
		EstimatedSignedSerializeSize: changelessSize,
	}
}

// RandomizeOutputPosition randomizes the position of a transaction's output by
// swapping it with a random output.  The new index is returned.  This should be
// done before signing.
func RandomizeOutputPosition(outputs []*wire.TxOut, index int) int {
	r := rand.Int32N(int32(len(outputs)))
	outputs[r], outputs[index] = outputs[index], outputs[r]
	return int(r)
}

// RandomizeChangePosition randomizes the position of an authored transaction's
// change output.  This should be done before signing.  It does nothing for a
// tx without change.
func (tx *AuthoredTx) RandomizeChangePosition() {
	if tx.ChangeIndex < 0 {
		return
	}
	tx.ChangeIndex = RandomizeOutputPosition(tx.Tx.TxOut, tx.ChangeIndex)
}

// SecretsSource provides private keys and redeem scripts necessary for
// constructing transaction input signatures.  Secrets are looked up by the
// corresponding Address for the previous output script.  Addresses for lookup
// are created using the source's blockchain parameters and means a single
// SecretsSource can only manage secrets for a single chain.
//
// TODO: Rewrite this interface to look up private keys and redeem scripts for
// pubkeys, pubkey hashes, script hashes, etc. as separate interface methods.
// This would remove the ChainParams requirement of the interface and could
// avoid unnecessary conversions from previous output scripts to Addresses.
// This can not be done without modifications to the txscript package.
type SecretsSource interface {
	sign.KeyDB
	sign.ScriptDB
	ChainParams() *chaincfg.Params
}

// AddAllInputScripts modifies transaction a transaction by adding inputs
// scripts for each input.  Previous output scripts being redeemed by each input
// are passed in prevPkScripts and the slice length must match the number of
// inputs.  Private keys and redeem scripts are looked up using a SecretsSource
// based on the previous output script.
func AddAllInputScripts(tx *wire.MsgTx, prevPkScripts [][]byte, secrets SecretsSource) error {
	inputs := tx.TxIn
	chainParams := secrets.ChainParams()

	if len(inputs) != len(prevPkScripts) {
		return errors.New("tx.TxIn and prevPkScripts slices must " +
			"have equal length")
	}

	for i := range inputs {
		pkScript := prevPkScripts[i]
		sigScript := inputs[i].SignatureScript
		script, err := sign.SignTxOutput(chainParams, tx, i,
			pkScript, txscript.SigHashAll, secrets, secrets,
			sigScript, true) // Yes treasury
		if err != nil {
			return err
		}
		inputs[i].SignatureScript = script
	}

	return nil
}

// AddAllInputScripts modifies an authored transaction by adding inputs scripts
// for each input of an authored transaction.  Private keys and redeem scripts
// are looked up using a SecretsSource based on the previous output script.
func (tx *AuthoredTx) AddAllInputScripts(secrets SecretsSource) error {
	return AddAllInputScripts(tx.Tx, tx.PrevScripts, secrets)
}
