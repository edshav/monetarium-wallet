// Copyright (c) 2016-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"time"

	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/internal/compat"
	"github.com/monetarium/monetarium-wallet/wallet/txauthor"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/txscript"
	"github.com/monetarium/monetarium-node/txscript/stdscript"
	"github.com/monetarium/monetarium-node/wire"
)

// OutputSelectionPolicy describes the rules for selecting an output from the
// wallet.
type OutputSelectionPolicy struct {
	Account               uint32
	RequiredConfirmations int32
	CoinType              cointype.CoinType // Required: transactions cannot mix coin types
}

func (p *OutputSelectionPolicy) meetsRequiredConfs(txHeight, curHeight int32) bool {
	return confirmed(p.RequiredConfirmations, txHeight, curHeight)
}

// UnspentOutputs fetches all unspent outputs from the wallet that match rules
// described in the passed policy.
func (w *Wallet) UnspentOutputs(ctx context.Context, policy OutputSelectionPolicy) ([]*TransactionOutput, error) {
	const op errors.Op = "wallet.UnspentOutputs"

	defer w.lockedOutpointMu.Unlock()
	w.lockedOutpointMu.Lock()

	var outputResults []*TransactionOutput
	err := walletdb.View(ctx, w.db, func(dbtx walletdb.ReadTx) error {
		addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)

		_, tipHeight := w.txStore.MainChainTip(dbtx)

		// TODO: actually stream outputs from the db instead of fetching
		// all of them at once.
		outputs, err := w.txStore.UnspentOutputs(dbtx, policy.CoinType)
		if err != nil {
			return err
		}
		stakeGenMatured := func(c *udb.Credit) bool {
			return w.txStore.StakeGenMatured(dbtx, c, tipHeight)
		}

		for _, output := range outputs {
			// Ignore outputs that haven't reached the required
			// number of confirmations.
			if !policy.meetsRequiredConfs(output.Height, tipHeight) {
				continue
			}

			// Ignore outputs that are not controlled by the account.
			_, addrs := stdscript.ExtractAddrs(scriptVersionAssumed, output.PkScript, w.chainParams)
			if len(addrs) == 0 {
				// Cannot determine which account this belongs
				// to without a valid address.  TODO: Fix this
				// by saving outputs per account, or accounts
				// per output.
				continue
			}
			outputAcct, err := w.manager.AddrAccount(addrmgrNs, addrs[0])
			if err != nil {
				return err
			}
			if outputAcct != policy.Account {
				continue
			}

			// Filter by coin type - must match policy's coin type
			if output.CoinType != policy.CoinType {
				continue
			}

			// Leave out tickets and immature outputs: the node
			// rejects a regular tx that spends them.
			if !creditSpendable(w.chainParams, output, tipHeight, stakeGenMatured) {
				continue
			}

			// Stakebase isn't exposed by wtxmgr so those will be
			// OutputKindNormal for now.
			outputSource := OutputKindNormal
			if output.FromCoinBase {
				outputSource = OutputKindCoinbase
			}

			result := &TransactionOutput{
				OutPoint: output.OutPoint,
				Output: wire.TxOut{
					Value: int64(output.Amount),
					// TODO: version is bogus but there is
					// only version 0 at time of writing.
					Version:  0,
					PkScript: output.PkScript,
					CoinType: output.CoinType,
				},
				OutputKind:      outputSource,
				ContainingBlock: BlockIdentity(output.Block),
				ReceiveTime:     output.Received,
			}
			// For SKA UTXOs the int64 Value field is meaningless (atoms
			// can exceed int64); the authoritative atom count lives in
			// SKAValue. Mirror the pattern used by OutputInfo above so
			// callers that read result.Output.SKAValue see the real value
			// instead of nil. SKAAmount.BigInt() returns a fresh copy.
			if output.CoinType.IsSKA() {
				result.Output.Value = 0
				result.Output.SKAValue = output.SKAAmount.BigInt()
			}
			outputResults = append(outputResults, result)
		}

		return nil
	})
	if err != nil {
		return nil, errors.E(op, err)
	}
	return outputResults, nil
}

// creditSpendable reports whether a credit may be spent by a regular
// transaction mined after tipHeight.  The rules are those of
// MakeInputSourceWithCoinType.  stakeGenMatured decides OP_SSGEN credits,
// whose maturity depends on whether they are vote or SSFee outputs.
func creditSpendable(params *chaincfg.Params, output *udb.Credit, tipHeight int32,
	stakeGenMatured func(*udb.Credit) bool) bool {
	txHeight := output.Height
	coinbaseMature := coinbaseMatured(params, txHeight, tipHeight)
	if output.HasExpiry && !coinbaseMature {
		return false
	}

	var op byte
	if len(output.PkScript) > 0 {
		op = output.PkScript[0]
	}
	switch op {
	case txscript.OP_SSTX:
		// Live tickets are only spendable by SSGen, never by a regular send.
		return false
	case txscript.OP_SSGEN:
		return stakeGenMatured(output)
	case txscript.OP_SSRTX, txscript.OP_TADD, txscript.OP_TGEN:
		return coinbaseMature
	case txscript.OP_SSTXCHANGE:
		return ticketChangeMatured(params, txHeight, tipHeight)
	}
	if output.FromCoinBase {
		return coinbaseMature
	}
	return true
}

// SelectInputs selects transaction inputs to redeem unspent outputs stored in
// the wallet. It returns an input detail summary. For VAR coin-type policies
// the `targetAmount` parameter drives selection and `targetSKAAmount` is
// ignored; for SKA the big.Int `targetSKAAmount` drives selection and
// `targetAmount` is ignored. Callers that don't need SKA precision can pass
// cointype.Zero().
func (w *Wallet) SelectInputs(ctx context.Context, targetAmount dcrutil.Amount, targetSKAAmount cointype.SKAAmount, policy OutputSelectionPolicy) (inputDetail *txauthor.InputDetail, err error) {
	const op errors.Op = "wallet.SelectInputs"

	defer w.lockedOutpointMu.Unlock()
	w.lockedOutpointMu.Lock()

	err = walletdb.View(ctx, w.db, func(dbtx walletdb.ReadTx) error {
		addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
		_, tipHeight := w.txStore.MainChainTip(dbtx)

		if policy.Account != udb.ImportedAddrAccount {
			lastAcct, err := w.manager.LastAccount(addrmgrNs)
			if err != nil {
				return err
			}
			if policy.Account > lastAcct {
				return errors.E(errors.NotExist, "account not found")
			}
		}

		sourceImpl := w.txStore.MakeInputSourceWithCoinType(dbtx, policy.Account,
			policy.RequiredConfirmations, tipHeight, nil, policy.CoinType)
		var err error
		inputDetail, err = sourceImpl.SelectInputs(targetAmount, targetSKAAmount)
		return err
	})
	if err != nil {
		err = errors.E(op, err)
	}
	return inputDetail, err
}

// OutputInfo describes additional info about an output which can be queried
// using an outpoint.
type OutputInfo struct {
	Received     time.Time
	Amount       dcrutil.Amount
	FromCoinbase bool
	CoinType     cointype.CoinType
	SKAAmount    cointype.SKAAmount
}

// OutputInfo queries the wallet for additional transaction output info
// regarding an outpoint.
func (w *Wallet) OutputInfo(ctx context.Context, out *wire.OutPoint) (OutputInfo, error) {
	const op errors.Op = "wallet.OutputInfo"
	var info OutputInfo
	err := walletdb.View(ctx, w.db, func(dbtx walletdb.ReadTx) error {
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

		txDetails, err := w.txStore.TxDetails(txmgrNs, &out.Hash)
		if err != nil {
			return err
		}
		if out.Index >= uint32(len(txDetails.TxRecord.MsgTx.TxOut)) {
			return errors.Errorf("transaction has no output %d", out.Index)
		}

		txOut := txDetails.TxRecord.MsgTx.TxOut[out.Index]
		info.Received = txDetails.Received
		info.CoinType = txOut.CoinType
		// Keep the int64 Amount field VAR-only. For SKA outputs the
		// authoritative atom count is in SKAAmount; leaving Amount at 0
		// avoids handing callers a silently-truncated int64.
		if txOut.CoinType.IsSKA() {
			if txOut.SKAValue != nil {
				info.SKAAmount = cointype.NewSKAAmount(txOut.SKAValue)
			}
		} else {
			info.Amount = dcrutil.Amount(txOut.Value)
		}
		info.FromCoinbase = compat.IsEitherCoinBaseTx(&txDetails.TxRecord.MsgTx)
		return nil
	})
	if err != nil {
		// Return a zero-valued OutputInfo on error so a caller that
		// dispatches on info.CoinType without checking err first cannot
		// confuse a missing SKA output (CoinType==0 zero-default) for a
		// real VAR output.
		return OutputInfo{}, errors.E(op, err)
	}
	return info, nil
}
