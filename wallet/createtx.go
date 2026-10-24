// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2024 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/monetarium/monetarium-wallet/deployments"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet/txauthor"
	"github.com/monetarium/monetarium-wallet/wallet/txrules"
	"github.com/monetarium/monetarium-wallet/wallet/txsizes"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
	"github.com/monetarium/monetarium-node/blockchain/stake"
	blockchain "github.com/monetarium/monetarium-node/blockchain/standalone"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/crypto/rand"
	"github.com/monetarium/monetarium-node/dcrec"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/mixing/mixclient"
	"github.com/monetarium/monetarium-node/txscript"
	"github.com/monetarium/monetarium-node/txscript/sign"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/txscript/stdscript"
	"github.com/monetarium/monetarium-node/wire"
)

// --------------------------------------------------------------------------------
// Constants and simple functions

const (
	revocationFeeLimit = 1 << 14

	// maxStandardTxSize is the maximum size allowed for transactions that
	// are considered standard and will therefore be relayed and considered
	// for mining.
	// TODO: import from mond.
	maxStandardTxSize = 100000

	// sanityVerifyFlags are the flags used to enable and disable features of
	// the txscript engine used for sanity checking of transactions signed by
	// the wallet.
	sanityVerifyFlags = txscript.ScriptDiscourageUpgradableNops |
		txscript.ScriptVerifyCleanStack |
		txscript.ScriptVerifyCheckLockTimeVerify |
		txscript.ScriptVerifyCheckSequenceVerify |
		txscript.ScriptVerifyTreasury

	// multisigFeePreSelectInputGuess is the input-count upper bound used
	// when computing the pre-selection fee budget in
	// txToMultisigInternal (both VAR and SKA branches). The post-selection
	// real-fee recompute is the authoritative balance check, so over-
	// estimating here is harmless (it just pulls more inputs than strictly
	// needed); under-estimating produces a spurious InsufficientBalance for
	// fragmented wallets that would otherwise have enough to cover the real
	// fee.
	//
	// 200 covers all but pathologically dust-fragmented wallets while still
	// fitting within standard tx size bounds. Raised from 50 because the
	// previous limit produced spurious InsufficientBalance errors on wallets
	// with >50 dust UTXOs. The proper fix is the iterative grow-on-shortfall
	// pattern from txauthor.NewUnsignedTransaction; until that lands here,
	// 200 leaves enough headroom for the realistic worst case.
	multisigFeePreSelectInputGuess = 200
)

// Input provides transaction inputs referencing spendable outputs.
type Input struct {
	OutPoint wire.OutPoint
	PrevOut  wire.TxOut
	CoinType cointype.CoinType
}

// --------------------------------------------------------------------------------
// Transaction creation

// OutputSelectionAlgorithm specifies the algorithm to use when selecting outputs
// to construct a transaction.
type OutputSelectionAlgorithm uint

const (
	// OutputSelectionAlgorithmDefault describes the default output selection
	// algorithm.  It is not optimized for any particular use case.
	OutputSelectionAlgorithmDefault = iota

	// OutputSelectionAlgorithmAll describes the output selection algorithm of
	// picking every possible available output.  This is useful for sweeping.
	OutputSelectionAlgorithmAll
)

// NewUnsignedTransaction constructs an unsigned transaction using unspent
// account outputs.
//
// The changeSource and inputSource parameters are optional and can be nil.
// When the changeSource is nil and change output should be added, an internal
// change address is created for the account.  When the inputSource is nil,
// the inputs will be selected by the wallet.
//
// relayFeePerKbOverride is an optional caller-supplied per-kB relay fee that
// takes effect for this single transaction. When zero, the wallet falls back
// to RelayFeeForCoinType for the inferred output coin type. The override is
// expressed as cointype.SKAAmount so the same parameter carries either a VAR
// fee (int64-shaped) or an SKA fee (big.Int) without truncation.
//
// The coin type is inferred from outputs[0].CoinType; with no outputs (sweep
// semantics) the inferred coin type is VAR. Callers needing to sweep a
// non-VAR account must use NewUnsignedSweepTransactionForCoinType.
func (w *Wallet) NewUnsignedTransaction(ctx context.Context, outputs []*wire.TxOut,
	relayFeePerKbOverride cointype.SKAAmount, account uint32, minConf int32,
	algo OutputSelectionAlgorithm, changeSource txauthor.ChangeSource, inputSource txauthor.InputSource) (*txauthor.AuthoredTx, error) {

	txCoinType := cointype.CoinTypeVAR
	if len(outputs) > 0 {
		txCoinType = outputs[0].CoinType
	}
	return w.newUnsignedTransactionWithCoinType(ctx, txCoinType, outputs,
		relayFeePerKbOverride, account, minConf, algo, changeSource, inputSource)
}

// NewUnsignedSweepTransactionForCoinType is the coin-type-aware sweep variant
// of NewUnsignedTransaction. It accepts no outputs (the destination receives
// the swept amount minus fees via changeSource) and requires the caller to
// specify the coin type explicitly so SKA accounts can be swept.
func (w *Wallet) NewUnsignedSweepTransactionForCoinType(ctx context.Context,
	txCoinType cointype.CoinType, relayFeePerKbOverride cointype.SKAAmount,
	account uint32, minConf int32, changeSource txauthor.ChangeSource) (*txauthor.AuthoredTx, error) {

	return w.newUnsignedTransactionWithCoinType(ctx, txCoinType, nil,
		relayFeePerKbOverride, account, minConf, OutputSelectionAlgorithmAll, changeSource, nil)
}

// newUnsignedTransactionWithCoinType is the shared implementation behind
// NewUnsignedTransaction (output-driven coin type inference) and
// NewUnsignedSweepTransactionForCoinType (explicit coin type for sweep).
func (w *Wallet) newUnsignedTransactionWithCoinType(ctx context.Context,
	txCoinType cointype.CoinType, outputs []*wire.TxOut,
	relayFeePerKbOverride cointype.SKAAmount, account uint32, minConf int32,
	algo OutputSelectionAlgorithm, changeSource txauthor.ChangeSource, inputSource txauthor.InputSource) (*txauthor.AuthoredTx, error) {

	const op errors.Op = "wallet.NewUnsignedTransaction"

	defer w.lockedOutpointMu.Unlock()
	w.lockedOutpointMu.Lock()

	var authoredTx *txauthor.AuthoredTx
	var changeSourceUpdates []func(walletdb.ReadWriteTx) error
	err := walletdb.View(ctx, w.db, func(dbtx walletdb.ReadTx) error {
		addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)

		if account != udb.ImportedAddrAccount {
			lastAcct, err := w.manager.LastAccount(addrmgrNs)
			if err != nil {
				return err
			}
			if account > lastAcct {
				return errors.E(errors.NotExist, "missing account")
			}
		}

		// Create coin-type-aware input source if nil. When the caller
		// requests OutputSelectionAlgorithmAll (sweep semantics), wrap the
		// default source so it always invokes the underlying store with the
		// no-target sentinel (target=0, targetSKA=Zero), which drains every
		// eligible UTXO regardless of the incremental target txauthor would
		// otherwise pass on each iteration. Without this wrap the
		// "all outputs" algorithm degenerates to "just enough to cover fee".
		if inputSource == nil {
			_, tipHeight := w.txStore.MainChainTip(dbtx)
			ignoreInput := func(op *wire.OutPoint) bool {
				_, ok := w.lockedOutpoints[outpoint{op.Hash, op.Index}]
				return ok
			}
			inputSourceObj := w.txStore.MakeInputSourceWithCoinType(dbtx, account,
				minConf, tipHeight, ignoreInput, txCoinType)
			if algo == OutputSelectionAlgorithmAll {
				inputSource = func(dcrutil.Amount, cointype.SKAAmount) (*txauthor.InputDetail, error) {
					return inputSourceObj.SelectInputs(0, cointype.Zero())
				}
			} else {
				inputSource = inputSourceObj.SelectInputs
			}
		}

		if changeSource == nil {
			changeSource = &p2PKHChangeSource{
				persist: w.deferPersistReturnedChild(ctx, &changeSourceUpdates),
				account: account,
				wallet:  w,
				ctx:     context.Background(),
			}
		}

		// Honor caller's per-kB relay fee override when supplied; else
		// resolve the wallet-configured fee for the inferred coin type.
		var actualRelayFee cointype.SKAAmount
		if !relayFeePerKbOverride.IsZero() {
			actualRelayFee = relayFeePerKbOverride
		} else {
			actualRelayFee = w.RelayFeeForCoinType(ctx, txCoinType)
		}
		if txCoinType.IsSKA() && actualRelayFee.IsZero() {
			return errors.E(errors.Invalid, fmt.Sprintf(
				"no relay fee configured for coin type %d; cannot author transaction", txCoinType))
		}

		var err error
		// Sweep semantics: outputs is empty and the caller wants "drain
		// every UTXO of txCoinType to changeSource". txauthor.NewUnsignedTransaction
		// infers coin type from outputs[0], so with no outputs it defaults
		// to VAR — for SKA sweeps that mis-infers and the int64 balance check
		// fires "insufficient balance" because SKA UTXOs report Amount=0
		// (atom value lives in the big.Int SKAAmount). NewUnsignedSweepTransaction
		// takes coin type explicitly so the SKA paths are taken.
		if algo == OutputSelectionAlgorithmAll && len(outputs) == 0 {
			authoredTx, err = txauthor.NewUnsignedSweepTransaction(txCoinType, actualRelayFee,
				inputSource, changeSource, w.chainParams.MaxTxSize)
		} else {
			authoredTx, err = txauthor.NewUnsignedTransaction(outputs, actualRelayFee,
				inputSource, changeSource, w.chainParams.MaxTxSize, -1)
		}
		if err != nil {
			return err
		}

		// Set coin type on change output if present
		if authoredTx.ChangeIndex >= 0 {
			authoredTx.Tx.TxOut[authoredTx.ChangeIndex].CoinType = txCoinType
		}

		// Dual-coin validation: ensure all outputs and inputs share the
		// same coin type before returning the authored tx.
		if err := w.validateAuthoredCoinTypes(dbtx, authoredTx.Tx); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, errors.E(op, err)
	}
	if len(changeSourceUpdates) != 0 {
		err := walletdb.Update(ctx, w.db, func(tx walletdb.ReadWriteTx) error {
			for _, up := range changeSourceUpdates {
				err := up(tx)
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return nil, errors.E(op, err)
		}
	}
	return authoredTx, nil
}

// ErrExternalInputInAuthoredTx is the sentinel returned by
// validateAuthoredCoinTypes when an input's previous output is not in this
// wallet's UTXO set. It lets RPC handlers distinguish "operator passed an
// externally-funded input to an authoring path that requires wallet-owned
// inputs" from generic "Invalid" so callers (e.g. signrawtransaction) can
// surface a more actionable error and route to the right validation path.
var ErrExternalInputInAuthoredTx = errors.New("input previous output not found in wallet UTXO set; foreign inputs must use signrawtransaction")

// validateAuthoredCoinTypes verifies that every output and every input of an
// authored transaction shares the same coin type. The check is run under the
// caller's dbtx so input UTXO lookups see a consistent snapshot. It is shared
// between the public NewUnsignedTransaction and the internal authorTx
// codepaths so a single source of truth gates mixed-coin transactions before
// they reach the network.
//
// Precondition: every input's previous output must be present in this
// wallet's own UTXO set; foreign inputs are rejected with
// ErrExternalInputInAuthoredTx. Callers handling externally-supplied inputs
// (e.g. signrawtransaction) must use a different validation path.
func (w *Wallet) validateAuthoredCoinTypes(dbtx walletdb.ReadTx, tx *wire.MsgTx) error {
	// txauthor never produces a tx with zero outputs, but failing loud here
	// is more informative than silently passing the per-input coin-type
	// check below. A degenerate inputs-only tx has no expected coin type
	// and cannot be classified.
	if len(tx.TxOut) == 0 {
		return errors.E(errors.Invalid,
			"validateAuthoredCoinTypes: transaction has no outputs")
	}
	expectedCoinType := tx.TxOut[0].CoinType
	for i, txOut := range tx.TxOut {
		if txOut.CoinType != expectedCoinType {
			return errors.E(errors.Invalid,
				fmt.Sprintf("output %d coin type %d does not match expected coin type %d",
					i, txOut.CoinType, expectedCoinType))
		}
		// Defense-in-depth: SKA outputs must carry their atom value in
		// SKAValue (big.Int) with Value=0; VAR outputs must have
		// SKAValue=nil. A logically-mixed output (both fields set, or
		// neither) would pass the per-output coin-type check above and
		// reach the network where it would be rejected — failing here
		// surfaces the bug at authoring time.
		if txOut.CoinType.IsSKA() {
			if txOut.Value != 0 {
				return errors.E(errors.Invalid,
					fmt.Sprintf("output %d is SKA but Value=%d (must be 0)",
						i, txOut.Value))
			}
			if txOut.SKAValue == nil {
				return errors.E(errors.Invalid,
					fmt.Sprintf("output %d is SKA but SKAValue is nil", i))
			}
		} else if txOut.SKAValue != nil {
			return errors.E(errors.Invalid,
				fmt.Sprintf("output %d is VAR but SKAValue is non-nil", i))
		}
	}
	if len(tx.TxIn) == 0 {
		return nil
	}
	txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)
	for i, txIn := range tx.TxIn {
		prevCredit, err := w.txStore.UnspentOutput(txmgrNs, txIn.PreviousOutPoint, true)
		if err != nil {
			return errors.E(errors.Invalid,
				fmt.Errorf("input %d: %w: %v", i, ErrExternalInputInAuthoredTx, err))
		}
		if prevCredit.CoinType != expectedCoinType {
			return errors.E(errors.Invalid,
				fmt.Sprintf("input %d coin type %d does not match output coin type %d",
					i, prevCredit.CoinType, expectedCoinType))
		}
	}
	return nil
}

// secretSource is an implementation of txauthor.SecretSource for the wallet's
// address manager.
type secretSource struct {
	*udb.Manager
	addrmgrNs walletdb.ReadBucket
	doneFuncs []func()
}

func (s *secretSource) GetKey(addr stdaddr.Address) ([]byte, dcrec.SignatureType, bool, error) {
	privKey, done, err := s.Manager.PrivateKey(s.addrmgrNs, addr)
	if err != nil {
		return nil, 0, false, err
	}
	s.doneFuncs = append(s.doneFuncs, done)
	return privKey.Serialize(), dcrec.STEcdsaSecp256k1, true, nil
}

func (s *secretSource) GetScript(addr stdaddr.Address) ([]byte, error) {
	return s.Manager.RedeemScript(s.addrmgrNs, addr)
}

// SecretsSource is an implementation of txauthor.SecretsSource querying the
// wallet's address manager.
//
// The Close method must be called after the SecretsSource usage is over.
type SecretsSource struct {
	wallet    *Wallet
	dbtx      walletdb.ReadTx
	doneFuncs []func()
}

// SecretsSource returns a txauthor.SecretsSource implementor using the wallet
// as the backing store for keys and scripts.
func (w *Wallet) SecretsSource() (*SecretsSource, error) {
	dbtx, err := w.db.BeginReadTx()
	if err != nil {
		return nil, err
	}
	return &SecretsSource{wallet: w, dbtx: dbtx}, nil
}

// ChainParams returns the chain parameters.
func (s *SecretsSource) ChainParams() *chaincfg.Params {
	return s.wallet.chainParams
}

// GetKey provides the private key associated with an address.
func (s *SecretsSource) GetKey(addr stdaddr.Address) (key []byte, sigType dcrec.SignatureType, compressed bool, err error) {
	addrmgrNs := s.dbtx.ReadBucket(waddrmgrNamespaceKey)
	privKey, done, err := s.wallet.manager.PrivateKey(addrmgrNs, addr)
	if err != nil {
		return
	}
	s.doneFuncs = append(s.doneFuncs, done)
	return privKey.Serialize(), dcrec.STEcdsaSecp256k1, true, nil
}

// GetScript provides the redeem script for a P2SH address.
func (s *SecretsSource) GetScript(addr stdaddr.Address) ([]byte, error) {
	addrmgrNs := s.dbtx.ReadBucket(waddrmgrNamespaceKey)
	return s.wallet.manager.RedeemScript(addrmgrNs, addr)
}

// Close finishes the SecretsSource usage by releasing all secret key material
// and closing the underlying database transaction.
func (s *SecretsSource) Close() error {
	for _, f := range s.doneFuncs {
		f()
	}
	s.doneFuncs = nil
	err := s.dbtx.Rollback()
	if err == nil {
		s.dbtx = nil
	}
	return err
}

// CreatedTx holds the state of a newly-created transaction and the change
// output (if one was added).
type CreatedTx struct {
	MsgTx       *wire.MsgTx
	ChangeAddr  stdaddr.Address
	ChangeIndex int // negative if no change
	Fee         dcrutil.Amount
}

// insertIntoTxMgr inserts a newly created transaction into the tx store
// as unconfirmed.
func (w *Wallet) insertIntoTxMgr(dbtx walletdb.ReadWriteTx, msgTx *wire.MsgTx) (*udb.TxRecord, error) {
	// Create transaction record and insert into the db.
	rec, err := udb.NewTxRecordFromMsgTx(msgTx, time.Now())
	if err != nil {
		return nil, err
	}

	err = w.txStore.InsertMemPoolTx(dbtx, rec)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// insertCreditsIntoTxMgr inserts the wallet credits from msgTx to the wallet's
// transaction store. It assumes msgTx is a regular transaction, which will
// cause balance issues if this is called from a code path where msgtx is not
// guaranteed to be a regular tx.
func (w *Wallet) insertCreditsIntoTxMgr(op errors.Op, dbtx walletdb.ReadWriteTx, msgTx *wire.MsgTx, rec *udb.TxRecord) error {
	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)

	// Check every output to determine whether it is controlled by a wallet
	// key.  If so, mark the output as a credit.
	for i, output := range msgTx.TxOut {
		_, addrs := stdscript.ExtractAddrs(output.Version, output.PkScript, w.chainParams)
		for _, addr := range addrs {
			ma, err := w.manager.Address(addrmgrNs, addr)
			if err == nil {
				// TODO: Credits should be added with the
				// account they belong to, so wtxmgr is able to
				// track per-account balances.
				err = w.txStore.AddCredit(dbtx, rec, nil,
					uint32(i), ma.Internal(), ma.Account())
				if err != nil {
					return errors.E(op, err)
				}
				err = w.markUsedAddress(op, dbtx, ma)
				if err != nil {
					return err
				}
				log.Debugf("Marked address %v used", addr)
				continue
			}

			// Missing addresses are skipped.  Other errors should
			// be propagated.
			if !errors.Is(err, errors.NotExist) {
				return errors.E(op, err)
			}
		}
	}

	return nil
}

// insertMultisigOutIntoTxMgr inserts a multisignature output into the
// transaction store database.
func (w *Wallet) insertMultisigOutIntoTxMgr(dbtx walletdb.ReadWriteTx, msgTx *wire.MsgTx, index uint32) error {
	// Create transaction record and insert into the db.
	rec, err := udb.NewTxRecordFromMsgTx(msgTx, time.Now())
	if err != nil {
		return err
	}

	return w.txStore.AddMultisigOut(dbtx, rec, nil, index)
}

// checkHighFees performs a high fee check if enabled and possible, returning an
// error if the transaction pays high fees. The check is coin-type aware:
// SKA transactions are evaluated against PaysHighFeesSKA, which uses the chain
// params' MinRelayTxFee × MaxFeeMultiplier × txSize threshold (relative to the
// per-coin relay fee, not an absolute amount), so naturally-priced SKA fees
// scale the cap up automatically. Pass cointype.Zero() for the unused total in
// each branch.
func (w *Wallet) checkHighFees(totalVARInput dcrutil.Amount, totalSKAInput cointype.SKAAmount, tx *wire.MsgTx) error {
	if w.allowHighFees {
		return nil
	}
	coinType := txrules.GetCoinTypeFromOutputs(tx.TxOut)
	if coinType.IsSKA() {
		highFee, err := txrules.PaysHighFeesSKA(totalSKAInput.BigInt(), tx, w.chainParams)
		if err != nil {
			return errors.E(errors.Bug, err)
		}
		if highFee {
			return errors.E(errors.Policy, "high SKA fee")
		}
		return nil
	}
	highFee, err := txrules.PaysHighFees(totalVARInput, tx)
	if err != nil {
		return errors.E(errors.Bug, err)
	}
	if highFee {
		return errors.E(errors.Policy, "high fee")
	}
	return nil
}

// publishAndWatch publishes an authored transaction to the network and begins watching for
// relevant transactions.
func (w *Wallet) publishAndWatch(ctx context.Context, op errors.Op, n NetworkBackend, tx *wire.MsgTx,
	watch []wire.OutPoint) error {

	if n == nil {
		var err error
		n, err = w.NetworkBackend()
		if err != nil {
			return errors.E(op, err)
		}
	}

	err := n.PublishTransactions(ctx, tx)
	if err != nil {
		hash := tx.TxHash()
		log.Errorf("Abandoning transaction %v which failed to publish", &hash)
		if err := w.AbandonTransaction(ctx, &hash); err != nil {
			log.Errorf("Cannot abandon %v: %v", &hash, err)
		}
		return errors.E(op, err)
	}

	// Watch for future relevant transactions.
	_, err = w.watchHDAddrs(ctx, false, n)
	if err != nil {
		log.Errorf("Failed to watch for future address usage after publishing "+
			"transaction: %v", err)
	}
	if len(watch) > 0 {
		err := n.LoadTxFilter(ctx, false, nil, watch)
		if err != nil {
			log.Errorf("Failed to watch outpoints: %v", err)
		}
	}
	return nil
}

type authorTx struct {
	outputs            []*wire.TxOut
	account            uint32
	changeAccount      uint32
	minconf            int32
	randomizeChangeIdx bool
	txFee              cointype.SKAAmount // SKAAmount for big.Int precision (supports both VAR and SKA)
	dontSignTx         bool
	isTreasury         bool

	// subtractFeeFromAmountIdx selects an output whose value is reduced by
	// the converged tx fee (Bitcoin Core's subtractfeefromamount semantics).
	// -1 disables the behavior; otherwise it indexes outputs.
	subtractFeeFromAmountIdx int

	atx                 *txauthor.AuthoredTx
	changeSourceUpdates []func(walletdb.ReadWriteTx) error
	watch               []wire.OutPoint
}

// authorTx creates a (typically signed) transaction which includes each output
// from outputs.  Previous outputs to redeem are chosen from the passed
// account's UTXO set and minconf policy. An additional output may be added to
// return change to the wallet.  An appropriate fee is included based on the
// wallet's current relay fee.  The wallet must be unlocked to create the
// transaction.
func (w *Wallet) authorTx(ctx context.Context, op errors.Op, a *authorTx) error {
	var unlockOutpoints []*wire.OutPoint
	defer func() {
		for _, op := range unlockOutpoints {
			delete(w.lockedOutpoints, outpoint{op.Hash, op.Index})
		}
		w.lockedOutpointMu.Unlock()
	}()
	ignoreInput := func(op *wire.OutPoint) bool {
		_, ok := w.lockedOutpoints[outpoint{op.Hash, op.Index}]
		return ok
	}
	w.lockedOutpointMu.Lock()

	var atx *txauthor.AuthoredTx
	var changeSourceUpdates []func(walletdb.ReadWriteTx) error
	err := walletdb.View(ctx, w.db, func(dbtx walletdb.ReadTx) error {
		addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)

		// Create the unsigned transaction.
		_, tipHeight := w.txStore.MainChainTip(dbtx)

		// Determine coin type from outputs for coin-type-aware UTXO selection
		var inputSource udb.InputSource
		if len(a.outputs) > 0 {
			txCoinType := a.outputs[0].CoinType
			inputSource = w.txStore.MakeInputSourceWithCoinType(dbtx, a.account,
				a.minconf, tipHeight, ignoreInput, txCoinType)
		}

		var changeSource txauthor.ChangeSource
		if a.isTreasury {
			changeSource = &p2PKHTreasuryChangeSource{
				persist: w.deferPersistReturnedChild(ctx,
					&changeSourceUpdates),
				account: a.changeAccount,
				wallet:  w,
				ctx:     ctx,
			}
		} else {
			changeSource = &p2PKHChangeSource{
				persist: w.deferPersistReturnedChild(ctx,
					&changeSourceUpdates),
				account:   a.changeAccount,
				wallet:    w,
				ctx:       ctx,
				gapPolicy: gapPolicyWrap,
			}
		}

		// Honor the caller's per-tx fee; only fall back to the wallet's
		// configured per-coin-type relay fee when the caller left it zero.
		actualTxFee := a.txFee
		if actualTxFee.IsZero() && len(a.outputs) > 0 {
			actualTxFee = w.RelayFeeForCoinType(ctx, a.outputs[0].CoinType)
		}
		if len(a.outputs) > 0 && a.outputs[0].CoinType.IsSKA() && actualTxFee.IsZero() {
			return errors.E(errors.Invalid, fmt.Sprintf(
				"no relay fee configured for coin type %d; cannot author transaction", a.outputs[0].CoinType))
		}

		var err error
		atx, err = txauthor.NewUnsignedTransaction(a.outputs, actualTxFee,
			inputSource.SelectInputs, changeSource,
			w.chainParams.MaxTxSize, a.subtractFeeFromAmountIdx)
		if err != nil {
			return err
		}
		for _, in := range atx.Tx.TxIn {
			prev := &in.PreviousOutPoint
			w.lockedOutpoints[outpoint{prev.Hash, prev.Index}] = struct{}{}
			unlockOutpoints = append(unlockOutpoints, prev)
		}

		// Randomize change position, if change exists, before signing.
		// This doesn't affect the serialize size, so the change amount
		// will still be valid.
		if atx.ChangeIndex >= 0 && a.randomizeChangeIdx {
			atx.RandomizeChangePosition()
		}

		// Ensure change output has correct coin type
		if atx.ChangeIndex >= 0 && len(a.outputs) > 0 {
			atx.Tx.TxOut[atx.ChangeIndex].CoinType = a.outputs[0].CoinType
		}

		// TADDs need to use version 3 txs.
		if a.isTreasury {
			// This check ensures that if NewUnsignedTransaction is
			// updated to generate a different transaction version
			// we error out loudly instead of failing to validate
			// in some obscure way.
			//
			// TODO: maybe isTreasury should be passed into
			// NewUnsignedTransaction?
			if atx.Tx.Version != wire.TxVersion {
				return errors.E(op, "violated assumption: "+
					"expected unsigned tx to be version 1")
			}
			atx.Tx.Version = wire.TxVersionTreasury
		}

		if !a.dontSignTx {
			// Sign the transaction.
			secrets := &secretSource{Manager: w.manager, addrmgrNs: addrmgrNs}
			err = atx.AddAllInputScripts(secrets)
			for _, done := range secrets.doneFuncs {
				done()
			}
			if err != nil {
				return err
			}
		}

		// Dual-coin validation under the same dbtx so the input lookups
		// see a consistent UTXO snapshot. authorTx relies on the input
		// source to filter by coin type, but verify here as defense in
		// depth — a future regression in MakeInputSourceWithCoinType must
		// not silently produce mixed-coin transactions that the node
		// would reject.
		return w.validateAuthoredCoinTypes(dbtx, atx.Tx)
	})
	if err != nil {
		return errors.E(op, err)
	}

	// Warn when spending UTXOs controlled by imported keys created change for
	// the default account.
	if atx.ChangeIndex >= 0 && a.account == udb.ImportedAddrAccount {
		changeOut := atx.Tx.TxOut[atx.ChangeIndex]
		if changeOut.CoinType.IsSKA() {
			var skaAmt cointype.SKAAmount
			if changeOut.SKAValue != nil {
				skaAmt = cointype.NewSKAAmount(changeOut.SKAValue)
			}
			log.Warnf("Spend from imported account produced SKA change: moving"+
				" %v atoms from imported account into default account.", skaAmt.BigInt())
		} else {
			changeAmount := dcrutil.Amount(changeOut.Value)
			log.Warnf("Spend from imported account produced change: moving"+
				" %v from imported account into default account.", changeAmount)
		}
	}

	err = w.checkHighFees(atx.TotalInput, atx.SKATotalInput, atx.Tx)
	if err != nil {
		return errors.E(op, err)
	}

	if !a.dontSignTx {
		// Ensure valid signatures were created.
		err = validateMsgTx(op, atx.Tx, atx.PrevScripts)
		if err != nil {
			return errors.E(op, err)
		}
	}

	a.atx = atx
	a.changeSourceUpdates = changeSourceUpdates
	return nil
}

// recordAuthoredTx records an authored transaction to the wallet's database.  It
// also updates the database for change addresses used by the new transaction.
//
// As a side effect of recording the transaction to the wallet, clients
// subscribed to new tx notifications will also be notified of the new
// transaction.
func (w *Wallet) recordAuthoredTx(ctx context.Context, op errors.Op, a *authorTx) error {
	rec, err := udb.NewTxRecordFromMsgTx(a.atx.Tx, time.Now())
	if err != nil {
		return errors.E(op, err)
	}

	w.lockedOutpointMu.Lock()
	defer w.lockedOutpointMu.Unlock()

	// To avoid a race between publishing a transaction and potentially opening
	// a database view during PublishTransaction, the update must be committed
	// before publishing the transaction to the network.
	var watch []wire.OutPoint
	err = walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
		for _, up := range a.changeSourceUpdates {
			err := up(dbtx)
			if err != nil {
				return err
			}
		}

		// TODO: this can be improved by not using the same codepath as notified
		// relevant transactions, since this does a lot of extra work.
		var err error
		watch, err = w.processTransactionRecord(ctx, dbtx, rec, nil, nil)
		return err
	})
	if err != nil {
		return errors.E(op, err)
	}

	a.watch = watch
	return nil
}

// txToMultisig spends funds to a multisig output, partially signs the
// transaction, then returns fund. For VAR the amount parameter is used and
// amountSKA is ignored; for SKA the amountSKA parameter is used end-to-end as
// a big.Int so amounts above math.MaxInt64 atoms (SKA's AtomsPerCoin=1e18) are
// preserved losslessly.
func (w *Wallet) txToMultisig(ctx context.Context, op errors.Op, account uint32, amount dcrutil.Amount, amountSKA cointype.SKAAmount,
	pubkeys [][]byte, nRequired int8, minconf int32, coinType cointype.CoinType) (*CreatedTx, stdaddr.Address, []byte, error) {

	defer w.lockedOutpointMu.Unlock()
	w.lockedOutpointMu.Lock()

	// Resolve the network backend up front so we fail fast on disconnect
	// rather than after authoring the transaction.
	n, err := w.NetworkBackend()
	if err != nil {
		return nil, nil, nil, errors.E(op, err)
	}

	var created *CreatedTx
	var addr stdaddr.Address
	var msScript []byte
	err = walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
		var err error
		created, addr, msScript, err = w.txToMultisigInternal(ctx, op, dbtx,
			account, amount, amountSKA, pubkeys, nRequired, minconf, coinType)
		return err
	})
	if err != nil {
		return nil, nil, nil, errors.E(op, err)
	}

	// Publish AFTER the DB tx commits.  If publish fails, abandon the
	// locally-recorded tx so the wallet's view stays consistent with the
	// network.  Mirrors compressWallet / publishAndWatch.
	if err := n.PublishTransactions(ctx, created.MsgTx); err != nil {
		hash := created.MsgTx.TxHash()
		log.Errorf("Abandoning multisig transaction %v which failed to publish", &hash)
		if abandonErr := w.AbandonTransaction(ctx, &hash); abandonErr != nil {
			log.Errorf("Cannot abandon %v: %v", &hash, abandonErr)
		}
		return nil, nil, nil, errors.E(op, err)
	}

	// Request updates from mond for new transactions sent to this script
	// hash address.  Match publishAndWatch's log-and-continue policy: a
	// LoadTxFilter failure should not retroactively invalidate an
	// already-published transaction.
	if err := n.LoadTxFilter(ctx, false, []stdaddr.Address{addr}, nil); err != nil {
		log.Errorf("Failed to watch multisig script address %v: %v", addr, err)
	}

	return created, addr, msScript, nil
}

func (w *Wallet) txToMultisigInternal(ctx context.Context, op errors.Op, dbtx walletdb.ReadWriteTx, account uint32, amount dcrutil.Amount,
	amountSKA cointype.SKAAmount, pubkeys [][]byte, nRequired int8, minconf int32, coinType cointype.CoinType) (*CreatedTx, stdaddr.Address, []byte, error) {

	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)

	txToMultisigError := func(err error) (*CreatedTx, stdaddr.Address, []byte, error) {
		return nil, nil, nil, err
	}

	// Get current block's height and hash.
	_, topHeight := w.txStore.MainChainTip(dbtx)

	// Instead of taking reward addresses by arg, just create them now and
	// automatically find all eligible outputs from all current utxos.
	const minAmount = 0
	const maxResults = 0
	var amountRequired dcrutil.Amount
	amountRequiredSKA := cointype.Zero()

	// Pre-selection fee budget. Both branches estimate tx size assuming up
	// to multisigFeePreSelectInputGuess inputs, one P2SH output, and a
	// P2PKH change output, then multiply by the configured per-coin-type
	// relay fee. The post-selection recompute at the balance-check is the
	// authoritative fee; this only needs to be a safe upper bound so
	// findEligibleOutputsAmount returns enough inputs to cover it.
	//
	// TODO(coin-aware-iterative-fee): the fixed multisigFeePreSelectInputGuess
	// budget will spuriously fail with InsufficientBalance for wallets that
	// hold more than that many dust UTXOs, even when the actual balance is
	// sufficient. Replace with the iterative grow-on-shortfall pattern in
	// txauthor.NewUnsignedTransaction (wallet/txauthor/author.go: target-fee
	// loop). Deferred — current callers cap at small input counts.
	estScriptSizes := make([]int, multisigFeePreSelectInputGuess)
	for i := range estScriptSizes {
		estScriptSizes[i] = txsizes.RedeemP2SHSigScriptSize
	}
	if coinType.IsSKA() {
		estTxOuts := []*wire.TxOut{{
			Value:    0,
			SKAValue: amountSKA.BigInt(),
			PkScript: make([]byte, txsizes.P2SHPkScriptSize),
			CoinType: coinType,
		}}
		preBudgetSize := txsizes.EstimateSerializeSizeSKA(estScriptSizes, estTxOuts, txsizes.P2PKHPkScriptSize)
		relayFeeBig := w.RelayFeeForCoinType(ctx, coinType)
		if relayFeeBig.IsZero() {
			return txToMultisigError(errors.E(op, errors.Invalid, errors.Errorf(
				"no relay fee configured for coin type %d; cannot author transaction", coinType)))
		}
		skaFeePreBudget := txrules.FeeForSerializeSizeSKA(relayFeeBig, preBudgetSize)
		amountRequiredSKA = amountSKA.Add(skaFeePreBudget)
	} else {
		estTxOuts := []*wire.TxOut{{
			Value:    int64(amount),
			PkScript: make([]byte, txsizes.P2SHPkScriptSize),
			CoinType: cointype.CoinTypeVAR,
		}}
		preBudgetSize := txsizes.EstimateSerializeSize(estScriptSizes, estTxOuts, txsizes.P2PKHPkScriptSize)
		feeEstForTx := txrules.FeeForSerializeSize(w.RelayFee(), preBudgetSize)
		amountRequired = amount + feeEstForTx
	}
	eligible, err := w.findEligibleOutputsAmount(dbtx, account, minconf,
		amountRequired, amountRequiredSKA, topHeight, minAmount, maxResults, coinType)
	if err != nil {
		return txToMultisigError(errors.E(op, err))
	}
	if eligible == nil {
		return txToMultisigError(errors.E(op, "not enough funds to send to multisig address"))
	}
	for i := range eligible {
		op := &eligible[i].OutPoint
		w.lockedOutpoints[outpoint{op.Hash, op.Index}] = struct{}{}
	}
	defer func() {
		for i := range eligible {
			op := &eligible[i].OutPoint
			delete(w.lockedOutpoints, outpoint{op.Hash, op.Index})
		}
	}()

	msgtx := wire.NewMsgTx()
	scriptSizes := make([]int, 0, len(eligible))
	// Fill out inputs.
	forSigning := make([]Input, 0, len(eligible))
	totalInput := dcrutil.Amount(0)
	totalSKAInput := cointype.Zero()
	for _, e := range eligible {
		txIn := wire.NewTxIn(&e.OutPoint, e.PrevOut.Value, nil)
		// Set SKAValueIn for SKA inputs (needed for V13 wire format).
		// Defensive-copy the prev-out's SKAValue so the wire-level tx
		// owns its own *big.Int — matches the convention at
		// multisig.go:120, methods.go:5286, methods.go:7888 and
		// guarantees later mutation of the prev-out value cannot
		// silently corrupt the on-chain serialization.
		if e.PrevOut.CoinType.IsSKA() && e.PrevOut.SKAValue != nil {
			txIn.SKAValueIn = new(big.Int).Set(e.PrevOut.SKAValue)
			totalSKAInput = totalSKAInput.Add(cointype.NewSKAAmount(e.PrevOut.SKAValue))
		} else {
			totalInput += dcrutil.Amount(e.PrevOut.Value)
		}
		msgtx.AddTxIn(txIn)
		forSigning = append(forSigning, e)
		scriptSizes = append(scriptSizes, txsizes.RedeemP2SHSigScriptSize)
	}

	// Insert a multi-signature output, then insert this P2SH
	// hash160 into the address manager and the transaction
	// manager.
	msScript, err := stdscript.MultiSigScriptV0(int(nRequired), pubkeys...)
	if err != nil {
		return txToMultisigError(errors.E(op, err))
	}
	_, err = w.manager.ImportScript(addrmgrNs, msScript)
	if err != nil {
		// We don't care if we've already used this address.
		if !errors.Is(err, errors.Exist) {
			return txToMultisigError(errors.E(op, err))
		}
	}
	scAddr, err := stdaddr.NewAddressScriptHashV0(msScript, w.chainParams)
	if err != nil {
		return txToMultisigError(errors.E(op, err))
	}
	vers, p2shScript := scAddr.PaymentScript()

	// Handle VAR and SKA separately to avoid int64 overflow
	var feeSize int
	if coinType.IsSKA() {
		// SKA path: use big.Int arithmetic end-to-end. amountSKA is the
		// caller's target in atoms, preserved losslessly.
		// Create output with SKAValue (Value=0 for SKA)
		txOut := &wire.TxOut{
			Value:    0,
			SKAValue: amountSKA.BigInt(),
			PkScript: p2shScript,
			Version:  vers,
			CoinType: coinType,
		}
		msgtx.AddTxOut(txOut)

		// Always estimate fee assuming a change output. SKA relay fees are
		// ~1e18 atoms/KB so the int64 feeEstForTx guess from the caller is
		// not usable for SKA (off by ~12 orders of magnitude); compute the
		// true fee from the relay-fee config for this coin type. Including
		// changeSize unconditionally over-estimates by ~25 bytes' worth of
		// fee in the no-change case, which is harmless; under-estimating
		// would risk relay rejection if the leftover after change-add
		// crossed the dust threshold.
		feeSize = txsizes.EstimateSerializeSizeSKA(scriptSizes, msgtx.TxOut, txsizes.P2PKHPkScriptSize)
		relayFeeBig := w.RelayFeeForCoinType(ctx, coinType)
		if relayFeeBig.IsZero() {
			return txToMultisigError(errors.E(op, errors.Invalid, errors.Errorf(
				"no relay fee configured for coin type %d; cannot author transaction", coinType)))
		}
		skaFeeEstActual := txrules.FeeForSerializeSizeSKA(relayFeeBig, feeSize)

		// Balance check
		required := amountSKA.Add(skaFeeEstActual)
		if totalSKAInput.Cmp(required) < 0 {
			return txToMultisigError(errors.E(op, errors.InsufficientBalance, errors.Errorf(
				"SKA inputs %s < required %s atoms (target %s + estimated fee %s)",
				totalSKAInput.String(), required.String(),
				amountSKA.String(), skaFeeEstActual.String())))
		}

		// Add change if needed. Drop sub-dust change (forfeit to fees) to
		// match wallet/txauthor/author.go behavior — a dust change output
		// would be silently rejected by the network.
		if totalSKAInput.Cmp(required) > 0 {
			change := totalSKAInput.Sub(required)
			if change.BigInt().Cmp(cointype.MinSKADustAmount) >= 0 {
				changeSource := p2PKHChangeSource{
					persist: w.persistReturnedChild(ctx, dbtx),
					account: account,
					wallet:  w,
					ctx:     ctx,
				}

				pkScript, vers, err := changeSource.Script()
				if err != nil {
					return txToMultisigError(err)
				}
				msgtx.AddTxOut(&wire.TxOut{
					Value:    0,
					SKAValue: change.BigInt(),
					Version:  vers,
					PkScript: pkScript,
					CoinType: coinType,
				})
			}
		}
	} else {
		// VAR path: use int64 arithmetic
		txOut := &wire.TxOut{
			Value:    int64(amount),
			PkScript: p2shScript,
			Version:  vers,
			CoinType: coinType,
		}
		msgtx.AddTxOut(txOut)

		// Compute fee assuming a change output is present; if no change is
		// produced below, the over-estimate is at most P2PKHPkScriptSize
		// bytes of fee (matches the SKA branch above).
		feeSize = txsizes.EstimateSerializeSize(scriptSizes, msgtx.TxOut, txsizes.P2PKHPkScriptSize)
		relayFeeBigVar := w.RelayFeeForCoinType(ctx, coinType)
		relayFeeInt64Var, err := relayFeeBigVar.Int64()
		if err != nil {
			return txToMultisigError(errors.E(op, errors.Invalid,
				"fee overflow: configured VAR relay fee rate produces a fee that exceeds int64"))
		}
		// Mirror the SKA branch's IsZero gate: a zero relay fee yields a
		// zero on-tx fee that the node will reject. Surface a clear error
		// here rather than letting an unbroadcastable tx ship to the
		// caller.
		if relayFeeInt64Var == 0 {
			return txToMultisigError(errors.E(op, errors.Invalid, errors.Errorf(
				"no relay fee configured for coin type %d; cannot author transaction", coinType)))
		}
		feeEst := txrules.FeeForSerializeSize(dcrutil.Amount(relayFeeInt64Var), feeSize)

		if totalInput < amount+feeEst {
			return txToMultisigError(errors.E(op, errors.InsufficientBalance))
		}
		if totalInput > amount+feeEst {
			changeSource := p2PKHChangeSource{
				persist: w.persistReturnedChild(ctx, dbtx),
				account: account,
				wallet:  w,
				ctx:     ctx,
			}

			pkScript, vers, err := changeSource.Script()
			if err != nil {
				return txToMultisigError(err)
			}
			change := totalInput - (amount + feeEst)
			msgtx.AddTxOut(&wire.TxOut{
				Value:    int64(change),
				Version:  vers,
				PkScript: pkScript,
				CoinType: coinType,
			})
		}
	}

	err = w.signP2PKHMsgTx(msgtx, forSigning, addrmgrNs)
	if err != nil {
		return txToMultisigError(errors.E(op, err))
	}

	err = w.checkHighFees(totalInput, totalSKAInput, msgtx)
	if err != nil {
		return txToMultisigError(errors.E(op, err))
	}

	// Record the tx in the wallet DB.  The actual network publish and
	// LoadTxFilter call run in the outer txToMultisig wrapper, after this
	// walletdb.Update commits — keeps the wallet from broadcasting a
	// transaction it has no record of if the local insert later fails.
	err = w.insertMultisigOutIntoTxMgr(dbtx, msgtx, 0)
	if err != nil {
		return txToMultisigError(errors.E(op, err))
	}

	created := &CreatedTx{
		MsgTx:       msgtx,
		ChangeAddr:  nil,
		ChangeIndex: -1,
	}

	return created, scAddr, msScript, nil
}

// validateMsgTx verifies transaction input scripts for tx.  All previous output
// scripts from outputs redeemed by the transaction, in the same order they are
// spent, must be passed in the prevScripts slice.
func validateMsgTx(op errors.Op, tx *wire.MsgTx, prevScripts [][]byte) error {
	for i, prevScript := range prevScripts {
		vm, err := txscript.NewEngine(prevScript, tx, i,
			sanityVerifyFlags, scriptVersionAssumed, nil)
		if err != nil {
			return errors.E(op, err)
		}
		err = vm.Execute()
		if err != nil {
			prevOut := &tx.TxIn[i].PreviousOutPoint
			sigScript := tx.TxIn[i].SignatureScript

			log.Errorf("Script validation failed (outpoint %v pkscript %x sigscript %x): %v",
				prevOut, prevScript, sigScript, err)
			return errors.E(op, errors.ScriptFailure, err)
		}
	}
	return nil
}

func creditScripts(credits []Input) [][]byte {
	scripts := make([][]byte, 0, len(credits))
	for _, c := range credits {
		scripts = append(scripts, c.PrevOut.PkScript)
	}
	return scripts
}

// compressWallet compresses all the utxos in a wallet into a single change
// address. For use when it becomes dusty.
//
// The DB-write phase (utxo selection, signing, and tx-record insertion) runs
// inside walletdb.Update; the network publish runs *after* the bbolt write
// transaction commits so a slow / hung peer cannot block other wallet writes
// for the duration of the publish call.  This mirrors the
// recordAuthoredTx + publishAndWatch split used by authorTx-built txs.
//
// Outpoint locking: compressWalletInternal records the consumed outpoints
// in w.lockedOutpoints and returns the slice; this function is responsible
// for releasing them — but only after publishAndWatch has run (which calls
// AbandonTransaction on failure). Releasing the locks before publish would
// admit a parallel selector to the same prevouts the moment lockedOutpointMu
// is narrowed in a future refactor; correctness must not rely on the outer
// mutex's current full-function scope.
func (w *Wallet) compressWallet(ctx context.Context, op errors.Op, maxNumIns int, account uint32, changeAddr stdaddr.Address, coinType cointype.CoinType) (*chainhash.Hash, error) {
	defer w.lockedOutpointMu.Unlock()
	w.lockedOutpointMu.Lock()

	n, err := w.NetworkBackend()
	if err != nil {
		return nil, errors.E(op, err)
	}

	var hash *chainhash.Hash
	var msgtx *wire.MsgTx
	var lockedOps []wire.OutPoint
	err = walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
		var err error
		hash, msgtx, lockedOps, err = w.compressWalletInternal(ctx, op, dbtx, maxNumIns, account, changeAddr, coinType)
		return err
	})
	// Whatever lockedOps the inner function reported as locked must be
	// released exactly once — on the success path after publishAndWatch
	// returns (success or AbandonTransaction), on the failure path right
	// here. Defer covers both.
	defer func() {
		for i := range lockedOps {
			delete(w.lockedOutpoints, outpoint{lockedOps[i].Hash, lockedOps[i].Index})
		}
	}()
	if err != nil {
		return nil, errors.E(op, err)
	}

	// Publish AFTER the DB tx commits.  publishAndWatch handles
	// AbandonTransaction on publish failure, leaving the wallet's view
	// of the failed tx consistent with what the network sees.
	if err := w.publishAndWatch(ctx, op, n, msgtx, nil); err != nil {
		return nil, err
	}
	txHash := msgtx.TxHash()
	log.Infof("Successfully consolidated funds in transaction %v", &txHash)
	return hash, nil
}

// compressWalletInternal returns the slice of outpoints it locked in
// w.lockedOutpoints; the caller (compressWallet) is responsible for
// releasing them — but only AFTER the network publish (success or abandon)
// has run. Releasing here, before publish, opens a double-spend window the
// moment a future refactor narrows the outer lockedOutpointMu scope.
func (w *Wallet) compressWalletInternal(ctx context.Context, op errors.Op, dbtx walletdb.ReadWriteTx, maxNumIns int, account uint32,
	changeAddr stdaddr.Address, coinType cointype.CoinType) (*chainhash.Hash, *wire.MsgTx, []wire.OutPoint, error) {

	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)

	// Get current block's height
	_, tipHeight := w.txStore.MainChainTip(dbtx)

	minconf := int32(1)
	eligible, err := w.findEligibleOutputs(dbtx, account, minconf, tipHeight, coinType)
	if err != nil {
		return nil, nil, nil, errors.E(op, err)
	}
	// Filter outputs already locked by another in-flight operation. The
	// outer caller holds lockedOutpointMu so the map is quiescent here, but
	// counting before filtering would let an unlocked-caller regression
	// admit a tx with too few real candidates.
	filtered := eligible[:0]
	for _, e := range eligible {
		if _, locked := w.lockedOutpoints[outpoint{e.OutPoint.Hash, e.OutPoint.Index}]; locked {
			continue
		}
		filtered = append(filtered, e)
	}
	eligible = filtered
	if len(eligible) <= 1 {
		return nil, nil, nil, errors.E(op, "too few outputs to consolidate")
	}
	lockedOps := make([]wire.OutPoint, 0, len(eligible))
	for i := range eligible {
		op := eligible[i].OutPoint
		w.lockedOutpoints[outpoint{op.Hash, op.Index}] = struct{}{}
		lockedOps = append(lockedOps, op)
	}

	// Check if output address is default, and generate a new address if needed
	if changeAddr == nil {
		const accountName = "" // not used, so can be faked.
		changeAddr, err = w.newChangeAddress(ctx, op, w.persistReturnedChild(ctx, dbtx),
			accountName, account, gapPolicyIgnore)
		if err != nil {
			return nil, nil, lockedOps, errors.E(op, err)
		}
	}
	vers, pkScript := changeAddr.PaymentScript()
	msgtx := wire.NewMsgTx()
	msgtx.AddTxOut(&wire.TxOut{
		Value:    0,
		PkScript: pkScript,
		Version:  vers,
		CoinType: coinType,
	})
	maximumTxSize := w.chainParams.MaxTxSize
	if w.chainParams.Net == wire.MainNet {
		maximumTxSize = maxStandardTxSize
	}

	// Add the txins using all the eligible outputs.
	// Track VAR and SKA totals separately to avoid int64 overflow for SKA
	totalAddedVAR := dcrutil.Amount(0)
	totalAddedSKA := cointype.Zero()
	scriptSizes := make([]int, 0, maxNumIns)
	forSigning := make([]Input, 0, maxNumIns)
	count := 0
	for _, e := range eligible {
		if count >= maxNumIns {
			break
		}
		// Add the size of a wire.OutPoint
		if msgtx.SerializeSize() > maximumTxSize {
			break
		}

		txIn := wire.NewTxIn(&e.OutPoint, e.PrevOut.Value, nil)
		// Set SKAValueIn for SKA inputs (needed for V13 wire format).
		// Defensive-copy the prev-out's SKAValue (see txToMultisigInternal
		// for the rationale).
		if e.PrevOut.CoinType.IsSKA() && e.PrevOut.SKAValue != nil {
			txIn.SKAValueIn = new(big.Int).Set(e.PrevOut.SKAValue)
			totalAddedSKA = totalAddedSKA.Add(cointype.NewSKAAmount(e.PrevOut.SKAValue))
		} else {
			totalAddedVAR += dcrutil.Amount(e.PrevOut.Value)
		}
		msgtx.AddTxIn(txIn)
		forSigning = append(forSigning, e)
		scriptSizes = append(scriptSizes, txsizes.RedeemP2PKHSigScriptSize)
		count++
	}

	// Set output value based on coin type. The dust/policy check is unified
	// via txrules.CheckOutput (SKA-aware) so VAR and SKA see the same
	// rejection semantics; the per-branch body below only computes the
	// post-fee output value.
	feeRateBig := w.RelayFeeForCoinType(ctx, coinType)
	if coinType.IsSKA() && feeRateBig.IsZero() {
		return nil, nil, lockedOps, errors.E(op, errors.Invalid, errors.Errorf(
			"no relay fee configured for coin type %d; cannot author transaction", coinType))
	}
	if coinType.IsSKA() {
		// SKA path: use big.Int arithmetic for full precision.
		szEst := txsizes.EstimateSerializeSizeSKA(scriptSizes, msgtx.TxOut, 0)
		skaFee := txrules.FeeForSerializeSizeSKA(feeRateBig, szEst)
		skaOutput := totalAddedSKA.Sub(skaFee)
		if skaOutput.IsNegative() {
			return nil, nil, lockedOps, errors.E(op, errors.InsufficientBalance, errors.Errorf(
				"SKA inputs total %s atoms but estimated fee is %s atoms",
				totalAddedSKA.String(), skaFee.String()))
		}
		if skaOutput.IsZero() {
			// Inputs cover the fee exactly — there's nothing left to
			// consolidate.  This is a Policy condition (the operator has
			// funds, just not above the fee), not InsufficientBalance.
			return nil, nil, lockedOps, errors.E(op, errors.Policy, errors.Errorf(
				"consolidation would produce zero output: SKA inputs total "+
					"%s atoms equal estimated fee %s atoms",
				totalAddedSKA.String(), skaFee.String()))
		}
		msgtx.TxOut[0].Value = 0
		msgtx.TxOut[0].SKAValue = skaOutput.BigInt()
	} else {
		// VAR path: use int64 arithmetic.
		feeRateInt64, err := feeRateBig.Int64()
		if err != nil {
			return nil, nil, lockedOps, errors.E(op, errors.Invalid,
				"fee overflow: configured VAR relay fee rate produces a fee that exceeds int64")
		}
		feeRate := dcrutil.Amount(feeRateInt64)
		szEst := txsizes.EstimateSerializeSize(scriptSizes, msgtx.TxOut, 0)
		feeEst := txrules.FeeForSerializeSize(feeRate, szEst)
		// Inputs do not cover the fee. The subtraction would underflow into
		// a negative int64, which CheckOutput below would later flag — but
		// the Policy-classed dust error it produces is misleading here:
		// the operator's actual problem is "no funds above fee", not
		// "below dust". Fail upfront with InsufficientBalance.
		if totalAddedVAR < feeEst {
			return nil, nil, lockedOps, errors.E(op, errors.InsufficientBalance, errors.Errorf(
				"consolidation cannot cover fee: VAR inputs total %v, estimated fee %v",
				totalAddedVAR, feeEst))
		}
		msgtx.TxOut[0].Value = int64(totalAddedVAR - feeEst)
	}
	if err := txrules.CheckOutput(msgtx.TxOut[0], feeRateBig); err != nil {
		// CheckOutput returns errors.Policy with a clear message about
		// dust thresholds. Preserve the Policy classification — operators
		// who hit dust have funds, just not enough to clear the threshold;
		// re-tagging as InsufficientBalance ("no funds") is misleading.
		return nil, nil, lockedOps, errors.E(op, err)
	}

	err = w.signP2PKHMsgTx(msgtx, forSigning, addrmgrNs)
	if err != nil {
		return nil, nil, lockedOps, errors.E(op, err)
	}
	err = validateMsgTx(op, msgtx, creditScripts(forSigning))
	if err != nil {
		return nil, nil, lockedOps, errors.E(op, err)
	}

	err = w.checkHighFees(totalAddedVAR, totalAddedSKA, msgtx)
	if err != nil {
		return nil, nil, lockedOps, errors.E(op, err)
	}

	// Record the tx in the wallet DB.  The actual network publish runs
	// after this walletdb.Update commits — see compressWallet.
	rec, err := w.insertIntoTxMgr(dbtx, msgtx)
	if err != nil {
		return nil, nil, lockedOps, errors.E(op, err)
	}
	err = w.insertCreditsIntoTxMgr(op, dbtx, msgtx, rec)
	if err != nil {
		return nil, nil, lockedOps, err
	}

	txHash := msgtx.TxHash()
	return &txHash, msgtx, lockedOps, nil
}

// makeTicket creates a ticket from a split transaction output.
func makeTicket(params *chaincfg.Params, input *Input, addrVote stdaddr.StakeAddress,
	addrSubsidy stdaddr.StakeAddress, ticketCost int64) (*wire.MsgTx, error) {

	mtx := wire.NewMsgTx()

	txIn := wire.NewTxIn(&input.OutPoint, input.PrevOut.Value, []byte{})
	mtx.AddTxIn(txIn)

	// Create a new script which pays to the provided address with an
	// SStx tagged output.
	if addrVote == nil {
		return nil, errors.E(errors.Invalid, "nil vote address")
	}
	vers, pkScript := addrVote.VotingRightsScript()

	txOut := &wire.TxOut{
		Value:    ticketCost,
		PkScript: pkScript,
		Version:  vers,
		CoinType: cointype.CoinTypeVAR, // Tickets are VAR-only
	}
	mtx.AddTxOut(txOut)

	// Obtain the commitment amounts.
	var amountsCommitted []int64
	const userSubsidyNullIdx = 0
	var err error
	_, amountsCommitted, err = stake.SStxNullOutputAmounts(
		[]int64{input.PrevOut.Value}, []int64{0}, ticketCost)
	if err != nil {
		return nil, err
	}

	// Zero value P2PKH addr.
	zeroed := [20]byte{}
	addrZeroed, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(zeroed[:], params)
	if err != nil {
		return nil, err
	}

	// 2. Create the commitment and change output paying to the user.
	//
	// Create an OP_RETURN push containing the pubkeyhash to send rewards to.
	// Apply limits to revocations for fees while not allowing
	// fees for votes.
	vers, pkScript = addrSubsidy.RewardCommitmentScript(
		amountsCommitted[userSubsidyNullIdx], 0, revocationFeeLimit)
	txout := &wire.TxOut{
		Value:    0,
		PkScript: pkScript,
		Version:  vers,
		CoinType: cointype.CoinTypeVAR, // Tickets are VAR-only
	}
	mtx.AddTxOut(txout)

	// Create a new script which pays to the provided address with an
	// SStx change tagged output.
	vers, pkScript = addrZeroed.StakeChangeScript()
	txOut = &wire.TxOut{
		Value:    0,
		PkScript: pkScript,
		Version:  vers,
		CoinType: cointype.CoinTypeVAR, // Tickets are VAR-only
	}
	mtx.AddTxOut(txOut)

	// Make sure we generated a valid SStx.
	if err := stake.CheckSStx(mtx); err != nil {
		return nil, errors.E(errors.Op("stake.CheckSStx"), errors.Bug, err)
	}

	return mtx, nil
}

// newP2PKHSizedScript returns a fresh 25-byte zero slice sized to a P2PKH
// script. Each caller gets its own backing array so a downstream writer (e.g.
// a future mix-client transformation) cannot corrupt sibling outputs through
// shared state.
func newP2PKHSizedScript() []byte { return make([]byte, 25) }

func (w *Wallet) mixedSplit(ctx context.Context, req *PurchaseTicketsRequest, neededPerTicket dcrutil.Amount) (tx *wire.MsgTx, outIndexes []int, err error) {
	// Use txauthor to perform input selection and change amount
	// calculations for the unmixed portions of the coinjoin.
	// Tickets are VAR-only
	const ticketCoinType = cointype.CoinTypeVAR
	mixOut := make([]*wire.TxOut, req.Count)
	for i := 0; i < req.Count; i++ {
		mixOut[i] = &wire.TxOut{Value: int64(neededPerTicket), Version: 0, PkScript: newP2PKHSizedScript(), CoinType: ticketCoinType}
	}
	relayFee := w.RelayFeeForCoinType(ctx, ticketCoinType)
	var changeSourceUpdates []func(walletdb.ReadWriteTx) error
	defer func() {
		if err != nil {
			return
		}

		err = walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
			for _, f := range changeSourceUpdates {
				if err := f(dbtx); err != nil {
					return err
				}
			}
			return nil
		})
	}()
	var unlockOutpoints []*wire.OutPoint
	defer func() {
		if len(unlockOutpoints) != 0 {
			w.lockedOutpointMu.Lock()
			for _, op := range unlockOutpoints {
				delete(w.lockedOutpoints, outpoint{op.Hash, op.Index})
			}
			w.lockedOutpointMu.Unlock()
		}
	}()
	ignoreInput := func(op *wire.OutPoint) bool {
		_, ok := w.lockedOutpoints[outpoint{op.Hash, op.Index}]
		return ok
	}

	w.lockedOutpointMu.Lock()
	var atx *txauthor.AuthoredTx
	err = walletdb.View(ctx, w.db, func(dbtx walletdb.ReadTx) error {
		_, tipHeight := w.txStore.MainChainTip(dbtx)
		inputSource := w.txStore.MakeInputSourceWithCoinType(dbtx, req.SourceAccount,
			req.MinConf, tipHeight, ignoreInput, ticketCoinType)
		changeSource := &p2PKHChangeSource{
			persist:   w.deferPersistReturnedChild(ctx, &changeSourceUpdates),
			account:   req.ChangeAccount,
			wallet:    w,
			ctx:       ctx,
			gapPolicy: gapPolicyIgnore,
		}
		var err error
		atx, err = txauthor.NewUnsignedTransaction(mixOut, relayFee,
			inputSource.SelectInputs, changeSource,
			w.chainParams.MaxTxSize, -1)
		if err != nil {
			return err
		}
		for _, in := range atx.Tx.TxIn {
			prev := &in.PreviousOutPoint
			w.lockedOutpoints[outpoint{prev.Hash, prev.Index}] = struct{}{}
			unlockOutpoints = append(unlockOutpoints, prev)
		}
		return nil
	})
	w.lockedOutpointMu.Unlock()
	if err != nil {
		return
	}
	for _, in := range atx.Tx.TxIn {
		log.Infof("selected input %v (%v) for ticket purchase split transaction",
			in.PreviousOutPoint, dcrutil.Amount(in.ValueIn))
	}

	var change *wire.TxOut
	if atx.ChangeIndex >= 0 {
		change = atx.Tx.TxOut[atx.ChangeIndex]
	}
	// Convert SKAAmount to dcrutil.Amount for smallestMixChange (mixing is VAR-only).
	// Guard the int64 conversion so a misconfigured VAR relay fee fails loudly
	// instead of computing a wraparound dust threshold; matches the canonical
	// guard pattern in wallet/txauthor/author.go (NewUnsignedTransaction).
	relayFeeInt64, err := relayFee.Int64()
	if err != nil {
		return nil, nil, errors.E(errors.Invalid,
			"fee overflow: configured VAR relay fee rate produces a fee that exceeds int64")
	}
	if change != nil && dcrutil.Amount(change.Value) < smallestMixChange(dcrutil.Amount(relayFeeInt64)) {
		change = nil
	}
	gen := w.makeGen(ctx, req.MixedSplitAccount, req.MixedAccountBranch)
	expires := w.dicemixExpiry(ctx)
	cj := mixclient.NewCoinJoin(gen, change, int64(neededPerTicket), expires, uint32(req.Count))
	for i, in := range atx.Tx.TxIn {
		var scriptVersion uint16 = 0 // XXX
		err = w.addCoinJoinInput(ctx, cj, in, atx.PrevScripts[i], scriptVersion)
		if err != nil {
			return
		}
	}

	err = w.mixClient.Dicemix(ctx, cj)
	if err != nil {
		return
	}
	splitTx := cj.Tx()
	splitTxHash := splitTx.TxHash()
	log.Infof("Completed CoinShuffle++ mix of ticket split transaction %v", &splitTxHash)
	return splitTx, cj.MixedIndices(), nil
}

func (w *Wallet) individualSplit(ctx context.Context, req *PurchaseTicketsRequest, neededPerTicket dcrutil.Amount) (tx *wire.MsgTx, outIndexes []int, err error) {
	// Fetch the single use split address to break tickets into, to
	// immediately be consumed as tickets.
	//
	// This opens a write transaction.
	splitTxAddr, err := w.NewInternalAddress(ctx, req.SourceAccount, WithGapPolicyWrap())
	if err != nil {
		return
	}

	vers, splitPkScript := splitTxAddr.PaymentScript()

	// Create the split transaction by using txToOutputs. This varies
	// based upon whether or not the user is using a stake pool or not.
	// For the default stake pool implementation, the user pays out the
	// first ticket commitment of a smaller amount to the pool, while
	// paying themselves with the larger ticket commitment.
	// Tickets are VAR-only
	const ticketCoinType = cointype.CoinTypeVAR
	var splitOuts []*wire.TxOut
	for i := 0; i < req.Count; i++ {
		splitOuts = append(splitOuts, &wire.TxOut{
			Value:    int64(neededPerTicket),
			PkScript: splitPkScript,
			Version:  vers,
			CoinType: ticketCoinType,
		})
		outIndexes = append(outIndexes, i)
	}

	const op errors.Op = "individualSplit"
	a := &authorTx{
		outputs:                  splitOuts,
		account:                  req.SourceAccount,
		changeAccount:            req.ChangeAccount,
		minconf:                  req.MinConf,
		randomizeChangeIdx:       false,
		txFee:                    w.RelayFeeForCoinType(ctx, ticketCoinType),
		dontSignTx:               req.DontSignTx,
		isTreasury:               false,
		subtractFeeFromAmountIdx: -1,
	}
	err = w.authorTx(ctx, op, a)
	if err != nil {
		return
	}
	if !req.DontSignTx {
		err = w.recordAuthoredTx(ctx, op, a)
		if err != nil {
			return
		}
		err = w.publishAndWatch(ctx, op, nil, a.atx.Tx, a.watch)
		if err != nil {
			return
		}
	}

	tx = a.atx.Tx
	return
}

var errVSPFeeRequiresUTXOSplit = errors.New("paying VSP fee requires UTXO split")

// purchaseTickets indicates to the wallet that a ticket should be purchased
// using all currently available funds.   Also, when the spend limit in the
// request is greater than or equal to 0, tickets that cost more than that limit
// will return an error that not enough funds are available.
func (w *Wallet) purchaseTickets(ctx context.Context, op errors.Op,
	n NetworkBackend, req *PurchaseTicketsRequest) (*PurchaseTicketsResponse, error) {
	// Staking is only supported for VAR coins
	// This is a fundamental protocol constraint - tickets, votes, and revocations
	// must use the native VAR currency for consensus participation
	// Note: This check ensures no SKA coins can be used for staking

	// Ensure the minimum number of required confirmations is positive.
	if req.MinConf < 0 {
		return nil, errors.E(op, errors.Invalid, "negative minconf")
	}
	// Need a positive or zero expiry that is higher than the next block to
	// generate.
	if req.Expiry < 0 {
		return nil, errors.E(op, errors.Invalid, "negative expiry")
	}

	// Perform a sanity check on expiry.
	var tipHeight int32
	err := walletdb.View(ctx, w.db, func(dbtx walletdb.ReadTx) error {
		_, tipHeight = w.txStore.MainChainTip(dbtx)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if req.Expiry <= tipHeight+1 && req.Expiry > 0 {
		return nil, errors.E(op, errors.Invalid, "expiry height must be above next block height")
	}

	// Pre-flight: staking requires VAR. If the source account holds no VAR
	// at all (e.g. operator pointed at an SKA-only account), surface an
	// actionable error here rather than failing late inside mixedSplit /
	// individualSplit as a generic InsufficientBalance.
	varBalance, err := w.AccountBalanceByCoinType(ctx, req.SourceAccount, cointype.CoinTypeVAR, req.MinConf)
	if err != nil {
		return nil, errors.E(op, err)
	}
	// Check Spendable (not Total): a wallet with all VAR locked in tickets
	// has Total > 0 but Spendable = 0; the ticket purchase still cannot
	// fund a new split, and the late mixedSplit/individualSplit failure
	// reports the same condition with less actionable wording.
	if varBalance.Spendable == 0 {
		return nil, errors.E(op, errors.InsufficientBalance,
			errors.Errorf("source account %d has no spendable VAR; staking requires spendable VAR (cointype %d)",
				req.SourceAccount, cointype.CoinTypeVAR))
	}

	stakeAddrFunc := func(op errors.Op, account, branch uint32) (stdaddr.StakeAddress, uint32, error) {
		const accountName = "" // not used, so can be faked.
		a, err := w.nextAddress(ctx, op, w.persistReturnedChild(ctx, nil), accountName,
			account, branch, WithGapPolicyIgnore())
		if err != nil {
			return nil, 0, err
		}
		var idx uint32
		if xpa, ok := a.(*xpubAddress); ok {
			idx = xpa.child
		}
		switch a := a.(type) {
		case stdaddr.StakeAddress:
			return a, idx, nil
		default:
			return nil, 0, errors.E(errors.Invalid, "account does "+
				"not return compatible stake addresses")
		}
	}

	// Calculate the current ticket price.  If the DCP0001 deployment is not
	// active, fallback to querying the ticket price over RPC.
	ticketPrice, err := w.NextStakeDifficulty(ctx)
	if errors.Is(err, errors.Deployment) {
		ticketPrice, err = n.StakeDifficulty(ctx)
	}
	if err != nil {
		return nil, err
	}

	const stakeSubmissionPkScriptSize = txsizes.P2PKHPkScriptSize + 1

	// Make sure that we have enough funds. Calculate different
	// ticket required amounts depending on whether or not a
	// pool output is needed. If the ticket fee increment is
	// unset in the request, use the global ticket fee increment.
	var neededPerTicket dcrutil.Amount
	var estSize int
	ticketRelayFee := w.RelayFee()

	// A solo ticket has:
	//   - a single input redeeming a P2PKH for the worst case size
	//   - a P2PKH or P2SH stake submission output
	//   - a ticket commitment output
	//   - an OP_SSTXCHANGE tagged P2PKH or P2SH change output
	//
	//   NB: The wallet currently only supports P2PKH change addresses.
	//   The network supports both P2PKH and P2SH change addresses however.
	inSizes := []int{txsizes.RedeemP2PKHSigScriptSize}
	outSizes := []int{stakeSubmissionPkScriptSize,
		txsizes.TicketCommitmentScriptSize, txsizes.P2PKHPkScriptSize + 1}
	estSize = txsizes.EstimateSerializeSizeFromScriptSizes(inSizes,
		outSizes, 0)

	ticketFee := txrules.FeeForSerializeSize(ticketRelayFee, estSize)
	neededPerTicket = ticketFee + ticketPrice

	// After tickets are created and published, watch for future
	// relevant transactions
	var watchOutPoints []wire.OutPoint
	defer func() {
		// Cancellation of the request context should not prevent the
		// watching of addresses and outpoints that need to be watched.
		// A better solution would be to watch for the data first,
		// before publishing transactions.
		ctx := context.Background()
		_, err := w.watchHDAddrs(ctx, false, n)
		if err != nil {
			log.Errorf("Failed to watch for future addresses after ticket "+
				"purchases: %v", err)
		}
		if len(watchOutPoints) > 0 {
			err := n.LoadTxFilter(ctx, false, nil, watchOutPoints)
			if err != nil {
				log.Errorf("Failed to watch outpoints: %v", err)
			}
		}
	}()

	var vspFeeCredits, ticketCredits [][]Input
	unlockCredits := true
	total := func(ins []Input) (v int64) {
		for _, in := range ins {
			v += in.PrevOut.Value
		}
		return
	}
	if req.VSPClient != nil {
		feePrice, err := req.VSPClient.FeePercentage(ctx)
		if err != nil {
			return nil, err
		}
		// In SPV mode, DCP0010 and DCP0012 are assumed to have activated.  This
		// results in a larger fee calculation for the purposes of UTXO
		// selection.  In RPC mode the actual activation can be determined.
		dcp0010Active := true
		dcp0012Active := true
		switch n := n.(type) {
		case deployments.Querier:
			dcp0010Active, err = deployments.DCP0010Active(ctx,
				tipHeight, w.chainParams, n)
			if err != nil {
				return nil, err
			}
			dcp0012Active, err = deployments.DCP0012Active(ctx,
				tipHeight, w.chainParams, n)
			if err != nil {
				return nil, err
			}
		}
		fee := txrules.StakePoolTicketFee(ticketPrice, ticketFee,
			tipHeight, feePrice, w.chainParams,
			dcp0010Active, dcp0012Active)

		// Reserve outputs for number of buys.
		vspFeeCredits = make([][]Input, 0, req.Count)
		ticketCredits = make([][]Input, 0, req.Count)
		defer func() {
			if unlockCredits {
				for _, credit := range vspFeeCredits {
					for _, c := range credit {
						log.Debugf("unlocked unneeded credit for vsp fee tx: %v",
							c.OutPoint.String())
						w.UnlockOutpoint(&c.OutPoint.Hash, c.OutPoint.Index)
					}
				}
			}
		}()
		if req.extraSplitOutput != nil {
			vspFeeCredits = make([][]Input, 1)
			vspFeeCredits[0] = []Input{*req.extraSplitOutput}
			op := &req.extraSplitOutput.OutPoint
			w.LockOutpoint(&op.Hash, op.Index)
		}
		var lowBalance bool
		for i := 0; i < req.Count; i++ {
			if req.extraSplitOutput == nil {
				credits, err := w.ReserveOutputsForAmount(ctx,
					req.SourceAccount, fee, cointype.Zero(), req.MinConf, cointype.CoinTypeVAR)

				if errors.Is(err, errors.InsufficientBalance) {
					lowBalance = true
					break
				}
				if err != nil {
					log.Errorf("ReserveOutputsForAmount failed: %v", err)
					return nil, err
				}
				vspFeeCredits = append(vspFeeCredits, credits)
			}

			credits, err := w.ReserveOutputsForAmount(ctx, req.SourceAccount,
				ticketPrice, cointype.Zero(), req.MinConf, cointype.CoinTypeVAR)
			if errors.Is(err, errors.InsufficientBalance) {
				lowBalance = true
				credits, _ = w.reserveOutputs(ctx, req.SourceAccount,
					req.MinConf, cointype.CoinTypeVAR)
				if len(credits) != 0 {
					ticketCredits = append(ticketCredits, credits)
				}
				break
			}
			if err != nil {
				log.Errorf("ReserveOutputsForAmount failed: %v", err)
				return nil, err
			}
			ticketCredits = append(ticketCredits, credits)
		}
		for _, credits := range ticketCredits {
			for _, c := range credits {
				log.Debugf("unlocked credit for ticket tx: %v",
					c.OutPoint.String())
				w.UnlockOutpoint(&c.OutPoint.Hash, c.OutPoint.Index)
			}
		}
		if lowBalance {
			// When there is UTXO contention between reserved fee
			// UTXOs and the tickets that can be purchased, UTXOs
			// which were selected for paying VSP fees are instead
			// allocated towards purchasing tickets.  We sort the
			// UTXOs picked for fees and tickets by decreasing
			// amounts and incrementally reserve them for ticket
			// purchases while reducing the total number of fees
			// (and therefore tickets) that will be purchased.  The
			// final UTXOs chosen for ticket purchases must be
			// unlocked for UTXO selection to work, while all inputs
			// for fee payments must be locked.
			credits := vspFeeCredits[:len(vspFeeCredits):len(vspFeeCredits)]
			credits = append(credits, ticketCredits...)
			sort.Slice(credits, func(i, j int) bool {
				return total(credits[i]) > total(credits[j])
			})
			if len(credits) == 0 {
				return nil, errors.E(errors.InsufficientBalance)
			}
			if req.Count > len(credits)-1 {
				req.Count = len(credits) - 1
			}
			var freedBalance int64
			extraSplit := true
			for req.Count > 1 {
				for _, c := range credits[0] {
					freedBalance += c.PrevOut.Value
					w.UnlockOutpoint(&c.OutPoint.Hash, c.OutPoint.Index)
				}
				credits = credits[1:]
				// XXX this is a bad estimate because it doesn't
				// consider the transaction fees
				if freedBalance > int64(ticketPrice)*int64(req.Count) {
					extraSplit = false
					break
				}
				req.Count--
			}
			vspFeeCredits = credits
			var remaining int64
			for _, c := range vspFeeCredits {
				remaining += total(c)
				for i := range c {
					w.LockOutpoint(&c[i].OutPoint.Hash, c[i].OutPoint.Index)
				}
			}

			if req.Count < 2 && extraSplit {
				// XXX still a bad estimate
				if int64(ticketPrice) > freedBalance+remaining {
					return nil, errors.E(errors.InsufficientBalance)
				}
				// A new transaction may need to be created to
				// split a single UTXO into two: one to pay the
				// VSP fee, and a second to fund the ticket
				// purchase.  This error condition is left to
				// the caller to detect and perform.
				return nil, errVSPFeeRequiresUTXOSplit
			}
		}
		log.Infof("Reserved credits for %d tickets: total fee: %v", req.Count, fee)
		for _, credit := range vspFeeCredits {
			for _, c := range credit {
				log.Debugf("%s reserved for vsp fee transaction", c.OutPoint.String())
			}
		}
	}

	purchaseTicketsResponse := &PurchaseTicketsResponse{}
	var splitTx *wire.MsgTx
	var splitOutputIndexes []int
	for {
		switch {
		case req.Mixing:
			splitTx, splitOutputIndexes, err = w.mixedSplit(ctx, req, neededPerTicket)
		default:
			splitTx, splitOutputIndexes, err = w.individualSplit(ctx, req, neededPerTicket)
		}
		if errors.Is(err, errors.InsufficientBalance) && req.Count > 1 {
			req.Count--
			if len(vspFeeCredits) > 0 {
				for _, in := range vspFeeCredits[0] {
					w.UnlockOutpoint(&in.OutPoint.Hash, in.OutPoint.Index)
				}
				vspFeeCredits = vspFeeCredits[1:]
			}
			continue
		}
		if err != nil {
			return nil, errors.E(op, err)
		}
		break
	}
	purchaseTicketsResponse.SplitTx = splitTx

	// Process and publish split tx.
	if !req.DontSignTx {
		rec, err := udb.NewTxRecordFromMsgTx(splitTx, time.Now())
		if err != nil {
			return nil, err
		}
		w.lockedOutpointMu.Lock()
		var publishHeight int32
		err = walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
			_, publishHeight = w.txStore.MainChainTip(dbtx)
			watch, err := w.processTransactionRecord(ctx, dbtx, rec, nil, nil)
			watchOutPoints = append(watchOutPoints, watch...)
			return err
		})
		w.lockedOutpointMu.Unlock()
		if err != nil {
			return nil, err
		}
		w.recentlyPublishedMu.Lock()
		w.markRecentlyPublishedLocked(rec.Hash, publishHeight, splitTx.Expiry)
		w.recentlyPublishedMu.Unlock()
		err = n.PublishTransactions(ctx, splitTx)
		if err != nil {
			// Match publishAndWatch: keep the wallet's view consistent
			// with the network by abandoning the locally-recorded but
			// unpublished transaction.
			hash := splitTx.TxHash()
			log.Errorf("Abandoning ticket split %v which failed to publish", &hash)
			if abandonErr := w.AbandonTransaction(ctx, &hash); abandonErr != nil {
				log.Errorf("Cannot abandon %v: %v", &hash, abandonErr)
			}
			return nil, err
		}
	}

	// Calculate trickle times for published mixed tickets.
	// Random times between 20s to 1m from now are chosen for each ticket,
	// and tickets will not be published until their trickle time is reached.
	var trickleTickets []time.Time
	if req.Mixing {
		now := time.Now()
		trickleTickets = make([]time.Time, 0, len(splitOutputIndexes))
		for range splitOutputIndexes {
			t := now.Add(20*time.Second + rand.Duration(40*time.Second))
			trickleTickets = append(trickleTickets, t)
		}
		sort.Slice(trickleTickets, func(i, j int) bool {
			t1 := trickleTickets[i]
			t2 := trickleTickets[j]
			return t1.Before(t2)
		})
	}

	// Create each ticket.
	ticketHashes := make([]*chainhash.Hash, 0, req.Count)
	tickets := make([]*wire.MsgTx, 0, req.Count)
	splitOutpoint := wire.OutPoint{Hash: splitTx.TxHash()}
	for _, index := range splitOutputIndexes {
		// Generate the extended outpoint that we need to use for ticket
		// input.
		var eop *Input
		splitOutpoint.Index = uint32(index)
		log.Infof("Split output is %v", &splitOutpoint)
		txOut := splitTx.TxOut[index]
		eop = &Input{
			OutPoint: splitOutpoint,
			PrevOut:  *txOut,
		}

		addrVote, idx, err := stakeAddrFunc(op, req.VotingAccount, 1)
		if err != nil {
			return nil, err
		}
		_, err = w.signingAddressAtIdx(ctx, op, w.persistReturnedChild(ctx, nil),
			req.VotingAccount, idx)
		if err != nil {
			return nil, err
		}
		subsidyAccount := req.SourceAccount
		var branch uint32 = 1
		if req.Mixing {
			subsidyAccount = req.MixedAccount
			branch = req.MixedAccountBranch
		}
		addrSubsidy, _, err := stakeAddrFunc(op, subsidyAccount, branch)
		if err != nil {
			return nil, err
		}

		w.lockedOutpointMu.Lock()
		err = walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
			// Generate the ticket msgTx and sign it if DontSignTx is false.
			ticket, err := makeTicket(w.chainParams, eop, addrVote,
				addrSubsidy, int64(ticketPrice))
			if err != nil {
				return err
			}
			// Set the expiry.
			ticket.Expiry = uint32(req.Expiry)

			ticketHash := ticket.TxHash()
			ticketHashes = append(ticketHashes, &ticketHash)
			tickets = append(tickets, ticket)

			purchaseTicketsResponse.Tickets = tickets
			purchaseTicketsResponse.TicketHashes = ticketHashes

			if req.DontSignTx {
				return nil
			}
			// Sign and publish tx if DontSignTx is false
			forSigning := []Input{*eop}

			ns := dbtx.ReadBucket(waddrmgrNamespaceKey)
			err = w.signP2PKHMsgTx(ticket, forSigning, ns)
			if err != nil {
				return err
			}
			err = validateMsgTx(op, ticket, creditScripts(forSigning))
			if err != nil {
				return err
			}

			err = w.checkHighFees(dcrutil.Amount(eop.PrevOut.Value), cointype.Zero(), ticket)
			if err != nil {
				return err
			}

			rec, err := udb.NewTxRecordFromMsgTx(ticket, time.Now())
			if err != nil {
				return err
			}

			_, publishHeight := w.txStore.MainChainTip(dbtx)
			watch, err := w.processTransactionRecord(ctx, dbtx, rec, nil, nil)
			watchOutPoints = append(watchOutPoints, watch...)
			if err != nil {
				return err
			}

			w.recentlyPublishedMu.Lock()
			w.markRecentlyPublishedLocked(rec.Hash, publishHeight, ticket.Expiry)
			w.recentlyPublishedMu.Unlock()

			return nil
		})
		w.lockedOutpointMu.Unlock()
		if err != nil {
			return purchaseTicketsResponse, errors.E(op, err)
		}
	}

	if req.DontSignTx {
		return purchaseTicketsResponse, nil
	}

	for i, ticket := range tickets {
		// Check for request context cancellation while waiting for
		// trickle time if this was a mixed buy.
		if len(trickleTickets) > 0 {
			t := trickleTickets[0]
			trickleTickets = trickleTickets[1:]
			timer := time.NewTimer(time.Until(t))
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return purchaseTicketsResponse, errors.E(op, ctx.Err())
			case <-timer.C:
			}
		} else if err := ctx.Err(); err != nil {
			return purchaseTicketsResponse, errors.E(op, err)
		}

		// Publish transaction
		err = n.PublishTransactions(ctx, ticket)
		if err != nil {
			// The ticket was already recorded locally before publish;
			// abandon it so wallet state stays consistent with the
			// network. Mirrors publishAndWatch.
			hash := ticket.TxHash()
			log.Errorf("Abandoning ticket %v which failed to publish", &hash)
			if abandonErr := w.AbandonTransaction(ctx, &hash); abandonErr != nil {
				log.Errorf("Cannot abandon %v: %v", &hash, abandonErr)
			}
			return purchaseTicketsResponse, errors.E(op, err)
		}
		log.Infof("Published ticket purchase %v", ticket.TxHash())

		// Pay VSP fee when configured to do so.
		if req.VSPClient == nil {
			continue
		}
		unlockCredits = false
		feeTx := wire.NewMsgTx()
		for j := range vspFeeCredits[i] {
			in := &vspFeeCredits[i][j]
			feeTx.AddTxIn(wire.NewTxIn(&in.OutPoint, in.PrevOut.Value, nil))
		}
		ticketHash := purchaseTicketsResponse.TicketHashes[i]

		// Unlock outpoints in case of error.
		unlock := func() {
			for _, outpoint := range vspFeeCredits[i] {
				w.UnlockOutpoint(&outpoint.OutPoint.Hash,
					outpoint.OutPoint.Index)
			}
		}

		ticket, err := w.NewVSPTicket(ctx, ticketHash)
		if err != nil {
			unlock()
			continue
		}

		err = req.VSPClient.Process(ctx, ticket, feeTx)
		if err != nil {
			unlock()
			continue
		}
		// watch for outpoints change.
		_, err = udb.NewTxRecordFromMsgTx(feeTx, time.Now())
		if err != nil {
			return nil, err
		}
	}

	return purchaseTicketsResponse, err
}

// ReserveOutputsForAmount returns locked spendable outpoints from the given
// account.  It is the responsibility of the caller to unlock the outpoints.
// For VAR coin type the `amount` parameter drives selection and `amountSKA`
// is ignored; for SKA the `amountSKA` big.Int parameter drives selection and
// `amount` is ignored. Callers operating on one coin should pass 0 or
// cointype.Zero() for the unused parameter.
func (w *Wallet) ReserveOutputsForAmount(ctx context.Context, account uint32, amount dcrutil.Amount, amountSKA cointype.SKAAmount, minconf int32, coinType cointype.CoinType) ([]Input, error) {
	defer w.lockedOutpointMu.Unlock()
	w.lockedOutpointMu.Lock()

	var outputs []Input
	err := walletdb.View(ctx, w.db, func(dbtx walletdb.ReadTx) error {
		// Get current block's height
		_, tipHeight := w.txStore.MainChainTip(dbtx)

		var err error
		const minAmount = 0
		const maxResults = 0
		outputs, err = w.findEligibleOutputsAmount(dbtx, account, minconf, amount, amountSKA, tipHeight,
			minAmount, maxResults, coinType)
		if err != nil {
			return err
		}

		for _, output := range outputs {
			w.lockedOutpoints[outpoint{output.OutPoint.Hash, output.OutPoint.Index}] = struct{}{}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return outputs, nil
}

func (w *Wallet) reserveOutputs(ctx context.Context, account uint32, minconf int32, coinType cointype.CoinType) ([]Input, error) {
	defer w.lockedOutpointMu.Unlock()
	w.lockedOutpointMu.Lock()

	var outputs []Input
	err := walletdb.View(ctx, w.db, func(dbtx walletdb.ReadTx) error {
		// Get current block's height
		_, tipHeight := w.txStore.MainChainTip(dbtx)

		var err error
		outputs, err = w.findEligibleOutputs(dbtx, account, minconf, tipHeight, coinType)
		if err != nil {
			return err
		}

		for _, output := range outputs {
			w.lockedOutpoints[outpoint{output.OutPoint.Hash, output.OutPoint.Index}] = struct{}{}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return outputs, nil
}

// This can't be optimized to use the random selection because it must read all
// outputs.  Prefer to use findEligibleOutputsAmount with various filter options
// instead.
func (w *Wallet) findEligibleOutputs(dbtx walletdb.ReadTx, account uint32, minconf int32,
	currentHeight int32, coinType cointype.CoinType) ([]Input, error) {

	addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)

	unspent, err := w.txStore.UnspentOutputs(dbtx, coinType)
	if err != nil {
		return nil, err
	}

	// TODO: Eventually all of these filters (except perhaps output locking)
	// should be handled by the call to UnspentOutputs (or similar).
	// Because one of these filters requires matching the output script to
	// the desired account, this change depends on making wtxmgr a waddrmgr
	// dependency and requesting unspent outputs for a single account.
	eligible := make([]Input, 0, len(unspent))
	for i := range unspent {
		output := unspent[i]

		// Locked unspent outputs are skipped.
		if _, locked := w.lockedOutpoints[outpoint{output.Hash, output.Index}]; locked {
			continue
		}

		// Only include this output if it meets the required number of
		// confirmations.  Coinbase transactions must have reached
		// maturity before their outputs may be spent.
		if !confirmed(minconf, output.Height, currentHeight) {
			continue
		}

		// Filter out unspendable outputs, that is, remove those that
		// (at this time) are not P2PKH outputs.  Other inputs must be
		// manually included in transactions and sent (for example,
		// using createrawtransaction, signrawtransaction, and
		// sendrawtransaction).
		class, addrs := stdscript.ExtractAddrs(scriptVersionAssumed, output.PkScript, w.chainParams)
		if len(addrs) != 1 {
			continue
		}

		// Make sure everything we're trying to spend is actually mature.
		switch class {
		case stdscript.STStakeGenPubKeyHash, stdscript.STStakeGenScriptHash:
			if !w.txStore.StakeGenMatured(dbtx, output, currentHeight) {
				continue
			}
		case stdscript.STStakeRevocationPubKeyHash, stdscript.STStakeRevocationScriptHash:
			if !coinbaseMatured(w.chainParams, output.Height, currentHeight) {
				continue
			}
		case stdscript.STTreasuryAdd, stdscript.STTreasuryGenPubKeyHash, stdscript.STTreasuryGenScriptHash:
			if !coinbaseMatured(w.chainParams, output.Height, currentHeight) {
				continue
			}
		case stdscript.STStakeChangePubKeyHash, stdscript.STStakeChangeScriptHash:
			if !ticketChangeMatured(w.chainParams, output.Height, currentHeight) {
				continue
			}
		case stdscript.STPubKeyHashEcdsaSecp256k1:
			if output.FromCoinBase {
				if !coinbaseMatured(w.chainParams, output.Height, currentHeight) {
					continue
				}
			}
		default:
			continue
		}

		// Only include the output if it is associated with the passed
		// account.
		//
		// TODO: Handle multisig outputs by determining if enough of the
		// addresses are controlled.
		addrAcct, err := w.manager.AddrAccount(addrmgrNs, addrs[0])
		if err != nil || addrAcct != account {
			continue
		}

		// Filter by coin type
		if output.CoinType != coinType {
			continue
		}

		txOut := &wire.TxOut{
			Value:    int64(output.Amount),
			Version:  wire.DefaultPkScriptVersion,
			PkScript: output.PkScript,
			CoinType: output.CoinType,
		}
		if output.CoinType.IsSKA() {
			// SKA value lives in SKAValue (big.Int); leave Value at 0
			// so downstream consumers (e.g. compressWalletInternal) treat
			// this as an SKA input and not a VAR input.
			txOut.Value = 0
			txOut.SKAValue = output.SKAAmount.BigInt()
		}
		eligible = append(eligible, Input{
			OutPoint: output.OutPoint,
			PrevOut:  *txOut,
		})
	}

	return eligible, nil
}

// findEligibleOutputsAmount uses wtxmgr to find a number of unspent outputs
// while doing maturity checks there.
//
// For VAR (coinType == CoinTypeVAR) the `amount` / `minAmount` parameters drive
// selection and `amountSKA` is ignored. For SKA coin types the `amountSKA`
// parameter drives selection (via big.Int comparisons so values above
// math.MaxInt64 atoms are handled correctly) and `amount` / `minAmount` are
// ignored.
//
// "No-target" sentinel: passing `amount == 0` (VAR) or `amountSKA.IsZero()`
// (SKA) signals "consume every eligible output up to maxResults" — the
// inherited wallet idiom, used by consolidation and sweep flows. There is
// no supported way to request a transaction with a real zero-atom target;
// callers that need exactly zero atoms (e.g. a VAR-only output that ships
// with an SKA-typed sibling) must construct the transaction manually. The
// public RPC layer rejects zero-amount sends in sendto*/sendtoburn before
// reaching this function, so this convention is safe in practice.
func (w *Wallet) findEligibleOutputsAmount(dbtx walletdb.ReadTx, account uint32, minconf int32,
	amount dcrutil.Amount, amountSKA cointype.SKAAmount, currentHeight int32, minAmount dcrutil.Amount,
	maxResults int, coinType cointype.CoinType) ([]Input, error) {

	addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
	isSKA := coinType.IsSKA()

	var eligible []Input
	var outTotal dcrutil.Amount
	outTotalSKA := cointype.Zero()
	seen := make(map[outpoint]struct{})
	skip := func(output *udb.Credit) bool {
		if _, ok := seen[outpoint{output.Hash, output.Index}]; ok {
			return true
		}

		// Locked unspent outputs are skipped.
		if _, locked := w.lockedOutpoints[outpoint{output.Hash, output.Index}]; locked {
			return true
		}

		// Only include this output if it meets the required number of
		// confirmations.  Coinbase transactions must have reached
		// maturity before their outputs may be spent.
		if !confirmed(minconf, output.Height, currentHeight) {
			return true
		}

		// When a minimum amount is required, skip when it is less.
		// VAR-only; SKA callers do not use minAmount (its int64 type
		// cannot represent SKA atoms anyway).
		if !isSKA && minAmount != 0 && output.Amount < minAmount {
			return true
		}

		// Filter out unspendable outputs, that is, remove those that
		// (at this time) are not P2PKH outputs.  Other inputs must be
		// manually included in transactions and sent (for example,
		// using createrawtransaction, signrawtransaction, and
		// sendrawtransaction).
		class, addrs := stdscript.ExtractAddrs(scriptVersionAssumed, output.PkScript, w.chainParams)
		if len(addrs) != 1 {
			return true
		}

		// Make sure everything we're trying to spend is actually mature.
		switch class {
		case stdscript.STStakeGenPubKeyHash, stdscript.STStakeGenScriptHash:
			if !w.txStore.StakeGenMatured(dbtx, output, currentHeight) {
				return true
			}
		case stdscript.STStakeRevocationPubKeyHash, stdscript.STStakeRevocationScriptHash:
			if !coinbaseMatured(w.chainParams, output.Height, currentHeight) {
				return true
			}
		case stdscript.STTreasuryAdd, stdscript.STTreasuryGenPubKeyHash, stdscript.STTreasuryGenScriptHash:
			if !coinbaseMatured(w.chainParams, output.Height, currentHeight) {
				return true
			}
		case stdscript.STStakeChangePubKeyHash, stdscript.STStakeChangeScriptHash:
			if !ticketChangeMatured(w.chainParams, output.Height, currentHeight) {
				return true
			}
		case stdscript.STPubKeyHashEcdsaSecp256k1:
			if output.FromCoinBase {
				if !coinbaseMatured(w.chainParams, output.Height, currentHeight) {
					return true
				}
			}
		default:
			return true
		}

		// Only include the output if it is associated with the passed
		// account.  There should only be one address since this is a
		// P2PKH script.
		addrAcct, err := w.manager.AddrAccount(addrmgrNs, addrs[0])
		if err != nil || addrAcct != account {
			return true
		}

		// Filter by coin type
		if output.CoinType != coinType {
			return true
		}

		return false
	}

	// targetMet reports whether accumulated outputs cover the caller's target.
	// amount == 0 (VAR) / amountSKA.IsZero() (SKA) means "no target" — keep
	// collecting until maxResults (if set) or the UTXO set is exhausted.
	targetMet := func() bool {
		if isSKA {
			return !amountSKA.IsZero() && outTotalSKA.Cmp(amountSKA) >= 0
		}
		return amount != 0 && outTotal >= amount
	}

	// appendInput builds the Input struct from a credit, tracks the running
	// total for the current coin type, and appends to the eligible slice.
	appendInput := func(output *udb.Credit) {
		txOut := &wire.TxOut{
			Value:    int64(output.Amount),
			Version:  wire.DefaultPkScriptVersion,
			PkScript: output.PkScript,
			CoinType: output.CoinType,
		}
		if isSKA {
			txOut.Value = 0
			txOut.SKAValue = output.SKAAmount.BigInt()
			outTotalSKA = outTotalSKA.Add(output.SKAAmount)
		} else {
			outTotal += output.Amount
		}
		eligible = append(eligible, Input{
			OutPoint: output.OutPoint,
			PrevOut:  *txOut,
		})
	}

	hasTarget := (!isSKA && amount != 0) || (isSKA && !amountSKA.IsZero())

	randTries := 0
	maxTries := 0
	if (hasTarget || maxResults != 0) && minconf > 0 {
		// Budget the random-pass by the count of UTXOs that RandomUTXO can
		// actually return (filtered by coin type) — otherwise a wallet with
		// many VAR UTXOs and few SKA UTXOs would burn iterations looking for
		// the wrong coin type before falling back to the deterministic pass.
		numUnspent := w.txStore.UnspentOutputCount(dbtx, &coinType)
		log.Debugf("Unspent bucket k/v count for cointype %d: %v", coinType, numUnspent)
		maxTries = numUnspent / 2
	}
	for ; randTries < maxTries; randTries++ {
		output, err := w.txStore.RandomUTXO(dbtx, minconf, currentHeight, coinType)
		if err != nil {
			return nil, err
		}
		if output == nil {
			break
		}
		if skip(output) {
			continue
		}
		seen[outpoint{output.Hash, output.Index}] = struct{}{}
		appendInput(output)
		if targetMet() {
			return eligible, nil
		}
		if maxResults != 0 && len(eligible) == maxResults {
			return eligible, nil
		}
	}
	if randTries > 0 {
		log.Debugf("Abandoned random UTXO selection "+
			"attempts after %v tries", randTries)
	}

	eligible = eligible[:0]
	seen = make(map[outpoint]struct{})
	outTotal = 0
	outTotalSKA = cointype.Zero()
	unspent, err := w.txStore.UnspentOutputs(dbtx, coinType)
	if err != nil {
		return nil, err
	}
	rand.ShuffleSlice(unspent)

	for i := range unspent {
		output := unspent[i]
		if skip(output) {
			continue
		}
		appendInput(output)
		if targetMet() {
			return eligible, nil
		}
		if maxResults != 0 && len(eligible) == maxResults {
			return eligible, nil
		}
	}
	if hasTarget && !targetMet() {
		return nil, errors.InsufficientBalance
	}

	return eligible, nil
}

// signP2PKHMsgTx sets the SignatureScript for every item in msgtx.TxIn.
// It must be called every time a msgtx is changed.
// Only P2PKH outputs are supported at this point.
func (w *Wallet) signP2PKHMsgTx(msgtx *wire.MsgTx, prevOutputs []Input, addrmgrNs walletdb.ReadBucket) error {
	if len(prevOutputs) != len(msgtx.TxIn) {
		return errors.Errorf(
			"Number of prevOutputs (%d) does not match number of tx inputs (%d)",
			len(prevOutputs), len(msgtx.TxIn))
	}
	for i, output := range prevOutputs {
		_, addrs := stdscript.ExtractAddrs(output.PrevOut.Version, output.PrevOut.PkScript, w.chainParams)
		if len(addrs) != 1 {
			return errors.E(errors.Op("wallet.signP2PKHMsgTx"), errors.Bug,
				errors.Errorf("input %d: previous output is not a P2PKH script (extracted %d addresses)", i, len(addrs)))
		}
		apkh, ok := addrs[0].(*stdaddr.AddressPubKeyHashEcdsaSecp256k1V0)
		if !ok {
			return errors.E(errors.Bug, "previous output address is not P2PKH")
		}

		// Wrap each iteration so its decrypted private key is released
		// (done()) immediately after this input is signed, instead of
		// accumulating N decrypted secp256k1 keys in memory until the
		// outer function returns.
		err := func() error {
			privKey, done, err := w.manager.PrivateKey(addrmgrNs, apkh)
			if err != nil {
				return err
			}
			defer done()

			sigscript, err := sign.SignatureScript(msgtx, i, output.PrevOut.PkScript,
				txscript.SigHashAll, privKey.Serialize(), dcrec.STEcdsaSecp256k1, true)
			if err != nil {
				return errors.E(errors.Op("txscript.SignatureScript"), err)
			}
			msgtx.TxIn[i].SignatureScript = sigscript
			return nil
		}()
		if err != nil {
			return err
		}
	}

	return nil
}

// signVoteOrRevocation signs a vote or revocation, specified by the isVote
// argument.  This signs the transaction by modifying tx's input scripts.
func (w *Wallet) signVoteOrRevocation(addrmgrNs walletdb.ReadBucket, ticketPurchase, tx *wire.MsgTx, isVote bool) error {
	// Create a slice of functions to run after the retreived secrets are no
	// longer needed.
	doneFuncs := make([]func(), 0, len(tx.TxIn))
	defer func() {
		for _, done := range doneFuncs {
			done()
		}
	}()

	// Prepare functions to look up private key and script secrets so signing
	// can be performed.
	var getKey sign.KeyClosure = func(addr stdaddr.Address) ([]byte, dcrec.SignatureType, bool, error) {
		key, done, err := w.manager.PrivateKey(addrmgrNs, addr)
		if err != nil {
			return nil, 0, false, err
		}
		doneFuncs = append(doneFuncs, done)

		// secp256k1 pubkeys are always compressed in Decred
		return key.Serialize(), dcrec.STEcdsaSecp256k1, true, nil
	}
	var getScript sign.ScriptClosure = func(addr stdaddr.Address) ([]byte, error) {
		return w.manager.RedeemScript(addrmgrNs, addr)
	}

	// Revocations only contain one input, which is the input that must be
	// signed.  The first input for a vote is the stakebase and the second input
	// must be signed.
	inputToSign := 0
	if isVote {
		inputToSign = 1
	}

	// Sign the input.
	redeemTicketScript := ticketPurchase.TxOut[0].PkScript
	signedScript, err := sign.SignTxOutput(w.chainParams, tx, inputToSign,
		redeemTicketScript, txscript.SigHashAll, getKey, getScript,
		tx.TxIn[inputToSign].SignatureScript, true) // Yes treasury
	if err != nil {
		return errors.E(errors.Op("txscript.SignTxOutput"), errors.ScriptFailure, err)
	}
	tx.TxIn[inputToSign].SignatureScript = signedScript

	return nil
}

// signVote signs a vote transaction.  This modifies the input scripts pointed
// to by the vote transaction.
func (w *Wallet) signVote(addrmgrNs walletdb.ReadBucket, ticketPurchase, vote *wire.MsgTx) error {
	return w.signVoteOrRevocation(addrmgrNs, ticketPurchase, vote, true)
}

// newVoteScript generates a voting script from the passed VoteBits, for
// use in a vote.
func newVoteScript(voteBits stake.VoteBits) ([]byte, error) {
	b := make([]byte, 2+len(voteBits.ExtendedBits))
	binary.LittleEndian.PutUint16(b[0:2], voteBits.Bits)
	copy(b[2:], voteBits.ExtendedBits)
	return stdscript.ProvablyPruneableScriptV0(b)
}

// createUnsignedVote creates an unsigned vote transaction that votes using the
// ticket specified by a ticket purchase hash and transaction with the provided
// vote bits.  The block height and hash must be of the previous block the vote
// is voting on.  The consolidationHash160 parameter specifies the 20-byte hash160
// address where batched SSFee UTXOs should be sent by miners.
func createUnsignedVote(ticketHash *chainhash.Hash, ticketPurchase *wire.MsgTx,
	blockHeight int32, blockHash *chainhash.Hash, voteBits stake.VoteBits,
	subsidyCache *blockchain.SubsidyCache, params *chaincfg.Params,
	dcp0010Active, dcp0012Active bool, consolidationHash160 []byte) (*wire.MsgTx, error) {

	// Parse the ticket purchase transaction to determine the required output
	// destinations for vote rewards or revocations.
	ticketPayKinds, ticketHash160s, ticketValues, _, _, _ :=
		stake.TxSStxStakeOutputInfo(ticketPurchase)

	// Calculate the subsidy for votes at this height.
	// Use Monetarium subsidy split (50% miners, 50% stakers, 0% treasury)
	ssv := blockchain.SSVMonetarium
	subsidy := subsidyCache.CalcStakeVoteSubsidyV3(int64(blockHeight), ssv)

	// Calculate the output values from this vote using the subsidy.
	voteRewardValues := stake.CalculateRewards(ticketValues,
		ticketPurchase.TxOut[0].Value, subsidy)

	// Begin constructing the vote transaction.
	vote := wire.NewMsgTx()

	// Add stakebase input to the vote.
	stakebaseOutPoint := wire.NewOutPoint(&chainhash.Hash{}, ^uint32(0),
		wire.TxTreeRegular)
	stakebaseInput := wire.NewTxIn(stakebaseOutPoint, subsidy,
		params.StakeBaseSigScript)
	vote.AddTxIn(stakebaseInput)

	// Votes reference the ticket purchase with the second input.
	ticketOutPoint := wire.NewOutPoint(ticketHash, 0, wire.TxTreeStake)
	ticketInput := wire.NewTxIn(ticketOutPoint,
		ticketPurchase.TxOut[ticketOutPoint.Index].Value, nil)
	vote.AddTxIn(ticketInput)

	// The first output references the previous block the vote is voting on.
	// This function never errors.
	blockRefScript, _ := txscript.GenerateSSGenBlockRef(*blockHash,
		uint32(blockHeight))
	vote.AddTxOut(&wire.TxOut{
		Value:    0,
		Version:  wire.DefaultPkScriptVersion,
		PkScript: blockRefScript,
		CoinType: cointype.CoinTypeVAR, // Votes are VAR-only
	})

	// The second output contains the votebits encode as a null data script.
	voteScript, err := newVoteScript(voteBits)
	if err != nil {
		return nil, err
	}
	vote.AddTxOut(&wire.TxOut{
		Value:    0,
		Version:  wire.DefaultPkScriptVersion,
		PkScript: voteScript,
		CoinType: cointype.CoinTypeVAR, // Votes are VAR-only
	})

	// All remaining outputs pay to the output destinations and amounts tagged
	// by the ticket purchase. First, handle VAR rewards (stake return + subsidy + VAR fees).
	for i, hash160 := range ticketHash160s {
		var addr stdaddr.StakeAddress
		var err error
		if ticketPayKinds[i] { // P2SH
			addr, err = stdaddr.NewAddressScriptHashV0FromHash(hash160, params)
		} else { // P2PKH
			addr, err = stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(hash160, params)
		}
		if err != nil {
			return nil, err
		}
		vers, script := addr.PayVoteCommitmentScript()
		vote.AddTxOut(&wire.TxOut{
			Value:    voteRewardValues[i],
			Version:  vers,
			PkScript: script,
			CoinType: cointype.CoinTypeVAR, // VAR rewards (stake + subsidy + VAR fees)
		})
	}

	// Note: Non-VAR (SKA) coin type fee rewards are distributed through separate
	// SSFee transactions created by the mining code, not through vote outputs.
	// Votes only contain VAR rewards (stake return + subsidy + VAR fees).
	// See mond/internal/mining/mining.go createSSFeeTx() for SKA fee distribution.

	// Add SSFee consolidation address output (REQUIRED)
	// This output tells miners where to send batched SSFee UTXOs for this voter.
	// Output format: OP_RETURN OP_DATA_22 "SC" <20-byte hash160>
	consolidationOut, err := stake.CreateSSFeeConsolidationOutput(consolidationHash160)
	if err != nil {
		return nil, err
	}
	vote.AddTxOut(consolidationOut)

	return vote, nil
}
