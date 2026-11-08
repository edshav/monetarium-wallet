// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2024 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package jsonrpc

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/monetarium/monetarium-wallet/chain"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/p2p"
	"github.com/monetarium/monetarium-wallet/rpc/client/mond"
	"github.com/monetarium/monetarium-wallet/rpc/jsonrpc/types"
	"github.com/monetarium/monetarium-wallet/spv"
	"github.com/monetarium/monetarium-wallet/version"
	"github.com/monetarium/monetarium-wallet/wallet"
	"github.com/monetarium/monetarium-wallet/wallet/txauthor"
	"github.com/monetarium/monetarium-wallet/wallet/txrules"
	"github.com/monetarium/monetarium-wallet/wallet/txsizes"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
	"github.com/monetarium/monetarium-node/blockchain/stake"
	blockchain "github.com/monetarium/monetarium-node/blockchain/standalone"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/crypto/rand"
	"github.com/monetarium/monetarium-node/dcrec"
	"github.com/monetarium/monetarium-node/dcrec/secp256k1"
	"github.com/monetarium/monetarium-node/dcrec/secp256k1/ecdsa"
	"github.com/monetarium/monetarium-node/dcrjson"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/hdkeychain"
	mondtypes "github.com/monetarium/monetarium-node/rpc/jsonrpc/types"
	"github.com/monetarium/monetarium-node/txscript"
	"github.com/monetarium/monetarium-node/txscript/sign"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/txscript/stdscript"
	"github.com/monetarium/monetarium-node/wire"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/sync/errgroup"
)

// Dual-coin constants
const (
	// CoinTypeVAR represents the VAR coin type (mined coins)
	CoinTypeVAR = uint8(cointype.CoinTypeVAR)
	// CoinTypeMaxSKA represents the maximum valid SKA coin type
	CoinTypeMaxSKA = uint8(cointype.CoinTypeMax)
)

// API version constants
const (
	jsonrpcSemverString = "10.0.0"
	jsonrpcSemverMajor  = 10
	jsonrpcSemverMinor  = 0
	jsonrpcSemverPatch  = 0
)

const (
	// sstxCommitmentString is the string to insert when a verbose
	// transaction output's pkscript type is a ticket commitment.
	sstxCommitmentString = "sstxcommitment"

	// The assumed output script version is defined to assist with refactoring
	// to use actual script versions.
	scriptVersionAssumed = 0

	// redeemMultiSigOutsMax bounds the number of multisig outputs a single
	// redeemmultisigouts call will process. Each iteration builds and signs
	// a redemption transaction, so an unbounded address list would let an
	// authenticated operator stall the RPC server. When the cap is hit, the
	// result's Truncated flag is set so callers know to paginate by spending
	// the returned redemptions and calling again.
	redeemMultiSigOutsMax uint32 = 256
)

// resolveRedeemMultiSigOutsCap clamps a caller-supplied cmd.Number against
// the server-side redeemMultiSigOutsMax. A nil or zero cmd.Number is treated
// as "use the default cap" — never as "return zero results" — so callers
// that omit the field don't get a silently empty response.
//
// Whether the result was truncated is computed downstream by
// redeemMultiSigOutsCollect after coin-type filtering, since pre-filter
// counts overstate truncation in mixed-coin-type wallets.
func resolveRedeemMultiSigOutsCap(reqNumber *int) (limit uint32) {
	limit = redeemMultiSigOutsMax
	if reqNumber != nil && *reqNumber > 0 && uint32(*reqNumber) < limit {
		limit = uint32(*reqNumber)
	}
	return
}

// validateCoinType validates a coin type parameter and returns an appropriate error
func validateCoinType(coinType cointype.CoinType) error {
	if !coinType.IsValid() {
		return rpcErrorf(dcrjson.ErrRPCInvalidParameter, "cointype must be between %d (VAR) and %d (SKA)", CoinTypeVAR, CoinTypeMaxSKA)
	}
	return nil
}

// validateCoinTypeConfigured combines validateCoinType with a chain-config
// presence check: an SKA coin type that passes validateCoinType still has to
// be configured in chainParams.SKACoins for the active network. Without the
// presence check, a caller-supplied SKA coin type that is in range but not
// configured would silently fall through to coin-type-agnostic codepaths and
// produce confusing downstream errors. VAR (0) is always valid and present.
func validateCoinTypeConfigured(params *chaincfg.Params, ct cointype.CoinType) error {
	if err := validateCoinType(ct); err != nil {
		return err
	}
	if ct.IsSKA() {
		if params == nil || params.SKACoins == nil || params.SKACoins[ct] == nil {
			return rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"SKA coin type %d is not configured for this network", ct)
		}
	}
	return nil
}

// skaCreditLookup is the wallet UTXO lookup used by populateSKAValueIn. The
// real implementation is wallet.UnspentOutput; tests inject a stub.
type skaCreditLookup func(ctx context.Context, op wire.OutPoint) (*udb.Credit, error)

// populateSKAValueIn fills tx.TxIn[i].SKAValueIn for SKA inputs that arrived
// with SKAValueIn=nil before the tx is handed to wallet.SignTransaction. Pin
// for the HIGH-2 finding from the 2026-05-04 review.
//
// The wire format carries SKAValueIn through deserialize/serialize for txs
// built by this wallet, so the common case is a no-op. This function defends
// against a third-party tool that builds wire.MsgTx from primitives (only
// PreviousOutPoint + ValueIn + SignatureScript — the upstream Decred wallet shape)
// without the V13 wire-format extension fields, which would otherwise
// produce an SKA tx with SKAValueIn=nil; the wallet would happily sign it
// and the node would reject the broadcast with a fraud-proof error.
//
// Detection: a transaction's outputs cannot mix coin types (consensus
// invariant; defense-in-depth check is in sendRawTransaction). The tx coin
// type is therefore the first output's CoinType. VAR transactions are a
// no-op.
//
// Population priority per input:
//  1. Caller-supplied decimal-coin string in callerSKA (parsed against the
//     SKA coin's atomsPerCoin via coinsToAtomsBig).
//  2. Wallet UTXO set via the lookup callback (credit.SKAAmount).
//  3. Refuse with ErrRPCInvalidParameter — the operator must either supply
//     skaValueIn on the RawTxInput or sign on a wallet that owns the prevout.
func populateSKAValueIn(ctx context.Context, tx *wire.MsgTx, params *chaincfg.Params,
	callerSKA map[wire.OutPoint]string, lookup skaCreditLookup) error {

	txCoinType := txrules.GetCoinTypeFromOutputs(tx.TxOut)
	if !txCoinType.IsSKA() {
		return nil
	}
	atomsPerCoin := getAtomsPerCoin(params, txCoinType)
	for i, txIn := range tx.TxIn {
		op := txIn.PreviousOutPoint
		if txIn.SKAValueIn != nil && txIn.SKAValueIn.Sign() > 0 {
			// On-wire SKAValueIn must satisfy the chain's MaxSupply bound
			// regardless of source. Without this check, a peer-built tx with
			// an out-of-bound SKAValueIn would reach signing; the node would
			// reject the broadcast, but a non-broadcast caller (emission-tx
			// pre-flight, multisig coordinator) would lose the magnitude
			// guarantee. The contract is uniform: the bound is a property
			// of the chain, not the source of the value.
			if err := validateSKAAtomMagnitude(params, txCoinType, txIn.SKAValueIn); err != nil {
				return rpcErrorf(dcrjson.ErrRPCInvalidParameter,
					"skaValueIn for input %d (%s:%d): %v",
					i, op.Hash, op.Index, err)
			}
			// On-wire SKAValueIn already populated. If the JSON RPC caller
			// also supplied a skaValueIn, validate it (parse error / non-
			// positive / out-of-magnitude all reject the call) and prefer
			// the caller value when it differs — caller-priority is the
			// wallet's documented contract; see TestPopulateSKAValueIn.
			// The override is logged at Warn so operator logs surface it.
			if s, ok := callerSKA[op]; ok {
				atoms, err := coinsToAtomsBig(s, atomsPerCoin)
				if err != nil {
					return rpcErrorf(dcrjson.ErrRPCInvalidParameter,
						"skaValueIn for input %d (%s:%d) is not a valid "+
							"decimal coin string for coin type %d: %v",
						i, op.Hash, op.Index, txCoinType, err)
				}
				if atoms.Sign() <= 0 {
					return rpcErrorf(dcrjson.ErrRPCInvalidParameter,
						"skaValueIn for input %d (%s:%d) must be positive",
						i, op.Hash, op.Index)
				}
				if err := validateSKAAtomMagnitude(params, txCoinType, atoms); err != nil {
					return rpcErrorf(dcrjson.ErrRPCInvalidParameter,
						"skaValueIn for input %d (%s:%d): %v",
						i, op.Hash, op.Index, err)
				}
				if atoms.Cmp(txIn.SKAValueIn) != 0 {
					log.Warnf("populateSKAValueIn: caller-supplied skaValueIn=%s overrides on-wire %s for input %d (%s:%d)",
						atoms.String(), txIn.SKAValueIn.String(), i, op.Hash, op.Index)
					txIn.ValueIn = 0
					txIn.SKAValueIn = atoms
				}
			}
			continue
		}
		// 1. Caller-supplied decimal coin string. The caller value
		// intentionally takes priority over the wallet's UTXO lookup so
		// that operators can correct a stale wallet view (e.g. during
		// reorgs or resync); this is exercised by
		// TestPopulateSKAValueIn/"caller value beats wallet lookup".
		if s, ok := callerSKA[op]; ok {
			atoms, err := coinsToAtomsBig(s, atomsPerCoin)
			if err != nil {
				return rpcErrorf(dcrjson.ErrRPCInvalidParameter,
					"skaValueIn for input %d (%s:%d) is not a valid "+
						"decimal coin string for coin type %d: %v",
					i, op.Hash, op.Index, txCoinType, err)
			}
			if atoms.Sign() <= 0 {
				return rpcErrorf(dcrjson.ErrRPCInvalidParameter,
					"skaValueIn for input %d (%s:%d) must be positive",
					i, op.Hash, op.Index)
			}
			if err := validateSKAAtomMagnitude(params, txCoinType, atoms); err != nil {
				return rpcErrorf(dcrjson.ErrRPCInvalidParameter,
					"skaValueIn for input %d (%s:%d): %v",
					i, op.Hash, op.Index, err)
			}
			txIn.ValueIn = 0
			txIn.SKAValueIn = atoms
			continue
		}
		// 2. Wallet UTXO set.
		if lookup != nil {
			credit, err := lookup(ctx, op)
			if err == nil && credit != nil {
				if credit.CoinType != txCoinType {
					return rpcErrorf(dcrjson.ErrRPCInvalidParameter,
						"input %d (%s:%d) is coin type %d but transaction "+
							"outputs are coin type %d",
						i, op.Hash, op.Index, credit.CoinType, txCoinType)
				}
				ska := credit.SKAAmount.BigInt()
				if ska == nil || ska.Sign() <= 0 {
					return rpcErrorf(dcrjson.ErrRPCInvalidParameter,
						"input %d (%s:%d) has no SKA value recorded in "+
							"wallet UTXO set", i, op.Hash, op.Index)
				}
				// Defense-in-depth: a corrupted credit record carrying more
				// atoms than the chain's MaxSupply must not reach signing.
				// The on-wire and caller-supplied branches above already
				// enforce this; the lookup branch is the third source and
				// the contract is uniform — see the on-wire comment.
				if err := validateSKAAtomMagnitude(params, txCoinType, ska); err != nil {
					return rpcErrorf(dcrjson.ErrRPCInvalidParameter,
						"input %d (%s:%d): %v", i, op.Hash, op.Index, err)
				}
				txIn.ValueIn = 0
				txIn.SKAValueIn = new(big.Int).Set(ska)
				continue
			}
		}
		// 3. No source available — refuse with an actionable error.
		return rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"SKA input %d (%s:%d) has no SKAValueIn; provide it via "+
				"the skaValueIn field on RawTxInput, or sign on a "+
				"wallet that owns the prevout",
			i, op.Hash, op.Index)
	}
	return nil
}

// validateSKAAtomMagnitude rejects SKA atom values that exceed the configured
// MaxSupply for the given coin type. Used by populateSKAValueIn to bound
// caller-supplied skaValueIn before the wallet commits expensive work
// (signing, validation) on behalf of an authenticated RPC client. A no-op for
// VAR or for unknown coin types (the latter is caught earlier by
// validateCoinType / GetCoinTypeFromOutputs).
func validateSKAAtomMagnitude(params *chaincfg.Params, ct cointype.CoinType, atoms *big.Int) error {
	if atoms == nil || !ct.IsSKA() || params == nil {
		return nil
	}
	cfg, ok := params.SKACoins[ct]
	if !ok || cfg == nil || cfg.MaxSupply == nil {
		return nil
	}
	if atoms.Cmp(cfg.MaxSupply) > 0 {
		return fmt.Errorf("value %s atoms exceeds MaxSupply %s for coin type %d",
			atoms.String(), cfg.MaxSupply.String(), ct)
	}
	return nil
}

// getAtomsPerCoin returns AtomsPerCoin for the given coin type from chain params.
// VAR uses 1e8, SKA uses configured value (typically 1e18). Always returns a
// freshly-allocated *big.Int — never the underlying chain-params pointer or
// the package-level cointype.AtomsPerSKACoin — so callers cannot accidentally
// mutate shared state through the returned value.
func getAtomsPerCoin(chainParams *chaincfg.Params, ct cointype.CoinType) *big.Int {
	if ct.IsVAR() {
		return big.NewInt(cointype.AtomsPerVAR)
	}
	if config, ok := chainParams.SKACoins[ct]; ok && config.AtomsPerCoin != nil {
		return new(big.Int).Set(config.AtomsPerCoin)
	}
	return cointype.GetAtomsPerSKACoin()
}

// atomsToDecimalString converts an int64 atom count to a decimal coin string
// against the supplied atomsPerCoin. Used by VAR result renderers so the JSON
// wire format is a uniform decimal string for both VAR and SKA.
func atomsToDecimalString(atoms int64, atomsPerCoin *big.Int) string {
	if atomsPerCoin == nil || atomsPerCoin.Sign() == 0 {
		atomsPerCoin = big.NewInt(cointype.AtomsPerVAR)
	}
	return cointype.AtomsToDecimalString(big.NewInt(atoms), atomsPerCoin)
}

// varAtomsToDecimalString is a shorthand for VAR amounts (1e8 atoms per coin).
func varAtomsToDecimalString(amt dcrutil.Amount) string {
	return cointype.AtomsToDecimalString(big.NewInt(int64(amt)), big.NewInt(cointype.AtomsPerVAR))
}

// p2shSKAValueInStr returns the SKA value of a P2SHMultiSigOutput as a decimal-
// coin string suitable for RawTxInput.SKAValueIn, or nil for VAR outputs.
// Pulled out as a helper so redeemMultiSigOut can pass the value through the
// synthesized RawTxInput explicitly rather than relying on SKAValueIn surviving
// the wire round-trip — and so this small piece of logic is unit-testable
// without a full wallet mock.
func p2shSKAValueInStr(p2sh *wallet.P2SHMultiSigOutput, ct cointype.CoinType, params *chaincfg.Params) *string {
	if p2sh == nil || !ct.IsSKA() {
		return nil
	}
	atomsPerCoin := getAtomsPerCoin(params, ct)
	s := cointype.AtomsToDecimalString(p2sh.SKAOutputAmount.BigInt(), atomsPerCoin)
	return &s
}

// coinsToAtomsBig converts a coin amount (as string or float64) to atoms using big.Int.
// For SKA amounts, this preserves full precision. The amount parameter can be:
// - string: "123.456789012345678901" (full precision for SKA)
// - float64: 123.456 (limited precision, mainly for VAR)
//
// Negative amounts and fractional parts longer than the configured precision
// are rejected — callers must validate before calling and never attempt to
// represent debits as negative values.
//
// Precondition: atomsPerCoin must be a positive power of ten. The decimal-place
// count is inferred from len(atomsPerCoin.String())-1, which is only equivalent
// to log10 under that invariant — a non-pow10 value (e.g. 99999999) would
// yield a fractional-precision count off by one. validateSKAChainParams in
// wallet/wallet.go enforces this at wallet Open and rejects misconfigured
// chain parameters with an actionable error, so by the time RPC handlers call
// this function the invariant is guaranteed for the active chain.
func coinsToAtomsBig(amount interface{}, atomsPerCoin *big.Int) (*big.Int, error) {
	if atomsPerCoin == nil || atomsPerCoin.Sign() == 0 {
		atomsPerCoin = big.NewInt(cointype.AtomsPerVAR)
	}

	// Defense in depth: validateSKAChainParams enforces that all SKA
	// AtomsPerCoin values are exact powers of 10 at wallet open. The
	// `decimals := len(atomsPerCoin.String())-1` shortcut below is only
	// equivalent to log10(atomsPerCoin) under that invariant. A future
	// call site that bypasses wallet-open validation must not silently
	// corrupt the decimal-string ↔ atoms conversion. Reject negatives too —
	// they would make the loop spin or produce a nonsensical scale.
	if atomsPerCoin.Sign() < 0 {
		return nil, fmt.Errorf("atomsPerCoin must be positive; got %s", atomsPerCoin.String())
	}
	if !wallet.IsPowerOf10(atomsPerCoin) {
		return nil, fmt.Errorf("atomsPerCoin must be a power of 10; got %s", atomsPerCoin.String())
	}

	var amountStr string
	switch v := amount.(type) {
	case string:
		amountStr = v
	case float64:
		// float64 has ~15 significant digits; reject for coin types with
		// more decimal places (e.g. SKA with 18) to prevent silent precision loss.
		decimals := len(atomsPerCoin.String()) - 1
		if decimals > 15 {
			return nil, fmt.Errorf("float64 amounts not supported for coin types with more than 15 decimal places; use string")
		}
		amountStr = strconv.FormatFloat(v, 'f', -1, 64)
	case int64:
		amountStr = strconv.FormatInt(v, 10)
	case int:
		amountStr = strconv.Itoa(v)
	default:
		return nil, fmt.Errorf("unsupported amount type: %T", amount)
	}

	if amountStr == "" {
		return nil, fmt.Errorf("amount must not be empty")
	}

	// Cap the input length so an authenticated RPC caller cannot coerce the
	// wallet into parsing a multi-megabyte decimal into a multi-megabyte
	// big.Int. 100 chars is generous: 60 integer digits + '.' + 18 fractional
	// digits + slack covers any legitimate amount under any configured
	// AtomsPerCoin. Same DoS rationale as the salt/N/r/p caps in
	// decryptPrivateKeyWithPassphrase.
	const maxAmountStrLen = 100
	if len(amountStr) > maxAmountStrLen {
		return nil, fmt.Errorf("amount string too long (%d chars, max %d)", len(amountStr), maxAmountStrLen)
	}

	// Parse the decimal amount string
	// Split on decimal point
	parts := strings.Split(amountStr, ".")
	if len(parts) > 2 {
		return nil, fmt.Errorf("invalid amount format: %s", amountStr)
	}

	// Get the decimal places from atomsPerCoin (e.g., 1e18 = 18 decimals)
	decimals := len(atomsPerCoin.String()) - 1

	var intPart, fracPart string
	intPart = parts[0]
	if len(parts) == 2 {
		fracPart = parts[1]
	}

	if strings.HasPrefix(intPart, "-") {
		return nil, fmt.Errorf("amount must be non-negative: %s", amountStr)
	}
	// big.Int.SetString accepts a leading '+', and the empty integer part
	// produced by inputs like "." or ".5" parses as 0 after fractional
	// padding. Both violate the decimal-coin-string contract — reject them
	// here so silently-zero or sign-prefixed amounts cannot reach the
	// downstream Sign() checks.
	if strings.HasPrefix(intPart, "+") {
		return nil, fmt.Errorf("amount must not have a leading '+': %s", amountStr)
	}
	if intPart == "" {
		return nil, fmt.Errorf("invalid amount format (missing integer part): %s", amountStr)
	}

	if len(fracPart) > decimals {
		return nil, fmt.Errorf("amount has more than %d fractional digits: %s", decimals, amountStr)
	}
	if len(fracPart) < decimals {
		fracPart += strings.Repeat("0", decimals-len(fracPart))
	}

	atomsStr := intPart + fracPart

	atoms, ok := new(big.Int).SetString(atomsStr, 10)
	if !ok {
		return nil, fmt.Errorf("failed to parse amount: %s", amountStr)
	}

	return atoms, nil
}

// atomsToCoinsBig converts atoms (big.Int) to coin string with full precision.
// This is the inverse of coinsToAtomsBig.
func atomsToCoinsBig(atoms *big.Int, atomsPerCoin *big.Int) string {
	if atoms == nil || atoms.Sign() == 0 {
		return "0"
	}
	if atomsPerCoin == nil || atomsPerCoin.Sign() == 0 {
		atomsPerCoin = big.NewInt(cointype.AtomsPerVAR)
	}

	// Calculate decimal places from atomsPerCoin (e.g., 1e18 = 18 decimals)
	decimals := len(atomsPerCoin.String()) - 1

	// Get string representation of atoms
	atomsStr := atoms.String()

	// Handle negative amounts
	negative := false
	if atomsStr[0] == '-' {
		negative = true
		atomsStr = atomsStr[1:]
	}

	var result string
	if len(atomsStr) <= decimals {
		// Pad with leading zeros: "0.000...XXX"
		result = "0." + strings.Repeat("0", decimals-len(atomsStr)) + atomsStr
	} else {
		// Insert decimal point at the right position
		insertPos := len(atomsStr) - decimals
		result = atomsStr[:insertPos] + "." + atomsStr[insertPos:]
	}

	// Trim trailing zeros after decimal, but keep at least one decimal place
	if strings.Contains(result, ".") {
		result = strings.TrimRight(result, "0")
		if strings.HasSuffix(result, ".") {
			result += "0"
		}
	}

	if negative {
		result = "-" + result
	}

	return result
}

// skaAmountToAtomsString returns the SKA amount as a raw atom string (no decimals).
// Use this when you need the exact atom count for calculations.
func skaAmountToAtomsString(amount cointype.SKAAmount) string {
	if amount.IsZero() {
		return ""
	}
	return amount.String()
}

// confirms returns the number of confirmations for a transaction in a block at
// height txHeight (or -1 for an unconfirmed tx) given the chain height
// curHeight.
func confirms(txHeight, curHeight int32) int32 {
	switch {
	case txHeight == -1, txHeight > curHeight:
		return 0
	default:
		return curHeight - txHeight + 1
	}
}

// the registered rpc handlers
var handlers = map[string]handler{
	"abandontransaction":               {fn: (*Server).abandonTransaction},
	"accountaddressindex":              {fn: (*Server).accountAddressIndex},
	"accountsyncaddressindex":          {fn: (*Server).accountSyncAddressIndex},
	"accountunlocked":                  {fn: (*Server).accountUnlocked},
	"addmultisigaddress":               {fn: (*Server).addMultiSigAddress},
	"addtransaction":                   {fn: (*Server).addTransaction},
	"auditreuse":                       {fn: (*Server).auditReuse},
	"consolidate":                      {fn: (*Server).consolidate},
	"createmultisig":                   {fn: (*Server).createMultiSig},
	"createnewaccount":                 {fn: (*Server).createNewAccount},
	"createauthorizedemission":         {fn: (*Server).createAuthorizedEmission},
	"createrawtransaction":             {fn: (*Server).createRawTransaction},
	"generateemissionkey":              {fn: (*Server).generateEmissionKey},
	"importemissionkey":                {fn: (*Server).importEmissionKey},
	"createsignature":                  {fn: (*Server).createSignature},
	"debuglevel":                       {fn: (*Server).debugLevel},
	"disapprovepercent":                {fn: (*Server).disapprovePercent},
	"discoverusage":                    {fn: (*Server).discoverUsage},
	"dumpprivkey":                      {fn: (*Server).dumpPrivKey},
	"fundrawtransaction":               {fn: (*Server).fundRawTransaction},
	"getaccount":                       {fn: (*Server).getAccount},
	"getaccountaddress":                {fn: (*Server).getAccountAddress},
	"getaddressesbyaccount":            {fn: (*Server).getAddressesByAccount},
	"getbalance":                       {fn: (*Server).getBalance},
	"getcoinbalance":                   {fn: (*Server).getCoinBalance},
	"getbestblock":                     {fn: (*Server).getBestBlock},
	"getbestblockhash":                 {fn: (*Server).getBestBlockHash},
	"getblockcount":                    {fn: (*Server).getBlockCount},
	"getblockhash":                     {fn: (*Server).getBlockHash},
	"getblockheader":                   {fn: (*Server).getBlockHeader},
	"getblock":                         {fn: (*Server).getBlock},
	"getcoinjoinsbyacct":               {fn: (*Server).getcoinjoinsbyacct},
	"getcurrentnet":                    {fn: (*Server).getCurrentNet},
	"getinfo":                          {fn: (*Server).getInfo},
	"getmasterpubkey":                  {fn: (*Server).getMasterPubkey},
	"getmultisigoutinfo":               {fn: (*Server).getMultisigOutInfo},
	"getnewaddress":                    {fn: (*Server).getNewAddress},
	"getpeerinfo":                      {fn: (*Server).getPeerInfo},
	"getrawchangeaddress":              {fn: (*Server).getRawChangeAddress},
	"getreceivedbyaccount":             {fn: (*Server).getReceivedByAccount},
	"getreceivedbyaddress":             {fn: (*Server).getReceivedByAddress},
	"getstakeinfo":                     {fn: (*Server).getStakeInfo},
	"gettickets":                       {fn: (*Server).getTickets},
	"gettransaction":                   {fn: (*Server).getTransaction},
	"gettxout":                         {fn: (*Server).getTxOut},
	"getunconfirmedbalance":            {fn: (*Server).getUnconfirmedBalance},
	"getvotechoices":                   {fn: (*Server).getVoteChoices},
	"getvotefeeconsolidationaddress":   {fn: (*Server).getVoteFeeConsolidationAddress},
	"getwalletfee":                     {fn: (*Server).getWalletFee},
	"clearvotefeeconsolidationaddress": {fn: (*Server).clearVoteFeeConsolidationAddress},
	"help":                             {fn: (*Server).help},
	"getcfilterv2":                     {fn: (*Server).getCFilterV2},
	"importcfiltersv2":                 {fn: (*Server).importCFiltersV2},
	"importprivkey":                    {fn: (*Server).importPrivKey},
	"importpubkey":                     {fn: (*Server).importPubKey},
	"importscript":                     {fn: (*Server).importScript},
	"importxpub":                       {fn: (*Server).importXpub},
	"listaccounts":                     {fn: (*Server).listAccounts},
	"listaddresstransactions":          {fn: (*Server).listAddressTransactions},
	"listcointypes":                    {fn: (*Server).listCoinTypes},
	"listalltransactions":              {fn: (*Server).listAllTransactions},
	"listlockunspent":                  {fn: (*Server).listLockUnspent},
	"listreceivedbyaccount":            {fn: (*Server).listReceivedByAccount},
	"listreceivedbyaddress":            {fn: (*Server).listReceivedByAddress},
	"listsinceblock":                   {fn: (*Server).listSinceBlock},
	"listtransactions":                 {fn: (*Server).listTransactions},
	"listunspent":                      {fn: (*Server).listUnspent},
	"lockaccount":                      {fn: (*Server).lockAccount},
	"lockunspent":                      {fn: (*Server).lockUnspent},
	"mixaccount":                       {fn: (*Server).mixAccount},
	"mixoutput":                        {fn: (*Server).mixOutput},
	"purchaseticket":                   {fn: (*Server).purchaseTicket},
	"processunmanagedticket":           {fn: (*Server).processUnmanagedTicket},
	"redeemmultisigout":                {fn: (*Server).redeemMultiSigOut},
	"redeemmultisigouts":               {fn: (*Server).redeemMultiSigOuts},
	"renameaccount":                    {fn: (*Server).renameAccount},
	"rescanwallet":                     {fn: (*Server).rescanWallet},
	"sendfrom":                         {fn: (*Server).sendFrom},
	"sendfromtreasury":                 {fn: (*Server).sendFromTreasury},
	"sendmany":                         {fn: (*Server).sendMany},
	"sendrawtransaction":               {fn: (*Server).sendRawTransaction},
	"sendtoaddress":                    {fn: (*Server).sendToAddress},
	"sendtomultisig":                   {fn: (*Server).sendToMultiSig},
	"sendtotreasury":                   {fn: (*Server).sendToTreasury},
	"sendtoburn":                       {fn: (*Server).sendToBurn},
	"setaccountpassphrase":             {fn: (*Server).setAccountPassphrase},
	"setdisapprovepercent":             {fn: (*Server).setDisapprovePercent},
	"settreasurypolicy":                {fn: (*Server).setTreasuryPolicy},
	"settspendpolicy":                  {fn: (*Server).setTSpendPolicy},
	"settxfee":                         {fn: (*Server).setTxFee},
	"setvotechoice":                    {fn: (*Server).setVoteChoice},
	"setvotefeeconsolidationaddress":   {fn: (*Server).setVoteFeeConsolidationAddress},
	"signmessage":                      {fn: (*Server).signMessage},
	"signrawtransaction":               {fn: (*Server).signRawTransaction},
	"signrawtransactions":              {fn: (*Server).signRawTransactions},
	"spendoutputs":                     {fn: (*Server).spendOutputs},
	"sweepaccount":                     {fn: (*Server).sweepAccount},
	"syncstatus":                       {fn: (*Server).syncStatus},
	"ticketinfo":                       {fn: (*Server).ticketInfo},
	"treasurypolicy":                   {fn: (*Server).treasuryPolicy},
	"tspendpolicy":                     {fn: (*Server).tspendPolicy},
	"unlockaccount":                    {fn: (*Server).unlockAccount},
	"validateaddress":                  {fn: (*Server).validateAddress},
	"verifymessage":                    {fn: (*Server).verifyMessage},
	"version":                          {fn: (*Server).version},
	"walletinfo":                       {fn: (*Server).walletInfo},
	"walletislocked":                   {fn: (*Server).walletIsLocked},
	"walletlock":                       {fn: (*Server).walletLock},
	"walletpassphrase":                 {fn: (*Server).walletPassphrase},
	"walletpassphrasechange":           {fn: (*Server).walletPassphraseChange},
	"walletpubpassphrasechange":        {fn: (*Server).walletPubPassphraseChange},

	// Unimplemented/unsupported RPCs which may be found in other
	// cryptocurrency wallets.
	"backupwallet":         {fn: unimplemented, noHelp: true},
	"getwalletinfo":        {fn: unimplemented, noHelp: true},
	"importwallet":         {fn: unimplemented, noHelp: true},
	"listaddressgroupings": {fn: unimplemented, noHelp: true},
	"dumpwallet":           {fn: unsupported, noHelp: true},
	"encryptwallet":        {fn: unsupported, noHelp: true},
	"move":                 {fn: unsupported, noHelp: true},
	"setaccount":           {fn: unsupported, noHelp: true},
}

// unimplemented handles an unimplemented RPC request with the
// appropriate error.
func unimplemented(*Server, context.Context, any) (any, error) {
	return nil, &dcrjson.RPCError{
		Code:    dcrjson.ErrRPCUnimplemented,
		Message: "Method unimplemented",
	}
}

// unsupported handles a standard bitcoind RPC request which is
// unsupported by upstream Decred wallet due to design differences.
func unsupported(*Server, context.Context, any) (any, error) {
	return nil, &dcrjson.RPCError{
		Code:    -1,
		Message: "Request unsupported by monw",
	}
}

// lazyHandler is a closure over a requestHandler or passthrough request with
// the RPC server's wallet and chain server variables as part of the closure
// context.
type lazyHandler func() (any, *dcrjson.RPCError)

// lazyApplyHandler looks up the best request handler func for the method,
// returning a closure that will execute it with the (required) wallet and
// (optional) consensus RPC server.  If no handlers are found and the
// chainClient is not nil, the returned handler performs RPC passthrough.
func lazyApplyHandler(s *Server, ctx context.Context, request *dcrjson.Request) lazyHandler {
	handlerData, ok := handlers[request.Method]
	if !ok {
		return func() (any, *dcrjson.RPCError) {
			// Attempt RPC passthrough if possible
			n, ok := s.walletLoader.NetworkBackend()
			if !ok {
				return nil, errRPCClientNotConnected
			}
			chainSyncer, ok := n.(*chain.Syncer)
			if !ok {
				return nil, rpcErrorf(dcrjson.ErrRPCClientNotConnected, "RPC passthrough requires mond RPC synchronization")
			}
			var resp json.RawMessage
			var params = make([]any, len(request.Params))
			for i := range request.Params {
				params[i] = request.Params[i]
			}
			err := chainSyncer.RPC().Call(ctx, request.Method, &resp, params...)
			if ctx.Err() != nil {
				log.Warnf("Canceled RPC method %v invoked by %v: %v", request.Method, remoteAddr(ctx), err)
				return nil, &dcrjson.RPCError{
					Code:    dcrjson.ErrRPCMisc,
					Message: ctx.Err().Error(),
				}
			}
			if err != nil {
				return nil, convertError(err)
			}
			return resp, nil
		}
	}

	return func() (any, *dcrjson.RPCError) {
		params, err := dcrjson.ParseParams(types.Method(request.Method), request.Params)
		if err != nil {
			return nil, dcrjson.ErrRPCInvalidRequest
		}

		defer func() {
			if err := ctx.Err(); err != nil {
				log.Warnf("Canceled RPC method %v invoked by %v: %v", request.Method, remoteAddr(ctx), err)
			}
		}()
		resp, err := handlerData.fn(s, ctx, params)
		if err != nil {
			return nil, convertError(err)
		}
		return resp, nil
	}
}

// makeResponse makes the JSON-RPC response struct for the result and error
// returned by a requestHandler.  The returned response is not ready for
// marshaling and sending off to a client, but must be
func makeResponse(id, result any, err error) dcrjson.Response {
	idPtr := idPointer(id)
	if err != nil {
		return dcrjson.Response{
			ID:    idPtr,
			Error: convertError(err),
		}
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return dcrjson.Response{
			ID: idPtr,
			Error: &dcrjson.RPCError{
				Code:    dcrjson.ErrRPCInternal.Code,
				Message: "Unexpected error marshalling result",
			},
		}
	}
	return dcrjson.Response{
		ID:     idPtr,
		Result: json.RawMessage(resultBytes),
	}
}

// abandonTransaction removes an unconfirmed transaction and all dependent
// transactions from the wallet.
func (s *Server) abandonTransaction(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.AbandonTransactionCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	hash, err := chainhash.NewHashFromStr(cmd.Hash)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
	}

	err = w.AbandonTransaction(ctx, hash)
	return nil, err
}

// accountAddressIndex returns the next address index for the passed
// account and branch.
func (s *Server) accountAddressIndex(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.AccountAddressIndexCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	account, err := w.AccountNumber(ctx, cmd.Account)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAccountNotFound
		}
		return nil, err
	}

	extChild, intChild, err := w.BIP0044BranchNextIndexes(ctx, account)
	if err != nil {
		return nil, err
	}
	switch uint32(cmd.Branch) {
	case udb.ExternalBranch:
		return extChild, nil
	case udb.InternalBranch:
		return intChild, nil
	default:
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "invalid branch %v", cmd.Branch)
	}
}

// accountSyncAddressIndex synchronizes the address manager and local address
// pool for some account and branch to the passed index. If the current pool
// index is beyond the passed index, an error is returned. If the passed index
// is the same as the current pool index, nothing is returned. If the syncing
// is successful, nothing is returned.
func (s *Server) accountSyncAddressIndex(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.AccountSyncAddressIndexCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	account, err := w.AccountNumber(ctx, cmd.Account)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAccountNotFound
		}
		return nil, err
	}

	branch := uint32(cmd.Branch)
	index := uint32(cmd.Index)

	if index >= hdkeychain.HardenedKeyStart {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"child index %d exceeds the maximum child index for an account", index)
	}

	// Additional addresses need to be watched.  Since addresses are derived
	// based on the last used address, this RPC no longer changes the child
	// indexes that new addresses are derived from.
	return nil, w.SyncLastReturnedAddress(ctx, account, branch, index)
}

// walletPubKeys decodes each encoded key or address to a public key.  If the
// address is P2PKH, the wallet is queried for the public key.
func walletPubKeys(ctx context.Context, w *wallet.Wallet, keys []string) ([][]byte, error) {
	pubKeys := make([][]byte, len(keys))

	for i, key := range keys {
		addr, err := decodeAddress(key, w.ChainParams())
		if err != nil {
			return nil, err
		}
		switch addr := addr.(type) {
		case *stdaddr.AddressPubKeyEcdsaSecp256k1V0:
			pubKeys[i] = addr.SerializedPubKey()
			continue
		}

		a, err := w.KnownAddress(ctx, addr)
		if err != nil {
			if errors.Is(err, errors.NotExist) {
				return nil, errAddressNotInWallet
			}
			return nil, err
		}
		var pubKey []byte
		switch a := a.(type) {
		case wallet.PubKeyHashAddress:
			pubKey, err = a.PubKey()
			if err != nil {
				return nil, err
			}
		default:
			err = errors.New("address has no associated public key")
			return nil, rpcError(dcrjson.ErrRPCInvalidAddressOrKey, err)
		}
		pubKeys[i] = pubKey
	}

	return pubKeys, nil
}

// addMultiSigAddress handles an addmultisigaddress request by adding a
// multisig address to the given wallet.
func (s *Server) addMultiSigAddress(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.AddMultisigAddressCmd)
	// If an account is specified, ensure that is the imported account.
	if cmd.Account != nil && *cmd.Account != udb.ImportedAddrAccountName {
		return nil, errNotImportedAccount
	}

	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	pubKeyAddrs, err := walletPubKeys(ctx, w, cmd.Keys)
	if err != nil {
		return nil, err
	}
	script, err := stdscript.MultiSigScriptV0(cmd.NRequired, pubKeyAddrs...)
	if err != nil {
		return nil, err
	}

	err = w.ImportScript(ctx, script)
	if err != nil && !errors.Is(err, errors.Exist) {
		return nil, err
	}

	return stdaddr.NewAddressScriptHashV0(script, w.ChainParams())
}

func (s *Server) addTransaction(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.AddTransactionCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	blockHash, err := chainhash.NewHashFromStr(cmd.BlockHash)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
	}

	tx := new(wire.MsgTx)
	err = tx.Deserialize(hex.NewDecoder(strings.NewReader(cmd.Transaction)))
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCDeserialization, err)
	}

	err = w.AddTransaction(ctx, tx, blockHash)
	return nil, err
}

// auditReuse returns an object keying reused addresses to two or more outputs
// referencing them.
func (s *Server) auditReuse(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.AuditReuseCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	var since int32
	if cmd.Since != nil {
		since = *cmd.Since
	}

	reuse := make(map[string][]string)
	inRange := make(map[string]struct{})
	params := w.ChainParams()
	err := w.GetTransactions(ctx, func(b *wallet.Block) (bool, error) {
		for _, tx := range b.Transactions {
			// Votes and revocations are skipped because they must
			// only pay to addresses previously committed to by
			// ticket purchases, and this "address reuse" is
			// expected.
			switch tx.Type {
			case wallet.TransactionTypeVote, wallet.TransactionTypeRevocation:
				continue
			}
			for _, out := range tx.MyOutputs {
				addr := out.Address.String()
				outpoints := reuse[addr]
				outpoint := wire.OutPoint{Hash: *tx.Hash, Index: out.Index}
				reuse[addr] = append(outpoints, outpoint.String())
				if b.Header == nil || int32(b.Header.Height) >= since {
					inRange[addr] = struct{}{}
				}
			}
			if tx.Type != wallet.TransactionTypeTicketPurchase {
				continue
			}
			ticket := new(wire.MsgTx)
			err := ticket.Deserialize(bytes.NewReader(tx.Transaction))
			if err != nil {
				return false, err
			}
			for i := 1; i < len(ticket.TxOut); i += 2 { // iterate commitments
				out := ticket.TxOut[i]
				addr, err := stake.AddrFromSStxPkScrCommitment(out.PkScript, params)
				if err != nil {
					return false, err
				}
				have, err := w.HaveAddress(ctx, addr)
				if err != nil {
					return false, err
				}
				if !have {
					continue
				}
				s := addr.String()
				outpoints := reuse[s]
				outpoint := wire.OutPoint{Hash: *tx.Hash, Index: uint32(i)}
				reuse[s] = append(outpoints, outpoint.String())
				if b.Header == nil || int32(b.Header.Height) >= since {
					inRange[s] = struct{}{}
				}
			}
		}
		return false, nil
	}, nil, nil)
	if err != nil {
		return nil, err
	}
	for s, outpoints := range reuse {
		if len(outpoints) <= 1 {
			delete(reuse, s)
			continue
		}
		if _, ok := inRange[s]; !ok {
			delete(reuse, s)
		}
	}
	return reuse, nil
}

// consolidate handles a consolidate request by returning attempting to compress
// as many inputs as given and then returning the txHash and error.
func (s *Server) consolidate(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.ConsolidateCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	account := uint32(udb.DefaultAccountNum)
	var err error
	if cmd.Account != nil {
		account, err = w.AccountNumber(ctx, *cmd.Account)
		if err != nil {
			if errors.Is(err, errors.NotExist) {
				return nil, errAccountNotFound
			}
			return nil, err
		}
	}

	// Set change address if specified.
	var changeAddr stdaddr.Address
	if cmd.Address != nil {
		if *cmd.Address != "" {
			addr, err := decodeAddress(*cmd.Address, w.ChainParams())
			if err != nil {
				return nil, err
			}
			changeAddr = addr
		}
	}

	// Get coin type (default to VAR if not specified)
	ct := cointype.CoinTypeVAR
	if cmd.CoinType != nil {
		ct = cointype.CoinType(*cmd.CoinType)
		if err := validateCoinTypeConfigured(w.ChainParams(), ct); err != nil {
			return nil, err
		}
	}

	txHash, err := w.ConsolidateWithCoinType(ctx, cmd.Inputs, account, changeAddr, ct)
	if err != nil {
		return nil, err
	}

	return txHash.String(), nil
}

// createMultiSig handles an createmultisig request by returning a
// multisig address for the given inputs.
func (s *Server) createMultiSig(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.CreateMultisigCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	pubKeys, err := walletPubKeys(ctx, w, cmd.Keys)
	if err != nil {
		return nil, err
	}
	script, err := stdscript.MultiSigScriptV0(cmd.NRequired, pubKeys...)
	if err != nil {
		return nil, err
	}

	address, err := stdaddr.NewAddressScriptHashV0(script, w.ChainParams())
	if err != nil {
		return nil, err
	}

	return types.CreateMultiSigResult{
		Address:      address.String(),
		RedeemScript: hex.EncodeToString(script),
	}, nil
}

// createRawTransaction handles createrawtransaction commands.
func (s *Server) createRawTransaction(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.CreateRawTransactionCmd)

	// Validate expiry, if given.
	if cmd.Expiry != nil && *cmd.Expiry < 0 {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "Expiry out of range")
	}

	// Validate the locktime, if given.
	if cmd.LockTime != nil &&
		(*cmd.LockTime < 0 ||
			*cmd.LockTime > int64(wire.MaxTxInSequenceNum)) {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "Locktime out of range")
	}

	// Cap the output map size before allocating intermediate state. A
	// multi-megabyte map would force the wallet through proportional
	// sorted-slice + decoded-address + big.Int allocations before the
	// downstream max-tx-size check rejects the resulting tx. 500 mirrors
	// realistic standard-tx output counts.
	const maxCreateRawTxAmounts = 500
	if len(cmd.Amounts) > maxCreateRawTxAmounts {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"too many output addresses: got %d, limit %d",
			len(cmd.Amounts), maxCreateRawTxAmounts)
	}

	// Determine coin type up front so input parsing can take the correct
	// scale-aware path. Default to VAR (CoinType nil or 0). Amounts is a
	// single map[string]string for both VAR and SKA — decimal coin strings
	// preserve full SKA precision (1 SKA = 1e18 atoms) and avoid float64
	// round-trip loss for VAR amounts above ~9e7 VAR.
	ct := cointype.CoinTypeVAR
	if cmd.CoinType != nil {
		ct = cointype.CoinType(*cmd.CoinType)
	}
	varAtomsPerCoin := big.NewInt(cointype.AtomsPerVAR)

	// Add all transaction inputs to a new transaction after performing
	// some validity checks. For VAR inputs, prefer cmd.InputAmounts[i]
	// (decimal coin string, lossless) when supplied, otherwise fall back to
	// the legacy float64 input.Amount — float64 round-trips lose precision
	// for VAR values above ~9e7 VAR. SKA inputs ignore the int64/float64
	// value field entirely; SKAValueIn is populated from the wallet's UTXO
	// set further below.
	var inputAmounts []string
	if cmd.InputAmounts != nil {
		inputAmounts = *cmd.InputAmounts
	}
	mtx := wire.NewMsgTx()
	for i, input := range cmd.Inputs {
		txHash, err := chainhash.NewHashFromStr(input.Txid)
		if err != nil {
			return nil, rpcError(dcrjson.ErrRPCInvalidParameter, err)
		}

		switch input.Tree {
		case wire.TxTreeRegular, wire.TxTreeStake:
		default:
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"Tx tree must be regular or stake")
		}

		var valueIn int64
		if !ct.IsSKA() {
			if i < len(inputAmounts) && inputAmounts[i] != "" {
				atoms, err := coinsToAtomsBig(inputAmounts[i], varAtomsPerCoin)
				if err != nil {
					return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
						"InputAmounts[%d] %q: %v", i, inputAmounts[i], err)
				}
				if atoms.Sign() < 0 {
					return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
						"InputAmounts[%d]: negative amount not allowed", i)
				}
				if !atoms.IsInt64() {
					return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
						"InputAmounts[%d]: VAR amount overflows int64", i)
				}
				valueIn = atoms.Int64()
			} else {
				amt, err := dcrutil.NewAmount(input.Amount)
				if err != nil {
					return nil, rpcError(dcrjson.ErrRPCInvalidParameter, err)
				}
				if amt < 0 {
					return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
						"Positive input amount is required")
				}
				valueIn = int64(amt)
			}
		}

		prevOut := wire.NewOutPoint(txHash, input.Vout, input.Tree)
		txIn := wire.NewTxIn(prevOut, valueIn, nil)
		if cmd.LockTime != nil && *cmd.LockTime != 0 {
			txIn.Sequence = wire.MaxTxInSequenceNum - 1
		}
		mtx.AddTxIn(txIn)
	}
	if ct.IsSKA() {
		if len(cmd.Amounts) == 0 {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"amounts required when cointype is a SKA coin")
		}
		w, ok := s.walletLoader.LoadedWallet()
		if !ok {
			return nil, errUnloadedWallet
		}

		params := w.ChainParams()
		if params.SKACoins == nil {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"No SKA coin %d configured for this network", ct)
		}
		cfg, ok := params.SKACoins[ct]
		if !ok || cfg == nil {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"No SKA coin %d configured for this network", ct)
		}
		if !cfg.Active {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"SKA coin %d is not active", ct)
		}
		atomsPerCoin := cfg.AtomsPerCoin

		// SKA inputs require SKAValueIn populated on each TxIn — without it
		// the node rejects the tx (TxPaysHighFeesSKA et al. read SKAValueIn,
		// not the legacy Value field). Population priority per input:
		//   1. Caller-supplied decimal coin string in cmd.InputAmounts[i]
		//      (parsed via coinsToAtomsBig against the SKA coin's
		//      atomsPerCoin and magnitude-bounded by MaxSupply). This
		//      supports cross-wallet flows where the prevout is not in this
		//      wallet's UTXO set — multisig coordinators in particular.
		//   2. Wallet UTXO set via UnspentOutput (credit.SKAAmount).
		//   3. Refuse with ErrRPCInvalidParameter — the operator must
		//      either supply InputAmounts[i] for the SKA value, or sign on
		//      a wallet that owns the prevout.
		for i, txIn := range mtx.TxIn {
			if i < len(inputAmounts) && inputAmounts[i] != "" {
				atoms, err := coinsToAtomsBig(inputAmounts[i], atomsPerCoin)
				if err != nil {
					return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
						"InputAmounts[%d] %q: %v", i, inputAmounts[i], err)
				}
				if atoms.Sign() <= 0 {
					return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
						"InputAmounts[%d]: SKA amount must be positive", i)
				}
				if err := validateSKAAtomMagnitude(params, ct, atoms); err != nil {
					return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
						"InputAmounts[%d]: %v", i, err)
				}
				txIn.ValueIn = 0
				txIn.SKAValueIn = atoms
				continue
			}
			credit, err := w.UnspentOutput(ctx, txIn.PreviousOutPoint, true)
			if err != nil {
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
					"SKA input %d (%s:%d) not found in this wallet's UTXO "+
						"set; supply the SKA value via InputAmounts[%d] "+
						"to author across wallet boundaries",
					i, txIn.PreviousOutPoint.Hash, txIn.PreviousOutPoint.Index, i)
			}
			if credit.CoinType != ct {
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
					"input %d coin type %d does not match output cointype %d",
					i, credit.CoinType, ct)
			}
			ska := credit.SKAAmount.BigInt()
			if ska == nil || ska.Sign() <= 0 {
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
					"input %d has no SKA value recorded in wallet UTXO set",
					i)
			}
			txIn.ValueIn = 0
			txIn.SKAValueIn = new(big.Int).Set(ska)
		}
		// Sort destination addresses so the on-the-wire output ordering is
		// deterministic across calls. Iterating cmd.Amounts directly would
		// produce different tx hashes for identical input on every call,
		// because Go's map iteration order is randomized.
		encodedAddrs := make([]string, 0, len(cmd.Amounts))
		for encodedAddr := range cmd.Amounts {
			encodedAddrs = append(encodedAddrs, encodedAddr)
		}
		sort.Strings(encodedAddrs)
		for _, encodedAddr := range encodedAddrs {
			amountStr := cmd.Amounts[encodedAddr]
			addr, err := stdaddr.DecodeAddress(encodedAddr, s.activeNet)
			if err != nil {
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidAddressOrKey,
					"Address %q: %v", encodedAddr, err)
			}
			switch addr.(type) {
			case *stdaddr.AddressPubKeyHashEcdsaSecp256k1V0:
			case *stdaddr.AddressScriptHashV0:
			default:
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidAddressOrKey,
					"Invalid type: %T", addr)
			}
			vers, pkScript := addr.PaymentScript()
			bigAtoms, err := coinsToAtomsBig(amountStr, atomsPerCoin)
			if err != nil {
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
					"Amount %q: %v", amountStr, err)
			}
			if bigAtoms.Sign() <= 0 {
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
					"Amount must be positive: %s", amountStr)
			}
			if cfg.MaxSupply != nil && cfg.MaxSupply.Sign() > 0 &&
				bigAtoms.Cmp(cfg.MaxSupply) > 0 {
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
					"Amount %s exceeds SKA%d max supply %s", amountStr, ct, cfg.MaxSupply)
			}
			mtx.AddTxOut(&wire.TxOut{
				Value:    0,
				SKAValue: bigAtoms,
				CoinType: ct,
				Version:  vers,
				PkScript: pkScript,
			})
		}
	} else {
		// VAR path: parse decimal coin strings via coinsToAtomsBig for full
		// precision (avoids float64 round-trip loss for amounts above ~9e7 VAR).
		atomsPerCoin := big.NewInt(cointype.AtomsPerVAR)
		// Sort destination addresses so the on-the-wire output ordering is
		// deterministic across calls. See the SKA branch above for rationale.
		encodedAddrs := make([]string, 0, len(cmd.Amounts))
		for encodedAddr := range cmd.Amounts {
			encodedAddrs = append(encodedAddrs, encodedAddr)
		}
		sort.Strings(encodedAddrs)
		for _, encodedAddr := range encodedAddrs {
			amountStr := cmd.Amounts[encodedAddr]
			addr, err := stdaddr.DecodeAddress(encodedAddr, s.activeNet)
			if err != nil {
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidAddressOrKey,
					"Address %q: %v", encodedAddr, err)
			}
			switch addr.(type) {
			case *stdaddr.AddressPubKeyHashEcdsaSecp256k1V0:
			case *stdaddr.AddressScriptHashV0:
			default:
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidAddressOrKey,
					"Invalid type: %T", addr)
			}
			vers, pkScript := addr.PaymentScript()
			bigAtoms, err := coinsToAtomsBig(amountStr, atomsPerCoin)
			if err != nil {
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
					"Amount %q: %v", amountStr, err)
			}
			if bigAtoms.Sign() <= 0 {
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
					"Amount must be positive: %s", amountStr)
			}
			if !bigAtoms.IsInt64() {
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
					"VAR amount %s exceeds int64 capacity", amountStr)
			}
			atomic := dcrutil.Amount(bigAtoms.Int64())
			if atomic > dcrutil.Amount(cointype.MaxVARAmount) {
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
					"Amount outside valid range: %v", atomic)
			}
			mtx.AddTxOut(&wire.TxOut{
				Value:    int64(atomic),
				Version:  vers,
				PkScript: pkScript,
				CoinType: cointype.CoinTypeVAR,
			})
		}
	}

	// Set the Locktime, if given.
	if cmd.LockTime != nil {
		mtx.LockTime = uint32(*cmd.LockTime)
	}

	// Set the Expiry, if given.
	if cmd.Expiry != nil {
		mtx.Expiry = uint32(*cmd.Expiry)
	}

	// Return the serialized and hex-encoded transaction.
	sb := new(strings.Builder)
	err := mtx.Serialize(hex.NewEncoder(sb))
	if err != nil {
		return nil, err
	}
	return sb.String(), nil
}

// createSignature creates a signature using the private key of a wallet
// address for a transaction input script. The serialized compressed public
// key of the address is also returned.
func (s *Server) createSignature(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.CreateSignatureCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	serializedTx, err := hex.DecodeString(cmd.SerializedTransaction)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
	}

	var tx wire.MsgTx
	err = tx.Deserialize(bytes.NewReader(serializedTx))
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCDeserialization, err)
	}

	if cmd.InputIndex >= len(tx.TxIn) {
		return nil, rpcErrorf(dcrjson.ErrRPCMisc,
			"transaction input %d does not exist", cmd.InputIndex)
	}

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}

	hashType := txscript.SigHashType(cmd.HashType)
	prevOutScript, err := hex.DecodeString(cmd.PreviousPkScript)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
	}

	sig, pubkey, err := w.CreateSignature(ctx, &tx, uint32(cmd.InputIndex),
		addr, hashType, prevOutScript)
	if err != nil {
		return nil, err
	}

	return &types.CreateSignatureResult{
		Signature: hex.EncodeToString(sig),
		PublicKey: hex.EncodeToString(pubkey),
	}, nil
}

func (s *Server) debugLevel(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.DebugLevelCmd)

	if cmd.LevelSpec == "show" {
		return fmt.Sprintf("Supported subsystems %v",
			s.cfg.Loggers.Subsystems()), nil
	}

	err := s.cfg.Loggers.SetLevels(cmd.LevelSpec)
	if err != nil {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"invalid debug level %v: %v", cmd.LevelSpec, err)
	}

	return "Done.", nil
}

// disapprovePercent returns the wallets current disapprove percentage.
func (s *Server) disapprovePercent(ctx context.Context, _ any) (any, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}
	return w.DisapprovePercent(), nil
}

func (s *Server) discoverUsage(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.DiscoverUsageCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	n, ok := s.walletLoader.NetworkBackend()
	if !ok {
		return nil, errNoNetwork
	}

	startBlock := w.ChainParams().GenesisHash
	if cmd.StartBlock != nil {
		h, err := chainhash.NewHashFromStr(*cmd.StartBlock)
		if err != nil {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "startblock: %v", err)
		}
		startBlock = *h
	}
	discoverAccounts := cmd.DiscoverAccounts != nil && *cmd.DiscoverAccounts

	gapLimit := w.GapLimit()
	if cmd.GapLimit != nil {
		gapLimit = *cmd.GapLimit
	}

	err := w.DiscoverActiveAddresses(ctx, n, &startBlock, discoverAccounts, gapLimit)
	return nil, err
}

// dumpPrivKey handles a dumpprivkey request with the private key
// for a single address, or an appropriate error if the wallet
// is locked.
func (s *Server) dumpPrivKey(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.DumpPrivKeyCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}

	key, err := w.DumpWIFPrivateKey(ctx, addr)
	if err != nil {
		if errors.Is(err, errors.Locked) {
			return nil, errWalletUnlockNeeded
		}
		return nil, err
	}
	return key, nil
}

// fundRawTxFeeRateOverride returns the per-kB relay-fee override that
// fundRawTransaction passes into NewUnsignedTransaction.
//
// For VAR outputs the caller-supplied (or network-default) VAR per-kB fee is
// wrapped as a SKA-amount carrier and used as an override. For SKA outputs the
// override is zero-valued so that NewUnsignedTransaction falls through to the
// per-coin-type default via RelayFeeForCoinType. Wrapping the VAR per-kB rate
// (typically ~1e5 atoms / kB) as if it were SKA atoms underpays by the
// AtomsPerCoin ratio (commonly 1e18 vs 1e8), producing a tx that the node
// would silently reject — keep this gate. opts.FeeRate is rejected upstream
// for SKA outputs (it is a coins-as-float64 field that cannot represent SKA's
// per-coin scale without precision loss), so the SKA branch here will only be
// taken when no explicit fee rate was supplied by the caller.
func fundRawTxFeeRateOverride(outputCoinType cointype.CoinType, varFeeRate dcrutil.Amount) cointype.SKAAmount {
	if outputCoinType.IsSKA() {
		return cointype.SKAAmount{}
	}
	return cointype.NewSKAAmount(big.NewInt(int64(varFeeRate)))
}

func (s *Server) fundRawTransaction(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.FundRawTransactionCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	var (
		changeAddress string
		feeRate       = w.RelayFee()
		feeRateSet    bool
		confs         = int32(1)
	)
	if cmd.Options != nil {
		opts := cmd.Options
		var err error
		if opts.ChangeAddress != nil {
			changeAddress = *opts.ChangeAddress
		}
		if opts.FeeRate != nil {
			feeRate, err = dcrutil.NewAmount(*opts.FeeRate)
			if err != nil {
				return nil, err
			}
			feeRateSet = true
		}
		if opts.ConfTarget != nil {
			confs = *opts.ConfTarget
			if confs < 0 {
				return nil, errors.New("confs must be non-negative")
			}
		}
	}

	tx := new(wire.MsgTx)
	err := tx.Deserialize(hex.NewDecoder(strings.NewReader(cmd.HexString)))
	if err != nil {
		return nil, err
	}
	// Existing inputs are problematic.  Without information about
	// how large the input scripts will be once signed, the wallet is
	// unable to perform correct fee estimation.  If fundrawtransaction
	// is changed later to work on a PSDT structure that includes this
	// information, this functionality may be enabled.  For now, prevent
	// the method from continuing.
	if len(tx.TxIn) != 0 {
		return nil, errors.New("transaction must not already have inputs")
	}

	// Reject the fee-rate option for SKA outputs: opts.FeeRate is a float64
	// in coins which converts cleanly to int64 atoms for VAR (1e8 atoms/coin)
	// but cannot represent SKA's per-coin scale (typically 1e18 atoms/coin)
	// without precision loss. Fall back to the network default for SKA.
	outputCoinType := txrules.GetCoinTypeFromOutputs(tx.TxOut)
	if feeRateSet && outputCoinType.IsSKA() {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"fee-rate option is unsupported for SKA outputs; "+
				"the network default fee rate will be used")
	}

	accountNum, err := w.AccountNumber(ctx, cmd.FundAccount)
	if err != nil {
		return nil, err
	}

	// Because there are no other inputs, a new transaction can be created.
	var changeSource txauthor.ChangeSource
	if changeAddress != "" {
		var err error
		changeSource, err = makeScriptChangeSource(changeAddress, w.ChainParams())
		if err != nil {
			return nil, err
		}
	}
	feeRateOverride := fundRawTxFeeRateOverride(outputCoinType, feeRate)
	atx, err := w.NewUnsignedTransaction(ctx, tx.TxOut, feeRateOverride, accountNum, confs,
		wallet.OutputSelectionAlgorithmDefault, changeSource, nil)
	if err != nil {
		return nil, err
	}

	// Include chosen inputs and change output (if any) in decoded
	// transaction.
	tx.TxIn = atx.Tx.TxIn
	if atx.ChangeIndex >= 0 {
		tx.TxOut = append(tx.TxOut, atx.Tx.TxOut[atx.ChangeIndex])
	}

	// Determine the absolute fee of the funded transaction. Branch on coin
	// type so SKA fees retain big.Int precision instead of being squashed
	// through float64; both branches emit Fee as a decimal coin string in
	// the coin type's native scale.
	txCoinType := txrules.GetCoinTypeFromOutputs(atx.Tx.TxOut)
	res := &types.FundRawTransactionResult{}
	if txCoinType.IsSKA() {
		fee := new(big.Int).Set(atx.SKATotalInput.BigInt())
		for i := range tx.TxOut {
			if tx.TxOut[i].SKAValue != nil {
				fee.Sub(fee, tx.TxOut[i].SKAValue)
			}
		}
		atomsPerCoin := getAtomsPerCoin(w.ChainParams(), txCoinType)
		res.Fee = cointype.AtomsToDecimalString(fee, atomsPerCoin)
	} else {
		fee := atx.TotalInput
		for i := range tx.TxOut {
			fee -= dcrutil.Amount(tx.TxOut[i].GetValue())
		}
		res.Fee = cointype.AtomsToDecimalString(
			big.NewInt(int64(fee)),
			big.NewInt(cointype.AtomsPerVAR))
	}

	b := new(strings.Builder)
	b.Grow(2 * tx.SerializeSize())
	err = tx.Serialize(hex.NewEncoder(b))
	if err != nil {
		return nil, err
	}
	res.Hex = b.String()
	return res, nil
}

// getAddressesByAccount handles a getaddressesbyaccount request by returning
// all addresses for an account, or an error if the requested account does
// not exist.
func (s *Server) getAddressesByAccount(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetAddressesByAccountCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	if cmd.Account == "imported" {
		addrs, err := w.ImportedAddresses(ctx, cmd.Account)
		if err != nil {
			return nil, err
		}
		return knownAddressMarshaler(addrs), nil
	}

	account, err := w.AccountNumber(ctx, cmd.Account)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAccountNotFound
		}
		return nil, err
	}

	xpub, err := w.AccountXpub(ctx, account)
	if err != nil {
		return nil, err
	}
	extBranch, err := xpub.Child(0)
	if err != nil {
		return nil, err
	}
	intBranch, err := xpub.Child(1)
	if err != nil {
		return nil, err
	}
	endExt, endInt, err := w.BIP0044BranchNextIndexes(ctx, account)
	if err != nil {
		return nil, err
	}
	params := w.ChainParams()
	addrs := make([]string, 0, endExt+endInt)
	appendAddrs := func(branchKey *hdkeychain.ExtendedKey, n uint32) error {
		for i := uint32(0); i < n; i++ {
			child, err := branchKey.Child(i)
			if errors.Is(err, hdkeychain.ErrInvalidChild) {
				continue
			}
			if err != nil {
				return err
			}
			pkh := dcrutil.Hash160(child.SerializedPubKey())
			addr, _ := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
				pkh, params)
			addrs = append(addrs, addr.String())
		}
		return nil
	}
	err = appendAddrs(extBranch, endExt)
	if err != nil {
		return nil, err
	}
	err = appendAddrs(intBranch, endInt)
	if err != nil {
		return nil, err
	}
	return addressStringsMarshaler(addrs), nil
}

// getBalance handles a getbalance request by returning the balance for an
// account (wallet), or an error if the requested account does not
// exist. Supports optional coin type filtering for dual-coin operations.
func (s *Server) getBalance(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetBalanceCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	minConf := int32(*cmd.MinConf)
	if minConf < 0 {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "minconf must be non-negative")
	}

	// Validate coin type if specified
	if cmd.CoinType != nil {
		coinType := cointype.CoinType(*cmd.CoinType)
		if err := validateCoinTypeConfigured(w.ChainParams(), coinType); err != nil {
			return nil, err
		}
	}

	accountName := "*"
	if cmd.Account != nil {
		accountName = *cmd.Account
	}

	blockHash, _ := w.MainChainTip(ctx)
	result := types.GetBalanceResult{
		BlockHash: blockHash.String(),
	}

	if accountName == "*" {
		// If coin type is specified, filter by coin type
		if cmd.CoinType != nil {
			coinType := cointype.CoinType(*cmd.CoinType)
			atomsPerCoin := getAtomsPerCoin(w.ChainParams(), coinType)
			allBalances, err := w.AccountBalances(ctx, minConf)
			if err != nil {
				return nil, err
			}

			// Filter for specified coin type and convert to result format
			result.Balances = make([]types.GetAccountBalanceResult, 0, len(allBalances))

			// For SKA coins, use big.Int totals
			isSKA := coinType.IsSKA()
			var (
				totImmatureCoinbase dcrutil.Amount
				totImmatureStakegen dcrutil.Amount
				totLocked           dcrutil.Amount
				totSpendable        dcrutil.Amount
				totUnconfirmed      dcrutil.Amount
				totVotingAuthority  dcrutil.Amount
				cumTot              dcrutil.Amount
				// SKA big.Int totals
				skaTotImmatureCoinbase cointype.SKAAmount // For SKA emission (coinbase-like)
				skaTotSpendable        cointype.SKAAmount
				skaTotUnconfirmed      cointype.SKAAmount
				skaCumTot              cointype.SKAAmount
			)

			for _, bal := range allBalances {
				// Check if this account has balances for the requested coin type
				coinBal, exists := bal.CoinTypeBalances[coinType]
				if !exists {
					continue
				}
				// For SKA, check SKATotal instead of Total (which may be 0 for large amounts)
				hasSKABalance := isSKA && (!coinBal.SKATotal.IsZero() || !coinBal.SKAUnconfirmed.IsZero())
				hasVARBalance := !isSKA && (coinBal.Total > 0 || coinBal.Unconfirmed > 0)
				if hasSKABalance || hasVARBalance {
					accountName, err := w.AccountName(ctx, bal.Account)
					if err != nil {
						if errors.Is(err, errors.NotExist) {
							return nil, rpcError(dcrjson.ErrRPCInternal.Code, err)
						}
						return nil, err
					}

					if isSKA {
						// Use SKA big.Int fields for SKA coins
						skaTotImmatureCoinbase = skaTotImmatureCoinbase.Add(coinBal.SKAImmatureCoinbaseRewards)
						skaTotSpendable = skaTotSpendable.Add(coinBal.SKASpendable)
						skaTotUnconfirmed = skaTotUnconfirmed.Add(coinBal.SKAUnconfirmed)
						skaCumTot = skaCumTot.Add(coinBal.SKATotal)

						// Use decimal strings for full precision SKA amounts
						json := types.GetAccountBalanceResult{
							AccountName:             accountName,
							ImmatureCoinbaseRewards: coinBal.SKAImmatureCoinbaseRewards.ToDecimalString(atomsPerCoin),
							ImmatureStakeGeneration: coinBal.SKAImmatureStakeGeneration.ToDecimalString(atomsPerCoin),
							LockedByTickets:         "0", // SKA doesn't participate in staking
							Spendable:               coinBal.SKASpendable.ToDecimalString(atomsPerCoin),
							Total:                   coinBal.SKATotal.ToDecimalString(atomsPerCoin),
							Unconfirmed:             coinBal.SKAUnconfirmed.ToDecimalString(atomsPerCoin),
							VotingAuthority:         "0", // SKA doesn't have voting authority
						}
						result.Balances = append(result.Balances, json)
					} else {
						// Use native .ToCoin() for VAR
						totImmatureCoinbase += coinBal.ImmatureCoinbaseRewards
						totImmatureStakegen += coinBal.ImmatureStakeGeneration
						totLocked += coinBal.LockedByTickets
						totSpendable += coinBal.Spendable
						totUnconfirmed += coinBal.Unconfirmed
						totVotingAuthority += coinBal.VotingAuthority
						cumTot += coinBal.Total

						json := types.GetAccountBalanceResult{
							AccountName:             accountName,
							ImmatureCoinbaseRewards: varAtomsToDecimalString(coinBal.ImmatureCoinbaseRewards),
							ImmatureStakeGeneration: varAtomsToDecimalString(coinBal.ImmatureStakeGeneration),
							LockedByTickets:         varAtomsToDecimalString(coinBal.LockedByTickets),
							Spendable:               varAtomsToDecimalString(coinBal.Spendable),
							Total:                   varAtomsToDecimalString(coinBal.Total),
							Unconfirmed:             varAtomsToDecimalString(coinBal.Unconfirmed),
							VotingAuthority:         varAtomsToDecimalString(coinBal.VotingAuthority),
						}
						result.Balances = append(result.Balances, json)
					}
				}
			}

			if isSKA {
				result.TotalImmatureCoinbaseRewards = skaTotImmatureCoinbase.ToDecimalString(atomsPerCoin)
				result.TotalImmatureStakeGeneration = "0"
				result.TotalLockedByTickets = "0"
				result.TotalSpendable = skaTotSpendable.ToDecimalString(atomsPerCoin)
				result.TotalUnconfirmed = skaTotUnconfirmed.ToDecimalString(atomsPerCoin)
				result.TotalVotingAuthority = "0"
				result.CumulativeTotal = skaCumTot.ToDecimalString(atomsPerCoin)
			} else {
				result.TotalImmatureCoinbaseRewards = varAtomsToDecimalString(totImmatureCoinbase)
				result.TotalImmatureStakeGeneration = varAtomsToDecimalString(totImmatureStakegen)
				result.TotalLockedByTickets = varAtomsToDecimalString(totLocked)
				result.TotalSpendable = varAtomsToDecimalString(totSpendable)
				result.TotalUnconfirmed = varAtomsToDecimalString(totUnconfirmed)
				result.TotalVotingAuthority = varAtomsToDecimalString(totVotingAuthority)
				result.CumulativeTotal = varAtomsToDecimalString(cumTot)
			}

			return result, nil
		}

		// Default behavior (backward compatible): use existing AccountBalances for VAR
		balances, err := w.AccountBalances(ctx, int32(*cmd.MinConf))
		if err != nil {
			return nil, err
		}

		var (
			totImmatureCoinbase dcrutil.Amount
			totImmatureStakegen dcrutil.Amount
			totLocked           dcrutil.Amount
			totSpendable        dcrutil.Amount
			totUnconfirmed      dcrutil.Amount
			totVotingAuthority  dcrutil.Amount
			cumTot              dcrutil.Amount
		)

		balancesLen := uint32(len(balances))
		result.Balances = make([]types.GetAccountBalanceResult, 0, balancesLen)

		for _, bal := range balances {
			accountName, err := w.AccountName(ctx, bal.Account)
			if err != nil {
				// Expect account lookup to succeed
				if errors.Is(err, errors.NotExist) {
					return nil, rpcError(dcrjson.ErrRPCInternal.Code, err)
				}
				return nil, err
			}

			totImmatureCoinbase += bal.ImmatureCoinbaseRewards
			totImmatureStakegen += bal.ImmatureStakeGeneration
			totLocked += bal.LockedByTickets
			totSpendable += bal.Spendable
			totUnconfirmed += bal.Unconfirmed
			totVotingAuthority += bal.VotingAuthority
			cumTot += bal.Total

			json := types.GetAccountBalanceResult{
				AccountName:             accountName,
				ImmatureCoinbaseRewards: varAtomsToDecimalString(bal.ImmatureCoinbaseRewards),
				ImmatureStakeGeneration: varAtomsToDecimalString(bal.ImmatureStakeGeneration),
				LockedByTickets:         varAtomsToDecimalString(bal.LockedByTickets),
				Spendable:               varAtomsToDecimalString(bal.Spendable),
				Total:                   varAtomsToDecimalString(bal.Total),
				Unconfirmed:             varAtomsToDecimalString(bal.Unconfirmed),
				VotingAuthority:         varAtomsToDecimalString(bal.VotingAuthority),
			}

			result.Balances = append(result.Balances, json)
		}

		result.TotalImmatureCoinbaseRewards = varAtomsToDecimalString(totImmatureCoinbase)
		result.TotalImmatureStakeGeneration = varAtomsToDecimalString(totImmatureStakegen)
		result.TotalLockedByTickets = varAtomsToDecimalString(totLocked)
		result.TotalSpendable = varAtomsToDecimalString(totSpendable)
		result.TotalUnconfirmed = varAtomsToDecimalString(totUnconfirmed)
		result.TotalVotingAuthority = varAtomsToDecimalString(totVotingAuthority)
		result.CumulativeTotal = varAtomsToDecimalString(cumTot)
	} else {
		account, err := w.AccountNumber(ctx, accountName)
		if err != nil {
			if errors.Is(err, errors.NotExist) {
				return nil, errAccountNotFound
			}
			return nil, err
		}

		// If coin type is specified, use coin-type specific balance for single account
		if cmd.CoinType != nil {
			coinType := cointype.CoinType(*cmd.CoinType)
			atomsPerCoin := getAtomsPerCoin(w.ChainParams(), coinType)
			coinBal, err := w.AccountBalanceByCoinType(ctx, account, coinType, minConf)
			if err != nil {
				return nil, err
			}

			var json types.GetAccountBalanceResult
			if coinType.IsSKA() {
				// Use decimal strings for full precision SKA amounts
				json = types.GetAccountBalanceResult{
					AccountName:             accountName,
					ImmatureCoinbaseRewards: coinBal.SKAImmatureCoinbaseRewards.ToDecimalString(atomsPerCoin),
					ImmatureStakeGeneration: coinBal.SKAImmatureStakeGeneration.ToDecimalString(atomsPerCoin),
					LockedByTickets:         "0",
					Spendable:               coinBal.SKASpendable.ToDecimalString(atomsPerCoin),
					Total:                   coinBal.SKATotal.ToDecimalString(atomsPerCoin),
					Unconfirmed:             coinBal.SKAUnconfirmed.ToDecimalString(atomsPerCoin),
					VotingAuthority:         "0",
				}
			} else {
				// Decimal coin string for VAR via cointype.AtomsToDecimalString.
				json = types.GetAccountBalanceResult{
					AccountName:             accountName,
					ImmatureCoinbaseRewards: varAtomsToDecimalString(coinBal.ImmatureCoinbaseRewards),
					ImmatureStakeGeneration: varAtomsToDecimalString(coinBal.ImmatureStakeGeneration),
					LockedByTickets:         varAtomsToDecimalString(coinBal.LockedByTickets),
					Spendable:               varAtomsToDecimalString(coinBal.Spendable),
					Total:                   varAtomsToDecimalString(coinBal.Total),
					Unconfirmed:             varAtomsToDecimalString(coinBal.Unconfirmed),
					VotingAuthority:         varAtomsToDecimalString(coinBal.VotingAuthority),
				}
			}
			result.Balances = append(result.Balances, json)
		} else {
			// Default behavior (backward compatible): use existing AccountBalance for VAR
			bal, err := w.AccountBalance(ctx, account, minConf)
			if err != nil {
				// Expect account lookup to succeed
				if errors.Is(err, errors.NotExist) {
					return nil, rpcError(dcrjson.ErrRPCInternal.Code, err)
				}
				return nil, err
			}
			json := types.GetAccountBalanceResult{
				AccountName:             accountName,
				ImmatureCoinbaseRewards: varAtomsToDecimalString(bal.ImmatureCoinbaseRewards),
				ImmatureStakeGeneration: varAtomsToDecimalString(bal.ImmatureStakeGeneration),
				LockedByTickets:         varAtomsToDecimalString(bal.LockedByTickets),
				Spendable:               varAtomsToDecimalString(bal.Spendable),
				Total:                   varAtomsToDecimalString(bal.Total),
				Unconfirmed:             varAtomsToDecimalString(bal.Unconfirmed),
				VotingAuthority:         varAtomsToDecimalString(bal.VotingAuthority),
			}
			result.Balances = append(result.Balances, json)
		}
	}

	return result, nil
}

// getBestBlock handles a getbestblock request by returning a JSON object
// with the height and hash of the most recently processed block.
func (s *Server) getBestBlock(ctx context.Context, icmd any) (any, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	hash, height := w.MainChainTip(ctx)
	result := &mondtypes.GetBestBlockResult{
		Hash:   hash.String(),
		Height: int64(height),
	}
	return result, nil
}

// getBestBlockHash handles a getbestblockhash request by returning the hash
// of the most recently processed block.
func (s *Server) getBestBlockHash(ctx context.Context, icmd any) (any, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	hash, _ := w.MainChainTip(ctx)
	return hash.String(), nil
}

// getBlockCount handles a getblockcount request by returning the chain height
// of the most recently processed block.
func (s *Server) getBlockCount(ctx context.Context, icmd any) (any, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	_, height := w.MainChainTip(ctx)
	return height, nil
}

// getBlockHash handles a getblockhash request by returning the main chain hash
// for a block at some height.
func (s *Server) getBlockHash(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetBlockHashCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	height := int32(cmd.Index)
	id := wallet.NewBlockIdentifierFromHeight(height)
	info, err := w.BlockInfo(ctx, id)
	if err != nil {
		return nil, err
	}
	return info.Hash.String(), nil
}

// getBlockHeader implements the getblockheader command.
func (s *Server) getBlockHeader(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetBlockHeaderCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Attempt RPC passthrough if connected to MOND.
	n, err := w.NetworkBackend()
	if err != nil {
		return nil, err
	}
	if chainSyncer, ok := n.(*chain.Syncer); ok {
		var resp json.RawMessage
		err := chainSyncer.RPC().Call(ctx, "getblockheader", &resp, cmd.Hash, cmd.Verbose)
		return resp, err
	}

	blockHash, err := chainhash.NewHashFromStr(cmd.Hash)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
	}

	blockHeader, err := w.BlockHeader(ctx, blockHash)
	if err != nil {
		return nil, err
	}

	// When the verbose flag isn't set, simply return the serialized block
	// header as a hex-encoded string.
	if cmd.Verbose == nil || !*cmd.Verbose {
		var headerBuf bytes.Buffer
		err := blockHeader.Serialize(&headerBuf)
		if err != nil {
			return nil, rpcErrorf(dcrjson.ErrRPCInternal.Code, "Could not serialize block header: %v", err)
		}
		return hex.EncodeToString(headerBuf.Bytes()), nil
	}

	// The verbose flag is set, so generate the JSON object and return it.

	// Get next block hash unless there are none.
	var nextHashString string
	confirmations := int64(-1)
	mainChainHasBlock, _, err := w.BlockInMainChain(ctx, blockHash)
	if err != nil {
		return nil, rpcErrorf(dcrjson.ErrRPCInternal.Code, "Error checking if block is in mainchain: %v", err)
	}
	if mainChainHasBlock {
		blockHeight := int32(blockHeader.Height)
		_, bestHeight := w.MainChainTip(ctx)
		if blockHeight < bestHeight {
			nextBlockID := wallet.NewBlockIdentifierFromHeight(blockHeight + 1)
			nextBlockInfo, err := w.BlockInfo(ctx, nextBlockID)
			if err != nil {
				return nil, rpcErrorf(dcrjson.ErrRPCInternal.Code, "Info not found for next block: %v", err)
			}
			nextHashString = nextBlockInfo.Hash.String()
		}
		confirmations = int64(confirms(blockHeight, bestHeight))
	}

	// Calculate past median time. Look at the last 11 blocks, starting
	// with the requested block, which is consistent with mond.
	iBlkHeader := blockHeader // start with the block header for the requested block
	timestamps := make([]int64, 0, 11)
	for i := 0; i < cap(timestamps); i++ {
		timestamps = append(timestamps, iBlkHeader.Timestamp.Unix())
		if iBlkHeader.Height == 0 {
			break
		}
		iBlkHeader, err = w.BlockHeader(ctx, &iBlkHeader.PrevBlock)
		if err != nil {
			return nil, rpcErrorf(dcrjson.ErrRPCInternal.Code, "Info not found for previous block: %v", err)
		}
	}
	sort.Slice(timestamps, func(i, j int) bool {
		return timestamps[i] < timestamps[j]
	})
	medianTime := timestamps[len(timestamps)/2]

	// Determine the PoW hash.  When the v1 PoW hash differs from the
	// block hash, this is assumed to be v2 (DCP0011).  More advanced
	// selection logic will be necessary if the PoW hash changes again in
	// the future.
	powHash := blockHeader.PowHashV1()
	if powHash != *blockHash {
		powHash = blockHeader.PowHashV2()
	}

	return &mondtypes.GetBlockHeaderVerboseResult{
		Hash:          blockHash.String(),
		PowHash:       powHash.String(),
		Confirmations: confirmations,
		Version:       blockHeader.Version,
		MerkleRoot:    blockHeader.MerkleRoot.String(),
		StakeRoot:     blockHeader.StakeRoot.String(),
		VoteBits:      blockHeader.VoteBits,
		FinalState:    hex.EncodeToString(blockHeader.FinalState[:]),
		Voters:        blockHeader.Voters,
		FreshStake:    blockHeader.FreshStake,
		Revocations:   blockHeader.Revocations,
		PoolSize:      blockHeader.PoolSize,
		Bits:          strconv.FormatInt(int64(blockHeader.Bits), 16),
		SBits:         dcrutil.Amount(blockHeader.SBits).ToCoin(),
		Height:        blockHeader.Height,
		Size:          blockHeader.Size,
		Time:          blockHeader.Timestamp.Unix(),
		MedianTime:    medianTime,
		Nonce:         blockHeader.Nonce,
		ExtraData:     hex.EncodeToString(blockHeader.ExtraData[:]),
		StakeVersion:  blockHeader.StakeVersion,
		Difficulty:    difficultyRatio(blockHeader.Bits, w.ChainParams()),
		ChainWork:     "", // unset because wallet is not equipped to easily calculate the cummulative chainwork
		PreviousHash:  blockHeader.PrevBlock.String(),
		NextHash:      nextHashString,
	}, nil
}

// getBlock implements the getblock command.
func (s *Server) getBlock(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetBlockCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}
	n, err := w.NetworkBackend()
	if err != nil {
		return nil, err
	}

	// Attempt RPC passthrough if connected to MOND.
	if chainSyncer, ok := n.(*chain.Syncer); ok {
		var resp json.RawMessage
		err := chainSyncer.RPC().Call(ctx, "getblock", &resp, cmd.Hash, cmd.Verbose, cmd.VerboseTx)
		return resp, err
	}

	blockHash, err := chainhash.NewHashFromStr(cmd.Hash)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
	}

	blocks, err := n.Blocks(ctx, []*chainhash.Hash{blockHash})
	if err != nil {
		return nil, err
	}
	if len(blocks) == 0 {
		// Should never happen but protects against a possible panic on
		// the following code.
		return nil, rpcErrorf(dcrjson.ErrRPCInternal.Code, "Network returned 0 blocks")
	}

	blk := blocks[0]

	// When the verbose flag isn't set, simply return the
	// network-serialized block as a hex-encoded string.
	if cmd.Verbose == nil || !*cmd.Verbose {
		b := new(strings.Builder)
		b.Grow(2 * blk.SerializeSize())
		err = blk.Serialize(hex.NewEncoder(b))
		if err != nil {
			return nil, rpcErrorf(dcrjson.ErrRPCInternal.Code, "Could not serialize block: %v", err)
		}
		return b.String(), nil
	}

	// Get next block hash unless there are none.
	var nextHashString string
	blockHeader := &blk.Header
	confirmations := int64(-1)
	mainChainHasBlock, _, err := w.BlockInMainChain(ctx, blockHash)
	if err != nil {
		return nil, rpcErrorf(dcrjson.ErrRPCInternal.Code, "Error checking if block is in mainchain: %v", err)
	}
	if mainChainHasBlock {
		blockHeight := int32(blockHeader.Height)
		_, bestHeight := w.MainChainTip(ctx)
		if blockHeight < bestHeight {
			nextBlockID := wallet.NewBlockIdentifierFromHeight(blockHeight + 1)
			nextBlockInfo, err := w.BlockInfo(ctx, nextBlockID)
			if err != nil {
				return nil, rpcErrorf(dcrjson.ErrRPCInternal.Code, "Info not found for next block: %v", err)
			}
			nextHashString = nextBlockInfo.Hash.String()
		}
		confirmations = int64(confirms(blockHeight, bestHeight))
	}

	// Calculate past median time. Look at the last 11 blocks, starting
	// with the requested block, which is consistent with mond.
	timestamps := make([]int64, 0, 11)
	for iBlkHeader := blockHeader; ; {
		timestamps = append(timestamps, iBlkHeader.Timestamp.Unix())
		if iBlkHeader.Height == 0 || len(timestamps) == cap(timestamps) {
			break
		}
		iBlkHeader, err = w.BlockHeader(ctx, &iBlkHeader.PrevBlock)
		if err != nil {
			return nil, rpcErrorf(dcrjson.ErrRPCInternal.Code, "Info not found for previous block: %v", err)
		}
	}
	sort.Slice(timestamps, func(i, j int) bool {
		return timestamps[i] < timestamps[j]
	})
	medianTime := timestamps[len(timestamps)/2]

	// Determine the PoW hash.  When the v1 PoW hash differs from the
	// block hash, this is assumed to be v2 (DCP0011).  More advanced
	// selection logic will be necessary if the PoW hash changes again in
	// the future.
	powHash := blockHeader.PowHashV1()
	if powHash != *blockHash {
		powHash = blockHeader.PowHashV2()
	}

	sbitsFloat := float64(blockHeader.SBits) / cointype.AtomsPerVAR
	blockReply := mondtypes.GetBlockVerboseResult{
		Hash:          cmd.Hash,
		PoWHash:       powHash.String(),
		Version:       blockHeader.Version,
		MerkleRoot:    blockHeader.MerkleRoot.String(),
		StakeRoot:     blockHeader.StakeRoot.String(),
		PreviousHash:  blockHeader.PrevBlock.String(),
		MedianTime:    medianTime,
		Nonce:         blockHeader.Nonce,
		VoteBits:      blockHeader.VoteBits,
		FinalState:    hex.EncodeToString(blockHeader.FinalState[:]),
		Voters:        blockHeader.Voters,
		FreshStake:    blockHeader.FreshStake,
		Revocations:   blockHeader.Revocations,
		PoolSize:      blockHeader.PoolSize,
		Time:          blockHeader.Timestamp.Unix(),
		StakeVersion:  blockHeader.StakeVersion,
		Confirmations: confirmations,
		Height:        int64(blockHeader.Height),
		Size:          int32(blk.Header.Size),
		Bits:          strconv.FormatInt(int64(blockHeader.Bits), 16),
		SBits:         sbitsFloat,
		Difficulty:    difficultyRatio(blockHeader.Bits, w.ChainParams()),
		ChainWork:     "", // unset because wallet is not equipped to easily calculate the cummulative chainwork
		ExtraData:     hex.EncodeToString(blockHeader.ExtraData[:]),
		NextHash:      nextHashString,
	}

	// The coinbase must be version 3 once the treasury agenda is active.
	isTreasuryEnabled := blk.Transactions[0].Version >= wire.TxVersionTreasury

	if cmd.VerboseTx == nil || !*cmd.VerboseTx {
		transactions := blk.Transactions
		txNames := make([]string, len(transactions))
		for i, tx := range transactions {
			txNames[i] = tx.TxHash().String()
		}
		blockReply.Tx = txNames

		stransactions := blk.STransactions
		stxNames := make([]string, len(stransactions))
		for i, tx := range stransactions {
			stxNames[i] = tx.TxHash().String()
		}
		blockReply.STx = stxNames
	} else {
		txns := blk.Transactions
		rawTxns := make([]mondtypes.TxRawResult, len(txns))
		for i, tx := range txns {
			rawTxn, err := createTxRawResult(w.ChainParams(), tx, uint32(i), blockHeader, confirmations, isTreasuryEnabled)
			if err != nil {
				return nil, rpcErrorf(dcrjson.ErrRPCInternal.Code, "Could not create transaction: %v", err)
			}
			rawTxns[i] = *rawTxn
		}
		blockReply.RawTx = rawTxns

		stxns := blk.STransactions
		rawSTxns := make([]mondtypes.TxRawResult, len(stxns))
		for i, tx := range stxns {
			rawSTxn, err := createTxRawResult(w.ChainParams(), tx, uint32(i), blockHeader, confirmations, isTreasuryEnabled)
			if err != nil {
				return nil, rpcErrorf(dcrjson.ErrRPCInternal.Code, "Could not create stake transaction: %v", err)
			}
			rawSTxns[i] = *rawSTxn
		}
		blockReply.RawSTx = rawSTxns
	}

	return blockReply, nil
}

func createTxRawResult(chainParams *chaincfg.Params, mtx *wire.MsgTx, blkIdx uint32, blkHeader *wire.BlockHeader,
	confirmations int64, isTreasuryEnabled bool) (*mondtypes.TxRawResult, error) {

	b := new(strings.Builder)
	b.Grow(2 * mtx.SerializeSize())
	err := mtx.Serialize(hex.NewEncoder(b))
	if err != nil {
		return nil, err
	}

	txReply := &mondtypes.TxRawResult{
		Hex:           b.String(),
		Txid:          mtx.CachedTxHash().String(),
		Version:       int32(mtx.Version),
		LockTime:      mtx.LockTime,
		Expiry:        mtx.Expiry,
		Vin:           createVinList(mtx, isTreasuryEnabled),
		Vout:          createVoutList(mtx, chainParams, nil),
		BlockHash:     blkHeader.BlockHash().String(),
		BlockHeight:   int64(blkHeader.Height),
		BlockIndex:    blkIdx,
		Confirmations: confirmations,
		Time:          blkHeader.Timestamp.Unix(),
		Blocktime:     blkHeader.Timestamp.Unix(), // identical to Time in bitcoind too
	}

	return txReply, nil
}

// createVinList returns a slice of JSON objects for the inputs of the passed
// transaction.
func createVinList(mtx *wire.MsgTx, isTreasuryEnabled bool) []mondtypes.Vin {
	// Treasurybase transactions only have a single txin by definition.
	//
	// NOTE: This check MUST come before the coinbase check because a
	// treasurybase will be identified as a coinbase as well.
	vinList := make([]mondtypes.Vin, len(mtx.TxIn))
	if isTreasuryEnabled && blockchain.IsTreasuryBase(mtx) {
		txIn := mtx.TxIn[0]
		vinEntry := &vinList[0]
		vinEntry.Treasurybase = true
		vinEntry.Sequence = txIn.Sequence
		vinEntry.AmountIn = dcrutil.Amount(txIn.ValueIn).ToCoin()
		vinEntry.BlockHeight = txIn.BlockHeight
		vinEntry.BlockIndex = txIn.BlockIndex
		return vinList
	}

	// Coinbase transactions only have a single txin by definition.
	if blockchain.IsCoinBaseTx(mtx, isTreasuryEnabled) {
		txIn := mtx.TxIn[0]
		vinEntry := &vinList[0]
		vinEntry.Coinbase = hex.EncodeToString(txIn.SignatureScript)
		vinEntry.Sequence = txIn.Sequence
		vinEntry.AmountIn = dcrutil.Amount(txIn.ValueIn).ToCoin()
		vinEntry.BlockHeight = txIn.BlockHeight
		vinEntry.BlockIndex = txIn.BlockIndex
		return vinList
	}

	// Treasury spend transactions only have a single txin by definition.
	if isTreasuryEnabled && stake.IsTSpend(mtx) {
		txIn := mtx.TxIn[0]
		vinEntry := &vinList[0]
		vinEntry.TreasurySpend = hex.EncodeToString(txIn.SignatureScript)
		vinEntry.Sequence = txIn.Sequence
		vinEntry.AmountIn = dcrutil.Amount(txIn.ValueIn).ToCoin()
		vinEntry.BlockHeight = txIn.BlockHeight
		vinEntry.BlockIndex = txIn.BlockIndex
		return vinList
	}

	// Stakebase transactions (votes) have two inputs: a null stake base
	// followed by an input consuming a ticket's stakesubmission.
	isSSGen := stake.IsSSGen(mtx)

	for i, txIn := range mtx.TxIn {
		// Handle only the null input of a stakebase differently.
		if isSSGen && i == 0 {
			vinEntry := &vinList[0]
			vinEntry.Stakebase = hex.EncodeToString(txIn.SignatureScript)
			vinEntry.Sequence = txIn.Sequence
			vinEntry.AmountIn = dcrutil.Amount(txIn.ValueIn).ToCoin()
			vinEntry.BlockHeight = txIn.BlockHeight
			vinEntry.BlockIndex = txIn.BlockIndex
			continue
		}

		// The disassembled string will contain [error] inline
		// if the script doesn't fully parse, so ignore the
		// error here.
		disbuf, _ := txscript.DisasmString(txIn.SignatureScript)

		vinEntry := &vinList[i]
		vinEntry.Txid = txIn.PreviousOutPoint.Hash.String()
		vinEntry.Vout = txIn.PreviousOutPoint.Index
		vinEntry.Tree = txIn.PreviousOutPoint.Tree
		vinEntry.Sequence = txIn.Sequence
		vinEntry.AmountIn = dcrutil.Amount(txIn.ValueIn).ToCoin()
		vinEntry.BlockHeight = txIn.BlockHeight
		vinEntry.BlockIndex = txIn.BlockIndex
		vinEntry.ScriptSig = &mondtypes.ScriptSig{
			Asm: disbuf,
			Hex: hex.EncodeToString(txIn.SignatureScript),
		}
	}

	return vinList
}

// createVoutList returns a slice of JSON objects for the outputs of the passed
// transaction.
func createVoutList(mtx *wire.MsgTx, chainParams *chaincfg.Params, filterAddrMap map[string]struct{}) []mondtypes.Vout {
	txType := stake.DetermineTxType(mtx)
	voutList := make([]mondtypes.Vout, 0, len(mtx.TxOut))
	for i, v := range mtx.TxOut {
		// The disassembled string will contain [error] inline if the
		// script doesn't fully parse, so ignore the error here.
		disbuf, _ := txscript.DisasmString(v.PkScript)

		// Attempt to extract addresses from the public key script.  In
		// the case of stake submission transactions, the odd outputs
		// contain a commitment address, so detect that case
		// accordingly.
		var addrs []stdaddr.Address
		var scriptClass string
		var reqSigs uint16
		var commitAmt *dcrutil.Amount
		if txType == stake.TxTypeSStx && (i%2 != 0) {
			scriptClass = sstxCommitmentString
			addr, err := stake.AddrFromSStxPkScrCommitment(v.PkScript,
				chainParams)
			if err != nil {
				log.Warnf("failed to decode ticket "+
					"commitment addr output for tx hash "+
					"%v, output idx %v", mtx.TxHash(), i)
			} else {
				addrs = []stdaddr.Address{addr}
			}
			amt, err := stake.AmountFromSStxPkScrCommitment(v.PkScript)
			if err != nil {
				log.Warnf("failed to decode ticket "+
					"commitment amt output for tx hash %v"+
					", output idx %v", mtx.TxHash(), i)
			} else {
				commitAmt = &amt
			}
		} else {
			// Ignore the error here since an error means the script
			// couldn't parse and there is no additional information
			// about it anyways.
			var sc stdscript.ScriptType
			sc, addrs = stdscript.ExtractAddrs(v.Version, v.PkScript, chainParams)
			reqSigs = stdscript.DetermineRequiredSigs(v.Version, v.PkScript)
			scriptClass = sc.String()
		}

		// Encode the addresses while checking if the address passes the
		// filter when needed.
		passesFilter := len(filterAddrMap) == 0
		encodedAddrs := make([]string, len(addrs))
		for j, addr := range addrs {
			encodedAddr := addr.String()
			encodedAddrs[j] = encodedAddr

			// No need to check the map again if the filter already
			// passes.
			if passesFilter {
				continue
			}
			if _, exists := filterAddrMap[encodedAddr]; exists {
				passesFilter = true
			}
		}

		if !passesFilter {
			continue
		}

		var vout mondtypes.Vout
		voutSPK := &vout.ScriptPubKey
		vout.N = uint32(i)
		vout.Value = dcrutil.Amount(v.Value).ToCoin()
		vout.Version = v.Version
		voutSPK.Addresses = encodedAddrs
		voutSPK.Asm = disbuf
		voutSPK.Hex = hex.EncodeToString(v.PkScript)
		voutSPK.Type = scriptClass
		voutSPK.ReqSigs = int32(reqSigs)
		if commitAmt != nil {
			voutSPK.CommitAmt = dcrjson.Float64(commitAmt.ToCoin())
		}

		voutList = append(voutList, vout)
	}

	return voutList
}

// difficultyRatio returns the proof-of-work difficulty as a multiple of the
// minimum difficulty using the passed bits field from the header of a block.
func difficultyRatio(bits uint32, params *chaincfg.Params) float64 {
	// The minimum difficulty is the max possible proof-of-work limit bits
	// converted back to a number.  Note this is not the same as the proof
	// of work limit directly because the block difficulty is encoded in a
	// block with the compact form which loses precision.
	max := blockchain.CompactToBig(params.PowLimitBits)
	target := blockchain.CompactToBig(bits)

	difficulty := new(big.Rat).SetFrac(max, target)
	outString := difficulty.FloatString(8)
	diff, err := strconv.ParseFloat(outString, 64)
	if err != nil {
		log.Errorf("Cannot get difficulty: %v", err)
		return 0
	}
	return diff
}

// syncStatus handles a syncstatus request.
func (s *Server) syncStatus(ctx context.Context, icmd any) (any, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}
	n, err := w.NetworkBackend()
	if err != nil {
		return nil, err
	}

	walletBestHash, walletBestHeight := w.MainChainTip(ctx)
	bestBlock, err := w.BlockInfo(ctx, wallet.NewBlockIdentifierFromHash(&walletBestHash))
	if err != nil {
		return nil, err
	}
	_24HoursAgo := time.Now().UTC().Add(-24 * time.Hour).Unix()
	walletBestBlockTooOld := bestBlock.Timestamp < _24HoursAgo

	synced, targetHeight := n.Synced(ctx)

	var headersFetchProgress float32
	blocksToFetch := targetHeight - walletBestHeight
	if blocksToFetch <= 0 {
		headersFetchProgress = 1
	} else {
		totalHeadersToFetch := targetHeight - w.InitialHeight()
		headersFetchProgress = 1 - (float32(blocksToFetch) / float32(totalHeadersToFetch))
	}

	return &types.SyncStatusResult{
		Synced:               synced,
		InitialBlockDownload: walletBestBlockTooOld,
		HeadersFetchProgress: headersFetchProgress,
	}, nil
}

// getCurrentNet handles a getcurrentnet request.
func (s *Server) getCurrentNet(ctx context.Context, icmd any) (any, error) {
	return s.activeNet.Net, nil
}

// getInfo handles a getinfo request by returning a structure containing
// information about the current state of the wallet.
func (s *Server) getInfo(ctx context.Context, icmd any) (any, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	tipHash, tipHeight := w.MainChainTip(ctx)
	tipHeader, err := w.BlockHeader(ctx, &tipHash)
	if err != nil {
		return nil, err
	}

	balances, err := w.AccountBalances(ctx, 1)
	if err != nil {
		return nil, err
	}
	var spendableBalance dcrutil.Amount
	for _, balance := range balances {
		spendableBalance += balance.Spendable
	}

	infoCoinType, err := w.CoinType(ctx)
	if errors.Is(err, errors.WatchingOnly) {
		infoCoinType = 0
	} else if err != nil {
		log.Errorf("Failed to retrieve the active coin type: %v", err)
		infoCoinType = 0
	}

	info := &types.InfoResult{
		Version:         version.Integer,
		ProtocolVersion: int32(p2p.Pver),
		WalletVersion:   version.Integer,
		Balance:         spendableBalance.ToCoin(),
		Blocks:          tipHeight,
		TimeOffset:      0,
		Connections:     0,
		Proxy:           "",
		Difficulty:      difficultyRatio(tipHeader.Bits, w.ChainParams()),
		TestNet:         w.ChainParams().Net == wire.TestNet3,
		KeypoolOldest:   0,
		KeypoolSize:     0,
		UnlockedUntil:   0,
		PaytxFee:        varAtomsToDecimalString(w.RelayFee()),
		RelayFee:        "0",
		CoinType:        infoCoinType,
		Errors:          "",
	}

	n, _ := s.walletLoader.NetworkBackend()
	if chainSyncer, ok := n.(*chain.Syncer); ok {
		var consensusInfo mondtypes.InfoChainResult
		err := chainSyncer.RPC().Call(ctx, "getinfo", &consensusInfo)
		if err != nil {
			return nil, err
		}
		info.Version = consensusInfo.Version
		info.ProtocolVersion = consensusInfo.ProtocolVersion
		info.TimeOffset = consensusInfo.TimeOffset
		info.Connections = consensusInfo.Connections
		info.Proxy = consensusInfo.Proxy
		info.RelayFee = strconv.FormatFloat(consensusInfo.RelayFee, 'f', -1, 64)
		info.Errors = consensusInfo.Errors
	}

	return info, nil
}

func decodeAddress(s string, params *chaincfg.Params) (stdaddr.Address, error) {
	// Secp256k1 pubkey as a string, handle differently.
	if len(s) == 66 || len(s) == 130 {
		pubKeyBytes, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		pubKeyAddr, err := stdaddr.NewAddressPubKeyEcdsaSecp256k1V0Raw(
			pubKeyBytes, params)
		if err != nil {
			return nil, err
		}

		return pubKeyAddr, nil
	}

	addr, err := stdaddr.DecodeAddress(s, params)
	if err != nil {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidAddressOrKey,
			"invalid address %q: decode failed: %#q", s, err)
	}
	return addr, nil
}

func decodeStakeAddress(s string, params *chaincfg.Params) (stdaddr.StakeAddress, error) {
	a, err := decodeAddress(s, params)
	if err != nil {
		return nil, err
	}
	if sa, ok := a.(stdaddr.StakeAddress); ok {
		return sa, nil
	}
	return nil, rpcErrorf(dcrjson.ErrRPCInvalidAddressOrKey,
		"invalid stake address %q", s)
}

// getAccount handles a getaccount request by returning the account name
// associated with a single address.
func (s *Server) getAccount(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetAccountCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}

	a, err := w.KnownAddress(ctx, addr)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAddressNotInWallet
		}
		return nil, err
	}

	return a.AccountName(), nil
}

// getAccountAddress handles a getaccountaddress by returning the most
// recently-created chained address that has not yet been used (does not yet
// appear in the blockchain, or any tx that has arrived in the mond mempool).
// If the most recently-requested address has been used, a new address (the
// next chained address in the keypool) is used.  This can fail if the keypool
// runs out (and will return dcrjson.ErrRPCWalletKeypoolRanOut if that happens).
func (s *Server) getAccountAddress(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetAccountAddressCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	account, err := w.AccountNumber(ctx, cmd.Account)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAccountNotFound
		}
		return nil, err
	}

	// Get the current address and persist it to the database so it can be
	// found when receiving transactions and appears in getaddressesbyaccount.
	addr, err := w.CurrentAddressAndPersist(ctx, account)
	if err != nil {
		// Expect account lookup to succeed
		if errors.Is(err, errors.NotExist) {
			return nil, rpcError(dcrjson.ErrRPCInternal.Code, err)
		}
		return nil, err
	}

	return addr.String(), nil
}

// getUnconfirmedBalance handles a getunconfirmedbalance extension request
// by returning the current unconfirmed balance of an account.
func (s *Server) getUnconfirmedBalance(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetUnconfirmedBalanceCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	acctName := "default"
	if cmd.Account != nil {
		acctName = *cmd.Account
	}
	account, err := w.AccountNumber(ctx, acctName)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAccountNotFound
		}
		return nil, err
	}
	bals, err := w.AccountBalance(ctx, account, 1)
	if err != nil {
		// Expect account lookup to succeed
		if errors.Is(err, errors.NotExist) {
			return nil, rpcError(dcrjson.ErrRPCInternal.Code, err)
		}
		return nil, err
	}

	return (bals.Total - bals.Spendable).ToCoin(), nil
}

// getCFilterV2 implements the getcfilterv2 command.
func (s *Server) getCFilterV2(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetCFilterV2Cmd)
	blockHash, err := chainhash.NewHashFromStr(cmd.BlockHash)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
	}

	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	key, filter, err := w.CFilterV2(ctx, blockHash)
	if err != nil {
		return nil, err
	}

	return &types.GetCFilterV2Result{
		BlockHash: cmd.BlockHash,
		Filter:    hex.EncodeToString(filter.Bytes()),
		Key:       hex.EncodeToString(key[:]),
	}, nil
}

// importCFiltersV2 handles an importcfiltersv2 request by parsing the provided
// hex-encoded filters into bytes and importing them into the wallet.
func (s *Server) importCFiltersV2(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.ImportCFiltersV2Cmd)

	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	filterData := make([][]byte, len(cmd.Filters))
	for i, fdhex := range cmd.Filters {
		var err error
		filterData[i], err = hex.DecodeString(fdhex)
		if err != nil {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParams.Code, "filter %d is not a valid hex string", i)
		}
	}

	err := w.ImportCFiltersV2(ctx, cmd.StartHeight, filterData)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCInvalidRequest.Code, err)
	}

	return nil, nil
}

// importPrivKey handles an importprivkey request by parsing
// a WIF-encoded private key and adding it to an account.
func (s *Server) importPrivKey(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.ImportPrivKeyCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	rescan := true
	if cmd.Rescan != nil {
		rescan = *cmd.Rescan
	}
	scanFrom := int32(0)
	if cmd.ScanFrom != nil {
		scanFrom = int32(*cmd.ScanFrom)
	}
	n, ok := s.walletLoader.NetworkBackend()
	if rescan && !ok {
		return nil, errNoNetwork
	}

	// Ensure that private keys are only imported to the correct account.
	//
	// Yes, Label is the account name.
	if cmd.Label != nil && *cmd.Label != udb.ImportedAddrAccountName {
		return nil, errNotImportedAccount
	}

	wif, err := dcrutil.DecodeWIF(cmd.PrivKey, w.ChainParams().PrivateKeyID)
	if err != nil {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidAddressOrKey, "WIF decode failed: %v", err)
	}

	// Import the private key, handling any errors.
	_, err = w.ImportPrivateKey(ctx, wif)
	if err != nil {
		switch {
		case errors.Is(err, errors.Exist):
			// Do not return duplicate key errors to the client.
			return nil, nil
		case errors.Is(err, errors.Locked):
			return nil, errWalletUnlockNeeded
		default:
			return nil, err
		}
	}

	if rescan {
		// Rescan in the background rather than blocking the rpc request. Use
		// the server waitgroup to ensure the rescan can return cleanly rather
		// than being killed mid database transaction.
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			serverCtx := s.httpServer.BaseContext(nil)
			_ = w.RescanFromHeight(serverCtx, n, scanFrom)
		}()
	}

	return nil, nil
}

// importPubKey handles an importpubkey request by importing a hex-encoded
// compressed 33-byte secp256k1 public key with sign byte, as well as its
// derived P2PKH address.  This method may only be used by watching-only
// wallets and with the special "imported" account.
func (s *Server) importPubKey(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.ImportPubKeyCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	rescan := true
	if cmd.Rescan != nil {
		rescan = *cmd.Rescan
	}
	scanFrom := int32(0)
	if cmd.ScanFrom != nil {
		scanFrom = int32(*cmd.ScanFrom)
	}
	n, ok := s.walletLoader.NetworkBackend()
	if rescan && !ok {
		return nil, errNoNetwork
	}

	if cmd.Label != nil && *cmd.Label != udb.ImportedAddrAccountName {
		return nil, errNotImportedAccount
	}

	pk, err := hex.DecodeString(cmd.PubKey)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
	}

	_, err = w.ImportPublicKey(ctx, pk)
	if errors.Is(err, errors.Exist) {
		// Do not return duplicate address errors, and skip any
		// rescans.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if rescan {
		// Rescan in the background rather than blocking the rpc request. Use
		// the server waitgroup to ensure the rescan can return cleanly rather
		// than being killed mid database transaction.
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			serverCtx := s.httpServer.BaseContext(nil)
			_ = w.RescanFromHeight(serverCtx, n, scanFrom)
		}()
	}

	return nil, nil
}

// importScript imports a redeem script for a P2SH output.
func (s *Server) importScript(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.ImportScriptCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	rescan := true
	if cmd.Rescan != nil {
		rescan = *cmd.Rescan
	}
	scanFrom := int32(0)
	if cmd.ScanFrom != nil {
		scanFrom = int32(*cmd.ScanFrom)
	}
	n, ok := s.walletLoader.NetworkBackend()
	if rescan && !ok {
		return nil, errNoNetwork
	}

	rs, err := hex.DecodeString(cmd.Hex)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
	}
	if len(rs) == 0 {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "empty script")
	}

	err = w.ImportScript(ctx, rs)
	if errors.Is(err, errors.Exist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if rescan {
		// Rescan in the background rather than blocking the rpc request. Use
		// the server waitgroup to ensure the rescan can return cleanly rather
		// than being killed mid database transaction.
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			serverCtx := s.httpServer.BaseContext(nil)
			_ = w.RescanFromHeight(serverCtx, n, scanFrom)
		}()
	}

	return nil, nil
}

func (s *Server) importXpub(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.ImportXpubCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	xpub, err := hdkeychain.NewKeyFromString(cmd.Xpub, w.ChainParams())
	if err != nil {
		return nil, err
	}

	return nil, w.ImportXpubAccount(ctx, cmd.Name, xpub)
}

// createNewAccount handles a createnewaccount request by creating and
// returning a new account. If the last account has no transaction history
// as per BIP 0044 a new account cannot be created so an error will be returned.
func (s *Server) createNewAccount(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.CreateNewAccountCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// The wildcard * is reserved by the rpc server with the special meaning
	// of "all accounts", so disallow naming accounts to this string.
	if cmd.Account == "*" {
		return nil, errReservedAccountName
	}

	_, err := w.NextAccount(ctx, cmd.Account)
	if err != nil {
		if errors.Is(err, errors.Locked) {
			return nil, rpcErrorf(dcrjson.ErrRPCWalletUnlockNeeded, "creating new accounts requires an unlocked wallet")
		}
		return nil, err
	}
	return nil, nil
}

// createAuthorizedEmission handles a createauthorizedemission request by creating a
// cryptographically signed SKA emission transaction.
//
// Capability gate: cmd.Passphrase is required. The wallet is unlocked for the
// duration of this single call and re-locked on return; the ambient
// walletpassphrase unlock window is intentionally NOT used. This prevents a
// concurrent authenticated RPC client from minting authorized emissions during
// an operator's open unlock window.
func (s *Server) createAuthorizedEmission(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.CreateAuthorizedEmissionCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Validate the coin type up front so VAR (or any out-of-range value)
	// produces a clear error instead of falling through to a misleading
	// "not configured in governance settings" message.
	ct := cointype.CoinType(cmd.CoinType)
	if err := validateCoinTypeConfigured(w.ChainParams(), ct); err != nil {
		return nil, err
	}
	if !ct.IsSKA() {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"createauthorizedemission requires an SKA coin type (1-255), got %d", cmd.CoinType)
	}

	// Get governance-defined parameters for this coin type
	chainParams := w.ChainParams()

	// Get SKA coin configuration from governance settings
	skaConfig := chainParams.SKACoins[ct]
	if skaConfig == nil {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"coin type %d is not configured in governance settings", cmd.CoinType)
	}

	if !skaConfig.Active {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"coin type %d is not active according to governance settings", cmd.CoinType)
	}

	// Get governance-defined emission addresses and amounts from chain configuration
	emissionAddresses := skaConfig.EmissionAddresses
	emissionAmounts := skaConfig.EmissionAmounts

	// Validate governance configuration
	if len(emissionAddresses) == 0 {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"no emission addresses configured for coin type %d - governance vote required", cmd.CoinType)
	}

	if len(emissionAddresses) != len(emissionAmounts) {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"emission addresses and amounts length mismatch for coin type %d", cmd.CoinType)
	}

	// Calculate and validate total amount (using big.Int for SKA precision)
	totalAmount := new(big.Int)
	zero := new(big.Int)
	for _, amount := range emissionAmounts {
		if amount == nil || amount.Cmp(zero) <= 0 {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"invalid emission amount %s for coin type %d", amount, cmd.CoinType)
		}
		totalAmount.Add(totalAmount, amount)
	}

	if totalAmount.Cmp(skaConfig.MaxSupply) != 0 {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"total emission amount %s does not match MaxSupply %s for coin type %d",
			totalAmount.String(), skaConfig.MaxSupply.String(), cmd.CoinType)
	}

	// Require an explicit wallet passphrase. Falling back to the ambient
	// walletpassphrase unlock window would preserve the very gap this
	// per-call gate is closing.
	if cmd.Passphrase == "" {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"walletpassphrase is required")
	}

	// Per-call capability gate: unlock the wallet for this single call only.
	// The ambient walletpassphrase unlock window is intentionally NOT used.
	return withWalletUnlocked(ctx, w, cmd.Passphrase, func() (any, error) {
		return s.createAuthorizedEmissionUnlocked(ctx, w, cmd, skaConfig, totalAmount, emissionAddresses, emissionAmounts)
	})
}

// createAuthorizedEmissionUnlocked runs the post-unlock body of the
// createauthorizedemission handler. Split out so the unlock/relock plumbing
// stays inside withWalletUnlocked while the long body keeps a flat
// non-nested return shape.
func (s *Server) createAuthorizedEmissionUnlocked(
	ctx context.Context,
	w *wallet.Wallet,
	cmd *types.CreateAuthorizedEmissionCmd,
	skaConfig *chaincfg.SKACoinConfig,
	totalAmount *big.Int,
	emissionAddresses []string,
	emissionAmounts []*big.Int,
) (any, error) {
	// Get emission private key for this coin type from wallet
	emissionPrivKey, err := getEmissionKeyForCoinType(w, ctx, cointype.CoinType(cmd.CoinType), cmd.EmissionKeyName)
	if err != nil {
		return nil, rpcErrorf(dcrjson.ErrRPCWallet,
			"failed to get emission key: %v", err)
	}

	// Default block height to the wallet's local synced tip; allow caller
	// override via cmd.Height for operators signing at a specific point in
	// the emission window or bypassing a stale wallet tip.
	_, currentHeight32 := w.MainChainTip(ctx)
	currentHeight := int64(currentHeight32)
	if cmd.Height != nil {
		if *cmd.Height < 0 {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"height must be non-negative")
		}
		currentHeight = *cmd.Height
	}

	// Footgun guards: reject out-of-window heights and non-default nonces
	// unless the corresponding force flag is set. The node enforces both in
	// validateEmissionAuthorization, so an authorization that violates either
	// is inert on chain — but the operator probably misconfigured something
	// and would otherwise discover that only at broadcast time. The two
	// flags are independent: bypassing the window is unrelated to bypassing
	// the nonce-must-be-1 invariant, and conflating them previously let one
	// override unlock both.
	forceWindow := cmd.ForceWindow != nil && *cmd.ForceWindow
	forceNonce := cmd.ForceNonce != nil && *cmd.ForceNonce
	emissionStart := int64(skaConfig.EmissionHeight)
	emissionEnd := emissionStart + int64(skaConfig.EmissionWindow)
	if currentHeight < emissionStart || currentHeight > emissionEnd {
		if !forceWindow {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"height %d is outside emission window [%d, %d] for coin type %d; "+
					"node will reject this authorization at validation time. "+
					"Pass forcewindow=true to override (only if you understand the consequences)",
				currentHeight, emissionStart, emissionEnd, cmd.CoinType)
		}
		log.Warnf("createauthorizedemission: signing at height %d outside "+
			"emission window [%d, %d] for coin type %d (wallet local tip=%d); "+
			"node will reject this authorization at validation time "+
			"(forcewindow=true)",
			currentHeight, emissionStart, emissionEnd, cmd.CoinType,
			currentHeight32)
	}

	// Default nonce to 1 (first and only emission per coin type under the
	// current governance policy). Operators re-authorizing a coin type that
	// has already been emitted must pass an explicit nonce.
	nonce := uint64(1)
	if cmd.Nonce != nil {
		nonce = *cmd.Nonce
	}

	// Footgun guard: reject non-default nonces unless forcenonce=true. The
	// node accepts only currentNonce+1 per coin type and each coin type emits
	// exactly once, so any nonce other than 1 is inert; forcenonce=true is
	// reserved for re-authorizing a coin type whose prior emission failed.
	if nonce != 1 {
		if !forceNonce {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"nonce %d != 1 for coin type %d; node only accepts the next-expected "+
					"nonce per coin type and emissions are one-shot. "+
					"Pass forcenonce=true to override (only valid when re-authorizing a coin type)",
				nonce, cmd.CoinType)
		}
		log.Warnf("createauthorizedemission: signing nonce %d (!= 1) for coin "+
			"type %d at height %d (wallet local tip=%d); node only accepts the "+
			"next-expected nonce per coin type and emissions are one-shot "+
			"(forcenonce=true)",
			nonce, cmd.CoinType, currentHeight, currentHeight32)
	}

	// Local one-shot guard: refuse a duplicate (CoinType, Nonce) pair to
	// stop a confused operator from producing two signed full-supply
	// emission transactions for the same logical authorization (e.g. after
	// a network blip during broadcast). The node rejects the second tx,
	// but until that round trip the wallet would have minted both. The
	// guard is bypassed when the operator passes forcenonce=true, which
	// is also the path used to re-author after a prior emission failed.
	priorHash, priorTs, priorExists, err := w.LookupEmissionAuthRecord(ctx, cmd.CoinType, nonce)
	if err != nil {
		return nil, rpcErrorf(dcrjson.ErrRPCWallet,
			"failed to check prior emission authorization: %v", err)
	}
	if priorExists && !forceNonce {
		priorHashStr := hex.EncodeToString(priorHash[:])
		// The DB stores hashes in raw byte order; surface the wire-format
		// chainhash string (reversed-hex) as well for direct comparison
		// with the result returned to the operator on the prior call.
		var ch chainhash.Hash
		copy(ch[:], priorHash[:])
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"createauthorizedemission already authored for coin type %d "+
				"nonce %d at %s (tx %s, raw=%s) — pass forcenonce=true to "+
				"override only if the prior tx is known not to have confirmed",
			cmd.CoinType, nonce, time.Unix(priorTs, 0).UTC().Format(time.RFC3339),
			ch.String(), priorHashStr)
	}

	// Create authorization structure (without signature initially)
	auth := &chaincfg.SKAEmissionAuth{
		EmissionKey: emissionPrivKey.PubKey(),
		Nonce:       nonce,
		CoinType:    cointype.CoinType(cmd.CoinType),
		Amount:      totalAmount,
		Height:      currentHeight,
		Timestamp:   time.Now().Unix(),
	}

	// Create the emission transaction first (unsigned)
	// We need to build the transaction before signing so we can sign the transaction hash
	tx, err := createUnsignedSKAEmissionTransaction(
		auth, emissionAddresses, emissionAmounts, w.ChainParams())
	if err != nil {
		return nil, rpcErrorf(dcrjson.ErrRPCInternal.Code,
			"failed to create emission transaction: %v", err)
	}

	// SECURITY FIX: Sign the transaction hash, not the addresses/amounts
	// This prevents miner redirect attacks
	authHash, err := createEmissionAuthHashFromTx(tx, auth, currentHeight, w.ChainParams())
	if err != nil {
		return nil, rpcErrorf(dcrjson.ErrRPCInternal.Code,
			"failed to create authorization hash: %v", err)
	}

	// Sign the authorization hash that includes the transaction
	signature := ecdsa.Sign(emissionPrivKey, authHash[:])
	auth.Signature = signature.Serialize()

	// Now update the transaction with the signed authorization
	authScript, err := createEmissionAuthScript(auth)
	if err != nil {
		return nil, rpcErrorf(dcrjson.ErrRPCInternal.Code,
			"failed to create authorization script: %v", err)
	}
	tx.TxIn[0].SignatureScript = authScript

	// Serialize transaction to hex
	var txBuf bytes.Buffer
	if err := tx.Serialize(&txBuf); err != nil {
		return nil, rpcErrorf(dcrjson.ErrRPCInternal.Code,
			"failed to serialize transaction: %v", err)
	}

	// Calculate transaction hash
	txHash := tx.TxHash()

	// Persist the (CoinType, Nonce, txHash) record so a duplicate call
	// (same coin type and nonce) is refused before signing again. The
	// handling splits on priorExists:
	//
	//   priorExists=true (forceNonce path) + persist failure:
	//     The operator already has a prior signed tx for this nonce. The
	//     current signed tx is in their hands too, and refusing to return
	//     it would force them to re-sign without our help. Log the failure
	//     and surface a Warning on the result so scripted callers can detect
	//     the broken local guard and avoid auto-retrying without forcenonce.
	//
	//   priorExists=false (fresh nonce) + persist failure:
	//     Neither party has the tx yet. Refuse the result outright — the
	//     operator can repair the DB and retry. Returning the tx with a
	//     warning here would create a tx in the operator's hands that the
	//     wallet has no local record of, defeating the one-shot guard's
	//     entire purpose on its first invocation.
	//
	// The node's own nonce check remains the authoritative replay protection
	// in either case.
	var hashBytes [32]byte
	copy(hashBytes[:], txHash[:])
	var warning string
	if storeErr := w.StoreEmissionAuthRecord(ctx, cmd.CoinType, nonce, hashBytes, time.Now().Unix()); storeErr != nil {
		if !priorExists {
			return nil, rpcErrorf(dcrjson.ErrRPCWallet,
				"refusing to return authorization: local one-shot guard "+
					"persistence failed for coin type %d nonce %d: %v — "+
					"repair the wallet DB and retry, or pass forcenonce=true",
				cmd.CoinType, nonce, storeErr)
		}
		log.Warnf("createauthorizedemission: failed to persist local "+
			"one-shot guard for coin type %d nonce %d (tx %s): %v",
			cmd.CoinType, nonce, txHash.String(), storeErr)
		warning = fmt.Sprintf("local one-shot guard persistence failed (%v); "+
			"do not retry this call without forcenonce=true", storeErr)
	}

	return &types.CreateAuthorizedEmissionResult{
		Transaction:     hex.EncodeToString(txBuf.Bytes()),
		TransactionHash: txHash.String(),
		Nonce:           nonce,
		TotalAmount:     totalAmount.String(),
		CoinType:        cmd.CoinType,
		Warning:         warning,
	}, nil
}

// renameAccount handles a renameaccount request by renaming an account.
// If the account does not exist an appropriate error will be returned.
func (s *Server) renameAccount(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.RenameAccountCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// The wildcard * is reserved by the rpc server with the special meaning
	// of "all accounts", so disallow naming accounts to this string.
	if cmd.NewAccount == "*" {
		return nil, errReservedAccountName
	}

	// Check that given account exists
	account, err := w.AccountNumber(ctx, cmd.OldAccount)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAccountNotFound
		}
		return nil, err
	}
	err = w.RenameAccount(ctx, account, cmd.NewAccount)
	return nil, err
}

// getMultisigOutInfo displays information about a given multisignature
// output.
func (s *Server) getMultisigOutInfo(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetMultisigOutInfoCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	hash, err := chainhash.NewHashFromStr(cmd.Hash)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
	}

	// Multisig outs are always in TxTreeRegular.
	op := &wire.OutPoint{
		Hash:  *hash,
		Index: cmd.Index,
		Tree:  wire.TxTreeRegular,
	}

	p2shOutput, err := w.FetchP2SHMultiSigOutput(ctx, op)
	if err != nil {
		return nil, err
	}

	// Get the list of pubkeys required to sign.
	_, pubkeyAddrs := stdscript.ExtractAddrs(scriptVersionAssumed, p2shOutput.RedeemScript, w.ChainParams())
	pubkeys := make([]string, 0, len(pubkeyAddrs))
	for _, pka := range pubkeyAddrs {
		switch pka := pka.(type) {
		case *stdaddr.AddressPubKeyEcdsaSecp256k1V0:
			pubkeys = append(pubkeys, hex.EncodeToString(pka.SerializedPubKey()))
		}
	}

	// Render the output value as a single decimal coin string regardless
	// of coin type so the wire shape is uniform.  VAR uses int64 atoms with
	// 1e8 atoms/coin; SKA uses big.Int atoms with the configured per-coin
	// scale (default 1e18).
	var amount string
	if p2shOutput.CoinType.IsSKA() {
		amount = p2shOutput.SKAOutputAmount.ToDecimalString(getAtomsPerCoin(w.ChainParams(), p2shOutput.CoinType))
	} else {
		amount = cointype.AtomsToDecimalString(
			big.NewInt(int64(p2shOutput.OutputAmount)),
			big.NewInt(cointype.AtomsPerVAR),
		)
	}
	result := &types.GetMultisigOutInfoResult{
		Address:      p2shOutput.P2SHAddress.String(),
		RedeemScript: hex.EncodeToString(p2shOutput.RedeemScript),
		M:            p2shOutput.M,
		N:            p2shOutput.N,
		Pubkeys:      pubkeys,
		TxHash:       p2shOutput.OutPoint.Hash.String(),
		Amount:       amount,
		CoinType:     uint8(p2shOutput.CoinType),
	}
	if !p2shOutput.ContainingBlock.None() {
		result.BlockHeight = uint32(p2shOutput.ContainingBlock.Height)
		result.BlockHash = p2shOutput.ContainingBlock.Hash.String()
	}
	if p2shOutput.Redeemer != nil {
		result.Spent = true
		result.SpentBy = p2shOutput.Redeemer.TxHash.String()
		result.SpentByIndex = p2shOutput.Redeemer.InputIndex
	}
	return result, nil
}

// getNewAddress handles a getnewaddress request by returning a new
// address for an account.  If the account does not exist an appropriate
// error is returned.
func (s *Server) getNewAddress(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetNewAddressCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	var callOpts []wallet.NextAddressCallOption
	if cmd.GapPolicy != nil {
		switch *cmd.GapPolicy {
		case "":
		case "error":
			callOpts = append(callOpts, wallet.WithGapPolicyError())
		case "ignore":
			callOpts = append(callOpts, wallet.WithGapPolicyIgnore())
		case "wrap":
			callOpts = append(callOpts, wallet.WithGapPolicyWrap())
		default:
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "unknown gap policy %q", *cmd.GapPolicy)
		}
	}

	acctName := "default"
	if cmd.Account != nil {
		acctName = *cmd.Account
	}
	account, err := w.AccountNumber(ctx, acctName)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAccountNotFound
		}
		return nil, err
	}

	addr, err := w.NewExternalAddress(ctx, account, callOpts...)
	if err != nil {
		return nil, err
	}
	return addr.String(), nil
}

// getRawChangeAddress handles a getrawchangeaddress request by creating
// and returning a new change address for an account.
//
// Note: bitcoind allows specifying the account as an optional parameter,
// but ignores the parameter.
func (s *Server) getRawChangeAddress(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetRawChangeAddressCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	acctName := "default"
	if cmd.Account != nil {
		acctName = *cmd.Account
	}
	account, err := w.AccountNumber(ctx, acctName)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAccountNotFound
		}
		return nil, err
	}

	addr, err := w.NewChangeAddress(ctx, account)
	if err != nil {
		return nil, err
	}

	// Return the new payment address string.
	return addr.String(), nil
}

// getReceivedByAccount handles a getreceivedbyaccount request by returning
// the total amount received by addresses of an account.
func (s *Server) getReceivedByAccount(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetReceivedByAccountCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	account, err := w.AccountNumber(ctx, cmd.Account)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAccountNotFound
		}
		return nil, err
	}

	// Transactions are not tracked for imported xpub accounts.
	if account > udb.ImportedAddrAccount {
		return 0.0, nil
	}

	// TODO: This is more inefficient that it could be, but the entire
	// algorithm is already dominated by reading every transaction in the
	// wallet's history.
	results, err := w.TotalReceivedForAccounts(ctx, int32(*cmd.MinConf))
	if err != nil {
		return nil, err
	}
	acctIndex := int(account)
	if account == udb.ImportedAddrAccount {
		acctIndex = len(results) - 1
	}
	return results[acctIndex].TotalReceived.ToCoin(), nil
}

// getReceivedByAddress handles a getreceivedbyaddress request by returning
// the total amount received by a single address.
func (s *Server) getReceivedByAddress(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetReceivedByAddressCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}
	// Default to VAR if no coin type specified.
	filterCoinType := cointype.CoinTypeVAR
	if cmd.CoinType != nil {
		filterCoinType = cointype.CoinType(*cmd.CoinType)
		if err := validateCoinTypeConfigured(w.ChainParams(), filterCoinType); err != nil {
			return nil, err
		}
	}

	// Get the correct AtomsPerCoin for this coin type
	atomsPerCoin := getAtomsPerCoin(w.ChainParams(), filterCoinType)

	var totalAtoms *big.Int
	if filterCoinType.IsSKA() {
		skaTotal, err := w.TotalReceivedSKAForAddr(ctx, addr, int32(*cmd.MinConf), filterCoinType)
		if err != nil {
			if errors.Is(err, errors.NotExist) {
				return nil, errAddressNotInWallet
			}
			return nil, err
		}
		totalAtoms = skaTotal.BigInt()
	} else {
		varTotal, err := w.TotalReceivedForAddr(ctx, addr, int32(*cmd.MinConf))
		if err != nil {
			if errors.Is(err, errors.NotExist) {
				return nil, errAddressNotInWallet
			}
			return nil, err
		}
		totalAtoms = big.NewInt(int64(varTotal))
	}

	// Both VAR and SKA return decimal coin strings — unified API contract.
	return cointype.AtomsToDecimalString(totalAtoms, atomsPerCoin), nil
}

// getMasterPubkey handles a getmasterpubkey request by returning the wallet
// master pubkey encoded as a string.
func (s *Server) getMasterPubkey(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetMasterPubkeyCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// If no account is passed, we provide the extended public key
	// for the default account number.
	account := uint32(udb.DefaultAccountNum)
	if cmd.Account != nil {
		var err error
		account, err = w.AccountNumber(ctx, *cmd.Account)
		if err != nil {
			if errors.Is(err, errors.NotExist) {
				return nil, errAccountNotFound
			}
			return nil, err
		}
	}

	xpub, err := w.AccountXpub(ctx, account)
	if err != nil {
		return nil, err
	}

	log.Warnf("Attention: Extended public keys must not be shared with or " +
		"leaked to external parties, such as VSPs, in combination with " +
		"any account private key; this reveals all private keys of " +
		"this account")

	return xpub.String(), nil
}

// getPeerInfo responds to the getpeerinfo request.
// It gets the network backend and views the data on remote peers when in spv mode
func (s *Server) getPeerInfo(ctx context.Context, icmd any) (any, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}
	n, err := w.NetworkBackend()
	if err != nil {
		return nil, err
	}

	syncer, ok := n.(*spv.Syncer)
	if !ok {
		var resp []*types.GetPeerInfoResult
		if chainSyncer, ok := n.(*chain.Syncer); ok {
			err := chainSyncer.RPC().Call(ctx, "getpeerinfo", &resp)
			if err != nil {
				return nil, err
			}
		}
		return resp, nil
	}

	rps := syncer.GetRemotePeers()
	infos := make([]*types.GetPeerInfoResult, 0, len(rps))

	for _, rp := range rps {
		info := &types.GetPeerInfoResult{
			ID:             int32(rp.ID()),
			Addr:           rp.RemoteAddr().String(),
			AddrLocal:      rp.LocalAddr().String(),
			Services:       fmt.Sprintf("%08d", uint64(rp.Services())),
			Version:        rp.Pver(),
			SubVer:         rp.UA(),
			StartingHeight: int64(rp.InitialHeight()),
			BanScore:       int32(rp.BanScore()),
		}
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].ID < infos[j].ID
	})
	return infos, nil
}

// getStakeInfo gets a large amounts of information about the stake environment
// and a number of statistics about local staking in the wallet.
func (s *Server) getStakeInfo(ctx context.Context, icmd any) (any, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	n, _ := s.walletLoader.NetworkBackend()
	var sinfo *wallet.StakeInfoData
	var err error
	if chainSyncer, ok := n.(*chain.Syncer); ok {
		sinfo, err = w.StakeInfoPrecise(ctx, chainSyncer.RPC())
	} else {
		sinfo, err = w.StakeInfo(ctx)
	}
	if err != nil {
		return nil, err
	}

	var proportionLive, proportionMissed float64
	if sinfo.PoolSize > 0 {
		proportionLive = float64(sinfo.Live) / float64(sinfo.PoolSize)
	}
	if sinfo.Missed > 0 {
		proportionMissed = float64(sinfo.Missed) / (float64(sinfo.Voted + sinfo.Missed))
	}

	resp := &types.GetStakeInfoResult{
		BlockHeight:  sinfo.BlockHeight,
		Difficulty:   sinfo.Sdiff.ToCoin(),
		TotalSubsidy: sinfo.TotalSubsidy.ToCoin(),

		OwnMempoolTix:  sinfo.OwnMempoolTix,
		Immature:       sinfo.Immature,
		Unspent:        sinfo.Unspent,
		Voted:          sinfo.Voted,
		Revoked:        sinfo.Revoked,
		UnspentExpired: sinfo.UnspentExpired,

		PoolSize:         sinfo.PoolSize,
		AllMempoolTix:    sinfo.AllMempoolTix,
		Live:             sinfo.Live,
		ProportionLive:   proportionLive,
		Missed:           sinfo.Missed,
		ProportionMissed: proportionMissed,
		Expired:          sinfo.Expired,
	}

	return resp, nil
}

// getTickets handles a gettickets request by returning the hashes of the tickets
// currently owned by wallet, encoded as strings.
func (s *Server) getTickets(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetTicketsCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	n, _ := s.walletLoader.NetworkBackend()
	rpc, _ := n.(wallet.LiveTicketQuerier) // nil rpc indicates SPV to LiveTicketHashes

	ticketHashes, err := w.LiveTicketHashes(ctx, rpc, cmd.IncludeImmature)
	if err != nil {
		return nil, err
	}

	// Compose a slice of strings to return.
	ticketHashStrs := make([]string, 0, len(ticketHashes))
	for i := range ticketHashes {
		ticketHashStrs = append(ticketHashStrs, ticketHashes[i].String())
	}

	return &types.GetTicketsResult{Hashes: ticketHashStrs}, nil
}

// getTransaction handles a gettransaction request by returning details about
// a single transaction saved by wallet.
func (s *Server) getTransaction(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetTransactionCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	txHash, err := chainhash.NewHashFromStr(cmd.Txid)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
	}

	// returns nil details when not found
	txd, err := wallet.UnstableAPI(w).TxDetails(ctx, txHash)
	if errors.Is(err, errors.NotExist) {
		return nil, rpcErrorf(dcrjson.ErrRPCNoTxInfo, "no information for transaction")
	} else if err != nil {
		return nil, err
	}

	_, tipHeight := w.MainChainTip(ctx)

	var b strings.Builder
	b.Grow(2 * txd.MsgTx.SerializeSize())
	err = txd.MsgTx.Serialize(hex.NewEncoder(&b))
	if err != nil {
		return nil, err
	}

	// TODO: Add a "generated" field to this result type.  "generated":true
	// is only added if the transaction is a coinbase.
	ret := types.GetTransactionResult{
		TxID:            cmd.Txid,
		Hex:             b.String(),
		Time:            txd.Received.Unix(),
		TimeReceived:    txd.Received.Unix(),
		WalletConflicts: []string{}, // Not saved
		//Generated:     compat.IsEitherCoinBaseTx(&details.MsgTx),
	}

	if txd.Block.Height != -1 {
		ret.BlockHash = txd.Block.Hash.String()
		ret.BlockTime = txd.Block.Time.Unix()
		ret.Confirmations = int64(confirms(txd.Block.Height,
			tipHeight))
	}

	// Defense-in-depth: consensus rejects mixed-coin-type transactions, but a
	// malformed tx that reached the wallet's txStore via SPV rescan or
	// addtransaction RPC must not silently mis-report balance. Refuse to
	// aggregate a mixed-coin-type tx and surface an internal error instead.
	if err := txrules.ValidateCoinTypeUniformity(txd.MsgTx.TxOut); err != nil {
		return nil, rpcErrorf(dcrjson.ErrRPCInternal.Code,
			"stored transaction %s has mixed coin types: %v", cmd.Txid, err)
	}
	txCoinType := txrules.GetCoinTypeFromOutputs(txd.MsgTx.TxOut)
	isSKA := txCoinType.IsSKA()
	atomsPerCoin := getAtomsPerCoin(w.ChainParams(), txCoinType)

	var (
		debitTotal     dcrutil.Amount
		creditTotal    dcrutil.Amount
		skaDebitTotal  cointype.SKAAmount
		skaCreditTotal cointype.SKAAmount
		fee            dcrutil.Amount
		negFeeStr      string
	)

	// For SKA transactions, use a direct calculation approach:
	// - Credits = outputs that belong to the wallet (in txd.Credits)
	// - Debits = either from database or calculated from inputs
	// - Net = Credits - Debits (negative for sends, positive for receives)
	if isSKA {
		// Calculate credits directly from outputs that are in txd.Credits
		for _, cred := range txd.Credits {
			if int(cred.Index) < len(txd.MsgTx.TxOut) {
				output := txd.MsgTx.TxOut[cred.Index]
				if output.SKAValue != nil && output.SKAValue.Sign() > 0 {
					skaCreditTotal = skaCreditTotal.Add(cointype.NewSKAAmount(output.SKAValue))
				}
			}
		}

		// Calculate debits: sum of all inputs from wallet (previous outputs being spent)
		// First try from database, then look up previous transactions
		for _, deb := range txd.Debits {
			if !deb.SKAAmount.IsZero() {
				skaDebitTotal = skaDebitTotal.Add(deb.SKAAmount)
			} else if int(deb.Index) < len(txd.MsgTx.TxIn) {
				// Look up the previous transaction's output to get the actual SKA amount
				prevOut := &txd.MsgTx.TxIn[deb.Index].PreviousOutPoint
				prevHash := prevOut.Hash
				prevTxs, _, err := w.GetTransactionsByHashes(ctx, []*chainhash.Hash{&prevHash})
				if err == nil && len(prevTxs) > 0 && prevTxs[0] != nil {
					if int(prevOut.Index) < len(prevTxs[0].TxOut) {
						out := prevTxs[0].TxOut[prevOut.Index]
						if out.SKAValue != nil && out.SKAValue.Sign() > 0 {
							skaDebitTotal = skaDebitTotal.Add(cointype.NewSKAAmount(out.SKAValue))
						}
					}
				}
			}
		}

		// For SKA, use output-based calculation which is more reliable
		// especially for unmined transactions where credits may not be populated yet.
		// For a send: Amount = -(outputs NOT to our wallet)
		// For a receive: Amount = (outputs TO our wallet that are credits)

		// Calculate fee if all inputs are debits and we have debit values
		var skaFee cointype.SKAAmount
		if len(txd.Debits) == len(txd.MsgTx.TxIn) && !skaDebitTotal.IsZero() {
			var skaOutputTotal cointype.SKAAmount
			for _, output := range txd.MsgTx.TxOut {
				if output.SKAValue != nil {
					skaOutputTotal = skaOutputTotal.Add(cointype.NewSKAAmount(output.SKAValue))
				}
			}
			skaFee = skaDebitTotal.Sub(skaOutputTotal)
			ret.Fee = skaFee.Neg().ToDecimalString(atomsPerCoin)
		}

		// Amount = credits - debits (same formula as VAR)
		// For mined transactions: credits are populated, so this gives correct net change
		// For unmined transactions: credits = 0, so this gives -debits (total spent)
		skaNet := skaCreditTotal.Sub(skaDebitTotal)
		ret.Amount = skaNet.ToDecimalString(atomsPerCoin)
	} else {
		// VAR transaction: emit decimal coin strings to match the unified
		// API contract.
		for _, deb := range txd.Debits {
			debitTotal += deb.Amount
		}
		for _, cred := range txd.Credits {
			creditTotal += cred.Amount
		}
		// Fee can only be determined if every input is a debit.
		if len(txd.Debits) == len(txd.MsgTx.TxIn) {
			var outputTotal dcrutil.Amount
			for _, output := range txd.MsgTx.TxOut {
				outputTotal += dcrutil.Amount(output.Value)
			}
			fee = debitTotal - outputTotal
			negFeeStr = varAtomsToDecimalString(-fee)
		}
		ret.Amount = varAtomsToDecimalString(creditTotal - debitTotal)
		ret.Fee = negFeeStr
	}

	details, err := w.ListTransactionDetails(ctx, txHash)
	if err != nil {
		return nil, err
	}
	ret.Details = make([]types.GetTransactionDetailsResult, len(details))
	for i, d := range details {
		ret.Details[i] = types.GetTransactionDetailsResult{
			Account:           d.Account,
			Address:           d.Address,
			Amount:            d.Amount,
			Category:          d.Category,
			InvolvesWatchOnly: d.InvolvesWatchOnly,
			Fee:               d.Fee,
			Vout:              d.Vout,
		}
	}

	return ret, nil
}

// getTxOut handles a gettxout request by returning details about an unspent
// output. In SPV mode, details are only returned for transaction outputs that
// are relevant to the wallet.
// To match the behavior in RPC mode, (nil, nil) is returned if the transaction
// output could not be found (never existed or was pruned) or is spent by another
// transaction already in the main chain.  Mined transactions that are spent by
// a mempool transaction are not affected by this.
func (s *Server) getTxOut(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetTxOutCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Attempt RPC passthrough if connected to MOND.
	n, err := w.NetworkBackend()
	if err != nil {
		return nil, err
	}
	if chainSyncer, ok := n.(*chain.Syncer); ok {
		var resp json.RawMessage
		err := chainSyncer.RPC().Call(ctx, "gettxout", &resp, cmd.Txid, cmd.Vout, cmd.Tree, cmd.IncludeMempool)
		return resp, err
	}

	txHash, err := chainhash.NewHashFromStr(cmd.Txid)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
	}

	if cmd.Tree != wire.TxTreeRegular && cmd.Tree != wire.TxTreeStake {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "Tx tree must be regular or stake")
	}

	// Attempt to read the unspent txout info from wallet.
	outpoint := wire.OutPoint{Hash: *txHash, Index: cmd.Vout, Tree: cmd.Tree}
	utxo, err := w.UnspentOutput(ctx, outpoint, *cmd.IncludeMempool)
	if err != nil && !errors.Is(err, errors.NotExist) {
		return nil, err
	}
	if utxo == nil {
		return nil, nil // output is spent or does not exist.
	}

	// gettxout's response shape (mondtypes.GetTxOutResult) only carries the
	// VAR-scale int64 Value field, so an SKA UTXO would be reported as
	// `value: 0` with no way for the caller to distinguish "spent" from
	// "SKA UTXO." Refuse with an actionable error pointing at listunspent,
	// which already exposes per-coin-type SKA fields.
	if utxo.CoinType.IsSKA() {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"gettxout in SPV mode does not expose SKA fields; use listunspent for coin type %d outputs",
			utxo.CoinType)
	}

	// Disassemble script into single line printable format.  The
	// disassembled string will contain [error] inline if the script
	// doesn't fully parse, so ignore the error here.
	disbuf, _ := txscript.DisasmString(utxo.PkScript)

	// Get further info about the script.  Ignore the error here since an
	// error means the script couldn't parse and there is no additional
	// information about it anyways.
	scriptClass, addrs := stdscript.ExtractAddrs(scriptVersionAssumed, utxo.PkScript, s.activeNet)
	reqSigs := stdscript.DetermineRequiredSigs(scriptVersionAssumed, utxo.PkScript)
	addresses := make([]string, len(addrs))
	for i, addr := range addrs {
		addresses[i] = addr.String()
	}

	bestHash, bestHeight := w.MainChainTip(ctx)
	var confirmations int64
	if utxo.Block.Height != -1 {
		confirmations = int64(confirms(utxo.Block.Height, bestHeight))
	}

	return &mondtypes.GetTxOutResult{
		BestBlock:     bestHash.String(),
		Confirmations: confirmations,
		Value:         utxo.Amount.ToCoin(),
		ScriptPubKey: mondtypes.ScriptPubKeyResult{
			Asm:       disbuf,
			Hex:       hex.EncodeToString(utxo.PkScript),
			ReqSigs:   int32(reqSigs),
			Type:      scriptClass.String(),
			Addresses: addresses,
		},
		Coinbase: utxo.FromCoinBase,
	}, nil
}

// getVoteChoices handles a getvotechoices request by returning configured vote
// preferences for each agenda of the latest supported stake version.
func (s *Server) getVoteChoices(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetVoteChoicesCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	var ticketHash *chainhash.Hash
	if cmd.TicketHash != nil {
		hash, err := chainhash.NewHashFromStr(*cmd.TicketHash)
		if err != nil {
			return nil, rpcError(dcrjson.ErrRPCInvalidParameter, err)
		}
		ticketHash = hash
	}

	version, agendas := wallet.CurrentAgendas(w.ChainParams())
	resp := &types.GetVoteChoicesResult{
		Version: version,
		Choices: make([]types.VoteChoice, 0, len(agendas)),
	}

	choices, _, err := w.AgendaChoices(ctx, ticketHash)
	if err != nil {
		return nil, err
	}

	for _, agenda := range agendas {
		agendaID := agenda.Vote.Id
		voteChoice := types.VoteChoice{
			AgendaID:          agendaID,
			AgendaDescription: agenda.Vote.Description,
			ChoiceID:          choices[agendaID],
			ChoiceDescription: "", // Set below
		}

		for _, choice := range agenda.Vote.Choices {
			if choices[agendaID] == choice.Id {
				voteChoice.ChoiceDescription = choice.Description
				break
			}
		}

		resp.Choices = append(resp.Choices, voteChoice)
	}

	return resp, nil
}

// getWalletFee returns the currently set tx fee for the requested wallet
// with source indication (manual, rpc, or static).
func (s *Server) getWalletFee(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetWalletFeeCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Default to VAR (coin type 0) if not specified
	ct := cointype.CoinType(0)
	if cmd.CoinType != nil {
		ct = cointype.CoinType(*cmd.CoinType)
	}

	// Get effective fee with source indication
	fee, source, err := w.GetEffectiveFee(ctx, ct)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCInternal.Code, err)
	}

	atomsPerCoin := atomsPerCoinForCoinType(w.ChainParams(), ct)

	return &types.GetWalletFeeResult{
		Fee:    fee.ToDecimalString(atomsPerCoin),
		Source: source,
	}, nil
}

// atomsPerCoinForCoinType returns the atoms-per-coin scale for ct on the
// active chain, falling back to the global SKA default when the SKA coin
// has no per-coin AtomsPerCoin configured. Used by the RPC fee handlers
// that render or parse fee values in decimal-coin units.
func atomsPerCoinForCoinType(params *chaincfg.Params, ct cointype.CoinType) *big.Int {
	if ct == cointype.CoinTypeVAR {
		return big.NewInt(int64(cointype.AtomsPerVAR))
	}
	if cfg, ok := params.SKACoins[ct]; ok && cfg != nil && cfg.AtomsPerCoin != nil {
		return cfg.AtomsPerCoin
	}
	return cointype.GetAtomsPerSKACoin()
}

// getVoteFeeConsolidationAddress handles the getvotefeeconsolidationaddress command.
func (s *Server) getVoteFeeConsolidationAddress(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetVoteFeeConsolidationAddressCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Call wallet method to get address
	addr, err := w.GetVoteFeeConsolidationAddress(ctx, cmd.Account)
	if err != nil {
		return nil, err
	}

	// Check if this is a custom address or the default
	hasCustom, err := w.HasCustomConsolidationAddress(ctx, cmd.Account)
	if err != nil {
		return nil, err
	}

	return types.GetVoteFeeConsolidationAddressResult{
		Account:   cmd.Account,
		Address:   addr.String(),
		IsDefault: !hasCustom,
	}, nil
}

// setVoteFeeConsolidationAddress handles the setvotefeeconsolidationaddress command.
func (s *Server) setVoteFeeConsolidationAddress(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.SetVoteFeeConsolidationAddressCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Decode and validate the address
	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}

	// Call wallet method
	err = w.SetVoteFeeConsolidationAddress(ctx, cmd.Account, addr)
	if err != nil {
		return nil, err
	}

	return "Consolidation address set successfully", nil
}

// clearVoteFeeConsolidationAddress handles the clearvotefeeconsolidationaddress command.
func (s *Server) clearVoteFeeConsolidationAddress(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.ClearVoteFeeConsolidationAddressCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Call wallet method
	err := w.ClearVoteFeeConsolidationAddress(ctx, cmd.Account)
	if err != nil {
		return nil, err
	}

	return "Consolidation address cleared (using default)", nil
}

// These generators create the following global variables in this package:
//
//   var localeHelpDescs map[string]func() map[string]string
//   var requestUsages string
//
// localeHelpDescs maps from locale strings (e.g. "en_US") to a function that
// builds a map of help texts for each RPC server method.  This prevents help
// text maps for every locale map from being rooted and created during init.
// Instead, the appropriate function is looked up when help text is first needed
// using the current locale and saved to the global below for further reuse.
//
// requestUsages contains single line usages for every supported request,
// separated by newlines.  It is set during init.  These usages are used for all
// locales.
//
//go:generate go run ../../rpchelp/genrpcserverhelp.go jsonrpc
//go:generate gofmt -w rpcserverhelp.go

var helpDescs map[string]string
var helpDescsMu sync.Mutex // Help may execute concurrently, so synchronize access.

// help handles the help request by returning one line usage of all available
// methods, or full help for a specific method.  The chainClient is optional,
// and this is simply a helper function for the HelpNoChainRPC and
// HelpWithChainRPC handlers.
func (s *Server) help(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.HelpCmd)
	// TODO: The "help" RPC should use a HTTP POST client when calling down to
	// mond for additional help methods.  This avoids including websocket-only
	// requests in the help, which are not callable by wallet JSON-RPC clients.
	var rpc *mond.RPC
	n, _ := s.walletLoader.NetworkBackend()
	if chainSyncer, ok := n.(*chain.Syncer); ok {
		rpc = chainSyncer.RPC()
	}
	if cmd.Command == nil || *cmd.Command == "" {
		// Prepend chain server usage if it is available.
		usages := requestUsages
		if rpc != nil {
			var usage string
			err := rpc.Call(ctx, "help", &usage)
			if err != nil {
				return nil, err
			}
			if usage != "" {
				usages = "Chain server usage:\n\n" + usage + "\n\n" +
					"Wallet server usage (overrides chain requests):\n\n" +
					requestUsages
			}
		}
		return usages, nil
	}

	defer helpDescsMu.Unlock()
	helpDescsMu.Lock()

	if helpDescs == nil {
		// TODO: Allow other locales to be set via config or detemine
		// this from environment variables.  For now, hardcode US
		// English.
		helpDescs = localeHelpDescs["en_US"]()
	}

	helpText, ok := helpDescs[*cmd.Command]
	if ok {
		return helpText, nil
	}

	// Return the chain server's detailed help if possible.
	var chainHelp string
	if rpc != nil {
		err := rpc.Call(ctx, "help", &chainHelp, *cmd.Command)
		if err != nil {
			return nil, err
		}
	}
	if chainHelp != "" {
		return chainHelp, nil
	}
	return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "no help for method %q", *cmd.Command)
}

// listAccounts handles a listaccounts request by returning a map of account
// names to their balances.
func (s *Server) listAccounts(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.ListAccountsCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	accountBalances := map[string]float64{}
	results, err := w.AccountBalances(ctx, int32(*cmd.MinConf))
	if err != nil {
		return nil, err
	}
	for _, result := range results {
		accountName, err := w.AccountName(ctx, result.Account)
		if err != nil {
			// Expect name lookup to succeed
			if errors.Is(err, errors.NotExist) {
				return nil, rpcError(dcrjson.ErrRPCInternal.Code, err)
			}
			return nil, err
		}
		accountBalances[accountName] = result.Spendable.ToCoin()
	}
	// Return the map.  This will be marshaled into a JSON object.
	return accountBalances, nil
}

// listLockUnspent handles a listlockunspent request by returning an slice of
// all locked outpoints.
func (s *Server) listLockUnspent(ctx context.Context, icmd any) (any, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	var account string
	cmd := icmd.(*types.ListLockUnspentCmd)
	if cmd.Account != nil {
		account = *cmd.Account
	}
	return w.LockedOutpoints(ctx, account)
}

// listReceivedByAccount handles a listreceivedbyaccount request by returning
// a slice of objects, each one containing:
//
//	"account": the receiving account;
//	"amount": total amount received by the account;
//	"confirmations": number of confirmations of the most recent transaction.
//
// It takes two parameters:
//
//	"minconf": minimum number of confirmations to consider a transaction -
//	           default: one;
//	"includeempty": whether or not to include addresses that have no transactions -
//	                default: false.
func (s *Server) listReceivedByAccount(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.ListReceivedByAccountCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	results, err := w.TotalReceivedForAccounts(ctx, int32(*cmd.MinConf))
	if err != nil {
		return nil, err
	}

	jsonResults := make([]types.ListReceivedByAccountResult, 0, len(results))
	for _, result := range results {
		jsonResults = append(jsonResults, types.ListReceivedByAccountResult{
			Account:       result.AccountName,
			Amount:        cointype.AtomsToDecimalString(big.NewInt(int64(result.TotalReceived)), big.NewInt(cointype.AtomsPerVAR)),
			Confirmations: uint64(result.LastConfirmation),
		})
	}
	return jsonResults, nil
}

// listReceivedByAddress handles a listreceivedbyaddress request by returning
// a slice of objects, each one containing:
//
//	"account": the account of the receiving address;
//	"address": the receiving address;
//	"amount": total amount received by the address;
//	"confirmations": number of confirmations of the most recent transaction.
//
// It takes two parameters:
//
//	"minconf": minimum number of confirmations to consider a transaction -
//	           default: one;
//	"includeempty": whether or not to include addresses that have no transactions -
//	                default: false.
func (s *Server) listReceivedByAddress(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.ListReceivedByAddressCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Intermediate data for each address.
	type AddrData struct {
		// Total amount received.
		amount dcrutil.Amount
		// Number of confirmations of the last transaction.
		confirmations int32
		// Hashes of transactions which include an output paying to the address
		tx []string
	}

	_, tipHeight := w.MainChainTip(ctx)

	// Intermediate data for all addresses.
	allAddrData := make(map[string]AddrData)
	// Create an AddrData entry for each active address in the account.
	// Otherwise we'll just get addresses from transactions later.
	sortedAddrs, err := w.SortedActivePaymentAddresses(ctx)
	if err != nil {
		return nil, err
	}
	for _, address := range sortedAddrs {
		// There might be duplicates, just overwrite them.
		allAddrData[address] = AddrData{}
	}

	minConf := *cmd.MinConf
	var endHeight int32
	if minConf == 0 {
		endHeight = -1
	} else {
		endHeight = tipHeight - int32(minConf) + 1
	}
	err = wallet.UnstableAPI(w).RangeTransactions(ctx, 0, endHeight, func(details []udb.TxDetails) (bool, error) {
		confirmations := confirms(details[0].Block.Height, tipHeight)
		for _, tx := range details {
			for _, cred := range tx.Credits {
				pkVersion := tx.MsgTx.TxOut[cred.Index].Version
				pkScript := tx.MsgTx.TxOut[cred.Index].PkScript
				_, addrs := stdscript.ExtractAddrs(pkVersion, pkScript, w.ChainParams())
				for _, addr := range addrs {
					addrStr := addr.String()
					addrData, ok := allAddrData[addrStr]
					if ok {
						addrData.amount += cred.Amount
						// Always overwrite confirmations with newer ones.
						addrData.confirmations = confirmations
					} else {
						addrData = AddrData{
							amount:        cred.Amount,
							confirmations: confirmations,
						}
					}
					addrData.tx = append(addrData.tx, tx.Hash.String())
					allAddrData[addrStr] = addrData
				}
			}
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}

	// Massage address data into output format.
	numAddresses := len(allAddrData)
	ret := make([]types.ListReceivedByAddressResult, numAddresses)
	idx := 0
	for address, addrData := range allAddrData {
		ret[idx] = types.ListReceivedByAddressResult{
			Address:       address,
			Amount:        cointype.AtomsToDecimalString(big.NewInt(int64(addrData.amount)), big.NewInt(cointype.AtomsPerVAR)),
			Confirmations: uint64(addrData.confirmations),
			TxIDs:         addrData.tx,
		}
		idx++
	}
	return ret, nil
}

// listSinceBlock handles a listsinceblock request by returning an array of maps
// with details of sent and received wallet transactions since the given block.
func (s *Server) listSinceBlock(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.ListSinceBlockCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	targetConf := int32(*cmd.TargetConfirmations)
	if targetConf < 1 {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "target_confirmations must be positive")
	}

	tipHash, tipHeight := w.MainChainTip(ctx)
	lastBlock := &tipHash
	if targetConf > 0 {
		id := wallet.NewBlockIdentifierFromHeight((tipHeight + 1) - targetConf)
		info, err := w.BlockInfo(ctx, id)
		if err != nil {
			return nil, err
		}

		lastBlock = &info.Hash
	}

	// TODO: This must begin at the fork point in the main chain, not the height
	// of this block.
	var end int32
	if cmd.BlockHash != nil {
		hash, err := chainhash.NewHashFromStr(*cmd.BlockHash)
		if err != nil {
			return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
		}
		header, err := w.BlockHeader(ctx, hash)
		if err != nil {
			return nil, err
		}
		end = int32(header.Height)
	}

	txInfoList, err := w.ListSinceBlock(ctx, -1, end, tipHeight)
	if err != nil {
		return nil, err
	}

	res := &types.ListSinceBlockResult{
		Transactions: txInfoList,
		LastBlock:    lastBlock.String(),
	}
	return res, nil
}

// listTransactions handles a listtransactions request by returning an
// array of maps with details of sent and recevied wallet transactions.
func (s *Server) listTransactions(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.ListTransactionsCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// TODO: ListTransactions does not currently understand the difference
	// between transactions pertaining to one account from another.  This
	// will be resolved when wtxmgr is combined with the waddrmgr namespace.

	if cmd.Account != nil && *cmd.Account != "*" {
		// For now, don't bother trying to continue if the user
		// specified an account, since this can't be (easily or
		// efficiently) calculated.
		return nil,
			errors.E(`Transactions can not be searched by account. ` +
				`Use "*" to reference all accounts.`)
	}

	return w.ListTransactions(ctx, *cmd.From, *cmd.Count)
}

// listAddressTransactions handles a listaddresstransactions request by
// returning an array of maps with details of spent and received wallet
// transactions.  The form of the reply is identical to listtransactions,
// but the array elements are limited to transaction details which are
// about the addresess included in the request.
func (s *Server) listAddressTransactions(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.ListAddressTransactionsCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	if cmd.Account != nil && *cmd.Account != "*" {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"listing transactions for addresses may only be done for all accounts")
	}

	// Decode addresses.
	hash160Map := make(map[string]struct{})
	for _, addrStr := range cmd.Addresses {
		addr, err := decodeAddress(addrStr, w.ChainParams())
		if err != nil {
			return nil, err
		}
		hash160er, ok := addr.(stdaddr.Hash160er)
		if !ok {
			// Not tracked by the wallet so skip reporting history
			// of this address.
			continue
		}
		hash160Map[string(hash160er.Hash160()[:])] = struct{}{}
	}

	return w.ListAddressTransactions(ctx, hash160Map)
}

// listAllTransactions handles a listalltransactions request by returning
// a map with details of sent and recevied wallet transactions.  This is
// similar to ListTransactions, except it takes only a single optional
// argument for the account name and replies with all transactions.
func (s *Server) listAllTransactions(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.ListAllTransactionsCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	if cmd.Account != nil && *cmd.Account != "*" {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"listing all transactions may only be done for all accounts")
	}

	return w.ListAllTransactions(ctx)
}

// listUnspent handles the listunspent command with optional coin type filtering.
func (s *Server) listUnspent(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.ListUnspentCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Validate coin type if specified
	if cmd.CoinType != nil {
		coinType := cointype.CoinType(*cmd.CoinType)
		if err := validateCoinTypeConfigured(w.ChainParams(), coinType); err != nil {
			return nil, err
		}
	}

	var addresses map[string]struct{}
	if cmd.Addresses != nil {
		addresses = make(map[string]struct{})
		// confirm that all of them are good:
		for _, as := range *cmd.Addresses {
			a, err := decodeAddress(as, w.ChainParams())
			if err != nil {
				return nil, err
			}
			addresses[a.String()] = struct{}{}
		}
	}

	var account string
	if cmd.Account != nil {
		account = *cmd.Account
	}

	// Push the coin-type filter into wallet.ListUnspent so it reads only the
	// requested per-coin-type bucket — no Go-side post-filter.
	var coinTypeFilter *cointype.CoinType
	if cmd.CoinType != nil {
		ct := cointype.CoinType(*cmd.CoinType)
		coinTypeFilter = &ct
	}
	result, err := w.ListUnspent(ctx, int32(*cmd.MinConf), int32(*cmd.MaxConf), addresses, account, coinTypeFilter)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAddressNotInWallet
		}
		return nil, err
	}
	return result, nil
}

// lockUnspent handles the lockunspent command.
func (s *Server) lockUnspent(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.LockUnspentCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	switch {
	case cmd.Unlock && len(cmd.Transactions) == 0:
		w.ResetLockedOutpoints()
	default:
		for _, input := range cmd.Transactions {
			txHash, err := chainhash.NewHashFromStr(input.Txid)
			if err != nil {
				return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
			}
			if cmd.Unlock {
				w.UnlockOutpoint(txHash, input.Vout)
			} else {
				w.LockOutpoint(txHash, input.Vout)
			}
		}
	}
	return true, nil
}

// purchaseTicket indicates to the wallet that a ticket should be purchased
// using all currently available funds. If the ticket could not be purchased
// because there are not enough eligible funds, an error will be returned.
func (s *Server) purchaseTicket(ctx context.Context, icmd any) (any, error) {
	// Enforce valid and positive spend limit.
	cmd := icmd.(*types.PurchaseTicketCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	n, err := w.NetworkBackend()
	if err != nil {
		return nil, err
	}

	spendLimit, err := dcrutil.NewAmount(cmd.SpendLimit)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCInvalidParameter, err)
	}
	if spendLimit < 0 {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "negative spend limit")
	}

	account, err := w.AccountNumber(ctx, cmd.FromAccount)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAccountNotFound
		}
		return nil, err
	}

	// Override the minimum number of required confirmations if specified
	// and enforce it is positive.
	minConf := int32(1)
	if cmd.MinConf != nil {
		minConf = int32(*cmd.MinConf)
		if minConf < 0 {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "negative minconf")
		}
	}

	numTickets := 1
	if cmd.NumTickets != nil {
		if *cmd.NumTickets > 1 {
			numTickets = *cmd.NumTickets
		}
	}

	// Set the expiry if specified.
	expiry := int32(0)
	if cmd.Expiry != nil {
		expiry = int32(*cmd.Expiry)
	}

	dontSignTx := false
	if cmd.DontSignTx != nil {
		dontSignTx = *cmd.DontSignTx
	}

	var mixedAccount uint32
	var mixedAccountBranch uint32
	var mixedSplitAccount uint32
	// Use purchasing account as change account by default (overridden below if
	// mixing is enabled).
	var changeAccount = account

	if s.cfg.MixingEnabled {
		mixedAccount, err = w.AccountNumber(ctx, s.cfg.MixAccount)
		if err != nil {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"Mixing enabled, but error on mixed account: %v", err)
		}
		mixedAccountBranch = s.cfg.MixBranch
		if mixedAccountBranch != 0 && mixedAccountBranch != 1 {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"MixedAccountBranch should be 0 or 1.")
		}
		mixedSplitAccount, err = w.AccountNumber(ctx, s.cfg.TicketSplitAccount)
		if err != nil {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"Mixing enabled, but error on mixedSplitAccount: %v", err)
		}
		changeAccount, err = w.AccountNumber(ctx, s.cfg.MixChangeAccount)
		if err != nil {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"Mixing enabled, but error on changeAccount: %v", err)
		}
	}

	var vspClient *wallet.VSPClient
	if s.cfg.VSPHost != "" {
		cfg := wallet.VSPClientConfig{
			URL:    s.cfg.VSPHost,
			PubKey: s.cfg.VSPPubKey,
			Policy: &wallet.VSPPolicy{
				MaxFee:     w.VSPMaxFee(),
				FeeAcct:    account,
				ChangeAcct: changeAccount,
			},
		}
		vspClient, err = w.VSP(cfg)
		if err != nil {
			return nil, rpcErrorf(dcrjson.ErrRPCMisc,
				"VSP Server instance failed to start: %v", err)
		}
	}

	request := &wallet.PurchaseTicketsRequest{
		Count:         numTickets,
		SourceAccount: account,
		MinConf:       minConf,
		Expiry:        expiry,
		DontSignTx:    dontSignTx,

		// CSPP
		Mixing:             s.cfg.MixingEnabled,
		MixedAccount:       mixedAccount,
		MixedAccountBranch: mixedAccountBranch,
		MixedSplitAccount:  mixedSplitAccount,
		ChangeAccount:      changeAccount,

		VSPClient: vspClient,
	}
	// Use the mixed account as voting account if mixing is enabled,
	// otherwise use the source account.
	if s.cfg.MixingEnabled {
		request.VotingAccount = mixedAccount
	} else {
		request.VotingAccount = account
	}

	ticketsResponse, err := w.PurchaseTickets(ctx, n, request)
	if err != nil {
		return nil, err
	}
	ticketsTx := ticketsResponse.Tickets
	splitTx := ticketsResponse.SplitTx

	// If dontSignTx is false, we return the TicketHashes of the published txs.
	if !dontSignTx {
		hashes := ticketsResponse.TicketHashes
		hashStrs := make([]string, len(hashes))
		for i := range hashes {
			hashStrs[i] = hashes[i].String()
		}

		return hashStrs, err
	}

	// Otherwise we return its unsigned tickets bytes and the splittx, so a
	// cold wallet can handle it.
	var stringBuilder strings.Builder
	unsignedTickets := make([]string, len(ticketsTx))
	for i, mtx := range ticketsTx {
		err = mtx.Serialize(hex.NewEncoder(&stringBuilder))
		if err != nil {
			return nil, err
		}
		unsignedTickets[i] = stringBuilder.String()
		stringBuilder.Reset()
	}

	err = splitTx.Serialize(hex.NewEncoder(&stringBuilder))
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCInvalidParameter, err)
	}

	splitTxString := stringBuilder.String()

	return types.CreateUnsignedTicketResult{
		UnsignedTickets: unsignedTickets,
		SplitTx:         splitTxString,
	}, nil
}

// processUnmanagedTicket takes a ticket hash as an argument and attempts to
// start managing it for the set vsp client from the config.
func (s *Server) processUnmanagedTicket(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.ProcessUnmanagedTicketCmd)

	if cmd.TicketHash == "" {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "ticket hash must be provided")
	}

	hash, err := chainhash.NewHashFromStr(cmd.TicketHash)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCInvalidParameter, err)
	}

	vspHost := s.cfg.VSPHost
	if vspHost == "" {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "vsphost must be set in options")
	}

	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	vspClient, err := w.LookupVSP(vspHost)
	if err != nil {
		return nil, err
	}

	ticket, err := w.NewVSPTicket(ctx, hash)
	if err != nil {
		return nil, err
	}

	err = vspClient.Process(ctx, ticket, nil)
	if err != nil {
		return nil, err
	}

	return nil, nil

}

// makeOutputsWithCoinTypeBig creates transaction outputs with specified coin type using big.Int amounts.
// This is essential for SKA transactions where amounts can exceed int64.
//
// Outputs are emitted in lexicographic order of the destination address so two
// identical sendmany calls produce identical on-the-wire transactions (and
// therefore identical tx hashes prior to change-position randomization). The
// underlying map iteration would otherwise be non-deterministic; the same
// deterministic ordering is applied in createrawtransaction at the addr-sort
// step.
func makeOutputsWithCoinTypeBig(pairs map[string]*big.Int, chainParams *chaincfg.Params, coinType cointype.CoinType) ([]*wire.TxOut, error) {
	addrs := make([]string, 0, len(pairs))
	for addrStr := range pairs {
		addrs = append(addrs, addrStr)
	}
	sort.Strings(addrs)
	outputs := make([]*wire.TxOut, 0, len(pairs))
	for _, addrStr := range addrs {
		amt := pairs[addrStr]
		if amt == nil || amt.Sign() <= 0 {
			return nil, errNeedPositiveAmount
		}
		addr, err := decodeAddress(addrStr, chainParams)
		if err != nil {
			return nil, err
		}

		vers, pkScript := addr.PaymentScript()

		txOut := &wire.TxOut{
			PkScript: pkScript,
			Version:  vers,
			CoinType: coinType,
		}

		// For SKA, use SKAValue (big.Int); for VAR, use Value (int64) with
		// an explicit overflow guard — silently truncating an oversize
		// big.Int via Int64() would author a transaction whose VAR output
		// is some negative or wraparound value.
		if coinType.IsSKA() {
			txOut.Value = 0 // SKA uses SKAValue, not Value
			txOut.SKAValue = new(big.Int).Set(amt)
		} else {
			if !amt.IsInt64() {
				return nil, fmt.Errorf("VAR amount %s exceeds int64 capacity", amt.String())
			}
			txOut.Value = amt.Int64()
		}

		outputs = append(outputs, txOut)
	}
	return outputs, nil
}

// sendPairsWithCoinTypeBig creates and sends payment transactions with coin type support using big.Int amounts.
// This is essential for SKA transactions where amounts can exceed int64.
//
// subtractFeeFromAmountIdx selects an output by index whose value should be
// reduced by the tx fee (Bitcoin Core's subtractfeefromamount). Pass -1 to
// disable. Multi-recipient callers (sendmany) currently always pass -1.
func (s *Server) sendPairsWithCoinTypeBig(ctx context.Context, w *wallet.Wallet, amounts map[string]*big.Int, account uint32, minconf int32, coinType cointype.CoinType, subtractFeeFromAmountIdx int) (string, error) {
	changeAccount := account
	if s.cfg.MixingEnabled && s.cfg.MixAccount != "" && s.cfg.MixChangeAccount != "" {
		mixAccount, err := w.AccountNumber(ctx, s.cfg.MixAccount)
		if err != nil {
			return "", err
		}
		if account == mixAccount {
			changeAccount, err = w.AccountNumber(ctx, s.cfg.MixChangeAccount)
			if err != nil {
				return "", err
			}
		}
	}

	outputs, err := makeOutputsWithCoinTypeBig(amounts, w.ChainParams(), coinType)
	if err != nil {
		return "", err
	}

	// Use existing SendOutputs method (coin type is embedded in outputs)
	txSha, err := w.SendOutputs(ctx, outputs, account, changeAccount, minconf, subtractFeeFromAmountIdx)
	if err != nil {
		if errors.Is(err, errors.Locked) {
			return "", errWalletUnlockNeeded
		}
		if errors.Is(err, errors.InsufficientBalance) {
			return "", rpcError(dcrjson.ErrRPCWalletInsufficientFunds, err)
		}
		return "", err
	}

	return txSha.String(), nil
}

// sendAmountToTreasury creates and sends payment transactions to the treasury.
// It returns the transaction hash in string format upon success All errors are
// returned in dcrjson.RPCError format
func (s *Server) sendAmountToTreasury(ctx context.Context, w *wallet.Wallet, amount dcrutil.Amount, account uint32, minconf int32) (string, error) {
	changeAccount := account
	if s.cfg.MixingEnabled {
		mixAccount, err := w.AccountNumber(ctx, s.cfg.MixAccount)
		if err != nil {
			return "", err
		}
		if account == mixAccount {
			changeAccount, err = w.AccountNumber(ctx,
				s.cfg.MixChangeAccount)
			if err != nil {
				return "", err
			}
		}
	}

	outputs := []*wire.TxOut{
		{
			Value:    int64(amount),
			PkScript: []byte{txscript.OP_TADD},
			Version:  wire.DefaultPkScriptVersion,
			CoinType: cointype.CoinTypeVAR,
		},
	}
	txSha, err := w.SendOutputsToTreasury(ctx, outputs, account,
		changeAccount, minconf)
	if err != nil {
		if errors.Is(err, errors.Locked) {
			return "", errWalletUnlockNeeded
		}
		if errors.Is(err, errors.InsufficientBalance) {
			return "", rpcError(dcrjson.ErrRPCWalletInsufficientFunds,
				err)
		}
		return "", err
	}

	return txSha.String(), nil
}

// sendOutputsFromTreasury creates and sends payment transactions from the treasury.
// It returns the transaction hash in string format upon success All errors are
// returned in dcrjson.RPCError format
func (s *Server) sendOutputsFromTreasury(ctx context.Context, w *wallet.Wallet, cmd types.SendFromTreasuryCmd) (string, error) {
	// Look to see if the we have the private key imported.
	publicKey, err := decodeAddress(cmd.Key, w.ChainParams())
	if err != nil {
		return "", err
	}
	privKey, zero, err := w.LoadPrivateKey(ctx, publicKey)
	if err != nil {
		return "", err
	}
	defer zero()

	_, tipHeight := w.MainChainTip(ctx)

	// OP_RETURN <8 Bytes ValueIn><24 byte random>. The encoded ValueIn is
	// added at the end of this function.
	var payload [32]byte
	rand.Read(payload[8:])
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_RETURN)
	builder.AddData(payload[:])
	opretScript, err := builder.Script()
	if err != nil {
		return "", rpcErrorf(dcrjson.ErrRPCInternal.Code,
			"sendOutputsFromTreasury NewScriptBuilder: %v", err)
	}
	msgTx := wire.NewMsgTx()
	msgTx.Version = wire.TxVersionTreasury
	opretOut := wire.NewTxOut(0, opretScript)
	opretOut.CoinType = cointype.CoinTypeVAR // treasury OP_RETURN is VAR
	msgTx.AddTxOut(opretOut)

	// Calculate expiry.
	msgTx.Expiry = blockchain.CalcTSpendExpiry(int64(tipHeight+1),
		w.ChainParams().TreasuryVoteInterval,
		w.ChainParams().TreasuryVoteIntervalMultiplier)

	// OP_TGEN and calculate totals.
	var totalPayout dcrutil.Amount
	for address, amount := range cmd.Amounts {
		amt, err := dcrutil.NewAmount(amount)
		if err != nil {
			return "", rpcError(dcrjson.ErrRPCInvalidParameter, err)
		}

		// While looping calculate total amount
		totalPayout += amt

		// Decode address.
		addr, err := decodeStakeAddress(address, w.ChainParams())
		if err != nil {
			return "", err
		}

		// Create OP_TGEN prefixed script.
		vers, script := addr.PayFromTreasuryScript()

		// Make sure this is not dust.
		txOut := &wire.TxOut{
			Value:    int64(amt),
			Version:  vers,
			PkScript: script,
			CoinType: cointype.CoinTypeVAR,
		}
		if txrules.IsDustOutput(txOut, w.RelayFee()) {
			return "", rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"Amount is dust: %v %v", addr, amt)
		}

		// Add to transaction.
		msgTx.AddTxOut(txOut)
	}

	// Calculate fee. Inputs are <signature> <compressed key> OP_TSPEND.
	estimatedFee := txsizes.EstimateSerializeSize([]int{txsizes.TSPENDInputSize},
		msgTx.TxOut, 0)
	fee := txrules.FeeForSerializeSize(w.RelayFee(), estimatedFee)

	// Assemble TxIn.
	msgTx.AddTxIn(&wire.TxIn{
		// Stakebase transactions have no inputs, so previous outpoint
		// is zero hash and max index.
		PreviousOutPoint: *wire.NewOutPoint(&chainhash.Hash{},
			wire.MaxPrevOutIndex, wire.TxTreeRegular),
		Sequence:        wire.MaxTxInSequenceNum,
		ValueIn:         int64(fee) + int64(totalPayout),
		BlockHeight:     wire.NullBlockHeight,
		BlockIndex:      wire.NullBlockIndex,
		SignatureScript: []byte{}, // Empty for now
	})

	// Encode total amount in first 8 bytes of TxOut[0] OP_RETURN.
	binary.LittleEndian.PutUint64(msgTx.TxOut[0].PkScript[2:2+8],
		uint64(fee)+uint64(totalPayout))

	// Calculate TSpend signature without SigHashType.
	privKeyBytes := privKey.Serialize()
	sigscript, err := sign.TSpendSignatureScript(msgTx, privKeyBytes)
	if err != nil {
		return "", err
	}
	msgTx.TxIn[0].SignatureScript = sigscript

	_, _, err = stake.CheckTSpend(msgTx)
	if err != nil {
		return "", err
	}

	// Send to mond.
	n, ok := s.walletLoader.NetworkBackend()
	if !ok {
		return "", errNoNetwork
	}
	err = n.PublishTransactions(ctx, msgTx)
	if err != nil {
		return "", err
	}

	return msgTx.TxHash().String(), nil
}

// treasuryPolicy returns voting policies for treasury spends by a particular
// key.  If a key is specified, that policy is returned; otherwise the policies
// for all keys are returned in an array.  If both a key and ticket hash are
// provided, the per-ticket key policy is returned.
func (s *Server) treasuryPolicy(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.TreasuryPolicyCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	var ticketHash *chainhash.Hash
	if cmd.Ticket != nil && *cmd.Ticket != "" {
		var err error
		ticketHash, err = chainhash.NewHashFromStr(*cmd.Ticket)
		if err != nil {
			return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
		}
	}

	if cmd.Key != nil && *cmd.Key != "" {
		pikey, err := hex.DecodeString(*cmd.Key)
		if err != nil {
			return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
		}
		var policy string
		switch w.TreasuryKeyPolicy(pikey, ticketHash) {
		case stake.TreasuryVoteYes:
			policy = "yes"
		case stake.TreasuryVoteNo:
			policy = "no"
		default:
			policy = "abstain"
		}
		res := &types.TreasuryPolicyResult{
			Key:    *cmd.Key,
			Policy: policy,
		}
		if cmd.Ticket != nil {
			res.Ticket = *cmd.Ticket
		}
		return res, nil
	}

	policies := w.TreasuryKeyPolicies()
	res := make([]types.TreasuryPolicyResult, 0, len(policies))
	for i := range policies {
		var policy string
		switch policies[i].Policy {
		case stake.TreasuryVoteYes:
			policy = "yes"
		case stake.TreasuryVoteNo:
			policy = "no"
		}
		r := types.TreasuryPolicyResult{
			Key:    hex.EncodeToString(policies[i].PiKey),
			Policy: policy,
		}
		if policies[i].Ticket != nil {
			r.Ticket = policies[i].Ticket.String()
		}
		res = append(res, r)
	}
	return res, nil
}

// setDisapprovePercent sets the wallet's disapprove percentage.
func (s *Server) setDisapprovePercent(ctx context.Context, icmd any) (any, error) {
	if s.activeNet.Net == wire.MainNet {
		return nil, dcrjson.ErrInvalidRequest
	}
	cmd := icmd.(*types.SetDisapprovePercentCmd)
	if cmd.Percent > 100 {
		return nil, rpcError(dcrjson.ErrRPCInvalidParameter,
			errors.New("percent must be from 0 to 100"))
	}
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}
	w.SetDisapprovePercent(cmd.Percent)
	return nil, nil
}

// setTreasuryPolicy saves the voting policy for treasury spends by a particular
// key, and optionally, setting the key policy used by a specific ticket.
//
// If a VSP host is configured in the application settings, the voting
// preferences will also be set with the VSP.
func (s *Server) setTreasuryPolicy(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.SetTreasuryPolicyCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	var ticketHash *chainhash.Hash
	if cmd.Ticket != nil && *cmd.Ticket != "" {
		if len(*cmd.Ticket) != chainhash.MaxHashStringSize {
			err := fmt.Errorf("invalid ticket hash length, expected %d got %d",
				chainhash.MaxHashStringSize, len(*cmd.Ticket))
			return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
		}
		var err error
		ticketHash, err = chainhash.NewHashFromStr(*cmd.Ticket)
		if err != nil {
			return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
		}
	}

	pikey, err := hex.DecodeString(cmd.Key)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
	}
	if len(pikey) != secp256k1.PubKeyBytesLenCompressed {
		err := errors.New("treasury key must be 33 bytes")
		return nil, rpcError(dcrjson.ErrRPCInvalidParameter, err)
	}
	var policy stake.TreasuryVoteT
	switch cmd.Policy {
	case "abstain", "invalid", "":
		policy = stake.TreasuryVoteInvalid
	case "yes":
		policy = stake.TreasuryVoteYes
	case "no":
		policy = stake.TreasuryVoteNo
	default:
		err := fmt.Errorf("unknown policy %q", cmd.Policy)
		return nil, rpcError(dcrjson.ErrRPCInvalidParameter, err)
	}

	err = w.SetTreasuryKeyPolicy(ctx, pikey, policy, ticketHash)
	if err != nil {
		return nil, err
	}

	// Update voting preferences on VSPs if required.
	policyMap := map[string]string{
		cmd.Key: cmd.Policy,
	}
	err = s.updateVSPVoteChoices(ctx, w, ticketHash, nil, nil, policyMap)

	return nil, err
}

// tspendPolicy returns voting policies for particular treasury spends
// transactions.  If a tspend transaction hash is specified, that policy is
// returned; otherwise the policies for all known tspends are returned in an
// array.  If both a tspend transaction hash and a ticket hash are provided,
// the per-ticket tspend policy is returned.
func (s *Server) tspendPolicy(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.TSpendPolicyCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	var ticketHash *chainhash.Hash
	if cmd.Ticket != nil && *cmd.Ticket != "" {
		var err error
		ticketHash, err = chainhash.NewHashFromStr(*cmd.Ticket)
		if err != nil {
			return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
		}
	}

	if cmd.Hash != nil && *cmd.Hash != "" {
		hash, err := chainhash.NewHashFromStr(*cmd.Hash)
		if err != nil {
			return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
		}
		var policy string
		switch w.TSpendPolicy(hash, ticketHash) {
		case stake.TreasuryVoteYes:
			policy = "yes"
		case stake.TreasuryVoteNo:
			policy = "no"
		default:
			policy = "abstain"
		}
		res := &types.TSpendPolicyResult{
			Hash:   *cmd.Hash,
			Policy: policy,
		}
		if cmd.Ticket != nil {
			res.Ticket = *cmd.Ticket
		}
		return res, nil
	}

	tspends := w.GetAllTSpends(ctx)
	res := make([]types.TSpendPolicyResult, 0, len(tspends))
	for i := range tspends {
		tspendHash := tspends[i].TxHash()
		p := w.TSpendPolicy(&tspendHash, ticketHash)

		var policy string
		switch p {
		case stake.TreasuryVoteYes:
			policy = "yes"
		case stake.TreasuryVoteNo:
			policy = "no"
		}
		r := types.TSpendPolicyResult{
			Hash:   tspendHash.String(),
			Policy: policy,
		}
		if cmd.Ticket != nil {
			r.Ticket = *cmd.Ticket
		}
		res = append(res, r)
	}
	return res, nil
}

// setTSpendPolicy saves the voting policy for a particular tspend transaction
// hash, and optionally, setting the tspend policy used by a specific ticket.
//
// If a VSP host is configured in the application settings, the voting
// preferences will also be set with the VSP.
func (s *Server) setTSpendPolicy(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.SetTSpendPolicyCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	if len(cmd.Hash) != chainhash.MaxHashStringSize {
		err := fmt.Errorf("invalid tspend hash length, expected %d got %d",
			chainhash.MaxHashStringSize, len(cmd.Hash))
		return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
	}

	hash, err := chainhash.NewHashFromStr(cmd.Hash)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
	}

	var ticketHash *chainhash.Hash
	if cmd.Ticket != nil && *cmd.Ticket != "" {
		if len(*cmd.Ticket) != chainhash.MaxHashStringSize {
			err := fmt.Errorf("invalid ticket hash length, expected %d got %d",
				chainhash.MaxHashStringSize, len(*cmd.Ticket))
			return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
		}
		var err error
		ticketHash, err = chainhash.NewHashFromStr(*cmd.Ticket)
		if err != nil {
			return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
		}
	}

	var policy stake.TreasuryVoteT
	switch cmd.Policy {
	case "abstain", "invalid", "":
		policy = stake.TreasuryVoteInvalid
	case "yes":
		policy = stake.TreasuryVoteYes
	case "no":
		policy = stake.TreasuryVoteNo
	default:
		err := fmt.Errorf("unknown policy %q", cmd.Policy)
		return nil, rpcError(dcrjson.ErrRPCInvalidParameter, err)
	}

	err = w.SetTSpendPolicy(ctx, hash, policy, ticketHash)
	if err != nil {
		return nil, err
	}

	// Update voting preferences on VSPs if required.
	policyMap := map[string]string{
		cmd.Hash: cmd.Policy,
	}
	err = s.updateVSPVoteChoices(ctx, w, ticketHash, nil, policyMap, nil)
	return nil, err
}

// redeemMultiSigOut receives a transaction hash/idx and fetches the first output
// index or indices with known script hashes from the transaction. It then
// construct a transaction with a single P2PKH paying to a specified address.
// It signs any inputs that it can, then provides the raw transaction to
// the user to export to others to sign.
func (s *Server) redeemMultiSigOut(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.RedeemMultiSigOutCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// If the caller supplied a cointype, validate it now; the on-chain match
	// check happens after FetchP2SHMultiSigOutput below. When omitted, the
	// coin type is defaulted from the on-chain record so an SKA multisig
	// redemption doesn't silently get built as a VAR transaction.
	var requestedCT *cointype.CoinType
	if cmd.CoinType != nil {
		c := cointype.CoinType(*cmd.CoinType)
		if err := validateCoinTypeConfigured(w.ChainParams(), c); err != nil {
			return nil, err
		}
		requestedCT = &c
	}

	// Convert the address to a useable format. If
	// we have no address, create a new address in
	// this wallet to send the output to.
	var addr stdaddr.Address
	var err error
	if cmd.Address != nil {
		addr, err = decodeAddress(*cmd.Address, w.ChainParams())
		if err != nil {
			return nil, err
		}
	} else {
		account := uint32(udb.DefaultAccountNum)
		addr, err = w.NewInternalAddress(ctx, account, wallet.WithGapPolicyWrap())
		if err != nil {
			return nil, err
		}
	}

	// Lookup the multisignature output and get the amount
	// along with the script for that transaction. Then,
	// begin crafting a MsgTx.
	hash, err := chainhash.NewHashFromStr(cmd.Hash)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCInvalidParameter, err)
	}
	op := wire.OutPoint{
		Hash:  *hash,
		Index: cmd.Index,
		Tree:  cmd.Tree,
	}
	p2shOutput, err := w.FetchP2SHMultiSigOutput(ctx, &op)
	if err != nil {
		return nil, err
	}

	ct := p2shOutput.CoinType
	if requestedCT != nil && *requestedCT != p2shOutput.CoinType {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"cointype %d does not match on-chain output cointype %d",
			*requestedCT, p2shOutput.CoinType)
	}

	sc := stdscript.DetermineScriptType(scriptVersionAssumed, p2shOutput.RedeemScript)
	if sc != stdscript.STMultiSig {
		return nil, errors.E("P2SH redeem script is not multisig")
	}
	msgTx := wire.NewMsgTx()
	var txIn *wire.TxIn
	if ct.IsSKA() {
		// SKA inputs carry their atom value in SKAValueIn (big.Int); Value
		// stays 0 in the V13 wire format. Defensive-copy so the wire-level
		// tx owns its own *big.Int — matches the convention at
		// multisig.go:120, methods.go:5286, methods.go:7888.
		txIn = wire.NewTxIn(&op, 0, nil)
		txIn.SKAValueIn = new(big.Int).Set(p2shOutput.SKAOutputAmount.BigInt())
	} else {
		txIn = wire.NewTxIn(&op, int64(p2shOutput.OutputAmount), nil)
	}
	msgTx.AddTxIn(txIn)

	_, pkScript := addr.PaymentScript()

	err = w.PrepareRedeemMultiSigOutTxOutput(ctx, msgTx, p2shOutput, &pkScript, ct)
	if err != nil {
		return nil, err
	}

	// Start creating the SignRawTransactionCmd.
	_, outpointScript := p2shOutput.P2SHAddress.PaymentScript()
	outpointScriptStr := hex.EncodeToString(outpointScript)

	rti := types.RawTxInput{
		Txid:         cmd.Hash,
		Vout:         cmd.Index,
		Tree:         cmd.Tree,
		ScriptPubKey: outpointScriptStr,
		RedeemScript: "",
		// SKA inputs: pass the value through explicitly rather than relying on
		// SKAValueIn surviving the upcoming msgTx → hex → msgTx round-trip.
		// The wire format round-trips SKAValueIn today, but an explicit
		// RawTxInput.SKAValueIn (decimal-coin string) is robust against any
		// future wire-level or intermediate-transform change that drops it.
		SKAValueIn: p2shSKAValueInStr(p2shOutput, ct, w.ChainParams()),
	}
	rtis := []types.RawTxInput{rti}

	var b strings.Builder
	b.Grow(2 * msgTx.SerializeSize())
	err = msgTx.Serialize(hex.NewEncoder(&b))
	if err != nil {
		return nil, err
	}
	sigHashAll := "ALL"

	srtc := &types.SignRawTransactionCmd{
		RawTx:    b.String(),
		Inputs:   &rtis,
		PrivKeys: &[]string{},
		Flags:    &sigHashAll,
	}

	// Sign it and give the results to the user.
	signedTxResult, err := s.signRawTransaction(ctx, srtc)
	if signedTxResult == nil || err != nil {
		return nil, err
	}
	srtTyped := signedTxResult.(types.SignRawTransactionResult)
	return types.RedeemMultiSigOutResult(srtTyped), nil
}

// redeemMultisigOuts receives a script hash (in the form of a
// script hash address), looks up all the unspent outpoints associated
// with that address, then generates a list of partially signed
// transactions spending to either an address specified or internal
// addresses in this wallet.
func (s *Server) redeemMultiSigOuts(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.RedeemMultiSigOutsCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Validate cmd.CoinType up front if supplied. When omitted, the
	// per-output call defaults from each output's on-chain CoinType — never
	// silently to VAR.
	if cmd.CoinType != nil {
		c := cointype.CoinType(*cmd.CoinType)
		if err := validateCoinTypeConfigured(w.ChainParams(), c); err != nil {
			return nil, err
		}
	}

	// Get all the multisignature outpoints that are unspent for this
	// address.
	addr, err := decodeAddress(cmd.FromScrAddress, w.ChainParams())
	if err != nil {
		return nil, err
	}
	p2shAddr, ok := addr.(*stdaddr.AddressScriptHashV0)
	if !ok {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "address is not P2SH")
	}
	msos, err := wallet.UnstableAPI(w).UnspentMultisigCreditsForAddress(ctx, p2shAddr)
	if err != nil {
		return nil, err
	}

	// Defensive filter: confirm each candidate against the node's UTXO view
	// before authoring a redemption. A wallet-authored multisig tx that fails
	// to publish leaves a phantom entry in bucketMultisigUsp; without this
	// step we'd emit a raw transaction spending an output that doesn't exist
	// on chain (see RemoveUnconfirmed in wallet/udb/txunmined.go for the
	// root-cause fix that prevents new phantoms).
	// A nil network backend (SPV-only / no node connection) is expected and
	// handled by chainSyncerQueryFunc: it returns a nil query and the filter
	// passes msos through unverified with a WARN log. The discarded ok values
	// are intentional.
	n, _ := s.walletLoader.NetworkBackend()
	chainSyncer, _ := n.(*chain.Syncer)
	live, skipped := filterLiveMultisigCredits(ctx, msos, chainSyncerQueryFunc(chainSyncer))

	// Resolve the per-call iteration cap. Whether more outputs remain after
	// coin-type filtering is determined by the collect function below.
	max := resolveRedeemMultiSigOutsCap(cmd.Number)

	rmsoResults, truncated := redeemMultiSigOutsCollect(ctx, live, max, cmd.ToAddress, cmd.CoinType,
		func(ctx context.Context, req *types.RedeemMultiSigOutCmd) (types.RedeemMultiSigOutResult, error) {
			res, err := s.redeemMultiSigOut(ctx, req)
			if err != nil {
				return types.RedeemMultiSigOutResult{}, err
			}
			return res.(types.RedeemMultiSigOutResult), nil
		})

	return types.RedeemMultiSigOutsResult{Results: rmsoResults, Truncated: truncated, Skipped: skipped}, nil
}

// multisigChainQuery resolves a single multisig outpoint against the node's
// UTXO set, returning (nil, nil) if the output is spent or never existed —
// matching the contract of mond's gettxout. A non-nil error signals the chain
// is unreachable and the caller should treat all credits as live (the SPV /
// no-node-connection fallback).
type multisigChainQuery func(ctx context.Context, op *wire.OutPoint) (*mondtypes.GetTxOutResult, error)

// chainSyncerQueryFunc wraps a chain.Syncer into a multisigChainQuery. When the
// syncer is nil (no node connection / SPV-only mode), the returned query is nil
// so callers can detect "no chain to consult" and skip filtering.
func chainSyncerQueryFunc(cs *chain.Syncer) multisigChainQuery {
	if cs == nil {
		return nil
	}
	return func(ctx context.Context, op *wire.OutPoint) (*mondtypes.GetTxOutResult, error) {
		// includeMempool=true is intentional. A redemption authored against
		// a multisig credit whose parent tx is still in mempool must not be
		// dropped as "phantom" — the parent has been broadcast and the
		// wallet legitimately needs to spend it. The residual race (parent
		// gets evicted before the redemption is mined and the redemption
		// becomes invalid) is acceptable: it has the same shape as any
		// unmined-spend flow and the wallet retries. Do not "tighten" this
		// to false thinking it strengthens validation — it breaks the
		// just-broadcast-but-not-yet-mined path.
		return cs.GetTxOut(ctx, &op.Hash, op.Index, op.Tree, true)
	}
}

// filterLiveMultisigCredits partitions the wallet's recorded multisig credits
// into those the node confirms are unspent (live) and those it does not
// (skipped). When query is nil the chain cannot be consulted: returns msos
// unchanged with an empty skipped list and a single WARN log so operators
// know verification was bypassed. Per-credit query errors are logged but do
// not block the credit — failing closed would deny recovery on transient RPC
// flakes, which matters more for a recovery RPC than perfect accuracy.
func filterLiveMultisigCredits(ctx context.Context, msos []*udb.MultisigCredit,
	query multisigChainQuery) ([]*udb.MultisigCredit, []types.SkippedMultisigOutpoint) {

	if query == nil {
		if len(msos) > 0 {
			log.Warnf("redeemmultisigouts: chain query unavailable; returning %d "+
				"credits unverified (no node connection or SPV-only mode)", len(msos))
		}
		return msos, nil
	}

	// Fan-out the per-credit lookups concurrently. Pattern mirrors the
	// signrawtransaction prevout fetch at methods.go:6847-6880.
	//
	// SetLimit caps in-flight gettxout calls: a wallet with thousands of
	// accumulated multisig credits would otherwise stampede mond's RPC pool
	// before the 256-cap in resolveRedeemMultiSigOutsCap fires (it runs after
	// this filter). 16 keeps latency reasonable (~16 round-trip waves over a
	// 256-credit batch) without saturating typical node configurations.
	//
	// Each call gets a per-credit 5s timeout so a single hung query does not
	// stall g.Wait until the caller's outer context expires; on deadline we
	// fall through to the "treat as live" branch below, preserving recovery
	// behaviour on flaky nodes.
	results := make([]*mondtypes.GetTxOutResult, len(msos))
	errs := make([]error, len(msos))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(16)
	for i, mso := range msos {
		i, mso := i, mso
		g.Go(func() error {
			qctx, cancel := context.WithTimeout(gctx, 5*time.Second)
			defer cancel()
			res, err := query(qctx, mso.OutPoint)
			results[i] = res
			errs[i] = err
			return nil // never abort the batch on a single failure
		})
	}
	_ = g.Wait()

	live := make([]*udb.MultisigCredit, 0, len(msos))
	var skipped []types.SkippedMultisigOutpoint
	for i, mso := range msos {
		switch {
		case errs[i] != nil:
			log.Warnf("redeemmultisigouts: gettxout failed for %v: %v — "+
				"treating credit as live and continuing", mso.OutPoint, errs[i])
			live = append(live, mso)
		case results[i] == nil:
			log.Warnf("redeemmultisigouts: phantom multisig credit %v "+
				"(coinType=%d, scriptHash=%x): node reports output as spent "+
				"or never existed — skipping", mso.OutPoint, mso.CoinType,
				mso.ScriptHash[:])
			skipped = append(skipped, types.SkippedMultisigOutpoint{
				Hash:     mso.OutPoint.Hash.String(),
				Vout:     mso.OutPoint.Index,
				Tree:     mso.OutPoint.Tree,
				CoinType: uint8(mso.CoinType),
				Reason:   "output not unspent on chain",
			})
		default:
			live = append(live, mso)
		}
	}
	return live, skipped
}

// redeemMultiSigOutsCollect iterates the cap-bounded multisig credits and
// invokes the per-output redeemer. Per-output failures are recorded on the
// result with Complete=false and the error in Errors[] rather than aborting
// the batch. This is the testable core of redeemMultiSigOuts.
//
// Each per-output request is built with the credit's own CoinType
// (mso.CoinType), not the outer cmd.CoinType. Routing every credit through
// the caller-supplied hint dropped SKA credits onto the VAR fee/output path
// when cmd.CoinType was nil and produced malformed transactions.
//
// The outer coinType parameter is repurposed as an optional filter: when
// non-nil, credits whose mso.CoinType does not match are skipped (these
// belong to a different coin type than the caller asked about).
//
// The returned truncated flag is true only when the cap is reached and at
// least one further matching credit (post-filter) remains unprocessed. This
// matters in mixed-coin-type wallets: a pre-filter "len(msos) > max" would
// overstate truncation when most credits are filtered out, causing
// pagination clients to loop forever.
func redeemMultiSigOutsCollect(
	ctx context.Context,
	msos []*udb.MultisigCredit,
	max uint32,
	toAddress *string,
	coinType *uint8,
	redeem func(context.Context, *types.RedeemMultiSigOutCmd) (types.RedeemMultiSigOutResult, error),
) ([]types.RedeemMultiSigOutResult, bool) {
	results := make([]types.RedeemMultiSigOutResult, 0, max)
	emitted := uint32(0)
	truncated := false
	for _, mso := range msos {
		ct := uint8(mso.CoinType)
		if coinType != nil && *coinType != ct {
			continue
		}
		if emitted >= max {
			// Cap was reached and at least one more matching credit
			// remains: signal pagination to the client.
			truncated = true
			break
		}
		// Bind &ct per-iteration: a single shared address would alias
		// across every request and the redeemer sees the wrong type for
		// all but the last credit.
		ctPerCredit := ct
		req := &types.RedeemMultiSigOutCmd{
			Hash:     mso.OutPoint.Hash.String(),
			Index:    mso.OutPoint.Index,
			Tree:     mso.OutPoint.Tree,
			Address:  toAddress,
			CoinType: &ctPerCredit,
		}
		emitted++
		res, err := redeem(ctx, req)
		if err != nil {
			// Per-output failure: record and continue. Earlier successes are
			// preserved; later outputs still get attempted.
			results = append(results, types.RedeemMultiSigOutResult{
				Complete: false,
				Errors: []types.SignRawTransactionError{{
					TxID:  mso.OutPoint.Hash.String(),
					Vout:  mso.OutPoint.Index,
					Error: err.Error(),
				}},
			})
			continue
		}
		results = append(results, res)
	}
	return results, truncated
}

// rescanWallet initiates a rescan of the block chain for wallet data, blocking
// until the rescan completes or exits with an error.
func (s *Server) rescanWallet(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.RescanWalletCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	n, ok := s.walletLoader.NetworkBackend()
	if !ok {
		return nil, errNoNetwork
	}

	err := w.RescanFromHeight(ctx, n, int32(*cmd.BeginHeight))
	return nil, err
}

// spendOutputsInputSource creates an input source from a wallet and a list of
// outputs to be spent.  Only the provided outputs will be returned by the
// source, without any other input selection. Every previous output must
// match expectedCoinType, and SKA inputs accumulate into detail.SKAAmount
// (big.Int) while VAR inputs accumulate into detail.Amount (int64) — the
// dual-coin txauthor.NewUnsignedTransaction reads from the matching field.
func spendOutputsInputSource(ctx context.Context, w *wallet.Wallet,
	account string, inputs []*wire.TxIn, expectedCoinType cointype.CoinType) (txauthor.InputSource, error) {

	params := w.ChainParams()

	detail := new(txauthor.InputDetail)
	detail.Inputs = inputs
	detail.Scripts = make([][]byte, len(inputs))
	detail.RedeemScriptSizes = make([]int, len(inputs))
	skaTotal := cointype.Zero()
	for i, in := range inputs {
		prevOut, err := w.FetchOutput(ctx, &in.PreviousOutPoint)
		if err != nil {
			return nil, err
		}
		if prevOut.CoinType != expectedCoinType {
			return nil, errors.E(errors.Invalid, errors.Errorf(
				"input %v coin type %d does not match expected coin type %d",
				&in.PreviousOutPoint, prevOut.CoinType, expectedCoinType))
		}
		if expectedCoinType.IsSKA() {
			if prevOut.SKAValue != nil {
				in.SKAValueIn = new(big.Int).Set(prevOut.SKAValue)
				skaTotal = skaTotal.Add(cointype.NewSKAAmount(prevOut.SKAValue))
			}
		} else {
			detail.Amount += dcrutil.Amount(prevOut.Value)
		}
		detail.Scripts[i] = prevOut.PkScript
		st, addrs := stdscript.ExtractAddrs(prevOut.Version,
			prevOut.PkScript, params)
		var addr stdaddr.Address
		var redeemScriptSize int
		switch st {
		case stdscript.STPubKeyHashEcdsaSecp256k1:
			addr = addrs[0]
			redeemScriptSize = txsizes.RedeemP2PKHInputSize
		default:
			// XXX: don't assume P2PKH, support other script types
			return nil, errors.E("unsupport address type")
		}
		ka, err := w.KnownAddress(ctx, addr)
		if err != nil {
			return nil, err
		}
		if ka.AccountName() != account {
			err := errors.Errorf("output address of %v does not "+
				"belong to account %q", &in.PreviousOutPoint,
				account)
			return nil, errors.E(errors.Invalid, err)
		}
		detail.RedeemScriptSizes[i] = redeemScriptSize
	}
	detail.SKAAmount = skaTotal

	fn := func(target dcrutil.Amount, targetSKA cointype.SKAAmount) (*txauthor.InputDetail, error) {
		return detail, nil
	}
	return fn, nil
}

type accountChangeSource struct {
	ctx     context.Context
	wallet  *wallet.Wallet
	account uint32
	addr    stdaddr.Address
}

func (a *accountChangeSource) Script() (script []byte, version uint16, err error) {
	if a.addr == nil {
		addr, err := a.wallet.NewChangeAddress(a.ctx, a.account)
		if err != nil {
			return nil, 0, err
		}
		a.addr = addr
	}

	version, script = a.addr.PaymentScript()
	return
}

func (a *accountChangeSource) ScriptSize() int {
	// XXX: shouldn't assume P2PKH
	return txsizes.P2PKHOutputSize
}

// spendOutputs creates, signs and publishes a transaction that spends the
// specified outputs belonging to an account, pays a list of address/amount
// pairs, with any change returned to the specified account. When CoinType
// is supplied (or non-zero), inputs and outputs are validated to match —
// SKA outputs use big.Int amounts via SKAValue, VAR outputs use int64.
func (s *Server) spendOutputs(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.SpendOutputsCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}
	n, err := w.NetworkBackend()
	if err != nil {
		return nil, err
	}

	coinType := cointype.CoinTypeVAR
	if cmd.CoinType != nil {
		coinType = cointype.CoinType(*cmd.CoinType)
		if err := validateCoinTypeConfigured(w.ChainParams(), coinType); err != nil {
			return nil, err
		}
	}
	isSKA := coinType.IsSKA()

	params := w.ChainParams()
	atomsPerCoin := getAtomsPerCoin(params, coinType)

	account, err := w.AccountNumber(ctx, cmd.Account)
	if err != nil {
		return nil, err
	}

	inputs := make([]*wire.TxIn, 0, len(cmd.PreviousOutpoints))
	outputs := make([]*wire.TxOut, 0, len(cmd.Outputs))
	for _, outpointStr := range cmd.PreviousOutpoints {
		op, err := parseOutpoint(outpointStr)
		if err != nil {
			return nil, rpcError(dcrjson.ErrRPCInvalidParameter, err)
		}
		inputs = append(inputs, wire.NewTxIn(op, wire.NullValueIn, nil))
	}
	for _, output := range cmd.Outputs {
		addr, err := stdaddr.DecodeAddress(output.Address, params)
		if err != nil {
			return nil, err
		}
		scriptVersion, script := addr.PaymentScript()
		var txOut *wire.TxOut
		if isSKA {
			atomsBig, err := coinsToAtomsBig(output.Amount, atomsPerCoin)
			if err != nil {
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "invalid SKA amount: %v", err)
			}
			if atomsBig.Sign() <= 0 {
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "amount must be positive")
			}
			txOut = wire.NewTxOut(0, script)
			txOut.CoinType = coinType
			txOut.SKAValue = atomsBig
		} else {
			// VAR via coinsToAtomsBig + guarded int64 conversion to preserve
			// precision and surface oversize amounts as errors.
			atomsBig, err := coinsToAtomsBig(output.Amount, atomsPerCoin)
			if err != nil {
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "invalid VAR amount: %v", err)
			}
			if atomsBig.Sign() <= 0 {
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "amount must be positive")
			}
			if !atomsBig.IsInt64() {
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
					"VAR amount %s exceeds int64 capacity", atomsBig.String())
			}
			txOut = wire.NewTxOut(atomsBig.Int64(), script)
			txOut.CoinType = cointype.CoinTypeVAR
		}
		txOut.Version = scriptVersion
		outputs = append(outputs, txOut)
	}
	rand.ShuffleSlice(inputs)
	rand.ShuffleSlice(outputs)

	inputSource, err := spendOutputsInputSource(ctx, w, cmd.Account,
		inputs, coinType)
	if err != nil {
		return nil, err
	}

	changeSource := &accountChangeSource{
		ctx:     ctx,
		wallet:  w,
		account: account,
	}

	secretsSource, err := w.SecretsSource()
	if err != nil {
		return nil, err
	}
	defer secretsSource.Close()

	relayFee := w.RelayFeeForCoinType(ctx, coinType)
	atx, err := txauthor.NewUnsignedTransaction(outputs, relayFee,
		inputSource, changeSource, params.MaxTxSize, -1)
	if err != nil {
		return nil, err
	}
	// Tag the change output (if any) with the transaction's coin type so the
	// dual-coin validation in PublishTransaction sees a uniform tx.
	if atx.ChangeIndex >= 0 {
		atx.Tx.TxOut[atx.ChangeIndex].CoinType = coinType
	}
	atx.RandomizeChangePosition()
	err = atx.AddAllInputScripts(secretsSource)
	if err != nil {
		return nil, err
	}

	hash, err := w.PublishTransaction(ctx, atx.Tx, n)
	if err != nil {
		return nil, err
	}
	return hash.String(), nil
}

func (s *Server) ticketInfo(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.TicketInfoCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	res := make([]types.TicketInfoResult, 0)

	start := wallet.NewBlockIdentifierFromHeight(*cmd.StartHeight)
	end := wallet.NewBlockIdentifierFromHeight(-1)
	tmptx := new(wire.MsgTx)
	err := w.GetTickets(ctx, func(ts []*wallet.TicketSummary, h *wire.BlockHeader) (bool, error) {
		for _, t := range ts {
			status := t.Status
			if status == wallet.TicketStatusUnmined {
				// Standardize on immature.  An unmined ticket
				// can be determined by the block height field
				// and the lack of a block hash.
				status = wallet.TicketStatusImmature
			}
			err := tmptx.Deserialize(bytes.NewReader(t.Ticket.Transaction))
			if err != nil {
				return false, err
			}
			out := tmptx.TxOut[0]
			info := types.TicketInfoResult{
				Hash:        t.Ticket.Hash.String(),
				Cost:        cointype.AtomsToDecimalString(big.NewInt(out.Value), big.NewInt(cointype.AtomsPerVAR)),
				BlockHeight: -1,
				Status:      status.String(),
			}

			_, addrs := stdscript.ExtractAddrs(out.Version, out.PkScript, w.ChainParams())
			if len(addrs) == 0 {
				return false, errors.New("unable to decode ticket pkScript")
			}
			info.VotingAddress = addrs[0].String()
			if h != nil {
				info.BlockHash = h.BlockHash().String()
				info.BlockHeight = int32(h.Height)
			}
			if t.Spender != nil {
				hash := t.Spender.Hash.String()
				if t.Spender.Type == wallet.TransactionTypeRevocation {
					info.Revocation = hash
				} else {
					info.Vote = hash
				}
			}

			choices, _, err := w.AgendaChoices(ctx, t.Ticket.Hash)
			if err != nil {
				return false, err
			}
			info.Choices = make([]types.VoteChoice, 0, len(choices))
			for agendaID, choiceID := range choices {
				info.Choices = append(info.Choices, types.VoteChoice{
					AgendaID: agendaID,
					ChoiceID: choiceID,
				})
			}

			host, err := w.VSPHostForTicket(ctx, t.Ticket.Hash)
			if err != nil && !errors.Is(err, errors.NotExist) {
				return false, err
			}
			info.VSPHost = host

			res = append(res, info)
		}
		return false, nil
	}, start, end)

	return res, err
}

func isNilOrEmpty(s *string) bool {
	return s == nil || *s == ""
}

// sendFrom handles a sendfrom RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to another payment
// address.  Leftover inputs not sent to the payment address or a fee for
// the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned.
func (s *Server) sendFrom(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.SendFromCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Validate coin type if specified
	var coinType cointype.CoinType = cointype.CoinTypeVAR // Default to VAR for backward compatibility
	if cmd.CoinType != nil {
		coinType = cointype.CoinType(*cmd.CoinType)
		if err := validateCoinTypeConfigured(w.ChainParams(), coinType); err != nil {
			return nil, err
		}
	}

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) || !isNilOrEmpty(cmd.CommentTo) {
		return nil, rpcErrorf(dcrjson.ErrRPCUnimplemented, "transaction comments are unsupported")
	}

	account, err := w.AccountNumber(ctx, cmd.FromAccount)
	if err != nil {
		return nil, err
	}

	// Check that amount is not negative
	if strings.HasPrefix(cmd.Amount, "-") {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "negative amount")
	}
	minConf := int32(*cmd.MinConf)
	if minConf < 0 {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "negative minconf")
	}

	// Convert coins to atoms via coinsToAtomsBig for both VAR and SKA. The
	// big.Int path preserves SKA precision (1e18 atoms-per-coin) and avoids
	// VAR float64 round-trip loss above ~9e7 VAR. Overflow into the int64
	// wire field is checked at the chokepoint in makeOutputsWithCoinTypeBig.
	atomsPerCoin := getAtomsPerCoin(w.ChainParams(), coinType)
	amtBig, err := coinsToAtomsBig(cmd.Amount, atomsPerCoin)
	if err != nil {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "invalid amount: %v", err)
	}
	if amtBig.Sign() <= 0 {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "amount must be positive")
	}
	pairsBig := map[string]*big.Int{
		cmd.ToAddress: amtBig,
	}

	// Resolve subtractfeefromamount: when true, the single recipient output
	// absorbs the fee. nil/false → -1 (default behavior).
	//
	// Invariant: sendfrom builds pairsBig with exactly one entry from
	// cmd.ToAddress, so index 0 is always the recipient. If sendfrom ever
	// grows multi-recipient support, this hardcoded 0 must be revisited.
	subtractFeeIdx := -1
	if cmd.SubtractFeeFromAmount != nil && *cmd.SubtractFeeFromAmount {
		subtractFeeIdx = 0
	}
	return s.sendPairsWithCoinTypeBig(ctx, w, pairsBig, account, minConf, coinType, subtractFeeIdx)
}

// sendMany handles a sendmany RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to any number of
// payment addresses.  Leftover inputs not sent to the payment address
// or a fee for the miner are sent back to a new address in the wallet.
// Upon success, the TxID for the created transaction is returned.
// Supports optional coin type for dual-coin operations.
func (s *Server) sendMany(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.SendManyCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Validate coin type if specified
	var coinType cointype.CoinType = cointype.CoinTypeVAR // Default to VAR for backward compatibility
	if cmd.CoinType != nil {
		coinType = cointype.CoinType(*cmd.CoinType)
		if err := validateCoinTypeConfigured(w.ChainParams(), coinType); err != nil {
			return nil, err
		}
	}

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) {
		return nil, rpcErrorf(dcrjson.ErrRPCUnimplemented, "transaction comments are unsupported")
	}

	account, err := w.AccountNumber(ctx, cmd.FromAccount)
	if err != nil {
		return nil, err
	}

	// Check that minconf is positive.
	minConf := int32(*cmd.MinConf)
	if minConf < 0 {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "negative minconf")
	}

	// Parse via coinsToAtomsBig for both VAR and SKA — see sendFrom for the
	// rationale. Single big.Int path eliminates float64 precision loss.
	atomsPerCoin := getAtomsPerCoin(w.ChainParams(), coinType)
	pairsBig := make(map[string]*big.Int, len(cmd.Amounts))
	for k, v := range cmd.Amounts {
		amtBig, err := coinsToAtomsBig(v, atomsPerCoin)
		if err != nil {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "invalid amount for %s: %v", k, err)
		}
		if amtBig.Sign() <= 0 {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "amount for %s must be positive", k)
		}
		pairsBig[k] = amtBig
	}
	// sendmany does not currently expose subtractfeefromamount; pass -1.
	return s.sendPairsWithCoinTypeBig(ctx, w, pairsBig, account, minConf, coinType, -1)
}

// sendToAddress handles a sendtoaddress RPC request by creating a new
// transaction spending unspent transaction outputs for a wallet to another
// payment address.  Leftover inputs not sent to the payment address or a fee
// for the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned. Supports optional coin type.
func (s *Server) sendToAddress(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.SendToAddressCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Validate coin type if specified
	var coinType cointype.CoinType = cointype.CoinTypeVAR // Default to VAR for backward compatibility
	if cmd.CoinType != nil {
		coinType = cointype.CoinType(*cmd.CoinType)
		if err := validateCoinTypeConfigured(w.ChainParams(), coinType); err != nil {
			return nil, err
		}
	}

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) || !isNilOrEmpty(cmd.CommentTo) {
		return nil, rpcErrorf(dcrjson.ErrRPCUnimplemented, "transaction comments are unsupported")
	}

	// Convert coins to atoms using the correct AtomsPerCoin for this coin type
	atomsPerCoin := getAtomsPerCoin(w.ChainParams(), coinType)

	// Check that amount is not negative
	if strings.HasPrefix(cmd.Amount, "-") {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "negative amount")
	}

	// Single big.Int path for both VAR and SKA — see sendFrom for the
	// rationale.
	amtBig, err := coinsToAtomsBig(cmd.Amount, atomsPerCoin)
	if err != nil {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "invalid amount: %v", err)
	}
	if amtBig.Sign() <= 0 {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "amount must be positive")
	}
	pairsBig := map[string]*big.Int{
		cmd.Address: amtBig,
	}

	// Resolve subtractfeefromamount: when true, the single recipient output
	// absorbs the fee. nil/false → -1 (default behavior).
	//
	// Invariant: sendtoaddress emits exactly one recipient output before
	// any change output is appended by the wallet, so index 0 is always
	// the recipient. If sendtoaddress ever grows multi-recipient support,
	// this hardcoded 0 must be revisited.
	subtractFeeIdx := -1
	if cmd.SubtractFeeFromAmount != nil && *cmd.SubtractFeeFromAmount {
		subtractFeeIdx = 0
	}

	// sendtoaddress always spends from the default account, this matches bitcoind
	return s.sendPairsWithCoinTypeBig(ctx, w, pairsBig, udb.DefaultAccountNum, 1, coinType, subtractFeeIdx)
}

// sendToMultiSig handles a sendtomultisig RPC request by creating a new
// transaction spending amount many funds to an output containing a multi-
// signature script hash. The function will fail if there isn't at least one
// public key in the public key list that corresponds to one that is owned
// locally.
// Upon successfully sending the transaction to the daemon, the script hash
// is stored in the transaction manager and the corresponding address
// specified to be watched by the daemon.
// The function returns a tx hash, P2SH address, and a multisig script if
// successful.
func (s *Server) sendToMultiSig(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.SendToMultiSigCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	ct := cointype.CoinTypeVAR
	if cmd.CoinType != nil {
		ct = cointype.CoinType(*cmd.CoinType)
		if err := validateCoinTypeConfigured(w.ChainParams(), ct); err != nil {
			return nil, err
		}
	}

	fromAccount := cmd.FromAccount
	if fromAccount == "" {
		fromAccount = "default"
	}
	account, err := w.AccountNumber(ctx, fromAccount)
	if err != nil {
		return nil, err
	}

	nrequired := int8(*cmd.NRequired)
	minconf := int32(*cmd.MinConf)

	// Parse amount via coinsToAtomsBig for both VAR and SKA — preserves SKA
	// precision (1e18 atoms-per-coin) and avoids VAR float64 round-trip loss.
	// Overflow into the int64 VAR field is checked at the conversion site.
	atomsPerCoin := getAtomsPerCoin(w.ChainParams(), ct)
	amtBig, err := coinsToAtomsBig(strings.TrimSpace(cmd.Amount), atomsPerCoin)
	if err != nil {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "invalid amount: %v", err)
	}
	if amtBig.Sign() <= 0 {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "amount must be positive")
	}
	var varAmount dcrutil.Amount
	skaAmount := cointype.Zero()
	if ct.IsSKA() {
		skaAmount = cointype.NewSKAAmount(amtBig)
	} else {
		if !amtBig.IsInt64() {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"VAR amount %s exceeds int64 capacity", amtBig.String())
		}
		varAmount = dcrutil.Amount(amtBig.Int64())
	}

	pubKeys, err := walletPubKeys(ctx, w, cmd.Pubkeys)
	if err != nil {
		return nil, err
	}

	tx, addr, script, err :=
		w.CreateMultisigTx(ctx, account, varAmount, skaAmount, pubKeys, nrequired, minconf, ct)
	if err != nil {
		return nil, err
	}

	result := &types.SendToMultiSigResult{
		TxHash:       tx.MsgTx.TxHash().String(),
		Address:      addr.String(),
		RedeemScript: hex.EncodeToString(script),
	}

	log.Infof("Successfully sent funds to multisignature output in "+
		"transaction %v", tx.MsgTx.TxHash().String())

	return result, nil
}

// sendRawTransaction handles a sendrawtransaction RPC request by decoding hex
// transaction and sending it to the network backend for propagation.
func (s *Server) sendRawTransaction(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.SendRawTransactionCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	n, err := w.NetworkBackend()
	if err != nil {
		return nil, err
	}

	msgtx := wire.NewMsgTx()
	err = msgtx.Deserialize(hex.NewDecoder(strings.NewReader(cmd.HexTx)))
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCDeserialization, err)
	}

	// Defense in depth: refuse mixed-coin-type raw transactions before
	// broadcasting. Consensus rejects them, but the wallet's high-fee
	// dispatch below routes on outputs[0] only and would otherwise call
	// the wrong fee evaluator on the trailing outputs.
	if len(msgtx.TxOut) > 1 {
		firstCT := msgtx.TxOut[0].CoinType
		for i, out := range msgtx.TxOut[1:] {
			if out.CoinType != firstCT {
				return nil, rpcErrorf(dcrjson.ErrRPCDeserialization,
					"mixed coin types in raw transaction: output 0 is %d, output %d is %d",
					firstCT, i+1, out.CoinType)
			}
		}
	}
	// Reject outputs whose CoinType and SKAValue presence disagree. A
	// maliciously crafted tx with CoinType=0 on every output but SKAValue
	// set on later outputs would otherwise pass the same-coin-type loop
	// above and dispatch via the VAR fee evaluator.
	for i, out := range msgtx.TxOut {
		if (out.SKAValue != nil) != out.CoinType.IsSKA() {
			return nil, rpcErrorf(dcrjson.ErrRPCDeserialization,
				"output %d coin type %d and SKAValue presence (%v) are inconsistent",
				i, out.CoinType, out.SKAValue != nil)
		}
	}

	if !*cmd.AllowHighFees {
		var highFees bool
		if txrules.GetCoinTypeFromOutputs(msgtx.TxOut).IsSKA() {
			highFees, err = txrules.TxPaysHighFeesSKA(msgtx, w.ChainParams())
		} else {
			highFees, err = txrules.TxPaysHighFees(msgtx)
		}
		if err != nil {
			return nil, err
		}
		if highFees {
			return nil, errors.E(errors.Policy, "high fees")
		}
	}

	txHash, err := w.PublishTransaction(ctx, msgtx, n)
	if err != nil {
		return nil, err
	}

	return txHash.String(), nil
}

// sendToTreasury handles a sendtotreasury RPC request by creating a new
// transaction spending unspent transaction outputs for a wallet to the
// treasury.  Leftover inputs not sent to the payment address or a fee for the
// miner are sent back to a new address in the wallet.  Upon success, the TxID
// for the created transaction is returned.
func (s *Server) sendToTreasury(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.SendToTreasuryCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	amt, err := dcrutil.NewAmount(cmd.Amount)
	if err != nil {
		return nil, err
	}

	// Check that signed integer parameters are positive.
	if amt <= 0 {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "negative amount")
	}

	// sendtotreasury always spends from the default account.
	return s.sendAmountToTreasury(ctx, w, amt, udb.DefaultAccountNum, 1)
}

// transaction spending treasury balance.
// Upon success, the TxID for the created transaction is returned.
func (s *Server) sendFromTreasury(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.SendFromTreasuryCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	return s.sendOutputsFromTreasury(ctx, w, *cmd)
}

// sendToBurn handles a sendtoburn RPC request by creating a new transaction
// that permanently burns (destroys) SKA coins by sending them to a provably
// unspendable OP_RETURN output. This operation is IRREVERSIBLE.
// Only SKA coin types (1-255) can be burned; VAR coins cannot be burned.
// Upon success, the TxID for the created burn transaction is returned.
func (s *Server) sendToBurn(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.SendToBurnCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Validate coin type - must be SKA (1-255), not VAR (0)
	coinType := cointype.CoinType(cmd.CoinType)
	if err := validateCoinTypeConfigured(w.ChainParams(), coinType); err != nil {
		return nil, err
	}
	if !coinType.IsSKA() {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"cannot burn VAR coins (coin type 0); only SKA coins (1-255) can be burned")
	}

	// Get chain params for AtomsPerCoin
	params := w.ChainParams()

	// Parse and validate amount - must be positive. The empty / leading-'-'
	// rejections produce friendlier errors than the downstream parse error;
	// the post-parse Sign() <= 0 check below is the single source of truth
	// for "must be strictly positive" (catches "0", "0.0", "+0", "00", etc.).
	if cmd.Amount == "" || strings.HasPrefix(cmd.Amount, "-") {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "amount must be positive")
	}

	// Convert coin amount to atoms using SKA's AtomsPerCoin (typically 1e18)
	atomsPerCoin := getAtomsPerCoin(params, coinType)
	skaAtoms, err := coinsToAtomsBig(cmd.Amount, atomsPerCoin)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCInvalidParameter, err)
	}
	if skaAtoms.Sign() <= 0 {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "amount must be positive")
	}

	// Temporarily unlock the wallet for this single call (per-call capability
	// gate). The ambient walletpassphrase unlock window is intentionally NOT
	// used; without this gate any other authenticated client during a
	// walletpassphrase window could initiate a burn.
	return withWalletUnlocked(ctx, w, cmd.Passphrase, func() (any, error) {
		// Create the burn script for this coin type
		burnScript, err := params.CreateSKABurnScript(coinType)
		if err != nil {
			return nil, rpcError(dcrjson.ErrRPCInvalidParameter, err)
		}

		// Create the burn output with coin type and burn script
		// SKA outputs use SKAValue (big.Int) instead of Value (int64)
		outputs := []*wire.TxOut{
			{
				Value:    0, // SKA outputs must have Value=0
				SKAValue: skaAtoms,
				CoinType: coinType,
				Version:  wire.DefaultPkScriptVersion,
				PkScript: burnScript,
			},
		}

		// Send the transaction - burning always spends from default account
		account := uint32(udb.DefaultAccountNum)
		changeAccount := account
		minConf := int32(1)

		// Handle mixing account change routing if enabled
		if s.cfg.MixingEnabled {
			mixAccount, err := w.AccountNumber(ctx, s.cfg.MixAccount)
			if err != nil {
				return nil, err
			}
			if account == mixAccount {
				changeAccount, err = w.AccountNumber(ctx, s.cfg.MixChangeAccount)
				if err != nil {
					return nil, err
				}
			}
		}

		txHash, err := w.SendOutputs(ctx, outputs, account, changeAccount, minConf, -1)
		if err != nil {
			if errors.Is(err, errors.Locked) {
				return nil, errWalletUnlockNeeded
			}
			if errors.Is(err, errors.InsufficientBalance) {
				return nil, rpcError(dcrjson.ErrRPCWalletInsufficientFunds, err)
			}
			return nil, err
		}

		return txHash.String(), nil
	})
}

// setTxFee sets the transaction fee per kilobyte added to transactions.
func (s *Server) setTxFee(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.SetTxFeeCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Default to VAR (coin type 0) if not specified
	ct := cointype.CoinType(0)
	if cmd.CoinType != nil {
		ct = cointype.CoinType(*cmd.CoinType)
	}

	// Reject coin types that are in range but not configured for this network
	// before any state read. Without this, an unconfigured-but-in-range coin
	// type would silently fall through to SetManualFee, which used to fan out
	// the override across every active SKA coin.
	if err := validateCoinTypeConfigured(w.ChainParams(), ct); err != nil {
		return nil, err
	}

	atomsPerCoin := atomsPerCoinForCoinType(w.ChainParams(), ct)

	// SetTxFeeCmd.Amount is a JSON string (see types.SetTxFeeCmd) — the type
	// system rejects JSON numbers, which is critical for SKA where 1e18
	// atoms-per-coin makes float64 round-trip lossy past ~16 significant
	// digits. Pass through coinsToAtomsBig for big.Int decimal parsing.
	feeAtoms, err := coinsToAtomsBig(cmd.Amount, atomsPerCoin)
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCInvalidParameter, err)
	}

	// Check for negative amount
	if feeAtoms.Sign() < 0 {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "negative amount")
	}

	// If amount is 0, clear manual override to use RPC dynamic fees
	if feeAtoms.Sign() == 0 {
		w.ClearManualFee(ct)
		// A boolean true result is returned upon success.
		return true, nil
	}

	// Set manual fee override for the specified coin type
	relayFee := cointype.NewSKAAmount(feeAtoms)
	if err := w.SetManualFee(ct, relayFee); err != nil {
		return nil, rpcError(dcrjson.ErrRPCInvalidParameter, err)
	}

	// A boolean true result is returned upon success.
	return true, nil
}

// setVoteChoice handles a setvotechoice request by modifying the preferred
// choice for a voting agenda.
//
// If a VSP host is configured in the application settings, the voting
// preferences will also be set with the VSP.
func (s *Server) setVoteChoice(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.SetVoteChoiceCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	var ticketHash *chainhash.Hash
	if cmd.TicketHash != nil {
		hash, err := chainhash.NewHashFromStr(*cmd.TicketHash)
		if err != nil {
			return nil, rpcError(dcrjson.ErrRPCInvalidParameter, err)
		}
		ticketHash = hash
	}

	choice := map[string]string{
		cmd.AgendaID: cmd.ChoiceID,
	}

	_, err := w.SetAgendaChoices(ctx, ticketHash, choice)
	if err != nil {
		return nil, err
	}

	// Update voting preferences on VSPs if required.
	err = s.updateVSPVoteChoices(ctx, w, ticketHash, choice, nil, nil)
	return nil, err
}

func (s *Server) updateVSPVoteChoices(ctx context.Context, w *wallet.Wallet, ticketHash *chainhash.Hash,
	choices map[string]string, tspendPolicy map[string]string, treasuryPolicy map[string]string) error {

	if ticketHash != nil {
		vspHost, err := w.VSPHostForTicket(ctx, ticketHash)
		if err != nil {
			if errors.Is(err, errors.NotExist) {
				// Ticket is not registered with a VSP, nothing more to do here.
				return nil
			}
			return err
		}
		vspClient, err := w.LookupVSP(vspHost)
		if err != nil {
			return err
		}

		ticket, err := w.NewVSPTicket(ctx, ticketHash)
		if err != nil {
			return err
		}

		err = vspClient.SetVoteChoice(ctx, ticket, choices, tspendPolicy, treasuryPolicy)
		return err
	}

	err := w.ForUnspentUnexpiredTickets(ctx, func(hash *chainhash.Hash) error {
		vspHost, err := w.VSPHostForTicket(ctx, hash)
		if err != nil {
			if errors.Is(err, errors.NotExist) {
				// Ticket is not registered with a VSP, nothing more to do here.
				return nil
			}
			return err
		}
		vspClient, err := w.LookupVSP(vspHost)
		if err != nil {
			return err
		}

		ticket, err := w.NewVSPTicket(ctx, hash)
		if err != nil {
			return err
		}

		// Never return errors here, so all tickets are tried.
		// The first error will be returned to the user.
		err = vspClient.SetVoteChoice(ctx, ticket, choices, tspendPolicy, treasuryPolicy)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

// signMessage signs the given message with the private key for the given
// address
func (s *Server) signMessage(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.SignMessageCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}
	sig, err := w.SignMessage(ctx, cmd.Message, addr)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAddressNotInWallet
		}
		if errors.Is(err, errors.Locked) {
			return nil, errWalletUnlockNeeded
		}
		return nil, err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// signRawTransaction handles the signrawtransaction command.
//
// chainClient may be nil, in which case it was called by the NoChainRPC
// variant.  It must be checked before all usage.
func (s *Server) signRawTransaction(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.SignRawTransactionCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	tx := wire.NewMsgTx()
	err := tx.Deserialize(hex.NewDecoder(strings.NewReader(cmd.RawTx)))
	if err != nil {
		return nil, rpcError(dcrjson.ErrRPCDeserialization, err)
	}
	if len(tx.TxIn) == 0 {
		err := errors.New("transaction with no inputs cannot be signed")
		return nil, rpcError(dcrjson.ErrRPCInvalidParameter, err)
	}

	// Defense in depth: refuse mixed-coin-type transactions before signing.
	// Mirrors sendRawTransaction. populateSKAValueIn below derives the tx
	// coin type from outputs[0]; without this guard a malformed tx with
	// inconsistent output coin types would be signed and produce a
	// confusing downstream error when broadcast.
	if len(tx.TxOut) > 1 {
		firstCT := tx.TxOut[0].CoinType
		for i, out := range tx.TxOut[1:] {
			if out.CoinType != firstCT {
				return nil, rpcErrorf(dcrjson.ErrRPCDeserialization,
					"mixed coin types in raw transaction: output 0 is %d, output %d is %d",
					firstCT, i+1, out.CoinType)
			}
		}
	}
	// Reject outputs whose CoinType and SKAValue presence disagree. A
	// maliciously crafted tx with CoinType=0 on every output but SKAValue
	// set on later outputs would otherwise slip through populateSKAValueIn
	// (which would resolve txCoinType to VAR and early-return) and reach
	// the signer with wire-format-violating outputs.
	for i, out := range tx.TxOut {
		if (out.SKAValue != nil) != out.CoinType.IsSKA() {
			return nil, rpcErrorf(dcrjson.ErrRPCDeserialization,
				"output %d coin type %d and SKAValue presence (%v) are inconsistent",
				i, out.CoinType, out.SKAValue != nil)
		}
	}

	var hashType txscript.SigHashType
	switch *cmd.Flags {
	case "ALL":
		hashType = txscript.SigHashAll
	case "NONE":
		hashType = txscript.SigHashNone
	case "SINGLE":
		hashType = txscript.SigHashSingle
	case "ALL|ANYONECANPAY":
		hashType = txscript.SigHashAll | txscript.SigHashAnyOneCanPay
	case "NONE|ANYONECANPAY":
		hashType = txscript.SigHashNone | txscript.SigHashAnyOneCanPay
	case "SINGLE|ANYONECANPAY":
		hashType = txscript.SigHashSingle | txscript.SigHashAnyOneCanPay
	case "ssgen": // Special case of SigHashAll
		hashType = txscript.SigHashAll
	case "ssrtx": // Special case of SigHashAll
		hashType = txscript.SigHashAll
	default:
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "invalid sighash flag")
	}

	// TODO: really we probably should look these up with mond anyway to
	// make sure that they match the blockchain if present.
	inputs := make(map[wire.OutPoint][]byte)
	scripts := make(map[string][]byte)
	// callerSKA collects caller-asserted SKAValueIn decimal-coin strings keyed
	// by outpoint. Populated only when the RawTxInput.SKAValueIn JSON field is
	// present. Parsed against the SKA coin's atomsPerCoin in the population
	// pass below (we cannot parse here because we do not yet know the tx's SKA
	// coin type). Used downstream to fill in tx.TxIn.SKAValueIn for SKA inputs
	// that arrived with SKAValueIn=nil (e.g. a third-party tool built the
	// wire.MsgTx from primitives without the V13 wire-format extension fields).
	callerSKA := make(map[wire.OutPoint]string)
	var cmdInputs []types.RawTxInput
	if cmd.Inputs != nil {
		cmdInputs = *cmd.Inputs
	}
	for _, rti := range cmdInputs {
		inputSha, err := chainhash.NewHashFromStr(rti.Txid)
		if err != nil {
			return nil, rpcError(dcrjson.ErrRPCInvalidParameter, err)
		}

		script, err := decodeHexStr(rti.ScriptPubKey)
		if err != nil {
			return nil, err
		}

		// redeemScript is only actually used iff the user provided
		// private keys. In which case, it is used to get the scripts
		// for signing. If the user did not provide keys then we always
		// get scripts from the wallet.
		// Empty strings are ok for this one and hex.DecodeString will
		// DTRT.
		// Note that redeemScript is NOT only the redeemscript
		// required to be appended to the end of a P2SH output
		// spend, but the entire signature script for spending
		// *any* outpoint with dummy values inserted into it
		// that can later be replacing by txscript's sign.
		if cmd.PrivKeys != nil && len(*cmd.PrivKeys) != 0 {
			redeemScript, err := decodeHexStr(rti.RedeemScript)
			if err != nil {
				return nil, err
			}

			addr, err := stdaddr.NewAddressScriptHashV0(redeemScript,
				w.ChainParams())
			if err != nil {
				return nil, err
			}
			scripts[addr.String()] = redeemScript
		}
		op := wire.OutPoint{
			Hash:  *inputSha,
			Tree:  rti.Tree,
			Index: rti.Vout,
		}
		inputs[op] = script
		if rti.SKAValueIn != nil {
			// Defer atoms-per-coin resolution until we know the tx coin type;
			// at this point we don't yet have the prevout's CoinType. Stash
			// the raw decimal string keyed by outpoint and parse downstream.
			s := *rti.SKAValueIn
			if s == "" {
				return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
					"skaValueIn for input %s:%d must not be empty",
					rti.Txid, rti.Vout)
			}
			callerSKA[op] = s
		}
	}

	// Now we go and look for any inputs that we were not provided by
	// querying mond with getrawtransaction. We queue up a bunch of async
	// requests and will wait for replies after we have checked the rest of
	// the arguments.
	requested := make(map[wire.OutPoint]*mondtypes.GetTxOutResult)
	var requestedMu sync.Mutex
	requestedGroup, gctx := errgroup.WithContext(ctx)
	n, _ := s.walletLoader.NetworkBackend()
	if chainSyncer, ok := n.(*chain.Syncer); ok {
		for i, txIn := range tx.TxIn {
			// We don't need the first input of a stakebase tx, as it's garbage
			// anyway.
			if i == 0 && *cmd.Flags == "ssgen" {
				continue
			}

			// Did we get this outpoint from the arguments?
			if _, ok := inputs[txIn.PreviousOutPoint]; ok {
				continue
			}

			// Asynchronously request the output script.
			txIn := txIn
			requestedGroup.Go(func() error {
				hash := &txIn.PreviousOutPoint.Hash
				index := txIn.PreviousOutPoint.Index
				tree := txIn.PreviousOutPoint.Tree
				res, err := chainSyncer.GetTxOut(gctx, hash, index, tree, true)
				if err != nil {
					return err
				}
				requestedMu.Lock()
				requested[txIn.PreviousOutPoint] = res
				requestedMu.Unlock()
				return nil
			})
		}
	}

	// Parse list of private keys, if present. If there are any keys here
	// they are the keys that we may use for signing. If empty we will
	// use any keys known to us already.
	var keys map[string]*dcrutil.WIF
	if cmd.PrivKeys != nil {
		keys = make(map[string]*dcrutil.WIF)

		for _, key := range *cmd.PrivKeys {
			wif, err := dcrutil.DecodeWIF(key, w.ChainParams().PrivateKeyID)
			if err != nil {
				return nil, rpcError(dcrjson.ErrRPCDeserialization, err)
			}

			var addr stdaddr.Address
			switch wif.DSA() {
			case dcrec.STEcdsaSecp256k1:
				addr, err = stdaddr.NewAddressPubKeyEcdsaSecp256k1V0Raw(
					wif.PubKey(), w.ChainParams())
				if err != nil {
					return nil, err
				}
			case dcrec.STEd25519:
				addr, err = stdaddr.NewAddressPubKeyEd25519V0Raw(
					wif.PubKey(), w.ChainParams())
				if err != nil {
					return nil, err
				}
			case dcrec.STSchnorrSecp256k1:
				addr, err = stdaddr.NewAddressPubKeySchnorrSecp256k1V0Raw(
					wif.PubKey(), w.ChainParams())
				if err != nil {
					return nil, err
				}
			}
			keys[addr.String()] = wif

			// Add the pubkey hash variant for supported addresses as well.
			if pkH, ok := addr.(stdaddr.AddressPubKeyHasher); ok {
				keys[pkH.AddressPubKeyHash().String()] = wif
			}
		}
	}

	// We have checked the rest of the args. now we can collect the async
	// txs.
	err = requestedGroup.Wait()
	if err != nil {
		return nil, err
	}
	for outPoint, result := range requested {
		// gettxout returns JSON null if the output is found, but is spent by
		// another transaction in the main chain.
		if result == nil {
			continue
		}
		script, err := hex.DecodeString(result.ScriptPubKey.Hex)
		if err != nil {
			return nil, rpcError(dcrjson.ErrRPCDecodeHexString, err)
		}
		inputs[outPoint] = script
	}

	// Populate SKAValueIn for SKA inputs that arrived without it. See
	// populateSKAValueIn for the contract.
	if err := populateSKAValueIn(ctx, tx, w.ChainParams(), callerSKA,
		func(ctx context.Context, op wire.OutPoint) (*udb.Credit, error) {
			return w.UnspentOutput(ctx, op, true)
		}); err != nil {
		return nil, err
	}

	// All args collected. Now we can sign all the inputs that we can.
	// `complete' denotes that we successfully signed all outputs and that
	// all scripts will run to completion. This is returned as part of the
	// reply.
	signErrs, txComplete, signErr := w.SignTransaction(ctx, tx, hashType, inputs, keys, scripts)

	var b strings.Builder
	b.Grow(2 * tx.SerializeSize())
	err = tx.Serialize(hex.NewEncoder(&b))
	if err != nil {
		return nil, err
	}

	signErrors := make([]types.SignRawTransactionError, 0, len(signErrs))
	for _, e := range signErrs {
		input := tx.TxIn[e.InputIndex]
		signErrors = append(signErrors, types.SignRawTransactionError{
			TxID:      input.PreviousOutPoint.Hash.String(),
			Vout:      input.PreviousOutPoint.Index,
			ScriptSig: hex.EncodeToString(input.SignatureScript),
			Sequence:  input.Sequence,
			Error:     e.Error.Error(),
		})
	}

	return types.SignRawTransactionResult{
		Hex:      b.String(),
		Complete: txComplete && len(signErrors) == 0 && signErr == nil,
		Errors:   signErrors,
	}, nil
}

// signRawTransactions handles the signrawtransactions command.
func (s *Server) signRawTransactions(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.SignRawTransactionsCmd)

	// Sign each transaction sequentially and record the results.
	// Error out if we meet some unexpected failure.
	results := make([]types.SignRawTransactionResult, len(cmd.RawTxs))
	for i, etx := range cmd.RawTxs {
		flagAll := "ALL"
		srtc := &types.SignRawTransactionCmd{
			RawTx: etx,
			Flags: &flagAll,
		}
		result, err := s.signRawTransaction(ctx, srtc)
		if err != nil {
			return nil, err
		}

		tResult := result.(types.SignRawTransactionResult)
		results[i] = tResult
	}

	// If the user wants completed transactions to be automatically send,
	// do that now. Otherwise, construct the slice and return it.
	toReturn := make([]types.SignedTransaction, len(cmd.RawTxs))

	if *cmd.Send {
		n, ok := s.walletLoader.NetworkBackend()
		if !ok {
			return nil, errNoNetwork
		}

		for i, result := range results {
			if result.Complete {
				// Slow/mem hungry because of the deserializing.
				msgTx := wire.NewMsgTx()
				err := msgTx.Deserialize(hex.NewDecoder(strings.NewReader(result.Hex)))
				if err != nil {
					return nil, rpcError(dcrjson.ErrRPCDeserialization, err)
				}
				sent := false
				hashStr := ""
				err = n.PublishTransactions(ctx, msgTx)
				// If sendrawtransaction errors out (blockchain rule
				// issue, etc), continue onto the next transaction.
				if err == nil {
					sent = true
					hashStr = msgTx.TxHash().String()
				}

				st := types.SignedTransaction{
					SigningResult: result,
					Sent:          sent,
					TxHash:        &hashStr,
				}
				toReturn[i] = st
			} else {
				st := types.SignedTransaction{
					SigningResult: result,
					Sent:          false,
					TxHash:        nil,
				}
				toReturn[i] = st
			}
		}
	} else { // Just return the results.
		for i, result := range results {
			st := types.SignedTransaction{
				SigningResult: result,
				Sent:          false,
				TxHash:        nil,
			}
			toReturn[i] = st
		}
	}

	return &types.SignRawTransactionsResult{Results: toReturn}, nil
}

// scriptChangeSource is a ChangeSource which is used to
// receive all correlated previous input value.
type scriptChangeSource struct {
	version uint16
	script  []byte
}

func (src *scriptChangeSource) Script() ([]byte, uint16, error) {
	return src.script, src.version, nil
}

func (src *scriptChangeSource) ScriptSize() int {
	return len(src.script)
}

func makeScriptChangeSource(address string, params *chaincfg.Params) (*scriptChangeSource, error) {
	destinationAddress, err := stdaddr.DecodeAddress(address, params)
	if err != nil {
		return nil, err
	}
	version, script := destinationAddress.PaymentScript()
	source := &scriptChangeSource{
		version: version,
		script:  script,
	}
	return source, nil
}

func sumOutputValues(outputs []*wire.TxOut) (totalOutput dcrutil.Amount) {
	for _, txOut := range outputs {
		totalOutput += dcrutil.Amount(txOut.Value)
	}
	return totalOutput
}

// sweepAccount handles the sweepaccount command.
func (s *Server) sweepAccount(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.SweepAccountCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Coin type defaults to VAR; SKA accounts opt in via cointype.
	sweepCoinType := cointype.CoinTypeVAR
	if cmd.CoinType != nil {
		sweepCoinType = cointype.CoinType(*cmd.CoinType)
		if err := validateCoinTypeConfigured(w.ChainParams(), sweepCoinType); err != nil {
			return nil, err
		}
	}

	// use provided fee per Kb if specified
	feePerKbOverride := cointype.Zero()
	if cmd.FeePerKb != nil {
		atomsPerCoin := getAtomsPerCoin(w.ChainParams(), sweepCoinType)
		atomsBig, err := coinsToAtomsBig(strings.TrimSpace(*cmd.FeePerKb), atomsPerCoin)
		if err != nil {
			return nil, rpcError(dcrjson.ErrRPCInvalidParameter, err)
		}
		if atomsBig.Sign() < 0 {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"feePerKb must be non-negative")
		}
		feePerKbOverride = cointype.NewSKAAmount(atomsBig)
	}

	// use provided required confirmations if specified
	requiredConfs := int32(1)
	if cmd.RequiredConfirmations != nil {
		requiredConfs = int32(*cmd.RequiredConfirmations)
		if requiredConfs < 0 {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"requiredconfirmations must be non-negative; got %d", requiredConfs)
		}
	}

	account, err := w.AccountNumber(ctx, cmd.SourceAccount)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAccountNotFound
		}
		return nil, err
	}

	changeSource, err := makeScriptChangeSource(cmd.DestinationAddress, w.ChainParams())
	if err != nil {
		return nil, err
	}
	tx, err := w.NewUnsignedSweepTransactionForCoinType(ctx, sweepCoinType,
		feePerKbOverride, account, requiredConfs, changeSource, nil)
	if err != nil {
		if errors.Is(err, errors.InsufficientBalance) {
			return nil, rpcError(dcrjson.ErrRPCWalletInsufficientFunds, err)
		}
		return nil, err
	}

	var b strings.Builder
	b.Grow(2 * tx.Tx.SerializeSize())
	err = tx.Tx.Serialize(hex.NewEncoder(&b))
	if err != nil {
		return nil, err
	}

	// Report aggregated input/output amounts as full-precision base-10
	// decimal coin strings.  Float64 cannot carry SKA atoms (1e18 atoms/coin)
	// without losing precision, so this is the only safe surface for both
	// VAR and SKA.
	atomsPerCoin := getAtomsPerCoin(w.ChainParams(), sweepCoinType)
	var totalInStr, totalOutStr string
	if sweepCoinType.IsSKA() {
		totalInStr = cointype.AtomsToDecimalString(tx.SKATotalInput.BigInt(), atomsPerCoin)
		skaTotalOut, err := sumSKAOutputValues(tx.Tx.TxOut)
		if err != nil {
			return nil, err
		}
		totalOutStr = cointype.AtomsToDecimalString(skaTotalOut, atomsPerCoin)
	} else {
		totalInStr = cointype.AtomsToDecimalString(big.NewInt(int64(tx.TotalInput)), atomsPerCoin)
		totalOutStr = cointype.AtomsToDecimalString(big.NewInt(int64(sumOutputValues(tx.Tx.TxOut))), atomsPerCoin)
	}
	res := &types.SweepAccountResult{
		UnsignedTransaction:       b.String(),
		TotalPreviousOutputAmount: totalInStr,
		TotalOutputAmount:         totalOutStr,
		EstimatedSignedSize:       uint32(tx.EstimatedSignedSerializeSize),
	}

	return res, nil
}

// sumSKAOutputValues sums SKAValue across all outputs. SKA outputs missing
// SKAValue are surfaced loudly: validateAuthoredCoinTypes rejects mixed-coin
// txs upstream for most paths, but sendrawtransaction bypasses that check, so
// silently dropping a malformed SKA output here would let a downstream sweep
// summary under-report. Returns an error in that case rather than swallowing.
func sumSKAOutputValues(outputs []*wire.TxOut) (*big.Int, error) {
	total := new(big.Int)
	for i, txOut := range outputs {
		if txOut.CoinType.IsSKA() && txOut.SKAValue == nil {
			return nil, fmt.Errorf("SKA output %d has nil SKAValue", i)
		}
		if txOut.SKAValue != nil {
			total.Add(total, txOut.SKAValue)
		}
	}
	return total, nil
}

// atomsToFloat converts a big.Int atom count to a float64 coin value via the
// given atomsPerCoin scale. Precision is lossy past ~15 decimal digits;
// callers needing exact values must use the decimal-string variant.
func atomsToFloat(atoms, atomsPerCoin *big.Int) float64 {
	if atoms == nil || atomsPerCoin == nil || atomsPerCoin.Sign() == 0 {
		return 0
	}
	atomsF, _ := new(big.Float).SetInt(atoms).Float64()
	scaleF, _ := new(big.Float).SetInt(atomsPerCoin).Float64()
	if scaleF == 0 {
		return 0
	}
	return atomsF / scaleF
}

// validateAddress handles the validateaddress command.
func (s *Server) validateAddress(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.ValidateAddressCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	result := types.ValidateAddressResult{}
	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		result.Script = stdscript.STNonStandard.String()
		// Use result zero value (IsValid=false).
		return result, nil
	}

	result.Address = addr.String()
	result.IsValid = true
	ver, scr := addr.PaymentScript()
	class, _ := stdscript.ExtractAddrs(ver, scr, w.ChainParams())
	result.Script = class.String()
	if pker, ok := addr.(stdaddr.SerializedPubKeyer); ok {
		result.PubKey = hex.EncodeToString(pker.SerializedPubKey())
		result.PubKeyAddr = addr.String()
	}
	if class == stdscript.STScriptHash {
		result.IsScript = true
	}
	if _, ok := addr.(stdaddr.Hash160er); ok {
		result.IsCompressed = true
	}

	ka, err := w.KnownAddress(ctx, addr)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			// No additional information available about the address.
			return result, nil
		}
		return nil, err
	}

	// The address lookup was successful which means there is further
	// information about it available and it is "mine".
	result.IsMine = true
	result.Account = ka.AccountName()

	switch ka := ka.(type) {
	case wallet.PubKeyHashAddress:
		pubKey, err := ka.PubKey()
		if err != nil {
			return nil, err
		}
		result.PubKey = hex.EncodeToString(pubKey)
		pubKeyAddr, err := stdaddr.NewAddressPubKeyEcdsaSecp256k1V0Raw(pubKey, w.ChainParams())
		if err != nil {
			return nil, err
		}
		result.PubKeyAddr = pubKeyAddr.String()
	case wallet.P2SHAddress:
		version, script := ka.RedeemScript()
		result.Hex = hex.EncodeToString(script)

		class, addrs := stdscript.ExtractAddrs(version, script, w.ChainParams())
		addrStrings := make([]string, len(addrs))
		for i, a := range addrs {
			addrStrings[i] = a.String()
		}
		result.Addresses = addrStrings
		result.Script = class.String()

		// Multi-signature scripts also provide the number of required
		// signatures.
		if class == stdscript.STMultiSig {
			result.SigsRequired = int32(stdscript.DetermineRequiredSigs(version, script))
		}
	}

	if ka, ok := ka.(wallet.BIP0044Address); ok {
		acct, branch, child := ka.Path()
		if ka.AccountKind() != wallet.AccountKindImportedXpub {
			result.AccountN = &acct
		}
		result.Branch = &branch
		result.Index = &child
	}

	return result, nil
}

// verifyMessage handles the verifymessage command by verifying the provided
// compact signature for the given address and message.
func (s *Server) verifyMessage(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.VerifyMessageCmd)

	var valid bool

	// Decode address and base64 signature from the request.
	addr, err := stdaddr.DecodeAddress(cmd.Address, s.activeNet)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(cmd.Signature)
	if err != nil {
		return nil, err
	}

	// Addresses must have an associated secp256k1 private key and must be P2PKH
	// (P2PK and P2SH is not allowed).
	switch addr.(type) {
	case *stdaddr.AddressPubKeyHashEcdsaSecp256k1V0:
	default:
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"address must be secp256k1 pay-to-pubkey-hash")
	}

	valid, err = wallet.VerifyMessage(cmd.Message, addr, sig, s.activeNet)
	// Mirror Bitcoin Core behavior, which treats all erorrs as an invalid
	// signature.
	return err == nil && valid, nil
}

// version handles the version command by returning the RPC API versions of the
// wallet and, optionally, the consensus RPC server as well if it is associated
// with the server.  The chainClient is optional, and this is simply a helper
// function for the versionWithChainRPC and versionNoChainRPC handlers.
func (s *Server) version(ctx context.Context, icmd any) (any, error) {
	resp := make(map[string]mondtypes.VersionResult)
	n, _ := s.walletLoader.NetworkBackend()
	if chainSyncer, ok := n.(*chain.Syncer); ok {
		err := chainSyncer.RPC().Call(ctx, "version", &resp)
		if err != nil {
			return nil, err
		}
	}

	walletVersion := mondtypes.VersionResult{
		VersionString: version.String(),
		Major:         version.Major,
		Minor:         version.Minor,
		Patch:         version.Patch,
		Prerelease:    version.PreRelease,
		BuildMetadata: version.BuildMetadata,
	}
	apiVersion := mondtypes.VersionResult{
		VersionString: jsonrpcSemverString,
		Major:         jsonrpcSemverMajor,
		Minor:         jsonrpcSemverMinor,
		Patch:         jsonrpcSemverPatch,
	}
	resp["monw"] = walletVersion
	resp["monwjsonrpcapi"] = apiVersion
	return resp, nil
}

// walletInfo gets the current information about the wallet. If the daemon
// is connected and fails to ping, the function will still return that the
// daemon is disconnected.
func (s *Server) walletInfo(ctx context.Context, icmd any) (any, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	var connected, spvMode bool
	switch n, _ := w.NetworkBackend(); syncer := n.(type) {
	case *spv.Syncer:
		spvMode = true
		connected = len(syncer.GetRemotePeers()) > 0
	case *chain.Syncer:
		err := syncer.RPC().Call(ctx, "ping", nil)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			log.Warnf("Ping failed on connected daemon client: %v", err)
		} else {
			connected = true
		}
	case nil:
		log.Warnf("walletInfo - no network backend")
	default:
		log.Errorf("walletInfo - invalid network backend (%T).", n)
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCMisc,
			Message: "invalid network backend",
		}
	}

	coinType, err := w.CoinType(ctx)
	if errors.Is(err, errors.WatchingOnly) {
		// This is a watching-only wallet, which does not store the active coin
		// type. Return CoinTypes default value (0), which will be omitted from
		// the JSON response, and log a debug message.
		log.Debug("Watching only wallets do not store the coin type keys.")
	} else if err != nil {
		log.Errorf("Failed to retrieve the active coin type: %v", err)
		coinType = 0
	}

	unlocked := !(w.Locked())
	fi := w.RelayFee()
	voteBits := w.VoteBits()
	var voteVersion uint32
	_ = binary.Read(bytes.NewBuffer(voteBits.ExtendedBits[0:4]), binary.LittleEndian, &voteVersion)
	voting := w.VotingEnabled()

	wi := &types.WalletInfoResult{
		DaemonConnected:  connected,
		SPV:              spvMode,
		Unlocked:         unlocked,
		CoinType:         coinType,
		TxFee:            varAtomsToDecimalString(fi),
		VoteBits:         voteBits.Bits,
		VoteBitsExtended: hex.EncodeToString(voteBits.ExtendedBits),
		VoteVersion:      voteVersion,
		Voting:           voting,
		VSP:              s.cfg.VSPHost,
		ManualTickets:    w.ManualTickets(),
	}

	birthState, err := w.BirthState(ctx)
	if err != nil {
		log.Errorf("Failed to get birth state: %v", err)
	} else if birthState != nil &&
		!(birthState.SetFromTime || birthState.SetFromHeight) {
		wi.BirthHash = birthState.Hash.String()
		wi.BirthHeight = birthState.Height
	}

	return wi, nil
}

// walletIsLocked handles the walletislocked extension request by
// returning the current lock state (false for unlocked, true for locked)
// of an account.
func (s *Server) walletIsLocked(ctx context.Context, icmd any) (any, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	return w.Locked(), nil
}

// walletLock handles a walletlock request by locking the all account
// wallets, returning an error if any wallet is not encrypted (for example,
// a watching-only wallet).
func (s *Server) walletLock(ctx context.Context, icmd any) (any, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	if err := w.Lock(); err != nil {
		return nil, rpcErrorf(dcrjson.ErrRPCWallet, "wallet lock failed: %v", err)
	}
	return nil, nil
}

// walletPassphrase responds to the walletpassphrase request by unlocking the
// wallet. The decryption key is saved in the wallet until timeout seconds
// expires, after which the wallet is locked. A timeout of 0 leaves the wallet
// unlocked indefinitely.
func (s *Server) walletPassphrase(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.WalletPassphraseCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	timeout := time.Second * time.Duration(cmd.Timeout)
	var unlockAfter <-chan time.Time
	if timeout != 0 {
		unlockAfter = time.After(timeout)
	}
	err := w.Unlock(ctx, []byte(cmd.Passphrase), unlockAfter)
	return nil, err
}

// walletPassphraseChange responds to the walletpassphrasechange request
// by unlocking all accounts with the provided old passphrase, and
// re-encrypting each private key with an AES key derived from the new
// passphrase.
//
// If the old passphrase is correct and the passphrase is changed, all
// wallets will be immediately locked.
func (s *Server) walletPassphraseChange(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.WalletPassphraseChangeCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	err := w.ChangePrivatePassphrase(ctx, []byte(cmd.OldPassphrase),
		[]byte(cmd.NewPassphrase))
	if err != nil {
		if errors.Is(err, errors.Passphrase) {
			return nil, rpcErrorf(dcrjson.ErrRPCWalletPassphraseIncorrect, "incorrect passphrase")
		}
		return nil, err
	}
	return nil, nil
}

func (s *Server) mixOutput(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.MixOutputCmd)
	if !s.cfg.MixingEnabled {
		return nil, errors.E("Mixing is not configured")
	}
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	outpoint, err := parseOutpoint(cmd.Outpoint)
	if err != nil {
		return nil, err
	}

	mixAccount, err := w.AccountNumber(ctx, s.cfg.MixAccount)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAccountNotFound
		}
		return nil, err
	}
	changeAccount, err := w.AccountNumber(ctx, s.cfg.MixChangeAccount)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAccountNotFound
		}
		return nil, err
	}

	mixBranch := s.cfg.MixBranch

	err = w.MixOutput(ctx, outpoint, changeAccount, mixAccount, mixBranch)
	return nil, err
}

func (s *Server) mixAccount(ctx context.Context, icmd any) (any, error) {
	if !s.cfg.MixingEnabled {
		return nil, errors.E("Mixing is not configured")
	}
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	mixAccount, err := w.AccountNumber(ctx, s.cfg.MixAccount)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAccountNotFound
		}
		return nil, err
	}
	changeAccount, err := w.AccountNumber(ctx, s.cfg.MixChangeAccount)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAccountNotFound
		}
		return nil, err
	}

	mixBranch := s.cfg.MixBranch

	err = w.MixAccount(ctx, changeAccount, mixAccount, mixBranch)
	return nil, err
}

func parseOutpoint(s string) (*wire.OutPoint, error) {
	const op errors.Op = "parseOutpoint"
	if len(s) < 66 {
		return nil, errors.E(op, "bad len")
	}
	if s[64] != ':' { // sep follows 32 bytes of hex
		return nil, errors.E(op, "bad separator")
	}
	hash, err := chainhash.NewHashFromStr(s[:64])
	if err != nil {
		return nil, errors.E(op, err)
	}
	index, err := strconv.ParseUint(s[65:], 10, 32)
	if err != nil {
		return nil, errors.E(op, err)
	}
	return &wire.OutPoint{Hash: *hash, Index: uint32(index)}, nil
}

// walletPubPassphraseChange responds to the walletpubpassphrasechange request
// by modifying the public passphrase of the wallet.
func (s *Server) walletPubPassphraseChange(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.WalletPubPassphraseChangeCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	err := w.ChangePublicPassphrase(ctx, []byte(cmd.OldPassphrase),
		[]byte(cmd.NewPassphrase))
	if errors.Is(errors.Passphrase, err) {
		return nil, rpcErrorf(dcrjson.ErrRPCWalletPassphraseIncorrect, "incorrect passphrase")
	}
	return nil, err
}

func (s *Server) setAccountPassphrase(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.SetAccountPassphraseCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	account, err := w.AccountNumber(ctx, cmd.Account)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAccountNotFound
		}
		return nil, err
	}
	err = w.SetAccountPassphrase(ctx, account, []byte(cmd.Passphrase))
	return nil, err
}

func (s *Server) accountUnlocked(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.AccountUnlockedCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	account, err := w.AccountNumber(ctx, cmd.Account)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAccountNotFound
		}
		return nil, err
	}

	encrypted, err := w.AccountHasPassphrase(ctx, account)
	if err != nil {
		return nil, err
	}
	if !encrypted {
		return &types.AccountUnlockedResult{}, nil
	}

	unlocked, err := w.AccountUnlocked(ctx, account)
	if err != nil {
		return nil, err
	}

	return &types.AccountUnlockedResult{
		Encrypted: true,
		Unlocked:  &unlocked,
	}, nil
}

func (s *Server) unlockAccount(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.UnlockAccountCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	account, err := w.AccountNumber(ctx, cmd.Account)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAccountNotFound
		}
		return nil, err
	}
	err = w.UnlockAccount(ctx, account, []byte(cmd.Passphrase))
	return nil, err
}

func (s *Server) lockAccount(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.LockAccountCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	if cmd.Account == "*" {
		a, err := w.Accounts(ctx)
		if err != nil {
			return nil, err
		}
		for _, acct := range a.Accounts {
			if acct.AccountEncrypted && acct.AccountUnlocked {
				err = w.LockAccount(ctx, acct.AccountNumber)
				if err != nil {
					return nil, err
				}
			}
		}
		return nil, nil
	}

	account, err := w.AccountNumber(ctx, cmd.Account)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, errAccountNotFound
		}
		return nil, err
	}
	err = w.LockAccount(ctx, account)
	return nil, err
}

// decodeHexStr decodes the hex encoding of a string, possibly prepending a
// leading '0' character if there is an odd number of bytes in the hex string.
// This is to prevent an error for an invalid hex string when using an odd
// number of bytes when calling hex.Decode.
func decodeHexStr(hexStr string) ([]byte, error) {
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, rpcErrorf(dcrjson.ErrRPCDecodeHexString, "hex string decode failed: %v", err)
	}
	return decoded, nil
}

func (s *Server) getcoinjoinsbyacct(ctx context.Context, icmd any) (any, error) {
	_ = icmd.(*types.GetCoinjoinsByAcctCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	acctCoinjoinsSum, err := w.GetCoinjoinTxsSumbByAcct(ctx)
	if err != nil {
		if errors.Is(err, errors.Passphrase) {
			return nil, rpcErrorf(dcrjson.ErrRPCWalletPassphraseIncorrect, "incorrect passphrase")
		}
		return nil, err
	}

	acctNameCoinjoinSum := map[string]int{}
	for acctIdx, coinjoinSum := range acctCoinjoinsSum {
		accountName, err := w.AccountName(ctx, acctIdx)
		if err != nil {
			// Expect account lookup to succeed
			if errors.Is(err, errors.NotExist) {
				return nil, rpcError(dcrjson.ErrRPCInternal.Code, err)
			}
			return nil, err
		}
		acctNameCoinjoinSum[accountName] = coinjoinSum
	}

	return acctNameCoinjoinSum, nil
}

// coinBalanceAmounts holds the seven balance amounts rendered into the
// getcoinbalance response. Each field is either float64 (VAR) or string
// (SKA decimal) per the GetCoinBalanceResult schema. Stake-only fields are
// fixed to "0" for SKA since SKA does not participate in PoS.
type coinBalanceAmounts struct {
	ImmatureCoinbaseRewards string
	ImmatureStakeGeneration string
	LockedByTickets         string
	Spendable               string
	Total                   string
	Unconfirmed             string
	VotingAuthority         string
}

// renderCoinBalanceAmounts formats a CoinBalance for getcoinbalance output.
// Both VAR and SKA emit decimal coin strings via AtomsToDecimalString /
// SKAAmount.ToDecimalString — unified wire shape, preserves SKA precision.
func renderCoinBalanceAmounts(cb wallet.CoinBalance, isSKA bool, atomsPerCoin *big.Int) coinBalanceAmounts {
	if isSKA {
		return coinBalanceAmounts{
			ImmatureCoinbaseRewards: cb.SKAImmatureCoinbaseRewards.ToDecimalString(atomsPerCoin),
			ImmatureStakeGeneration: "0",
			LockedByTickets:         "0",
			Spendable:               cb.SKASpendable.ToDecimalString(atomsPerCoin),
			Total:                   cb.SKATotal.ToDecimalString(atomsPerCoin),
			Unconfirmed:             cb.SKAUnconfirmed.ToDecimalString(atomsPerCoin),
			VotingAuthority:         "0",
		}
	}
	return coinBalanceAmounts{
		ImmatureCoinbaseRewards: atomsToDecimalString(int64(cb.ImmatureCoinbaseRewards), atomsPerCoin),
		ImmatureStakeGeneration: atomsToDecimalString(int64(cb.ImmatureStakeGeneration), atomsPerCoin),
		LockedByTickets:         atomsToDecimalString(int64(cb.LockedByTickets), atomsPerCoin),
		Spendable:               atomsToDecimalString(int64(cb.Spendable), atomsPerCoin),
		Total:                   atomsToDecimalString(int64(cb.Total), atomsPerCoin),
		Unconfirmed:             atomsToDecimalString(int64(cb.Unconfirmed), atomsPerCoin),
		VotingAuthority:         atomsToDecimalString(int64(cb.VotingAuthority), atomsPerCoin),
	}
}

// getCoinBalance handles a getcoinbalance request by returning the balance
// for a specific coin type (VAR or SKA) with detailed breakdown.
func (s *Server) getCoinBalance(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GetCoinBalanceCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	coinType := cointype.CoinType(cmd.CoinType)
	minConf := int32(1)
	if cmd.MinConf != nil {
		minConf = int32(*cmd.MinConf)
		if minConf < 0 {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "minconf must be non-negative")
		}
	}

	// Validate coin type range and presence in chain params
	if err := validateCoinTypeConfigured(w.ChainParams(), coinType); err != nil {
		return nil, err
	}

	// Get AtomsPerCoin for the specified coin type
	atomsPerCoin := getAtomsPerCoin(w.ChainParams(), coinType)
	isSKA := coinType.IsSKA()

	accountName := "*"
	if cmd.Account != nil {
		accountName = *cmd.Account
	}

	blockHash, _ := w.MainChainTip(ctx)

	if accountName == "*" {
		// Get total balance for this coin type across all accounts
		totalBalance, err := w.TotalBalanceByCoinType(ctx, coinType, minConf)
		if err != nil {
			return nil, err
		}

		// Get per-account breakdown
		allBalances, err := w.AccountBalances(ctx, minConf)
		if err != nil {
			return nil, err
		}

		totals := renderCoinBalanceAmounts(totalBalance, isSKA, atomsPerCoin)
		result := types.GetCoinBalanceResult{
			CoinType:                     uint8(coinType),
			BlockHash:                    blockHash.String(),
			TotalImmatureCoinbaseRewards: totals.ImmatureCoinbaseRewards,
			TotalImmatureStakeGeneration: totals.ImmatureStakeGeneration,
			TotalLockedByTickets:         totals.LockedByTickets,
			TotalSpendable:               totals.Spendable,
			TotalUnconfirmed:             totals.Unconfirmed,
			TotalVotingAuthority:         totals.VotingAuthority,
			CumulativeTotal:              totals.Total,
		}

		// Add per-account breakdown
		result.Balances = make([]types.GetCoinAccountBalanceResult, 0)
		for _, balance := range allBalances {
			coinBalance, exists := balance.CoinTypeBalances[coinType]
			if !exists {
				continue
			}
			hasBalance := (isSKA && !coinBalance.SKATotal.IsZero()) || (!isSKA && coinBalance.Total > 0)
			if !hasBalance {
				continue
			}
			accountName, err := w.AccountName(ctx, balance.Account)
			if err != nil {
				if errors.Is(err, errors.NotExist) {
					return nil, rpcError(dcrjson.ErrRPCInternal.Code, err)
				}
				return nil, err
			}

			amounts := renderCoinBalanceAmounts(coinBalance, isSKA, atomsPerCoin)
			result.Balances = append(result.Balances, types.GetCoinAccountBalanceResult{
				AccountName:             accountName,
				CoinType:                uint8(coinType),
				ImmatureCoinbaseRewards: amounts.ImmatureCoinbaseRewards,
				ImmatureStakeGeneration: amounts.ImmatureStakeGeneration,
				LockedByTickets:         amounts.LockedByTickets,
				Spendable:               amounts.Spendable,
				Total:                   amounts.Total,
				Unconfirmed:             amounts.Unconfirmed,
				VotingAuthority:         amounts.VotingAuthority,
			})
		}

		return result, nil
	} else {
		// Single account query
		account, err := w.AccountNumber(ctx, accountName)
		if err != nil {
			if errors.Is(err, errors.NotExist) {
				return nil, errAccountNotFound
			}
			return nil, err
		}

		coinBalance, err := w.AccountBalanceByCoinType(ctx, account, coinType, minConf)
		if err != nil {
			return nil, err
		}

		amounts := renderCoinBalanceAmounts(coinBalance, isSKA, atomsPerCoin)
		return types.GetCoinBalanceResult{
			CoinType:                     uint8(coinType),
			BlockHash:                    blockHash.String(),
			TotalImmatureCoinbaseRewards: amounts.ImmatureCoinbaseRewards,
			TotalImmatureStakeGeneration: amounts.ImmatureStakeGeneration,
			TotalLockedByTickets:         amounts.LockedByTickets,
			TotalSpendable:               amounts.Spendable,
			TotalUnconfirmed:             amounts.Unconfirmed,
			TotalVotingAuthority:         amounts.VotingAuthority,
			CumulativeTotal:              amounts.Total,
			Balances: []types.GetCoinAccountBalanceResult{{
				AccountName:             accountName,
				CoinType:                uint8(coinType),
				ImmatureCoinbaseRewards: amounts.ImmatureCoinbaseRewards,
				ImmatureStakeGeneration: amounts.ImmatureStakeGeneration,
				LockedByTickets:         amounts.LockedByTickets,
				Spendable:               amounts.Spendable,
				Total:                   amounts.Total,
				Unconfirmed:             amounts.Unconfirmed,
				VotingAuthority:         amounts.VotingAuthority,
			}},
		}, nil
	}
}

// listCoinTypes handles a listcointypes request by returning all coin types
// that have non-zero balances in the wallet with balance information.
func (s *Server) listCoinTypes(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.ListCoinTypesCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	minConf := int32(1)
	if cmd.MinConf != nil {
		minConf = int32(*cmd.MinConf)
		if minConf < 0 {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "minconf must be non-negative")
		}
	}

	// Get list of active coin types from wallet
	coinTypes, err := w.ListCoinTypes(ctx, minConf)
	if err != nil {
		return nil, err
	}

	result := types.ListCoinTypesResult{
		CoinTypes: make([]types.CoinTypeInfo, 0, len(coinTypes)),
	}

	// Get balance for each coin type and create info
	for _, coinType := range coinTypes {
		balance, err := w.TotalBalanceByCoinType(ctx, coinType, minConf)
		if err != nil {
			return nil, err
		}

		// Get the correct AtomsPerCoin for this coin type
		atomsPerCoin := getAtomsPerCoin(w.ChainParams(), coinType)

		// Generate human-readable name
		var name string
		if coinType == cointype.CoinTypeVAR {
			name = "VAR"
		} else {
			name = fmt.Sprintf("SKA%d", coinType)
		}

		// Both VAR and SKA emit decimal coin strings — unified API contract.
		var balanceValue string
		if coinType.IsSKA() {
			balanceValue = balance.SKASpendable.ToDecimalString(atomsPerCoin)
		} else {
			balanceValue = atomsToDecimalString(int64(balance.Spendable), atomsPerCoin)
		}

		info := types.CoinTypeInfo{
			CoinType: uint8(coinType),
			Name:     name,
			Balance:  balanceValue,
		}

		result.CoinTypes = append(result.CoinTypes, info)
	}

	return result, nil
}

// auditKeyName redacts a caller-supplied emission-key name for audit logs.
// Operator docs forbid embedding secrets or PII in key names, but the audit
// log is permanent and operator discipline is fallible — return a SHA-256/8
// hex digest plus the length so logs correlate without echoing the raw name.
// The pubkey hex logged alongside is the canonical identifier; the digest is
// for operator-side cross-referencing only.
func auditKeyName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return fmt.Sprintf("%s(len=%d)", hex.EncodeToString(sum[:8]), len(name))
}

// auditFallbackCounter is the monotonic-counter source used when crypto/rand
// fails. A literal "unknown" sentinel would correlate every fallback line to
// the same token; a counter at least guarantees per-event uniqueness within
// a process, distinguishable from real random IDs by the "fallback-" prefix.
var auditFallbackCounter atomic.Uint64

// auditRequestID returns an 8-byte hex correlation ID for one emission audit
// event. The wsrpc layer does not inject a request ID into the context, so we
// mint one at audit-log time. Operators cross-reference the value against the
// access log by timestamp + ID to recover "which RPC client retrieved this
// emission key" forensically. crypto/rand is used so an attacker cannot
// fabricate a matching ID after the fact.
func auditRequestID() string {
	var b [8]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		// crypto/rand failure is exceptional; fall back to a per-process
		// monotonic counter so an operator forensically reconstructing
		// emission key access does not see correlated lines that are not
		// in fact the same request. The "fallback-" prefix marks these
		// lines as non-random so they are distinguishable in the log.
		return fmt.Sprintf("fallback-%016x", auditFallbackCounter.Add(1))
	}
	return hex.EncodeToString(b[:])
}

// getEmissionKeyForCoinType retrieves a stored emission key by name and validates
// it matches the governance-approved public key for the specified coin type.
func getEmissionKeyForCoinType(w *wallet.Wallet, ctx context.Context, coinType cointype.CoinType, keyName string) (*secp256k1.PrivateKey, error) {
	const op errors.Op = "rpc.getEmissionKeyForCoinType"

	// Defensive precondition: emission keys are decrypted under the master
	// key, so the wallet must be unlocked. Every caller today routes through
	// withWalletPassphraseGate, but a future caller that forgets the gate
	// would surface a misleading "key not found" error from the underlying
	// store. Fail loudly here instead.
	if w.Locked() {
		return nil, errors.E(op, errors.Locked, errors.Errorf(
			"wallet must be unlocked to retrieve emission key %s", keyName))
	}

	privateKey, err := retrieveEmissionKeyByName(w, ctx, keyName)
	if err != nil {
		// Preserve the underlying error class (Passphrase, Crypto, NotExist,
		// ...) so operators see the real cause of an emission key fetch
		// failure instead of a misleading "not found".
		return nil, errors.E(op, err)
	}

	chainParams := w.ChainParams()
	authorizedKey := chainParams.GetSKAEmissionKey(coinType)
	if authorizedKey == nil {
		return nil, errors.E(op, errors.Invalid, errors.Errorf(
			"no emission key configured for coin type %d in governance settings", coinType))
	}

	publicKey := privateKey.PubKey()
	if !bytes.Equal(publicKey.SerializeCompressed(), authorizedKey.SerializeCompressed()) {
		return nil, errors.E(op, errors.Invalid, errors.Errorf(
			"stored key %s does not match governance-approved public key for coin type %d", keyName, coinType))
	}

	// Audit log: emission keys are the highest-privilege secret in the
	// wallet, so every successful retrieval is recorded with public material
	// only (redacted key-name digest, pubkey hex, coin type, request ID).
	// Never log the private key bytes. The keyName is hashed via auditKeyName
	// so an operator who ignored the docs and put a secret in the name does
	// not leak it into permanent logs; the pubkey hex is the canonical
	// identifier. The reqID is a per-event correlation token so operators
	// can tie this line to an entry in the wsrpc access log when forensically
	// reconstructing "who retrieved this key, when".
	log.Infof("emission key retrieved: reqID=%s keyNameDigest=%s pubkey=%x coinType=%d",
		auditRequestID(), auditKeyName(keyName), publicKey.SerializeCompressed(), coinType)

	return privateKey, nil
}

// createEmissionAuthHashFromTx creates the authorization hash for SKA emission signing.
// SECURITY: This function creates a hash that binds the signature to:
// - The exact transaction outputs (preventing miner redirect attacks)
// - The network ID (preventing cross-network replay)
// - The coin type, nonce, and block height
func createEmissionAuthHashFromTx(tx *wire.MsgTx, auth *chaincfg.SKAEmissionAuth,
	_ int64, chainParams *chaincfg.Params) ([32]byte, error) {

	// Compute the transaction hash using no-witness serialization
	// This ensures the signature binds to the exact outputs
	txBytes, err := tx.BytesPrefix()
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to serialize transaction: %w", err)
	}
	txHash := sha256.Sum256(txBytes)

	// Build the domain-separated signing message
	// Format: "SKA-EMIT-V2" || netID || coinType || nonce || blockHeight || txHash
	var msgBuf bytes.Buffer

	// Domain separator to prevent signature reuse in other contexts
	msgBuf.WriteString("SKA-EMIT-V2")

	// Network ID for replay protection across networks
	if err := binary.Write(&msgBuf, binary.LittleEndian, uint32(chainParams.Net)); err != nil {
		return [32]byte{}, fmt.Errorf("failed to write network ID: %w", err)
	}

	// Coin type
	msgBuf.WriteByte(byte(auth.CoinType))

	// Nonce for replay protection within network
	if err := binary.Write(&msgBuf, binary.LittleEndian, auth.Nonce); err != nil {
		return [32]byte{}, fmt.Errorf("failed to write nonce: %w", err)
	}

	// Use auth.Height (signed by emitter) instead of current blockHeight
	// This allows broadcasting to mempool and inclusion at any valid height within window
	if err := binary.Write(&msgBuf, binary.LittleEndian, uint64(auth.Height)); err != nil {
		return [32]byte{}, fmt.Errorf("failed to write authorization height: %w", err)
	}

	// Transaction hash - this binds the signature to exact outputs
	msgBuf.Write(txHash[:])

	// Create the final message hash
	return sha256.Sum256(msgBuf.Bytes()), nil
}

// createUnsignedSKAEmissionTransaction creates an unsigned SKA emission transaction.
// The transaction will be signed separately after creation to bind the signature
// to the transaction hash (preventing miner redirect attacks).
func createUnsignedSKAEmissionTransaction(auth *chaincfg.SKAEmissionAuth,
	emissionAddresses []string, amounts []*big.Int, chainParams *chaincfg.Params) (*wire.MsgTx, error) {

	// Validate authorization structure
	if auth == nil {
		return nil, fmt.Errorf("SKA emission authorization required")
	}

	if auth.EmissionKey == nil {
		return nil, fmt.Errorf("SKA emission key required")
	}

	// Note: Signature is not required here since this creates an unsigned transaction
	// The signature will be added after the transaction is created

	// Validate coin type
	if auth.CoinType < 1 || auth.CoinType > 255 {
		return nil, fmt.Errorf("invalid SKA coin type: %d", auth.CoinType)
	}

	// Check if emission is authorized for this coin type
	authorizedKey := chainParams.GetSKAEmissionKey(auth.CoinType)
	if authorizedKey == nil {
		return nil, fmt.Errorf("no emission key configured for coin type %d", auth.CoinType)
	}

	// Verify the provided key matches the authorized key
	if !bytes.Equal(auth.EmissionKey.SerializeCompressed(),
		authorizedKey.SerializeCompressed()) {
		return nil, fmt.Errorf("unauthorized emission key for coin type %d", auth.CoinType)
	}

	// NOTE: Nonce checking is NOT performed during transaction creation
	// because wallets cannot reliably know the chain state due to reorgs and lag.
	// The nonce will be validated during block acceptance in mond
	// which uses the actual blockchain state for proper replay protection.

	// Validate emission amounts
	if len(emissionAddresses) != len(amounts) {
		return nil, fmt.Errorf("emission addresses and amounts length mismatch")
	}

	if len(emissionAddresses) == 0 {
		return nil, fmt.Errorf("no emission addresses specified")
	}

	zero := new(big.Int)
	totalAmount := new(big.Int)
	for _, amount := range amounts {
		if amount == nil || amount.Cmp(zero) <= 0 {
			return nil, fmt.Errorf("invalid emission amount: %s", amount)
		}
		totalAmount.Add(totalAmount, amount)
	}

	// Verify total matches authorization
	if totalAmount.Cmp(auth.Amount) != 0 {
		return nil, fmt.Errorf("total emission amount %s does not match authorization %s",
			totalAmount.String(), auth.Amount.String())
	}

	// Get the SKA coin config for this coin type and validate emission window
	skaConfig, exists := chainParams.SKACoins[auth.CoinType]
	if !exists {
		return nil, fmt.Errorf("SKA coin type %d not configured", auth.CoinType)
	}

	// Verify emission height is within the emission window
	emissionStart := int64(skaConfig.EmissionHeight)
	emissionEnd := emissionStart + int64(skaConfig.EmissionWindow)
	if auth.Height < emissionStart || auth.Height > emissionEnd {
		return nil, fmt.Errorf("emission height %d is outside emission window [%d, %d] for coin type %d",
			auth.Height, emissionStart, emissionEnd, auth.CoinType)
	}
	// Expiry is a uint32 on the wire; refuse to construct a transaction whose
	// emission-window end would silently wrap. Current chain params fit
	// comfortably, but a future misconfiguration of EmissionHeight or
	// EmissionWindow must fail loudly rather than truncate.
	if emissionEnd < 0 || emissionEnd > math.MaxUint32 {
		return nil, fmt.Errorf("emission window end %d cannot be represented as a 32-bit Expiry for coin type %d — chain params misconfigured",
			emissionEnd, auth.CoinType)
	}

	// Note: Signature verification is not done here since we're creating an unsigned transaction.
	// The signature will be added after the transaction is created.

	// Create the authorized emission transaction with Expiry set to window end
	// This ensures automatic mempool cleanup if the emission window expires
	tx := &wire.MsgTx{
		SerType:  wire.TxSerializeFull,
		Version:  1,
		LockTime: 0,
		Expiry:   uint32(emissionEnd),
	}

	// Create signature script with authorization data
	authScript, err := createEmissionAuthScript(auth)
	if err != nil {
		return nil, fmt.Errorf("failed to create authorization script: %w", err)
	}

	// Add null input for emission with full authorization script
	tx.TxIn = append(tx.TxIn, &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash{}, // All zeros
			Index: 0xffffffff,       // Max value indicates null
			Tree:  wire.TxTreeRegular,
		},
		SignatureScript: authScript,
		Sequence:        0xffffffff,
		BlockHeight:     wire.NullBlockHeight,
		BlockIndex:      wire.NullBlockIndex,
		ValueIn:         wire.NullValueIn,
	})

	// Add outputs for each emission address
	for i, addressStr := range emissionAddresses {
		addr, err := stdaddr.DecodeAddress(addressStr, chainParams)
		if err != nil {
			return nil, fmt.Errorf("invalid emission address %s: %w", addressStr, err)
		}

		// Create script for the address
		_, pkScript := addr.PaymentScript()

		// Add SKA output with specific coin type. Defensive-copy the
		// caller's *big.Int into the wire tx so a later mutation by the
		// caller cannot retroactively change the emission output amount —
		// matches the pattern used for txIn.SKAValueIn elsewhere.
		var skaValue *big.Int
		if amounts[i] != nil {
			skaValue = new(big.Int).Set(amounts[i])
		}
		tx.TxOut = append(tx.TxOut, &wire.TxOut{
			Value:    0,             // Not used for SKA
			SKAValue: skaValue,      // SKA uses big.Int for amounts
			CoinType: auth.CoinType, // Use authorized coin type
			Version:  0,
			PkScript: pkScript,
		})
	}

	return tx, nil
}

// createEmissionAuthScript creates the authorization script for SKA emission input.
// Format v3 (for big.Int amounts):
// [SKA_marker:4][auth_version:1][nonce:8][coin_type:1][amount_len:1][amount:N][height:8][pubkey:33][sig_len:1][signature:var]
func createEmissionAuthScript(auth *chaincfg.SKAEmissionAuth) ([]byte, error) {
	var script bytes.Buffer

	// Standard SKA emission marker
	script.Write([]byte{0x01, 0x53, 0x4b, 0x41}) // "SKA" marker

	// Authorization data - version 0x03 for big.Int amounts
	script.WriteByte(0x03) // Auth version 3

	// Nonce (8 bytes)
	nonceBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonceBytes, auth.Nonce)
	script.Write(nonceBytes)

	// Coin type (1 byte)
	script.WriteByte(uint8(auth.CoinType))

	// Amount (variable length big.Int)
	// Write length prefix (1 byte) followed by big-endian bytes
	amountBytes := auth.Amount.Bytes() // Big-endian representation
	if len(amountBytes) > 255 {
		return nil, fmt.Errorf("amount too large: %d bytes (max 255)", len(amountBytes))
	}
	script.WriteByte(uint8(len(amountBytes)))
	script.Write(amountBytes)

	// Height (8 bytes)
	heightBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(heightBytes, uint64(auth.Height))
	script.Write(heightBytes)

	// Public key (33 bytes compressed)
	pubKeyBytes := auth.EmissionKey.SerializeCompressed()
	script.Write(pubKeyBytes)

	// Signature length and signature. Bound length explicitly: secp256k1 ECDSA-DER
	// signatures are at most ~72 bytes today, but a future caller passing a Schnorr
	// or aggregated form whose serialized size exceeded 255 bytes would otherwise
	// have len(...) silently truncated by the uint8 cast and produce a malformed
	// script that consensus would reject during emission. Mirrors the amountBytes
	// check above.
	if len(auth.Signature) > 255 {
		return nil, fmt.Errorf("signature too large: %d bytes (max 255)", len(auth.Signature))
	}
	script.WriteByte(uint8(len(auth.Signature)))
	script.Write(auth.Signature)

	return script.Bytes(), nil
}

// generateEmissionKey handles a generateemissionkey request by creating a new private key
// for SKA emission authorization (primary flow - key exists before governance).
//
// Capability gate: cmd.WalletPassphrase is required. The wallet is unlocked
// for the duration of this single call and re-locked on return; the ambient
// walletpassphrase unlock window is intentionally NOT used. This prevents a
// concurrent authenticated RPC client from minting emission keys during an
// operator's open unlock window.
func (s *Server) generateEmissionKey(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.GenerateEmissionKeyCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Validate coin type if provided (optional parameter)
	if cmd.CoinType != nil && (*cmd.CoinType < 1 || *cmd.CoinType > 255) {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"coin type must be between 1 and 255 (SKA types)")
	}

	// Validate key name
	if cmd.KeyName == "" {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"key name cannot be empty")
	}

	// Require an explicit wallet passphrase. Falling back to the ambient
	// walletpassphrase unlock window would preserve the very gap this
	// per-call gate is closing.
	if cmd.WalletPassphrase == "" {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"walletpassphrase is required")
	}

	return withWalletUnlocked(ctx, w, cmd.WalletPassphrase, func() (any, error) {
		// Generate new private key for emission
		privateKey, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			return nil, rpcErrorf(dcrjson.ErrRPCInternal.Code,
				"failed to generate private key: %v", err)
		}

		publicKey := privateKey.PubKey()

		// Store the emission key in wallet database (coin-type agnostic)
		err = storeGeneratedEmissionKey(w, ctx, cmd.KeyName, privateKey)
		if err != nil {
			return nil, rpcErrorf(dcrjson.ErrRPCWallet,
				"failed to store emission key: %v", err)
		}

		// Audit log: emission keys are the highest-privilege secret in the
		// wallet, so every store/retrieve is recorded with public material
		// only (redacted key-name digest, pubkey hex, optional coin type).
		// Never log the private key bytes or the raw key name; see
		// auditKeyName for the digest contract.
		log.Infof("generateemissionkey: stored emission key keyNameDigest=%s pubkey=%x coinType=%s",
			auditKeyName(cmd.KeyName), publicKey.SerializeCompressed(), formatOptionalCoinType(cmd.CoinType))

		// The canonical backup is the wallet DB itself (stored under CKTEmission,
		// scrypt-protected by the wallet's master passphrase). The encrypted backup
		// blob is only returned when the caller explicitly opts in, since it
		// otherwise appears in RPC logs, proxies, and debug traces.
		result := &types.GenerateEmissionKeyResult{
			Success:   true,
			KeyName:   cmd.KeyName,
			PublicKey: hex.EncodeToString(publicKey.SerializeCompressed()),
		}
		if cmd.CoinType != nil {
			result.CoinType = *cmd.CoinType
		}
		if cmd.ReturnEncryptedBackup != nil && *cmd.ReturnEncryptedBackup {
			if err := requireBackupPassphrase(cmd.Passphrase); err != nil {
				return nil, err
			}
			encryptedPrivateKey, err := encryptPrivateKeyWithPassphrase(privateKey, cmd.Passphrase)
			if err != nil {
				return nil, rpcErrorf(dcrjson.ErrRPCInternal.Code,
					"failed to encrypt private key: %v", err)
			}
			result.EncryptedPrivateKey = encryptedPrivateKey
		}

		return result, nil
	})
}

// importEmissionKey handles an importemissionkey request by storing a private key
// used for SKA emission authorization in the wallet database (emergency/recovery only).
//
// Capability gate: cmd.WalletPassphrase is required. The wallet is unlocked
// for the duration of this single call and re-locked on return; the ambient
// walletpassphrase unlock window is intentionally NOT used. See generateEmissionKey.
func (s *Server) importEmissionKey(ctx context.Context, icmd any) (any, error) {
	cmd := icmd.(*types.ImportEmissionKeyCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Validate coin type if provided (optional parameter)
	if cmd.CoinType != nil && (*cmd.CoinType < 1 || *cmd.CoinType > 255) {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"coin type must be between 1 and 255 (SKA types)")
	}

	// Validate key name
	if cmd.KeyName == "" {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"key name cannot be empty")
	}

	// Require an explicit wallet passphrase. Falling back to the ambient
	// walletpassphrase unlock window would preserve the very gap this
	// per-call gate is closing.
	if cmd.WalletPassphrase == "" {
		return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"walletpassphrase is required")
	}

	// Parse private key - handle both encrypted and plain hex formats
	var privateKey *secp256k1.PrivateKey
	var err error

	if strings.HasPrefix(cmd.PrivateKey, "aes256gcm:") {
		// Encrypted format - decrypt with provided passphrase
		if err := requireBackupPassphrase(cmd.Passphrase); err != nil {
			return nil, err
		}
		privateKey, err = decryptPrivateKeyWithPassphrase(cmd.PrivateKey, cmd.Passphrase)
		if err != nil {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"failed to decrypt private key: %v", err)
		}
	} else {
		// Plain hex format - backward compatibility.
		privateKeyBytes, decodeErr := hex.DecodeString(cmd.PrivateKey)
		// Wipe the decoded bytes on return so the raw key material does not
		// linger on the heap. zeroBytes is nil-safe so this also covers the
		// hex-decode error path.
		defer zeroBytes(privateKeyBytes)
		if decodeErr != nil {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter,
				"invalid private key hex: %v", decodeErr)
		}
		// secp256k1.PrivKeyFromBytes silently truncates >32 bytes and
		// mod-reduces; parseSecp256k1Private rejects both non-32-byte
		// inputs and post-reduction zero scalars.
		var parseErr error
		privateKey, parseErr = parseSecp256k1Private(privateKeyBytes)
		if parseErr != nil {
			return nil, rpcErrorf(dcrjson.ErrRPCInvalidParameter, "%v", parseErr)
		}
	}

	publicKey := privateKey.PubKey()

	return withWalletUnlocked(ctx, w, cmd.WalletPassphrase, func() (any, error) {
		// Store the imported emission key in wallet database. Storage is
		// cointype-agnostic; governance validation is deferred to
		// createauthorizedemission.
		if err := storeGeneratedEmissionKey(w, ctx, cmd.KeyName, privateKey); err != nil {
			return nil, rpcErrorf(dcrjson.ErrRPCWallet,
				"failed to store emission key: %v", err)
		}

		// Audit log: see generateEmissionKey for rationale. Public material only.
		log.Infof("importemissionkey: stored emission key keyNameDigest=%s pubkey=%x coinType=%s",
			auditKeyName(cmd.KeyName), publicKey.SerializeCompressed(), formatOptionalCoinType(cmd.CoinType))

		result := &types.ImportEmissionKeyResult{
			Success:   true,
			KeyName:   cmd.KeyName,
			PublicKey: hex.EncodeToString(publicKey.SerializeCompressed()),
		}
		if cmd.CoinType != nil {
			result.CoinType = *cmd.CoinType
		}
		return result, nil
	})
}

// storeGeneratedEmissionKey stores a newly generated emission private key in the wallet database.
// This key is coin-type agnostic - the same key can be used for multiple coin types if governance approves.
func storeGeneratedEmissionKey(w *wallet.Wallet, ctx context.Context, keyName string, privateKey *secp256k1.PrivateKey) error {
	// Store the emission key using the wallet's public method
	return w.StoreEmissionKey(ctx, keyName, privateKey)
}

// retrieveEmissionKeyByName retrieves an emission private key by name from the wallet database.
// This is coin-type agnostic - the caller must validate the key matches governance settings.
func retrieveEmissionKeyByName(w *wallet.Wallet, ctx context.Context, keyName string) (*secp256k1.PrivateKey, error) {
	// Retrieve the emission key using the wallet's public method
	return w.RetrieveEmissionKey(ctx, keyName)
}

// formatOptionalCoinType renders a *uint8 coin type for audit log lines.
// Returns "<unset>" when the caller did not specify a coin type so the log
// line stays unambiguous about the absence vs. coin type 0.
func formatOptionalCoinType(ct *uint8) string {
	if ct == nil {
		return "<unset>"
	}
	return strconv.FormatUint(uint64(*ct), 10)
}

// Emission-key backup KDF parameters. Match wallet/internal/snacl defaults.
const (
	emissionKDFVersion = "v3"
	emissionKDFSaltLen = 16
	emissionKDFN       = 1 << 15
	emissionKDFR       = 8
	emissionKDFP       = 1
	emissionKDFKeyLen  = 32

	// numV3BlobParts is the colon-delimited part count of a v3 backup blob:
	// "aes256gcm:v3:salt:N:r:p:nonce:ciphertext" → 8 parts.
	// A future v4 format must update both this constant and the prefix-strip
	// in decryptPrivateKeyWithPassphrase.
	numV3BlobParts = 8
)

// emissionBackupAAD builds the AES-GCM additional-authenticated-data string
// that binds the scrypt KDF parameters (salt, N, r, p) into the v3 ciphertext.
// Without this binding, an attacker who can modify the blob in transit could
// swap the salt or KDF cost parameters; with the binding any tampering is
// detected at gcm.Open time. The format must be reconstructed identically on
// encrypt and decrypt — do not change without bumping emissionKDFVersion.
func emissionBackupAAD(version string, salt []byte, n, r, p int) []byte {
	return []byte(fmt.Sprintf("%s:%s:%d:%d:%d",
		version, hex.EncodeToString(salt), n, r, p))
}

// zeroBytes overwrites the given slice with zeros.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// withWalletUnlocked runs fn with the wallet temporarily unlocked using the
// supplied passphrase. The cleartext []byte copy is wiped on return; if the
// wallet was locked before the call, it is re-locked on return (even on panic).
// The ambient walletpassphrase unlock window is NOT relied on. This is the
// per-call capability gate used by emission and burn RPCs so that a compromised
// authenticated client which races against an open walletpassphrase window
// cannot mint coins.
//
// On Unlock failure the underlying error is intentionally not wrapped (matching
// the createauthorizedemission/sendtoburn convention) to avoid leaking internal
// DB/cipher strings to clients.
//
// Caveat: only the local []byte copy is wiped here. The caller-supplied Go
// `string` (typically allocated by the dcrjson parser when parsing the RPC
// request body) is immutable and remains in heap memory until the garbage
// collector reclaims it. Operators should treat the wallet master passphrase
// as exposed to the host's process memory for as long as the request lifetime
// + GC delay, and not reuse it across services. See SECURITY.md.
func withWalletUnlocked(ctx context.Context, w *wallet.Wallet, passphrase string, fn func() (any, error)) (any, error) {
	return withWalletPassphraseGate(ctx, w, passphrase, fn)
}

// walletPassphraseGate is the subset of *wallet.Wallet that withWalletUnlocked
// touches. Extracting it lets unit tests exercise the relock semantics without
// standing up a real wallet fixture.
type walletPassphraseGate interface {
	Locked() bool
	Unlock(ctx context.Context, passphrase []byte, timeout <-chan time.Time) error
	Lock() error
}

// withWalletPassphraseGate runs fn after unlocking gate with passphrase, then
// always relocks before returning. The relock is unconditional: any ambient
// `walletpassphrase` window held by another caller is terminated when this
// function returns. That is the per-call capability gate's whole purpose —
// without it, a privileged bystander could ride out an emission/burn call's
// unlock window and reuse it for unrelated authenticated RPCs (sendtoaddress,
// signrawtransaction, etc.).
//
// Operators issuing emission/burn against an already-unlocked wallet must
// re-issue `walletpassphrase` afterward to restore ambient access.
//
// If fn returns an error and the relock also fails, fn's error wins (it is the
// more useful diagnostic for the caller). Either failure is logged.
func withWalletPassphraseGate(ctx context.Context, gate walletPassphraseGate, passphrase string, fn func() (any, error)) (any, error) {
	pp := []byte(passphrase)
	defer zeroBytes(pp)

	if err := gate.Unlock(ctx, pp, nil); err != nil {
		return nil, rpcErrorf(dcrjson.ErrRPCWalletPassphraseIncorrect, "incorrect passphrase")
	}

	result, fnErr := fn()
	if lockErr := gate.Lock(); lockErr != nil {
		log.Errorf("post-capability-gate relock failed: %v", lockErr)
		if fnErr == nil {
			return nil, rpcErrorf(dcrjson.ErrRPCWallet, "wallet relock failed: %v", lockErr)
		}
	}
	return result, fnErr
}

// minBackupPassphraseLen is the minimum length required for an emission-key
// backup passphrase. A leaked encrypted backup is a permanent capability for
// the lifetime of the SKA coin, so a weak passphrase (or empty string) would
// reduce the AES-256-GCM blob to a trivially-decryptable artifact.
const minBackupPassphraseLen = 12

// requireBackupPassphrase enforces the minimum passphrase length for emission-key
// backup encrypt/decrypt paths. The passphrase value itself is never echoed in
// the returned error.
func requireBackupPassphrase(passphrase string) error {
	if len(passphrase) < minBackupPassphraseLen {
		return rpcErrorf(dcrjson.ErrRPCInvalidParameter,
			"passphrase must be at least %d characters for emission-key backup",
			minBackupPassphraseLen)
	}
	return nil
}

// encryptPrivateKeyWithPassphrase encrypts an emission private key for user-held
// backup with a passphrase. Uses scrypt(N=2^15,r=8,p=1) to derive a 32-byte
// AES-256-GCM key from the passphrase with a fresh random 16-byte salt, then
// AES-256-GCM with a random 12-byte nonce. The KDF parameters (salt, N, r, p)
// are bound into the ciphertext via AES-GCM additional-authenticated-data, so
// any in-transit tampering with those fields is detected on decrypt.
//
// Blob format: "aes256gcm:v3:<hex-salt>:<N>:<r>:<p>:<hex-nonce>:<hex-ciphertext>"
func encryptPrivateKeyWithPassphrase(privateKey *secp256k1.PrivateKey, passphrase string) (string, error) {
	pp := []byte(passphrase)
	defer zeroBytes(pp)

	salt := make([]byte, emissionKDFSaltLen)
	if _, err := cryptorand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %v", err)
	}

	key, err := scrypt.Key(pp, salt, emissionKDFN, emissionKDFR, emissionKDFP, emissionKDFKeyLen)
	if err != nil {
		return "", fmt.Errorf("scrypt key derivation failed: %v", err)
	}
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := cryptorand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	privateKeyBytes := privateKey.Serialize()
	defer zeroBytes(privateKeyBytes)
	aad := emissionBackupAAD(emissionKDFVersion, salt, emissionKDFN, emissionKDFR, emissionKDFP)
	ciphertext := gcm.Seal(nil, nonce, privateKeyBytes, aad)

	return fmt.Sprintf("aes256gcm:%s:%s:%d:%d:%d:%s:%s",
		emissionKDFVersion,
		hex.EncodeToString(salt),
		emissionKDFN, emissionKDFR, emissionKDFP,
		hex.EncodeToString(nonce),
		hex.EncodeToString(ciphertext),
	), nil
}

// parseSecp256k1Private validates raw private-key bytes and returns the
// resulting *secp256k1.PrivateKey. secp256k1.PrivKeyFromBytes silently
// truncates inputs longer than 32 bytes and mod-reduces, so callers must
// reject non-32-byte input upfront; a post-reduction zero scalar is also
// invalid (would produce signatures that the consensus validator rejects).
// Used by both the plain-hex import path and the AES-GCM-v3 backup
// decryption path. The caller owns the input slice and is expected to
// zero it after this returns.
func parseSecp256k1Private(b []byte) (*secp256k1.PrivateKey, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("private key must be exactly 32 bytes (got %d)", len(b))
	}
	priv := secp256k1.PrivKeyFromBytes(b)
	if priv.Key.IsZero() {
		return nil, fmt.Errorf("private key is zero or out of range")
	}
	return priv, nil
}

// decryptPrivateKeyWithPassphrase decrypts a v3 emission-key backup blob produced
// by encryptPrivateKeyWithPassphrase. Legacy v1 blobs ("aes256gcm:<iv>:<ct>",
// sha256(passphrase) KDF, no salt) and v2 blobs (scrypt+AES-GCM but no AAD on
// KDF params) are rejected; users with older backups must re-export from the
// canonical wallet DB via generateemissionkey.
func decryptPrivateKeyWithPassphrase(encryptedKey, passphrase string) (*secp256k1.PrivateKey, error) {
	pp := []byte(passphrase)
	defer zeroBytes(pp)

	if !strings.HasPrefix(encryptedKey, "aes256gcm:") {
		return nil, fmt.Errorf("invalid encrypted key format, expected aes256gcm: prefix")
	}

	parts := strings.Split(encryptedKey, ":")
	// Reject v1 ("aes256gcm:<iv>:<ct>", 3 parts) with a clear, actionable error.
	if len(parts) == 3 {
		return nil, fmt.Errorf("emission-key backup format v1 is insecure (no KDF, no salt) " +
			"and is no longer supported; re-export from the canonical wallet DB via generateemissionkey")
	}
	// Reject v2 (KDF params not bound via AEAD additional-data) with a clear,
	// actionable error. v2 blobs would silently fail on the AAD mismatch
	// otherwise; the explicit error tells operators what to do.
	if len(parts) >= 2 && parts[1] == "v2" {
		return nil, fmt.Errorf("emission-key backup format v2 (no AAD on KDF params) " +
			"is no longer supported; re-export from the canonical wallet DB via generateemissionkey")
	}
	if len(parts) != numV3BlobParts || parts[1] != emissionKDFVersion {
		return nil, fmt.Errorf("invalid encrypted key format, expected aes256gcm:%s:salt:N:r:p:nonce:ciphertext",
			emissionKDFVersion)
	}

	salt, err := hex.DecodeString(parts[2])
	if err != nil || len(salt) == 0 {
		return nil, fmt.Errorf("invalid salt hex: %v", err)
	}
	// Cap salt at 64 bytes for parity with the N/r/p bounds. Legitimate
	// salt is emissionKDFSaltLen (16) bytes; a malicious blob with a
	// multi-MB salt is parsed before scrypt copies it, so reject early.
	if len(salt) > 64 {
		return nil, fmt.Errorf("invalid salt: %d bytes exceeds 64-byte cap", len(salt))
	}
	n, err := strconv.Atoi(parts[3])
	// Reject N values that are not a power of 2, ≤1, or > 1<<20.
	// Encryption uses 1<<15; the upper bound prevents a malicious blob
	// from forcing multi-GiB scrypt allocations.
	if err != nil || n <= 1 || n > 1<<20 || n&(n-1) != 0 {
		return nil, fmt.Errorf("invalid scrypt N parameter")
	}
	// Bound r and p for the same reason as N: a malicious blob with
	// (e.g.) r=1<<10 or p=1<<10 would honour scrypt's contract and burn
	// CPU/memory.  Encryption uses r=8, p=1; a cap of 16 each leaves
	// generous headroom for legitimate parameter changes while denying
	// the unauthenticated-cost-amplification path.
	r, err := strconv.Atoi(parts[4])
	if err != nil || r < 1 || r > 16 {
		return nil, fmt.Errorf("invalid scrypt r parameter")
	}
	p, err := strconv.Atoi(parts[5])
	if err != nil || p < 1 || p > 16 {
		return nil, fmt.Errorf("invalid scrypt p parameter")
	}
	nonce, err := hex.DecodeString(parts[6])
	if err != nil {
		return nil, fmt.Errorf("invalid nonce hex: %v", err)
	}
	ciphertext, err := hex.DecodeString(parts[7])
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext hex: %v", err)
	}
	// Cap ciphertext at 256 bytes for parity with the salt/N/r/p caps. Real
	// ciphertext is 32 plaintext + 16 GCM tag = 48 bytes; 256 leaves headroom
	// while denying a multi-MB blob from forcing a multi-MB allocation
	// before scrypt+gcm.Open authenticate the bytes.
	if len(ciphertext) > 256 {
		return nil, fmt.Errorf("invalid ciphertext: %d bytes exceeds 256-byte cap", len(ciphertext))
	}

	key, err := scrypt.Key(pp, salt, n, r, p, emissionKDFKeyLen)
	if err != nil {
		return nil, fmt.Errorf("scrypt key derivation failed: %v", err)
	}
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: got %d, want %d", len(nonce), gcm.NonceSize())
	}

	aad := emissionBackupAAD(emissionKDFVersion, salt, n, r, p)
	privateKeyBytes, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key (wrong passphrase or tampered blob?): %v", err)
	}
	// Safe to zero on defer: PrivKeyFromBytes calls ModNScalar.SetByteSlice,
	// which copies the bytes into the scalar's internal limbs before
	// returning, so wiping privateKeyBytes does not mutate the returned
	// key's state.
	defer zeroBytes(privateKeyBytes)

	// Mirror the plain-hex import validation via parseSecp256k1Private: a
	// malicious blob that authenticated against a tampered KDF could
	// otherwise yield a non-32-byte plaintext or the zero scalar.
	privateKey, err := parseSecp256k1Private(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("decrypted %v", err)
	}
	return privateKey, nil
}
