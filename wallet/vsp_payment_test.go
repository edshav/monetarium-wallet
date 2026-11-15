// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/gcs/blockcf2"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/txscript/stdscript"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet/txrules"
	"github.com/monetarium/monetarium-wallet/wallet/txsizes"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// vspPaymentFixture is a wallet whose outputs are added mined or unmined.
// They are paid to feeAcct, which pays the fee; change goes to account 0.
type vspPaymentFixture struct {
	w       *Wallet
	cfg     Config
	forest  SidechainForest
	tip     wire.BlockHeader
	n       byte
	feeAcct uint32
	sbits   int64 // the ticket price in the headers of mined outputs' blocks
}

func newVSPPaymentFixture(ctx context.Context, t *testing.T) *vspPaymentFixture {
	t.Helper()
	f := &vspPaymentFixture{cfg: basicWalletConfig}
	f.cfg.AccountGapLimit = 2 // lets a test add a fee account to an unused wallet
	w, teardown := testWallet(ctx, t, &f.cfg, nil)
	t.Cleanup(teardown)
	if err := w.Unlock(ctx, testPrivPass, nil); err != nil {
		t.Fatal(err)
	}
	f.w = w
	f.tip = f.cfg.Params.GenesisBlock.Header
	return f
}

// fund adds a tx paying the wallet one VAR output per value and returns it.
func (f *vspPaymentFixture) fund(ctx context.Context, t *testing.T, mined bool, values ...dcrutil.Amount) *wire.MsgTx {
	t.Helper()
	return f.fundCoin(ctx, t, mined, cointype.CoinTypeVAR, values...)
}

// fundCoin is fund for coinType; SKA values are in atoms of that coin.
func (f *vspPaymentFixture) fundCoin(ctx context.Context, t *testing.T, mined bool,
	coinType cointype.CoinType, values ...dcrutil.Amount) *wire.MsgTx {
	t.Helper()
	addr, err := f.w.NewInternalAddress(ctx, f.feeAcct)
	if err != nil {
		t.Fatal(err)
	}
	ver, script := addr.(Address).PaymentScript()
	f.n++
	tx := wire.NewMsgTx()
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{f.n}}, 0, nil))
	for _, v := range values {
		out := &wire.TxOut{Value: int64(v), Version: ver, PkScript: script, CoinType: coinType}
		if coinType.IsSKA() {
			out.Value, out.SKAValue = 0, big.NewInt(int64(v))
		}
		tx.AddTxOut(out)
	}
	if !mined {
		if err := f.w.AddTransaction(ctx, tx, nil); err != nil {
			t.Fatal(err)
		}
		return tx
	}
	header := wire.BlockHeader{
		PrevBlock: f.tip.BlockHash(),
		Height:    f.tip.Height + 1,
		Bits:      f.cfg.Params.PowLimitBits,
		SBits:     f.sbits,
		VoteBits:  1, // approve the previous block, or its outputs are invalidated
	}
	filter, err := blockcf2.Regular(&wire.MsgBlock{Header: header}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash := header.BlockHash()
	_, err = f.w.ChainSwitch(ctx, &f.forest, []*BlockNode{NewBlockNode(&header, &hash, filter)},
		map[chainhash.Hash][]*wire.MsgTx{hash: {tx}})
	if err != nil {
		t.Fatal(err)
	}
	f.tip = header
	return tx
}

// oneInputMinerFee is the miner fee of a one-input fee tx.
func (f *vspPaymentFixture) oneInputMinerFee() dcrutil.Amount {
	return txrules.FeeForSerializeSize(f.w.RelayFee(), txsizes.EstimateSerializeSize(
		[]int{txsizes.RedeemP2PKHSigScriptSize},
		[]*wire.TxOut{{PkScript: make([]byte, txsizes.P2PKHPkScriptSize)}},
		txsizes.P2PKHPkScriptSize))
}

// pay runs CreateVspPayment for fee and checks it with checkLocked and, when
// it succeeds, with checkFeeTx.
func (f *vspPaymentFixture) pay(ctx context.Context, t *testing.T, tx *wire.MsgTx, fee dcrutil.Amount) error {
	t.Helper()
	feeAddr, err := f.w.NewExternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	before := lockedOutpoints(ctx, t, f.w)
	err = f.w.CreateVspPayment(ctx, tx, fee, feeAddr, f.feeAcct, 0)
	if err != nil {
		checkLocked(ctx, t, f.w, before, nil)
		return err
	}
	checkLocked(ctx, t, f.w, before, tx)
	checkFeeTx(t, f.w, tx, fee, feeAddr)
	return nil
}

// checkFeeTx checks that the fee tx spends no input twice, pays feeAddr
// exactly fee, and pays the miner at least the relay fee for its size.
func checkFeeTx(t *testing.T, w *Wallet, tx *wire.MsgTx, fee dcrutil.Amount, feeAddr stdaddr.Address) {
	t.Helper()
	_, feeScript := feeAddr.PaymentScript()
	var in, out, toVSP int64
	seen := make(map[wire.OutPoint]bool)
	for _, txIn := range tx.TxIn {
		if seen[txIn.PreviousOutPoint] {
			t.Fatalf("input %v spent twice", txIn.PreviousOutPoint)
		}
		seen[txIn.PreviousOutPoint] = true
		in += txIn.ValueIn
	}
	for _, txOut := range tx.TxOut {
		out += txOut.Value
		if string(txOut.PkScript) == string(feeScript) {
			toVSP += txOut.Value
		}
	}
	if toVSP != int64(fee) {
		t.Errorf("VSP gets %v, want %v", dcrutil.Amount(toVSP), fee)
	}
	// The tx is signed, so its size is the real one.
	minFee := txrules.FeeForSerializeSize(w.RelayFee(), tx.SerializeSize())
	if minerFee := dcrutil.Amount(in - out); minerFee < minFee {
		t.Errorf("%d-input fee tx pays the miner %v, below the relay fee %v",
			len(tx.TxIn), minerFee, minFee)
	}
}

// lockedOutpoints returns the wallet's locked outpoints as txid:vout.
func lockedOutpoints(ctx context.Context, t *testing.T, w *Wallet) map[string]bool {
	t.Helper()
	ins, err := w.LockedOutpoints(ctx, "*")
	if err != nil {
		t.Fatal(err)
	}
	locked := make(map[string]bool)
	for _, in := range ins {
		locked[fmt.Sprintf("%s:%d", in.Txid, in.Vout)] = true
	}
	return locked
}

// checkLocked checks that the outpoints locked before a fee payment are the
// ones locked after it, less the inputs of feeTx, the fee tx the wallet
// recorded, if any: recording a tx releases the locks on its inputs.
func checkLocked(ctx context.Context, t *testing.T, w *Wallet, before map[string]bool, feeTx *wire.MsgTx) {
	t.Helper()
	want := maps.Clone(before)
	if feeTx != nil {
		for _, in := range feeTx.TxIn {
			op := in.PreviousOutPoint
			delete(want, fmt.Sprintf("%s:%d", op.Hash, op.Index))
		}
	}
	if got := lockedOutpoints(ctx, t, w); !maps.Equal(got, want) {
		t.Errorf("locked outpoints %v, want %v", got, want)
	}
}

// unminedTxs returns the number of unmined txs the wallet holds.
func unminedTxs(ctx context.Context, t *testing.T, w *Wallet) int {
	t.Helper()
	var n int
	err := walletdb.View(ctx, w.db, func(dbtx walletdb.ReadTx) error {
		recs, err := w.txStore.UnminedTxs(dbtx)
		n = len(recs)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// checkUnpaid checks that a failed fee payment ran out of funds and recorded
// no fee tx: the wallet holds the unmined txs it held before.
func checkUnpaid(ctx context.Context, t *testing.T, w *Wallet, err error, unminedBefore int) {
	t.Helper()
	if !errors.Is(err, errors.InsufficientBalance) {
		t.Errorf("error %v, want %v", err, errors.InsufficientBalance)
	}
	if n := unminedTxs(ctx, t, w) - unminedBefore; n != 0 {
		t.Errorf("%d fee txs recorded, want none", n)
	}
}

// fallingFeeNetwork is a node whose fee estimate is first on the first call
// and later on every call after it.
type fallingFeeNetwork struct {
	mockNetwork
	first, later dcrutil.Amount
	calls        atomic.Int32
}

func (n *fallingFeeNetwork) GetFeeEstimatesByCoinType(_ context.Context, coinType uint8) (*FeeEstimates, error) {
	rate := n.later
	if n.calls.Add(1) == 1 {
		rate = n.first
	}
	return &FeeEstimates{CoinType: coinType, NormalFee: strconv.FormatInt(int64(rate), 10)}, nil
}

func TestCreateVspPaymentFunding(t *testing.T) {
	const fee = dcrutil.Amount(1e7)

	t.Run("output matching the quote", func(t *testing.T) {
		ctx := context.Background()
		f := newVSPPaymentFixture(ctx, t)
		f.fund(ctx, t, true, fee)
		// Nothing pays the miner on top of the quote.
		checkUnpaid(ctx, t, f.w, f.pay(ctx, t, wire.NewMsgTx(), fee), 0)
	})

	t.Run("output matching the quote and the miner fee", func(t *testing.T) {
		ctx := context.Background()
		f := newVSPPaymentFixture(ctx, t)
		f.fund(ctx, t, true, fee+f.oneInputMinerFee())
		tx := wire.NewMsgTx()
		if err := f.pay(ctx, t, tx, fee); err != nil {
			t.Fatal(err)
		}
		if len(tx.TxIn) != 1 {
			t.Errorf("%d inputs, want 1", len(tx.TxIn))
		}
	})

	t.Run("output matching the quote and the miner fee without change", func(t *testing.T) {
		ctx := context.Background()
		f := newVSPPaymentFixture(ctx, t)
		// Enough for a one-input fee tx that drops its change output,
		// but the fee tx is sized with one.
		noChange := txrules.FeeForSerializeSize(f.w.RelayFee(), txsizes.EstimateSerializeSize(
			[]int{txsizes.RedeemP2PKHSigScriptSize},
			[]*wire.TxOut{{PkScript: make([]byte, txsizes.P2PKHPkScriptSize)}}, 0))
		f.fund(ctx, t, true, fee+noChange)
		checkUnpaid(ctx, t, f.w, f.pay(ctx, t, wire.NewMsgTx(), fee), 0)
	})

	t.Run("caller input covering the quote and the miner fee", func(t *testing.T) {
		ctx := context.Background()
		f := newVSPPaymentFixture(ctx, t)
		value := fee + f.oneInputMinerFee()
		funds := f.fund(ctx, t, true, value)
		op := wire.NewOutPoint(funds.CachedTxHash(), 0, wire.TxTreeRegular)
		f.w.LockOutpoint(&op.Hash, op.Index) // as the purchase does
		tx := wire.NewMsgTx()
		tx.AddTxIn(wire.NewTxIn(op, int64(value), nil))
		// The wallet has nothing else to top up with.
		if err := f.pay(ctx, t, tx, fee); err != nil {
			t.Fatalf("caller's input not enough alone: %v", err)
		}
		if len(tx.TxIn) != 1 {
			t.Errorf("%d inputs, want 1", len(tx.TxIn))
		}
	})

	t.Run("relay fee falling during the call", func(t *testing.T) {
		ctx := context.Background()
		f := newVSPPaymentFixture(ctx, t)
		f.fund(ctx, t, true, 1e8)
		// The node's estimate falls after the wallet reads it to size the
		// fee tx; the change must not be paid back at the lower rate.
		const sized = 1e5
		n := &fallingFeeNetwork{first: sized, later: sized / 10}
		f.w.SetNetworkBackend(n)
		tx := wire.NewMsgTx()
		if err := f.pay(ctx, t, tx, fee); err != nil {
			t.Fatal(err)
		}
		if n.calls.Load() == 0 {
			t.Fatal("relay fee not read from the network backend")
		}
		var minerFee int64
		for _, in := range tx.TxIn {
			minerFee += in.ValueIn
		}
		for _, out := range tx.TxOut {
			minerFee -= out.Value
		}
		if min := txrules.FeeForSerializeSize(sized, tx.SerializeSize()); dcrutil.Amount(minerFee) < min {
			t.Errorf("fee tx pays the miner %v, below %v at the rate it was sized at",
				dcrutil.Amount(minerFee), min)
		}
	})

	t.Run("separate fee and change accounts", func(t *testing.T) {
		ctx := context.Background()
		f := newVSPPaymentFixture(ctx, t)
		var err error
		f.feeAcct, err = f.w.NextAccount(ctx, "fee")
		if err != nil {
			t.Fatal(err)
		}
		funds := f.fund(ctx, t, true, 1e8)
		tx := wire.NewMsgTx()
		if err := f.pay(ctx, t, tx, fee); err != nil {
			t.Fatal(err)
		}
		for _, in := range tx.TxIn {
			if in.PreviousOutPoint.Hash != funds.TxHash() {
				t.Errorf("input %v is not from the fee account", in.PreviousOutPoint)
			}
		}
		var change int
		for _, out := range tx.TxOut {
			_, addrs := stdscript.ExtractAddrs(out.Version, out.PkScript, f.w.chainParams)
			if len(addrs) != 1 {
				continue
			}
			ka, err := f.w.KnownAddress(ctx, addrs[0])
			if err != nil {
				continue // not the wallet's
			}
			if acct, branch, _ := ka.(BIP0044Address).Path(); branch == 1 {
				change++
				if acct != 0 {
					t.Errorf("change paid to account %d, want 0", acct)
				}
			}
		}
		if change != 1 {
			t.Errorf("%d change outputs, want 1", change)
		}
	})

	t.Run("unmined output", func(t *testing.T) {
		ctx := context.Background()
		f := newVSPPaymentFixture(ctx, t)
		f.fund(ctx, t, false, 1e8)
		checkUnpaid(ctx, t, f.w, f.pay(ctx, t, wire.NewMsgTx(), fee), 1)
	})

	t.Run("unmined caller input", func(t *testing.T) {
		ctx := context.Background()
		f := newVSPPaymentFixture(ctx, t)
		v := fee + f.oneInputMinerFee()
		unmined := f.fund(ctx, t, false, v)
		op := wire.NewOutPoint(unmined.CachedTxHash(), 0, wire.TxTreeRegular)
		f.w.LockOutpoint(&op.Hash, op.Index) // as the purchase does
		tx := wire.NewMsgTx()
		tx.AddTxIn(wire.NewTxIn(op, int64(v), nil))
		if err := f.pay(ctx, t, tx, fee); err != nil {
			t.Fatal(err)
		}
		if len(tx.TxIn) != 1 {
			t.Errorf("%d inputs, want the caller's alone", len(tx.TxIn))
		}
	})

	t.Run("caller inputs short of the quote", func(t *testing.T) {
		ctx := context.Background()
		f := newVSPPaymentFixture(ctx, t)
		short := f.fund(ctx, t, true, fee/2)
		f.fund(ctx, t, true, 1e8)
		op := wire.NewOutPoint(short.CachedTxHash(), 0, wire.TxTreeRegular)
		f.w.LockOutpoint(&op.Hash, op.Index) // as the purchase does
		tx := wire.NewMsgTx()
		tx.AddTxIn(wire.NewTxIn(op, int64(fee/2), nil))
		if err := f.pay(ctx, t, tx, fee); err != nil {
			t.Fatalf("short inputs not topped up: %v", err)
		}
		if len(tx.TxIn) < 2 || tx.TxIn[0].PreviousOutPoint.Hash != short.TxHash() {
			t.Errorf("caller's input not kept first among %d inputs", len(tx.TxIn))
		}
	})

	t.Run("caller inputs short of the quote, SKA1 in the fee account", func(t *testing.T) {
		ctx := context.Background()
		f := newVSPPaymentFixture(ctx, t)
		short := f.fund(ctx, t, true, fee/2)
		ska := f.fundCoin(ctx, t, true, cointype.CoinType(1), 1e8)
		if bal, err := f.w.AccountBalanceByCoinType(ctx, f.feeAcct, cointype.CoinType(1), 1); err != nil || !bal.SKASpendable.IsPositive() {
			t.Fatalf("SKA1 output not spendable: %v, %v", bal.SKASpendable, err)
		}
		f.fund(ctx, t, true, 1e8)
		op := wire.NewOutPoint(short.CachedTxHash(), 0, wire.TxTreeRegular)
		f.w.LockOutpoint(&op.Hash, op.Index) // as the purchase does
		tx := wire.NewMsgTx()
		tx.AddTxIn(wire.NewTxIn(op, int64(fee/2), nil))
		err := f.pay(ctx, t, tx, fee)
		// Checked before err: a top-up that reserves SKA1 adds no VAR, so
		// the next round fails with the SKA1 input left in tx.
		for _, in := range tx.TxIn {
			if in.PreviousOutPoint.Hash == ska.TxHash() {
				t.Errorf("fee tx spends SKA1 output %v", in.PreviousOutPoint)
			}
		}
		if err != nil {
			t.Fatalf("short inputs not topped up with VAR: %v", err)
		}
	})

	t.Run("several small outputs", func(t *testing.T) {
		ctx := context.Background()
		f := newVSPPaymentFixture(ctx, t)
		// Four of these cover the quote plus the miner fee of a one-input
		// fee tx, but not of the four-input tx they make: a fifth is needed.
		each := (fee + f.oneInputMinerFee() + 3) / 4
		f.fund(ctx, t, true, each, each, each, each, each)
		tx := wire.NewMsgTx()
		if err := f.pay(ctx, t, tx, fee); err != nil {
			t.Fatal(err)
		}
		if len(tx.TxIn) != 5 {
			t.Errorf("%d inputs, want 5", len(tx.TxIn))
		}
	})

	t.Run("several small outputs without the last", func(t *testing.T) {
		ctx := context.Background()
		f := newVSPPaymentFixture(ctx, t)
		// The first top-up reserves all four, the second finds none.
		each := (fee + f.oneInputMinerFee() + 3) / 4
		f.fund(ctx, t, true, each, each, each, each)
		checkUnpaid(ctx, t, f.w, f.pay(ctx, t, wire.NewMsgTx(), fee), 0)
	})
}

// TestVSPProcessFundsFeeTx checks that Process, which a ticket purchase calls,
// sends the VSP a fee tx that pays the quoted fee and the miner, whether the
// caller hands it inputs short of the quote or no fee tx.  When the wallet
// cannot top the inputs up, Process fails, marks the ticket errored and leaves
// the caller's input locked.
func TestVSPProcessFundsFeeTx(t *testing.T) {
	const fee = dcrutil.Amount(1e7)
	for _, tc := range []struct {
		name        string
		callerInput bool
		unfunded    bool // the wallet has nothing to top the caller's input up with
	}{
		{name: "caller input short of the quote", callerInput: true},
		{name: "no fee tx"},
		{name: "wallet short of the quote", callerInput: true, unfunded: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			feeAddr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
				make([]byte, 20), basicWalletConfig.Params)
			if err != nil {
				t.Fatal(err)
			}
			var sent atomic.Pointer[wire.MsgTx]
			c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				switch path {
				case "/api/v3/feeaddress":
					return http.StatusOK, types.FeeAddressResponse{
						FeeAddress: feeAddr.String(),
						FeeAmount:  int64(fee),
						Request:    body,
					}
				case "/api/v3/payfee":
					var req types.PayFeeRequest
					if err := json.Unmarshal(body, &req); err != nil {
						return apiError(types.ErrBadRequest)
					}
					raw, err := hex.DecodeString(req.FeeTx)
					if err != nil {
						return apiError(types.ErrBadRequest)
					}
					tx := new(wire.MsgTx)
					if err := tx.FromBytes(raw); err != nil {
						return apiError(types.ErrBadRequest)
					}
					sent.Store(tx)
					return http.StatusOK, types.PayFeeResponse{Request: body}
				}
				return apiError(types.ErrInternalError)
			})
			f := &vspPaymentFixture{w: c.wallet, cfg: basicWalletConfig,
				tip: basicWalletConfig.Params.GenesisBlock.Header}
			var feeTx *wire.MsgTx
			var callerOp *wire.OutPoint
			if tc.callerInput {
				short := f.fund(ctx, t, false, fee/2)
				callerOp = wire.NewOutPoint(short.CachedTxHash(), 0, wire.TxTreeRegular)
				c.wallet.LockOutpoint(&callerOp.Hash, callerOp.Index) // as the purchase does
				feeTx = wire.NewMsgTx()
				feeTx.AddTxIn(wire.NewTxIn(callerOp, int64(fee/2), nil))
			}
			if !tc.unfunded {
				f.fund(ctx, t, true, 1e8)
			}
			// The unmined ticket is added after the funding block: a block
			// whose stake difficulty differs from its price prunes it.
			ticket := testVSPTicket(ctx, t, c, 0xf1) // apart from f.fund's inputs
			// The job feePayment would make for a new ticket, made here
			// so that no reconcile is scheduled to race Process.
			c.jobs[*ticket.Hash()] = &vspFeePayment{
				client: c,
				ctx:    context.Background(),
				ticket: ticket,
				policy: c.policy,
				params: c.wallet.chainParams,
			}

			before := lockedOutpoints(ctx, t, c.wallet)
			unmined := unminedTxs(ctx, t, c.wallet)

			err = c.Process(ctx, ticket, feeTx)
			if tc.unfunded {
				checkUnpaid(ctx, t, c.wallet, err, unmined)
				info, err := ticket.VSPTicketInfo(ctx)
				if err != nil || udb.FeeStatus(info.FeeTxStatus) != udb.VSPFeeProcessErrored {
					t.Errorf("ticket not marked errored (info %+v, err %v)", info, err)
				}
				// The caller's input stays locked: the caller unlocks it.
				checkLocked(ctx, t, c.wallet, before, nil)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			paid := sent.Load()
			if paid == nil {
				t.Fatal("no fee tx sent to the VSP")
			}
			checkFeeTx(t, c.wallet, paid, fee, feeAddr)
			if callerOp != nil && paid.TxIn[0].PreviousOutPoint != *callerOp {
				t.Errorf("caller's input not kept first among %d inputs", len(paid.TxIn))
			}
			checkLocked(ctx, t, c.wallet, before, paid)
		})
	}
}
