// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet/txauthor"
	"github.com/monetarium/monetarium-wallet/wallet/txrules"
	"github.com/monetarium/monetarium-wallet/wallet/txsizes"
)

// authoringFixture is a wallet holding three unmined outputs of one coin
// type, each worth unit atoms.
type authoringFixture struct {
	w        *Wallet
	coinType cointype.CoinType
	unit     *big.Int
	fund     *wire.MsgTx
	script   []byte
	ver      uint16
}

func newAuthoringFixture(ctx context.Context, t *testing.T, coinType cointype.CoinType) *authoringFixture {
	t.Helper()
	cfg := basicWalletConfig
	w, teardown := testWallet(ctx, t, &cfg, nil)
	t.Cleanup(teardown)
	addr, err := w.NewInternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	ver, script := addr.(Address).PaymentScript()
	f := &authoringFixture{w: w, coinType: coinType, script: script, ver: ver,
		unit: big.NewInt(1e8)}
	if coinType.IsSKA() {
		// 100 SKA: above int64, so only the big.Int path can carry it.
		f.unit = new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	}
	f.fund = wire.NewMsgTx()
	f.fund.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{1}}, 0, nil))
	for range 3 {
		f.fund.AddTxOut(f.out(f.unit))
	}
	if err := w.AddTransaction(ctx, f.fund, nil); err != nil {
		t.Fatal(err)
	}
	return f
}

// out returns an output of the fixture's coin type paying the wallet.
func (f *authoringFixture) out(v *big.Int) *wire.TxOut {
	return f.outOf(f.coinType, v)
}

func (f *authoringFixture) outOf(coinType cointype.CoinType, v *big.Int) *wire.TxOut {
	if coinType.IsSKA() {
		return &wire.TxOut{Version: f.ver, PkScript: f.script, CoinType: coinType,
			SKAValue: new(big.Int).Set(v)}
	}
	return &wire.TxOut{Value: v.Int64(), Version: f.ver, PkScript: f.script}
}

// source offers op, worth one unit, whatever the target.
func (f *authoringFixture) source(op *wire.OutPoint) txauthor.InputSource {
	in := wire.NewTxIn(op, 0, nil)
	detail := &txauthor.InputDetail{
		Inputs:            []*wire.TxIn{in},
		Scripts:           [][]byte{f.script},
		RedeemScriptSizes: []int{txsizes.RedeemP2PKHSigScriptSize},
	}
	if f.coinType.IsSKA() {
		in.SKAValueIn = new(big.Int).Set(f.unit)
		detail.SKAAmount = cointype.NewSKAAmount(f.unit)
	} else {
		in.ValueIn = f.unit.Int64()
		detail.Amount = dcrutil.Amount(f.unit.Int64())
	}
	return func(dcrutil.Amount, cointype.SKAAmount) (*txauthor.InputDetail, error) {
		return detail, nil
	}
}

func outValue(o *wire.TxOut) *big.Int {
	if o.CoinType.IsSKA() {
		return new(big.Int).Set(o.SKAValue)
	}
	return big.NewInt(o.Value)
}

// authoredFee is the total input value minus the total output value. It fails
// the test unless the fee is the relay rate for the estimated signed size.
func authoredFee(ctx context.Context, t *testing.T, w *Wallet, tx *txauthor.AuthoredTx,
	coinType cointype.CoinType) *big.Int {
	t.Helper()
	fee := big.NewInt(int64(tx.TotalInput))
	if coinType.IsSKA() {
		fee = tx.SKATotalInput.BigInt()
	}
	for _, o := range tx.Tx.TxOut {
		fee.Sub(fee, outValue(o))
	}
	want := txrules.FeeForSerializeSizeSKA(w.RelayFeeForCoinType(ctx, coinType),
		tx.EstimatedSignedSerializeSize).BigInt()
	if fee.Cmp(want) != 0 {
		t.Errorf("fee %v, want %v for %d bytes", fee, want, tx.EstimatedSignedSerializeSize)
	}
	return fee
}

var authoringCoinTypes = []struct {
	name     string
	coinType cointype.CoinType
}{
	{"VAR", cointype.CoinTypeVAR},
	{"SKA", cointype.CoinType(1)},
}

func TestNewUnsignedTransactionWithSFFA(t *testing.T) {
	for _, ct := range authoringCoinTypes {
		t.Run(ct.name, func(t *testing.T) {
			ctx := context.Background()
			f := newAuthoringFixture(ctx, t, ct.coinType)
			// One and a half units: needs two inputs and leaves change.
			amount := new(big.Int).Div(new(big.Int).Mul(f.unit, big.NewInt(3)), big.NewInt(2))

			for _, idx := range []int{-1, 0} {
				outputs := []*wire.TxOut{f.out(amount)}
				var tx *txauthor.AuthoredTx
				var err error
				if idx < 0 {
					// NewUnsignedTransaction must keep the fee out of the outputs.
					tx, err = f.w.NewUnsignedTransaction(ctx, outputs, cointype.Zero(),
						0, 0, OutputSelectionAlgorithmDefault, nil, nil)
				} else {
					tx, err = f.w.NewUnsignedTransactionWithSFFA(ctx, outputs, cointype.Zero(),
						0, 0, OutputSelectionAlgorithmDefault, nil, nil, idx)
				}
				if err != nil {
					t.Fatalf("idx %d: %v", idx, err)
				}
				if tx.ChangeIndex < 0 {
					t.Fatalf("idx %d: no change output", idx)
				}
				fee := authoredFee(ctx, t, f.w, tx, ct.coinType)
				if fee.Sign() <= 0 {
					t.Fatalf("idx %d: fee %v", idx, fee)
				}
				recipient := outValue(tx.Tx.TxOut[1-tx.ChangeIndex])
				want := new(big.Int).Set(amount)
				if idx == 0 {
					want.Sub(want, fee)
				}
				if recipient.Cmp(want) != 0 {
					t.Errorf("idx %d: recipient gets %v, want %v (fee %v)", idx, recipient, want, fee)
				}
				if outValue(outputs[0]).Cmp(amount) != 0 {
					t.Errorf("idx %d: caller's output was modified", idx)
				}
			}

			// No outputs would otherwise take the sweep path and drain the account.
			_, err := f.w.NewUnsignedTransactionWithSFFA(ctx, nil, cointype.Zero(),
				0, 0, OutputSelectionAlgorithmAll, nil, nil, 0)
			if !errors.Is(err, errors.Invalid) {
				t.Errorf("no outputs with an index: err %v, want Invalid", err)
			}
		})
	}
}

func TestSweepFromInputSource(t *testing.T) {
	for _, ct := range authoringCoinTypes {
		t.Run(ct.name, func(t *testing.T) {
			ctx := context.Background()
			f := newAuthoringFixture(ctx, t, ct.coinType)

			// The source offers the middle output only.
			op := wire.NewOutPoint(f.fund.CachedTxHash(), 1, wire.TxTreeRegular)
			source := f.source(op)

			for _, tc := range []struct {
				name   string
				source txauthor.InputSource
				inputs int
			}{
				{"nil source sweeps all", nil, 3},
				{"given source sweeps its inputs", source, 1},
			} {
				tx, err := f.w.NewUnsignedSweepTransactionForCoinType(ctx, ct.coinType,
					cointype.Zero(), 0, 0, nil, tc.source)
				if err != nil {
					t.Fatalf("%s: %v", tc.name, err)
				}
				if len(tx.Tx.TxIn) != tc.inputs || len(tx.Tx.TxOut) != 1 {
					t.Fatalf("%s: %d inputs, %d outputs; want %d, 1", tc.name,
						len(tx.Tx.TxIn), len(tx.Tx.TxOut), tc.inputs)
				}
				if tc.source != nil && tx.Tx.TxIn[0].PreviousOutPoint != *op {
					t.Errorf("%s: spends %v, want %v", tc.name, tx.Tx.TxIn[0].PreviousOutPoint, op)
				}
				total := new(big.Int).Mul(f.unit, big.NewInt(int64(tc.inputs)))
				fee := authoredFee(ctx, t, f.w, tx, ct.coinType)
				if fee.Sign() <= 0 || new(big.Int).Add(outValue(tx.Tx.TxOut[0]), fee).Cmp(total) != 0 {
					t.Errorf("%s: output %v + fee %v != inputs %v", tc.name,
						outValue(tx.Tx.TxOut[0]), fee, total)
				}
			}
		})
	}
}

// TestAuthoringWithSourceRejects checks that a supplied input source still
// goes through the shared checks, on both entry points that take one.
func TestAuthoringWithSourceRejects(t *testing.T) {
	for _, ct := range authoringCoinTypes {
		t.Run(ct.name, func(t *testing.T) {
			ctx := context.Background()
			f := newAuthoringFixture(ctx, t, ct.coinType)
			own := f.source(wire.NewOutPoint(f.fund.CachedTxHash(), 0, wire.TxTreeRegular))
			foreign := f.source(wire.NewOutPoint(&chainhash.Hash{2}, 0, wire.TxTreeRegular))
			half := new(big.Int).Div(f.unit, big.NewInt(2))
			noFeeCoin := cointype.CoinType(9) // no SKA coin 9 on simnet
			// A supplied change source leaves the account check as the only
			// use of the account.
			change := &mockChangeSource{script: f.script, scriptSize: len(f.script)}

			entries := []struct {
				name   string
				author func(coinType cointype.CoinType, account uint32, src txauthor.InputSource) error
			}{
				{"sweep", func(coinType cointype.CoinType, account uint32, src txauthor.InputSource) error {
					_, err := f.w.NewUnsignedSweepTransactionForCoinType(ctx, coinType,
						cointype.Zero(), account, 0, change, src)
					return err
				}},
				{"SFFA", func(coinType cointype.CoinType, account uint32, src txauthor.InputSource) error {
					_, err := f.w.NewUnsignedTransactionWithSFFA(ctx,
						[]*wire.TxOut{f.outOf(coinType, half)}, cointype.Zero(),
						account, 0, OutputSelectionAlgorithmDefault, change, src, 0)
					return err
				}},
			}
			for _, e := range entries {
				err := e.author(ct.coinType, 0, foreign)
				if !errors.Is(err, ErrExternalInputInAuthoredTx) {
					t.Errorf("%s, foreign input: err %v, want ErrExternalInputInAuthoredTx", e.name, err)
				}
				err = e.author(ct.coinType, 5, own)
				if !errors.Is(err, errors.NotExist) {
					t.Errorf("%s, missing account: err %v, want NotExist", e.name, err)
				}
				err = e.author(noFeeCoin, 0, own)
				if !errors.Is(err, errors.Invalid) || !strings.Contains(err.Error(), "no relay fee") {
					t.Errorf("%s, coin without a relay fee: err %v, want the relay fee reject", e.name, err)
				}
			}
		})
	}
}
