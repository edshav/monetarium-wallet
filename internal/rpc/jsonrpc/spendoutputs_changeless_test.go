// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package jsonrpc

import (
	"bytes"
	"context"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/dcrjson"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/mixing"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/internal/loader"
	"github.com/monetarium/monetarium-wallet/rpc/jsonrpc/types"
	"github.com/monetarium/monetarium-wallet/wallet"
	"github.com/monetarium/monetarium-wallet/wallet/txrules"
	"github.com/monetarium/monetarium-wallet/wallet/txsizes"
)

// publishRecorder is a NetworkBackend that records published txs. Every
// method spendoutputs does not need returns an error, so a new path fails
// cleanly instead of panicking.
type publishRecorder struct {
	published []*wire.MsgTx
}

var _ wallet.NetworkBackend = (*publishRecorder)(nil)

func (p *publishRecorder) PublishTransactions(_ context.Context, txs ...*wire.MsgTx) error {
	p.published = append(p.published, txs...)
	return nil
}

func (p *publishRecorder) LoadTxFilter(context.Context, bool, []stdaddr.Address, []wire.OutPoint) error {
	return nil
}

func (p *publishRecorder) GetFeeEstimatesByCoinType(context.Context, uint8) (*wallet.FeeEstimates, error) {
	return nil, errors.E(errors.NoPeers) // use the static relay fee
}

func (p *publishRecorder) Blocks(context.Context, []*chainhash.Hash) ([]*wire.MsgBlock, error) {
	return nil, unexpectedCall("Blocks")
}

func (p *publishRecorder) CFiltersV2(context.Context, []*chainhash.Hash) ([]wallet.FilterProof, error) {
	return nil, unexpectedCall("CFiltersV2")
}

func (p *publishRecorder) PublishMixMessages(context.Context, ...mixing.Message) error {
	return unexpectedCall("PublishMixMessages")
}

func (p *publishRecorder) Rescan(context.Context, []chainhash.Hash,
	func(*chainhash.Hash, []*wire.MsgTx) error) error {
	return unexpectedCall("Rescan")
}

func (p *publishRecorder) StakeDifficulty(context.Context) (dcrutil.Amount, error) {
	return 0, unexpectedCall("StakeDifficulty")
}

// Synced and Done cannot return an error: report not synced and never
// disconnected.
func (p *publishRecorder) Synced(context.Context) (bool, int32) { return false, 0 }
func (p *publishRecorder) Done() <-chan struct{}                { return nil }
func (p *publishRecorder) Err() error                           { return unexpectedCall("Err") }

// TestSpendOutputsChangeless spends one wallet output whose value covers
// the requested output plus the change-less fee but not the with-change
// fee. spendoutputs must publish a tx without change that pays the
// requested output, rather than panic in RandomizeChangePosition, and the
// whole leftover must be its fee. One atom below the change-less fee,
// spendoutputs must fail with insufficient funds and publish nothing.
func TestSpendOutputsChangeless(t *testing.T) {
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
			params := chaincfg.SimNetParams()
			privPass := []byte("private")
			l := loader.NewLoader(params, filepath.Join(t.TempDir(), "simnet"), false, 20, 0,
				false, 1e5, 0, wallet.DefaultAccountGapLimit, false, false, false, 0, nil)
			w, err := l.CreateNewWallet(ctx, []byte(wallet.InsecurePubPassphrase), privPass, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer l.UnloadWallet()
			if err := w.Unlock(ctx, privPass, nil); err != nil {
				t.Fatal(err)
			}
			nb := &publishRecorder{}
			w.SetNetworkBackend(nb)
			isSKA := tc.coinType.IsSKA()

			addr, err := w.NewExternalAddress(ctx, 0)
			if err != nil {
				t.Fatal(err)
			}
			ver, script := addr.PaymentScript()
			txOut := func(atoms *big.Int) *wire.TxOut {
				if isSKA {
					return &wire.TxOut{Version: ver, PkScript: script,
						CoinType: tc.coinType, SKAValue: new(big.Int).Set(atoms)}
				}
				return &wire.TxOut{Value: atoms.Int64(), Version: ver, PkScript: script}
			}

			// spendoutputs sizes each input as RedeemP2PKHInputSize.
			relayFee := w.RelayFeeForCoinType(ctx, tc.coinType)
			outputs := []*wire.TxOut{txOut(tc.amount)}
			inputSizes := []int{txsizes.RedeemP2PKHInputSize}
			changelessFee := txrules.FeeForSerializeSizeSKA(relayFee,
				txsizes.EstimateSerializeSizeForCoinType(tc.coinType, inputSizes, outputs, 0)).BigInt()
			withChangeFee := txrules.FeeForSerializeSizeSKA(relayFee,
				txsizes.EstimateSerializeSizeForCoinType(tc.coinType, inputSizes, outputs,
					txsizes.P2PKHPkScriptSize)).BigInt()
			leftover := new(big.Int).Add(changelessFee, big.NewInt(1))
			if leftover.Cmp(withChangeFee) >= 0 {
				t.Fatalf("test shape broken: leftover %v >= with-change fee %v", leftover, withChangeFee)
			}

			// fundAndSpend adds a wallet output of amount + leftover, from a
			// distinct parent per call, and spends it to amount.
			s := &Server{walletLoader: l}
			fundAndSpend := func(parent byte, leftover *big.Int) (*wire.MsgTx, any, error) {
				fund := wire.NewMsgTx()
				fund.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{parent}}, 0, nil))
				fund.AddTxOut(txOut(new(big.Int).Add(tc.amount, leftover)))
				if err := w.AddTransaction(ctx, fund, nil); err != nil {
					t.Fatal(err)
				}
				cmd := &types.SpendOutputsCmd{
					Account:           "default",
					PreviousOutpoints: []string{fund.TxHash().String() + ":0"},
					Outputs: []types.AddressAmountPair{{Address: addr.String(),
						Amount: cointype.AtomsToDecimalString(tc.amount, getAtomsPerCoin(params, tc.coinType))}},
				}
				if isSKA {
					ct := uint8(tc.coinType)
					cmd.CoinType = &ct
				}
				res, err := s.spendOutputs(ctx, cmd)
				return fund, res, err
			}

			// One atom below the change-less fee: no shape is fundable.
			_, _, err = fundAndSpend(2, new(big.Int).Sub(changelessFee, big.NewInt(1)))
			if !errors.Is(err, errors.InsufficientBalance) {
				t.Fatalf("below-minimum spend: want InsufficientBalance, got %v", err)
			}
			if code := convertError(err).Code; code != dcrjson.ErrRPCWalletInsufficientFunds {
				t.Fatalf("below-minimum spend: RPC code %v, want %v", code,
					dcrjson.ErrRPCWalletInsufficientFunds)
			}
			if len(nb.published) != 0 {
				t.Fatalf("below-minimum spend published %d txs", len(nb.published))
			}

			fund, res, err := fundAndSpend(1, leftover)
			if err != nil {
				t.Fatal(err)
			}

			if len(nb.published) != 1 {
				t.Fatalf("%d txs published, want 1", len(nb.published))
			}
			tx := nb.published[0]
			if res != tx.TxHash().String() {
				t.Fatalf("result %v, published tx %v", res, tx.TxHash())
			}
			if len(tx.TxIn) != 1 || len(tx.TxOut) != 1 {
				t.Fatalf("%d inputs, %d outputs; want 1, 1 (no change)", len(tx.TxIn), len(tx.TxOut))
			}
			out := tx.TxOut[0]
			if out.CoinType != tc.coinType || out.Version != ver || !bytes.Equal(out.PkScript, script) {
				t.Fatalf("output does not pay the requested address: %+v", out)
			}
			// The whole leftover is the fee: the only input is the funding
			// output, and the only output is the requested amount.
			if tx.TxIn[0].PreviousOutPoint != (wire.OutPoint{Hash: fund.TxHash()}) {
				t.Fatalf("input %v, want the funding output", tx.TxIn[0].PreviousOutPoint)
			}
			if isSKA {
				if out.Value != 0 || out.SKAValue.Cmp(tc.amount) != 0 {
					t.Fatalf("output amount %v, want %v", out.SKAValue, tc.amount)
				}
			} else if out.SKAValue != nil || out.Value != tc.amount.Int64() {
				t.Fatalf("output amount %v, want %v", out.Value, tc.amount)
			}
			// Fee from the wallet's record of the spent output, not from the
			// test's own arithmetic.
			prev, err := w.FetchOutput(ctx, &tx.TxIn[0].PreviousOutPoint)
			if err != nil {
				t.Fatal(err)
			}
			var fee *big.Int
			if isSKA {
				fee = new(big.Int).Sub(prev.SKAValue, out.SKAValue)
			} else {
				fee = big.NewInt(prev.Value - out.Value)
			}
			if fee.Cmp(leftover) != 0 {
				t.Fatalf("fee %v, want the whole leftover %v", fee, leftover)
			}
		})
	}
}
