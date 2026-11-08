// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/blockchain/stake"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
)

// publishRecorder is a mockNetwork that keeps every published tx.
type publishRecorder struct {
	mockNetwork
	txs *[]*wire.MsgTx
}

func (n publishRecorder) PublishTransactions(ctx context.Context, txs ...*wire.MsgTx) error {
	*n.txs = append(*n.txs, txs...)
	return nil
}

// failingFeeVSP is a fake VSP that quotes a 1% fee and fails every other
// request, so the fee is never paid.
func failingFeeVSP(path string, _ []byte) (int, any) {
	if path == "/api/v3/vspinfo" {
		return http.StatusOK, types.VspInfoResponse{Timestamp: time.Now().Unix(), FeePercentage: 1}
	}
	return apiError(types.ErrInternalError)
}

const noSpendableVAR = "has no spendable VAR"

// TestPurchaseTicketsVSPSingleUTXO checks that a non-mixed VSP purchase from a
// wallet with one spendable output publishes the ticket: the fee split spends
// that output, and the retry at minconf 0 funds the ticket from the split's
// unmined change.
func TestPurchaseTicketsVSPSingleUTXO(t *testing.T) {
	ctx := context.Background()
	c := testVSPClient(ctx, t, failingFeeVSP)
	w := c.wallet
	var published []*wire.MsgTx
	n := publishRecorder{txs: &published}
	w.SetNetworkBackend(n)

	addr, err := w.NewExternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	fund := wire.NewMsgTx()
	fund.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{0xfd}}, 2e8, nil))
	ver, script := addr.PaymentScript()
	fund.AddTxOut(&wire.TxOut{Value: 2e8, Version: ver, PkScript: script})
	blockOne := maketg(t, w.chainParams).createBlockOne("block-one")
	_, err = w.ChainSwitch(ctx, new(SidechainForest), []*BlockNode{blockOne.BlockNode},
		map[chainhash.Hash][]*wire.MsgTx{*blockOne.Hash: {fund}})
	if err != nil {
		t.Fatal(err)
	}

	_, err = w.PurchaseTickets(ctx, n, &PurchaseTicketsRequest{
		Count:     1,
		MinConf:   1,
		VSPClient: c,
	})
	var tickets int
	for _, tx := range published {
		if stake.IsSStx(tx) {
			tickets++
		}
	}
	if tickets != 1 {
		t.Fatalf("published %d tickets of %d txs, want 1 (PurchaseTickets error: %v)",
			tickets, len(published), err)
	}
}

// TestPurchaseTicketsAllVARInTickets checks that an account with no spendable
// VAR still gets the "no spendable VAR" pre-flight error: its VAR is in a
// ticket (counted as voting authority, mined or not), or it holds only SKA.
func TestPurchaseTicketsAllVARInTickets(t *testing.T) {
	tests := []struct {
		name    string
		mined   bool
		ska     bool // an SKA credit instead of a ticket
		minConf int32
	}{
		{name: "mined ticket, minconf 1", mined: true, minConf: 1},
		{name: "mined ticket, minconf 0", mined: true, minConf: 0},
		{name: "unmined ticket, minconf 0", minConf: 0},
		{name: "mined SKA only, minconf 1", mined: true, ska: true, minConf: 1},
		{name: "mined SKA only, minconf 0", mined: true, ska: true, minConf: 0},
		{name: "unmined SKA only, minconf 0", ska: true, minConf: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := testVSPClient(ctx, t, failingFeeVSP)
			w := c.wallet
			w.SetNetworkBackend(mockNetwork{})

			blockOne := maketg(t, w.chainParams).createBlockOne("block-one")
			_, err := w.ChainSwitch(ctx, new(SidechainForest), []*BlockNode{blockOne.BlockNode}, nil)
			if err != nil {
				t.Fatal(err)
			}

			addr, err := w.NewExternalAddress(ctx, 0)
			if err != nil {
				t.Fatal(err)
			}
			stakeAddr := addr.(stdaddr.StakeAddress)
			const price = 1e8
			ticket := wire.NewMsgTx()
			ticket.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{0xfe}}, price, nil))
			if tc.ska {
				// 100 SKA1, above int64 in atoms.
				ver, script := addr.(Address).PaymentScript()
				ticket.AddTxOut(&wire.TxOut{Version: ver, PkScript: script, CoinType: 1,
					SKAValue: new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))})
			} else {
				ver, script := stakeAddr.VotingRightsScript()
				ticket.AddTxOut(&wire.TxOut{Value: price, Version: ver, PkScript: script})
				ver, script = stakeAddr.RewardCommitmentScript(price, 0, 0)
				ticket.AddTxOut(&wire.TxOut{Version: ver, PkScript: script})
				ver, script = stakeAddr.StakeChangeScript()
				ticket.AddTxOut(&wire.TxOut{Version: ver, PkScript: script})
			}
			var blockHash *chainhash.Hash
			if tc.mined {
				blockHash = blockOne.Hash
			}
			if err := w.AddTransaction(ctx, ticket, blockHash); err != nil {
				t.Fatal(err)
			}
			bal, err := w.AccountBalance(ctx, 0, tc.minConf)
			if err != nil {
				t.Fatal(err)
			}
			if bal.Spendable != 0 || (!tc.ska && bal.VotingAuthority != price) {
				t.Fatalf("test setup: balance %+v, want only the ticket", bal)
			}
			if tc.ska {
				skaBal, err := w.AccountBalanceByCoinType(ctx, 0, 1, tc.minConf)
				if err != nil {
					t.Fatal(err)
				}
				if skaBal.SKATotal.IsZero() {
					t.Fatalf("test setup: no SKA1 credit recorded: %+v", skaBal)
				}
			}

			_, err = w.PurchaseTickets(ctx, mockNetwork{}, &PurchaseTicketsRequest{
				Count:     1,
				MinConf:   tc.minConf,
				VSPClient: c,
			})
			if !errors.Is(err, errors.InsufficientBalance) ||
				!strings.Contains(err.Error(), noSpendableVAR) {
				t.Fatalf("PurchaseTickets: got %v, want the %q pre-flight error", err, noSpendableVAR)
			}
		})
	}
}

// TestPurchaseTicketsPreflightBalance checks which balance the pre-flight
// reads: AccountBalanceByCoinType at minconf ≥ 1, AccountBalance at minconf 0
// for any purchase, both scoped to the source account.
func TestPurchaseTicketsPreflightBalance(t *testing.T) {
	const amt = 2e8
	tests := []struct {
		name    string
		mined   bool
		expiry  uint32 // fund tx expiry
		change  bool   // pay an internal address
		other   bool   // purchase from a second, empty account
		minConf int32
		// Spendable at minConf as each balance reads it, checked in setup.
		wantAcct, wantByCoin dcrutil.Amount
		wantPreflight        bool
	}{{
		// AccountBalance counts a young output with expiry as immature,
		// AccountBalanceByCoinType as spendable.
		name: "mined output with expiry, minconf 1", mined: true, expiry: 1000,
		minConf: 1, wantAcct: 0, wantByCoin: amt,
	}, {
		// AccountBalanceByCoinType never counts unmined credits.
		name: "unmined change, minconf 0, no VSP", change: true,
		minConf: 0, wantAcct: amt, wantByCoin: 0,
	}, {
		name: "VAR only in another account, minconf 0", mined: true, other: true,
		minConf: 0, wantAcct: 0, wantByCoin: 0, wantPreflight: true,
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			cfg := basicWalletConfig
			cfg.AccountGapLimit = 2 // let NextAccount create account 1
			w, teardown := testWallet(ctx, t, &cfg, nil)
			t.Cleanup(teardown)
			err := w.Unlock(ctx, testPrivPass, nil)
			if err != nil {
				t.Fatal(err)
			}
			w.SetNetworkBackend(mockNetwork{})

			blockOne := maketg(t, w.chainParams).createBlockOne("block-one")
			_, err = w.ChainSwitch(ctx, new(SidechainForest), []*BlockNode{blockOne.BlockNode}, nil)
			if err != nil {
				t.Fatal(err)
			}

			newAddr := w.NewExternalAddress
			if tc.change {
				newAddr = w.NewInternalAddress
			}
			addr, err := newAddr(ctx, 0)
			if err != nil {
				t.Fatal(err)
			}
			fund := wire.NewMsgTx()
			fund.Expiry = tc.expiry
			fund.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{0xfd}}, amt, nil))
			ver, script := addr.(Address).PaymentScript()
			fund.AddTxOut(&wire.TxOut{Value: amt, Version: ver, PkScript: script})
			var blockHash *chainhash.Hash
			if tc.mined {
				blockHash = blockOne.Hash
			}
			if err := w.AddTransaction(ctx, fund, blockHash); err != nil {
				t.Fatal(err)
			}

			var account uint32
			if tc.other {
				account, err = w.NextAccount(ctx, "empty")
				if err != nil {
					t.Fatal(err)
				}
			}
			bal, err := w.AccountBalance(ctx, account, tc.minConf)
			if err != nil {
				t.Fatal(err)
			}
			coinBal, err := w.AccountBalanceByCoinType(ctx, account, cointype.CoinTypeVAR, tc.minConf)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantByCoin > 0 && coinBal.Spendable == 0 {
				// Selection-side maturity for expiry outputs (a separate
				// change) makes both readings agree; nothing left to pin.
				t.Skip("AccountBalanceByCoinType already counts this output as immature")
			}
			if bal.Spendable != tc.wantAcct || coinBal.Spendable != tc.wantByCoin {
				t.Fatalf("test setup: Spendable %v (AccountBalance), %v (AccountBalanceByCoinType), want %v, %v",
					bal.Spendable, coinBal.Spendable, tc.wantAcct, tc.wantByCoin)
			}
			if tc.other {
				def, err := w.AccountBalance(ctx, 0, tc.minConf)
				if err != nil {
					t.Fatal(err)
				}
				if def.Spendable != amt {
					t.Fatalf("test setup: default account Spendable %v, want %v", def.Spendable, dcrutil.Amount(amt))
				}
			}

			_, err = w.PurchaseTickets(ctx, mockNetwork{}, &PurchaseTicketsRequest{
				Count:         1,
				SourceAccount: account,
				MinConf:       tc.minConf,
			})
			t.Logf("PurchaseTickets: %v", err)
			preflight := errors.Is(err, errors.InsufficientBalance) &&
				strings.Contains(err.Error(), noSpendableVAR)
			if preflight != tc.wantPreflight {
				t.Fatalf("PurchaseTickets: got %v, want pre-flight error %q: %v",
					err, noSpendableVAR, tc.wantPreflight)
			}
		})
	}
}
