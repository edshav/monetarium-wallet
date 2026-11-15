// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/blockchain/stake"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/gcs/blockcf2"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet/txrules"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
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
// unmined change. When the VSP accepts the fee, the fee tx spends the split's
// output reserved for it and the ticket is recorded as paid.
func TestPurchaseTicketsVSPSingleUTXO(t *testing.T) {
	for _, accept := range []bool{false, true} {
		name := "VSP fails"
		if accept {
			name = "VSP accepts the fee"
		}
		t.Run(name, func(t *testing.T) { testPurchaseTicketsVSPSingleUTXO(t, accept) })
	}
}

func testPurchaseTicketsVSPSingleUTXO(t *testing.T, accept bool) {
	ctx := context.Background()
	feeAddr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
		make([]byte, 20), basicWalletConfig.Params)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var quote dcrutil.Amount
	var paid []*wire.MsgTx
	reply := failingFeeVSP
	if accept {
		reply = func(path string, body []byte) (int, any) {
			mu.Lock()
			defer mu.Unlock()
			switch path {
			case "/api/v3/feeaddress":
				return http.StatusOK, types.FeeAddressResponse{Timestamp: time.Now().Unix(),
					FeeAddress: feeAddr.String(), FeeAmount: int64(quote), Request: body}
			case "/api/v3/payfee":
				var req types.PayFeeRequest
				if err := json.Unmarshal(body, &req); err != nil {
					return apiError(types.ErrBadRequest)
				}
				raw, err := hex.DecodeString(req.FeeTx)
				tx := new(wire.MsgTx)
				if err != nil || tx.FromBytes(raw) != nil {
					return apiError(types.ErrBadRequest)
				}
				paid = append(paid, tx)
				return http.StatusOK, types.PayFeeResponse{Timestamp: time.Now().Unix(), Request: body}
			}
			return failingFeeVSP(path, body)
		}
	}
	c := testVSPClient(ctx, t, reply)
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
	// Extend the chain to stake validation height, where the vote subsidy,
	// and with it the VSP fee, is no longer zero.  At a ticket price of
	// 0.1 VAR the fee is not dust.
	chain := []*BlockNode{blockOne.BlockNode}
	for tip := blockOne.MsgBlock.Header; int64(tip.Height) < w.chainParams.StakeValidationHeight; {
		header := wire.BlockHeader{
			PrevBlock: tip.BlockHash(),
			Height:    tip.Height + 1,
			Bits:      w.chainParams.PowLimitBits,
			SBits:     1e7,
			VoteBits:  dcrutil.BlockValid, // keep block one's funding tx valid
		}
		filter, err := blockcf2.Regular(&wire.MsgBlock{Header: header}, nil)
		if err != nil {
			t.Fatal(err)
		}
		hash := header.BlockHash()
		chain = append(chain, NewBlockNode(&header, &hash, filter))
		tip = header
	}
	_, err = w.ChainSwitch(ctx, new(SidechainForest), chain,
		map[chainhash.Hash][]*wire.MsgTx{*blockOne.Hash: {fund}})
	if err != nil {
		t.Fatal(err)
	}

	// Quote the largest fee the split's fee output covers: the wallet's own
	// estimate.  vspd quotes slightly less, with a fixed relay fee.
	sdiff, err := w.NextStakeDifficulty(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, height := w.MainChainTip(ctx)
	mu.Lock()
	quote = txrules.StakePoolTicketFee(sdiff, w.RelayFee(), height, 1, w.chainParams, true, true)
	mu.Unlock()
	feeScriptVer, feeScript := feeAddr.PaymentScript()
	quoteOut := &wire.TxOut{Value: int64(quote), Version: feeScriptVer, PkScript: feeScript}
	if quote <= 0 || txrules.IsDustOutput(quoteOut, w.RelayFee()) {
		t.Fatalf("test setup: VSP fee %v at height %d, sdiff %v, want above dust", quote, height, sdiff)
	}

	resp, err := w.PurchaseTickets(ctx, n, &PurchaseTicketsRequest{
		Count:     1,
		MinConf:   1,
		VSPClient: c,
	})
	var tickets int
	var extraSplit *wire.MsgTx
	fundOut := wire.OutPoint{Hash: fund.TxHash()}
	for _, tx := range published {
		if stake.IsSStx(tx) {
			tickets++
		}
		for _, in := range tx.TxIn {
			if in.PreviousOutPoint == fundOut {
				extraSplit = tx
			}
		}
	}
	if tickets != 1 {
		t.Fatalf("published %d tickets of %d txs, want 1 (PurchaseTickets error: %v)",
			tickets, len(published), err)
	}
	if !accept {
		return
	}
	if err != nil {
		t.Fatalf("PurchaseTickets: %v", err)
	}
	if extraSplit == nil {
		t.Fatal("no published tx spends the funding output")
	}

	mu.Lock()
	defer mu.Unlock()
	// The scheduled reconcile may resubmit the same fee tx.
	if len(paid) == 0 {
		t.Fatal("VSP received no fee tx")
	}
	feeTx := paid[0]
	for _, tx := range paid[1:] {
		if tx.TxHash() != feeTx.TxHash() {
			t.Fatalf("VSP received fee txs %v and %v, want one", feeTx.TxHash(), tx.TxHash())
		}
	}
	if len(feeTx.TxIn) != 1 {
		t.Fatalf("fee tx has %d inputs, want 1", len(feeTx.TxIn))
	}
	feeIn := feeTx.TxIn[0].PreviousOutPoint
	if feeIn.Hash != extraSplit.TxHash() {
		t.Fatalf("fee tx spends %v, want an output of the fee split %v", &feeIn, extraSplit.TxHash())
	}
	for _, tx := range published {
		for _, in := range tx.TxIn {
			if in.PreviousOutPoint == feeIn {
				t.Fatalf("fee input %v is also spent by published tx %v", &feeIn, tx.TxHash())
			}
		}
	}
	var toVSP dcrutil.Amount
	for _, out := range feeTx.TxOut {
		if out.Version == feeScriptVer && bytes.Equal(out.PkScript, feeScript) {
			toVSP += dcrutil.Amount(out.Value)
		}
	}
	if toVSP != quote {
		t.Errorf("fee tx pays the VSP %v, want the quote %v", toVSP, quote)
	}
	ticket, err := w.NewVSPTicket(ctx, resp.TicketHashes[0])
	if err != nil {
		t.Fatal(err)
	}
	info, err := ticket.VSPTicketInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.FeeTxStatus != uint32(udb.VSPFeeProcessPaid) || info.FeeHash != feeTx.TxHash() {
		t.Errorf("ticket fee status %d hash %v, want paid (%d) with %v",
			info.FeeTxStatus, info.FeeHash, udb.VSPFeeProcessPaid, feeTx.TxHash())
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
		name        string
		mined       bool
		expiry      uint32 // fund tx expiry
		coinbase    bool   // fund tx is a coinbase
		unpublished bool   // fund tx is recorded but not published
		change      bool   // pay an internal address
		other       bool   // purchase from a second, empty account
		minConf     int32
		// Spendable at minConf as each balance reads it, checked in setup.
		wantAcct, wantByCoin dcrutil.Amount
		wantPreflight        bool
	}{{
		// AccountBalance counts a young output with expiry as immature.
		// AccountBalanceByCoinType counts it as spendable until it
		// applies the same rule (a separate change); then the case skips.
		name: "mined output with expiry, minconf 1", mined: true, expiry: 1000,
		minConf: 1, wantAcct: 0, wantByCoin: amt,
	}, {
		// The same output at minconf 0: the node rejects the spend
		// (ErrExpiryTxSpentEarly), so the pre-flight refuses.
		name: "mined output with expiry, minconf 0", mined: true, expiry: 1000,
		minConf: 0, wantAcct: 0, wantByCoin: amt, wantPreflight: true,
	}, {
		// The node rejects any spend of an unmined output with an expiry,
		// so AccountBalance leaves it out of Spendable at minconf 0, as
		// selection does, and the check refuses.
		name: "unmined output with expiry, minconf 0", expiry: 1000,
		minConf: 0, wantAcct: 0, wantByCoin: 0, wantPreflight: true,
	}, {
		// Selection skips outputs of unpublished txs at any minconf.
		name: "unpublished tx, minconf 0", unpublished: true,
		minConf: 0, wantAcct: 0, wantByCoin: 0, wantPreflight: true,
	}, {
		name: "immature coinbase, minconf 0", mined: true, coinbase: true,
		minConf: 0, wantAcct: 0, wantByCoin: 0, wantPreflight: true,
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
			prevOut := wire.OutPoint{Hash: chainhash.Hash{0xfd}}
			if tc.coinbase {
				prevOut = wire.OutPoint{Index: wire.MaxPrevOutIndex}
			}
			fund.AddTxIn(wire.NewTxIn(&prevOut, amt, nil))
			ver, script := addr.(Address).PaymentScript()
			fund.AddTxOut(&wire.TxOut{Value: amt, Version: ver, PkScript: script})
			var blockHash *chainhash.Hash
			if tc.mined {
				blockHash = blockOne.Hash
			}
			if err := w.AddTransaction(ctx, fund, blockHash); err != nil {
				t.Fatal(err)
			}
			if tc.unpublished {
				fundHash := fund.TxHash()
				if err := w.SetPublished(ctx, &fundHash, false); err != nil {
					t.Fatal(err)
				}
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
			// Selection-side maturity for expiry outputs (a separate
			// change) makes both readings agree.  A refusal is still
			// pinned; a pass has nothing left to pin.
			agree := tc.wantByCoin > 0 && coinBal.Spendable == 0
			if agree && !tc.wantPreflight {
				t.Skip("AccountBalanceByCoinType already counts this output as immature")
			}
			if bal.Spendable != tc.wantAcct || (!agree && coinBal.Spendable != tc.wantByCoin) {
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
