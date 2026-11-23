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
	"runtime"
	"slices"
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
	"github.com/monetarium/monetarium-node/hdkeychain"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet/txrules"
	"github.com/monetarium/monetarium-wallet/wallet/txsizes"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

const purchaseVSPFeePercent = 2.0

// purchaseFixture is a wallet buying tickets through a fake VSP. The VSP
// quotes the fee the wallet estimates and keeps each fee tx it is paid with.
type purchaseFixture struct {
	*vspPaymentFixture
	c       *VSPClient
	feeAddr stdaddr.Address

	mu      sync.Mutex
	quote   dcrutil.Amount
	locked  []map[outpoint]struct{} // locked outpoints at each feeaddress request
	paid    []*wire.MsgTx
	paidFor []string // the ticket hash of each paid fee tx
	// feeTickets are the tickets the VSP was asked a fee address for, in
	// the order of their first request.  The VSP fails each request for
	// ticket failTicket, counted from 1; 0 fails none.
	feeTickets []string
	failTicket int
}

func newPurchaseFixture(ctx context.Context, t *testing.T) *purchaseFixture {
	t.Helper()
	p := &purchaseFixture{}
	p.c = testVSPClient(ctx, t, p.reply)
	p.vspPaymentFixture = &vspPaymentFixture{
		w:   p.c.wallet,
		cfg: basicWalletConfig,
		tip: basicWalletConfig.Params.GenesisBlock.Header,
	}
	p.w.SetNetworkBackend(mockNetwork{})
	var err error
	p.feeAddr, err = stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
		make([]byte, 20), basicWalletConfig.Params)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *purchaseFixture) reply(path string, body []byte) (int, any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch path {
	case "/api/v3/vspinfo":
		return http.StatusOK, types.VspInfoResponse{FeePercentage: purchaseVSPFeePercent}
	case "/api/v3/feeaddress":
		w := p.w
		w.lockedOutpointMu.Lock()
		p.locked = append(p.locked, maps.Clone(w.lockedOutpoints))
		w.lockedOutpointMu.Unlock()
		var req types.FeeAddressRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return apiError(types.ErrBadRequest)
		}
		i := slices.Index(p.feeTickets, req.TicketHash)
		if i < 0 {
			i = len(p.feeTickets)
			p.feeTickets = append(p.feeTickets, req.TicketHash)
		}
		if i+1 == p.failTicket {
			return apiError(types.ErrInternalError)
		}
		return http.StatusOK, types.FeeAddressResponse{
			FeeAddress: p.feeAddr.String(),
			FeeAmount:  int64(p.quote),
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
		p.paid = append(p.paid, tx)
		p.paidFor = append(p.paidFor, req.TicketHash)
		return http.StatusOK, types.PayFeeResponse{Request: body}
	}
	return apiError(types.ErrInternalError)
}

// setQuote makes the VSP quote the fee the wallet estimates for the next
// ticket, as vspd does, and returns the ticket price, the split output a
// ticket needs, and the quote.
func (p *purchaseFixture) setQuote(ctx context.Context, t *testing.T) (price, needed, quote dcrutil.Amount) {
	t.Helper()
	price, err := p.w.NextStakeDifficulty(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, tipHeight := p.w.MainChainTip(ctx)
	size := txsizes.EstimateSerializeSizeFromScriptSizes(
		[]int{txsizes.RedeemP2PKHSigScriptSize},
		[]int{txsizes.P2PKHPkScriptSize + 1, txsizes.TicketCommitmentScriptSize,
			txsizes.P2PKHPkScriptSize + 1}, 0)
	ticketFee := txrules.FeeForSerializeSize(p.w.RelayFee(), size)
	quote = txrules.StakePoolTicketFee(price, ticketFee, tipHeight,
		purchaseVSPFeePercent, p.w.chainParams, true, true)
	p.mu.Lock()
	p.quote = quote
	p.mu.Unlock()
	return price, price + ticketFee, quote
}

// splitOutputs returns the outputs of resp's split that fund its tickets and
// the fee outputs: the other outputs paying the tickets' split address.
func splitOutputs(t *testing.T, resp *PurchaseTicketsResponse) (ticketOuts map[uint32]bool, feeOuts map[outpoint]struct{}) {
	t.Helper()
	split := resp.SplitTx
	splitHash := split.TxHash()
	ticketOuts = make(map[uint32]bool)
	for _, ticket := range resp.Tickets {
		ticketOuts[ticket.TxIn[0].PreviousOutPoint.Index] = true
	}
	if len(ticketOuts) == 0 {
		t.Fatal("no tickets")
	}
	var splitScript []byte
	for idx := range ticketOuts {
		splitScript = split.TxOut[idx].PkScript
	}
	feeOuts = make(map[outpoint]struct{})
	for idx, out := range split.TxOut {
		if !ticketOuts[uint32(idx)] && string(out.PkScript) == string(splitScript) {
			feeOuts[outpoint{splitHash, uint32(idx)}] = struct{}{}
		}
	}
	return ticketOuts, feeOuts
}

// feeTxs returns the fee tx paid for each ticket, by ticket hash.  The fee
// payment Process starts also schedules a reconcile 0 to 2 minutes out, which
// may pay a ticket's fee again while a test runs; it resubmits the same fee
// tx, so a ticket paid twice must be paid with one tx.  The caller holds p.mu.
func (p *purchaseFixture) feeTxs(t *testing.T) map[string]*wire.MsgTx {
	t.Helper()
	txs := make(map[string]*wire.MsgTx)
	for i, tx := range p.paid {
		ticket := p.paidFor[i]
		if prev := txs[ticket]; prev != nil && prev.TxHash() != tx.TxHash() {
			t.Errorf("ticket %v paid with fee txs %v and %v", ticket, prev.TxHash(), tx.TxHash())
		}
		txs[ticket] = tx
	}
	return txs
}

// publishNetwork calls publish with each tx the wallet publishes.
type publishNetwork struct {
	mockNetwork
	publish func(*wire.MsgTx)
}

func (n publishNetwork) PublishTransactions(_ context.Context, txs ...*wire.MsgTx) error {
	for _, tx := range txs {
		n.publish(tx)
	}
	return nil
}

// TestPurchaseTicketsFundsVSPFeeFromSplit checks that a purchase without
// mixing pays each VSP fee from an output of the ticket split: one per
// ticket, locked while the fees are paid, and the only input of its fee tx.
// No other UTXO is reserved for the fees.  The fee outputs are locked by the
// time the split is published: once it is recorded they are spendable
// credits, and a concurrent spend could select them.  Below stake validation
// height the estimate is 0, so the split has no fee outputs and the fee
// payment funds the fee from other outputs.
func TestPurchaseTicketsFundsVSPFeeFromSplit(t *testing.T) {
	t.Run("below SVH", func(t *testing.T) {
		testPurchaseTicketsFundsVSPFeeFromSplit(t, 2, 0, 0, 0, false)
	})
	// The pads and the dust threshold both scale with the relay fee.
	t.Run("below SVH, relay fee 2e4", func(t *testing.T) {
		testPurchaseTicketsFundsVSPFeeFromSplit(t, 2, 0, 0, 2e4, false)
	})
	// At 3 atoms/kB each pad rounds up to the relay fee, so the two pads
	// are not dust; the 0 estimate alone leaves the fee outputs out.
	t.Run("below SVH, relay fee 3", func(t *testing.T) {
		testPurchaseTicketsFundsVSPFeeFromSplit(t, 2, 0, 0, 3, false)
	})
	// Past StakeValidationHeight the wallet's estimate is above 0, and at a
	// ticket price of 0.1 VAR the fee output is not dust.  1 is the
	// purchaseticket RPC's default minconf.
	t.Run("past SVH, minconf 1", func(t *testing.T) {
		svh := uint32(basicWalletConfig.Params.StakeValidationHeight)
		testPurchaseTicketsFundsVSPFeeFromSplit(t, svh, 1e7, 1, 0, true)
	})
	// At 1e6 atoms/kB the quote and one pad are dust and the quote and both
	// pads are not: the output that is tested is the one the split carries.
	t.Run("past SVH, relay fee 1e6", func(t *testing.T) {
		svh := uint32(basicWalletConfig.Params.StakeValidationHeight)
		testPurchaseTicketsFundsVSPFeeFromSplit(t, svh, 1e7, 1, 1e6, true)
	})
	// At a ticket price of 0.01 VAR and 1e6 atoms/kB the quote and two pads
	// are dust, so a quote above 0 still leaves the fee outputs out.
	t.Run("past SVH, dust at relay fee 1e6", func(t *testing.T) {
		svh := uint32(basicWalletConfig.Params.StakeValidationHeight)
		testPurchaseTicketsFundsVSPFeeFromSplit(t, svh, 1e6, 1, 1e6, false)
	})
}

// feeOutput is the split's fee output for a quote: the quote and two one-input
// miner fees.
func (p *purchaseFixture) feeOutput(quote dcrutil.Amount) dcrutil.Amount {
	return quote + 2*p.oneInputMinerFee()
}

// setRelayFee makes relayFee the wallet's VAR relay fee, as a manual fee does:
// it takes priority over the fee the network backend reports.
func (p *purchaseFixture) setRelayFee(t *testing.T, relayFee dcrutil.Amount) {
	t.Helper()
	if err := p.w.SetManualFee(cointype.CoinTypeVAR, cointype.SKAAmountFromInt64(int64(relayFee))); err != nil {
		t.Fatal(err)
	}
	if got := p.w.RelayFee(); got != relayFee {
		t.Fatalf("test setup: relay fee %v, want %v", got, relayFee)
	}
}

// checkNoDust fails the test when tx has an output that a node whose minimum
// relay fee is relayFee rejects as dust.  The rule is the node's (isDust in
// monetarium-node internal/mempool/policy.go), sized from the wire format
// rather than by the wallet's own dust code.
func checkNoDust(t *testing.T, tx *wire.MsgTx, relayFee dcrutil.Amount) {
	t.Helper()
	for i, out := range tx.TxOut {
		if out.Value*1000/(3*int64(out.SerializeSize()+165)) < int64(relayFee) {
			t.Errorf("tx %v output %d of %v is dust", tx.TxHash(), i, dcrutil.Amount(out.Value))
		}
	}
}

// pastSVH mines to stake validation height at a ticket price of 0.1 VAR, so
// the wallet's estimate is above 0 and the split gets fee outputs.
func (p *purchaseFixture) pastSVH(ctx context.Context, t *testing.T) {
	t.Helper()
	p.sbits = 1e7
	p.mine(ctx, t, uint32(basicWalletConfig.Params.StakeValidationHeight))
}

// mine extends the main chain with empty blocks up to height in one
// ChainSwitch, each header carrying ticket price p.sbits.
func (p *purchaseFixture) mine(ctx context.Context, t *testing.T, height uint32) {
	t.Helper()
	var chain []*BlockNode
	for p.tip.Height < height {
		header := wire.BlockHeader{
			PrevBlock: p.tip.BlockHash(),
			Height:    p.tip.Height + 1,
			Bits:      p.cfg.Params.PowLimitBits,
			SBits:     p.sbits,
			VoteBits:  1, // approve the previous block, or its outputs are invalidated
		}
		filter, err := blockcf2.Regular(&wire.MsgBlock{Header: header}, nil)
		if err != nil {
			t.Fatal(err)
		}
		hash := header.BlockHash()
		chain = append(chain, NewBlockNode(&header, &hash, filter))
		p.tip = header
	}
	if len(chain) == 0 {
		return
	}
	if _, err := p.w.ChainSwitch(ctx, &p.forest, chain, nil); err != nil {
		t.Fatal(err)
	}
}

// testPurchaseTicketsFundsVSPFeeFromSplit mines empty blocks, then funds 16
// outputs in each of the last two blocks up to height, each header carrying
// ticket price sbits, and buys at minConf, at relayFee unless it is 0.  The
// split has fee outputs when feeOutputs is set.  Above minconf 0 selection
// starts with a random walk that can come back empty when the account holds
// only a few outputs; 32 outputs make that negligible.
func testPurchaseTicketsFundsVSPFeeFromSplit(t *testing.T, height uint32, sbits int64, minConf int32, relayFee dcrutil.Amount, feeOutputs bool) {
	ctx := context.Background()
	p := newPurchaseFixture(ctx, t)
	if relayFee != 0 {
		p.setRelayFee(t, relayFee)
	}
	p.sbits = sbits
	p.mine(ctx, t, height-2)
	for p.tip.Height < height {
		p.fund(ctx, t, true, slices.Repeat([]dcrutil.Amount{1e8}, 16)...)
	}
	_, needed, quote := p.setQuote(ctx, t)
	pastSVH := int64(height) >= basicWalletConfig.Params.StakeValidationHeight
	if pastSVH != (quote > 0) {
		t.Fatalf("test setup: wallet's estimate is %v at height %d", quote, height)
	}
	// A dust fee output would make a real node reject the split.
	dust := txrules.IsDustAmount(p.feeOutput(quote), txsizes.P2PKHPkScriptSize, p.w.RelayFee())
	if feeOutputs != (quote > 0 && !dust) {
		t.Fatalf("test setup: estimate %v, fee output %v dust: %v; want fee outputs: %v",
			quote, p.feeOutput(quote), dust, feeOutputs)
	}

	// The locked outpoints at each publish of each tx.
	lockedAtPublish := make(map[wire.OutPoint][]map[outpoint]struct{})
	n := publishNetwork{publish: func(tx *wire.MsgTx) {
		p.w.lockedOutpointMu.Lock()
		defer p.w.lockedOutpointMu.Unlock()
		op := wire.OutPoint{Hash: tx.TxHash()}
		lockedAtPublish[op] = append(lockedAtPublish[op], maps.Clone(p.w.lockedOutpoints))
	}}
	p.w.SetNetworkBackend(n)

	const count = 2
	resp, err := p.w.PurchaseTickets(ctx, n, &PurchaseTicketsRequest{
		Count:     count,
		MinConf:   minConf,
		VSPClient: p.c,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Tickets) != count {
		t.Fatalf("%d tickets, want %d", len(resp.Tickets), count)
	}
	split := resp.SplitTx

	ticketOuts, feeOuts := splitOutputs(t, resp)
	for idx := range ticketOuts {
		if out := split.TxOut[idx]; out.Value != int64(needed) {
			t.Errorf("ticket output %d is %v, want %v", idx, dcrutil.Amount(out.Value), needed)
		}
	}
	checkNoDust(t, split, p.w.RelayFee())
	if !feeOutputs {
		// No fee outputs: the split is the tickets' outputs and change.
		if len(feeOuts) != 0 || len(split.TxOut) > count+1 {
			t.Errorf("split has %d fee outputs and %d outputs, want no fee outputs and at most %d outputs",
				len(feeOuts), len(split.TxOut), count+1)
		}
		// No other output is reserved for the fees either, and none is
		// left locked once the fee payment returns.
		for i, locked := range lockedAtPublish[wire.OutPoint{Hash: split.TxHash()}] {
			if len(locked) != 0 {
				t.Errorf("locked at publish %d of the split: %v, want nothing", i, locked)
			}
		}
		p.w.lockedOutpointMu.Lock()
		if len(p.w.lockedOutpoints) != 0 {
			t.Errorf("locked after the purchase: %v, want nothing", p.w.lockedOutpoints)
		}
		p.w.lockedOutpointMu.Unlock()
		return
	}
	want := p.feeOutput(quote)
	for op := range feeOuts {
		out := split.TxOut[op.index]
		if dcrutil.Amount(out.Value) != want {
			t.Errorf("fee output %d is %v, want the quote and two one-input miner fees: %v",
				op.index, dcrutil.Amount(out.Value), want)
		}
	}
	if len(feeOuts) != count {
		t.Fatalf("split has %d fee outputs, want %d", len(feeOuts), count)
	}

	published := lockedAtPublish[wire.OutPoint{Hash: split.TxHash()}]
	if len(published) == 0 {
		t.Fatal("split not published")
	}
	for i, locked := range published {
		for op := range feeOuts {
			if _, ok := locked[op]; !ok {
				t.Errorf("fee output %d not locked at publish %d of the split", op.index, i)
			}
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.locked) == 0 {
		t.Fatal("VSP not asked for a fee address")
	}
	// When the first fee is quoted, the fee outputs are locked and nothing
	// else is.
	if !maps.Equal(p.locked[0], feeOuts) {
		t.Errorf("locked at the first quote: %v, want the fee outputs %v", p.locked[0], feeOuts)
	}
	paid := p.feeTxs(t)
	if len(paid) != count {
		t.Fatalf("fees paid for %d tickets, want %d", len(paid), count)
	}
	spent := make(map[outpoint]struct{})
	for _, hash := range resp.TicketHashes {
		tx := paid[hash.String()]
		if tx == nil {
			t.Errorf("ticket %v fee not paid", hash)
			continue
		}
		checkFeeTx(t, p.w, tx, quote, p.feeAddr)
		if len(tx.TxIn) != 1 {
			t.Errorf("fee tx has %d inputs, want 1", len(tx.TxIn))
			continue
		}
		op := tx.TxIn[0].PreviousOutPoint
		spent[outpoint{op.Hash, op.Index}] = struct{}{}
	}
	if !maps.Equal(spent, feeOuts) {
		t.Errorf("fee txs spend %v, want the fee outputs %v", spent, feeOuts)
	}
}

// TestPurchaseTicketsExtraSplitOutput checks a purchase that pays the VSP fee
// from extraSplitOutput, the output PurchaseTickets makes after
// errVSPFeeRequiresUTXOSplit.  Only a mixed purchase can return that error, so
// only a mixed purchase reaches this retry; the subtest "funds for the
// ticket" calls purchaseTickets with extraSplitOutput set and no mixing to
// drive the reservation loop directly.  The ticket is funded from other
// outputs, which are first reserved for the ticket price.
func TestPurchaseTicketsExtraSplitOutput(t *testing.T) {
	// funds returns the other outputs to fund for a ticket price.
	setup := func(ctx context.Context, t *testing.T, funds func(price dcrutil.Amount) []dcrutil.Amount) (*purchaseFixture, *PurchaseTicketsRequest) {
		p := newPurchaseFixture(ctx, t)
		price, _, quote := p.setQuote(ctx, t)
		extra := p.fund(ctx, t, true, p.feeOutput(quote))
		p.fund(ctx, t, true, funds(price)...)
		return p, &PurchaseTicketsRequest{
			Count:     1,
			MinConf:   0,
			VSPClient: p.c,
			extraSplitOutput: &Input{
				OutPoint: wire.OutPoint{Hash: extra.TxHash()},
				PrevOut:  *extra.TxOut[0],
			},
		}
	}

	t.Run("funds for the ticket", func(t *testing.T) {
		ctx := context.Background()
		p, req := setup(ctx, t, func(dcrutil.Amount) []dcrutil.Amount {
			return []dcrutil.Amount{1e8, 1e8}
		})
		resp, err := p.w.purchaseTickets(ctx, "test", mockNetwork{}, req)
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Tickets) != 1 {
			t.Fatalf("%d tickets, want 1", len(resp.Tickets))
		}
		// No fee output in the split: the ticket output and change.
		if _, feeOuts := splitOutputs(t, resp); len(feeOuts) != 0 {
			t.Errorf("split has %d fee outputs, want none", len(feeOuts))
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		tx := p.feeTxs(t)[resp.TicketHashes[0].String()]
		if tx == nil {
			t.Fatal("ticket fee not paid")
		}
		if in := tx.TxIn; len(in) != 1 || in[0].PreviousOutPoint != req.extraSplitOutput.OutPoint {
			t.Errorf("fee tx does not spend extraSplitOutput alone")
		}
	})

	t.Run("funds short of the ticket price", func(t *testing.T) {
		ctx := context.Background()
		p, req := setup(ctx, t, func(price dcrutil.Amount) []dcrutil.Amount {
			return []dcrutil.Amount{price/2 - 1, price/2 - 1}
		})
		unmined := unminedTxs(ctx, t, p.w)
		_, err := p.w.purchaseTickets(ctx, "test", mockNetwork{}, req)
		// The ticket-price reservation finds the other outputs short, and
		// they make the price only together with extraSplitOutput.
		if !errors.Is(err, errVSPFeeRequiresUTXOSplit) {
			t.Errorf("error %v, want %v", err, errVSPFeeRequiresUTXOSplit)
		}
		if n := unminedTxs(ctx, t, p.w) - unmined; n != 0 {
			t.Errorf("%d txs published, want none", n)
		}
		if locked := lockedOutpoints(ctx, t, p.w); len(locked) != 0 {
			t.Errorf("outpoints left locked: %v", locked)
		}
	})
}

// TestPurchaseTicketsDontSignNoFeeOutputs checks that an unsigned purchase,
// which pays no VSP fee, gets a split without fee outputs.
func TestPurchaseTicketsDontSignNoFeeOutputs(t *testing.T) {
	ctx := context.Background()
	p := newPurchaseFixture(ctx, t)
	p.pastSVH(ctx, t)
	p.fund(ctx, t, true, 1e8)
	p.fund(ctx, t, true, 1e8)
	p.setQuote(ctx, t)

	const count = 2
	resp, err := p.w.PurchaseTickets(ctx, mockNetwork{}, &PurchaseTicketsRequest{
		Count:      count,
		MinConf:    0,
		VSPClient:  p.c,
		DontSignTx: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Tickets) != count {
		t.Fatalf("%d tickets, want %d", len(resp.Tickets), count)
	}
	for i, in := range resp.SplitTx.TxIn {
		if len(in.SignatureScript) != 0 {
			t.Errorf("split input %d is signed", i)
		}
	}
	if _, feeOuts := splitOutputs(t, resp); len(feeOuts) != 0 {
		t.Errorf("split has %d fee outputs, want none", len(feeOuts))
	}
}

// TestPurchaseTicketsSKAInAccount checks that a purchase from an account that
// also holds SKA funds the split, and so the VSP fees, with VAR only.
func TestPurchaseTicketsSKAInAccount(t *testing.T) {
	ctx := context.Background()
	p := newPurchaseFixture(ctx, t)
	p.pastSVH(ctx, t)
	p.fund(ctx, t, true, 1e8)
	addr, err := p.w.NewInternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	ver, script := addr.(Address).PaymentScript()
	ska := wire.NewMsgTx()
	ska.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{0xff}}, 0, nil))
	ska.AddTxOut(&wire.TxOut{Version: ver, PkScript: script, CoinType: cointype.CoinType(1),
		SKAValue: new(big.Int).Mul(big.NewInt(1e18), big.NewInt(1e3))})
	if err := p.w.AddTransaction(ctx, ska, nil); err != nil {
		t.Fatal(err)
	}
	if bal, err := p.w.AccountBalanceByCoinType(ctx, 0, cointype.CoinType(1), 0); err != nil {
		t.Fatal(err)
	} else if !bal.SKATotal.IsPositive() {
		t.Fatalf("SKA balance %v, want the funded output", bal.SKATotal)
	}
	p.setQuote(ctx, t)

	resp, err := p.w.PurchaseTickets(ctx, mockNetwork{}, &PurchaseTicketsRequest{
		Count:     1,
		MinConf:   0,
		VSPClient: p.c,
	})
	if err != nil {
		t.Fatal(err)
	}
	split := resp.SplitTx
	skaHash := ska.TxHash()
	for i, in := range split.TxIn {
		if in.PreviousOutPoint.Hash == skaHash || in.SKAValueIn != nil {
			t.Errorf("split input %d spends SKA", i)
		}
	}
	for i, out := range split.TxOut {
		if out.CoinType != cointype.CoinTypeVAR || out.SKAValue != nil {
			t.Errorf("split output %d is coin type %v", i, out.CoinType)
		}
	}
	_, feeOuts := splitOutputs(t, resp)
	if len(feeOuts) != 1 {
		t.Fatalf("split has %d fee outputs, want 1", len(feeOuts))
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	tx := p.feeTxs(t)[resp.TicketHashes[0].String()]
	if tx == nil {
		t.Fatal("ticket fee not paid")
	}
	for i, in := range tx.TxIn {
		if _, ok := feeOuts[outpoint{in.PreviousOutPoint.Hash, in.PreviousOutPoint.Index}]; !ok {
			t.Errorf("fee tx input %d is not a fee output of the split", i)
		}
	}
	for i, out := range tx.TxOut {
		if out.CoinType != cointype.CoinTypeVAR || out.SKAValue != nil {
			t.Errorf("fee tx output %d is coin type %v", i, out.CoinType)
		}
	}
}

// TestPurchaseTicketsMixedReservesVSPFee checks that a mixed purchase still
// reserves a wallet UTXO per VSP fee before the split: with two outputs, one
// is reserved for the first fee and the other for the first ticket, so the
// second ticket asks for an extra split.  The same outputs fund two tickets
// without mixing (TestPurchaseTicketsFundsVSPFeeFromSplit).  The mix itself
// cannot run here: it needs mixing peers.
func TestPurchaseTicketsMixedReservesVSPFee(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p := newPurchaseFixture(ctx, t)
	p.fund(ctx, t, true, 1e8)
	p.fund(ctx, t, true, 1e8)
	p.setQuote(ctx, t)
	unmined := unminedTxs(ctx, t, p.w)

	_, err := p.w.purchaseTickets(ctx, "test", mockNetwork{}, &PurchaseTicketsRequest{
		Count:     2,
		MinConf:   0,
		VSPClient: p.c,
		Mixing:    true,
	})
	if !errors.Is(err, errVSPFeeRequiresUTXOSplit) {
		t.Errorf("error %v, want %v", err, errVSPFeeRequiresUTXOSplit)
	}
	if n := unminedTxs(ctx, t, p.w) - unmined; n != 0 {
		t.Errorf("%d txs published, want none", n)
	}
	if locked := lockedOutpoints(ctx, t, p.w); len(locked) != 0 {
		t.Errorf("outpoints left locked: %v", locked)
	}
}

// lockedNow returns the outpoints the wallet has locked, including those of
// txs it no longer holds, which LockedOutpoints leaves out.
func lockedNow(w *Wallet) map[outpoint]struct{} {
	w.lockedOutpointMu.Lock()
	defer w.lockedOutpointMu.Unlock()
	return maps.Clone(w.lockedOutpoints)
}

// sortedIndexes returns the output indexes of ops in ascending order.
func sortedIndexes(ops map[outpoint]struct{}) []uint32 {
	var idx []uint32
	for op := range ops {
		idx = append(idx, op.index)
	}
	slices.Sort(idx)
	return idx
}

// TestPurchaseTicketsVSPQuoteAboveFeeOutput checks a purchase whose VSP quotes
// more than the split's fee output holds: the fee tx adds another input to
// the fee output and still pays the quote and the miner.
func TestPurchaseTicketsVSPQuoteAboveFeeOutput(t *testing.T) {
	ctx := context.Background()
	p := newPurchaseFixture(ctx, t)
	p.pastSVH(ctx, t)
	p.fund(ctx, t, true, 1e8)
	p.fund(ctx, t, true, 1e8)
	_, _, quote := p.setQuote(ctx, t)
	// Above the wallet's estimate plus both one-input miner-fee pads.
	quote += 1e6
	p.mu.Lock()
	p.quote = quote
	p.mu.Unlock()

	resp, err := p.w.PurchaseTickets(ctx, mockNetwork{}, &PurchaseTicketsRequest{
		Count:     1,
		MinConf:   0,
		VSPClient: p.c,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, feeOuts := splitOutputs(t, resp)
	if len(feeOuts) != 1 {
		t.Fatalf("split has %d fee outputs, want 1", len(feeOuts))
	}
	for op := range feeOuts {
		if v := dcrutil.Amount(resp.SplitTx.TxOut[op.index].Value); v >= quote {
			t.Fatalf("fee output %v covers the quote %v", v, quote)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	tx := p.feeTxs(t)[resp.TicketHashes[0].String()]
	if tx == nil {
		t.Fatal("ticket fee not paid")
	}
	checkFeeTx(t, p.w, tx, quote, p.feeAddr)
	var fromFeeOut bool
	for _, in := range tx.TxIn {
		op := in.PreviousOutPoint
		if _, ok := feeOuts[outpoint{op.Hash, op.Index}]; ok {
			fromFeeOut = true
		}
	}
	if !fromFeeOut || len(tx.TxIn) < 2 {
		t.Errorf("fee tx has %d inputs, spends the fee output: %v; want the fee output and more",
			len(tx.TxIn), fromFeeOut)
	}
}

// TestPurchaseTicketsVSPQuoteNoTopUp checks a purchase whose VSP quotes more
// than the split's fee output holds when no mined output is left to top it up:
// the split spent the only one, and top-ups take mined outputs only.  The
// ticket is bought, its fee is left unpaid and marked errored for the
// scheduled retry, no fee tx is recorded, and nothing stays locked.
func TestPurchaseTicketsVSPQuoteNoTopUp(t *testing.T) {
	ctx := context.Background()
	p := newPurchaseFixture(ctx, t)
	p.pastSVH(ctx, t)
	p.fund(ctx, t, true, 1e8)
	_, _, quote := p.setQuote(ctx, t)
	p.mu.Lock()
	p.quote = quote + 1e6 // above the fee output
	p.mu.Unlock()

	resp, err := p.w.PurchaseTickets(ctx, mockNetwork{}, &PurchaseTicketsRequest{
		Count:     1,
		MinConf:   0,
		VSPClient: p.c,
	})
	// The returned error is ErrVSPFeeNotPaid, which
	// TestPurchaseTicketsFeeErrorNamesTicket checks, so only the response is
	// checked here.
	if resp == nil || len(resp.TicketHashes) != 1 {
		t.Fatalf("response %v, %v, want 1 ticket hash", resp, err)
	}
	if _, feeOuts := splitOutputs(t, resp); len(feeOuts) != 1 {
		t.Fatalf("split has %d fee outputs, want 1", len(feeOuts))
	}

	p.mu.Lock()
	asked, paid := len(p.feeTickets), len(p.paid)
	p.mu.Unlock()
	if asked != 1 || paid != 0 {
		t.Errorf("VSP asked for %d fee addresses and paid %d fee txs, want 1 and none", asked, paid)
	}
	ticket, err := p.w.NewVSPTicket(ctx, resp.TicketHashes[0])
	if err != nil {
		t.Fatal(err)
	}
	info, err := ticket.VSPTicketInfo(ctx)
	if err != nil || udb.FeeStatus(info.FeeTxStatus) != udb.VSPFeeProcessErrored {
		t.Errorf("ticket fee status %+v (err %v), want errored", info, err)
	}
	if n := unminedTxs(ctx, t, p.w); n != 2 {
		t.Errorf("%d unmined txs, want the split and the ticket alone", n)
	}
	if locked := lockedNow(p.w); len(locked) != 0 {
		t.Errorf("outpoints left locked: %v", locked)
	}
}

// TestPurchaseTicketsLockedAfterPublishFeeOutput checks that a ticket whose
// fee step cannot sign (the wallet is locked once the ticket is published)
// has its fee output unlocked and a fee job that retries the fee.  The VSP is
// never asked for a fee address, as that request is signed.
func TestPurchaseTicketsLockedAfterPublishFeeOutput(t *testing.T) {
	ctx := context.Background()
	p := newPurchaseFixture(ctx, t)
	p.pastSVH(ctx, t)
	p.fund(ctx, t, true, 1e8)
	p.setQuote(ctx, t)
	n := publishNetwork{publish: func(tx *wire.MsgTx) {
		if stake.IsSStx(tx) {
			p.w.Lock()
		}
	}}
	p.w.SetNetworkBackend(n)

	resp, err := p.w.PurchaseTickets(ctx, n, &PurchaseTicketsRequest{
		Count:     1,
		MinConf:   0,
		VSPClient: p.c,
	})
	if resp == nil || len(resp.TicketHashes) != 1 {
		t.Fatalf("response %v, %v, want 1 ticket hash", resp, err)
	}
	if _, feeOuts := splitOutputs(t, resp); len(feeOuts) != 1 {
		t.Fatalf("split has %d fee outputs, want 1", len(feeOuts))
	}
	p.mu.Lock()
	asked := len(p.feeTickets)
	p.mu.Unlock()
	if asked != 0 {
		t.Fatalf("VSP asked for %d fee addresses, want none: a locked wallet cannot sign the request", asked)
	}
	if locked := lockedNow(p.w); len(locked) != 0 {
		t.Errorf("outpoints left locked: %v", locked)
	}
	p.c.mu.Lock()
	fp := p.c.jobs[*resp.TicketHashes[0]]
	p.c.mu.Unlock()
	if fp == nil {
		t.Errorf("no fee job for ticket %v", resp.TicketHashes[0])
	}
}

// lockedVotingAccount returns a new account of w with its own passphrase,
// locked, so its private keys cannot be read although w is unlocked.
func lockedVotingAccount(ctx context.Context, t *testing.T, w *Wallet) uint32 {
	t.Helper()
	w.accountGapLimit = 1 // allow one account without history
	account, err := w.NextAccount(ctx, "voting")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetAccountPassphrase(ctx, account, []byte("voting")); err != nil {
		t.Fatal(err)
	}
	if err := w.LockAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	return account
}

// xpubVotingAccount imports an account from an xpub, which has no private
// keys, and returns its number.
func xpubVotingAccount(ctx context.Context, t *testing.T, w *Wallet) uint32 {
	t.Helper()
	seed := make([]byte, hdkeychain.RecommendedSeedLen)
	seed[0] = 1
	master, err := hdkeychain.NewMaster(seed, w.chainParams)
	if err != nil {
		t.Fatal(err)
	}
	acct, err := master.Child(hdkeychain.HardenedKeyStart)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.ImportXpubAccount(ctx, "xpub", acct.Neuter()); err != nil {
		t.Fatal(err)
	}
	account, err := w.AccountNumber(ctx, "xpub")
	if err != nil {
		t.Fatal(err)
	}
	return account
}

// TestPurchaseTicketsVotingKeyUnreadable checks that a purchase through a VSP
// publishes nothing, not even the split, when the voting account cannot give
// up the voting key the VSP needs: a locked account with its own passphrase,
// an account imported from an xpub, or no such account.  A ticket buyer retries every block,
// so a split published before the failure would cost a miner fee each time.
func TestPurchaseTicketsVotingKeyUnreadable(t *testing.T) {
	tests := []struct {
		name    string
		account func(context.Context, *testing.T, *Wallet) uint32
		kind    errors.Kind
	}{
		{"locked", lockedVotingAccount, errors.Locked},
		{"xpub", xpubVotingAccount, errors.Invalid},
		{"missing", func(context.Context, *testing.T, *Wallet) uint32 { return 42 }, errors.NotExist},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			p := newPurchaseFixture(ctx, t)
			p.pastSVH(ctx, t)
			p.fund(ctx, t, true, 1e8)
			p.setQuote(ctx, t)
			voting := tc.account(ctx, t, p.w)
			var published []*wire.MsgTx
			n := publishNetwork{publish: func(tx *wire.MsgTx) { published = append(published, tx) }}
			p.w.SetNetworkBackend(n)

			resp, err := p.w.PurchaseTickets(ctx, n, &PurchaseTicketsRequest{
				Count:         2,
				MinConf:       0,
				VSPClient:     p.c,
				VotingAccount: voting,
			})
			if resp != nil || !errors.Is(err, tc.kind) || errors.Is(err, ErrVSPFeeNotPaid) {
				t.Fatalf("PurchaseTickets: got %+v, %v; want no response and a %v error without ErrVSPFeeNotPaid", resp, err, tc.kind)
			}
			if want := fmt.Sprintf("voting account %d", voting); !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not name %q", err, want)
			}
			for _, tx := range published {
				t.Errorf("published %v", tx.TxHash())
			}
			if n := unminedTxs(ctx, t, p.w); n != 0 {
				t.Errorf("%d unmined txs, want none", n)
			}
			if locked := lockedNow(p.w); len(locked) != 0 {
				t.Errorf("outpoints left locked: %v", locked)
			}
			p.mu.Lock()
			asked := len(p.feeTickets)
			p.mu.Unlock()
			if asked != 0 {
				t.Errorf("VSP asked for %d fee addresses, want none", asked)
			}
		})
	}
}

// TestPurchaseTicketsMixedVotingKeyUnreadable checks that a mixed purchase
// through a VSP from a locked voting account publishes nothing.  With one
// UTXO the purchase needs a fee-prep split first, and the voting key check
// must come before it.
func TestPurchaseTicketsMixedVotingKeyUnreadable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := newPurchaseFixture(ctx, t)
	p.pastSVH(ctx, t)
	p.fund(ctx, t, true, 1e8)
	p.setQuote(ctx, t)
	voting := lockedVotingAccount(ctx, t, p.w)
	var published []*wire.MsgTx
	n := publishNetwork{publish: func(tx *wire.MsgTx) {
		published = append(published, tx)
		cancel() // do not wait for mixing peers
	}}
	p.w.SetNetworkBackend(n)

	_, err := p.w.PurchaseTickets(ctx, n, &PurchaseTicketsRequest{
		Count:         1,
		MinConf:       0,
		VSPClient:     p.c,
		Mixing:        true,
		MixedAccount:  voting,
		VotingAccount: voting,
	})
	for _, tx := range published {
		t.Errorf("published %v", tx.TxHash())
	}
	if !errors.Is(err, errors.Locked) {
		t.Errorf("error %v, want %v", err, errors.Locked)
	}
}

// TestPurchaseTicketsUnsignedSkipsVotingKeyCheck checks that an unsigned
// purchase through a VSP, which builds no VSPTicket, does not need the voting
// key: it returns both tickets from a locked voting account or wallet.
func TestPurchaseTicketsUnsignedSkipsVotingKeyCheck(t *testing.T) {
	tests := []struct {
		name string
		lock func(context.Context, *testing.T, *Wallet) uint32
	}{
		{"locked voting account", lockedVotingAccount},
		{"locked wallet", func(_ context.Context, t *testing.T, w *Wallet) uint32 {
			if err := w.Lock(); err != nil {
				t.Fatal(err)
			}
			return 0
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			p := newPurchaseFixture(ctx, t)
			p.pastSVH(ctx, t)
			p.fund(ctx, t, true, 1e8)
			p.fund(ctx, t, true, 1e8)
			p.setQuote(ctx, t)
			voting := tc.lock(ctx, t, p.w)
			resp, err := p.w.PurchaseTickets(ctx, mockNetwork{}, &PurchaseTicketsRequest{
				Count:         2,
				MinConf:       0,
				VSPClient:     p.c,
				DontSignTx:    true,
				VotingAccount: voting,
			})
			if err != nil || resp == nil || len(resp.Tickets) != 2 {
				t.Fatalf("PurchaseTickets: got %+v, %v; want two unsigned tickets", resp, err)
			}
		})
	}
}

// lockOnKeyReadDB is the wallet's database, which locks w when NewVSPTicket
// opens a read for the nth voting key.
type lockOnKeyReadDB struct {
	walletdb.DB
	w     *Wallet
	n     int
	reads int
}

func (d *lockOnKeyReadDB) BeginReadTx() (walletdb.ReadTx, error) {
	if inCallers(".(*Wallet).NewVSPTicket") && inCallers(".(*Wallet).LoadPrivateKey") {
		d.reads++
		if d.reads == d.n {
			d.w.Lock()
		}
	}
	return d.DB.BeginReadTx()
}

// inCallers returns whether a function whose name ends with suffix is on the
// calling goroutine's stack.
func inCallers(suffix string) bool {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	for {
		f, more := frames.Next()
		if strings.HasSuffix(f.Function, suffix) {
			return true
		}
		if !more {
			return false
		}
	}
}

// TestPurchaseTicketsLockedBeforeVSPTicket checks that when the VSPTicket of
// the first or the second ticket cannot be built (the wallet is locked right
// before its voting key is read, after the voting key check), neither ticket
// is published and the wallet drops both, including a first ticket whose
// VSPTicket was built.  The split, already published with its fee outputs,
// stays, and nothing is left locked.
func TestPurchaseTicketsLockedBeforeVSPTicket(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
	}{{"first", 1}, {"second", 2}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			p := newPurchaseFixture(ctx, t)
			p.pastSVH(ctx, t)
			p.fund(ctx, t, true, 1e8)
			p.setQuote(ctx, t)
			db := &lockOnKeyReadDB{DB: p.w.db, w: p.w, n: tc.n}
			p.w.db = db
			var published []*wire.MsgTx
			n := publishNetwork{publish: func(tx *wire.MsgTx) { published = append(published, tx) }}
			p.w.SetNetworkBackend(n)

			resp, err := p.w.PurchaseTickets(ctx, n, &PurchaseTicketsRequest{
				Count:     2,
				MinConf:   0,
				VSPClient: p.c,
			})
			if db.reads != tc.n {
				t.Fatalf("%d voting key reads, want %d", db.reads, tc.n)
			}
			if resp != nil || !errors.Is(err, errors.Locked) || errors.Is(err, ErrVSPFeeNotPaid) {
				t.Fatalf("PurchaseTickets: got %+v, %v; want no response and a Locked error without ErrVSPFeeNotPaid", resp, err)
			}
			var split *wire.MsgTx
			for _, tx := range published {
				switch {
				case stake.IsSStx(tx):
					t.Errorf("ticket %v published", tx.TxHash())
				case split == nil:
					split = tx
				case tx.TxHash() != split.TxHash():
					t.Errorf("published %v besides the split %v", tx.TxHash(), split.TxHash())
				}
			}
			// Two ticket outputs, two fee outputs and change.
			if split == nil || len(split.TxOut) != 5 {
				t.Fatalf("split %v published, want one with 5 outputs", split)
			}
			if n := unminedTxs(ctx, t, p.w); n != 1 {
				t.Errorf("%d unmined txs, want the split alone", n)
			}
			if locked := lockedNow(p.w); len(locked) != 0 {
				t.Errorf("outpoints left locked: %v", locked)
			}
		})
	}
}

// TestPurchaseTicketsLockedVotingAccountNoVSP checks that a purchase without
// a VSP does not read the voting key: from a locked voting account it buys
// the ticket.
func TestPurchaseTicketsLockedVotingAccountNoVSP(t *testing.T) {
	ctx := context.Background()
	p := newPurchaseFixture(ctx, t)
	p.pastSVH(ctx, t)
	p.fund(ctx, t, true, 1e8)
	voting := lockedVotingAccount(ctx, t, p.w)
	n := publishNetwork{publish: func(*wire.MsgTx) {}}
	p.w.SetNetworkBackend(n)

	resp, err := p.w.PurchaseTickets(ctx, n, &PurchaseTicketsRequest{
		Count:         1,
		MinConf:       0,
		VotingAccount: voting,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.TicketHashes) != 1 {
		t.Fatalf("%d tickets, want 1", len(resp.TicketHashes))
	}
}

// TestPurchaseTicketsCountDownFeeOutputs checks the retry that buys one
// ticket less after the split finds the balance short: the published split
// has a fee output per ticket bought, ticket i's fee tx spends fee output i,
// and no fee output is left locked.
func TestPurchaseTicketsCountDownFeeOutputs(t *testing.T) {
	ctx := context.Background()
	p := newPurchaseFixture(ctx, t)
	p.pastSVH(ctx, t)
	_, needed, quote := p.setQuote(ctx, t)
	perTicket := needed + p.feeOutput(quote)
	// Two and a half tickets' worth: three do not fit, two do.
	p.fund(ctx, t, true, perTicket*5/4, perTicket*5/4)
	p.setQuote(ctx, t)

	published := make(map[chainhash.Hash]bool)
	n := publishNetwork{publish: func(tx *wire.MsgTx) { published[tx.TxHash()] = true }}
	p.w.SetNetworkBackend(n)

	resp, err := p.w.PurchaseTickets(ctx, n, &PurchaseTicketsRequest{
		Count:     3,
		MinConf:   0,
		VSPClient: p.c,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Tickets) != 2 {
		t.Fatalf("%d tickets, want 2: one less than requested", len(resp.Tickets))
	}
	splitHash := resp.SplitTx.TxHash()
	if !published[splitHash] {
		t.Fatal("returned split not published")
	}
	ticketOuts, feeOuts := splitOutputs(t, resp)
	if len(feeOuts) != len(resp.Tickets) {
		t.Fatalf("split has %d fee outputs, want %d", len(feeOuts), len(resp.Tickets))
	}
	ticketIdx := slices.Sorted(maps.Keys(ticketOuts))
	feeIdx := sortedIndexes(feeOuts)
	for i, ticket := range resp.Tickets {
		if got := ticket.TxIn[0].PreviousOutPoint.Index; got != ticketIdx[i] {
			t.Errorf("ticket %d spends split output %d, want %d", i, got, ticketIdx[i])
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	paid := p.feeTxs(t)
	if len(paid) != len(resp.Tickets) {
		t.Fatalf("fees paid for %d tickets, want %d", len(paid), len(resp.Tickets))
	}
	for i, hash := range resp.TicketHashes {
		tx := paid[hash.String()]
		if tx == nil {
			t.Errorf("ticket %d fee not paid", i)
			continue
		}
		checkFeeTx(t, p.w, tx, p.quote, p.feeAddr)
		want := wire.OutPoint{Hash: splitHash, Index: feeIdx[i]}
		if len(tx.TxIn) != 1 || tx.TxIn[0].PreviousOutPoint != want {
			t.Errorf("ticket %d fee tx spends %d inputs, want fee output %d alone",
				i, len(tx.TxIn), feeIdx[i])
		}
	}
	if locked := lockedNow(p.w); len(locked) != 0 {
		t.Errorf("outpoints left locked: %v", locked)
	}
}

var errPublish = errors.New("publish failed")

// failPublishNetwork fails each publish of a tx that fail reports.
type failPublishNetwork struct {
	mockNetwork
	fail func(*wire.MsgTx) bool
}

func (n failPublishNetwork) PublishTransactions(_ context.Context, txs ...*wire.MsgTx) error {
	for _, tx := range txs {
		if n.fail(tx) {
			return errPublish
		}
	}
	return nil
}

// TestPurchaseTicketsSplitPublishFails checks that a split that fails to
// publish leaves no outpoint locked: not its fee outputs, which were locked
// before it was recorded, nor its inputs.
func TestPurchaseTicketsSplitPublishFails(t *testing.T) {
	ctx := context.Background()
	p := newPurchaseFixture(ctx, t)
	p.pastSVH(ctx, t)
	p.fund(ctx, t, true, 1e8)
	p.fund(ctx, t, true, 1e8)
	p.setQuote(ctx, t)

	var splitHash chainhash.Hash
	var lockedAtPublish map[outpoint]struct{}
	n := failPublishNetwork{fail: func(tx *wire.MsgTx) bool {
		if lockedAtPublish == nil {
			splitHash = tx.TxHash()
			lockedAtPublish = lockedNow(p.w)
		}
		return true
	}}
	p.w.SetNetworkBackend(n)

	const count = 2
	_, err := p.w.PurchaseTickets(ctx, n, &PurchaseTicketsRequest{
		Count:     count,
		MinConf:   0,
		VSPClient: p.c,
	})
	if !errors.Is(err, errPublish) {
		t.Fatalf("error %v, want %v", err, errPublish)
	}
	var feeLocked int
	for op := range lockedAtPublish {
		if op.hash == splitHash {
			feeLocked++
		}
	}
	if feeLocked != count {
		t.Fatalf("%d split outputs locked at publish, want the %d fee outputs", feeLocked, count)
	}
	if locked := lockedNow(p.w); len(locked) != 0 {
		t.Errorf("outpoints left locked: %v", locked)
	}
}

// TestPurchaseTicketsSecondFeeFails checks a purchase whose VSP fails the fee
// of its second ticket: the first fee is paid from the first fee output, and
// the second fee output is unlocked.
func TestPurchaseTicketsSecondFeeFails(t *testing.T) {
	ctx := context.Background()
	p := newPurchaseFixture(ctx, t)
	p.pastSVH(ctx, t)
	p.fund(ctx, t, true, 1e8)
	p.fund(ctx, t, true, 1e8)
	_, _, quote := p.setQuote(ctx, t)
	p.mu.Lock()
	p.failTicket = 2
	p.mu.Unlock()

	resp, err := p.w.PurchaseTickets(ctx, mockNetwork{}, &PurchaseTicketsRequest{
		Count:     2,
		MinConf:   0,
		VSPClient: p.c,
	})
	// The returned error is ErrVSPFeeNotPaid, which
	// TestPurchaseTicketsFeeErrorNamesTicket checks, so only the response is
	// checked here.
	if resp == nil || len(resp.TicketHashes) != 2 {
		t.Fatalf("response %v, %v, want 2 ticket hashes", resp, err)
	}
	_, feeOuts := splitOutputs(t, resp)
	if len(feeOuts) != 2 {
		t.Fatalf("split has %d fee outputs, want 2", len(feeOuts))
	}
	splitHash := resp.SplitTx.TxHash()
	feeIdx := sortedIndexes(feeOuts)

	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.feeTickets) != 2 {
		t.Errorf("fee addresses asked for %d tickets, want 2", len(p.feeTickets))
	}
	paid := p.feeTxs(t)
	tx := paid[resp.TicketHashes[0].String()]
	if len(paid) != 1 || tx == nil {
		t.Fatalf("fees paid for tickets %v, want the first ticket %v alone",
			slices.Collect(maps.Keys(paid)), resp.TicketHashes[0])
	}
	checkFeeTx(t, p.w, tx, quote, p.feeAddr)
	want := wire.OutPoint{Hash: splitHash, Index: feeIdx[0]}
	if len(tx.TxIn) != 1 || tx.TxIn[0].PreviousOutPoint != want {
		t.Errorf("first fee tx spends %d inputs, want fee output %d alone", len(tx.TxIn), feeIdx[0])
	}
	locked := lockedNow(p.w)
	if _, ok := locked[outpoint{splitHash, feeIdx[1]}]; ok {
		t.Errorf("second fee output %d left locked", feeIdx[1])
	}
	if len(locked) != 0 {
		t.Errorf("outpoints left locked: %v", locked)
	}
}

// TestPurchaseTicketsLocksFeeOutputsBeforeRecord checks that the split's fee
// outputs are locked when the split is recorded, which makes them spendable
// credits.  Recording it notifies each transaction client in turn while the
// wallet holds lockedOutpointMu.  Between the sends to the first and the
// second client the wallet is blocked and no one else can take the mutex, so
// the locked outpoints are read there without it.
func TestPurchaseTicketsLocksFeeOutputsBeforeRecord(t *testing.T) {
	ctx := context.Background()
	p := newPurchaseFixture(ctx, t)
	p.pastSVH(ctx, t)
	p.fund(ctx, t, true, 1e8)
	p.fund(ctx, t, true, 1e8)
	p.setQuote(ctx, t)

	type recorded struct {
		hash   chainhash.Hash
		locked map[outpoint]struct{}
	}
	atRecord := make(chan recorded, 1)
	first := p.w.NtfnServer.TransactionNotifications()
	second := p.w.NtfnServer.TransactionNotifications()
	go func() {
		read := false
		for n := range first.C {
			// Only the first notification, the split's, is known to be
			// sent under the mutex.
			if !read {
				read = true
				var r recorded
				if len(n.UnminedTransactions) != 0 {
					r.hash = *n.UnminedTransactions[0].Hash
				}
				r.locked = maps.Clone(p.w.lockedOutpoints)
				atRecord <- r
			}
			<-second.C
		}
	}()
	resp, err := p.w.PurchaseTickets(ctx, mockNetwork{}, &PurchaseTicketsRequest{
		Count:     2,
		MinConf:   0,
		VSPClient: p.c,
	})
	first.Done()
	second.Done()
	if err != nil {
		t.Fatal(err)
	}
	var r recorded
	select {
	case r = <-atRecord:
	default:
		t.Fatal("no tx notified")
	}
	if r.hash != resp.SplitTx.TxHash() {
		t.Fatalf("first tx notified is %v, want the split %v", r.hash, resp.SplitTx.TxHash())
	}
	_, feeOuts := splitOutputs(t, resp)
	if len(feeOuts) != 2 {
		t.Fatalf("split has %d fee outputs, want 2", len(feeOuts))
	}
	for op := range feeOuts {
		if _, ok := r.locked[op]; !ok {
			t.Errorf("fee output %d not locked when the split is recorded", op.index)
		}
	}
}

// TestPurchaseTicketsFeePrepSplitNotDust checks the split PurchaseTickets
// publishes to give a mixed purchase's VSP fee its own output: the wallet's
// estimate and two fees of that split, sized with its change output, and at
// least the dust threshold, which a node enforces.  Below SVH the estimate is
// 0 and the two fees are above the threshold.  At 50 atoms/kB the two fees
// alone are dust, so the output is the dust threshold; a node run with a
// minimum relay fee that low enforces it.  Past SVH the estimate is above 0.
func TestPurchaseTicketsFeePrepSplitNotDust(t *testing.T) {
	for _, relayFee := range []dcrutil.Amount{0, 50} {
		t.Run(fmt.Sprintf("relay fee %d", relayFee), func(t *testing.T) {
			testPurchaseTicketsFeePrepSplitNotDust(t, relayFee, false)
		})
	}
	t.Run("past SVH", func(t *testing.T) {
		testPurchaseTicketsFeePrepSplitNotDust(t, 0, true)
	})
}

func testPurchaseTicketsFeePrepSplitNotDust(t *testing.T, relayFee dcrutil.Amount, pastSVH bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p := newPurchaseFixture(ctx, t)
	if relayFee != 0 {
		p.setRelayFee(t, relayFee)
	}
	if pastSVH {
		p.pastSVH(ctx, t)
	}
	p.fund(ctx, t, true, 1e8)
	p.setQuote(ctx, t)
	var prep *wire.MsgTx
	n := publishNetwork{publish: func(tx *wire.MsgTx) {
		if prep == nil {
			prep = tx
			cancel() // the mixed retry that follows cannot run without peers
		}
	}}
	p.w.SetNetworkBackend(n)

	_, err := p.w.PurchaseTickets(ctx, n, &PurchaseTicketsRequest{
		Count:        1,
		MinConf:      0,
		VSPClient:    p.c,
		Mixing:       true,
		MixedAccount: 1,
	})
	if prep == nil {
		t.Fatalf("no fee split published (PurchaseTickets: %v)", err)
	}
	if len(prep.TxOut) != 2 {
		t.Fatalf("fee split has %d outputs, want the fee output and change", len(prep.TxOut))
	}
	checkNoDust(t, prep, p.w.RelayFee())
	// The output is the estimate and two fees of a one-input, one-output
	// split, or the threshold at the wallet's relay fee where that is more.
	relay := p.w.RelayFee()
	price, err := p.w.NextStakeDifficulty(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, height := p.w.MainChainTip(ctx)
	estimate := txrules.StakePoolTicketFee(price, relay, height, purchaseVSPFeePercent,
		p.w.chainParams, true, true)
	if pastSVH != (estimate > 0) {
		t.Fatalf("test setup: estimate %v at height %d", estimate, height)
	}
	size := txsizes.EstimateSerializeSize([]int{txsizes.RedeemP2PKHInputSize},
		[]*wire.TxOut{{PkScript: make([]byte, txsizes.P2PKHPkScriptSize)}}, txsizes.P2PKHPkScriptSize)
	want := max(estimate+2*txrules.FeeForSerializeSize(relay, size),
		txrules.DustThreshold(txsizes.P2PKHPkScriptSize, relay))
	if a, b := prep.TxOut[0].Value, prep.TxOut[1].Value; min(a, b) != int64(want) {
		t.Errorf("fee split outputs %d and %d atoms, want the fee output at %d", a, b, int64(want))
	}
}

// TestPurchaseTicketsMixedFeeReservation checks that a mixed purchase reserves
// one output for the VSP fee when one covers it: of two outputs worth the
// ticket price each, one is reserved for the fee and the split, funded from
// the other alone, finds the balance short.  The wallet's quote is 0 at this
// height, so an amount without the miner fee would reserve both outputs and
// ask for an extra split instead.
func TestPurchaseTicketsMixedFeeReservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p := newPurchaseFixture(ctx, t)
	price, _, _ := p.setQuote(ctx, t)
	p.fund(ctx, t, true, price, price)
	p.setQuote(ctx, t)
	unmined := unminedTxs(ctx, t, p.w)

	_, err := p.w.purchaseTickets(ctx, "test", mockNetwork{}, &PurchaseTicketsRequest{
		Count:     1,
		MinConf:   0,
		VSPClient: p.c,
		Mixing:    true,
	})
	if !errors.Is(err, errors.InsufficientBalance) || errors.Is(err, errVSPFeeRequiresUTXOSplit) {
		t.Errorf("error %v, want %v from the split", err, errors.InsufficientBalance)
	}
	if n := unminedTxs(ctx, t, p.w) - unmined; n != 0 {
		t.Errorf("%d txs published, want none", n)
	}
	if locked := lockedNow(p.w); len(locked) != 0 {
		t.Errorf("outpoints left locked: %v", locked)
	}
}

// TestPurchaseTicketsSplitRepublishFails checks a split that individualSplit
// published but purchaseTickets then fails to publish again: no fee output
// is left locked.
func TestPurchaseTicketsSplitRepublishFails(t *testing.T) {
	ctx := context.Background()
	p := newPurchaseFixture(ctx, t)
	p.pastSVH(ctx, t)
	p.fund(ctx, t, true, 1e8)
	p.fund(ctx, t, true, 1e8)
	p.setQuote(ctx, t)

	var splitHash *chainhash.Hash
	var publishes int
	n := failPublishNetwork{fail: func(tx *wire.MsgTx) bool {
		hash := tx.TxHash()
		if splitHash == nil {
			splitHash = &hash
		}
		if hash != *splitHash {
			return false
		}
		publishes++
		return publishes == 2
	}}
	p.w.SetNetworkBackend(n)

	_, err := p.w.PurchaseTickets(ctx, n, &PurchaseTicketsRequest{
		Count:     2,
		MinConf:   0,
		VSPClient: p.c,
	})
	if !errors.Is(err, errPublish) {
		t.Fatalf("error %v, want %v", err, errPublish)
	}
	if publishes != 2 {
		t.Fatalf("split published %d times, want 2", publishes)
	}
	if locked := lockedNow(p.w); len(locked) != 0 {
		t.Errorf("outpoints left locked: %v", locked)
	}
}

// TestPurchaseTicketsTicketFails checks a purchase that publishes its split
// and then fails to make a ticket: no fee output is left locked.
func TestPurchaseTicketsTicketFails(t *testing.T) {
	setup := func(ctx context.Context, t *testing.T) *purchaseFixture {
		p := newPurchaseFixture(ctx, t)
		p.pastSVH(ctx, t)
		p.fund(ctx, t, true, 1e8)
		p.fund(ctx, t, true, 1e8)
		p.setQuote(ctx, t)
		return p
	}
	check := func(t *testing.T, p *purchaseFixture, resp *PurchaseTicketsResponse, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("purchase succeeded")
		}
		if resp == nil || resp.SplitTx == nil {
			t.Fatalf("no split returned: %v", err)
		}
		if locked := lockedNow(p.w); len(locked) != 0 {
			t.Errorf("outpoints left locked: %v", locked)
		}
	}

	t.Run("wallet locked before signing", func(t *testing.T) {
		ctx := context.Background()
		p := setup(ctx, t)
		var splitHash *chainhash.Hash
		var publishes int
		n := publishNetwork{publish: func(tx *wire.MsgTx) {
			hash := tx.TxHash()
			if splitHash == nil {
				splitHash = &hash
			}
			if hash != *splitHash {
				return
			}
			// Lock after purchaseTickets publishes the split, so the
			// first ticket fails to sign inside its record.
			if publishes++; publishes == 2 {
				if err := p.w.Lock(); err != nil {
					t.Error(err)
				}
			}
		}}
		p.w.SetNetworkBackend(n)
		resp, err := p.w.PurchaseTickets(ctx, n, &PurchaseTicketsRequest{
			Count:     2,
			MinConf:   0,
			VSPClient: p.c,
		})
		if !errors.Is(err, errors.Locked) {
			t.Errorf("error %v, want %v", err, errors.Locked)
		}
		check(t, p, resp, err)
	})
}
