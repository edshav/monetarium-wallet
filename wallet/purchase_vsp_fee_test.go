// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"maps"
	"math/big"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/gcs/blockcf2"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet/txrules"
	"github.com/monetarium/monetarium-wallet/wallet/txsizes"
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
// credits, and a concurrent spend could select them.
func TestPurchaseTicketsFundsVSPFeeFromSplit(t *testing.T) {
	t.Run("below SVH", func(t *testing.T) {
		testPurchaseTicketsFundsVSPFeeFromSplit(t, 2, 0, 0)
	})
	// Past StakeValidationHeight the wallet's estimate is above 0, and at a
	// ticket price of 0.1 VAR the fee output is not dust.  1 is the
	// purchaseticket RPC's default minconf.
	t.Run("past SVH, minconf 1", func(t *testing.T) {
		svh := uint32(basicWalletConfig.Params.StakeValidationHeight)
		testPurchaseTicketsFundsVSPFeeFromSplit(t, svh, 1e7, 1)
	})
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
// ticket price sbits, and buys at minConf.  Above minconf 0 selection starts
// with a random walk that can come back empty when the account holds only a
// few outputs; 32 outputs make that negligible.
func testPurchaseTicketsFundsVSPFeeFromSplit(t *testing.T, height uint32, sbits int64, minConf int32) {
	ctx := context.Background()
	p := newPurchaseFixture(ctx, t)
	p.sbits = sbits
	p.mine(ctx, t, height-2)
	for p.tip.Height < height {
		p.fund(ctx, t, true, slices.Repeat([]dcrutil.Amount{1e8}, 16)...)
	}
	_, needed, quote := p.setQuote(ctx, t)
	pastSVH := int64(height) >= basicWalletConfig.Params.StakeValidationHeight
	if pastSVH && quote <= 0 {
		t.Fatalf("wallet's estimate is %v past SVH, want above 0", quote)
	}
	// A dust fee output would make a real node reject the split.
	if pastSVH && txrules.IsDustAmount(quote+2*p.oneInputMinerFee(), txsizes.P2PKHPkScriptSize, p.w.RelayFee()) {
		t.Fatalf("fee output of %v is dust", quote+2*p.oneInputMinerFee())
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
	for op := range feeOuts {
		out := split.TxOut[op.index]
		if want := quote + 2*p.oneInputMinerFee(); dcrutil.Amount(out.Value) != want {
			t.Errorf("fee output %d is %v, want the quote and two one-input miner fees %v",
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
		extra := p.fund(ctx, t, true, quote+2*p.oneInputMinerFee())
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

// TestPurchaseTicketsCountDownFeeOutputs checks the retry that buys one
// ticket less after the split finds the balance short: the published split
// has a fee output per ticket bought, ticket i's fee tx spends fee output i,
// and no fee output is left locked.
func TestPurchaseTicketsCountDownFeeOutputs(t *testing.T) {
	ctx := context.Background()
	p := newPurchaseFixture(ctx, t)
	_, needed, quote := p.setQuote(ctx, t)
	perTicket := needed + quote + 2*p.oneInputMinerFee()
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
	// Whether the failed fee's error is returned is a separate change, so
	// only the response is checked here.
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

	t.Run("no voting address", func(t *testing.T) {
		ctx := context.Background()
		p := setup(ctx, t)
		var split *wire.MsgTx
		n := publishNetwork{publish: func(tx *wire.MsgTx) {
			if split == nil {
				split = tx
			}
		}}
		p.w.SetNetworkBackend(n)
		_, err := p.w.PurchaseTickets(ctx, n, &PurchaseTicketsRequest{
			Count:         2,
			MinConf:       0,
			VSPClient:     p.c,
			VotingAccount: 42, // no such account
		})
		check(t, p, &PurchaseTicketsResponse{SplitTx: split}, err)
	})

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
