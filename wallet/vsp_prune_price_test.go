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

	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/blockchain/stake"
	blockchain "github.com/monetarium/monetarium-node/blockchain/standalone"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/gcs/blockcf2"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// TestVSPTicketPriceAfterReorg connects, at the last block of a ticket price
// window, a sibling of the tip, as a one-block reorg does.  An unmined VSP
// ticket at the next block's price, as the ticket buyer buys there, or at the
// tip's price can still be mined, so it stays, with its unpublished fee tx
// and its fee job.  One at neither price is pruned, and its fee tx is
// abandoned, by the block's pass and by the job.  A two-block reorg prices the
// ticket by the new tip, not by the first block attached or the old tip: a
// sibling that buys tickets has another next price, and a ticket at the old
// one is pruned.  When the next block's price is unknown, no ticket is pruned
// for its price.
func TestVSPTicketPriceAfterReorg(t *testing.T) {
	// The ticket's price is 1e8.  With the pool size the same at both
	// ends of the window, the next price is half the tip's.
	for _, tc := range []struct {
		name     string
		tipPrice int64
		depth    int    // blocks replaced; 0 is 1
		fresh    uint8  // tickets bought in the new tip
		unknown  string // why the next block's price cannot be computed
		wantKept bool
	}{
		{name: "next block's price", tipPrice: 2e8, wantKept: true},
		{name: "next block's price, two-block reorg", tipPrice: 2e8, depth: 2, wantKept: true},
		{name: "tip's price", tipPrice: 1e8, wantKept: true},
		{name: "neither price", tipPrice: 4e8},
		{name: "neither price, two-block reorg", tipPrice: 4e8, depth: 2},
		{name: "old tip's next price", tipPrice: 2e8, fresh: 20},
		{name: "next price unknown, DCP0001 not active", tipPrice: 4e8, unknown: "deployment", wantKept: true},
		{name: "next price unknown, header read fails", tipPrice: 4e8, unknown: "store", wantKept: true},
	} {
		for _, job := range []bool{false, true} {
			name := tc.name
			if job {
				name += ", fee job"
			}
			t.Run(name, func(t *testing.T) {
				testVSPTicketPriceAfterReorg(t, tc.tipPrice, max(tc.depth, 1), tc.fresh, tc.unknown, job, tc.wantKept)
			})
		}
	}
}

func testVSPTicketPriceAfterReorg(t *testing.T, tipPrice int64, depth int, fresh uint8, unknown string, job, wantKept bool) {
	ctx := context.Background()
	var feeHash chainhash.Hash
	c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
		if strings.HasSuffix(path, "/api/v3/ticketstatus") {
			return http.StatusOK, types.TicketStatusResponse{
				FeeTxStatus: "received",
				FeeTxHash:   feeHash.String(),
				Request:     body,
			}
		}
		t.Errorf("unexpected VSP request %s", path)
		return apiError(types.ErrInternalError)
	})
	w := c.wallet
	f := &vspPaymentFixture{w: w, cfg: basicWalletConfig,
		tip: basicWalletConfig.Params.GenesisBlock.Header, sbits: tipPrice, poolSize: 200}
	window := int(w.chainParams.StakeDiffWindowSize)
	f.mineEmpty(ctx, t, 3*window-2)
	// The rescan has recorded every block.
	err := walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
		tip, _ := w.txStore.MainChainTip(dbtx)
		return w.txStore.UpdateProcessedTxsBlockMarker(dbtx, &tip)
	})
	if err != nil {
		t.Fatal(err)
	}
	f.mine(ctx, t)
	if next := int64(f.tip.Height) + 1; next%int64(window) != 0 {
		t.Fatalf("tip height %d is not the last of a price window", f.tip.Height)
	}
	next, err := w.NextStakeDifficultyAfterHeader(ctx, &f.tip)
	if err != nil {
		t.Fatal(err)
	}
	if int64(next) != tipPrice/2 {
		t.Fatalf("next ticket price %v, want %v", next, tipPrice/2)
	}

	op := testWalletOutput(ctx, t, w, 2)
	ticket := testVSPTicket(ctx, t, c, 1)
	if price := ticket.rawTx.TxOut[0].Value; !stake.IsSStx(ticket.rawTx) || price != 1e8 {
		t.Fatalf("ticket price %v", price)
	}
	fee := wire.NewMsgTx()
	fee.AddTxIn(wire.NewTxIn(op, 1e8, nil))
	if err := w.CreateVspPayment(ctx, fee, 1e7, ticket.votingAddr, 0, 0); err != nil {
		t.Fatal(err)
	}
	feeHash = fee.TxHash()
	if err := ticket.UpdateFeePaid(ctx, feeHash, c.URL, c.PubKey); err != nil {
		t.Fatal(err)
	}
	var fp *vspFeePayment
	if job {
		// The job a restart makes from the record.
		fp = c.feePayment(ctx, ticket, true)
		if fp == nil {
			t.Fatal("no job for the ticket")
		}
		fp.stop()
	}

	// Siblings of the last depth blocks, up to the window's last height,
	// each with more work.
	replaced := []wire.BlockHeader{f.tip}
	for len(replaced) < depth {
		parent, err := w.BlockHeader(ctx, &replaced[0].PrevBlock)
		if err != nil {
			t.Fatal(err)
		}
		replaced = append([]wire.BlockHeader{*parent}, replaced...)
	}
	relevant := make(map[chainhash.Hash][]*wire.MsgTx)
	var hash chainhash.Hash
	for i, sibling := range replaced {
		if i > 0 {
			sibling.PrevBlock = hash
		}
		sibling.Bits = blockchain.BigToCompact(new(big.Int).Rsh(f.cfg.Params.PowLimit, 1))
		if i == len(replaced)-1 && fresh != 0 {
			sibling.FreshStake = fresh
			next, err := w.NextStakeDifficultyAfterHeader(ctx, &sibling)
			if err != nil {
				t.Fatal(err)
			}
			if int64(next) == tipPrice/2 || int64(next) == tipPrice {
				t.Fatalf("next ticket price after the new tip %v, want another", next)
			}
		}
		filter, err := blockcf2.Regular(&wire.MsgBlock{Header: sibling}, nil)
		if err != nil {
			t.Fatal(err)
		}
		h := sibling.BlockHash()
		if !f.forest.AddBlockNode(NewBlockNode(&sibling, &h, filter)) {
			t.Fatal("sibling not added to the sidechain forest")
		}
		hash = h
		relevant[hash] = nil
	}
	best, err := w.EvaluateBestChain(ctx, &f.forest)
	if err != nil {
		t.Fatal(err)
	}
	if len(best) != depth || *best[depth-1].Hash != hash {
		t.Fatalf("best chain %v, want the siblings", best)
	}
	if unknown == "store" {
		// A damaged store: the header at the previous retarget height, which
		// the next price reads, is gone ("h" is udb's header bucket).
		err := walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
			ns := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)
			gone, err := w.txStore.GetMainChainBlockHashForHeight(ns, int32(f.tip.Height)-int32(window))
			if err != nil {
				return err
			}
			return ns.NestedReadWriteBucket([]byte("h")).Delete(gone[:])
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	params := w.chainParams
	if unknown == "deployment" {
		// A network where DCP0001 is not active at this height.
		p := *params
		p.Net = 0x48e7a065 // testnet2
		w.chainParams = &p
	}
	_, err = w.ChainSwitch(ctx, &f.forest, best, relevant)
	w.chainParams = params
	if err != nil {
		t.Fatal(err)
	}
	if tip, _ := w.MainChainTip(ctx); tip != hash {
		t.Fatalf("tip %v, want the last sibling %v", tip, hash)
	}

	if gone := ticket.Pruned(ctx); gone == wantKept {
		t.Errorf("ticket pruned = %v, want %v", gone, !wantKept)
	}
	if job {
		err := fp.confirmPayment()
		fp.stop()
		if stopped := err != nil; stopped == wantKept {
			t.Errorf("job's attempt: %v; want stopped %v", err, !wantKept)
		}
		if listed := testJob(c, ticket) == fp; listed != wantKept {
			t.Errorf("job listed = %v, want %v", listed, wantKept)
		}
	}
	if held := testHoldsUnmined(ctx, t, w, feeHash); held != wantKept {
		t.Errorf("wallet holds the fee tx = %v, want %v", held, wantKept)
	}
	if unspent := testUnspentOutputs(ctx, t, w)[*op]; unspent == wantKept {
		t.Errorf("fee tx input unspent = %v, want %v", unspent, !wantKept)
	}
	info, err := ticket.VSPTicketInfo(ctx)
	if err != nil || info.FeeHash != feeHash {
		t.Fatalf("the ticket's VSP record: %+v, %v", info, err)
	}
}
