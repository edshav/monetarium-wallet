// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package rpcserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/mixing"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	vsptypes "github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/blockchain/stake"
	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/gcs/blockcf2"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/internal/loader"
	pb "github.com/monetarium/monetarium-wallet/rpc/walletrpc"
	"github.com/monetarium/monetarium-wallet/wallet"
)

// ticketNetwork records the txs it publishes.  The methods neither a ticket
// purchase nor address watching call are left to the nil embedded backend,
// and panic.
var _ wallet.NetworkBackend = (*ticketNetwork)(nil)

type ticketNetwork struct {
	published []*wire.MsgTx
	ticketErr error // returned instead of publishing a ticket, when set
}

func (n *ticketNetwork) PublishTransactions(_ context.Context, txs ...*wire.MsgTx) error {
	for _, tx := range txs {
		if n.ticketErr != nil && stake.IsSStx(tx) {
			return n.ticketErr
		}
	}
	n.published = append(n.published, txs...)
	return nil
}

func (n *ticketNetwork) LoadTxFilter(context.Context, bool, []stdaddr.Address, []wire.OutPoint) error {
	return nil
}

func (n *ticketNetwork) Done() <-chan struct{} { return nil } // never disconnects

func (n *ticketNetwork) GetFeeEstimatesByCoinType(context.Context, uint8) (*wallet.FeeEstimates, error) {
	return nil, errors.E(errors.NoPeers) // use the static relay fee
}

// TestPurchaseTicketsVSPFeeFailureKeepsHashes checks that the gRPC
// PurchaseTickets returns the hash of a published ticket, and no error, when
// the VSP fee step fails after publishing, and still returns the error when a
// ticket fails to publish.
func TestPurchaseTicketsVSPFeeFailureKeepsHashes(t *testing.T) {
	t.Run("fee fails", func(t *testing.T) {
		n := new(ticketNetwork)
		res, err := purchaseTicketsWithFailingVSP(t, n)
		if err != nil {
			t.Fatalf("PurchaseTickets: %v", err)
		}
		var tickets []chainhash.Hash
		for _, tx := range n.published {
			if stake.IsSStx(tx) {
				tickets = append(tickets, tx.TxHash())
			}
		}
		if len(tickets) != 1 || len(res.TicketHashes) != 1 || !bytes.Equal(res.TicketHashes[0], tickets[0][:]) {
			t.Fatalf("PurchaseTickets returned %x, published tickets %v; want one, the same", res.TicketHashes, tickets)
		}
	})
	t.Run("ticket publish fails", func(t *testing.T) {
		publishErr := errors.New("ticket publish refused")
		res, err := purchaseTicketsWithFailingVSP(t, &ticketNetwork{ticketErr: publishErr})
		if !errors.Is(err, publishErr) {
			t.Fatalf("PurchaseTickets returned %x, %v; want the publish error", res.GetTicketHashes(), err)
		}
	})
}

// purchaseTicketsWithFailingVSP buys one ticket through n with a VSP that
// fails every fee request.
func purchaseTicketsWithFailingVSP(t *testing.T, n *ticketNetwork) (*pb.PurchaseTicketsResponse, error) {
	ctx := context.Background()
	params := chaincfg.SimNetParams()
	privPass := []byte("private")
	l := loader.NewLoader(params, filepath.Join(t.TempDir(), "simnet"), false, 20, 0,
		false, 1e5, 1e8, wallet.DefaultAccountGapLimit, false, false, false, 0, nil)
	w, err := l.CreateNewWallet(ctx, []byte(wallet.InsecurePubPassphrase), privPass, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.UnloadWallet() })
	if err := w.Unlock(ctx, privPass, nil); err != nil {
		t.Fatal(err)
	}
	w.SetNetworkBackend(n)

	// A fake VSP that quotes its fee percentage and fails every other
	// request, signing each reply as vspd does.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	vsp := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var resp any = vsptypes.VspInfoResponse{Timestamp: time.Now().Unix(), FeePercentage: 1}
		status := http.StatusOK
		if r.URL.Path != "/api/v3/vspinfo" {
			code := vsptypes.ErrInternalError
			status, resp = code.HTTPStatus(), vsptypes.ErrorResponse{Code: code, Message: code.DefaultMessage()}
		}
		out, _ := json.Marshal(resp)
		rw.Header().Set("VSP-Server-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(priv, out)))
		rw.WriteHeader(status)
		rw.Write(out)
	}))
	t.Cleanup(vsp.Close)

	// Two outputs mined in block one.
	addr, err := w.NewExternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	fund := wire.NewMsgTx()
	fund.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{0xfd}}, 2e8, nil))
	ver, script := addr.PaymentScript()
	for range 2 {
		fund.AddTxOut(&wire.TxOut{Value: 1e8, Version: ver, PkScript: script})
	}
	header := &wire.BlockHeader{PrevBlock: params.GenesisHash, Height: 1, Bits: params.PowLimitBits}
	filter, err := blockcf2.Regular(&wire.MsgBlock{Header: *header}, nil)
	if err != nil {
		t.Fatal(err)
	}
	header.StakeRoot = filter.Hash() // the cfilter commitment, with an empty proof
	hash := header.BlockHash()
	_, err = w.ChainSwitch(ctx, new(wallet.SidechainForest),
		[]*wallet.BlockNode{wallet.NewBlockNode(header, &hash, filter)},
		map[chainhash.Hash][]*wire.MsgTx{hash: {fund}})
	if err != nil {
		t.Fatal(err)
	}

	s := &walletServer{wallet: w}
	// minconf 0 skips the random UTXO pick, which can come back empty with
	// several eligible outputs (a separate bug).
	return s.PurchaseTickets(ctx, &pb.PurchaseTicketsRequest{
		NumTickets:            1,
		RequiredConfirmations: 0,
		VspHost:               vsp.URL,
		VspPubkey:             base64.StdEncoding.EncodeToString(pub),
	})
}

func unexpectedCall(method string) error {
	return errors.New("ticketNetwork: unexpected call to " + method)
}

func (n *ticketNetwork) Blocks(context.Context, []*chainhash.Hash) ([]*wire.MsgBlock, error) {
	return nil, unexpectedCall("Blocks")
}

func (n *ticketNetwork) CFiltersV2(context.Context, []*chainhash.Hash) ([]wallet.FilterProof, error) {
	return nil, unexpectedCall("CFiltersV2")
}

func (n *ticketNetwork) PublishMixMessages(context.Context, ...mixing.Message) error {
	return unexpectedCall("PublishMixMessages")
}

func (n *ticketNetwork) Rescan(context.Context, []chainhash.Hash,
	func(*chainhash.Hash, []*wire.MsgTx) error) error {
	return unexpectedCall("Rescan")
}

func (n *ticketNetwork) StakeDifficulty(context.Context) (dcrutil.Amount, error) {
	return 0, unexpectedCall("StakeDifficulty")
}

// Synced and Done cannot return an error: report not synced and never
// disconnected.
func (n *ticketNetwork) Synced(context.Context) (bool, int32) { return false, 0 }
func (n *ticketNetwork) Err() error                           { return unexpectedCall("Err") }
