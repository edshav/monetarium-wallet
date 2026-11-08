// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/blockchain/stake"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
)

// TestVSPProcessDropsCallerFeeTxOnFailure checks that when Process cannot get
// the fee address or make the fee tx, it returns the error and does not leave
// the purchase's fee tx for the scheduled attempt: the purchase unlocks those
// inputs once Process fails and may spend them, and a failed fee tx may have
// outputs but no signatures.  A fee tx the scheduled attempt made meanwhile
// stays.
func TestVSPProcessDropsCallerFeeTxOnFailure(t *testing.T) {
	tests := []struct {
		name       string
		feeAddress bool // the VSP quotes a fee
		// meanwhile, if set, runs as a scheduled attempt would while
		// Process waits for the fee address.
		meanwhile func(fp *vspFeePayment)
	}{
		{name: "fee address fails"},
		{name: "fee tx fails", feeAddress: true},
		{name: "scheduled attempt replaced the tx", meanwhile: func(fp *vspFeePayment) {
			fp.feeTx = wire.NewMsgTx()
		}},
		{name: "scheduled attempt made its tx in place", meanwhile: func(fp *vspFeePayment) {
			fp.feeHash = chainhash.Hash{0xfe}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var c *VSPClient
			var ticket *VSPTicket
			var want *wire.MsgTx // fp.feeTx after Process; under fp.mu
			c = testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				if tc.meanwhile != nil && path == "/api/v3/feeaddress" {
					c.mu.Lock()
					fp := c.jobs[*ticket.Hash()]
					c.mu.Unlock()
					fp.mu.Lock()
					tc.meanwhile(fp)
					want = fp.feeTx
					fp.mu.Unlock()
				}
				if !tc.feeAddress || path != "/api/v3/feeaddress" {
					return apiError(types.ErrInternalError)
				}
				return http.StatusOK, types.FeeAddressResponse{
					Timestamp:  time.Now().Unix(),
					FeeAddress: ticket.votingAddr.String(),
					FeeAmount:  1e7,
					Expiration: time.Now().Add(time.Hour).Unix(),
					Request:    body,
				}
			})
			ticket = testVSPTicket(ctx, t, c, 1)
			// The wallet does not know this input, so signing the fee
			// tx fails after its outputs were written.
			purchaseTx := wire.NewMsgTx()
			purchaseTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{0xca}}, 1e8, nil))

			err := c.Process(ctx, ticket, purchaseTx)
			var apiErr types.ErrorResponse
			var walletErr *errors.Error
			switch {
			case tc.feeAddress:
				if !errors.As(err, &walletErr) || walletErr.Op != "wallet.SignTransaction" {
					t.Fatalf("Process: want the signing error, got %v", err)
				}
				if len(purchaseTx.TxOut) == 0 {
					t.Fatal("test setup: the fee tx failed before its outputs were written")
				}
			case !errors.As(err, &apiErr) || apiErr.Code != types.ErrInternalError:
				t.Fatalf("Process: want the fee address error, got %v", err)
			}
			c.mu.Lock()
			fp := c.jobs[*ticket.Hash()]
			c.mu.Unlock()
			if fp == nil {
				t.Fatal("Process did not register the payment")
			}
			fp.stop()
			fp.mu.Lock()
			defer fp.mu.Unlock()
			if fp.feeTx != want {
				t.Fatalf("scheduled attempt's fee tx: got %p, want %p (purchase's %p)", fp.feeTx, want, purchaseTx)
			}
			// A fee tx kept in place is the scheduled attempt's, and so
			// is its recorded status; this fake records none.
			info, err := ticket.VSPTicketInfo(ctx)
			errored := err == nil && udb.FeeStatus(info.FeeTxStatus) == udb.VSPFeeProcessErrored
			if wantErrored := want != purchaseTx; errored != wantErrored {
				t.Fatalf("ticket marked errored: %v, want %v (info %+v, err %v)", errored, wantErrored, info, err)
			}
		})
	}
}

// recordingNetwork is a mockNetwork that records the txs it publishes and
// passes each to onPublish, if set.
type recordingNetwork struct {
	mockNetwork
	published []*wire.MsgTx
	onPublish func(*wire.MsgTx)
}

func (n *recordingNetwork) PublishTransactions(_ context.Context, txs ...*wire.MsgTx) error {
	for _, tx := range txs {
		n.published = append(n.published, tx)
		if n.onPublish != nil {
			n.onPublish(tx)
		}
	}
	return nil
}

// vspInfoOr answers vspinfo, and every other request with reply.
func vspInfoOr(reply func(path string, body []byte) (int, any)) func(string, []byte) (int, any) {
	return func(path string, body []byte) (int, any) {
		if path == "/api/v3/vspinfo" {
			return http.StatusOK, types.VspInfoResponse{Timestamp: time.Now().Unix(), FeePercentage: 1}
		}
		return reply(path, body)
	}
}

// purchaseWithVSP funds the client's wallet with two outputs mined in block
// one and buys one ticket through c, publishing over n.
func purchaseWithVSP(ctx context.Context, t *testing.T, c *VSPClient, n *recordingNetwork) (*PurchaseTicketsResponse, error) {
	t.Helper()
	w := c.wallet
	w.SetNetworkBackend(n)

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
	blockOne := maketg(t, w.chainParams).createBlockOne("block-one")
	_, err = w.ChainSwitch(ctx, new(SidechainForest), []*BlockNode{blockOne.BlockNode},
		map[chainhash.Hash][]*wire.MsgTx{*blockOne.Hash: {fund}})
	if err != nil {
		t.Fatal(err)
	}

	return w.PurchaseTickets(ctx, n, &PurchaseTicketsRequest{
		Count: 1,
		// MinConf 0 skips the random UTXO pick, which can come back empty
		// with several eligible outputs (a separate bug).
		MinConf:   0,
		VSPClient: c,
	})
}

// checkPurchase checks that resp holds one ticket hash, that the ticket was
// published, and that no outputs stay locked.
func checkPurchase(ctx context.Context, t *testing.T, w *Wallet, n *recordingNetwork, resp *PurchaseTicketsResponse) {
	t.Helper()
	if resp == nil || len(resp.TicketHashes) != 1 {
		t.Fatalf("PurchaseTickets response: got %+v, want 1 ticket hash", resp)
	}
	var tickets []chainhash.Hash
	for _, tx := range n.published {
		if stake.IsSStx(tx) {
			tickets = append(tickets, tx.TxHash())
		}
	}
	if len(tickets) != 1 || tickets[0] != *resp.TicketHashes[0] {
		t.Fatalf("published tickets %v, want %v", tickets, resp.TicketHashes[0])
	}
	locked, err := w.LockedOutpoints(ctx, "*")
	if err != nil {
		t.Fatal(err)
	}
	if len(locked) != 0 {
		t.Errorf("%d outputs still locked: %v", len(locked), locked)
	}
}

// TestPurchaseTicketsFeeFailureKeepsHashes checks that when the VSP fee step
// fails after the tickets are published, the caller still gets the ticket
// hash, and an error that says the fees were not paid.  The outputs reserved
// for the unpaid fee are released.
func TestPurchaseTicketsFeeFailureKeepsHashes(t *testing.T) {
	ctx := context.Background()
	c := testVSPClient(ctx, t, vspInfoOr(func(string, []byte) (int, any) {
		return apiError(types.ErrInternalError)
	}))
	n := new(recordingNetwork)
	resp, err := purchaseWithVSP(ctx, t, c, n)
	if !errors.Is(err, ErrVSPFeeNotPaid) {
		t.Errorf("PurchaseTickets error: got %v, want ErrVSPFeeNotPaid", err)
	}
	checkPurchase(ctx, t, c.wallet, n, resp)
}

// TestPurchaseTicketsVSPTicketFailureKeepsHashes checks the same when the
// VSP ticket record cannot be made after publishing: here the wallet is
// locked once the ticket is published, so its voting key cannot be read.
func TestPurchaseTicketsVSPTicketFailureKeepsHashes(t *testing.T) {
	ctx := context.Background()
	c := testVSPClient(ctx, t, vspInfoOr(func(string, []byte) (int, any) {
		return apiError(types.ErrInternalError)
	}))
	n := &recordingNetwork{onPublish: func(tx *wire.MsgTx) {
		if stake.IsSStx(tx) {
			c.wallet.Lock()
		}
	}}
	resp, err := purchaseWithVSP(ctx, t, c, n)
	if !errors.Is(err, ErrVSPFeeNotPaid) || !errors.Is(err, errors.Locked) {
		t.Errorf("PurchaseTickets error: got %v, want ErrVSPFeeNotPaid and Locked", err)
	}
	checkPurchase(ctx, t, c.wallet, n, resp)
}

// TestPurchaseTicketsFeePaid checks that a purchase whose VSP fee is paid
// returns the ticket hash and no error.
func TestPurchaseTicketsFeePaid(t *testing.T) {
	ctx := context.Background()
	var feeAddr string
	var payFee atomic.Bool
	c := testVSPClient(ctx, t, vspInfoOr(func(path string, body []byte) (int, any) {
		switch path {
		case "/api/v3/feeaddress":
			return http.StatusOK, types.FeeAddressResponse{
				Timestamp:  time.Now().Unix(),
				FeeAddress: feeAddr,
				FeeAmount:  1000, // below the output the purchase reserved
				Expiration: time.Now().Add(time.Hour).Unix(),
				Request:    body,
			}
		case "/api/v3/payfee":
			payFee.Store(true)
			return http.StatusOK, types.PayFeeResponse{Timestamp: time.Now().Unix(), Request: body}
		}
		return apiError(types.ErrInternalError)
	}))
	addr, err := c.wallet.NewExternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	feeAddr = addr.String()
	n := new(recordingNetwork)
	resp, err := purchaseWithVSP(ctx, t, c, n)
	if err != nil {
		t.Errorf("PurchaseTickets error: %v", err)
	}
	if !payFee.Load() {
		t.Error("the fee was not paid")
	}
	checkPurchase(ctx, t, c.wallet, n, resp)
}
