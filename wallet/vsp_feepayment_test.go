// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/decred/vspd/types/v3"
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

func managed(c *VSPClient, ticket *VSPTicket) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.jobs[*ticket.Hash()]
	return ok
}

// TestVSPFeeTooHighStopsRetries checks that a fee above the configured maximum
// is not retried every few minutes but marked errored for the next Process
// call.
func TestVSPFeeTooHighStopsRetries(t *testing.T) {
	// The job may start with no fee hash, or keep the hash of an earlier
	// fee tx, as after an expired fee.
	for name, start := range map[string]chainhash.Hash{
		"no fee hash":      {},
		"earlier fee hash": {0xab},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			var ticket *VSPTicket
			c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				if path != "/api/v3/feeaddress" {
					return apiError(types.ErrInternalError)
				}
				return http.StatusOK, types.FeeAddressResponse{
					Timestamp:  time.Now().Unix(),
					FeeAddress: ticket.votingAddr.String(),
					FeeAmount:  2e8, // above the client's 1e8 MaxFee
					Expiration: time.Now().Add(time.Hour).Unix(),
					Request:    body,
				}
			})
			ticket = testVSPTicket(ctx, t, c, 1)
			if err := ticket.UpdateFeeStarted(ctx, start, c.URL, c.PubKey); err != nil {
				t.Fatal(err)
			}
			fp := &vspFeePayment{
				client:  c,
				ctx:     ctx,
				ticket:  ticket,
				feeHash: start,
				policy:  c.policy,
				params:  c.wallet.chainParams,
			}
			c.jobs[*ticket.Hash()] = fp

			if err := fp.reconcilePayment(); !errors.Is(err, errFeeTooHigh) {
				t.Fatalf("reconcilePayment: want errFeeTooHigh, got %v", err)
			}
			if timerSet(fp) {
				t.Fatal("a fee above the maximum was scheduled for another attempt")
			}
			if managed(c, ticket) {
				t.Fatal("a fee above the maximum left the ticket managed by the client")
			}
			if got := feeStatus(ctx, t, ticket); got != udb.VSPFeeProcessErrored {
				t.Fatalf("fee status = %v, want errored", got)
			}
		})
	}
}

// TestVSPFeeTooHighKeepsConcurrentPayment checks that a quote above the maximum
// does not mark errored or remove a payment that a concurrent Process call
// made while the attempt waited for the quote.
func TestVSPFeeTooHighKeepsConcurrentPayment(t *testing.T) {
	ctx := context.Background()
	var ticket *VSPTicket
	var fp *vspFeePayment
	paid := chainhash.Hash{0xfe}
	c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
		if path != "/api/v3/feeaddress" {
			return apiError(types.ErrInternalError)
		}
		// A concurrent Process call makes and records a fee tx.
		fp.mu.Lock()
		fp.feeHash = paid
		fp.mu.Unlock()
		if err := ticket.UpdateFeePaid(ctx, paid, fp.client.URL, fp.client.PubKey); err != nil {
			t.Error(err)
		}
		return http.StatusOK, types.FeeAddressResponse{
			Timestamp:  time.Now().Unix(),
			FeeAddress: ticket.votingAddr.String(),
			FeeAmount:  2e8, // above the client's 1e8 MaxFee
			Expiration: time.Now().Add(time.Hour).Unix(),
			Request:    body,
		}
	})
	ticket = testVSPTicket(ctx, t, c, 1)
	fp = &vspFeePayment{
		client: c,
		ctx:    ctx,
		ticket: ticket,
		policy: c.policy,
		params: c.wallet.chainParams,
	}
	c.jobs[*ticket.Hash()] = fp

	if err := fp.reconcilePayment(); !errors.Is(err, errFeeTooHigh) {
		t.Fatalf("reconcilePayment: want errFeeTooHigh, got %v", err)
	}
	if !managed(c, ticket) {
		t.Fatal("the concurrent payment's job was removed")
	}
	if !timerSet(fp) {
		t.Fatal("the concurrent payment's job has nothing scheduled")
	}
	fp.stop()
	if got := feeStatus(ctx, t, ticket); got != udb.VSPFeeProcessPaid {
		t.Fatalf("fee status = %v, want paid", got)
	}
}

// TestVSPPrunedTicketIsRemoved checks that a ticket the wallet no longer has
// is dropped from the client instead of being retried, with its VSP record
// kept, and that an unmined ticket the wallet still has keeps its job.
func TestVSPPrunedTicketIsRemoved(t *testing.T) {
	ctx := context.Background()
	c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
		return apiError(types.ErrInternalError)
	})
	kept := testVSPTicket(ctx, t, c, 1) // unmined, in the wallet
	// Same ticket data under a hash the wallet does not have.
	h := chainhash.Hash{0xdd}
	pruned := &VSPTicket{
		hash:           &h,
		rawTx:          kept.rawTx,
		parentTx:       kept.parentTx,
		commitmentAddr: kept.commitmentAddr,
		votingAddr:     kept.votingAddr,
		wallet:         c.wallet,
	}
	jobs := make(map[*VSPTicket]*vspFeePayment)
	for _, ticket := range []*VSPTicket{kept, pruned} {
		if err := ticket.UpdateFeeStarted(ctx, chainhash.Hash{}, c.URL, c.PubKey); err != nil {
			t.Fatal(err)
		}
		fp := &vspFeePayment{
			client: c,
			ctx:    ctx,
			ticket: ticket,
			policy: c.policy,
			params: c.wallet.chainParams,
		}
		c.jobs[*ticket.Hash()] = fp
		jobs[ticket] = fp
	}

	if err := jobs[pruned].reconcilePayment(); !errors.Is(err, errStopped) {
		t.Fatalf("pruned ticket: reconcilePayment: want errStopped, got %v", err)
	}
	if managed(c, pruned) {
		t.Fatal("the pruned ticket is still managed by the client")
	}
	if timerSet(jobs[pruned]) {
		t.Fatal("the pruned ticket was scheduled for another attempt")
	}
	if _, err := pruned.VSPTicketInfo(ctx); err != nil {
		t.Fatalf("the pruned ticket's VSP record is gone: %v", err)
	}

	// The fake VSP fails the quote, so the unmined ticket is retried.
	if err := jobs[kept].reconcilePayment(); err == nil || errors.Is(err, errStopped) {
		t.Fatalf("unmined ticket: reconcilePayment: want the VSP error, got %v", err)
	}
	if !managed(c, kept) {
		t.Fatal("the unmined ticket was removed from the client")
	}
	if !timerSet(jobs[kept]) {
		t.Fatal("the unmined ticket was not scheduled for another attempt")
	}
	if got := feeStatus(ctx, t, kept); got != udb.VSPFeeProcessStarted {
		t.Fatalf("unmined ticket fee status = %v, want started", got)
	}

	// A database that cannot be read says nothing about the ticket.
	jobs[kept].stop()
	if err := c.wallet.db.Close(); err != nil {
		t.Fatal(err)
	}
	if kept.Pruned(ctx) {
		t.Fatal("a database error was taken for a pruned ticket")
	}
}
