// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
)

// TestVSPRemovedJobDoesNotPayTwice runs the sequence where a Process call
// takes a ticket's job, a scheduled attempt removes that job while Process
// waits for it, and a second Process call starts a new job for the ticket and
// pays its fee.  The first call must then not pay a second fee tx from the
// removed job: the VSP would keep one, and the other's inputs would stay
// locked.
func TestVSPRemovedJobDoesNotPayTwice(t *testing.T) {
	ctx := context.Background()
	var ticket *VSPTicket
	var mu sync.Mutex
	paid := make(map[string]bool) // fee txs sent to the VSP
	c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
		switch path {
		case "/api/v3/feeaddress":
			return http.StatusOK, types.FeeAddressResponse{
				Timestamp:  time.Now().Unix(),
				FeeAddress: ticket.votingAddr.String(),
				FeeAmount:  1e7,
				Expiration: time.Now().Add(time.Hour).Unix(),
				Request:    body,
			}
		case "/api/v3/payfee":
			var req types.PayFeeRequest
			if err := json.Unmarshal(body, &req); err != nil {
				t.Error(err)
			}
			mu.Lock()
			paid[req.FeeTx] = true
			mu.Unlock()
			return http.StatusOK, types.PayFeeResponse{
				Timestamp: time.Now().Unix(),
				Request:   body,
			}
		}
		return apiError(types.ErrInternalError)
	})
	w := c.wallet
	ticket = testVSPTicket(ctx, t, c, 1)
	feeTxA := walletFundedFeeTx(ctx, t, w, 1)
	feeTxB := walletFundedFeeTx(ctx, t, w, 2)

	// The scheduled attempt of the first job holds its lock.
	first := c.feePayment(ctx, ticket, false)
	first.stop()
	first.procMu.Lock()
	done := make(chan error, 1)
	go func() { done <- c.Process(ctx, ticket, feeTxA) }()
	waitBlockedOnMutex(t, "(*VSPClient).Process")
	// The attempt removes the job (as for a fee above the maximum) and
	// returns, and a second Process call starts a new job and pays.
	first.remove("VSP fee above the configured maximum")
	if err := c.Process(ctx, ticket, feeTxB); err != nil {
		t.Fatalf("second Process: %v", err)
	}
	c.mu.Lock()
	second := c.jobs[*ticket.Hash()]
	c.mu.Unlock()
	first.procMu.Unlock()

	err := <-done
	if second != nil {
		second.stop()
	}
	if err != nil {
		t.Fatalf("first Process: %v", err)
	}
	mu.Lock()
	n := len(paid)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("the VSP was sent %d fee txs for one ticket, want 1", n)
	}
	// The first call found the fee paid and confirmed it through the second
	// job, leaving its own fee tx unused.
	if len(feeTxA.TxOut) != 0 {
		t.Fatal("the first Process call built or copied a fee tx after the fee was paid")
	}
	c.mu.Lock()
	job := c.jobs[*ticket.Hash()]
	c.mu.Unlock()
	if job != second {
		t.Fatalf("the ticket's job after both calls is %p, want the second job %p", job, second)
	}
}

// TestVSPRemoveKeepsNewerJob checks that a job removing itself leaves alone
// a newer job registered for the same ticket.
func TestVSPRemoveKeepsNewerJob(t *testing.T) {
	ctx := context.Background()
	c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
		return apiError(types.ErrTicketCannotVote)
	})
	ticket := testVSPTicket(ctx, t, c, 1)
	old := &vspFeePayment{
		client: c,
		ctx:    ctx,
		ticket: ticket,
		policy: c.policy,
		params: c.wallet.chainParams,
	}
	newer := &vspFeePayment{client: c, ctx: ctx, ticket: ticket}
	c.jobs[*ticket.Hash()] = newer

	// A scheduled attempt of the old job, already running when the newer
	// job was registered, learns the ticket cannot vote and removes itself.
	var apiErr types.ErrorResponse
	if err := old.reconcilePayment(); !errors.As(err, &apiErr) || apiErr.Code != types.ErrTicketCannotVote {
		t.Fatalf("reconcilePayment: want ErrTicketCannotVote, got %v", err)
	}
	c.mu.Lock()
	got := c.jobs[*ticket.Hash()]
	c.mu.Unlock()
	if got != newer {
		t.Fatalf("the old job's removal dropped the newer job (registered job %p, want %p)", got, newer)
	}
}

// TestVSPRemovedPaidJobIsReplaced checks that a Process call for a paid
// ticket, whose job a scheduled attempt removed while Process waited for it,
// confirms the payment through a new listed job and does not reschedule the
// removed one.
func TestVSPRemovedPaidJobIsReplaced(t *testing.T) {
	ctx := context.Background()
	c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
		return apiError(types.ErrInternalError)
	})
	ticket := testVSPTicket(ctx, t, c, 1)
	if err := ticket.UpdateFeePaid(ctx, chainhash.Hash{0xfe}, c.URL, c.PubKey); err != nil {
		t.Fatal(err)
	}

	first := c.feePayment(ctx, ticket, true)
	first.stop()
	first.procMu.Lock()
	done := make(chan error, 1)
	go func() { done <- c.Process(ctx, ticket, nil) }()
	waitBlockedOnMutex(t, "(*VSPClient).Process")
	first.remove("VSP fee above the configured maximum")
	// Another caller registers a new job for the ticket meanwhile.
	newer := c.feePayment(ctx, ticket, true)
	newer.stop()
	first.procMu.Unlock()
	if err := <-done; err != nil {
		t.Fatalf("Process: %v", err)
	}

	c.mu.Lock()
	job := c.jobs[*ticket.Hash()]
	c.mu.Unlock()
	if job != nil {
		job.stop()
	}
	if timerSet(first) {
		first.stop()
		t.Fatal("the removed job was scheduled again")
	}
	if job != newer {
		t.Fatalf("the ticket's job after Process is %p, want the newer job %p", job, newer)
	}
}

// TestVSPRemovedJobAttemptDoesNothing checks that a scheduled attempt whose
// job is removed while it waits for the job's lock (its timer had already
// fired, so stopping it did not help) makes no VSP request and schedules
// nothing.
func TestVSPRemovedJobAttemptDoesNothing(t *testing.T) {
	ctx := context.Background()
	var n int
	var mu sync.Mutex
	c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
		mu.Lock()
		n++
		mu.Unlock()
		return apiError(types.ErrInternalError)
	})
	ticket := testVSPTicket(ctx, t, c, 1)
	fp := &vspFeePayment{
		client: c,
		ctx:    ctx,
		ticket: ticket,
		policy: c.policy,
		params: c.wallet.chainParams,
	}
	c.mu.Lock()
	c.jobs[*ticket.Hash()] = fp
	c.mu.Unlock()

	// A Process call holds the lock and removes the job meanwhile.
	fp.procMu.Lock()
	done := make(chan struct{})
	go func() {
		fp.task("reconcile payment", fp.reconcilePayment)()
		close(done)
	}()
	waitBlockedOnMutex(t, "(*vspFeePayment).task")
	fp.remove("expired")
	// A newer job is registered for the ticket meanwhile.
	c.mu.Lock()
	c.jobs[*ticket.Hash()] = &vspFeePayment{client: c, ctx: ctx, ticket: ticket}
	c.mu.Unlock()
	fp.procMu.Unlock()
	<-done

	mu.Lock()
	got := n
	mu.Unlock()
	if got != 0 {
		t.Fatalf("the removed job's attempt sent %d VSP requests", got)
	}
	if timerSet(fp) {
		fp.stop()
		t.Fatal("the removed job's attempt scheduled another")
	}
}

// TestVSPRemovedJobRestartPays checks what Process calls waiting on a job get
// when a scheduled attempt removes it and nothing replaces it: each restarts,
// the payment goes ahead through a new job with a caller's own fee tx, one fee
// tx reaches the VSP, and no caller is left waiting on the removed job's lock.
// The ticket is unpaid, or paid and marked errored while the callers wait (as
// for a fee above the maximum).
func TestVSPRemovedJobRestartPays(t *testing.T) {
	for _, tc := range []struct {
		name string
		paid bool
	}{
		{name: "unpaid"},
		{name: "paid, errored meanwhile", paid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var ticket *VSPTicket
			var mu sync.Mutex
			paid := make(map[string]bool)
			c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				switch path {
				case "/api/v3/feeaddress":
					return http.StatusOK, types.FeeAddressResponse{
						Timestamp:  time.Now().Unix(),
						FeeAddress: ticket.votingAddr.String(),
						FeeAmount:  1e7,
						Expiration: time.Now().Add(time.Hour).Unix(),
						Request:    body,
					}
				case "/api/v3/payfee":
					var req types.PayFeeRequest
					if err := json.Unmarshal(body, &req); err != nil {
						t.Error(err)
					}
					mu.Lock()
					paid[req.FeeTx] = true
					mu.Unlock()
					return http.StatusOK, types.PayFeeResponse{
						Timestamp: time.Now().Unix(),
						Request:   body,
					}
				}
				return apiError(types.ErrInternalError)
			})
			w := c.wallet
			ticket = testVSPTicket(ctx, t, c, 1)
			if tc.paid {
				if err := ticket.UpdateFeePaid(ctx, chainhash.Hash{0xfe}, c.URL, c.PubKey); err != nil {
					t.Fatal(err)
				}
			}
			feeTxs := []*wire.MsgTx{walletFundedFeeTx(ctx, t, w, 1), walletFundedFeeTx(ctx, t, w, 2)}

			first := c.feePayment(ctx, ticket, tc.paid)
			first.stop()
			first.procMu.Lock()
			done := make(chan error, len(feeTxs))
			for _, feeTx := range feeTxs {
				go func() { done <- c.Process(ctx, ticket, feeTx) }()
			}
			waitBlockedOnMutexN(t, "(*VSPClient).Process", len(feeTxs))
			if tc.paid {
				if err := ticket.UpdateFeeErrored(ctx, c.URL, c.PubKey); err != nil {
					t.Fatal(err)
				}
			}
			first.remove("VSP fee above the configured maximum")
			first.procMu.Unlock()

			for range feeTxs {
				select {
				case err := <-done:
					if err != nil {
						t.Fatalf("Process: %v", err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("a Process call stayed waiting on the removed job")
				}
			}
			mu.Lock()
			n := len(paid)
			mu.Unlock()
			if n != 1 {
				t.Fatalf("the VSP was sent %d fee txs for one ticket, want 1", n)
			}
			if len(feeTxs[0].TxOut) == 0 && len(feeTxs[1].TxOut) == 0 {
				t.Fatal("the fee was not paid with a caller's fee tx")
			}
			c.mu.Lock()
			job := c.jobs[*ticket.Hash()]
			c.mu.Unlock()
			if job == nil || job == first {
				t.Fatalf("the ticket's job after Process is %p, want a new job", job)
			}
		})
	}
}

// TestVSPFailedConfirmedWriteIsRetried checks that when a scheduled attempt
// learns from the VSP that the fee is confirmed but cannot write the confirmed
// status, the job stays listed with a retry scheduled, and the retry records
// the confirmation.
func TestVSPFailedConfirmedWriteIsRetried(t *testing.T) {
	ctx := context.Background()
	feeHash := chainhash.Hash{0xfe}
	c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
		switch {
		case strings.HasSuffix(path, "/api/v3/ticketstatus"):
			return http.StatusOK, types.TicketStatusResponse{
				FeeTxStatus: "confirmed",
				FeeTxHash:   feeHash.String(),
				Request:     body,
			}
		case strings.HasSuffix(path, "/api/v3/feeaddress"):
			return apiError(types.ErrFeeAlreadyReceived)
		}
		return apiError(types.ErrInternalError)
	})
	ticket := testVSPTicket(ctx, t, c, 1)
	if err := ticket.UpdateFeePaid(ctx, feeHash, c.URL, c.PubKey); err != nil {
		t.Fatal(err)
	}
	fp := c.feePayment(ctx, ticket, true)
	fp.stop()
	url := c.URL
	failVSPWrites(c)
	fp.task("confirm payment", fp.confirmPayment)()
	if !fp.listed() || !timerSet(fp) {
		fp.stop()
		t.Fatal("a failed confirmed write left no retry")
	}
	fp.stop()
	info, err := ticket.VSPTicketInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if udb.FeeStatus(info.FeeTxStatus) != udb.VSPFeeProcessPaid {
		t.Fatalf("after the failed write: fee status %v, want paid", udb.FeeStatus(info.FeeTxStatus))
	}

	// The write works again, and the retry runs as its timer would.
	c.URL = url
	fp.task("reconcile payment", fp.reconcilePayment)()
	info, err = ticket.VSPTicketInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if udb.FeeStatus(info.FeeTxStatus) != udb.VSPFeeProcessConfirmed || info.FeeHash != feeHash {
		t.Fatalf("after the retry: fee status %v, hash %v; want confirmed, %v",
			udb.FeeStatus(info.FeeTxStatus), info.FeeHash, feeHash)
	}
	if fp.listed() || timerSet(fp) {
		fp.stop()
		t.Fatal("the job was kept after the confirmation was recorded")
	}
}
