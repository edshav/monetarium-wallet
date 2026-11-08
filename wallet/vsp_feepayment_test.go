// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
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
// outputs but no signatures.  A scheduled attempt that runs while Process waits
// for it owns the fee status: a fee tx it made and paid stays paid, and one
// the VSP rejected stays errored without the purchase's tx taking its place.
func TestVSPProcessDropsCallerFeeTxOnFailure(t *testing.T) {
	tests := []struct {
		name       string
		feeAddress bool // the VSP quotes a fee
		// attempt, if set, is what a scheduled attempt running while
		// Process waits for it does: "pays" makes and pays a fee tx,
		// "rejected" drops a fee tx the VSP refused.
		attempt string
	}{
		{name: "fee address fails"},
		{name: "fee tx fails", feeAddress: true},
		{name: "scheduled attempt paid while Process waited", attempt: "pays"},
		{name: "scheduled attempt's fee tx rejected while Process waited", attempt: "rejected"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var ticket *VSPTicket
			c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
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

			fp := c.feePayment(ctx, ticket, false)
			fp.stop()
			var attemptTx *wire.MsgTx
			if tc.attempt == "rejected" {
				// The job holds an earlier fee tx.
				old := wire.NewMsgTx()
				old.AddTxOut(wire.NewTxOut(1e7, []byte{0x52}))
				fp.feeTx, fp.feeHash = old, old.TxHash()
			}
			if tc.attempt != "" {
				fp.procMu.Lock() // the attempt is running
			}
			errc := make(chan error, 1)
			go func() { errc <- c.Process(ctx, ticket, purchaseTx) }()
			if tc.attempt != "" {
				waitBlockedOnMutex(t, "(*VSPClient).Process")
				var err error
				fp.mu.Lock()
				switch tc.attempt {
				case "pays":
					if fp.feeTx != nil {
						t.Error("Process gave the job the purchase's fee tx before it held the lock")
					}
					attemptTx = wire.NewMsgTx()
					attemptTx.AddTxOut(wire.NewTxOut(1e7, []byte{0x51}))
					fp.feeTx, fp.feeHash = attemptTx, attemptTx.TxHash()
					err = ticket.UpdateFeePaid(ctx, attemptTx.TxHash(), c.URL, c.PubKey)
				case "rejected":
					fp.feeTx, fp.feeHash = nil, chainhash.Hash{}
					err = ticket.UpdateFeeErrored(ctx, c.URL, c.PubKey)
				}
				fp.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
				fp.procMu.Unlock()
			}
			err := <-errc

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
			fp.mu.Lock()
			defer fp.mu.Unlock()
			if fp.feeTx != attemptTx {
				t.Fatalf("job's fee tx: got %p, want %p (purchase's %p)", fp.feeTx, attemptTx, purchaseTx)
			}
			want := udb.VSPFeeProcessErrored
			if tc.attempt == "pays" {
				want = udb.VSPFeeProcessPaid
			}
			info, err := ticket.VSPTicketInfo(ctx)
			if err != nil || udb.FeeStatus(info.FeeTxStatus) != want {
				t.Fatalf("fee status: %+v, %v; want %v", info, err, want)
			}
		})
	}
}

// waitBlockedOnMutex returns once a goroutine running fn waits to lock a
// mutex.
func waitBlockedOnMutex(t *testing.T, fn string) {
	t.Helper()
	buf := make([]byte, 1<<20)
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		n := runtime.Stack(buf, true)
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(g, "[sync.Mutex.Lock") && strings.Contains(g, fn) {
				return
			}
		}
		runtime.Gosched()
	}
	t.Fatalf("no goroutine in %s waited for a mutex", fn)
}

// TestVSPFeeWorkHoldsProcessingLock checks that Process and a scheduled
// attempt make every VSP request for a ticket while holding its processing
// lock, so the two cannot build or submit that ticket's fee tx at once.
func TestVSPFeeWorkHoldsProcessingLock(t *testing.T) {
	ctx := context.Background()
	var fp *vspFeePayment
	var ticket *VSPTicket
	var requests, unlocked, payFees atomic.Int32
	var quote atomic.Bool // answer feeaddress with a fee
	c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
		requests.Add(1)
		if fp.procMu.TryLock() {
			fp.procMu.Unlock()
			unlocked.Add(1)
		}
		switch {
		case path == "/api/v3/payfee":
			payFees.Add(1)
		case path == "/api/v3/feeaddress" && quote.Load():
			return http.StatusOK, types.FeeAddressResponse{
				Timestamp:  time.Now().Unix(),
				FeeAddress: ticket.votingAddr.String(),
				FeeAmount:  1e7,
				Expiration: time.Now().Add(time.Hour).Unix(),
				Request:    body,
			}
		}
		return apiError(types.ErrInternalError)
	})
	ticket = testVSPTicket(ctx, t, c, 1)
	fp = &vspFeePayment{
		client: c,
		ctx:    ctx,
		ticket: ticket,
		policy: c.policy,
		params: c.wallet.chainParams,
	}
	c.mu.Lock()
	c.jobs[*ticket.Hash()] = fp
	c.mu.Unlock()

	check := func(name string, work func()) {
		t.Helper()
		before := requests.Load()
		work()
		if requests.Load() == before {
			t.Fatalf("%s made no VSP request", name)
		}
		if n := unlocked.Load(); n != 0 {
			t.Fatalf("%s made %d VSP request(s) without the processing lock", name, n)
		}
	}
	check("Process", func() { _ = c.Process(ctx, ticket, nil) })
	check("scheduled attempt", fp.task("reconcile payment", fp.reconcilePayment))
	fp.stop() // the attempt rescheduled itself; its timer would hold the lock

	// With a finished fee tx in the job, Process submits it.
	finished := wire.NewMsgTx()
	finished.AddTxOut(wire.NewTxOut(1e7, []byte{0x51}))
	fp.mu.Lock()
	fp.feeTx = finished
	fp.mu.Unlock()
	quote.Store(true)
	check("Process submitting a fee", func() { _ = c.Process(ctx, ticket, nil) })
	if payFees.Load() == 0 {
		t.Fatal("test setup: Process did not submit the fee")
	}
	quote.Store(false)
	if err := ticket.UpdateFeePaid(ctx, chainhash.Hash{0xfe}, c.URL, c.PubKey); err != nil {
		t.Fatal(err)
	}
	check("Process of a paid ticket", func() { _ = c.Process(ctx, ticket, nil) })
}
