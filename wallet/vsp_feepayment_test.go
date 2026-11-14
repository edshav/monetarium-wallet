// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/blockchain/stake"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/gcs/blockcf2"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
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

// signedFeeTx returns a fee tx that looks finished to the client: it has an
// output and a signed input.
func signedFeeTx(id byte) *wire.MsgTx {
	tx := wire.NewMsgTx()
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{id}}, 2e7, []byte{0x51}))
	tx.AddTxOut(wire.NewTxOut(1e7, []byte{0x51}))
	return tx
}

// insertUnmined records tx as an unmined wallet transaction, unpublished (as
// the wallet records a fee tx it built) or published.
func insertUnmined(ctx context.Context, t *testing.T, w *Wallet, tx *wire.MsgTx, unpublished bool) {
	t.Helper()
	err := walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
		rec, err := udb.NewTxRecordFromMsgTx(tx, time.Now())
		if err != nil {
			return err
		}
		rec.Unpublished = unpublished
		return w.txStore.InsertMemPoolTx(dbtx, rec)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// failVSPWrites makes every fee status write of c fail with errors.Invalid:
// the wallet keys the VSP's record by its URL, and bbolt refuses keys over
// 32 KiB.  Requests still reach the fake VSP, under a longer path.
func failVSPWrites(c *VSPClient) {
	c.URL += "/" + strings.Repeat("v", 1<<15)
}

// TestVSPExpiredFeeMarksErrored checks that after the VSP reports the fee as
// expired, the ticket is no longer recorded as paid with the abandoned tx.
func TestVSPExpiredFeeMarksErrored(t *testing.T) {
	for _, tc := range []struct {
		name       string
		published  bool // the job's fee tx is one the wallet published
		failWrites bool
	}{
		{name: "unpublished fee tx"},
		{name: "published fee tx", published: true},
		// The VSP's error is returned, not the failed write's.
		{name: "status write fails", failWrites: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
				return apiError(types.ErrFeeExpired)
			})
			ticket := testVSPTicket(ctx, t, c, 1)
			feeTx := signedFeeTx(0xcc)
			insertUnmined(ctx, t, c.wallet, feeTx, !tc.published)
			if err := ticket.UpdateFeePaid(ctx, feeTx.TxHash(), c.URL, c.PubKey); err != nil {
				t.Fatal(err)
			}
			if tc.failWrites {
				failVSPWrites(c)
			}
			fp := &vspFeePayment{
				client:  c,
				ctx:     ctx,
				ticket:  ticket,
				policy:  c.policy,
				params:  c.wallet.chainParams,
				fee:     1e7,
				feeAddr: ticket.votingAddr,
				feeHash: feeTx.TxHash(),
				feeTx:   feeTx,
			}
			c.jobs[*ticket.Hash()] = fp

			var apiErr types.ErrorResponse
			if err := fp.reconcilePayment(); !errors.As(err, &apiErr) || apiErr.Code != types.ErrFeeExpired {
				t.Fatalf("reconcilePayment: want ErrFeeExpired, got %v", err)
			}
			fp.stop()
			want := udb.VSPFeeProcessErrored
			if tc.failWrites {
				want = udb.VSPFeeProcessPaid
			}
			if got := feeStatus(ctx, t, ticket); got != want {
				t.Fatalf("fee status after an expired fee = %v, want %v", got, want)
			}
			fp.mu.Lock()
			feeHash := fp.feeHash
			fp.mu.Unlock()
			if feeHash != (chainhash.Hash{}) {
				t.Fatalf("payment still holds the abandoned fee hash %v", feeHash)
			}
			expired := feeTx.TxHash()
			_, _, err := c.wallet.TxBlock(ctx, &expired)
			if gone := errors.Is(err, errors.NotExist); gone == tc.published {
				t.Fatalf("expired fee tx gone from the wallet: %v, want %v (err %v)", gone, !tc.published, err)
			}
		})
	}
}

// walletFundedFeeTx returns an unsigned fee tx with one input, an output the
// wallet holds, for makeFeeTx to finish.
func walletFundedFeeTx(ctx context.Context, t *testing.T, w *Wallet) *wire.MsgTx {
	t.Helper()
	addr, err := w.NewInternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	ver, script := addr.(Address).PaymentScript()
	fund := wire.NewMsgTx()
	fund.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{2}}, 1e8, nil))
	fund.AddTxOut(&wire.TxOut{Value: 1e8, Version: ver, PkScript: script})
	if err := w.AddTransaction(ctx, fund, nil); err != nil {
		t.Fatal(err)
	}
	feeTx := wire.NewMsgTx()
	feeTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: fund.TxHash()}, 1e8, nil))
	return feeTx
}

// TestVSPRejectedNewFeeTxIsAbandoned checks that a fee tx reconcilePayment
// makes and the VSP then rejects in the same attempt is removed from the
// wallet, so its inputs can be spent again.
func TestVSPRejectedNewFeeTxIsAbandoned(t *testing.T) {
	ctx := context.Background()
	c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
		return apiError(types.ErrInvalidFeeTx)
	})
	w := c.wallet
	ticket := testVSPTicket(ctx, t, c, 1)
	feeTx := walletFundedFeeTx(ctx, t, w)
	fp := &vspFeePayment{
		client:  c,
		ctx:     ctx,
		ticket:  ticket,
		policy:  c.policy,
		params:  w.chainParams,
		fee:     1e7,
		feeAddr: ticket.votingAddr,
		feeTx:   feeTx,
	}
	c.jobs[*ticket.Hash()] = fp

	var apiErr types.ErrorResponse
	if err := fp.reconcilePayment(); !errors.As(err, &apiErr) || apiErr.Code != types.ErrInvalidFeeTx {
		t.Fatalf("reconcilePayment: want ErrInvalidFeeTx, got %v", err)
	}
	fp.stop()
	if len(feeTx.TxOut) == 0 {
		t.Fatal("test setup: the fee tx was not made")
	}
	feeHash := feeTx.TxHash()
	if _, _, err := w.TxBlock(ctx, &feeHash); !errors.Is(err, errors.NotExist) {
		t.Fatalf("the rejected fee tx is still in the wallet (err %v)", err)
	}
}

// TestVSPRejectedFeeTxIsAbandoned checks that a fee tx the VSP rejects is
// removed from the wallet so its inputs can be spent again, and that a new fee
// is requested on the retry, even when the errored status cannot be written.
// When it can, the ticket is recorded as errored.
func TestVSPRejectedFeeTxIsAbandoned(t *testing.T) {
	for _, tc := range []struct {
		name       string
		code       types.ErrorCode
		failWrites bool
		published  bool
	}{
		{name: "invalid, status written", code: types.ErrInvalidFeeTx},
		{name: "invalid, status write fails", code: types.ErrInvalidFeeTx, failWrites: true},
		{name: "cannot broadcast", code: types.ErrCannotBroadcastFee},
		{name: "unknown outputs", code: types.ErrCannotBroadcastFeeUnknownOutputs},
		// The VSP names a tx the wallet published: it stays.
		{name: "published tx", code: types.ErrInvalidFeeTx, published: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
				return apiError(tc.code)
			})
			ticket := testVSPTicket(ctx, t, c, 1)
			feeTx := signedFeeTx(0xcd)
			insertUnmined(ctx, t, c.wallet, feeTx, !tc.published)
			feeHash := feeTx.TxHash()
			if err := ticket.UpdateFeeStarted(ctx, feeHash, c.URL, c.PubKey); err != nil {
				t.Fatal(err)
			}
			if tc.failWrites {
				failVSPWrites(c)
			}
			fp := &vspFeePayment{
				client:  c,
				ctx:     ctx,
				ticket:  ticket,
				policy:  c.policy,
				params:  c.wallet.chainParams,
				fee:     1e7,
				feeAddr: ticket.votingAddr,
				feeHash: feeHash,
				feeTx:   feeTx,
			}
			c.jobs[*ticket.Hash()] = fp

			var apiErr types.ErrorResponse
			err := fp.reconcilePayment()
			if !errors.As(err, &apiErr) || apiErr.Code != tc.code {
				t.Fatalf("reconcilePayment: want %v, got %v", tc.code, err)
			}
			if !timerSet(fp) {
				t.Fatal("no retry scheduled after the VSP rejected the fee tx")
			}
			fp.stop()
			_, _, err = c.wallet.TxBlock(ctx, &feeHash)
			if gone := errors.Is(err, errors.NotExist); gone == tc.published {
				t.Fatalf("fee tx gone from the wallet: %v, want %v (err %v)", gone, !tc.published, err)
			}
			fp.mu.Lock()
			fee := fp.fee
			fp.mu.Unlock()
			if fee != 0 {
				t.Fatalf("the retry would pay the rejected fee %v again", fee)
			}
			want := udb.VSPFeeProcessErrored
			if tc.failWrites {
				want = udb.VSPFeeProcessStarted
			}
			if got := feeStatus(ctx, t, ticket); got != want {
				t.Fatalf("fee status after the VSP rejected the fee tx = %v, want %v", got, want)
			}
		})
	}
}

// TestVSPReconcileRetriesFailedPaidWrite checks that when the VSP accepts the
// fee but the wallet cannot record it as paid, the payment is retried rather
// than left with nothing scheduled.
func TestVSPReconcileRetriesFailedPaidWrite(t *testing.T) {
	ctx := context.Background()
	c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
		if !strings.HasSuffix(path, "/api/v3/payfee") {
			return apiError(types.ErrInternalError)
		}
		return http.StatusOK, types.PayFeeResponse{
			Timestamp: time.Now().Unix(),
			Request:   body,
		}
	})
	ticket := testVSPTicket(ctx, t, c, 1)
	failVSPWrites(c)
	feeTx := signedFeeTx(0xcf)
	fp := &vspFeePayment{
		client:  c,
		ctx:     ctx,
		ticket:  ticket,
		policy:  c.policy,
		params:  c.wallet.chainParams,
		fee:     1e7,
		feeAddr: ticket.votingAddr,
		feeHash: feeTx.TxHash(),
		feeTx:   feeTx,
	}
	c.jobs[*ticket.Hash()] = fp

	if err := fp.reconcilePayment(); !errors.Is(err, errors.Invalid) {
		t.Fatalf("reconcilePayment: want the failed write, got %v", err)
	}
	if !timerSet(fp) {
		t.Fatal("a failed write after the VSP took the fee left no retry")
	}
}

// TestVSPFailedPaidWriteAbandonsFeeTx checks that a fee tx made and stored in
// the wallet is removed again when the ticket cannot be recorded as paid, so
// it does not hold its inputs while no payment refers to it.
func TestVSPFailedPaidWriteAbandonsFeeTx(t *testing.T) {
	ctx := context.Background()
	c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
		return apiError(types.ErrInternalError)
	})
	w := c.wallet
	ticket := testVSPTicket(ctx, t, c, 1)
	feeTx := walletFundedFeeTx(ctx, t, w)
	failVSPWrites(c)
	fp := &vspFeePayment{
		client:  c,
		ctx:     ctx,
		ticket:  ticket,
		policy:  c.policy,
		params:  w.chainParams,
		fee:     1e7,
		feeAddr: ticket.votingAddr,
	}

	c.jobs[*ticket.Hash()] = fp
	fp.feeTx = feeTx
	if err := fp.reconcilePayment(); !errors.Is(err, errors.Invalid) {
		t.Fatalf("reconcilePayment: want the failed write, got %v", err)
	}
	fp.stop()
	if len(feeTx.TxOut) == 0 {
		t.Fatal("test setup: the fee tx was not made")
	}
	feeHash := feeTx.TxHash()
	if _, _, err := w.TxBlock(ctx, &feeHash); !errors.Is(err, errors.NotExist) {
		t.Fatalf("fee tx with no recorded payment is still in the wallet (err %v)", err)
	}
}

// TestVSPProcessManagedTicketsSkipsBadTicket checks that an error for one
// ticket does not stop the remaining tickets from being resumed.
func TestVSPProcessManagedTicketsSkipsBadTicket(t *testing.T) {
	validHash := chainhash.Hash{0xfe}.String()
	for _, tc := range []struct {
		name       string
		status     string
		feeHash    string
		failWrites bool
		// locked locks the wallet once the bad ticket's status is
		// answered, so the next ticket's request fails.
		locked bool
	}{
		{name: "bad confirmed fee hash", status: "confirmed", feeHash: "not a hash"},
		{name: "bad paid fee hash", status: "broadcast", feeHash: "not a hash"},
		{name: "confirmed write fails", status: "confirmed", feeHash: validHash, failWrites: true},
		{name: "paid write fails", status: "broadcast", feeHash: validHash, failWrites: true},
		{name: "wallet locks after a bad ticket", status: "confirmed", feeHash: "not a hash", locked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var badHash string // set once the ticket exists
			var c *VSPClient
			c = testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				if !strings.HasSuffix(path, "/api/v3/ticketstatus") {
					return apiError(types.ErrInternalError)
				}
				var req types.TicketStatusRequest
				if err := json.Unmarshal(body, &req); err != nil {
					return apiError(types.ErrBadRequest)
				}
				if req.TicketHash == badHash {
					if tc.locked {
						c.wallet.Lock()
					}
					return http.StatusOK, types.TicketStatusResponse{
						FeeTxStatus: tc.status,
						FeeTxHash:   tc.feeHash,
						Request:     body,
					}
				}
				return http.StatusOK, types.TicketStatusResponse{FeeTxStatus: "none", Request: body}
			})
			bad := testVSPTicket(ctx, t, c, 1)
			unpaid := testVSPTicket(ctx, t, c, 2)
			badHash = bad.Hash().String()
			if tc.failWrites {
				failVSPWrites(c)
			}

			err := c.ProcessManagedTickets(ctx, []*VSPTicket{bad, unpaid})
			if err == nil || !strings.Contains(err.Error(), badHash) {
				t.Fatalf("ProcessManagedTickets: want the bad ticket's error, got %v", err)
			}
			if tc.locked {
				if !errors.Is(err, errors.Locked) {
					t.Fatalf("ProcessManagedTickets: want the Locked error too, got %v", err)
				}
				return
			}
			c.mu.Lock()
			_, resumed := c.jobs[*unpaid.Hash()]
			_, badJob := c.jobs[*bad.Hash()]
			c.mu.Unlock()
			if badJob {
				t.Fatal("a job was started for the ticket whose status could not be recorded")
			}
			if !resumed {
				t.Fatal("an error for one ticket stopped the next ticket")
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

func managed(c *VSPClient, ticket *VSPTicket) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.jobs[*ticket.Hash()]
	return ok
}

// prunedTicket returns kept's ticket data under a hash the wallet does not have.
func prunedTicket(c *VSPClient, kept *VSPTicket) *VSPTicket {
	h := chainhash.Hash{0xdd}
	return &VSPTicket{
		hash:           &h,
		rawTx:          kept.rawTx,
		parentTx:       kept.parentTx,
		commitmentAddr: kept.commitmentAddr,
		votingAddr:     kept.votingAddr,
		wallet:         c.wallet,
	}
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
	pruned := prunedTicket(c, kept)
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
	if err := jobs[kept].reconcilePayment(); errors.Is(err, errStopped) {
		t.Fatal("a database error was taken for a pruned ticket")
	}
	jobs[kept].stop()
}

// TestVSPPrunedTicketStopsBeforeVSPRequests checks that a pruned ticket's
// payment stops before any VSP request on each path into it: Process of an
// unpaid ticket (fee address), Process of a paid one (status), and a scheduled
// attempt whose job already holds a fee tx (fee submission).
func TestVSPPrunedTicketStopsBeforeVSPRequests(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(ctx context.Context, t *testing.T, c *VSPClient, ticket *VSPTicket) error
	}{{
		name: "Process, fee not paid",
		run: func(ctx context.Context, t *testing.T, c *VSPClient, ticket *VSPTicket) error {
			return c.Process(ctx, ticket, nil)
		},
	}, {
		name: "Process, fee paid",
		run: func(ctx context.Context, t *testing.T, c *VSPClient, ticket *VSPTicket) error {
			if err := ticket.UpdateFeePaid(ctx, chainhash.Hash{0xee}, c.URL, c.PubKey); err != nil {
				t.Fatal(err)
			}
			return c.Process(ctx, ticket, nil)
		},
	}, {
		name: "scheduled attempt with a fee tx",
		run: func(ctx context.Context, t *testing.T, c *VSPClient, ticket *VSPTicket) error {
			feeTx := wire.NewMsgTx()
			feeTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{0xef}}, 1e7, nil))
			feeTx.AddTxOut(&wire.TxOut{Value: 1e7})
			fp := &vspFeePayment{client: c, ctx: ctx, ticket: ticket, feeTx: feeTx}
			c.jobs[*ticket.Hash()] = fp
			err := fp.reconcilePayment()
			if timerSet(fp) {
				t.Fatal("the removed job was scheduled for another attempt")
			}
			return err
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var requests atomic.Int32
			c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
				requests.Add(1)
				return apiError(types.ErrInternalError)
			})
			pruned := prunedTicket(c, testVSPTicket(ctx, t, c, 1))

			if err := tc.run(ctx, t, c, pruned); !errors.Is(err, errStopped) {
				t.Fatalf("want errStopped, got %v", err)
			}
			if n := requests.Load(); n != 0 {
				t.Fatalf("%d requests sent to the VSP for a pruned ticket", n)
			}
			if managed(c, pruned) {
				t.Fatal("the pruned ticket is still managed by the client")
			}
		})
	}
}

// TestVSPTicketPrunedDuringProcessStops checks that a ticket the wallet drops
// while Process waits for the fee address is not paid for: submitPayment
// stops before the payfee request.
func TestVSPTicketPrunedDuringProcessStops(t *testing.T) {
	ctx := context.Background()
	var c *VSPClient
	var ticket *VSPTicket
	var payfee atomic.Int32
	c = testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
		switch path {
		case "/api/v3/feeaddress":
			if err := c.wallet.AbandonTransaction(ctx, ticket.Hash()); err != nil {
				t.Error(err)
			}
			return http.StatusOK, types.FeeAddressResponse{
				Timestamp:  time.Now().Unix(),
				FeeAddress: ticket.votingAddr.String(),
				FeeAmount:  1e7,
				Expiration: time.Now().Add(time.Hour).Unix(),
				Request:    body,
			}
		case "/api/v3/payfee":
			payfee.Add(1)
		}
		return apiError(types.ErrInternalError)
	})
	ticket = testVSPTicket(ctx, t, c, 1)

	// Fund the fee tx with a wallet output.
	addr, err := c.wallet.NewInternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	ver, script := addr.(Address).PaymentScript()
	fund := wire.NewMsgTx()
	fund.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{2}}, 1e8, nil))
	fund.AddTxOut(&wire.TxOut{Value: 1e8, Version: ver, PkScript: script})
	if err := c.wallet.AddTransaction(ctx, fund, nil); err != nil {
		t.Fatal(err)
	}
	feeTx := wire.NewMsgTx()
	feeTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: fund.TxHash()}, 1e8, nil))

	if err := c.Process(ctx, ticket, feeTx); !errors.Is(err, errStopped) {
		t.Fatalf("Process: want errStopped, got %v", err)
	}
	if n := payfee.Load(); n != 0 {
		t.Fatalf("%d payfee requests for a ticket pruned during Process", n)
	}
	if managed(c, ticket) {
		t.Fatal("the pruned ticket is still managed by the client")
	}
}

// publishRecordingNetwork is a mockNetwork that records the txs it publishes and
// passes each to onPublish, if set.
type publishRecordingNetwork struct {
	mockNetwork
	published []*wire.MsgTx
	onPublish func(*wire.MsgTx)
}

func (n *publishRecordingNetwork) PublishTransactions(_ context.Context, txs ...*wire.MsgTx) error {
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

// purchaseWithVSP funds the client's wallet with two outputs per ticket, one
// for its fee and one for its price, mined in block one, and buys count
// tickets through c, publishing over n.
func purchaseWithVSP(ctx context.Context, t *testing.T, c *VSPClient, n *publishRecordingNetwork, count int) (*PurchaseTicketsResponse, error) {
	t.Helper()
	w := c.wallet
	w.SetNetworkBackend(n)

	addr, err := w.NewExternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	fund := wire.NewMsgTx()
	fund.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{0xfd}}, int64(2*count)*1e8, nil))
	ver, script := addr.PaymentScript()
	for range 2 * count {
		fund.AddTxOut(&wire.TxOut{Value: 1e8, Version: ver, PkScript: script})
	}
	blockOne := maketg(t, w.chainParams).createBlockOne("block-one")
	_, err = w.ChainSwitch(ctx, new(SidechainForest), []*BlockNode{blockOne.BlockNode},
		map[chainhash.Hash][]*wire.MsgTx{*blockOne.Hash: {fund}})
	if err != nil {
		t.Fatal(err)
	}

	// Below stake validation height the VSP fee estimate is zero, and the
	// fee reservation for a zero amount takes every output, which leaves
	// one ticket.  More tickets need empty blocks up to that height.
	if count > 1 {
		var chain []*BlockNode
		prev := blockOne.MsgBlock.Header
		for int64(prev.Height) < w.chainParams.StakeValidationHeight {
			header := wire.BlockHeader{
				PrevBlock: prev.BlockHash(),
				VoteBits:  1, // approve the parent, so block one keeps the funds
				Height:    prev.Height + 1,
				Bits:      w.chainParams.PowLimitBits,
				SBits:     w.chainParams.MinimumStakeDiff,
			}
			filter, err := blockcf2.Regular(&wire.MsgBlock{Header: header}, nil)
			if err != nil {
				t.Fatal(err)
			}
			hash := header.BlockHash()
			chain = append(chain, NewBlockNode(&header, &hash, filter))
			prev = header
		}
		_, err = w.ChainSwitch(ctx, new(SidechainForest), chain, map[chainhash.Hash][]*wire.MsgTx{})
		if err != nil {
			t.Fatal(err)
		}
	}

	return w.PurchaseTickets(ctx, n, &PurchaseTicketsRequest{
		Count: count,
		// MinConf 0 skips the random UTXO pick, which can come back empty
		// with several eligible outputs (a separate bug).
		MinConf:   0,
		VSPClient: c,
	})
}

// checkPurchase checks that resp holds count ticket hashes, that those
// tickets were published, and that no outputs stay locked.
func checkPurchase(ctx context.Context, t *testing.T, w *Wallet, n *publishRecordingNetwork, resp *PurchaseTicketsResponse, count int) {
	t.Helper()
	if resp == nil || len(resp.TicketHashes) != count {
		t.Fatalf("PurchaseTickets response: got %+v, want %d ticket hashes", resp, count)
	}
	var tickets []chainhash.Hash
	for _, tx := range n.published {
		if stake.IsSStx(tx) {
			tickets = append(tickets, tx.TxHash())
		}
	}
	if len(tickets) != count {
		t.Fatalf("published tickets %v, want %v", tickets, resp.TicketHashes)
	}
	for i := range tickets {
		if tickets[i] != *resp.TicketHashes[i] {
			t.Fatalf("published tickets %v, want %v", tickets, resp.TicketHashes)
		}
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
	n := new(publishRecordingNetwork)
	resp, err := purchaseWithVSP(ctx, t, c, n, 1)
	if !errors.Is(err, ErrVSPFeeNotPaid) {
		t.Errorf("PurchaseTickets error: got %v, want ErrVSPFeeNotPaid", err)
	}
	checkPurchase(ctx, t, c.wallet, n, resp, 1)
}

// TestPurchaseTicketsVSPTicketFailureKeepsHashes checks the same when the
// VSP ticket record cannot be made after publishing: here the wallet is
// locked once the ticket is published, so its voting key cannot be read.
func TestPurchaseTicketsVSPTicketFailureKeepsHashes(t *testing.T) {
	ctx := context.Background()
	c := testVSPClient(ctx, t, vspInfoOr(func(string, []byte) (int, any) {
		return apiError(types.ErrInternalError)
	}))
	n := &publishRecordingNetwork{onPublish: func(tx *wire.MsgTx) {
		if stake.IsSStx(tx) {
			c.wallet.Lock()
		}
	}}
	resp, err := purchaseWithVSP(ctx, t, c, n, 1)
	if !errors.Is(err, ErrVSPFeeNotPaid) || !errors.Is(err, errors.Locked) {
		t.Errorf("PurchaseTickets error: got %v, want ErrVSPFeeNotPaid and Locked", err)
	}
	checkPurchase(ctx, t, c.wallet, n, resp, 1)
	if hash := resp.TicketHashes[0].String(); err == nil || !strings.Contains(err.Error(), hash) {
		t.Errorf("PurchaseTickets error %v: want it to name %s", err, hash)
	}
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
	n := new(publishRecordingNetwork)
	resp, err := purchaseWithVSP(ctx, t, c, n, 1)
	if err != nil {
		t.Errorf("PurchaseTickets error: %v", err)
	}
	if !payFee.Load() {
		t.Error("the fee was not paid")
	}
	checkPurchase(ctx, t, c.wallet, n, resp, 1)
}

// TestPurchaseTicketsFeeErrorNamesTicket checks that when one of two tickets'
// VSP fee fails, the caller gets both ticket hashes and an error that names
// the unpaid ticket and not the paid one.
func TestPurchaseTicketsFeeErrorNamesTicket(t *testing.T) {
	ctx := context.Background()
	var feeAddr string
	var mu sync.Mutex
	var failed string  // the first ticket to ask for a fee address
	var paidFee string // the ticket whose fee was paid
	c := testVSPClient(ctx, t, vspInfoOr(func(path string, body []byte) (int, any) {
		switch path {
		case "/api/v3/feeaddress":
			var req types.FeeAddressRequest
			if err := json.Unmarshal(body, &req); err != nil {
				return apiError(types.ErrBadRequest)
			}
			mu.Lock()
			if failed == "" {
				failed = req.TicketHash
			}
			fail := req.TicketHash == failed
			mu.Unlock()
			if fail {
				return apiError(types.ErrInternalError)
			}
			return http.StatusOK, types.FeeAddressResponse{
				Timestamp:  time.Now().Unix(),
				FeeAddress: feeAddr,
				FeeAmount:  1000, // below the output the purchase reserved
				Expiration: time.Now().Add(time.Hour).Unix(),
				Request:    body,
			}
		case "/api/v3/payfee":
			var req types.PayFeeRequest
			if err := json.Unmarshal(body, &req); err != nil {
				return apiError(types.ErrBadRequest)
			}
			mu.Lock()
			paidFee = req.TicketHash
			mu.Unlock()
			return http.StatusOK, types.PayFeeResponse{Timestamp: time.Now().Unix(), Request: body}
		}
		return apiError(types.ErrInternalError)
	}))
	addr, err := c.wallet.NewExternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	feeAddr = addr.String()
	n := new(publishRecordingNetwork)
	resp, err := purchaseWithVSP(ctx, t, c, n, 2)
	checkPurchase(ctx, t, c.wallet, n, resp, 2)
	unpaid, paid := resp.TicketHashes[0].String(), resp.TicketHashes[1].String()
	mu.Lock()
	gotFailed, gotPaid := failed, paidFee
	mu.Unlock()
	if gotFailed != unpaid || gotPaid != paid {
		t.Fatalf("fee failed for %s and paid for %s, want failed for %s and paid for %s",
			gotFailed, gotPaid, unpaid, paid)
	}
	if !errors.Is(err, ErrVSPFeeNotPaid) {
		t.Fatalf("PurchaseTickets error: got %v, want ErrVSPFeeNotPaid", err)
	}
	if msg := err.Error(); !strings.Contains(msg, unpaid) || strings.Contains(msg, paid) {
		t.Errorf("PurchaseTickets error %q: want it to name %s and not %s", msg, unpaid, paid)
	}
}
