// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/decred/slog"
	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// TestVSPCatchUpAttemptWaitsForRescan checks a fee job whose ticket is pruned
// by a block connected without its txs, as during catch-up, for its price or
// for its tx's expiry height.  Each step that checks the ticket waits: it sends
// nothing to the VSP, reschedules itself, or reconcilePayment for the steps
// before payment, and keeps the job, the fee tx and the record.  Once the
// processed-txs marker reaches the tip, the scheduled attempt decides: a ticket
// the rescan recorded as mined gets its fee paid, whether or not the VSP already
// held it, and a ticket still gone has its job removed and its fee tx freed.
func TestVSPCatchUpAttemptWaitsForRescan(t *testing.T) {
	type row struct {
		step     string // "process", "reconcile", "confirm" or "process paid"
		vspHolds bool   // the VSP holds the fee tx before the prune
		mined    bool   // the rescan records the ticket as mined
		reason   string // "price" or "expiry"
	}
	var rows []row
	for _, step := range []string{"process", "reconcile", "confirm", "process paid"} {
		for _, vspHolds := range []bool{false, true} {
			for _, mined := range []bool{false, true} {
				rows = append(rows, row{step, vspHolds, mined, "price"})
			}
		}
		for _, mined := range []bool{false, true} {
			rows = append(rows, row{step, false, mined, "expiry"})
		}
	}
	for _, tc := range rows {
		name := fmt.Sprintf("%s, VSP holds %v, mined %v, %s", tc.step, tc.vspHolds, tc.mined, tc.reason)
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			var ticket *VSPTicket
			var waiting, received atomic.Bool
			var heldHash atomic.Value   // chainhash.Hash
			var firstAfter atomic.Value // string: the first request after the rescan
			var rescanned atomic.Bool
			received.Store(tc.vspHolds)
			c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				if waiting.Load() {
					t.Errorf("VSP request %s while the wallet catches up", path)
				}
				if rescanned.Load() {
					firstAfter.CompareAndSwap(nil, path)
				}
				switch path {
				case "/api/v3/feeaddress":
					if received.Load() {
						return apiError(types.ErrFeeAlreadyReceived)
					}
					return testFeeAddressReply(ticket, body)
				case "/api/v3/payfee":
					hash, ok := testPaidFee(body)
					if !ok {
						return apiError(types.ErrBadRequest)
					}
					if received.Load() {
						return apiError(types.ErrFeeAlreadyReceived)
					}
					heldHash.Store(hash)
					received.Store(true)
					return http.StatusOK, types.PayFeeResponse{Request: body}
				case "/api/v3/ticketstatus":
					// "error": the VSP holds no fee it can broadcast.
					status := "error"
					if received.Load() {
						status = "received"
					}
					held, _ := heldHash.Load().(chainhash.Hash)
					return http.StatusOK, types.TicketStatusResponse{
						FeeTxStatus: status,
						FeeTxHash:   held.String(),
						Request:     body,
					}
				}
				return apiError(types.ErrInternalError)
			})
			w := c.wallet
			logs := &vspLogLines{}
			c.log = slog.NewBackend(logs).Logger("VSP")
			c.log.SetLevel(slog.LevelDebug)
			walletLogs := testWalletLog(t)

			f := &vspPaymentFixture{w: w, cfg: basicWalletConfig,
				tip: basicWalletConfig.Params.GenesisBlock.Header}
			op := wire.OutPoint{Hash: f.fund(ctx, t, true, 1e8).TxHash()}
			expiry := uint32(wire.NoExpiryValue)
			if tc.reason == "expiry" {
				// Price checks pass; the tx expires two blocks on.
				f.sbits = 1e8
				expiry = uint32(f.tip.Height) + 2
			}
			ticket = testVSPTicketExpiring(ctx, t, c, wire.OutPoint{Hash: chainhash.Hash{1}}, expiry)
			fee := wire.NewMsgTx()
			fee.AddTxIn(wire.NewTxIn(&op, 1e8, nil))
			if err := w.CreateVspPayment(ctx, fee, 1e7, ticket.votingAddr, 0, 0); err != nil {
				t.Fatal(err)
			}
			feeHash := fee.TxHash()
			heldHash.Store(feeHash)
			paid := tc.step == "confirm" || tc.step == "process paid"
			record := ticket.UpdateFeeStarted
			if paid {
				record = ticket.UpdateFeePaid
			}
			if err := record(ctx, feeHash, c.URL, c.PubKey); err != nil {
				t.Fatal(err)
			}
			var fp *vspFeePayment
			if tc.step == "reconcile" || tc.step == "confirm" {
				// The job a restart makes from the record.
				fp = c.feePayment(ctx, ticket, paid)
				fp.stop()
			}

			// Blocks connected without their txs prune the ticket.
			switch tc.reason {
			case "price":
				f.mineEmpty(ctx, t, 1)
			case "expiry":
				f.mineEmpty(ctx, t, 2)
			}
			if !ticket.Pruned(ctx) {
				t.Fatal("the ticket is not pruned")
			}
			if rp, err := w.RescanPoint(ctx); err != nil || rp == nil {
				t.Fatalf("rescan point %v, %v; want one", rp, err)
			}
			recBefore, err := ticket.VSPTicketInfo(ctx)
			if err != nil {
				t.Fatal(err)
			}

			// The attempt during catch-up.
			waiting.Store(true)
			switch tc.step {
			case "process", "process paid":
				err = c.Process(ctx, ticket, nil)
				fp = testJob(c, ticket)
			case "reconcile", "confirm":
				// As the job's timer runs it.
				name, method := "reconcile payment", fp.reconcilePayment
				if tc.step == "confirm" {
					name, method = "confirm payment", fp.confirmPayment
				}
				fp.task(name, method)()
				fp.mu.Lock()
				err = fp.err
				fp.mu.Unlock()
			}
			waiting.Store(false)
			if !errors.Is(err, errCatchingUp) {
				t.Fatalf("attempt: %v; want errCatchingUp", err)
			}
			if fp == nil || testJob(c, ticket) != fp {
				t.Fatal("the job is not kept")
			}
			wantNext := "Scheduling reconcile payment"
			if paid {
				wantNext = "Scheduling confirm payment"
			}
			if got := testLastScheduled(logs); got != wantNext || !timerSet(fp) {
				t.Fatalf("%q, timer set %v; want %q", got, timerSet(fp), wantNext)
			}
			retry := testTakeScheduled(t, fp)
			rec, err := ticket.VSPTicketInfo(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if rec.FeeHash != recBefore.FeeHash || rec.FeeTxStatus != recBefore.FeeTxStatus ||
				!testHoldsUnmined(ctx, t, w, feeHash) {
				t.Fatalf("record %+v, want %+v; fee tx held %v", rec, recBefore,
					testHoldsUnmined(ctx, t, w, feeHash))
			}
			if strings.Contains(logs.String()+walletLogs.String(), "[ERR]") {
				t.Fatalf("an error is logged while the wallet catches up:\n%s%s", logs, walletLogs)
			}

			// The rescan records every block, and the ticket if it was mined.
			if tc.mined {
				f.mine(ctx, t, ticket.rawTx)
			}
			err = walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
				tip, _ := w.txStore.MainChainTip(dbtx)
				return w.txStore.UpdateProcessedTxsBlockMarker(dbtx, &tip)
			})
			if err != nil {
				t.Fatal(err)
			}

			// The scheduled attempts, run in the timer's place until the job
			// is removed or waits for the VSP to broadcast the fee.  The first
			// is the step that waited: an unpaid record's pays the fee tx the
			// record names, and a paid record's asks the fee's status.
			rescanned.Store(true)
			last := retry()
			wantFirst := ""
			if tc.mined {
				wantFirst = "/api/v3/payfee"
				if paid {
					wantFirst = "/api/v3/ticketstatus"
				}
			}
			if got, _ := firstAfter.Load().(string); got != wantFirst {
				t.Fatalf("first VSP request after the rescan %q, want %q", got, wantFirst)
			}
			for range 3 {
				if errors.Is(last, errStopped) || testJob(c, ticket) == nil ||
					received.Load() && testLastScheduled(logs) == "Scheduling confirm payment" {
					break
				}
				last = testRunScheduled(t, fp)
			}
			fp.stop()

			rec, err = ticket.VSPTicketInfo(ctx)
			if err != nil {
				t.Fatalf("the ticket's VSP record: %v", err)
			}
			if !tc.mined {
				if !errors.Is(last, errStopped) || testJob(c, ticket) != nil {
					t.Fatalf("last attempt %v; the job of a ticket still gone is kept %v",
						last, testJob(c, ticket) != nil)
				}
				if testHoldsUnmined(ctx, t, w, feeHash) || !testUnspentOutputs(ctx, t, w)[op] {
					t.Fatal("the fee tx of a ticket still gone is not freed")
				}
				return
			}
			held, _ := heldHash.Load().(chainhash.Hash)
			if last != nil || !received.Load() || testJob(c, ticket) == nil {
				t.Fatalf("last attempt %v; VSP holds the fee %v; job kept %v",
					last, received.Load(), testJob(c, ticket) != nil)
			}
			if rec.FeeTxStatus != uint32(udb.VSPFeeProcessPaid) || rec.FeeHash != held {
				t.Fatalf("record %+v, want paid with the VSP's %v", rec, held)
			}
		})
	}
}

// testWalletLog sends the package logger to the returned lines until the test
// ends.
func testWalletLog(t *testing.T) *vspLogLines {
	lines := &vspLogLines{}
	old := log
	UseLogger(slog.NewBackend(lines).Logger("WLLT"))
	t.Cleanup(func() { UseLogger(old) })
	return lines
}

// TestVSPUnprocessedTicketDuringCatchUp checks ProcessUnprocessedTickets for a
// ticket pruned during catch-up: the Process call waits for the rescan, and
// its error is not logged as one.
func TestVSPUnprocessedTicketDuringCatchUp(t *testing.T) {
	ctx := context.Background()
	c := testVSPClient(ctx, t, func(path string, _ []byte) (int, any) {
		t.Errorf("VSP request %s while the wallet catches up", path)
		return apiError(types.ErrInternalError)
	})
	w := c.wallet
	logs := &vspLogLines{}
	c.log = slog.NewBackend(logs).Logger("VSP")
	ticket := testVSPTicket(ctx, t, c, 1)
	f := &vspPaymentFixture{w: w, cfg: basicWalletConfig,
		tip: basicWalletConfig.Params.GenesisBlock.Header}
	f.mineEmpty(ctx, t, 1)
	if !ticket.Pruned(ctx) {
		t.Fatal("the ticket is not pruned")
	}
	c.ProcessUnprocessedTickets(ctx, []*VSPTicket{ticket})
	fp := testJob(c, ticket)
	if fp == nil || !timerSet(fp) {
		t.Fatal("no job waits for the rescan")
	}
	fp.stop()
	if strings.Contains(logs.String(), "[ERR]") {
		t.Fatalf("an error is logged:\n%s", logs)
	}
}

// TestVSPTaskLogLevel checks that a job's scheduled attempt logs a wait for
// the rescan at debug level and any other error as an error.
func TestVSPTaskLogLevel(t *testing.T) {
	for _, tc := range []struct {
		err     error
		wantErr bool
	}{
		{err: errCatchingUp},
		{err: errors.New("VSP unreachable"), wantErr: true},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			ctx := context.Background()
			c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
				return apiError(types.ErrInternalError)
			})
			logs := &vspLogLines{}
			c.log = slog.NewBackend(logs).Logger("VSP")
			c.log.SetLevel(slog.LevelDebug)
			fp := c.feePayment(ctx, testVSPTicket(ctx, t, c, 1), false)
			fp.stop()
			fp.task("attempt", func() error { return tc.err })()
			if logged := strings.Contains(logs.String(), "[ERR] VSP: Ticket"); logged != tc.wantErr {
				t.Fatalf("error logged = %v, want %v:\n%s", logged, tc.wantErr, logs)
			}
			if !strings.Contains(logs.String(), tc.err.Error()) {
				t.Fatalf("the error is not logged:\n%s", logs)
			}
		})
	}
}

// TestVSPScheduleTimerRunsTask checks that the job's timer runs the task the
// job keeps, which the other tests run in the timer's place.
func TestVSPScheduleTimerRunsTask(t *testing.T) {
	ctx := context.Background()
	c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
		return apiError(types.ErrInternalError)
	})
	fp := c.feePayment(ctx, testVSPTicket(ctx, t, c, 1), false)
	fp.stop()
	ran := make(chan struct{}, 1)
	fp.schedule("attempt", func() error {
		select {
		case ran <- struct{}{}:
		default:
		}
		return nil
	})
	defer fp.stop()
	// Fire it now, not after the job's random delay.
	fp.timerMu.Lock()
	fp.timer.Reset(0)
	fp.timerMu.Unlock()
	select {
	case <-ran:
	case <-time.After(time.Minute):
		t.Fatal("the timer did not run the scheduled attempt")
	}
}

// failViewsDB fails the views, or with writes the updates, opened under a
// function whose name contains under, while fail is set.
type failViewsDB struct {
	walletdb.DB
	under  string
	writes bool
	fail   atomic.Bool
}

func (d *failViewsDB) failing() bool {
	if !d.fail.Load() {
		return false
	}
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(3, pcs)])
	for {
		f, more := frames.Next()
		if strings.Contains(f.Function, d.under) {
			return true
		}
		if !more {
			return false
		}
	}
}

func (d *failViewsDB) BeginReadTx() (walletdb.ReadTx, error) {
	if !d.writes && d.failing() {
		return nil, errors.New("view fails")
	}
	return d.DB.BeginReadTx()
}

func (d *failViewsDB) BeginReadWriteTx() (walletdb.ReadWriteTx, error) {
	if d.writes && d.failing() {
		return nil, errors.New("update fails")
	}
	return d.DB.BeginReadWriteTx()
}

// TestVSPTicketHeightsLogLevel checks calcHeights' log: none for a ticket the
// wallet lacks, an error when the wallet cannot be read.
func TestVSPTicketHeightsLogLevel(t *testing.T) {
	for _, fails := range []bool{false, true} {
		t.Run(fmt.Sprintf("view fails %v", fails), func(t *testing.T) {
			ctx := context.Background()
			c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
				return apiError(types.ErrInternalError)
			})
			w := c.wallet
			ticket := testVSPTicket(ctx, t, c, 1)
			if err := w.AbandonTransaction(ctx, ticket.Hash()); err != nil {
				t.Fatal(err)
			}
			if fails {
				d := &failViewsDB{DB: w.db, under: ".(*VSPTicket).calcHeights"}
				d.fail.Store(true)
				w.db = d
				t.Cleanup(func() { w.db = d.DB })
			}
			logs := testWalletLog(t)
			if ticket.ExpiryHeight(ctx) != 0 {
				t.Fatal("a ticket the wallet lacks has an expiry height")
			}
			if logged := strings.Contains(logs.String(), "[ERR]"); logged != fails {
				t.Fatalf("error logged = %v, want %v:\n%s", logged, fails, logs)
			}
		})
	}
}

// TestVSPCatchUpRetriesOwnFeeTxAbandon checks the own fee tx the VSP replaced,
// for a ticket missing during catch-up: an abandon that fails to read or to
// update the wallet keeps it the job's, and the next attempt abandons and
// forgets it.  One another ticket's record names is forgotten and kept.
func TestVSPCatchUpRetriesOwnFeeTxAbandon(t *testing.T) {
	for _, fails := range []string{"view", "update", "another ticket's"} {
		t.Run(fails, func(t *testing.T) {
			testVSPCatchUpRetriesOwnFeeTxAbandon(t, fails)
		})
	}
}

func testVSPCatchUpRetriesOwnFeeTxAbandon(t *testing.T, fails string) {
	ctx := context.Background()
	c := testVSPClient(ctx, t, func(path string, _ []byte) (int, any) {
		t.Errorf("VSP request %s while the wallet catches up", path)
		return apiError(types.ErrInternalError)
	})
	w := c.wallet
	op := testWalletOutput(ctx, t, w, 2)
	ticket := testVSPTicket(ctx, t, c, 1)
	own := wire.NewMsgTx()
	own.AddTxIn(wire.NewTxIn(op, 1e8, nil))
	if err := w.CreateVspPayment(ctx, own, 1e7, ticket.votingAddr, 0, 0); err != nil {
		t.Fatal(err)
	}
	ownHash := own.TxHash()
	// The VSP named another fee tx, as recordReceivedFee leaves it.
	vspHash := chainhash.Hash{0xfe}
	if err := ticket.UpdateFeePaid(ctx, vspHash, c.URL, c.PubKey); err != nil {
		t.Fatal(err)
	}
	fp := c.feePayment(ctx, ticket, true)
	fp.stop()
	fp.mu.Lock()
	fp.feeHash, fp.ownFeeHash = vspHash, ownHash
	fp.mu.Unlock()

	f := &vspPaymentFixture{w: w, cfg: basicWalletConfig,
		tip: basicWalletConfig.Params.GenesisBlock.Header}
	f.mineEmpty(ctx, t, 1)
	d := &failViewsDB{DB: w.db, under: ".(*VSPClient).abandonFeeTx", writes: fails == "update"}
	w.db = d
	t.Cleanup(func() { w.db = d.DB })
	if fails == "another ticket's" {
		other := testVSPTicket(ctx, t, c, 3)
		if err := other.UpdateFeeStarted(ctx, ownHash, c.URL, c.PubKey); err != nil {
			t.Fatal(err)
		}
	}

	attempt := func() {
		t.Helper()
		fp.procMu.Lock()
		err := fp.confirmPayment()
		fp.procMu.Unlock()
		fp.stop()
		if !errors.Is(err, errCatchingUp) {
			t.Fatalf("attempt: %v; want errCatchingUp", err)
		}
	}
	keeps := func() bool {
		fp.mu.Lock()
		defer fp.mu.Unlock()
		return fp.ownFeeHash == ownHash
	}
	if fails == "another ticket's" {
		attempt()
		if keeps() || !testHoldsUnmined(ctx, t, w, ownHash) {
			t.Fatalf("the job keeps the own fee tx %v, the wallet holds it %v; want false, true",
				keeps(), testHoldsUnmined(ctx, t, w, ownHash))
		}
		return
	}
	d.fail.Store(true)
	attempt()
	if !keeps() || !testHoldsUnmined(ctx, t, w, ownHash) {
		t.Fatalf("after a failed abandon: the job keeps the own fee tx %v, the wallet holds it %v",
			keeps(), testHoldsUnmined(ctx, t, w, ownHash))
	}
	d.fail.Store(false)
	attempt()
	if keeps() || testHoldsUnmined(ctx, t, w, ownHash) || !testUnspentOutputs(ctx, t, w)[*op] {
		t.Fatal("the next attempt does not abandon the own fee tx")
	}
}
