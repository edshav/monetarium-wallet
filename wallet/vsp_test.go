// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/decred/slog"
	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/wire"
	werrors "github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// apiError is a reply that makes the vspd client return types.ErrorResponse
// with the given code.
func apiError(code types.ErrorCode) (int, any) {
	return code.HTTPStatus(), types.ErrorResponse{Code: code, Message: code.DefaultMessage()}
}

// testVSPClient returns an unlocked wallet with a VSP client pointed at a fake
// VSP. reply receives the request path and body and returns the HTTP status
// and the JSON body to send back; the fake signs it with its own key, as vspd
// does.
func testVSPClient(ctx context.Context, t *testing.T, reply func(path string, body []byte) (int, any)) *VSPClient {
	t.Helper()

	cfg := basicWalletConfig
	w, teardown := testWallet(ctx, t, &cfg, nil)
	t.Cleanup(teardown)
	if err := w.Unlock(ctx, testPrivPass, nil); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		status, resp := reply(r.URL.Path, body)
		out, _ := json.Marshal(resp)
		rw.Header().Set("VSP-Server-Signature",
			base64.StdEncoding.EncodeToString(ed25519.Sign(priv, out)))
		rw.WriteHeader(status)
		rw.Write(out)
	}))
	t.Cleanup(srv.Close)

	c, err := w.NewVSPClient(VSPClientConfig{
		URL:    srv.URL,
		PubKey: base64.StdEncoding.EncodeToString(pub),
		Policy: &VSPPolicy{MaxFee: 1e8},
	}, slog.Disabled, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, fp := range c.jobs {
			fp.stop()
		}
	})
	return c
}

// testVSPTicket records an unmined ticket purchase in the client's wallet and
// returns it. Its voting and commitment addresses belong to the wallet, so
// requests about it can be signed. id makes each ticket distinct.
func testVSPTicket(ctx context.Context, t *testing.T, c *VSPClient, id byte) *VSPTicket {
	t.Helper()

	addr, err := c.wallet.NewExternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	stakeAddr, ok := addr.(stdaddr.StakeAddress)
	if !ok {
		t.Fatalf("%T is not a stake address", addr)
	}

	const price = 1e8
	tx := wire.NewMsgTx()
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{id}}, price, nil))
	ver, script := stakeAddr.VotingRightsScript()
	tx.AddTxOut(&wire.TxOut{Value: price, Version: ver, PkScript: script})
	ver, script = stakeAddr.RewardCommitmentScript(price, 0, 0)
	tx.AddTxOut(&wire.TxOut{Version: ver, PkScript: script})
	ver, script = stakeAddr.StakeChangeScript()
	tx.AddTxOut(&wire.TxOut{Version: ver, PkScript: script})

	err = walletdb.Update(ctx, c.wallet.db, func(dbtx walletdb.ReadWriteTx) error {
		rec, err := udb.NewTxRecordFromMsgTx(tx, time.Now())
		if err != nil {
			return err
		}
		return c.wallet.txStore.InsertMemPoolTx(dbtx, rec)
	})
	if err != nil {
		t.Fatal(err)
	}

	hash := tx.TxHash()
	return &VSPTicket{
		hash:           &hash,
		rawTx:          tx,
		parentTx:       wire.NewMsgTx(),
		commitmentAddr: stakeAddr,
		votingAddr:     stakeAddr,
		wallet:         c.wallet,
	}
}

// TestVSPExpiredFeeRequestsNewQuote checks that once the VSP reports the fee
// as expired, the next attempt asks the VSP for a new fee amount and address
// instead of paying the expired quote again.
func TestVSPExpiredFeeRequestsNewQuote(t *testing.T) {
	ctx := context.Background()
	var feeAddressCalls atomic.Int32
	c := testVSPClient(ctx, t, func(path string, _ []byte) (int, any) {
		switch path {
		case "/api/v3/payfee":
			return apiError(types.ErrFeeExpired)
		case "/api/v3/feeaddress":
			feeAddressCalls.Add(1)
		}
		return apiError(types.ErrInternalError)
	})
	ticket := testVSPTicket(ctx, t, c, 1)

	feeTx := wire.NewMsgTx()
	feeTx.AddTxOut(wire.NewTxOut(1e7, []byte{0x51}))
	fp := &vspFeePayment{
		client:  c,
		ctx:     ctx,
		ticket:  ticket,
		policy:  c.policy,
		params:  c.wallet.chainParams,
		fee:     1e7,
		feeAddr: ticket.votingAddr,
		feeTx:   feeTx,
	}

	var apiErr types.ErrorResponse
	err := fp.submitPayment()
	if !errors.As(err, &apiErr) || apiErr.Code != types.ErrFeeExpired {
		t.Fatalf("submitPayment: want ErrFeeExpired, got %v", err)
	}

	// The fake VSP refuses the new quote; only the request matters here.
	_ = fp.makeFeeTx(nil)
	if n := feeAddressCalls.Load(); n != 1 {
		t.Fatalf("after an expired fee, the next attempt made %d feeaddress "+
			"requests, want 1", n)
	}
}

// TestVSPReconcileRetriesWhenFeeTxFails checks that a failure to create the
// fee transaction schedules another attempt with a new fee transaction, unless
// the VSP says the ticket can never vote.  When the VSP says it already has the
// fee but cannot report it, the retry asks again.
func TestVSPReconcileRetriesWhenFeeTxFails(t *testing.T) {
	tests := []struct {
		name      string
		code      types.ErrorCode
		wantRetry bool
	}{
		{"VSP error", types.ErrInternalError, true},
		{"ticket cannot vote", types.ErrTicketCannotVote, false},
		{"fee already received", types.ErrFeeAlreadyReceived, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
				return apiError(tc.code)
			})
			// A ticket purchase hands Process a fee tx with inputs, and
			// unlocks them again once Process fails.
			purchaseTx := wire.NewMsgTx()
			purchaseTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{0xca}}, 1e8, nil))
			fp := &vspFeePayment{
				client: c,
				ctx:    ctx,
				ticket: testVSPTicket(ctx, t, c, 1),
				policy: c.policy,
				params: c.wallet.chainParams,
				feeTx:  purchaseTx,
			}
			c.jobs[*fp.ticket.Hash()] = fp

			if err := fp.reconcilePayment(); err == nil {
				t.Fatal("reconcilePayment: want an error from the fake VSP")
			}
			fp.timerMu.Lock()
			retry := fp.timer != nil
			fp.timerMu.Unlock()
			if retry != tc.wantRetry {
				t.Fatalf("retry scheduled = %v, want %v", retry, tc.wantRetry)
			}
			fp.mu.Lock()
			reused := fp.feeTx != nil
			fp.mu.Unlock()
			if retry && reused {
				t.Fatal("the retry would reuse the failed attempt's fee tx")
			}
		})
	}
}

// TestVSPReconcileRetryRequestsNewQuote checks that when the fee transaction
// cannot be created for a fee the client already holds, the retry asks the VSP
// for the fee again, so it learns if the VSP has received one meanwhile.
func TestVSPReconcileRetryRequestsNewQuote(t *testing.T) {
	ctx := context.Background()
	var feeAddressCalls atomic.Int32
	c := testVSPClient(ctx, t, func(path string, _ []byte) (int, any) {
		if path == "/api/v3/feeaddress" {
			feeAddressCalls.Add(1)
		}
		return apiError(types.ErrInternalError)
	})
	ticket := testVSPTicket(ctx, t, c, 1)
	fp := &vspFeePayment{
		client:  c,
		ctx:     ctx,
		ticket:  ticket,
		policy:  c.policy,
		params:  c.wallet.chainParams,
		fee:     1e7,
		feeAddr: ticket.votingAddr,
	}
	c.jobs[*ticket.Hash()] = fp

	// The test wallet has no funds to pay the fee from.
	if err := fp.reconcilePayment(); err == nil {
		t.Fatal("reconcilePayment: want an error from an empty wallet")
	}
	fp.stop()
	_ = fp.makeFeeTx(nil)
	if n := feeAddressCalls.Load(); n != 1 {
		t.Fatalf("after a failed fee tx, the retry made %d feeaddress "+
			"requests, want 1", n)
	}
}

// TestVSPReconcileRetryKeepsFinishedFeeTx checks that a failed attempt keeps a
// fee transaction, and its fee, that a concurrent Process call finished for the
// same ticket while the attempt waited on the VSP. If Process left its fee tx
// unfinished, or a concurrent attempt cleared it, the retry must ask for the
// fee again.
func TestVSPReconcileRetryKeepsFinishedFeeTx(t *testing.T) {
	tests := []struct {
		name      string
		startHash chainhash.Hash // fee hash of the job when the attempt starts
		process   func(fp *vspFeePayment, other *wire.MsgTx)
		wantKept  bool
	}{{
		// Process records the hash once its fee tx is made.
		name: "finished",
		process: func(fp *vspFeePayment, other *wire.MsgTx) {
			fp.feeTx = other
			fp.feeHash = other.TxHash()
		},
		wantKept: true,
	}, {
		// Process builds its fee tx in place in the job, and has not
		// recorded the hash yet.
		name: "unfinished",
		process: func(fp *vspFeePayment, other *wire.MsgTx) {
			fp.feeTx = other
		},
	}, {
		// A concurrent attempt whose fee tx the VSP rejected clears the
		// tx and the hash. The job still holds an earlier, expired fee's
		// hash.
		name:      "failed",
		startHash: chainhash.Hash{0xee},
		process: func(fp *vspFeePayment, _ *wire.MsgTx) {
			fp.feeTx = nil
			fp.feeHash = chainhash.Hash{}
		},
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			other := wire.NewMsgTx()
			other.AddTxOut(wire.NewTxOut(1e7, []byte{0x51}))
			var fp *vspFeePayment
			c := testVSPClient(ctx, t, func(path string, _ []byte) (int, any) {
				if path == "/api/v3/feeaddress" {
					// A concurrent call left a quote in the job.
					fp.mu.Lock()
					fp.fee = 1e7
					tc.process(fp, other)
					fp.mu.Unlock()
				}
				return apiError(types.ErrInternalError)
			})
			fp = &vspFeePayment{
				client:  c,
				ctx:     ctx,
				ticket:  testVSPTicket(ctx, t, c, 1),
				policy:  c.policy,
				params:  c.wallet.chainParams,
				feeHash: tc.startHash,
			}
			c.jobs[*fp.ticket.Hash()] = fp

			if err := fp.reconcilePayment(); err == nil {
				t.Fatal("reconcilePayment: want an error from the fake VSP")
			}
			fp.mu.Lock()
			kept := fp.feeTx == other
			requote := fp.fee == 0
			fp.mu.Unlock()
			if kept != tc.wantKept || requote == tc.wantKept {
				t.Fatalf("concurrent fee tx kept = %v, fee asked "+
					"again = %v; want %v, %v",
					kept, requote, tc.wantKept, !tc.wantKept)
			}
		})
	}
}

// TestVSPProcessManagedTicketsContinuesPastConfirmed checks that a ticket
// whose fee the VSP has already confirmed does not stop the remaining tickets
// from being resumed.
func TestVSPProcessManagedTicketsContinuesPastConfirmed(t *testing.T) {
	ctx := context.Background()
	var confirmedHash string // set once the ticket exists
	c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
		if path != "/api/v3/ticketstatus" {
			return apiError(types.ErrInternalError)
		}
		var req types.TicketStatusRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return apiError(types.ErrBadRequest)
		}
		if req.TicketHash == confirmedHash {
			return http.StatusOK, types.TicketStatusResponse{
				FeeTxStatus: "confirmed",
				FeeTxHash:   chainhash.Hash{0xfe}.String(),
				Request:     body,
			}
		}
		return http.StatusOK, types.TicketStatusResponse{
			FeeTxStatus: "none",
			Request:     body,
		}
	})
	confirmed := testVSPTicket(ctx, t, c, 1)
	unpaid := testVSPTicket(ctx, t, c, 2)
	confirmedHash = confirmed.Hash().String()

	err := c.ProcessManagedTickets(ctx, []*VSPTicket{confirmed, unpaid})
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	_, resumed := c.jobs[*unpaid.Hash()]
	c.mu.Unlock()
	if !resumed {
		t.Fatal("the unpaid ticket after a confirmed one was not resumed")
	}
}

// TestVSPFeeChangeSpendableOnceBroadcast checks that the change of a fee tx
// is not spent at minconf 0 while the VSP only holds the fee tx.  The VSP
// broadcasts a received fee tx once the ticket has enough confirmations, and
// until then the network does not know it: a ticket split funded from its
// change was rejected as an orphan (issue #8).  Once the VSP reports this fee
// tx as broadcast, its change may be spent.
func TestVSPFeeChangeSpendableOnceBroadcast(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    string
		otherTx   bool // the VSP reports a fee tx other than the wallet's
		wantSpend bool
	}{
		{name: "received", status: "received"},
		{name: "broadcast", status: "broadcast", wantSpend: true},
		{name: "broadcast other tx", status: "broadcast", otherTx: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var feeHash chainhash.Hash // set once the fee tx exists
			c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				switch path {
				case "/api/v3/payfee":
					// The fee tx was already submitted once.
					return apiError(types.ErrFeeAlreadyReceived)
				case "/api/v3/ticketstatus":
					vspFeeHash := feeHash
					if tc.otherTx {
						vspFeeHash = chainhash.Hash{0xfe}
					}
					return http.StatusOK, types.TicketStatusResponse{
						FeeTxStatus: tc.status,
						FeeTxHash:   vspFeeHash.String(),
						Request:     body,
					}
				}
				return apiError(types.ErrInternalError)
			})
			w := c.wallet
			ticket := testVSPTicket(ctx, t, c, 1)

			// Fund the fee tx from an output of the wallet.
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
			if err := w.CreateVspPayment(ctx, feeTx, 1e7, ticket.votingAddr, 0, 0); err != nil {
				t.Fatal(err)
			}
			feeHash = feeTx.TxHash()

			fp := &vspFeePayment{
				client:  c,
				ctx:     ctx,
				ticket:  ticket,
				policy:  c.policy,
				params:  w.chainParams,
				fee:     1e7,
				feeAddr: ticket.votingAddr,
				feeTx:   feeTx,
				feeHash: feeHash,
			}
			c.jobs[*ticket.Hash()] = fp // stopped on cleanup
			next := txNotifications(t, w)
			if err := fp.reconcilePayment(); err != nil {
				t.Fatal(err)
			}

			// Only the broadcast of the wallet's fee tx notifies it, once;
			// the sentinel comes next.
			sentinel := walletPayment(ctx, t, w, cointype.CoinTypeVAR)(3)
			if err := w.AddTransaction(ctx, sentinel, nil); err != nil {
				t.Fatal(err)
			}
			want := []chainhash.Hash{sentinel.TxHash()}
			if tc.wantSpend {
				want = []chainhash.Hash{feeHash, sentinel.TxHash()}
			}
			for _, h := range want {
				if got := next(); len(got) != 1 || got[0] != h {
					t.Fatalf("notified %v, want %v", got, h)
				}
			}

			// Spend everything the wallet has at minconf 0.
			var spent bool
			err = walletdb.View(ctx, w.db, func(dbtx walletdb.ReadTx) error {
				_, tip := w.txStore.MainChainTip(dbtx)
				src := w.txStore.MakeInputSourceWithCoinType(dbtx, 0, 0,
					tip, nil, cointype.CoinTypeVAR)
				detail, err := src.SelectInputs(0, cointype.Zero())
				if err != nil {
					return err
				}
				for _, in := range detail.Inputs {
					spent = spent || in.PreviousOutPoint.Hash == feeHash
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if spent != tc.wantSpend {
				t.Fatalf("fee tx change spent at minconf 0 = %v, want %v",
					spent, tc.wantSpend)
			}
		})
	}
}

// TestVSPUpdateMaxFeeRaisesRunningJobCap checks that UpdateMaxFee raises the
// cap that an existing fee job checks the VSP's quote against, never lowers
// it, and is safe to call while a job reads the cap (run with -race).
func TestVSPUpdateMaxFeeRaisesRunningJobCap(t *testing.T) {
	ctx := context.Background()
	const quote = 2e8 // above testVSPClient's MaxFee of 1e8
	var feeAddr string
	c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
		if path != "/api/v3/feeaddress" {
			return apiError(types.ErrInternalError)
		}
		return http.StatusOK, types.FeeAddressResponse{
			Timestamp:  time.Now().Unix(),
			FeeAddress: feeAddr,
			FeeAmount:  quote,
			Expiration: time.Now().Add(time.Hour).Unix(),
			Request:    body,
		}
	})
	ticket := testVSPTicket(ctx, t, c, 1)
	feeAddr = ticket.votingAddr.String()

	// Process reuses this job, whose scheduled attempt is stopped so that it
	// cannot run during the test.
	fp := c.feePayment(ctx, ticket, false)
	fp.stop()

	// The refusal is checked by its message.
	err := c.Process(ctx, ticket, nil)
	if err == nil || !strings.Contains(err.Error(), "server fee amount too high") {
		t.Fatalf("Process: want the fee cap refusal, got %v", err)
	}
	info, err := ticket.VSPTicketInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := udb.FeeStatus(info.FeeTxStatus); got != udb.VSPFeeProcessErrored {
		t.Fatalf("fee status after the refusal = %v, want errored", got)
	}
	fp.mu.Lock()
	refused := fp.fee
	fp.mu.Unlock()
	if refused != 0 {
		t.Fatalf("the refused quote %v was kept", refused)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.UpdateMaxFee(quote) // the cap equal to the quote accepts it
	}()
	_ = fp.receiveFeeAddress() // races UpdateMaxFee; either outcome is fine
	<-done

	if err := fp.receiveFeeAddress(); err != nil {
		t.Fatalf("quote within the raised cap: %v", err)
	}
	if fp.fee != quote {
		t.Fatalf("fee = %v, want %v", fp.fee, quote)
	}
	c.UpdateMaxFee(1)
	if got := c.maxFee(); got != quote {
		t.Fatalf("UpdateMaxFee lowered the cap to %v", got)
	}
}

// TestVSPFeeJobUsesLifetime checks that a fee job started after SetLifetime
// runs under that context, not the caller's request context.
func TestVSPFeeJobUsesLifetime(t *testing.T) {
	ctx := context.Background()
	c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
		return apiError(types.ErrInternalError)
	})
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	c.SetLifetime(life)
	c.SetLifetime(nil)

	first := testVSPTicket(ctx, t, c, 1)
	fp := c.feePayment(ctx, first, false)
	fp.stop()
	if fp.ctx != life {
		t.Fatalf("fee job context is %v, want the lifetime context", fp.ctx)
	}
	// Ending the lifetime ends the job's VSP requests but keeps the job, so
	// Process on this client reuses it and fails too.
	cancel()
	if err := fp.receiveFeeAddress(); !errors.Is(err, context.Canceled) {
		t.Fatalf("VSP request after the lifetime ended: want context.Canceled, got %v", err)
	}
	if err := c.Process(ctx, first, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Process after the lifetime ended: want context.Canceled, got %v", err)
	}
	c.mu.Lock()
	kept := c.jobs[*first.Hash()] == fp
	c.mu.Unlock()
	if !kept {
		t.Fatal("ending the lifetime removed the job")
	}

	// SetLifetime may run while a job starts (checked by -race).
	ticket := testVSPTicket(ctx, t, c, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.SetLifetime(life)
	}()
	_ = c.feePayment(ctx, ticket, false)
	<-done
}

// growDB writes enough to make bbolt remap the database file, which waits for
// every open read transaction to end.
func growDB(ctx context.Context, w *Wallet, bucket string) error {
	return walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
		b, err := dbtx.CreateTopLevelBucket([]byte(bucket))
		if err != nil {
			return err
		}
		return b.Put([]byte("k"), make([]byte, 16<<20))
	})
}

// TestVSPTicketLookups checks VSPTicket, ForEachVSPTicket and TxUnpublished
// against a ticket whose fee payment has started. A returned record must not
// alias database memory, and the ForEachVSPTicket callback must be able to use
// the wallet, including writes that grow the database.
func TestVSPTicketLookups(t *testing.T) {
	ctx := context.Background()
	c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
		return apiError(types.ErrInternalError)
	})
	w := c.wallet
	// Enough hosts that the pubkey bucket is stored in its own pages rather
	// than inline, so its values are read straight from the database map.
	err := walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
		for i := range 64 {
			host := []byte(fmt.Sprintf("https://vsp%d.example", i))
			err := udb.SetVSPPubKey(dbtx, host, &udb.VSPPubKey{ID: 1000 + uint32(i), PubKey: c.PubKey})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Two tickets, each with its own fee hash and status, the first a
	// non-zero one.
	ticket := testVSPTicket(ctx, t, c, 1)
	feeHash := chainhash.Hash{0xfe}
	if err := ticket.UpdateFeePaid(ctx, feeHash, c.URL, c.PubKey); err != nil {
		t.Fatal(err)
	}
	other := testVSPTicket(ctx, t, c, 2)
	if err := other.UpdateFeeStarted(ctx, chainhash.Hash{0xfd}, c.URL, c.PubKey); err != nil {
		t.Fatal(err)
	}
	type fee struct {
		hash   chainhash.Hash
		status udb.FeeStatus
	}
	want := map[chainhash.Hash]fee{
		*ticket.Hash(): {feeHash, udb.VSPFeeProcessPaid},
		*other.Hash():  {chainhash.Hash{0xfd}, udb.VSPFeeProcessStarted},
	}

	rec, err := w.VSPTicket(ctx, ticket.Hash())
	if err != nil {
		t.Fatal(err)
	}
	if rec.FeeHash != feeHash || rec.Host != c.URL || !bytes.Equal(rec.PubKey, c.PubKey) ||
		rec.FeeTxStatus != uint32(udb.VSPFeeProcessPaid) {
		t.Fatalf("VSPTicket = %+v", rec)
	}
	// The record is the caller's: a slice into the read-only database map
	// would fault here.
	rec.PubKey[0] ^= 0xff

	// A deadlocked database cannot be closed by the test cleanup either, so
	// end the process from outside the test goroutine.
	timer := time.AfterFunc(time.Minute, func() {
		panic("ForEachVSPTicket callback deadlocked on the database")
	})
	seen := make(map[chainhash.Hash]bool)
	err = w.ForEachVSPTicket(ctx, func(h chainhash.Hash, rec *udb.VSPTicket) error {
		wantFee, ok := want[h]
		if !ok || seen[h] || rec.FeeHash != wantFee.hash || udb.FeeStatus(rec.FeeTxStatus) != wantFee.status {
			t.Errorf("ForEachVSPTicket visited %v with %+v", h, rec)
		}
		seen[h] = true
		if _, err := w.TxUnpublished(ctx, &h); err != nil {
			return err
		}
		if len(seen) > 1 {
			return nil
		}
		return growDB(ctx, w, "testgrow")
	})
	timer.Stop()
	if err != nil || len(seen) != len(want) {
		t.Fatalf("ForEachVSPTicket: err %v, visited %d, want %d", err, len(seen), len(want))
	}

	for _, published := range []bool{false, true} {
		if err := w.SetPublished(ctx, ticket.Hash(), published); err != nil {
			t.Fatal(err)
		}
		unpublished, err := w.TxUnpublished(ctx, ticket.Hash())
		if err != nil {
			t.Fatal(err)
		}
		if unpublished == published {
			t.Fatalf("TxUnpublished = %v after SetPublished(%v)", unpublished, published)
		}
	}
	if _, err := w.TxUnpublished(ctx, &chainhash.Hash{0xaa}); !werrors.Is(err, werrors.NotExist) {
		t.Fatalf("TxUnpublished of an unknown tx: %v, want NotExist", err)
	}
	if _, err := w.VSPTicket(ctx, &chainhash.Hash{0xaa}); !werrors.Is(err, werrors.NotExist) {
		t.Fatalf("VSPTicket of an unknown ticket: %v, want NotExist", err)
	}

	errStop := errors.New("stop")
	err = w.ForEachVSPTicket(ctx, func(chainhash.Hash, *udb.VSPTicket) error {
		return errStop
	})
	if !errors.Is(err, errStop) {
		t.Fatalf("ForEachVSPTicket returned %v, want the callback's error", err)
	}

	if err := w.db.Close(); err != nil {
		t.Fatal(err)
	}
	err = w.ForEachVSPTicket(ctx, func(chainhash.Hash, *udb.VSPTicket) error {
		t.Error("callback ran on a closed database")
		return nil
	})
	if err == nil {
		t.Fatal("ForEachVSPTicket on a closed database returned nil")
	}
}

// TestVSPSetVoteChoiceTreasuryPolicy checks that SetVoteChoice compares the
// wallet's treasury policy against the VSP's treasury policy map (not the
// tspend policy map, whose keys are tspend hashes rather than treasury
// pubkeys), and only signs a setvotechoices request when the two differ.
func TestVSPSetVoteChoiceTreasuryPolicy(t *testing.T) {
	// A treasury policy key is the hex of a 33-byte treasury pubkey.
	const pubkey = "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122"
	walletPolicy := map[string]string{pubkey: "yes"}

	tests := []struct {
		name     string
		vspHas   map[string]string
		wantSets int32
	}{
		{"policy already in sync", walletPolicy, 0},
		{"policy differs", map[string]string{pubkey: "no"}, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var statuses, sets atomic.Int32
			c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				switch path {
				case "/api/v3/ticketstatus":
					statuses.Add(1)
					return http.StatusOK, types.TicketStatusResponse{
						TreasuryPolicy: tc.vspHas,
						Request:        body,
					}
				case "/api/v3/setvotechoices":
					sets.Add(1)
					var req types.SetVoteChoicesRequest
					if err := json.Unmarshal(body, &req); err != nil {
						t.Errorf("setvotechoices body: %v", err)
					}
					if len(req.TreasuryPolicy) != len(walletPolicy) ||
						req.TreasuryPolicy[pubkey] != walletPolicy[pubkey] {
						t.Errorf("setvotechoices treasury policy = %v, want the "+
							"wallet's %v", req.TreasuryPolicy, walletPolicy)
					}
					return http.StatusOK, types.SetVoteChoicesResponse{Request: body}
				}
				return apiError(types.ErrInternalError)
			})
			ticket := testVSPTicket(ctx, t, c, 1)

			// Empty, not nil, vote choices: a real VSP rejects
			// "votechoices": null.
			err := c.SetVoteChoice(ctx, ticket, map[string]string{}, nil, walletPolicy)
			if err != nil {
				t.Fatalf("SetVoteChoice: %v", err)
			}

			// SetVoteChoice returns nil even when the status check fails, so
			// require exactly one ticketstatus call to catch a broken fake
			// reply making the in-sync case pass vacuously.
			if n := statuses.Load(); n != 1 {
				t.Fatalf("made %d ticketstatus requests, want 1", n)
			}
			if n := sets.Load(); n != tc.wantSets {
				t.Fatalf("made %d setvotechoices requests, want %d", n, tc.wantSets)
			}
		})
	}
}
