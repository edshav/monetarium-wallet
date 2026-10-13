// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/decred/slog"
	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/wire"
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
// the VSP says the ticket can never vote or already has its fee.
func TestVSPReconcileRetriesWhenFeeTxFails(t *testing.T) {
	tests := []struct {
		name      string
		code      types.ErrorCode
		wantRetry bool
	}{
		{"VSP error", types.ErrInternalError, true},
		{"ticket cannot vote", types.ErrTicketCannotVote, false},
		{"fee already received", types.ErrFeeAlreadyReceived, false},
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
			if err := fp.reconcilePayment(); err != nil {
				t.Fatal(err)
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
