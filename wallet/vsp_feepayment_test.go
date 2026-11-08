// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
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
		name      string
		published bool // the job's fee tx is one the wallet published
	}{
		{name: "unpublished fee tx"},
		{name: "published fee tx", published: true},
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
			if got := feeStatus(ctx, t, ticket); got != udb.VSPFeeProcessErrored {
				t.Fatalf("fee status after an expired fee = %v, want errored", got)
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

// TestVSPRejectedFeeTxIsAbandoned checks that a fee tx the VSP rejects is
// removed from the wallet so its inputs can be spent again, and that a new fee
// is requested on the retry, even when the errored status cannot be written.
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
	failVSPWrites(c)
	feeTx := wire.NewMsgTx()
	feeTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: fund.TxHash()}, 1e8, nil))
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
