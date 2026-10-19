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
