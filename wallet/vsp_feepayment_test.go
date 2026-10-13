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
)

// TestVSPProcessDropsCallerFeeTxOnFailure checks that when Process cannot get
// the fee address or make the fee tx, it returns the error and does not leave
// the purchase's fee tx for the scheduled attempt: the purchase unlocks those
// inputs once Process fails and may spend them, and a failed fee tx may have
// outputs but no signatures.
func TestVSPProcessDropsCallerFeeTxOnFailure(t *testing.T) {
	tests := []struct {
		name       string
		feeAddress bool // the VSP quotes a fee
	}{
		{"fee address fails", false},
		{"fee tx fails", true},
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

			if err := c.Process(ctx, ticket, purchaseTx); err == nil {
				t.Fatal("Process: want an error, got nil")
			}
			if tc.feeAddress && len(purchaseTx.TxOut) == 0 {
				t.Fatal("test setup: the fee tx failed before its outputs were written")
			}
			c.mu.Lock()
			fp := c.jobs[*ticket.Hash()]
			c.mu.Unlock()
			if fp == nil {
				t.Fatal("Process did not register the payment")
			}
			fp.stop()
			fp.mu.Lock()
			kept := fp.feeTx == purchaseTx
			fp.mu.Unlock()
			if kept {
				t.Fatal("the scheduled attempt would build on the purchase's fee tx")
			}
		})
	}
}
