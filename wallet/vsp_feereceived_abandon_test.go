// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/wire"
)

// TestVSPFeeAlreadyReceivedAbandonsOwnFeeTx checks the job's own fee tx when
// Process learns that the VSP already holds a fee tx for the ticket.  If the
// VSP names another tx, the job's unpublished fee tx is abandoned, so its
// input is spendable again.  It is kept when the VSP names it, when it was
// published, and when the VSP's tx is not learned or recorded: the status
// request fails or names no fee tx, or recording its hash fails.  After an
// abandon, the account balance is back to what it was before the job's tx.  A tx the job knows only by its fee hash, which may be one
// the VSP named for another ticket, is kept.
func TestVSPFeeAlreadyReceivedAbandonsOwnFeeTx(t *testing.T) {
	for _, tc := range []struct {
		name        string
		vspNamesOwn bool // the VSP's fee tx is the job's
		published   bool
		hashOnly    bool                         // the job holds the tx's hash but not the tx
		status      func(body []byte) (int, any) // nil: the VSP's fee tx, received
		failWrites  bool                         // recording the VSP's hash fails
		wantUnspent bool
	}{
		{name: "VSP names another fee tx", wantUnspent: true},
		{name: "VSP names the job's fee tx", vspNamesOwn: true},
		{name: "job's fee tx published", published: true},
		{name: "fee hash without the tx", hashOnly: true},
		{name: "status request fails", status: func([]byte) (int, any) {
			return apiError(types.ErrInternalError)
		}},
		{name: "VSP names no fee tx", status: func(body []byte) (int, any) {
			return http.StatusOK, types.TicketStatusResponse{FeeTxStatus: "received", Request: body}
		}},
		{name: "recording the VSP's hash fails", failWrites: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			vspFeeHash := chainhash.Hash{0xfe}
			c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				// failVSPWrites lengthens the URL's path.
				path = path[strings.Index(path, "/api/v3/"):]
				switch path {
				case "/api/v3/feeaddress":
					return apiError(types.ErrFeeAlreadyReceived)
				case "/api/v3/ticketstatus":
					if tc.status != nil {
						return tc.status(body)
					}
					return http.StatusOK, types.TicketStatusResponse{
						FeeTxStatus: "received",
						FeeTxHash:   vspFeeHash.String(),
						Request:     body,
					}
				}
				return apiError(types.ErrInternalError)
			})
			w := c.wallet
			ticket := testVSPTicket(ctx, t, c, 1)

			// A fee tx an earlier attempt made and recorded unpublished.
			op := testWalletOutput(ctx, t, w, 2)
			before := testSpendable(ctx, t, w)
			own := wire.NewMsgTx()
			own.AddTxIn(wire.NewTxIn(op, 1e8, nil))
			if err := w.CreateVspPayment(ctx, own, 1e7, ticket.votingAddr, 0, 0); err != nil {
				t.Fatal(err)
			}
			ownHash := own.TxHash()
			if tc.published {
				if err := w.SetPublished(ctx, &ownHash, true); err != nil {
					t.Fatal(err)
				}
			}
			if tc.vspNamesOwn {
				vspFeeHash = ownHash
			}
			fp := &vspFeePayment{
				client:  c,
				ctx:     ctx,
				ticket:  ticket,
				policy:  c.policy,
				params:  w.chainParams,
				feeTx:   own,
				feeHash: ownHash,
			}
			if tc.hashOnly {
				fp.feeTx = nil
			}
			c.jobs[*ticket.Hash()] = fp // stopped on cleanup
			if tc.failWrites {
				failVSPWrites(c)
			}

			err := c.Process(ctx, ticket, nil)
			if tc.status != nil || tc.failWrites {
				// The VSP's tx is not learned; a retry is scheduled.
				if err == nil {
					t.Fatal("Process: want an error")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				info, err := ticket.VSPTicketInfo(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if info.FeeHash != vspFeeHash {
					t.Fatalf("fee hash %v, want the VSP's %v", info.FeeHash, vspFeeHash)
				}
			}
			if unspent := testUnspentOutputs(ctx, t, w)[*op]; unspent != tc.wantUnspent {
				t.Fatalf("own fee tx's input unspent = %v, want %v", unspent, tc.wantUnspent)
			}
			if after := testSpendable(ctx, t, w); tc.wantUnspent && after != before {
				t.Fatalf("spendable balance %v after the abandon, want %v as before the job's tx",
					after, before)
			}
		})
	}
}

// testSpendable returns account 0's spendable balance at minconf 0, as
// getbalance reports it.
func testSpendable(ctx context.Context, t *testing.T, w *Wallet) dcrutil.Amount {
	t.Helper()
	bal, err := w.AccountBalance(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return bal.Spendable
}
