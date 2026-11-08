// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"net/http"
	"testing"

	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
)

// TestVSPFeeAlreadyReceivedRecordsFee checks that when the VSP answers a fee
// address request saying it already holds the ticket's fee, the wallet records
// the VSP's fee tx as paid, and as confirmed once the VSP reports it so, both
// when processing a ticket and when a fee payment job retries.
func TestVSPFeeAlreadyReceivedRecordsFee(t *testing.T) {
	paths := []struct {
		name string
		run  func(ctx context.Context, c *VSPClient, ticket *VSPTicket) error
	}{{
		name: "Process",
		run: func(ctx context.Context, c *VSPClient, ticket *VSPTicket) error {
			return c.Process(ctx, ticket, nil)
		},
	}, {
		name: "reconcilePayment",
		run: func(ctx context.Context, c *VSPClient, ticket *VSPTicket) error {
			return c.jobs[*ticket.Hash()].reconcilePayment()
		},
	}}
	statuses := []struct {
		vspStatus string
		want      udb.FeeStatus
	}{
		{"received", udb.VSPFeeProcessPaid},
		{"confirmed", udb.VSPFeeProcessConfirmed},
	}
	for _, path := range paths {
		for _, st := range statuses {
			t.Run(path.name+"/"+st.vspStatus, func(t *testing.T) {
				ctx := context.Background()
				vspFeeHash := chainhash.Hash{0xfe}
				c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
					switch path {
					case "/api/v3/feeaddress":
						return apiError(types.ErrFeeAlreadyReceived)
					case "/api/v3/ticketstatus":
						return http.StatusOK, types.TicketStatusResponse{
							FeeTxStatus: st.vspStatus,
							FeeTxHash:   vspFeeHash.String(),
							Request:     body,
						}
					}
					return apiError(types.ErrInternalError)
				})
				ticket := testVSPTicket(ctx, t, c, 1)
				// A job of its own keeps feePayment from scheduling a
				// concurrent attempt.
				c.jobs[*ticket.Hash()] = &vspFeePayment{
					client: c,
					ctx:    ctx,
					ticket: ticket,
					policy: c.policy,
					params: c.wallet.chainParams,
				}

				if err := path.run(ctx, c, ticket); err != nil {
					t.Fatal(err)
				}
				info, err := ticket.VSPTicketInfo(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if got := udb.FeeStatus(info.FeeTxStatus); got != st.want {
					t.Fatalf("fee status %v, want %v", got, st.want)
				}
				if info.FeeHash != vspFeeHash {
					t.Fatalf("fee hash %v, want the VSP's %v", info.FeeHash, vspFeeHash)
				}
			})
		}
	}
}

// TestVSPFeeAlreadyReceivedStatusFails checks that when the VSP says it holds
// the fee but cannot report it, or reports no fee tx, nothing is recorded as
// paid and the retry asks the VSP for the fee again instead of paying the
// quote the job already holds.
func TestVSPFeeAlreadyReceivedStatusFails(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status func(body []byte) (int, any)
	}{{
		name: "status error",
		status: func([]byte) (int, any) {
			return apiError(types.ErrInternalError)
		},
	}, {
		name: "no fee tx hash",
		status: func(body []byte) (int, any) {
			return http.StatusOK, types.TicketStatusResponse{
				FeeTxStatus: "received",
				Request:     body,
			}
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				switch path {
				case "/api/v3/feeaddress":
					return apiError(types.ErrFeeAlreadyReceived)
				case "/api/v3/ticketstatus":
					return tc.status(body)
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

			if err := c.Process(ctx, ticket, nil); err == nil {
				t.Fatal("Process: want an error")
			}
			fp.timerMu.Lock()
			retry := fp.timer != nil
			fp.timerMu.Unlock()
			fp.mu.Lock()
			fee, feeTx := fp.fee, fp.feeTx
			fp.mu.Unlock()
			if !retry || fee != 0 || feeTx != nil {
				t.Fatalf("retry scheduled = %v, fee = %v, fee tx kept = %v; "+
					"want a retry that asks for the fee again", retry, fee, feeTx != nil)
			}
			info, err := ticket.VSPTicketInfo(ctx)
			if err == nil && udb.FeeStatus(info.FeeTxStatus) == udb.VSPFeeProcessPaid {
				t.Fatalf("ticket recorded as paid with hash %v", info.FeeHash)
			}
		})
	}
}

// TestVSPProcessPaidKeepsVSPFeeHash checks that confirming a paid ticket whose
// fee tx the wallet does not hold keeps the recorded fee hash.
func TestVSPProcessPaidKeepsVSPFeeHash(t *testing.T) {
	ctx := context.Background()
	vspFeeHash := chainhash.Hash{0xfe}
	c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
		if path != "/api/v3/ticketstatus" {
			return apiError(types.ErrInternalError)
		}
		return http.StatusOK, types.TicketStatusResponse{
			FeeTxStatus: "confirmed",
			FeeTxHash:   vspFeeHash.String(),
			Request:     body,
		}
	})
	ticket := testVSPTicket(ctx, t, c, 1)
	err := ticket.UpdateFeePaid(ctx, vspFeeHash, c.Client.URL, c.Client.PubKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Process(ctx, ticket, nil); err != nil {
		t.Fatal(err)
	}
	info, err := ticket.VSPTicketInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if udb.FeeStatus(info.FeeTxStatus) != udb.VSPFeeProcessConfirmed || info.FeeHash != vspFeeHash {
		t.Fatalf("fee status %v, hash %v; want confirmed, %v",
			udb.FeeStatus(info.FeeTxStatus), info.FeeHash, vspFeeHash)
	}
}
