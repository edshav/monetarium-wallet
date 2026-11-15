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
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// TestVSPProcessManagedTicketsAbandonsOwnFeeTx checks the fee tx the wallet
// recorded for a ticket when ProcessManagedTickets records the fee tx the VSP
// holds, received, broadcast or confirmed.  If the VSP names another tx, the
// wallet's unpublished one is abandoned, so its input is spendable again and
// the balance is back to what it was before it.  It is kept when the VSP
// names it, when it was published, when another ticket's record names it,
// when it was sent to another VSP, when the VSP names no fee tx or its fee
// errored, and when recording the VSP's hash fails.  A record that names no
// VSP counts as this VSP's, as in Process.
func TestVSPProcessManagedTicketsAbandonsOwnFeeTx(t *testing.T) {
	for _, tc := range []struct {
		name        string
		feeStatus   string // the VSP's FeeTxStatus
		vspNamesOwn bool   // the VSP's fee tx is the wallet's
		published   bool
		otherTicket bool // another ticket's record names the wallet's fee tx
		otherVSP    bool // the wallet's fee tx went to another VSP
		noHost      bool // the ticket's record names no VSP
		noVSPHash   bool // the VSP names no fee tx
		failWrites  bool // recording the VSP's hash fails
		wantUnspent bool
	}{
		{name: "confirmed, VSP names another fee tx", feeStatus: "confirmed", wantUnspent: true},
		{name: "received, VSP names another fee tx", feeStatus: "received", wantUnspent: true},
		{name: "VSP names the wallet's fee tx", feeStatus: "confirmed", vspNamesOwn: true},
		{name: "wallet's fee tx published", feeStatus: "confirmed", published: true},
		{name: "another ticket names the fee tx", feeStatus: "confirmed", otherTicket: true},
		{name: "fee tx sent to another VSP", feeStatus: "confirmed", otherVSP: true},
		{name: "broadcast, VSP names another fee tx", feeStatus: "broadcast", wantUnspent: true},
		// An errored fee would take the wallet's tx again.
		{name: "VSP fee errored", feeStatus: "error"},
		{name: "record names no VSP", feeStatus: "confirmed", noHost: true, wantUnspent: true},
		{name: "confirmed without a fee hash", feeStatus: "confirmed", noVSPHash: true},
		{name: "recording the VSP's hash fails, received", feeStatus: "received", failWrites: true},
		{name: "recording the VSP's hash fails, confirmed", feeStatus: "confirmed", failWrites: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			vspFeeHash := chainhash.Hash{0xfe}
			var c *VSPClient
			var ticket *VSPTicket
			c = testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				// failVSPWrites lengthens the URL's path.
				path = path[strings.Index(path, "/api/v3/"):]
				if path == "/api/v3/ticketstatus" {
					feeHash := vspFeeHash.String()
					if tc.noVSPHash {
						feeHash = ""
					}
					return http.StatusOK, types.TicketStatusResponse{
						FeeTxStatus: tc.feeStatus,
						FeeTxHash:   feeHash,
						Request:     body,
					}
				}
				return apiError(types.ErrInternalError)
			})
			w := c.wallet
			ticket = testVSPTicket(ctx, t, c, 1)

			// A fee tx paid before a restart, recorded unpublished.
			op := testWalletOutput(ctx, t, w, 2)
			before := testSpendable(ctx, t, w)
			own := wire.NewMsgTx()
			own.AddTxIn(wire.NewTxIn(op, 1e8, nil))
			if err := w.CreateVspPayment(ctx, own, 1e7, ticket.votingAddr, 0, 0); err != nil {
				t.Fatal(err)
			}
			ownHash := own.TxHash()
			host := c.URL
			if tc.otherVSP {
				host = "https://other.vsp.example"
			}
			if err := ticket.UpdateFeeStarted(ctx, ownHash, host, c.PubKey); err != nil {
				t.Fatal(err)
			}
			if tc.published {
				if err := w.SetPublished(ctx, &ownHash, true); err != nil {
					t.Fatal(err)
				}
			}
			if tc.otherTicket {
				other := testVSPTicket(ctx, t, c, 3)
				if err := other.UpdateFeeStarted(ctx, ownHash, c.URL, c.PubKey); err != nil {
					t.Fatal(err)
				}
			}
			if tc.vspNamesOwn {
				vspFeeHash = ownHash
			}
			// setHost rewrites the host the ticket's record names.  The
			// host record is keyed by its id, so any host can be stored.
			setHost := func(host string) {
				err := walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
					rec, err := udb.GetVSPTicket(dbtx, *ticket.Hash())
					if err != nil {
						return err
					}
					return udb.SetVSPHost(dbtx, rec.VSPHostID, &udb.VSPHost{Host: []byte(host)})
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			if tc.noHost {
				setHost("")
			}
			if tc.failWrites {
				failVSPWrites(c)
				// The record names this VSP under its lengthened URL, so
				// only the write fails.
				setHost(c.URL)
			}

			err := c.ProcessManagedTickets(ctx, []*VSPTicket{ticket})
			if tc.failWrites {
				if err == nil {
					t.Fatal("ProcessManagedTickets: want the failed write's error")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				info, err := ticket.VSPTicketInfo(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if want := vspFeeHash; !tc.noVSPHash && info.FeeHash != want {
					t.Fatalf("fee hash %v, want the VSP's %v", info.FeeHash, vspFeeHash)
				}
			}
			if unspent := testUnspentOutputs(ctx, t, w)[*op]; unspent != tc.wantUnspent {
				t.Fatalf("wallet's fee tx input unspent = %v, want %v", unspent, tc.wantUnspent)
			}
			if after := testSpendable(ctx, t, w); tc.wantUnspent && after != before {
				t.Fatalf("spendable balance %v after the abandon, want %v as before the fee tx",
					after, before)
			}
		})
	}
}
