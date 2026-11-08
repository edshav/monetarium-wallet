// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
)

func TestSameVSPHost(t *testing.T) {
	pairs := []struct {
		a, b string
		want bool
	}{
		{"https://vsp.monetarium.online", "https://vsp.monetarium.online/", true},
		{"https://VSP.Monetarium.online", "https://vsp.monetarium.online", true},
		{"https://vsp.monetarium.online", "https://vsp.testnet.monetarium.online", false},
		{"https://vsp.monetarium.online/api", "https://vsp.monetarium.online/api/", true},
		{"https://vsp.monetar\u0130um.online", "https://vsp.monetarium.online", false},
		{"https://\u212Asp.example", "https://ksp.example", false},
		{"http://vsp.example", "https://vsp.example", false},
		{"https://vsp.example:8443", "https://vsp.example", false},
		{"https://vsp.example/API", "https://vsp.example/api", false},
	}
	for _, tc := range pairs {
		if got := SameVSPHost(tc.a, tc.b); got != tc.want {
			t.Fatalf("SameVSPHost(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestVSPProcessPaidTicketHost checks that a ticket paid to this VSP is
// confirmed with it even when the VSP URL was recorded with another spelling,
// and that a ticket paid to another VSP is not.
func TestVSPProcessPaidTicketHost(t *testing.T) {
	for _, tc := range []struct {
		name       string
		host       func(clientURL string) string
		wantStatus udb.FeeStatus
	}{
		{"same VSP", func(u string) string { return u + "/" }, udb.VSPFeeProcessConfirmed},
		{"other VSP", func(string) string { return "https://other.example" }, udb.VSPFeeProcessPaid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			feeHash := chainhash.Hash{0xfe}
			c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				if path != "/api/v3/ticketstatus" {
					return apiError(types.ErrInternalError)
				}
				return http.StatusOK, types.TicketStatusResponse{
					FeeTxStatus: "confirmed",
					FeeTxHash:   feeHash.String(),
					Request:     body,
				}
			})
			ticket := testVSPTicket(ctx, t, c, 1)
			err := ticket.UpdateFeePaid(ctx, feeHash, tc.host(c.Client.URL), c.Client.PubKey)
			if err != nil {
				t.Fatal(err)
			}

			err = c.Process(ctx, ticket, nil)
			if (err == nil) != (tc.wantStatus == udb.VSPFeeProcessConfirmed) {
				t.Fatalf("Process: %v", err)
			}
			info, err := ticket.VSPTicketInfo(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got := udb.FeeStatus(info.FeeTxStatus); got != tc.wantStatus {
				t.Fatalf("fee status %v, want %v", got, tc.wantStatus)
			}
		})
	}
}

// TestVSPClientSharedAcrossSpellings checks that one VSP spelled two ways gets
// one client, so its fee payment jobs are not run twice.
func TestVSPClientSharedAcrossSpellings(t *testing.T) {
	ctx := context.Background()
	c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
		return apiError(types.ErrInternalError)
	})
	w := c.wallet
	cfg := VSPClientConfig{
		URL:    "https://VSP.example",
		PubKey: base64.StdEncoding.EncodeToString(c.Client.PubKey),
		Policy: c.policy,
	}
	a, err := w.VSP(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.URL = "https://vsp.example/"
	b, err := w.VSP(cfg)
	if err != nil {
		t.Fatal(err)
	}
	found, err := w.LookupVSP("https://Vsp.example//")
	if err != nil {
		t.Fatal(err)
	}
	if a != b || a != found {
		t.Fatal("one VSP spelled differently got more than one client")
	}
}
