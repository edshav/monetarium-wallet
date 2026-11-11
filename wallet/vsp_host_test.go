// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-wallet/errors"
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
// and that a ticket paid to another VSP is not.  The client's URL is
// http://localhost:<port>.
func TestVSPProcessPaidTicketHost(t *testing.T) {
	for _, tc := range []struct {
		name       string
		host       func(port string) string
		wantStatus udb.FeeStatus
	}{
		{"trailing slash", func(p string) string { return "http://localhost:" + p + "/" }, udb.VSPFeeProcessConfirmed},
		{"host case", func(p string) string { return "http://LocalHost:" + p }, udb.VSPFeeProcessConfirmed},
		{"other host", func(string) string { return "https://other.example" }, udb.VSPFeeProcessPaid},
		{"other scheme", func(p string) string { return "https://localhost:" + p }, udb.VSPFeeProcessPaid},
		{"other port", func(string) string { return "http://localhost:1" }, udb.VSPFeeProcessPaid},
		// U+017F folds to "s" under strings.EqualFold.
		{"look-alike host", func(p string) string { return "http://localho\u017Ft:" + p }, udb.VSPFeeProcessPaid},
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
			u, err := url.Parse(c.Client.URL)
			if err != nil {
				t.Fatal(err)
			}
			c.Client.URL = "http://localhost:" + u.Port()
			ticket := testVSPTicket(ctx, t, c, 1)
			err = ticket.UpdateFeePaid(ctx, feeHash, tc.host(u.Port()), c.Client.PubKey)
			if err != nil {
				t.Fatal(err)
			}

			err = c.Process(ctx, ticket, nil)
			refused := err != nil && strings.Contains(err.Error(), "another vsp")
			confirm := tc.wantStatus == udb.VSPFeeProcessConfirmed
			if (confirm && err != nil) || (!confirm && !refused) {
				t.Fatalf("Process: %v", err)
			}
			info, err := ticket.VSPTicketInfo(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got := udb.FeeStatus(info.FeeTxStatus); got != tc.wantStatus {
				t.Fatalf("fee status %v, want %v", got, tc.wantStatus)
			}
			// Confirming records the host as the client spells it.
			if confirm && info.Host != c.Client.URL {
				t.Fatalf("recorded host %q, want %q", info.Host, c.Client.URL)
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
	// GetTrackedVSPTickets reports each VSP under its AllVSPs key.
	all := w.AllVSPs()
	if len(all) != 1 || all["https://vsp.example"] != a {
		t.Fatalf("AllVSPs = %v, want the client under https://vsp.example", all)
	}
}

// TestVSPClientKeepsOtherVSPsApart checks that a VSP URL that SameVSPHost
// does not match, including a Unicode look-alike of the host, is not found
// by LookupVSP and gets a client of its own, with its own pubkey.
func TestVSPClientKeepsOtherVSPsApart(t *testing.T) {
	ctx := context.Background()
	c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
		return apiError(types.ErrInternalError)
	})
	w := c.wallet
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ url, other string }{
		{"https://vsp.monetarium.example", "https://vsp.monetar\u0130um.example"},
		{"https://ksp.example", "https://\u212Asp.example"},
		{"https://vsp1.example", "http://vsp1.example"},
		{"https://vsp2.example", "https://vsp2.example:8443"},
		{"https://vsp3.example/api", "https://vsp3.example/API"},
		{"https://vsp4.example", "https://user@vsp4.example"},
		{"https://vsp5.example", "https://vsp5.example?x=1"},
	} {
		first, err := w.VSP(VSPClientConfig{
			URL:    tc.url,
			PubKey: base64.StdEncoding.EncodeToString(c.Client.PubKey),
			Policy: c.policy,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.LookupVSP(tc.other); !errors.Is(err, errors.NotExist) {
			t.Errorf("LookupVSP(%q) after VSP(%q): %v, want NotExist", tc.other, tc.url, err)
		}
		other, err := w.VSP(VSPClientConfig{
			URL:    tc.other,
			PubKey: base64.StdEncoding.EncodeToString(otherPub),
			Policy: c.policy,
		})
		if err != nil {
			t.Fatal(err)
		}
		if other == first || !bytes.Equal(other.Client.PubKey, otherPub) {
			t.Errorf("VSP(%q) shares the client of %q", tc.other, tc.url)
		}
	}

	// "/" normalizes to "", which an unparseable URL must not match.
	_, err = w.VSP(VSPClientConfig{
		URL:    "/",
		PubKey: base64.StdEncoding.EncodeToString(c.Client.PubKey),
		Policy: c.policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.LookupVSP("%zz"); !errors.Is(err, errors.NotExist) {
		t.Errorf(`LookupVSP("%%zz") after VSP("/"): %v, want NotExist`, err)
	}
}
