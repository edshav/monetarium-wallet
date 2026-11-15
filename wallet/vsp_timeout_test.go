// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/decred/slog"
	"github.com/decred/vspd/types/v3"
)

// TestVSPProcessReturnsWhenVSPHangs checks that a VSP which accepts the
// request but never finishes its reply does not hold Process, and with it the
// ticket's fee processing lock, forever: the request times out and Process
// returns.  The VSP stalls either before it answers or after it sends the
// headers, in the middle of the body.
func TestVSPProcessReturnsWhenVSPHangs(t *testing.T) {
	defer func(d time.Duration) { vspRequestTimeout = d }(vspRequestTimeout)
	vspRequestTimeout = 200 * time.Millisecond

	for _, tc := range []struct {
		name    string
		headers bool // send the headers and part of the body first
	}{
		{name: "no answer"},
		{name: "body stalls", headers: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			w := testVSPClient(ctx, t, func(string, []byte) (int, any) {
				return apiError(types.ErrInternalError)
			}).wallet
			release := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				if tc.headers {
					rw.Header().Set("Content-Length", "100")
					rw.WriteHeader(http.StatusOK)
					rw.Write([]byte("{"))
					rw.(http.Flusher).Flush()
				}
				<-release
			}))
			t.Cleanup(srv.Close)
			// Registered after srv.Close, so it runs first.
			t.Cleanup(func() { close(release) })
			pub, _, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
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
			ticket := testVSPTicket(ctx, t, c, 1)

			done := make(chan error, 1)
			go func() { done <- c.Process(ctx, ticket, nil) }()
			select {
			case err := <-done:
				var netErr net.Error
				if !errors.As(err, &netErr) || !netErr.Timeout() {
					t.Fatalf("Process: want the request's timeout, got %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Process did not return while the VSP never finished its reply")
			}
		})
	}
}

// TestVSPClientTimeout checks the limit a VSP client is built with: zero
// would mean no limit at all.
func TestVSPClientTimeout(t *testing.T) {
	c := testVSPClient(context.Background(), t, func(string, []byte) (int, any) {
		return apiError(types.ErrInternalError)
	})
	if got := c.Client.Timeout; got != 30*time.Second {
		t.Fatalf("VSP client timeout = %v, want 30s", got)
	}
}
