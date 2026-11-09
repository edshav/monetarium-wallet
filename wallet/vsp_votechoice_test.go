// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-wallet/errors"
)

// TestVSPSetVoteChoiceStatusError checks that SetVoteChoice fails, naming the
// ticket and the VSP, when the VSP cannot report the ticket's current choices,
// as the VSP then keeps them, and succeeds for a ticket the VSP does not know.
// A locked wallet, which cannot sign the status request, stays a Locked error.
func TestVSPSetVoteChoiceStatusError(t *testing.T) {
	for _, tc := range []struct {
		name        string
		code        types.ErrorCode
		unreachable bool
		locked      bool // the wallet is locked
		wantErr     bool
	}{
		{name: "VSP error", code: types.ErrInternalError, wantErr: true},
		{name: "ticket cannot vote", code: types.ErrTicketCannotVote, wantErr: true},
		{name: "VSP unreachable", unreachable: true, wantErr: true},
		{name: "unknown ticket", code: types.ErrUnknownTicket},
		// The VSP would report nothing to fix, so only the lock fails it.
		{name: "wallet locked", code: types.ErrUnknownTicket, locked: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := testVSPClient(ctx, t, func(string, []byte) (int, any) {
				return apiError(tc.code)
			})
			if tc.unreachable {
				closed := httptest.NewServer(nil)
				closed.Close()
				c.Client.URL = closed.URL
			}
			ticket := testVSPTicket(ctx, t, c, 1)
			if tc.locked {
				if err := c.wallet.Lock(); err != nil {
					t.Fatal(err)
				}
			}

			choices := map[string]string{"agenda": "yes"}
			err := c.SetVoteChoice(ctx, ticket, choices, nil, nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("SetVoteChoice: %v, want error %v", err, tc.wantErr)
			}
			if !tc.wantErr {
				return
			}
			var apiErr types.ErrorResponse
			switch {
			case tc.locked:
				if !errors.Is(err, errors.Locked) {
					t.Fatalf("SetVoteChoice: %v, want a Locked error", err)
				}
			case !tc.unreachable && !(errors.As(err, &apiErr) && apiErr.Code == tc.code):
				t.Fatalf("SetVoteChoice: %v, want VSP error %v", err, tc.code)
			}
			msg := err.Error()
			if !strings.Contains(msg, ticket.Hash().String()) || !strings.Contains(msg, c.Client.URL) {
				t.Fatalf("SetVoteChoice: %q does not name the ticket and the VSP", msg)
			}
		})
	}
}
