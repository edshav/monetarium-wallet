// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/decred/vspd/types/v3"
)

// TestVSPSetVoteChoiceStatusError checks that SetVoteChoice fails, naming the
// ticket and the VSP, when the VSP cannot report the ticket's current choices,
// as the VSP then keeps them, and succeeds for a ticket the VSP does not know.
func TestVSPSetVoteChoiceStatusError(t *testing.T) {
	for _, tc := range []struct {
		name        string
		code        types.ErrorCode
		unreachable bool
		wantErr     bool
	}{
		{name: "VSP error", code: types.ErrInternalError, wantErr: true},
		{name: "ticket cannot vote", code: types.ErrTicketCannotVote, wantErr: true},
		{name: "VSP unreachable", unreachable: true, wantErr: true},
		{name: "unknown ticket", code: types.ErrUnknownTicket},
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

			choices := map[string]string{"agenda": "yes"}
			err := c.SetVoteChoice(ctx, ticket, choices, nil, nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("SetVoteChoice: %v, want error %v", err, tc.wantErr)
			}
			if !tc.wantErr {
				return
			}
			var apiErr types.ErrorResponse
			if !tc.unreachable && !(errors.As(err, &apiErr) && apiErr.Code == tc.code) {
				t.Fatalf("SetVoteChoice: %v, want VSP error %v", err, tc.code)
			}
			msg := err.Error()
			if !strings.Contains(msg, ticket.Hash().String()) || !strings.Contains(msg, c.Client.URL) {
				t.Fatalf("SetVoteChoice: %q does not name the ticket and the VSP", msg)
			}
		})
	}
}
