// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/decred/vspd/types/v3"
)

// TestVSPSetVoteChoiceNilChoices checks that a policy update sent with nil
// vote choices, as settreasurypolicy and settspendpolicy send it, reaches the
// VSP as an empty object. vspd requires votechoices and rejects null.
func TestVSPSetVoteChoiceNilChoices(t *testing.T) {
	treasuryKey := "02" + strings.Repeat("ab", 32)
	tspendHash := strings.Repeat("cd", 32)
	for _, tc := range []struct {
		name             string
		tspend, treasury map[string]string
	}{
		{name: "settreasurypolicy", treasury: map[string]string{treasuryKey: "yes"}},
		{name: "settspendpolicy", tspend: map[string]string{tspendHash: "no"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var sets atomic.Int32
			c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				switch path {
				case "/api/v3/ticketstatus":
					return http.StatusOK, types.TicketStatusResponse{Request: body}
				case "/api/v3/setvotechoices":
					sets.Add(1)
					var req map[string]json.RawMessage
					if err := json.Unmarshal(body, &req); err != nil {
						return apiError(types.ErrBadRequest)
					}
					// vspd's binding:"required" on votechoices.
					if v, ok := req["votechoices"]; !ok || bytes.Equal(v, []byte("null")) {
						return apiError(types.ErrBadRequest)
					}
					return http.StatusOK, types.SetVoteChoicesResponse{Request: body}
				}
				return apiError(types.ErrInternalError)
			})
			ticket := testVSPTicket(ctx, t, c, 1)

			err := c.SetVoteChoice(ctx, ticket, nil, tc.tspend, tc.treasury)
			if err != nil {
				t.Fatalf("SetVoteChoice: %v", err)
			}
			if n := sets.Load(); n != 1 {
				t.Fatalf("%d setvotechoices requests, want 1", n)
			}
		})
	}
}
