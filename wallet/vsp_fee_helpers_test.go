// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"testing"

	"github.com/monetarium/monetarium-wallet/wallet/udb"
)

// feeStatus returns the fee status recorded for ticket.
func feeStatus(ctx context.Context, t *testing.T, ticket *VSPTicket) udb.FeeStatus {
	t.Helper()
	info, err := ticket.VSPTicketInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return udb.FeeStatus(info.FeeTxStatus)
}

// timerSet reports whether fp has an attempt scheduled.
func timerSet(fp *vspFeePayment) bool {
	fp.timerMu.Lock()
	defer fp.timerMu.Unlock()
	return fp.timer != nil
}
