// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package udb

import (
	"context"
	"testing"

	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// TestSetPublishedReportsChange checks that SetPublished reports a change
// only when it sets or clears the unpublished flag, and not when the flag
// already has the requested state.
func TestSetPublishedReportsChange(t *testing.T) {
	ctx := context.Background()
	db, _, s, teardown, err := cloneDB(ctx, "set_published.kv")
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	hash := chainhash.Hash{1}
	for i, step := range []struct {
		published, changed bool
	}{
		{published: true, changed: false},
		{published: false, changed: true},
		{published: false, changed: false},
		{published: true, changed: true},
		{published: true, changed: false},
	} {
		err := walletdb.Update(ctx, db, func(dbtx walletdb.ReadWriteTx) error {
			changed, err := s.SetPublished(dbtx, &hash, step.published)
			if err != nil {
				return err
			}
			if changed != step.changed {
				t.Errorf("step %d: SetPublished(%v) changed = %v, want %v",
					i, step.published, changed, step.changed)
			}
			ns := dbtx.ReadBucket(wtxmgrBucketKey)
			if got := !existsUnpublished(ns, hash[:]); got != step.published {
				t.Errorf("step %d: published = %v, want %v", i, got, step.published)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
