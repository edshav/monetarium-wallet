// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txrules

import (
	"testing"

	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/wire"
)

// nodeIsDust is the node's mempool dust rule for a VAR output (isDust in
// monetarium-node internal/mempool/policy.go): the output's wire size plus a
// 165-byte P2PKH input, at a third of the relay fee.
func nodeIsDust(out *wire.TxOut, relayFee dcrutil.Amount) bool {
	totalSize := out.SerializeSize() + 165
	return out.Value*1000/(3*int64(totalSize)) < int64(relayFee)
}

// TestDustThreshold checks that DustThreshold is the smallest amount the
// node's dust rule accepts, and that IsDustAmount agrees with that rule.
func TestDustThreshold(t *testing.T) {
	for _, relayFee := range []dcrutil.Amount{1, 999, 1e3, 1e4, 12345, 1e5} {
		for _, scriptSize := range []int{23, 25, 34, 300} {
			got := DustThreshold(scriptSize, relayFee)
			out := &wire.TxOut{PkScript: make([]byte, scriptSize)}
			for _, v := range []dcrutil.Amount{got - 1, got, got + 1} {
				out.Value = int64(v)
				dust := nodeIsDust(out, relayFee)
				if IsDustAmount(v, scriptSize, relayFee) != dust {
					t.Errorf("IsDustAmount(%v, %d, %v) = %v, the node's rule says %v",
						v, scriptSize, relayFee, !dust, dust)
				}
				if (v < got) != dust {
					t.Errorf("DustThreshold(%d, %v) = %v, but the node's rule says %v is dust: %v",
						scriptSize, relayFee, got, v, dust)
				}
			}
		}
	}
	// The P2PKH threshold at the default relay fee: a VAR output is 37
	// bytes on the wire, its coin type byte included.
	if got := DustThreshold(25, 1e4); got != 6060 {
		t.Errorf("DustThreshold(25, 1e4) = %v, want 6060 atoms", int64(got))
	}
}
