// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"math/big"
	"testing"

	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-node/wire"
)

// TestAccountBalanceUnminedExpiry checks how AccountBalance at minconf 0
// counts a published, unmined output paying the wallet.  With an expiry it is
// unconfirmed, not spendable: the node rejects any spend of it until it is
// mined and mature, and coin selection skips it.  Without one it is
// spendable.  The wallet treats an SKA emission tx, and any tx with an SSFee
// miner-fee marker, like a coinbase; with an expiry its unmined output counts
// in the total alone, as unmined coinbase-like credits do at minconf 1 and up.
func TestAccountBalanceUnminedExpiry(t *testing.T) {
	const amt = 2e8 // atoms
	tests := []struct {
		name     string
		ct       cointype.CoinType
		expiry   uint32
		emission bool
		mfMarker bool // add an SSFee miner-fee OP_RETURN marker output
		// Spendable and Unconfirmed in atoms; Total is always amt.
		spendable, unconfirmed int64
	}{
		{name: "VAR", ct: cointype.CoinTypeVAR, spendable: amt},
		{name: "VAR, expiry", ct: cointype.CoinTypeVAR, expiry: 1000, unconfirmed: amt},
		{name: "SKA1", ct: 1, spendable: amt},
		{name: "SKA1, expiry", ct: 1, expiry: 1000, unconfirmed: amt},
		{name: "SKA1 emission", ct: 1, expiry: 1000, emission: true},
		{name: "VAR miner-fee marker, expiry", ct: cointype.CoinTypeVAR, expiry: 1000, mfMarker: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			w, teardown := testWallet(ctx, t, &basicWalletConfig, nil)
			t.Cleanup(teardown)

			addr, err := w.NewExternalAddress(ctx, 0)
			if err != nil {
				t.Fatal(err)
			}
			ver, script := addr.(Address).PaymentScript()
			tx := wire.NewMsgTx()
			tx.Expiry = tc.expiry
			in := wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{0xfd}}, amt, nil)
			if tc.emission {
				// The shape wire.IsSKAEmissionTransaction detects.
				in = wire.NewTxIn(&wire.OutPoint{Index: wire.MaxPrevOutIndex}, 0, []byte{0x01, 'S', 'K', 'A'})
			}
			tx.AddTxIn(in)
			out := &wire.TxOut{Value: amt, Version: ver, PkScript: script, CoinType: tc.ct}
			if tc.ct.IsSKA() {
				out.Value, out.SKAValue = 0, big.NewInt(amt)
			}
			tx.AddTxOut(out)
			if tc.mfMarker {
				tx.AddTxOut(&wire.TxOut{PkScript: []byte{0x6a, 0x06, 'M', 'F', 0, 0, 0, 0}})
			}
			if tc.emission != wire.IsSKAEmissionTransaction(tx) {
				t.Fatalf("test setup: emission %v, wire says %v", tc.emission, !tc.emission)
			}
			if err := w.AddTransaction(ctx, tx, nil); err != nil {
				t.Fatal(err)
			}

			bal, err := w.AccountBalance(ctx, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			cb := bal.CoinTypeBalances[tc.ct]
			spendable, unconfirmed, total := int64(cb.Spendable), int64(cb.Unconfirmed), int64(cb.Total)
			if tc.ct.IsSKA() {
				spendable = cb.SKASpendable.BigInt().Int64()
				unconfirmed = cb.SKAUnconfirmed.BigInt().Int64()
				total = cb.SKATotal.BigInt().Int64()
			}
			if spendable != tc.spendable || unconfirmed != tc.unconfirmed || total != amt {
				t.Errorf("spendable %d, unconfirmed %d, total %d atoms; want %d, %d, %d",
					spendable, unconfirmed, total, tc.spendable, tc.unconfirmed, int64(amt))
			}
			if tc.ct == cointype.CoinTypeVAR && (int64(bal.Spendable) != tc.spendable ||
				int64(bal.Unconfirmed) != tc.unconfirmed || bal.Total != amt) {
				t.Errorf("account VAR spendable %v, unconfirmed %v, total %v; want %v, %v, %v",
					bal.Spendable, bal.Unconfirmed, bal.Total, dcrutil.Amount(tc.spendable),
					dcrutil.Amount(tc.unconfirmed), dcrutil.Amount(amt))
			}
		})
	}
}
