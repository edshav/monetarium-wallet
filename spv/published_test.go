// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package spv

import (
	"context"
	"slices"
	"testing"

	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/txscript"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/wallet"
)

func published(t *testing.T, w *wallet.Wallet, tx *wire.MsgTx) bool {
	t.Helper()
	txs, err := w.UnminedTransactions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return slices.ContainsFunc(txs, func(u *wire.MsgTx) bool { return u.TxHash() == tx.TxHash() })
}

// TestHandleTxInvsMarksRelayedPublished checks that a transaction the wallet
// holds back as unpublished, recorded as the wallet records a VSP fee that
// spends its output and pays elsewhere, is marked published once a peer
// relays it.
func TestHandleTxInvsMarksRelayedPublished(t *testing.T) {
	for _, ct := range []cointype.CoinType{cointype.CoinTypeVAR, 1} {
		t.Run(ct.String(), func(t *testing.T) {
			ctx := context.Background()
			w, version, script, syncer := txInvsWallet(t)
			fund := payment(version, script, ct, 1)
			if err := w.AddTransaction(ctx, fund, nil); err != nil {
				t.Fatal(err)
			}
			fee := spendOf(t, w, fund, []byte{txscript.OP_TRUE}, nil)
			hash := fee.TxHash()
			if err := w.SetPublished(ctx, &hash, false); err != nil {
				t.Fatal(err)
			}
			if err := w.AddTransaction(ctx, fee, nil); err != nil {
				t.Fatal(err)
			}
			if published(t, w, fee) {
				t.Fatal("unpublished transaction counted as published")
			}

			rp := connectFakePeer(t, wire.SFNodeNetwork, nil, []*wire.MsgTx{fee})
			syncer(&fee.TxIn[0].PreviousOutPoint).handleTxInvs(ctx, rp, hashes(fee))
			if !published(t, w, fee) {
				t.Fatal("relayed transaction still unpublished")
			}
		})
	}
}
