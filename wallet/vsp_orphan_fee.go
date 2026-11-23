// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// abandonOrphanFeeTxs removes the unpublished fee txs that VSP ticket records
// name when the wallet no longer has the record's ticket, so their inputs can
// be spent again.  A fee job does the same when it finds its ticket gone, but
// a ticket can leave the wallet while no job runs for it.  A fee tx a record
// of a ticket the wallet still has names is kept, as are published and mined
// txs.  The records stay, so a ticket mined later can still be paid.  It
// returns the removed hashes.
func (w *Wallet) abandonOrphanFeeTxs(dbtx walletdb.ReadWriteTx) ([]*chainhash.Hash, error) {
	ns := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)
	unpublished, err := udb.UnpublishedHashes(ns)
	if err != nil || len(unpublished) == 0 {
		return nil, err
	}
	// For each unpublished tx: whether a record names it, and whether a
	// record naming it has its ticket in the wallet.
	type use struct{ named, held bool }
	uses := make(map[chainhash.Hash]*use, len(unpublished))
	for _, h := range unpublished {
		uses[h] = new(use)
	}
	err = udb.ForEachVSPTicket(dbtx, func(ticketHash chainhash.Hash, t *udb.VSPTicket) error {
		if u := uses[t.FeeHash]; u != nil {
			u.named = true
			u.held = u.held || w.txStore.ExistsTx(ns, &ticketHash)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var removed []*chainhash.Hash
	for _, h := range unpublished {
		if u := uses[h]; !u.named || u.held {
			continue
		}
		// A mined tx is not recorded unpublished; this only guards the
		// removal.
		details, err := w.txStore.TxDetails(ns, &h)
		if err != nil || details.Block.Height != -1 {
			continue
		}
		if err := w.txStore.RemoveUnconfirmed(ns, &details.MsgTx, &h); err != nil {
			return removed, err
		}
		log.Infof("Abandoned fee tx %v of a VSP ticket the wallet no longer has", &h)
		removed = append(removed, &h)
	}
	return removed, nil
}
