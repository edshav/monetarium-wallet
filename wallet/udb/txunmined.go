// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package udb

import (
	"bytes"

	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
	"github.com/monetarium/monetarium-node/blockchain/stake"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/wire"
)

// InsertMemPoolTx inserts a memory pool transaction record.  It also marks
// previous outputs referenced by its inputs as spent.  Errors with the
// DoubleSpend code if another unmined transaction is a double spend of this
// transaction.
func (s *Store) InsertMemPoolTx(dbtx walletdb.ReadWriteTx, rec *TxRecord) error {
	ns := dbtx.ReadWriteBucket(wtxmgrBucketKey)

	_, recVal := latestTxRecord(ns, rec.Hash[:])
	if recVal != nil {
		return errors.E(errors.Exist, "transaction already exists mined")
	}

	v := existsRawUnmined(ns, rec.Hash[:])
	if v != nil {
		return nil
	}

	// Check for other unmined transactions which cause this tx to be a double
	// spend.  Unlike mined transactions that double spend an unmined tx,
	// existing unmined txs are not removed when inserting a double spending
	// unmined tx.
	//
	// An exception is made for this rule for votes and revocations that double
	// spend an unmined vote that doesn't vote on the tip block.
	for _, input := range rec.MsgTx.TxIn {
		prevOut := &input.PreviousOutPoint
		k := canonicalOutPoint(&prevOut.Hash, prevOut.Index)
		if v := existsRawUnminedInput(ns, k); v != nil {
			var spenderHash chainhash.Hash
			readRawUnminedInputSpenderHash(v, &spenderHash)

			// A switch is used here instead of an if statement so it can be
			// broken out of to the error below.
		DoubleSpendVoteCheck:
			switch rec.TxType {
			case stake.TxTypeSSGen, stake.TxTypeSSRtx:
				spenderVal := existsRawUnmined(ns, spenderHash[:])
				spenderTxBytes := extractRawUnminedTx(spenderVal)
				var spenderTx wire.MsgTx
				err := spenderTx.Deserialize(bytes.NewReader(spenderTxBytes))
				if err != nil {
					return errors.E(errors.IO, err)
				}
				if stake.DetermineTxType(&spenderTx) != stake.TxTypeSSGen {
					break DoubleSpendVoteCheck
				}
				votedBlock, _ := stake.SSGenBlockVotedOn(&spenderTx)
				tipBlock, _ := s.MainChainTip(dbtx)
				if votedBlock == tipBlock {
					err := errors.Errorf("vote or revocation %v double spends unmined "+
						"vote %v on the tip block", &rec.Hash, &spenderHash)
					return errors.E(errors.DoubleSpend, err)
				}

				err = s.RemoveUnconfirmed(ns, &spenderTx, &spenderHash)
				if err != nil {
					return err
				}
				continue
			}

			err := errors.Errorf("%v conflicts with %v by double spending %v", &rec.Hash, &spenderHash, prevOut)
			return errors.E(errors.DoubleSpend, err)
		}
	}

	log.Infof("Inserting unconfirmed transaction %v", &rec.Hash)
	v, err := valueTxRecord(rec)
	if err != nil {
		return err
	}
	err = putRawUnmined(ns, rec.Hash[:], v)
	if err != nil {
		return err
	}
	if rec.Unpublished {
		err = putUnpublished(ns, rec.Hash[:])
		if err != nil {
			return err
		}
	}

	txType := stake.DetermineTxType(&rec.MsgTx)

	for i, input := range rec.MsgTx.TxIn {
		// Skip stakebases for votes.
		if i == 0 && txType == stake.TxTypeSSGen {
			continue
		}
		prevOut := &input.PreviousOutPoint
		k := canonicalOutPoint(&prevOut.Hash, prevOut.Index)
		err = putRawUnminedInput(ns, k, rec.Hash[:])
		if err != nil {
			return err
		}
	}

	// If the transaction is a ticket purchase, record it in the ticket
	// purchases bucket.
	if txType == stake.TxTypeSStx {
		tk := rec.Hash[:]
		tv := existsRawTicketRecord(ns, tk)
		if tv == nil {
			tv = valueTicketRecord(-1)
			err := putRawTicketRecord(ns, tk, tv)
			if err != nil {
				return err
			}
		}
	}

	// TODO: increment credit amount for each credit (but those are unknown
	// here currently).

	return nil
}

// SetPublished modifies the published state of an unmined transaction.
func (s *Store) SetPublished(dbtx walletdb.ReadWriteTx, txHash *chainhash.Hash, published bool) error {
	ns := dbtx.ReadWriteBucket(wtxmgrBucketKey)
	if published {
		return deleteUnpublished(ns, txHash[:])
	}
	return putUnpublished(ns, txHash[:])
}

// removeDoubleSpends checks for any unmined transactions which would introduce
// a double spend if tx was added to the store (either as a confirmed or unmined
// transaction).  Each conflicting transaction and all transactions which spend
// it are recursively removed.
func (s *Store) removeDoubleSpends(ns walletdb.ReadWriteBucket, rec *TxRecord) error {
	for _, input := range rec.MsgTx.TxIn {
		prevOut := &input.PreviousOutPoint
		prevOutKey := canonicalOutPoint(&prevOut.Hash, prevOut.Index)
		doubleSpendHash := existsRawUnminedInput(ns, prevOutKey)
		if doubleSpendHash != nil {
			var doubleSpend TxRecord
			doubleSpendVal := existsRawUnmined(ns, doubleSpendHash)
			copy(doubleSpend.Hash[:], doubleSpendHash) // Silly but need an array
			err := readRawTxRecord(&doubleSpend.Hash, doubleSpendVal,
				&doubleSpend)
			if err != nil {
				return err
			}

			log.Debugf("Removing double spending transaction %v",
				doubleSpend.Hash)
			err = s.RemoveUnconfirmed(ns, &doubleSpend.MsgTx, &doubleSpend.Hash)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// RemoveUnconfirmed removes an unmined transaction record and all spend chains
// deriving from it from the store.  This is designed to remove transactions
// that would otherwise result in double spend conflicts if left in the store,
// and to remove transactions that spend coinbase transactions on reorgs. It
// can also be used to remove old tickets that do not meet the network difficulty
// and expired transactions.
func (s *Store) RemoveUnconfirmed(ns walletdb.ReadWriteBucket, tx *wire.MsgTx, txHash *chainhash.Hash) error {

	stxType := stake.DetermineTxType(tx)

	// For each potential credit for this record, each spender (if any) must
	// be recursively removed as well.  Once the spenders are removed, the
	// credit is deleted.
	numOuts := uint32(len(tx.TxOut))
	for i := uint32(0); i < numOuts; i++ {
		k := canonicalOutPoint(txHash, i)
		spenderHash := existsRawUnminedInput(ns, k)
		if spenderHash != nil {
			var spender TxRecord
			spenderVal := existsRawUnmined(ns, spenderHash)
			copy(spender.Hash[:], spenderHash) // Silly but need an array
			err := readRawTxRecord(&spender.Hash, spenderVal, &spender)
			if err != nil {
				return err
			}

			log.Debugf("Transaction %v is part of a removed conflict "+
				"chain -- removing as well", spender.Hash)
			err = s.RemoveUnconfirmed(ns, &spender.MsgTx, &spender.Hash)
			if err != nil {
				return err
			}
		}
		err := deleteRawUnminedCredit(ns, k, s.chainParams)
		if err != nil {
			return err
		}

		// Drain any speculative multisig record left behind by
		// insertMultisigOutIntoTxMgr (createtx.go) when this tx authored a
		// P2SH multisig output. Without this, an abandoned-publish multisig
		// tx leaves the entry in bucketMultisig and bucketMultisigUsp forever,
		// causing redeemmultisigouts to emit a raw transaction for an output
		// that never reached the chain. Both deletes are idempotent (no-op
		// on missing keys), so call them unconditionally — this also drains
		// any legacy bucketMultisigUsp orphans whose matching bucketMultisig
		// entry was already removed.
		if err := deleteMultisigOutUS(ns, k); err != nil {
			return err
		}
		if err := deleteMultisigOut(ns, k); err != nil {
			return err
		}

		if (stxType == stake.TxTypeSStx) && (i%2 == 1) {
			// An unconfirmed ticket leaving the store means we need to delete
			// the respective commitment and its entry from the unspent
			// commitments index.

			// This assumes that the key to ticket commitment values in the db are
			// canonicalOutPoints. If this ever changes, this needs to be changed to
			// use keyTicketCommitment(...).
			ktc := k
			vtc := existsRawTicketCommitment(ns, ktc)
			if vtc != nil {
				log.Debugf("Removing unconfirmed ticket commitment %s:%d",
					txHash, i)
				err = deleteRawTicketCommitment(ns, ktc)
				if err != nil {
					return err
				}
				err = deleteRawUnspentTicketCommitment(ns, ktc)
				if err != nil {
					return err
				}
			}
		}
	}

	if (stxType == stake.TxTypeSSGen) || (stxType == stake.TxTypeSSRtx) {
		// An unconfirmed vote/revocation leaving the store means we need to
		// unmark the commitments of the respective ticket as unminedSpent.
		err := s.replaceTicketCommitmentUnminedSpent(ns, stxType, tx, false)
		if err != nil {
			return err
		}
	}

	// If this tx spends any previous credits (either mined or unmined), set
	// each unspent.  Mined transactions are only marked spent by having the
	// output in the unmined inputs bucket.
	for _, input := range tx.TxIn {
		prevOut := &input.PreviousOutPoint
		k := canonicalOutPoint(&prevOut.Hash, prevOut.Index)
		err := deleteRawUnminedInput(ns, k)
		if err != nil {
			return err
		}

		// If a multisig output is recorded for this input, mark it unspent.
		if v := existsMultisigOut(ns, k); v != nil {
			vcopy := make([]byte, len(v))
			copy(vcopy, v)
			setMultisigOutUnSpent(vcopy)
			err := putMultisigOutRawValues(ns, k, vcopy)
			if err != nil {
				return err
			}
			err = putMultisigOutUS(ns, k)
			if err != nil {
				return err
			}
		}
	}

	err := deleteUnpublished(ns, txHash[:])
	if err != nil {
		return err
	}

	return deleteRawUnmined(ns, txHash[:])
}

// UnminedTxs returns the transaction records for all unmined transactions
// which are not known to have been mined in a block.  Transactions are
// guaranteed to be sorted by their dependency order.
func (s *Store) UnminedTxs(dbtx walletdb.ReadTx) ([]*TxRecord, error) {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)
	recSet, err := s.unminedTxRecords(ns)
	if err != nil {
		return nil, err
	}

	recs := dependencySort(recSet)
	return recs, nil
}

func (s *Store) unminedTxRecords(ns walletdb.ReadBucket) (map[chainhash.Hash]*TxRecord, error) {
	unmined := make(map[chainhash.Hash]*TxRecord)
	err := ns.NestedReadBucket(bucketUnmined).ForEach(func(k, v []byte) error {
		var txHash chainhash.Hash
		err := readRawUnminedHash(k, &txHash)
		if err != nil {
			return err
		}

		rec := new(TxRecord)
		err = readRawTxRecord(&txHash, v, rec)
		if err != nil {
			return err
		}
		rec.Unpublished = existsUnpublished(ns, txHash[:])

		unmined[rec.Hash] = rec
		return nil
	})
	return unmined, err
}

// UnminedTxHashes returns the hashes of all transactions not known to have been
// mined in a block.
func (s *Store) UnminedTxHashes(ns walletdb.ReadBucket) ([]*chainhash.Hash, error) {
	return s.unminedTxHashes(ns)
}

func (s *Store) unminedTxHashes(ns walletdb.ReadBucket) ([]*chainhash.Hash, error) {
	var hashes []*chainhash.Hash
	err := ns.NestedReadBucket(bucketUnmined).ForEach(func(k, v []byte) error {
		hash := new(chainhash.Hash)
		err := readRawUnminedHash(k, hash)
		if err == nil {
			hashes = append(hashes, hash)
		}
		return err
	})
	return hashes, err
}

// PruneUnmined removes unmined transactions that no longer belong in the
// unmined tx set.  This includes:
//
//   - Any transactions past a set expiry
//   - Ticket purchases with a different ticket price than the passed stake
//     difficulty
//   - Votes that do not vote on the tip block
//   - Regular transactions whose inputs have been double-spent on chain
//     (e.g., after a reorg where the transaction was orphaned)
func (s *Store) PruneUnmined(dbtx walletdb.ReadWriteTx, stakeDiff int64) ([]*chainhash.Hash, error) {
	ns := dbtx.ReadWriteBucket(wtxmgrBucketKey)

	tipHash, tipHeight := s.MainChainTip(dbtx)

	type removeTx struct {
		tx     wire.MsgTx
		hash   *chainhash.Hash
		reason string
	}
	var toRemove []*removeTx

	c := ns.NestedReadBucket(bucketUnmined).ReadCursor()
	defer c.Close()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		var tx wire.MsgTx
		err := tx.Deserialize(bytes.NewReader(extractRawUnminedTx(v)))
		if err != nil {
			return nil, errors.E(errors.IO, err)
		}

		var reason string
		switch {
		case tx.Expiry != wire.NoExpiryValue && tx.Expiry <= uint32(tipHeight):
			reason = "expired"
		case stake.IsSStx(&tx):
			if tx.TxOut[0].Value == stakeDiff {
				continue
			}
			reason = "outdated ticket purchase"
		case stake.IsSSGen(&tx):
			// This will never actually error
			votedBlockHash, _ := stake.SSGenBlockVotedOn(&tx)
			if votedBlockHash == tipHash {
				continue
			}
			reason = "missed or invalid vote"
		case stake.IsSSRtx(&tx):
			// Revocations: check if their inputs are still valid
			if s.hasValidInputs(ns, &tx) {
				continue
			}
			reason = "orphaned revocation (inputs double-spent)"
		default:
			// Regular transactions: check if any input has been double-spent
			// on chain (spent by a mined transaction). This can happen after
			// a reorg where the unmined tx was orphaned.
			if s.hasValidInputs(ns, &tx) {
				continue
			}
			reason = "orphaned transaction (inputs double-spent)"
		}

		txHash, err := chainhash.NewHash(k)
		if err != nil {
			return nil, errors.E(errors.IO, err)
		}

		log.Infof("Removing %s unmined transaction %v", reason, txHash)

		toRemove = append(toRemove, &removeTx{tx, txHash, reason})
	}

	removed := make([]*chainhash.Hash, 0, len(toRemove))
	for _, r := range toRemove {
		err := s.RemoveUnconfirmed(ns, &r.tx, r.hash)
		if err != nil {
			return removed, err
		}
		removed = append(removed, r.hash)
	}

	return removed, nil
}

// hasValidInputs reports whether no input of an unmined transaction spends a
// wallet credit that is already spent by a mined transaction.  That happens
// after a reorg, when the unmined transaction was orphaned by a conflicting
// mined one.
//
// An input the wallet has no mined credit for (an output of an unmined
// transaction, or an output the wallet never owned, e.g. the inputs of an
// incoming payment) is not known to be double spent and counts as valid.
func (s *Store) hasValidInputs(ns walletdb.ReadBucket, tx *wire.MsgTx) bool {
	txType := stake.DetermineTxType(tx)

	for i, input := range tx.TxIn {
		// Skip stakebases for votes (input 0 is the stakebase)
		if i == 0 && txType == stake.TxTypeSSGen {
			continue
		}

		prevOut := &input.PreviousOutPoint
		k, v := latestTxRecord(ns, prevOut.Hash[:])
		if v == nil {
			continue
		}
		var block Block
		if err := readRawTxRecordBlock(k, &block); err != nil {
			log.Errorf("Failed to read block of tx record %v: %v", &prevOut.Hash, err)
			continue
		}
		credVal := existsRawCredit(ns, keyCredit(&prevOut.Hash, prevOut.Index, &block))
		if credVal != nil && extractRawCreditIsSpent(credVal) {
			return false
		}
	}

	return true
}
