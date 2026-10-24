// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2015-2024 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package udb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/internal/compat"
	"github.com/monetarium/monetarium-wallet/wallet/txauthor"
	"github.com/monetarium/monetarium-wallet/wallet/txrules"
	"github.com/monetarium/monetarium-wallet/wallet/txsizes"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
	"github.com/monetarium/monetarium-node/blockchain/stake"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/crypto/rand"
	"github.com/monetarium/monetarium-node/crypto/ripemd160"
	"github.com/monetarium/monetarium-node/dcrutil"
	gcs2 "github.com/monetarium/monetarium-node/gcs"
	"github.com/monetarium/monetarium-node/gcs/blockcf2"
	"github.com/monetarium/monetarium-node/txscript"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/txscript/stdscript"
	"github.com/monetarium/monetarium-node/wire"
)

const (
	opNonstake = txscript.OP_NOP10

	// The assumed output script version is defined to assist with refactoring
	// to use actual script versions.
	scriptVersionAssumed = 0
)

// Block contains the minimum amount of data to uniquely identify any block on
// either the best or side chain.
type Block struct {
	Hash   chainhash.Hash
	Height int32
}

// BlockMeta contains the unique identification for a block and any metadata
// pertaining to the block.  At the moment, this additional metadata only
// includes the block time from the block header.
type BlockMeta struct {
	Block
	Time     time.Time
	VoteBits uint16
}

// blockRecord is an in-memory representation of the block record saved in the
// database.
type blockRecord struct {
	Block
	Time         time.Time
	VoteBits     uint16
	transactions []chainhash.Hash
}

// incidence records the block hash and blockchain height of a mined transaction.
// Since a transaction hash alone is not enough to uniquely identify a mined
// transaction (duplicate transaction hashes are allowed), the incidence is used
// instead.
type incidence struct {
	txHash chainhash.Hash
	block  Block
}

// indexedIncidence records the transaction incidence and an input or output
// index.
type indexedIncidence struct {
	incidence
	index uint32
}

// credit describes a transaction output which was or is spendable by wallet.
type credit struct {
	outPoint   wire.OutPoint
	block      Block
	amount     dcrutil.Amount
	change     bool
	spentBy    indexedIncidence // Index == ^uint32(0) if unspent
	opCode     uint8
	isCoinbase bool
	hasExpiry  bool
	coinType   cointype.CoinType // Dual-coin support: track coin type
}

// TxRecord represents a transaction managed by the Store.
type TxRecord struct {
	MsgTx        wire.MsgTx
	Hash         chainhash.Hash
	Received     time.Time
	SerializedTx []byte // Optional: may be nil
	TxType       stake.TxType
	Unpublished  bool
}

// getSSFeeMarkerType checks if a transaction is an SSFee and returns its type.
// Returns stake.SSFeeMarkerMiner for miner SSFee, stake.SSFeeMarkerStaker for
// staker SSFee, or stake.SSFeeMarkerNone if not an SSFee transaction.
// This is used to distinguish miner fees (goes to ImmatureCoinbaseRewards)
// from staker fees (goes to ImmatureStakeGeneration).
//
// This function first checks the SSFee marker cache (populated during credit
// insertion) and falls back to deserializing the transaction if not cached.
func getSSFeeMarkerType(ns walletdb.ReadBucket, cKey []byte) stake.SSFeeMarkerType {
	// Extract tx record key (first 68 bytes of credit key)
	if len(cKey) < 68 {
		return stake.SSFeeMarkerNone
	}
	txRecKey := cKey[0:68]

	// Check the cache first to avoid deserializing the transaction
	if markerType, cached := fetchSSFeeMarker(ns, txRecKey); cached {
		return markerType
	}

	// Cache miss - fall back to deserializing the transaction
	txRecVal := existsRawTxRecord(ns, txRecKey)
	if txRecVal == nil {
		return stake.SSFeeMarkerNone
	}

	// Deserialize the transaction to check output[0]
	var txHash chainhash.Hash
	if err := readRawTxRecordHash(txRecKey, &txHash); err != nil {
		return stake.SSFeeMarkerNone
	}
	var rec TxRecord
	if err := readRawTxRecord(&txHash, txRecVal, &rec); err != nil {
		return stake.SSFeeMarkerNone
	}

	// Check output[0] for SSFee marker
	if len(rec.MsgTx.TxOut) == 0 {
		return stake.SSFeeMarkerNone
	}
	return stake.HasSSFeeMarker(rec.MsgTx.TxOut[0].PkScript)
}

// NewTxRecord creates a new transaction record that may be inserted into the
// store.  It uses memoization to save the transaction hash and the serialized
// transaction.
func NewTxRecord(serializedTx []byte, received time.Time) (*TxRecord, error) {
	rec := &TxRecord{
		Received:     received,
		SerializedTx: serializedTx,
	}
	err := rec.MsgTx.Deserialize(bytes.NewReader(serializedTx))
	if err != nil {
		return nil, err
	}
	rec.TxType = stake.DetermineTxType(&rec.MsgTx)
	hash := rec.MsgTx.TxHash()
	copy(rec.Hash[:], hash[:])
	return rec, nil
}

// NewTxRecordFromMsgTx creates a new transaction record that may be inserted
// into the store.
func NewTxRecordFromMsgTx(msgTx *wire.MsgTx, received time.Time) (*TxRecord, error) {
	var buf bytes.Buffer
	buf.Grow(msgTx.SerializeSize())
	err := msgTx.Serialize(&buf)
	if err != nil {
		return nil, err
	}
	rec := &TxRecord{
		MsgTx:        *msgTx,
		Received:     received,
		SerializedTx: buf.Bytes(),
	}
	rec.TxType = stake.DetermineTxType(&rec.MsgTx)
	hash := rec.MsgTx.TxHash()
	copy(rec.Hash[:], hash[:])
	return rec, nil
}

// MultisigOut represents a spendable multisignature outpoint contain
// a script hash.
//
// Dual-coin: CoinType records whether this multisig output holds VAR or a
// specific SKA coin type. For VAR outputs the int64 Amount field is the
// authoritative value and SKAAmount is Zero. For SKA outputs the big.Int
// SKAAmount field is authoritative and Amount is 0.
type MultisigOut struct {
	OutPoint     *wire.OutPoint
	Tree         int8
	ScriptHash   [ripemd160.Size]byte
	M            uint8
	N            uint8
	TxHash       chainhash.Hash
	BlockHash    chainhash.Hash
	BlockHeight  uint32
	Amount       dcrutil.Amount
	CoinType     cointype.CoinType
	SKAAmount    cointype.SKAAmount
	Spent        bool
	SpentBy      chainhash.Hash
	SpentByIndex uint32
}

// Credit is the type representing a transaction output which was spent or
// is still spendable by wallet.  A UTXO is an unspent Credit, but not all
// Credits are UTXOs.
type Credit struct {
	wire.OutPoint
	BlockMeta
	Amount       dcrutil.Amount
	SKAAmount    cointype.SKAAmount // SKA big.Int amount for values exceeding int64
	PkScript     []byte             // TODO: script version
	Received     time.Time
	FromCoinBase bool
	HasExpiry    bool
	CoinType     cointype.CoinType // Dual-coin support: track coin type (VAR=0, SKA=1-255)
}

// Store implements a transaction store for storing and managing wallet
// transactions.
type Store struct {
	chainParams    *chaincfg.Params
	acctLookupFunc func(walletdb.ReadBucket, stdaddr.Address) (uint32, error)
	manager        *Manager
}

// getActiveSKACoinTypes returns a slice of coin types that are configured
// as active in the chain parameters. This replaces hardcoded loops that
// iterate over a fixed range of potential SKA coin types.
func (s *Store) getActiveSKACoinTypes() []cointype.CoinType {
	var activeCoinTypes []cointype.CoinType
	if s.chainParams != nil && s.chainParams.SKACoins != nil {
		for coinType, config := range s.chainParams.SKACoins {
			if config.Active {
				activeCoinTypes = append(activeCoinTypes, coinType)
			}
		}
	}
	return activeCoinTypes
}

// getAllActiveCoinTypes returns VAR (coin type 0) plus all active SKA coin types.
// This is useful for operations that need to iterate over all active coin types.
func (s *Store) getAllActiveCoinTypes() []cointype.CoinType {
	activeCoinTypes := []cointype.CoinType{cointype.CoinType(0)} // Always include VAR
	activeCoinTypes = append(activeCoinTypes, s.getActiveSKACoinTypes()...)
	return activeCoinTypes
}

// MainChainTip returns the hash and height of the currently marked tip-most
// block of the main chain.
func (s *Store) MainChainTip(dbtx walletdb.ReadTx) (chainhash.Hash, int32) {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)
	var hash chainhash.Hash
	tipHash := ns.Get(rootTipBlock)
	copy(hash[:], tipHash)

	header := ns.NestedReadBucket(bucketHeaders).Get(hash[:])
	height := extractBlockHeaderHeight(header)

	return hash, height
}

// ExtendMainChain inserts a block header and compact filter into the database.
// It must connect to the existing tip block.
//
// If the block is already inserted and part of the main chain, an errors.Exist
// error is returned.
//
// The main chain tip may not be extended unless compact filters have been saved
// for all existing main chain blocks.
func (s *Store) ExtendMainChain(ns walletdb.ReadWriteBucket, header *wire.BlockHeader, blockHash *chainhash.Hash, f *gcs2.FilterV2) error {
	height := int32(header.Height)
	if height < 1 {
		return errors.E(errors.Invalid, "block 0 cannot be added")
	}
	v := ns.Get(rootHaveCFilters)
	if len(v) != 1 || v[0] != 1 {
		return errors.E(errors.Invalid, "main chain may not be extended without first saving all previous cfilters")
	}

	headerBucket := ns.NestedReadWriteBucket(bucketHeaders)

	currentTipHash := ns.Get(rootTipBlock)
	if !bytes.Equal(header.PrevBlock[:], currentTipHash) {
		// Return a special error if it is a duplicate of an existing block in
		// the main chain (NOT the headers bucket, since headers are never
		// pruned).
		_, v := existsBlockRecord(ns, height)
		if v != nil && bytes.Equal(extractRawBlockRecordHash(v), blockHash[:]) {
			return errors.E(errors.Exist, "block already recorded in main chain")
		}
		return errors.E(errors.Invalid, "not direct child of current tip")
	}
	// Also check that the height is one more than the current height
	// recorded by the current tip.
	currentTipHeader := headerBucket.Get(currentTipHash)
	currentTipHeight := extractBlockHeaderHeight(currentTipHeader)
	if currentTipHeight+1 != height {
		return errors.E(errors.Invalid, "invalid height for next block")
	}

	var err error
	if approvesParent(header.VoteBits) {
		err = stakeValidate(ns, currentTipHeight)
	} else {
		err = stakeInvalidate(ns, currentTipHeight)
	}
	if err != nil {
		return err
	}

	// Add the header
	var headerBuffer bytes.Buffer
	err = header.Serialize(&headerBuffer)
	if err != nil {
		return err
	}
	err = headerBucket.Put(blockHash[:], headerBuffer.Bytes())
	if err != nil {
		return errors.E(errors.IO, err)
	}

	// Update the tip block
	err = ns.Put(rootTipBlock, blockHash[:])
	if err != nil {
		return errors.E(errors.IO, err)
	}

	// Add an empty block record
	blockKey := keyBlockRecord(height)
	blockVal := valueBlockRecordEmptyFromHeader(blockHash[:], headerBuffer.Bytes())
	err = putRawBlockRecord(ns, blockKey, blockVal)
	if err != nil {
		return err
	}

	// Save the compact filter.
	bcf2Key := blockcf2.Key(&header.MerkleRoot)
	return putRawCFilter(ns, blockHash[:], valueRawCFilter2(bcf2Key, f.Bytes()))
}

// ProcessedTxsBlockMarker returns the hash of the block which records the last
// block after the genesis block which has been recorded as being processed for
// relevant transactions.
func (s *Store) ProcessedTxsBlockMarker(dbtx walletdb.ReadTx) *chainhash.Hash {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)
	var h chainhash.Hash
	copy(h[:], ns.Get(rootLastTxsBlock))
	return &h
}

// UpdateProcessedTxsBlockMarker updates the hash of the block recording the
// final block since the genesis block for which all transactions have been
// processed.  Hash must describe a main chain block.  This does not modify the
// database if hash has a lower block height than the main chain fork point of
// the existing marker.
func (s *Store) UpdateProcessedTxsBlockMarker(dbtx walletdb.ReadWriteTx, hash *chainhash.Hash) error {
	ns := dbtx.ReadWriteBucket(wtxmgrBucketKey)
	prev := s.ProcessedTxsBlockMarker(dbtx)
	for {
		mainChain, _ := s.BlockInMainChain(dbtx, prev)
		if mainChain {
			break
		}
		h, err := s.GetBlockHeader(dbtx, prev)
		if err != nil {
			return err
		}
		prev = &h.PrevBlock
	}
	prevHeader, err := s.GetBlockHeader(dbtx, prev)
	if err != nil {
		return err
	}
	if mainChain, _ := s.BlockInMainChain(dbtx, hash); !mainChain {
		return errors.E(errors.Invalid, errors.Errorf("%v is not a main chain block", hash))
	}
	header, err := s.GetBlockHeader(dbtx, hash)
	if err != nil {
		return err
	}
	if header.Height > prevHeader.Height {
		err := ns.Put(rootLastTxsBlock, hash[:])
		if err != nil {
			return errors.E(errors.IO, err)
		}
	}
	return nil
}

// BirthdayState holds fields for setting and reading the birthday block.
// SetFromHeight and SetFromTime indicate that the birthday block should be set
// from those respective fields. Upon setting the hash and height are filled in
// and SetFrom fields set to false.
type BirthdayState struct {
	Hash                       chainhash.Hash
	Height                     uint32
	Time                       time.Time
	SetFromHeight, SetFromTime bool
}

// SetBirthState sets the birthday state in the database.
//
// [0:1] Options (1 byte)
// [1:33]  Birthblock block header hash (32 bytes)
// [33:37] Birthblock block height (4 bytes)
// [37:45] Birthday time (8 bytes)
func SetBirthState(dbtx walletdb.ReadWriteTx, bs *BirthdayState) error {
	ns := dbtx.ReadWriteBucket(wtxmgrBucketKey)
	const (
		optionsSize       = 1
		heightSize        = 4
		timeSize          = 8
		flagSetFromHeight = 1
		flagSetFromTime   = 1 << 1
	)
	v := make([]byte, optionsSize+chainhash.HashSize+heightSize+timeSize)
	options := 0
	if bs.SetFromHeight {
		options += flagSetFromHeight
	}
	if bs.SetFromTime {
		options += flagSetFromTime
	}
	v[0] = byte(options)
	copy(v[optionsSize:], bs.Hash[:])
	byteOrder.PutUint32(v[optionsSize+chainhash.HashSize:], bs.Height)
	byteOrder.PutUint64(v[optionsSize+chainhash.HashSize+heightSize:], uint64(bs.Time.Unix()))
	return ns.Put(rootBirthState, v)
}

// BirthState returns the current birthday state.
func BirthState(dbtx walletdb.ReadTx) *BirthdayState {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)
	const (
		optionsSize       = 1
		heightSize        = 4
		timeSize          = 8
		flagSetFromHeight = 1
		flagSetFromTime   = 1 << 1
	)
	v := ns.Get(rootBirthState)
	if len(v) != optionsSize+chainhash.HashSize+heightSize+timeSize {
		return nil
	}
	options := v[0]
	setFromHeight := options&flagSetFromHeight != 0
	setFromTime := options&flagSetFromTime != 0
	var h chainhash.Hash
	copy(h[:], v[optionsSize:])
	height := byteOrder.Uint32(v[optionsSize+chainhash.HashSize:])
	t := time.Unix(int64(byteOrder.Uint64(v[optionsSize+chainhash.HashSize+heightSize:])), 0)
	return &BirthdayState{
		Hash:          h,
		Height:        height,
		Time:          t,
		SetFromHeight: setFromHeight,
		SetFromTime:   setFromTime,
	}
}

// IsMissingMainChainCFilters returns whether all compact filters for main chain
// blocks have been recorded to the database after the upgrade which began to
// require them to extend the main chain.  If compact filters are missing, they
// must be added using InsertMissingCFilters.
func (s *Store) IsMissingMainChainCFilters(dbtx walletdb.ReadTx) bool {
	v := dbtx.ReadBucket(wtxmgrBucketKey).Get(rootHaveCFilters)
	return len(v) != 1 || v[0] == 0
}

// MissingCFiltersHeight returns the first main chain block height
// with a missing cfilter.  Errors with NotExist when all main chain
// blocks record cfilters.
func (s *Store) MissingCFiltersHeight(dbtx walletdb.ReadTx) (int32, error) {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)
	c := ns.NestedReadBucket(bucketBlocks).ReadCursor()
	defer c.Close()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		hash := extractRawBlockRecordHash(v)
		_, _, err := fetchRawCFilter2(ns, hash)
		if errors.Is(err, errors.NotExist) {
			height := int32(byteOrder.Uint32(k))
			return height, nil
		}
	}
	return 0, errors.E(errors.NotExist)
}

// InsertMissingCFilters records compact filters for each main chain block
// specified by blockHashes.  This is used to add the additional required
// cfilters after upgrading a database to version TODO as recording cfilters
// becomes a required part of extending the main chain.  This method may be
// called incrementally to record all main chain block cfilters.  When all
// cfilters of the main chain are recorded, extending the main chain becomes
// possible again.
func (s *Store) InsertMissingCFilters(dbtx walletdb.ReadWriteTx, blockHashes []*chainhash.Hash, filters []*gcs2.FilterV2) error {
	ns := dbtx.ReadWriteBucket(wtxmgrBucketKey)
	v := ns.Get(rootHaveCFilters)
	if len(v) == 1 && v[0] != 0 {
		return errors.E(errors.Invalid, "all cfilters for main chain blocks are already recorded")
	}

	if len(blockHashes) != len(filters) {
		return errors.E(errors.Invalid, "slices must have equal len")
	}
	if len(blockHashes) == 0 {
		return nil
	}

	for i, blockHash := range blockHashes {
		// Ensure that blockHashes are ordered and that all previous cfilters in the
		// main chain are known.
		ok := i == 0 && *blockHash == s.chainParams.GenesisHash
		var bcf2Key [gcs2.KeySize]byte
		if !ok {
			header := existsBlockHeader(ns, blockHash[:])
			if header == nil {
				return errors.E(errors.NotExist, errors.Errorf("missing header for block %v", blockHash))
			}
			parentHash := extractBlockHeaderParentHash(header)
			merkleRoot := extractBlockHeaderMerkleRoot(header)
			merkleRootHash, err := chainhash.NewHash(merkleRoot)
			if err != nil {
				return errors.E(errors.Invalid, errors.Errorf("invalid stored header %v", blockHash))
			}
			bcf2Key = blockcf2.Key(merkleRootHash)
			if i == 0 {
				_, _, err := fetchRawCFilter2(ns, parentHash)
				ok = err == nil
			} else {
				ok = bytes.Equal(parentHash, blockHashes[i-1][:])
			}
		}
		if !ok {
			return errors.E(errors.Invalid, "block hashes are not ordered or previous cfilters are missing")
		}

		// Record cfilter for this block
		err := putRawCFilter(ns, blockHash[:], valueRawCFilter2(bcf2Key, filters[i].Bytes()))
		if err != nil {
			return err
		}
	}

	// Mark all main chain cfilters as saved if the last block hash is the main
	// chain tip.
	tip, _ := s.MainChainTip(dbtx)
	if bytes.Equal(tip[:], blockHashes[len(blockHashes)-1][:]) {
		err := ns.Put(rootHaveCFilters, []byte{1})
		if err != nil {
			return errors.E(errors.IO, err)
		}
	}

	return nil
}

// BlockCFilter is a compact filter for a Decred block.
type BlockCFilter struct {
	BlockHash chainhash.Hash
	FilterV2  *gcs2.FilterV2
	Key       [gcs2.KeySize]byte
}

// GetMainChainCFilters returns compact filters from the main chain, starting at
// startHash, copying as many as possible into the storage slice and returning a
// subslice for the total number of results.  If the start hash is not in the
// main chain, this function errors.  If inclusive is true, the startHash is
// included in the results, otherwise only blocks after the startHash are
// included.
func (s *Store) GetMainChainCFilters(dbtx walletdb.ReadTx, startHash *chainhash.Hash, inclusive bool, storage []*BlockCFilter) ([]*BlockCFilter, error) {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)
	header := ns.NestedReadBucket(bucketHeaders).Get(startHash[:])
	if header == nil {
		return nil, errors.E(errors.NotExist, errors.Errorf("starting block %v not found", startHash))
	}
	height := extractBlockHeaderHeight(header)
	if !inclusive {
		height++
	}

	blockRecords := ns.NestedReadBucket(bucketBlocks)

	storageUsed := 0
	for storageUsed < len(storage) {
		v := blockRecords.Get(keyBlockRecord(height))
		if v == nil {
			break
		}
		blockHash := extractRawBlockRecordHash(v)
		bcf2Key, rawFilter, err := fetchRawCFilter2(ns, blockHash)
		if err != nil {
			return nil, err
		}
		fCopy := make([]byte, len(rawFilter))
		copy(fCopy, rawFilter)
		f, err := gcs2.FromBytesV2(blockcf2.B, blockcf2.M, fCopy)
		if err != nil {
			return nil, err
		}
		bf := &BlockCFilter{FilterV2: f, Key: bcf2Key}
		copy(bf.BlockHash[:], blockHash)
		storage[storageUsed] = bf

		height++
		storageUsed++
	}
	return storage[:storageUsed], nil
}

func extractBlockHeaderParentHash(header []byte) []byte {
	const parentOffset = 4
	return header[parentOffset : parentOffset+chainhash.HashSize]
}

func extractBlockHeaderMerkleRoot(header []byte) []byte {
	const merkleRootOffset = 36
	return header[merkleRootOffset : merkleRootOffset+chainhash.HashSize]
}

// ExtractBlockHeaderParentHash subslices the header to return the bytes of the
// parent block's hash.  Must only be called on known good input.
//
// TODO: This really should not be exported by this package.
func ExtractBlockHeaderParentHash(header []byte) []byte {
	return extractBlockHeaderParentHash(header)
}

func extractBlockHeaderVoteBits(header []byte) uint16 {
	const voteBitsOffset = 100
	return binary.LittleEndian.Uint16(header[voteBitsOffset:])
}

func extractBlockHeaderHeight(header []byte) int32 {
	const heightOffset = 128
	return int32(binary.LittleEndian.Uint32(header[heightOffset:]))
}

// ExtractBlockHeaderHeight returns the height field that is encoded in the
// header.  Must only be called on known good input.
//
// TODO: This really should not be exported by this package.
func ExtractBlockHeaderHeight(header []byte) int32 {
	return extractBlockHeaderHeight(header)
}

func extractBlockHeaderUnixTime(header []byte) uint32 {
	const timestampOffset = 136
	return binary.LittleEndian.Uint32(header[timestampOffset:])
}

// ExtractBlockHeaderTime returns the unix timestamp that is encoded in the
// header.  Must only be called on known good input.  Header timestamps are only
// 4 bytes and this value is actually limited to a maximum unix time of 2^32-1.
//
// TODO: This really should not be exported by this package.
func ExtractBlockHeaderTime(header []byte) int64 {
	return int64(extractBlockHeaderUnixTime(header))
}

func blockMetaFromHeader(blockHash *chainhash.Hash, header []byte) BlockMeta {
	return BlockMeta{
		Block: Block{
			Hash:   *blockHash,
			Height: extractBlockHeaderHeight(header),
		},
		Time:     time.Unix(int64(extractBlockHeaderUnixTime(header)), 0),
		VoteBits: extractBlockHeaderVoteBits(header),
	}
}

// RawBlockHeader is a 180 byte block header (always true for version 0 blocks).
type RawBlockHeader [180]byte

// Height extracts the height encoded in a block header.
func (h *RawBlockHeader) Height() int32 {
	return extractBlockHeaderHeight(h[:])
}

// BlockHeaderData contains the block hashes and serialized blocks headers that
// are inserted into the database.  At time of writing this only supports wire
// protocol version 0 blocks and changes will need to be made if the block
// header size changes.
type BlockHeaderData struct {
	BlockHash        chainhash.Hash
	SerializedHeader RawBlockHeader
}

// stakeValidate validates regular tree transactions from the main chain block
// at some height.  This does not perform any changes when the block is not
// marked invalid.  When currently invalidated, the invalidated byte is set to 0
// to mark the block as stake validated and the mined balance is incremented for
// all credits of this block.
//
// Stake validation or invalidation should only occur for the block at height
// tip-1.
func stakeValidate(ns walletdb.ReadWriteBucket, height int32) error {
	k, v := existsBlockRecord(ns, height)
	if v == nil {
		return errors.E(errors.IO, errors.Errorf("missing block record for height %v", height))
	}
	if !extractRawBlockRecordStakeInvalid(v) {
		return nil
	}

	minedBalance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}

	var blockRec blockRecord
	err = readRawBlockRecord(k, v, &blockRec)
	if err != nil {
		return err
	}

	// Rewrite the block record, marking the regular tree as stake validated.
	err = putRawBlockRecord(ns, k, valueBlockRecordStakeValidated(v))
	if err != nil {
		return err
	}

	for i := range blockRec.transactions {
		txHash := &blockRec.transactions[i]

		_, txv := existsTxRecord(ns, txHash, &blockRec.Block)
		if txv == nil {
			return errors.E(errors.IO, errors.Errorf("missing transaction record for tx %v block %v",
				txHash, &blockRec.Block.Hash))
		}
		var txRec TxRecord
		err = readRawTxRecord(txHash, txv, &txRec)
		if err != nil {
			return err
		}

		// Only regular tree transactions must be considered.
		if txRec.TxType != stake.TxTypeRegular {
			continue
		}

		// Move all credits from this tx to the non-invalidated credits bucket.
		// Add an unspent output for each validated credit.
		// The mined balance is incremented for all moved credit outputs.
		creditOutPoint := wire.OutPoint{Hash: txRec.Hash} // Index set in loop
		for i, output := range txRec.MsgTx.TxOut {
			k, v := existsInvalidatedCredit(ns, &txRec.Hash, uint32(i), &blockRec.Block)
			if v == nil {
				continue
			}

			err = ns.NestedReadWriteBucket(bucketStakeInvalidatedCredits).
				Delete(k)
			if err != nil {
				return errors.E(errors.IO, err)
			}
			err = putRawCredit(ns, k, v)
			if err != nil {
				return err
			}

			// Restore the SKA big.Int amount to the live side bucket if one
			// was archived during the prior stakeInvalidate. This must happen
			// after putRawCredit so the live credit and its side-bucket entry
			// are consistent.
			skaAmt, err := fetchSKAStakeInvalidatedCreditAmount(ns, k)
			if err != nil {
				return err
			}
			if !skaAmt.IsZero() {
				if err := putSKACreditAmount(ns, k, skaAmt); err != nil {
					return err
				}
				if err := deleteSKAStakeInvalidatedCreditAmount(ns, k); err != nil {
					return err
				}
			}

			// Get coin type from the credit
			coinType := fetchRawCreditCoinType(v)

			creditOutPoint.Index = uint32(i)
			err = putUnspent(ns, &creditOutPoint, &blockRec.Block, coinType)
			if err != nil {
				return err
			}

			// VAR-only aggregate; SKA totals live in per-coin-type buckets.
			minedBalance += dcrutil.Amount(output.Value)
		}

		// Move all debits from this tx to the non-invalidated debits bucket,
		// and spend any previous credits spent by the stake validated tx.
		// Remove utxos for all spent previous credits.  The mined balance is
		// decremented for all previous credits that are no longer spendable.
		debitIncidence := indexedIncidence{
			incidence: incidence{txHash: txRec.Hash, block: blockRec.Block},
			// index set for each rec input below.
		}
		for i := range txRec.MsgTx.TxIn {
			debKey, credKey, err := existsInvalidatedDebit(ns, &txRec.Hash, uint32(i),
				&blockRec.Block)
			if err != nil {
				return err
			}
			if debKey == nil {
				continue
			}
			debitIncidence.index = uint32(i)

			debVal := ns.NestedReadBucket(bucketStakeInvalidatedDebits).
				Get(debKey)
			debitAmount := extractRawDebitAmount(debVal)

			_, err = spendCredit(ns, credKey, &debitIncidence)
			if err != nil {
				return err
			}

			prevOut := &txRec.MsgTx.TxIn[i].PreviousOutPoint
			unspentKey := canonicalOutPoint(&prevOut.Hash, prevOut.Index)
			// Get the coinType from the credit
			credVal := existsRawCredit(ns, credKey)
			coinType := fetchRawCreditCoinType(credVal)
			err = deleteRawUnspent(ns, unspentKey, coinType)
			if err != nil {
				return err
			}

			err = ns.NestedReadWriteBucket(bucketStakeInvalidatedDebits).
				Delete(debKey)
			if err != nil {
				return errors.E(errors.IO, err)
			}
			err = putRawDebit(ns, debKey, debVal)
			if err != nil {
				return err
			}

			minedBalance -= debitAmount
		}
	}

	return putMinedBalance(ns, minedBalance)
}

// stakeInvalidate invalidates regular tree transactions from the main chain
// block at some height.  This does not perform any changes when the block is
// not marked invalid.  When not marked invalid, the invalidated byte is set to
// 1 to mark the block as stake invalidated and the mined balance is decremented
// for all credits.
//
// Stake validation or invalidation should only occur for the block at height
// tip-1.
//
// See stakeValidate (which performs the reverse operation) for more details.
func stakeInvalidate(ns walletdb.ReadWriteBucket, height int32) error {
	k, v := existsBlockRecord(ns, height)
	if v == nil {
		return errors.E(errors.IO, errors.Errorf("missing block record for height %v", height))
	}
	if extractRawBlockRecordStakeInvalid(v) {
		return nil
	}

	minedBalance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}

	var blockRec blockRecord
	err = readRawBlockRecord(k, v, &blockRec)
	if err != nil {
		return err
	}

	// Rewrite the block record, marking the regular tree as stake invalidated.
	err = putRawBlockRecord(ns, k, valueBlockRecordStakeInvalidated(v))
	if err != nil {
		return err
	}

	for i := range blockRec.transactions {
		txHash := &blockRec.transactions[i]

		_, txv := existsTxRecord(ns, txHash, &blockRec.Block)
		if txv == nil {
			return errors.E(errors.IO, errors.Errorf("missing transaction record for tx %v block %v",
				txHash, &blockRec.Block.Hash))
		}
		var txRec TxRecord
		err = readRawTxRecord(txHash, txv, &txRec)
		if err != nil {
			return err
		}

		// Only regular tree transactions must be considered.
		if txRec.TxType != stake.TxTypeRegular {
			continue
		}

		// Move all credits from this tx to the invalidated credits bucket.
		// Remove the unspent output for each invalidated credit.
		// The mined balance is decremented for all moved credit outputs.
		for i, output := range txRec.MsgTx.TxOut {
			k, v := existsCredit(ns, &txRec.Hash, uint32(i), &blockRec.Block)
			if v == nil {
				continue
			}

			// Capture the SKA big.Int amount BEFORE deleteRawCredit (which
			// cascades to deleteSKACreditAmount) so we can move it to the
			// stake-invalidated archive in lockstep with the credit body.
			skaAmt, err := fetchSKACreditAmount(ns, k)
			if err != nil {
				return err
			}

			err = deleteRawCredit(ns, k)
			if err != nil {
				return err
			}
			err = ns.NestedReadWriteBucket(bucketStakeInvalidatedCredits).
				Put(k, v)
			if err != nil {
				return errors.E(errors.IO, err)
			}
			if !skaAmt.IsZero() {
				if err := putSKAStakeInvalidatedCreditAmount(ns, k, skaAmt); err != nil {
					return err
				}
			}

			unspentKey := canonicalOutPoint(txHash, uint32(i))
			// Get the coinType from the credit. The credit was just moved to
			// the stake-invalidated archive; read it from there.
			creditKey := keyCredit(txHash, uint32(i), &blockRec.Block)
			credVal := ns.NestedReadBucket(bucketStakeInvalidatedCredits).Get(creditKey)
			if credVal == nil {
				// Fall back to the original v we just archived.
				credVal = v
			}
			coinType := fetchRawCreditCoinType(credVal)
			err = deleteRawUnspent(ns, unspentKey, coinType)
			if err != nil {
				return err
			}

			minedBalance -= dcrutil.Amount(output.Value)
		}

		// Move all debits from this tx to the invalidated debits bucket, and
		// unspend any credit spents by the stake invalidated tx.  The mined
		// balance is incremented for all previous credits that are spendable
		// again.
		for i := range txRec.MsgTx.TxIn {
			debKey, credKey, err := existsDebit(ns, &txRec.Hash, uint32(i),
				&blockRec.Block)
			if err != nil {
				return err
			}
			if debKey == nil {
				continue
			}

			debVal := ns.NestedReadBucket(bucketDebits).Get(debKey)
			debitAmount := extractRawDebitAmount(debVal)

			// Get the credit value to extract coin type
			credVal := existsRawCredit(ns, credKey)
			var coinType cointype.CoinType
			if credVal != nil {
				coinType = fetchRawCreditCoinType(credVal)
			} else {
				// Fallback to VAR if credit not found (shouldn't happen in normal operation)
				coinType = cointype.CoinTypeVAR
			}

			_, err = unspendRawCredit(ns, credKey)
			if err != nil {
				return err
			}

			err = deleteRawDebit(ns, debKey)
			if err != nil {
				return err
			}
			err = ns.NestedReadWriteBucket(bucketStakeInvalidatedDebits).
				Put(debKey, debVal)
			if err != nil {
				return errors.E(errors.IO, err)
			}

			prevOut := &txRec.MsgTx.TxIn[i].PreviousOutPoint
			unspentKey := canonicalOutPoint(&prevOut.Hash, prevOut.Index)
			unspentVal := extractRawDebitUnspentValue(debVal)
			err = putRawUnspent(ns, unspentKey, unspentVal, coinType)
			if err != nil {
				return err
			}

			minedBalance += debitAmount
		}
	}

	return putMinedBalance(ns, minedBalance)
}

// GetMainChainBlockHashForHeight returns the block hash of the block on the
// main chain at a given height.
func (s *Store) GetMainChainBlockHashForHeight(ns walletdb.ReadBucket, height int32) (chainhash.Hash, error) {
	_, v := existsBlockRecord(ns, height)
	if v == nil {
		err := errors.E(errors.NotExist, errors.Errorf("no block at height %v in main chain", height))
		return chainhash.Hash{}, err
	}
	var hash chainhash.Hash
	copy(hash[:], extractRawBlockRecordHash(v))
	return hash, nil
}

// GetSerializedBlockHeader returns the bytes of the serialized header for the
// block specified by its hash.  These bytes are a copy of the value returned
// from the DB and are usable outside of the transaction.
func (s *Store) GetSerializedBlockHeader(ns walletdb.ReadBucket, blockHash *chainhash.Hash) ([]byte, error) {
	return fetchRawBlockHeader(ns, keyBlockHeader(blockHash))
}

// GetBlockHeaderTime returns the timestamp field of the header for the block
// identified by its hash.
func (s *Store) GetBlockHeaderTime(dbtx walletdb.ReadTx, blockHash *chainhash.Hash) (int64, error) {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)
	v := ns.NestedReadBucket(bucketHeaders).Get(keyBlockHeader(blockHash))
	if v == nil {
		return 0, errors.E(errors.NotExist, "block header")
	}
	return int64(extractBlockHeaderUnixTime(v)), nil
}

// GetBlockHeader returns the block header for the block specified by its hash.
func (s *Store) GetBlockHeader(dbtx walletdb.ReadTx, blockHash *chainhash.Hash) (*wire.BlockHeader, error) {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)
	serialized, err := fetchRawBlockHeader(ns, keyBlockHeader(blockHash))
	if err != nil {
		return nil, err
	}
	header := new(wire.BlockHeader)
	err = header.Deserialize(bytes.NewReader(serialized))
	if err != nil {
		return nil, errors.E(errors.IO, err)
	}
	return header, nil
}

// BlockInMainChain returns whether a block identified by its hash is in the
// current main chain and if so, whether it has been stake invalidated by the
// next main chain block.
func (s *Store) BlockInMainChain(dbtx walletdb.ReadTx, blockHash *chainhash.Hash) (inMainChain bool, invalidated bool) {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)
	header := existsBlockHeader(ns, keyBlockHeader(blockHash))
	if header == nil {
		return false, false
	}

	_, v := existsBlockRecord(ns, extractBlockHeaderHeight(header))
	if v == nil {
		return false, false
	}
	if !bytes.Equal(extractRawBlockRecordHash(v), blockHash[:]) {
		return false, false
	}
	return true, extractRawBlockRecordStakeInvalid(v)
}

// GetBlockMetaForHash returns the BlockMeta for a block specified by its hash.
//
// TODO: This is legacy code now that headers are saved.  BlockMeta can be removed.
func (s *Store) GetBlockMetaForHash(ns walletdb.ReadBucket, blockHash *chainhash.Hash) (BlockMeta, error) {
	header := ns.NestedReadBucket(bucketHeaders).Get(blockHash[:])
	if header == nil {
		err := errors.E(errors.NotExist, errors.Errorf("block %v header not found", blockHash))
		return BlockMeta{}, err
	}
	return BlockMeta{
		Block: Block{
			Hash:   *blockHash,
			Height: extractBlockHeaderHeight(header),
		},
		Time:     time.Unix(int64(extractBlockHeaderUnixTime(header)), 0),
		VoteBits: extractBlockHeaderVoteBits(header),
	}, nil
}

// GetMainChainBlockHashes returns block hashes from the main chain, starting at
// startHash, copying as many as possible into the storage slice and returning a
// subslice for the total number of results.  If the start hash is not in the
// main chain, this function errors.  If inclusive is true, the startHash is
// included in the results, otherwise only blocks after the startHash are
// included.
func (s *Store) GetMainChainBlockHashes(ns walletdb.ReadBucket, startHash *chainhash.Hash,
	inclusive bool, storage []chainhash.Hash) ([]chainhash.Hash, error) {

	header := ns.NestedReadBucket(bucketHeaders).Get(startHash[:])
	if header == nil {
		return nil, errors.E(errors.NotExist, errors.Errorf("starting block %v not found", startHash))
	}
	height := extractBlockHeaderHeight(header)

	// Check that the hash of the recorded main chain block at height is equal
	// to startHash.
	blockRecords := ns.NestedReadBucket(bucketBlocks)
	blockVal := blockRecords.Get(keyBlockRecord(height))
	if !bytes.Equal(extractRawBlockRecordHash(blockVal), startHash[:]) {
		return nil, errors.E(errors.Invalid, errors.Errorf("block %v not in main chain", startHash))
	}

	if !inclusive {
		height++
	}

	i := 0
	for i < len(storage) {
		v := blockRecords.Get(keyBlockRecord(height))
		if v == nil {
			break
		}
		copy(storage[i][:], extractRawBlockRecordHash(v))
		height++
		i++
	}
	return storage[:i], nil
}

// fetchAccountForPkScript fetches an account for a given pkScript given a
// credit value, the script, and an account lookup function. It does this
// to maintain compatibility with older versions of the database.
func (s *Store) fetchAccountForPkScript(addrmgrNs walletdb.ReadBucket,
	credVal []byte, unminedCredVal []byte, pkScript []byte) (uint32, error) {

	// Attempt to get the account from the mined credit. If the account was
	// never stored, we can ignore the error and fall through to do the lookup
	// with the acctLookupFunc.
	//
	// TODO: upgrade the database to actually store the account for every credit
	// to avoid this nonsensical error handling.  The upgrade was not done
	// correctly in the past and only began recording accounts for newly
	// inserted credits without modifying existing ones.
	if credVal != nil {
		acct, err := fetchRawCreditAccount(credVal)
		if err == nil {
			return acct, nil
		}
	}
	if unminedCredVal != nil {
		acct, err := fetchRawUnminedCreditAccount(unminedCredVal)
		if err == nil {
			return acct, nil
		}
	}

	// Neither credVal or unminedCredVal were passed, or if they were, they
	// didn't have the account set. Figure out the account from the pkScript the
	// expensive way.
	_, addrs := stdscript.ExtractAddrs(scriptVersionAssumed, pkScript, s.chainParams)
	if len(addrs) == 0 {
		return 0, errors.New("no addresses decoded from pkScript")
	}

	// Only look at the first address returned. This does not handle
	// multisignature or other custom pkScripts in the correct way, which
	// requires multiple account tracking.
	return s.acctLookupFunc(addrmgrNs, addrs[0])
}

// moveMinedTx moves a transaction record from the unmined buckets to block
// buckets.
func (s *Store) moveMinedTx(ns walletdb.ReadWriteBucket, addrmgrNs walletdb.ReadBucket, rec *TxRecord, recKey, recVal []byte, block *BlockMeta) error {
	log.Debugf("Marking unconfirmed transaction %v mined in block %d",
		&rec.Hash, block.Height)

	// Add transaction to block record.
	blockKey, blockVal := existsBlockRecord(ns, block.Height)
	blockVal, err := appendRawBlockRecord(blockVal, &rec.Hash)
	if err != nil {
		return err
	}
	err = putRawBlockRecord(ns, blockKey, blockVal)
	if err != nil {
		return err
	}

	err = putRawTxRecord(ns, recKey, recVal)
	if err != nil {
		return err
	}
	minedBalance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}

	// For all transaction inputs, remove the previous output marker from the
	// unmined inputs bucket.  For any mined transactions with unspent credits
	// spent by this transaction, mark each spent, remove from the unspents map,
	// and insert a debit record for the spent credit.
	debitIncidence := indexedIncidence{
		incidence: incidence{txHash: rec.Hash, block: block.Block},
		// index set for each rec input below.
	}
	for i, input := range rec.MsgTx.TxIn {
		unspentKey, credKey := existsUnspent(ns, &input.PreviousOutPoint, s.chainParams)

		err = deleteRawUnminedInput(ns, unspentKey)
		if err != nil {
			return err
		}

		if credKey == nil {
			continue
		}

		debitIncidence.index = uint32(i)
		amt, err := spendCredit(ns, credKey, &debitIncidence)
		if err != nil {
			return err
		}

		credVal := existsRawCredit(ns, credKey)
		if credVal == nil {
			return errors.E(errors.IO, errors.Errorf("missing credit "+
				"%v, key %x, spent by %v", &input.PreviousOutPoint, credKey, &rec.Hash))
		}
		creditOpCode := fetchRawCreditTagOpCode(credVal)

		// Do not decrement ticket amounts.
		if !(creditOpCode == txscript.OP_SSTX) {
			minedBalance -= amt
		}
		// Get the coinType from the credit
		coinType := fetchRawCreditCoinType(credVal)
		err = deleteRawUnspent(ns, unspentKey, coinType)
		if err != nil {
			return err
		}

		err = putDebit(ns, &rec.Hash, uint32(i), amt, &block.Block, credKey)
		if err != nil {
			return err
		}
	}

	// For each output of the record that is marked as a credit, if the
	// output is marked as a credit by the unconfirmed store, remove the
	// marker and mark the output as a mined credit in the db.
	//
	// Moved credits are added as unspents, even if there is another
	// unconfirmed transaction which spends them.
	cred := credit{
		outPoint: wire.OutPoint{Hash: rec.Hash},
		block:    block.Block,
		spentBy:  indexedIncidence{index: ^uint32(0)},
	}
	for i := uint32(0); i < uint32(len(rec.MsgTx.TxOut)); i++ {
		k := canonicalOutPoint(&rec.Hash, i)
		v := existsRawUnminedCredit(ns, k, s.chainParams)
		if v == nil {
			continue
		}

		// TODO: This should use the raw apis.  The credit value (it.cv)
		// can be moved from unmined directly to the credits bucket.
		// The key needs a modification to include the block
		// height/hash.
		amount, change, err := fetchRawUnminedCreditAmountChange(v)
		if err != nil {
			return err
		}
		cred.outPoint.Index = i
		cred.amount = amount
		cred.change = change
		cred.opCode = fetchRawUnminedCreditTagOpCode(v)
		cred.isCoinbase = fetchRawUnminedCreditTagIsCoinbase(v)
		cred.hasExpiry = rec.MsgTx.Expiry != wire.NoExpiryValue
		cred.coinType = rec.MsgTx.TxOut[i].CoinType

		// Legacy credit output values may be of the wrong
		// size.
		scrType := fetchRawUnminedCreditScriptType(v)
		scrPos := fetchRawUnminedCreditScriptOffset(v)
		scrLen := fetchRawUnminedCreditScriptLength(v)

		// Grab the pkScript quickly.
		pkScript, err := fetchRawTxRecordPkScript(recKey, recVal,
			cred.outPoint.Index, scrPos, scrLen)
		if err != nil {
			return err
		}

		acct, err := s.fetchAccountForPkScript(addrmgrNs, nil, v, pkScript)
		if err != nil {
			return err
		}

		// For SKA credits, capture the big.Int amount from the unmined side
		// bucket BEFORE deleteRawUnminedCredit (which cascades and clears
		// that bucket). Fall back to rec.MsgTx.TxOut[i].SKAValue when the
		// side-bucket entry is missing — this happens for credits that were
		// stored before the side-bucket migration landed.
		var skaAmt cointype.SKAAmount
		if cred.coinType.IsSKA() {
			skaAmt, err = fetchSKAUnminedCreditAmount(ns, k)
			if err != nil {
				return err
			}
			if skaAmt.IsZero() {
				txOut := rec.MsgTx.TxOut[i]
				if txOut.SKAValue != nil && txOut.SKAValue.Sign() > 0 {
					skaAmt = cointype.NewSKAAmount(txOut.SKAValue)
				}
			}
		}

		err = deleteRawUnminedCredit(ns, k, s.chainParams)
		if err != nil {
			return err
		}
		err = putUnspentCredit(ns, &cred, scrType, scrPos, scrLen, acct, DBVersion)
		if err != nil {
			return err
		}
		err = putUnspent(ns, &cred.outPoint, &block.Block, cred.coinType)
		if err != nil {
			return err
		}

		// Migrate the captured SKA big.Int to the mined side bucket.
		if !skaAmt.IsZero() {
			minedKey := keyCredit(&rec.Hash, i, &block.Block)
			if err := putSKACreditAmount(ns, minedKey, skaAmt); err != nil {
				return err
			}
		}

		// Do not increment ticket credits. SKA credits also bypass the int64
		// minedBalance entirely — their atoms live in the SKA side bucket.
		// This guard keeps the accumulator clean even if an unmined credit
		// stored before the SKA-truncation fix carries a non-zero amount.
		if !(cred.opCode == txscript.OP_SSTX) && !cred.coinType.IsSKA() {
			minedBalance += amount
		}
	}

	err = putMinedBalance(ns, minedBalance)
	if err != nil {
		return err
	}

	err = deleteUnpublished(ns, rec.Hash[:])
	if err != nil {
		return err
	}

	return deleteRawUnmined(ns, rec.Hash[:])
}

// InsertMinedTx inserts a new transaction record for a mined transaction into
// the database.  The block header must have been previously saved.  If the
// exact transaction is already saved as an unmined transaction, it is moved to
// a block.  Other unmined transactions which become double spends are removed.
func (s *Store) InsertMinedTx(dbtx walletdb.ReadWriteTx, rec *TxRecord, blockHash *chainhash.Hash) error {
	ns := dbtx.ReadWriteBucket(wtxmgrBucketKey)
	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrBucketKey)

	// Ensure block is in the main chain before proceeding.
	blockHeader := existsBlockHeader(ns, blockHash[:])
	if blockHeader == nil {
		return errors.E(errors.Invalid, "block header must be recorded")
	}
	height := extractBlockHeaderHeight(blockHeader)
	blockVal := ns.NestedReadBucket(bucketBlocks).Get(keyBlockRecord(height))
	if !bytes.Equal(extractRawBlockRecordHash(blockVal), blockHash[:]) {
		return errors.E(errors.Invalid, "mined transactions must be added to main chain blocks")
	}

	// Fetch the mined balance in case we need to update it.
	minedBalance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}

	// Add a debit record for each unspent credit spent by this tx.
	block := blockMetaFromHeader(blockHash, blockHeader)
	spender := indexedIncidence{
		incidence: incidence{
			txHash: rec.Hash,
			block:  block.Block,
		},
		// index set for each iteration below
	}
	txType := stake.DetermineTxType(&rec.MsgTx)

	invalidated := false
	if txType == stake.TxTypeRegular {
		height := extractBlockHeaderHeight(blockHeader)
		_, rawBlockRecVal := existsBlockRecord(ns, height)
		invalidated = extractRawBlockRecordStakeInvalid(rawBlockRecVal)
	}

	// Process transaction inputs (including augmented SSFee with real UTXO inputs).
	// Augmented SSFee transactions spend existing UTXOs to consolidate fees,
	// preventing dust accumulation. They are processed like regular transactions.
	for i, input := range rec.MsgTx.TxIn {
		unspentKey, credKey := existsUnspent(ns, &input.PreviousOutPoint, s.chainParams)
		if credKey == nil {
			// Debits for unmined transactions are not explicitly
			// tracked.  Instead, all previous outputs spent by any
			// unmined transaction are added to a map for quick
			// lookups when it must be checked whether a mined
			// output is unspent or not.
			//
			// Tracking individual debits for unmined transactions
			// could be added later to simplify (and increase
			// performance of) determining some details that need
			// the previous outputs (e.g. determining a fee), but at
			// the moment that is not done (and a db lookup is used
			// for those cases instead).  There is also a good
			// chance that all unmined transaction handling will
			// move entirely to the db rather than being handled in
			// memory for atomicity reasons, so the simplist
			// implementation is currently used.
			continue
		}

		if invalidated {
			// Add an invalidated debit but do not spend the previous credit,
			// remove it from the utxo set, or decrement the mined balance.
			debKey := keyDebit(&rec.Hash, uint32(i), &block.Block)
			credVal := existsRawCredit(ns, credKey)
			credAmt, err := fetchRawCreditAmount(credVal)
			if err != nil {
				return err
			}
			debVal := valueDebit(credAmt, credKey)
			err = ns.NestedReadWriteBucket(bucketStakeInvalidatedDebits).
				Put(debKey, debVal)
			if err != nil {
				return errors.E(errors.IO, err)
			}
		} else {
			spender.index = uint32(i)
			amt, err := spendCredit(ns, credKey, &spender)
			if err != nil {
				return err
			}
			err = putDebit(ns, &rec.Hash, uint32(i), amt, &block.Block,
				credKey)
			if err != nil {
				return err
			}

			// Don't decrement spent ticket amounts.
			isTicketInput := (txType == stake.TxTypeSSGen && i == 1) ||
				(txType == stake.TxTypeSSRtx && i == 0)
			if !isTicketInput {
				minedBalance -= amt
			}

			// Get the coinType from the credit (credVal fetched earlier at line 1292)
			credVal := existsRawCredit(ns, credKey)
			coinType := fetchRawCreditCoinType(credVal)
			err = deleteRawUnspent(ns, unspentKey, coinType)
			if err != nil {
				return err
			}
		}
	}

	// TODO only update if we actually modified the
	// mined balance.
	err = putMinedBalance(ns, minedBalance)
	if err != nil {
		return err
	}

	// If a transaction record for this tx hash and block already exist,
	// there is nothing left to do.
	k, v := existsTxRecord(ns, &rec.Hash, &block.Block)
	if v != nil {
		return nil
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

	// If the exact tx (not a double spend) is already included but
	// unconfirmed, move it to a block.
	v = existsRawUnmined(ns, rec.Hash[:])
	if v != nil {
		if invalidated {
			return errors.E(errors.Invalid,
				fmt.Sprintf("unimplemented: moveMinedTx called on a stake-invalidated tx: block %v height %v tx %v",
					&block.Hash, block.Height, &rec.Hash))
		}
		return s.moveMinedTx(ns, addrmgrNs, rec, k, v, &block)
	}

	// As there may be unconfirmed transactions that are invalidated by this
	// transaction (either being duplicates, or double spends), remove them
	// from the unconfirmed set.  This also handles removing unconfirmed
	// transaction spend chains if any other unconfirmed transactions spend
	// outputs of the removed double spend.
	err = s.removeDoubleSpends(ns, rec)
	if err != nil {
		return err
	}

	// Adding this transaction hash to the set of transactions from this block.
	blockKey, blockValue := existsBlockRecord(ns, block.Height)
	blockValue, err = appendRawBlockRecord(blockValue, &rec.Hash)
	if err != nil {
		return err
	}
	err = putRawBlockRecord(ns, blockKey, blockValue)
	if err != nil {
		return err
	}

	return putTxRecord(ns, rec, &block.Block)
}

// AddCredit marks a transaction record as containing a transaction output
// spendable by wallet.  The output is added unspent, and is marked spent
// when a new transaction spending the output is inserted into the store.
//
// TODO(jrick): This should not be necessary.  Instead, pass the indexes
// that are known to contain credits when a transaction or merkleblock is
// inserted into the store.
func (s *Store) AddCredit(dbtx walletdb.ReadWriteTx, rec *TxRecord, block *BlockMeta,
	index uint32, change bool, account uint32) error {

	ns := dbtx.ReadWriteBucket(wtxmgrBucketKey)

	if int(index) >= len(rec.MsgTx.TxOut) {
		return errors.E(errors.Invalid, "transaction output index for credit does not exist")
	}

	invalidated := false
	if rec.TxType == stake.TxTypeRegular && block != nil {
		blockHeader := existsBlockHeader(ns, block.Hash[:])
		height := extractBlockHeaderHeight(blockHeader)
		_, rawBlockRecVal := existsBlockRecord(ns, height)
		invalidated = extractRawBlockRecordStakeInvalid(rawBlockRecVal)
	}
	if invalidated {
		// Write an invalidated credit.  Do not create a utxo for the output,
		// and do not increment the mined balance.
		version := rec.MsgTx.TxOut[index].Version
		pkScript := rec.MsgTx.TxOut[index].PkScript
		k := keyCredit(&rec.Hash, index, &block.Block)
		isCoinbase := compat.IsEitherCoinBaseTx(&rec.MsgTx)
		// SKA emission transactions should be treated like coinbase for maturity.
		// They create new coins from nothing and require the same maturity period.
		if !isCoinbase && wire.IsSKAEmissionTransaction(&rec.MsgTx) {
			isCoinbase = true
		}
		// SSFee MF (Miner Fee) transactions should be treated like coinbase for maturity.
		if !isCoinbase && isSSFeeMinerTx(&rec.MsgTx) {
			isCoinbase = true
		}
		// SKA credits keep amount=0; the atoms live in the SKA side bucket.
		var stakeInvalidAmt dcrutil.Amount
		if !rec.MsgTx.TxOut[index].CoinType.IsSKA() {
			stakeInvalidAmt = dcrutil.Amount(rec.MsgTx.TxOut[index].Value)
		}
		cred := credit{
			outPoint: wire.OutPoint{
				Hash:  rec.Hash,
				Index: index,
			},
			block:      block.Block,
			amount:     stakeInvalidAmt,
			change:     change,
			spentBy:    indexedIncidence{index: ^uint32(0)},
			opCode:     getStakeOpCode(version, pkScript),
			isCoinbase: isCoinbase,
			hasExpiry:  rec.MsgTx.Expiry != 0,
			coinType:   rec.MsgTx.TxOut[index].CoinType,
		}
		scTy := pkScriptType(version, pkScript)
		scLoc := uint32(rec.MsgTx.PkScriptLocs()[index])
		v := valueUnspentCredit(&cred, scTy, scLoc, uint32(len(pkScript)),
			account, DBVersion)
		err := ns.NestedReadWriteBucket(bucketStakeInvalidatedCredits).Put(k, v)
		if err != nil {
			return errors.E(errors.IO, err)
		}
		return nil
	}

	_, err := s.addCredit(ns, rec, block, index, change, account)
	return err
}

// getStakeOpCode returns opNonstake for non-stake transactions, or the stake op
// code tag for stake transactions. This excludes TADD.
func getStakeOpCode(version uint16, pkScript []byte) uint8 {
	class := stdscript.DetermineScriptType(version, pkScript)
	switch class {
	case stdscript.STStakeSubmissionPubKeyHash, stdscript.STStakeSubmissionScriptHash:
		return txscript.OP_SSTX
	case stdscript.STStakeGenPubKeyHash, stdscript.STStakeGenScriptHash:
		return txscript.OP_SSGEN
	case stdscript.STStakeRevocationPubKeyHash, stdscript.STStakeRevocationScriptHash:
		return txscript.OP_SSRTX
	case stdscript.STStakeChangePubKeyHash, stdscript.STStakeChangeScriptHash:
		return txscript.OP_SSTXCHANGE
	case stdscript.STTreasuryGenPubKeyHash, stdscript.STTreasuryGenScriptHash:
		return txscript.OP_TGEN
	}

	return opNonstake
}

// pkScriptType determines the general type of pkScript for the purposes of
// fast extraction of pkScript data from a raw transaction record.
func pkScriptType(ver uint16, pkScript []byte) scriptType {
	class := stdscript.DetermineScriptType(ver, pkScript)
	switch class {
	case stdscript.STPubKeyHashEcdsaSecp256k1:
		return scriptTypeP2PKH
	case stdscript.STPubKeyEcdsaSecp256k1:
		return scriptTypeP2PK
	case stdscript.STScriptHash:
		return scriptTypeP2SH
	case stdscript.STPubKeyHashEd25519, stdscript.STPubKeyHashSchnorrSecp256k1:
		return scriptTypeP2PKHAlt
	case stdscript.STPubKeyEd25519, stdscript.STPubKeySchnorrSecp256k1:
		return scriptTypeP2PKAlt
	case stdscript.STStakeSubmissionPubKeyHash, stdscript.STStakeGenPubKeyHash,
		stdscript.STStakeRevocationPubKeyHash, stdscript.STStakeChangePubKeyHash,
		stdscript.STTreasuryGenPubKeyHash:
		return scriptTypeSP2PKH
	case stdscript.STStakeSubmissionScriptHash, stdscript.STStakeGenScriptHash,
		stdscript.STStakeRevocationScriptHash, stdscript.STStakeChangeScriptHash,
		stdscript.STTreasuryGenScriptHash:
		return scriptTypeSP2SH
	}

	return scriptTypeUnspecified
}

// addCredit creates a credit entry for a transaction output.
// This function handles all output types including:
// - Regular transaction outputs
// - Coinbase outputs
// - SSFee outputs (both null-input and augmented)
//
// For augmented SSFee transactions (Phase 3), the transaction spends an existing
// UTXO as input and creates a new output with value = input + fee. The wallet
// automatically handles this by:
// 1. Creating a debit for the input (when InsertMinedTx processes inputs)
// 2. Creating a credit for the output (here)
// 3. Net balance change = output - input = fee amount
func (s *Store) addCredit(ns walletdb.ReadWriteBucket, rec *TxRecord, block *BlockMeta,
	index uint32, change bool, account uint32) (bool, error) {

	// Reject malformed SKA outputs upfront, before any DB writes. An SKA
	// TxOut with a nil or non-positive SKAValue would otherwise be tracked
	// as an unspent credit with no recoverable amount — effectively a
	// silently-corrupt UTXO. The companion VAR Value field must be exactly
	// zero on SKA outputs (the dual-coin protocol uses Value for VAR atoms
	// only); a non-zero Value alongside a SKAValue is a wire-protocol
	// violation that we refuse to bookkeep here even if the upstream
	// validator missed it.
	if rec.MsgTx.TxOut[index].CoinType.IsSKA() {
		skaValue := rec.MsgTx.TxOut[index].SKAValue
		if skaValue == nil || skaValue.Sign() <= 0 {
			return false, errors.E(errors.Invalid,
				"SKA output with nil or non-positive SKAValue cannot be credited")
		}
		if rec.MsgTx.TxOut[index].Value != 0 {
			return false, errors.E(errors.Invalid,
				"SKA output with non-zero VAR Value cannot be credited")
		}
	}

	scriptVersion, pkScript := rec.MsgTx.TxOut[index].Version, rec.MsgTx.TxOut[index].PkScript
	opCode := getStakeOpCode(scriptVersion, pkScript)
	isCoinbase := compat.IsEitherCoinBaseTx(&rec.MsgTx)

	// SKA emission transactions should be treated like coinbase for maturity.
	// They create new coins from nothing and require the same maturity period.
	if !isCoinbase && wire.IsSKAEmissionTransaction(&rec.MsgTx) {
		isCoinbase = true
	}

	// SSFee MF (Miner Fee) transactions should be treated like coinbase for maturity.
	// They distribute fees to miners and need the same maturity period as regular coinbase.
	// This applies to both null-input and augmented SSFee transactions.
	if !isCoinbase && isSSFeeMinerTx(&rec.MsgTx) {
		isCoinbase = true
	}

	hasExpiry := rec.MsgTx.Expiry != wire.NoExpiryValue

	if block == nil {
		// Unmined tx must have been already added for the credit to be added.
		if existsRawUnmined(ns, rec.Hash[:]) == nil {
			return false, errors.E(errors.Invalid,
				"attempted to add credit for unmined tx, but unmined tx with same hash does not exist")
		}

		k := canonicalOutPoint(&rec.Hash, index)
		if existsRawUnminedCredit(ns, k, s.chainParams) != nil {
			return false, nil
		}
		scrType := pkScriptType(scriptVersion, pkScript)
		pkScrLocs := rec.MsgTx.PkScriptLocs()
		scrLoc := pkScrLocs[index]
		scrLen := len(pkScript)

		txOut := rec.MsgTx.TxOut[index]
		// For SKA outputs the int64 credit-value slot must stay 0; the
		// authoritative atom count lives in the SKA side bucket. Routing
		// SKA atoms through txOut.GetValue() (which silently truncates to
		// SKAValue.Int64() when it fits) would pollute the int64
		// accounting paths shared with VAR.
		var unminedCredAmt dcrutil.Amount
		if !txOut.CoinType.IsSKA() {
			unminedCredAmt = dcrutil.Amount(txOut.Value)
		}
		v := valueUnminedCredit(unminedCredAmt,
			change, opCode, isCoinbase, hasExpiry, scrType, uint32(scrLoc),
			uint32(scrLen), account, txOut.CoinType, DBVersion)
		err := putRawUnminedCredit(ns, k, v)
		if err != nil {
			return false, err
		}

		// For SKA credits, also store the big.Int amount separately
		// since SKAValue may exceed int64 capacity
		if txOut.CoinType.IsSKA() {
			var skaAmt cointype.SKAAmount
			if txOut.SKAValue != nil {
				skaAmt = cointype.NewSKAAmount(txOut.SKAValue)
			}
			if !skaAmt.IsZero() {
				if err := putSKAUnminedCreditAmount(ns, k, skaAmt); err != nil {
					return false, err
				}
			}
		}
		return true, nil
	}

	k, v := existsCredit(ns, &rec.Hash, index, &block.Block)
	if v != nil {
		// Credit exists, but SKA amount might not be stored yet (migration case)
		// Check if this is a SKA credit and store the big.Int amount if missing
		txOut := rec.MsgTx.TxOut[index]
		if txOut.CoinType.IsSKA() {
			existingSKA, err := fetchSKACreditAmount(ns, k)
			if err != nil {
				return false, err
			}
			if existingSKA.IsZero() {
				var skaAmt cointype.SKAAmount
				if txOut.SKAValue != nil && txOut.SKAValue.Sign() > 0 {
					skaAmt = cointype.NewSKAAmount(txOut.SKAValue)
				}
				if !skaAmt.IsZero() {
					if err := putSKACreditAmount(ns, k, skaAmt); err != nil {
						return false, err
					}
				}
			}
		}
		return false, nil
	}

	txOut := rec.MsgTx.TxOut[index]
	// For SKA outputs the int64 credit amount slot must stay 0 — the
	// authoritative atom count lives in the SKA side bucket
	// (putSKACreditAmount below). Sending SKA atoms through
	// txOut.GetValue() would silently leak them into the wallet's int64
	// minedBalance accumulator.
	var txOutAmt dcrutil.Amount
	if !txOut.CoinType.IsSKA() {
		txOutAmt = dcrutil.Amount(txOut.Value)
	}

	cred := credit{
		outPoint: wire.OutPoint{
			Hash:  rec.Hash,
			Index: index,
		},
		block:      block.Block,
		amount:     txOutAmt,
		change:     change,
		spentBy:    indexedIncidence{index: ^uint32(0)},
		opCode:     opCode,
		isCoinbase: isCoinbase,
		hasExpiry:  rec.MsgTx.Expiry != wire.NoExpiryValue,
		coinType:   txOut.CoinType,
	}
	scrType := pkScriptType(scriptVersion, pkScript)
	pkScrLocs := rec.MsgTx.PkScriptLocs()
	scrLoc := pkScrLocs[index]
	scrLen := len(pkScript)

	v = valueUnspentCredit(&cred, scrType, uint32(scrLoc), uint32(scrLen),
		account, DBVersion)
	err := putRawCredit(ns, k, v)
	if err != nil {
		return false, err
	}

	// For SKA credits, also store the big.Int amount separately
	// since SKAValue may exceed int64 capacity
	if txOut.CoinType.IsSKA() && txOut.SKAValue != nil && txOut.SKAValue.Sign() > 0 {
		skaAmt := cointype.NewSKAAmount(txOut.SKAValue)
		if err := putSKACreditAmount(ns, k, skaAmt); err != nil {
			return false, err
		}
	}

	minedBalance, err := fetchMinedBalance(ns)
	if err != nil {
		return false, err
	}
	// Update the balance so long as it's not a ticket output. SKA credits
	// never touch the int64 minedBalance accumulator — those atoms are
	// tracked exclusively through the SKA side bucket, and even txOutAmt=0
	// is skipped here as defense-in-depth against any future regression
	// reintroducing a non-zero amount on the SKA path.
	if !(opCode == txscript.OP_SSTX) && !txOut.CoinType.IsSKA() {
		err = putMinedBalance(ns, minedBalance+txOutAmt)
		if err != nil {
			return false, err
		}
	}

	return true, putUnspent(ns, &cred.outPoint, &block.Block, cred.coinType)
}

// AddTicketCommitment adds the given output of a transaction as a ticket
// commitment originating from a wallet account.
//
// The transaction record MUST correspond to a ticket (sstx) transaction, the
// index MUST be from a commitment output and the account MUST be from a
// wallet-controlled account, otherwise the database will be put in an undefined
// state.
func (s *Store) AddTicketCommitment(ns walletdb.ReadWriteBucket, rec *TxRecord,
	index, account uint32) error {

	k := keyTicketCommitment(rec.Hash, index)
	v := existsRawTicketCommitment(ns, k)
	if v != nil {
		// If we have already recorded this ticket commitment, there's nothing
		// else to do. Note that this means unspent ticket commitment entries
		// are added to the index only once, at the very first time the ticket
		// commitment is seen.
		return nil
	}

	if index >= uint32(len(rec.MsgTx.TxOut)) {
		return errors.E(errors.Invalid, "index should be of an existing output")
	}

	if index%2 != 1 {
		return errors.E(errors.Invalid, "index should be of a ticket commitment")
	}

	if rec.TxType != stake.TxTypeSStx {
		return errors.E(errors.Invalid, "transaction record should be of a ticket")
	}

	txOut := rec.MsgTx.TxOut[index]
	txOutAmt, err := stake.AmountFromSStxPkScrCommitment(txOut.PkScript)
	if err != nil {
		return err
	}

	// In a ticket transaction:
	// - Output 0: The submission output (the actual ticket price)
	// - Output 1,3,5...: Commitment outputs (contain price + fee in script)
	// The fee is the difference between the commitment amount and the submission output
	submissionOutput := rec.MsgTx.TxOut[0]
	ticketPrice := dcrutil.Amount(submissionOutput.Value)

	// The commitment amount includes both price and fee
	// We only want to store the actual ticket price as "locked"
	// The fee portion (txOutAmt - ticketPrice) is paid to miners
	actualTicketPrice := ticketPrice

	log.Debugf("Accounting for ticket commitment %v:%d (commitment amt: %v, ticket price: %v) from the wallet",
		rec.Hash, index, txOutAmt, actualTicketPrice)

	v = valueTicketCommitment(actualTicketPrice, account)
	err = putRawTicketCommitment(ns, k, v)
	if err != nil {
		return err
	}

	v = valueUnspentTicketCommitment(false)
	return putRawUnspentTicketCommitment(ns, k, v)
}

// originalTicketInfo returns the transaction hash and output count for the
// ticket spent by the given transaction.
//
// spenderType MUST be either TxTypeSSGen or TxTypeSSRtx and MUST by the type of
// the provided spenderTx, otherwise the result is undefined.
func originalTicketInfo(spenderType stake.TxType, spenderTx *wire.MsgTx) (chainhash.Hash, uint32) {
	if spenderType == stake.TxTypeSSGen {
		// Votes have an additional input (stakebase) and two additional outputs
		// (previous block hash and vote bits) so account for those.
		return spenderTx.TxIn[1].PreviousOutPoint.Hash,
			uint32((len(spenderTx.TxOut)-2)*2 + 1)
	}

	return spenderTx.TxIn[0].PreviousOutPoint.Hash,
		uint32(len(spenderTx.TxOut)*2 + 1)
}

// removeUnspentTicketCommitments deletes any outstanding commitments that are
// controlled by this wallet and have been redeemed by the given transaction.
//
// rec MUST be either a vote or revocation transaction, otherwise the results
// are undefined.
func (s *Store) removeUnspentTicketCommitments(ns walletdb.ReadWriteBucket,
	txType stake.TxType, tx *wire.MsgTx) error {

	ticketHash, ticketOutCount := originalTicketInfo(txType, tx)
	for i := uint32(1); i < ticketOutCount; i += 2 {
		k := keyTicketCommitment(ticketHash, i)
		if existsRawTicketCommitment(ns, k) == nil {
			// This commitment was not tracked by the wallet, so ignore it.
			continue
		}

		log.Debugf("Removing unspent ticket commitment %v:%d from the wallet",
			ticketHash, i)

		err := deleteRawUnspentTicketCommitment(ns, k)
		if err != nil {
			return err
		}
	}

	return nil
}

// replaceTicketCommitmentUnminedSpent replaces the unminedSpent flag of all
// unspent commitments spent by the given transaction to the given value.
//
// txType MUST be either a TxTypeSSGen or TxTypeSSRtx and MUST be the type for
// the corresponding tx parameter, otherwise the result is undefined.
func (s *Store) replaceTicketCommitmentUnminedSpent(ns walletdb.ReadWriteBucket,
	txType stake.TxType, tx *wire.MsgTx, value bool) error {

	ticketHash, ticketOutCount := originalTicketInfo(txType, tx)

	// Loop over the indices of possible ticket commitments, checking if they
	// are controlled by the wallet. If they are, replace the corresponding
	// unminedSpent flag.
	for i := uint32(1); i < ticketOutCount; i += 2 {
		k := keyTicketCommitment(ticketHash, i)
		if existsRawTicketCommitment(ns, k) == nil {
			// This commitment was not tracked by the wallet, so ignore it.
			continue
		}

		log.Debugf("Marking ticket commitment %v:%d unmined spent as %v",
			ticketHash, i, value)
		v := valueUnspentTicketCommitment(value)
		err := putRawUnspentTicketCommitment(ns, k, v)
		if err != nil {
			return err
		}
	}

	return nil
}

// RedeemTicketCommitments redeems the commitments of the given vote or
// revocation transaction by marking the commitments unminedSpent or removing
// them altogether.
//
// rec MUST be either a vote (ssgen) or revocation (ssrtx) or this method fails.
func (s *Store) RedeemTicketCommitments(ns walletdb.ReadWriteBucket, rec *TxRecord,
	block *BlockMeta) error {

	if (rec.TxType != stake.TxTypeSSGen) && (rec.TxType != stake.TxTypeSSRtx) {
		return errors.E(errors.Invalid, "rec must be a vote or revocation tx")
	}

	if block == nil {
		// When the tx is unmined, we only mark the commitment as spent by an
		// unmined tx.
		return s.replaceTicketCommitmentUnminedSpent(ns, rec.TxType,
			&rec.MsgTx, true)
	}

	// When the tx is mined we completely remove the commitment from the unspent
	// commitments index.
	return s.removeUnspentTicketCommitments(ns, rec.TxType, &rec.MsgTx)
}

// copied from txscript/v1
func getScriptHashFromP2SHScript(pkScript []byte) ([]byte, error) {
	// Scan through the opcodes until the first HASH160 opcode is found.
	const scriptVersion = 0
	tokenizer := txscript.MakeScriptTokenizer(scriptVersion, pkScript)
	for tokenizer.Next() {
		if tokenizer.Opcode() == txscript.OP_HASH160 {
			break
		}
	}

	// Attempt to extract the script hash if the script is not already fully
	// parsed and didn't already fail during parsing above.
	//
	// Note that this means a script without a data push for the script hash or
	// where OP_HASH160 wasn't found will result in nil data being returned.
	// This was done to preserve existing behavior, although it is questionable
	// since a p2sh script has a specific form and if there is no push here,
	// it's not really a p2sh script and thus should probably have returned an
	// appropriate error for calling the function incorrectly.
	if tokenizer.Next() {
		return tokenizer.Data(), nil
	}
	return nil, tokenizer.Err()
}

// AddMultisigOut adds a P2SH multisignature spendable output into the
// transaction manager. In the event that the output already existed but
// was not mined, the output is updated so its value reflects the block
// it was included in.
func (s *Store) AddMultisigOut(dbtx walletdb.ReadWriteTx, rec *TxRecord, block *BlockMeta, index uint32) error {
	ns := dbtx.ReadWriteBucket(wtxmgrBucketKey)
	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrBucketKey)

	if int(index) >= len(rec.MsgTx.TxOut) {
		return errors.E(errors.Invalid, "transaction output does not exist")
	}

	empty := &chainhash.Hash{}

	// Check to see if the output already exists and is now being
	// mined into a block. If it does, update the record and return.
	key := keyMultisigOut(rec.Hash, index)
	val := existsMultisigOutCopy(ns, key)
	if val != nil && block != nil {
		blockHashV, _ := fetchMultisigOutMined(val)
		if blockHashV.IsEqual(empty) {
			setMultisigOutMined(val, block.Block.Hash,
				uint32(block.Block.Height))
			return putMultisigOutRawValues(ns, key, val)
		}
		return errors.E(errors.Invalid, "multisig credit is mined")
	}
	// The multisignature output already exists in the database
	// as an unmined, unspent output and something is trying to
	// add it in duplicate. Return.
	if val != nil && block == nil {
		blockHashV, _ := fetchMultisigOutMined(val)
		if blockHashV.IsEqual(empty) {
			return nil
		}
	}

	// Dummy block for created transactions.
	if block == nil {
		block = &BlockMeta{Block{*empty, 0},
			rec.Received,
			0}
	}

	// Otherwise create a full record and insert it.
	version := rec.MsgTx.TxOut[index].Version
	p2shScript := rec.MsgTx.TxOut[index].PkScript
	class := stdscript.DetermineScriptType(version, p2shScript)
	tree := wire.TxTreeRegular
	class, isStakeType := txrules.StakeSubScriptType(class)
	if isStakeType {
		tree = wire.TxTreeStake
	}
	if class != stdscript.STScriptHash {
		return errors.E(errors.Invalid, "multisig output must be P2SH")
	}
	scriptHash, err := getScriptHashFromP2SHScript(p2shScript)
	if err != nil {
		return err
	}
	multisigScript, err := s.manager.redeemScriptForHash160(addrmgrNs, scriptHash)
	if err != nil {
		return err
	}
	if version != 0 {
		return errors.E(errors.IO, "only version 0 scripts are supported")
	}
	multisigDetails := stdscript.ExtractMultiSigScriptDetailsV0(multisigScript, false)
	if !multisigDetails.Valid {
		return errors.E(errors.IO, "invalid m-of-n multisig script")
	}
	var p2shScriptHash [ripemd160.Size]byte
	copy(p2shScriptHash[:], scriptHash)
	txOut := rec.MsgTx.TxOut[index]
	ct := txOut.CoinType
	// Reject malformed SKA outputs before any DB write. addCredit applies
	// the same gate; without it here a wire-protocol violation (CoinType=SKA
	// with nil/non-positive SKAValue, or a non-zero VAR Value) would be
	// silently coerced to a (VAR, 0) record.
	if ct.IsSKA() {
		if txOut.SKAValue == nil || txOut.SKAValue.Sign() <= 0 {
			return errors.E(errors.Invalid,
				"SKA multisig output with nil or non-positive SKAValue cannot be recorded")
		}
		if txOut.Value != 0 {
			return errors.E(errors.Invalid,
				"SKA multisig output with non-zero VAR Value cannot be recorded")
		}
	}
	var varAmount dcrutil.Amount
	skaAmount := cointype.Zero()
	if ct.IsSKA() {
		skaAmount = cointype.NewSKAAmount(txOut.SKAValue)
	} else {
		varAmount = dcrutil.Amount(txOut.GetValue())
	}
	val, err = valueMultisigOut(p2shScriptHash,
		uint8(multisigDetails.RequiredSigs),
		uint8(multisigDetails.NumPubKeys),
		false,
		tree,
		block.Block.Hash,
		uint32(block.Block.Height),
		varAmount,
		*empty,     // Unspent
		0xFFFFFFFF, // Unspent
		rec.Hash,
		ct,
		skaAmount)
	if err != nil {
		return err
	}

	// Write the output, and insert the unspent key.
	err = putMultisigOutRawValues(ns, key, val)
	if err != nil {
		return err
	}
	return putMultisigOutUS(ns, key)
}

// SpendMultisigOut spends a multisignature output by making it spent in
// the general bucket and removing it from the unspent bucket.
func (s *Store) SpendMultisigOut(ns walletdb.ReadWriteBucket, op *wire.OutPoint, spendHash chainhash.Hash, spendIndex uint32) error {
	// Mark the output spent.
	key := keyMultisigOut(op.Hash, op.Index)
	val := existsMultisigOutCopy(ns, key)
	if val == nil {
		return errors.E(errors.NotExist, errors.Errorf("no multisig output for outpoint %v", op))
	}
	// Attempting to double spend an outpoint is an error.
	if fetchMultisigOutSpent(val) {
		_, foundSpendHash, foundSpendIndex := fetchMultisigOutSpentVerbose(val)
		// It's not technically an error to try to respend
		// the output with exactly the same transaction.
		// However, there's no need to set it again. Just return.
		if spendHash == foundSpendHash && foundSpendIndex == spendIndex {
			return nil
		}
		return errors.E(errors.DoubleSpend, errors.Errorf("outpoint %v spent by %v", op, &foundSpendHash))
	}
	setMultisigOutSpent(val, spendHash, spendIndex)

	// Check to see that it's in the unspent bucket.
	existsUnspent := existsMultisigOutUS(ns, key)
	if !existsUnspent {
		return errors.E(errors.IO, "missing unspent multisig record")
	}

	// Write the updated output, and delete the unspent key.
	err := putMultisigOutRawValues(ns, key, val)
	if err != nil {
		return err
	}
	return deleteMultisigOutUS(ns, key)
}

func approvesParent(voteBits uint16) bool {
	return dcrutil.IsFlagSet16(voteBits, dcrutil.BlockValid)
}

// Rollback removes all blocks at height onwards, moving any transactions within
// each block to the unconfirmed pool.
func (s *Store) Rollback(dbtx walletdb.ReadWriteTx, height int32) error {
	// Note: does not stake validate the parent block at height-1.  Assumes the
	// rollback is being done to add more blocks starting at height, and stake
	// validation will occur when that block is attached.

	ns := dbtx.ReadWriteBucket(wtxmgrBucketKey)
	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrBucketKey)

	if height == 0 {
		return errors.E(errors.Invalid, "cannot rollback the genesis block")
	}

	minedBalance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}

	// Keep track of all credits that were removed from coinbase
	// transactions.  After detaching all blocks, if any transaction record
	// exists in unmined that spends these outputs, remove them and their
	// spend chains.
	//
	// It is necessary to keep these in memory and fix the unmined
	// transactions later since blocks are removed in increasing order.
	var coinBaseCredits []wire.OutPoint

	var heightsToRemove []int32

	it := makeReverseBlockIterator(ns)
	defer it.close()
	for it.prev() {
		b := &it.elem
		if it.elem.Height < height {
			break
		}

		heightsToRemove = append(heightsToRemove, it.elem.Height)

		log.Debugf("Rolling back transactions from block %v height %d",
			b.Hash, b.Height)

		// cache the values of removed credits so they can be inspected even
		// after removal from the db.
		removedCredits := make(map[string][]byte)

		for i := range b.transactions {
			txHash := &b.transactions[i]

			recKey := keyTxRecord(txHash, &b.Block)
			recVal := existsRawTxRecord(ns, recKey)
			var rec TxRecord
			err = readRawTxRecord(txHash, recVal, &rec)
			if err != nil {
				return err
			}

			err = deleteTxRecord(ns, txHash, &b.Block)
			if err != nil {
				return err
			}

			// Handle coinbase transactions specially since they are
			// not moved to the unconfirmed store.  A coinbase cannot
			// contain any debits, but all credits should be removed
			// and the mined balance decremented.
			if compat.IsEitherCoinBaseTx(&rec.MsgTx) {
				for i, output := range rec.MsgTx.TxOut {
					k, v := existsCredit(ns, &rec.Hash,
						uint32(i), &b.Block)
					if v == nil {
						continue
					}

					coinBaseCredits = append(coinBaseCredits, wire.OutPoint{
						Hash:  rec.Hash,
						Index: uint32(i),
						Tree:  wire.TxTreeRegular,
					})

					outPointKey := canonicalOutPoint(&rec.Hash, uint32(i))
					credKey := existsRawUnspent(ns, outPointKey, s.chainParams)
					if credKey != nil {
						// VAR-only aggregate; SKA totals live in per-coin-type buckets.
						minedBalance -= dcrutil.Amount(output.Value)
						// Get the coinType from the credit value (v)
						coinType := fetchRawCreditCoinType(v)
						err = deleteRawUnspent(ns, outPointKey, coinType)
						if err != nil {
							return err
						}
					}
					removedCredits[string(k)] = v
					// Coinbase rollback permanently discards the credit; the
					// cascading deleteRawCredit also clears the SKA side bucket.
					err = deleteRawCredit(ns, k)
					if err != nil {
						return err
					}

					// Check if this output is a multisignature
					// P2SH output. If it is, access the value
					// for the key and mark it unmined.
					msKey := keyMultisigOut(*txHash, uint32(i))
					msVal := existsMultisigOutCopy(ns, msKey)
					if msVal != nil {
						setMultisigOutUnmined(msVal)
						err := putMultisigOutRawValues(ns, msKey, msVal)
						if err != nil {
							return err
						}
					}
				}

				continue
			}

			err = putRawUnmined(ns, txHash[:], recVal)
			if err != nil {
				return err
			}

			txType := rec.TxType

			// For each debit recorded for this transaction, mark
			// the credit it spends as unspent (as long as it still
			// exists) and delete the debit.  The previous output is
			// recorded in the unconfirmed store for every previous
			// output, not just debits.
			for i, input := range rec.MsgTx.TxIn {
				// Skip stakebases.
				if i == 0 && txType == stake.TxTypeSSGen {
					continue
				}

				prevOut := &input.PreviousOutPoint
				prevOutKey := canonicalOutPoint(&prevOut.Hash,
					prevOut.Index)
				err = putRawUnminedInput(ns, prevOutKey, rec.Hash[:])
				if err != nil {
					return err
				}

				// If this input is a debit, remove the debit
				// record and mark the credit that it spent as
				// unspent, incrementing the mined balance.
				debKey, credKey, err := existsDebit(ns,
					&rec.Hash, uint32(i), &b.Block)
				if err != nil {
					return err
				}
				if debKey == nil {
					continue
				}

				// Store the credit OP code for later use.  Since the credit may
				// already have been removed if it also appeared in this block,
				// a cache of removed credits is also checked.
				credVal := existsRawCredit(ns, credKey)
				if credVal == nil {
					credVal = removedCredits[string(credKey)]
				}
				if credVal == nil {
					return errors.E(errors.IO, errors.Errorf("missing credit "+
						"%v, key %x, spent by %v", prevOut, credKey, &rec.Hash))
				}
				creditOpCode := fetchRawCreditTagOpCode(credVal)

				// unspendRawCredit does not error in case the no credit exists
				// for this key, but this behavior is correct.  Since
				// transactions are removed in an unspecified order
				// (transactions in the blo	ck record are not sorted by
				// appearance in the block), this credit may have already been
				// removed.
				var amt dcrutil.Amount
				amt, err = unspendRawCredit(ns, credKey)
				if err != nil {
					return err
				}

				err = deleteRawDebit(ns, debKey)
				if err != nil {
					return err
				}

				// If the credit was previously removed in the
				// rollback, the credit amount is zero.  Only
				// mark the previously spent credit as unspent
				// if it still exists.
				if amt == 0 {
					continue
				}
				unspentVal, err := fetchRawCreditUnspentValue(credKey)
				if err != nil {
					return err
				}

				// Get coin type from the credit
				coinType := fetchRawCreditCoinType(credVal)

				// Ticket output spends are never decremented, so no need
				// to add them back.
				if !(creditOpCode == txscript.OP_SSTX) {
					minedBalance += amt
				}

				err = putRawUnspent(ns, prevOutKey, unspentVal, coinType)
				if err != nil {
					return err
				}

				// Check if this input uses a multisignature P2SH
				// output. If it did, mark the output unspent
				// and create an entry in the unspent bucket.
				msVal := existsMultisigOutCopy(ns, prevOutKey)
				if msVal != nil {
					setMultisigOutUnSpent(msVal)
					err := putMultisigOutRawValues(ns, prevOutKey, msVal)
					if err != nil {
						return err
					}
					err = putMultisigOutUS(ns, prevOutKey)
					if err != nil {
						return err
					}
				}
			}

			// For each detached non-coinbase credit, move the
			// credit output to unmined.  If the credit is marked
			// unspent, it is removed from the utxo set and the
			// mined balance is decremented.
			//
			// TODO: use a credit iterator
			for i, output := range rec.MsgTx.TxOut {
				k, v := existsCredit(ns, &rec.Hash, uint32(i),
					&b.Block)
				if v == nil {
					continue
				}
				vcopy := make([]byte, len(v))
				copy(vcopy, v)
				removedCredits[string(k)] = vcopy

				amt, change, err := fetchRawCreditAmountChange(v)
				if err != nil {
					return err
				}
				opCode := fetchRawCreditTagOpCode(v)
				isCoinbase := fetchRawCreditIsCoinbase(v)
				hasExpiry := fetchRawCreditHasExpiry(v, DBVersion)

				scrType := pkScriptType(output.Version, output.PkScript)
				scrLoc := rec.MsgTx.PkScriptLocs()[i]
				scrLen := len(rec.MsgTx.TxOut[i].PkScript)

				acct, err := s.fetchAccountForPkScript(addrmgrNs, v, nil, output.PkScript)
				if err != nil {
					return err
				}

				outPointKey := canonicalOutPoint(&rec.Hash, uint32(i))
				unminedCredVal := valueUnminedCredit(amt, change, opCode,
					isCoinbase, hasExpiry, scrType, uint32(scrLoc), uint32(scrLen),
					acct, output.CoinType, DBVersion)
				err = putRawUnminedCredit(ns, outPointKey, unminedCredVal)
				if err != nil {
					return err
				}

				// For SKA credits, migrate the big.Int amount from the mined
				// side bucket to the unmined side bucket BEFORE deleteRawCredit
				// (which cascades and clears the mined entry). The keys differ:
				// mined credits are keyed by the 72-byte keyCredit, unmined
				// credits by the 36-byte canonicalOutPoint.
				if output.CoinType.IsSKA() {
					skaAmt, err := fetchSKACreditAmount(ns, k)
					if err != nil {
						return err
					}
					if !skaAmt.IsZero() {
						if err := putSKAUnminedCreditAmount(ns, outPointKey, skaAmt); err != nil {
							return err
						}
					}
				}

				err = deleteRawCredit(ns, k)
				if err != nil {
					return err
				}

				credKey := existsRawUnspent(ns, outPointKey, s.chainParams)
				if credKey != nil {
					// Ticket amounts were never added, so ignore them when
					// correcting the balance.
					isTicketOutput := (txType == stake.TxTypeSStx && i == 0)
					if !isTicketOutput {
						// VAR-only aggregate; SKA amounts were migrated to
						// bucketSKAUnminedCreditAmounts above.
						minedBalance -= dcrutil.Amount(output.Value)
					}
					// Use the coinType from the output
					err = deleteRawUnspent(ns, outPointKey, output.CoinType)
					if err != nil {
						return err
					}
				}

				// Check if this output is a multisignature
				// P2SH output. If it is, access the value
				// for the key and mark it unmined.
				msKey := keyMultisigOut(*txHash, uint32(i))
				msVal := existsMultisigOutCopy(ns, msKey)
				if msVal != nil {
					setMultisigOutUnmined(msVal)
					err := putMultisigOutRawValues(ns, msKey, msVal)
					if err != nil {
						return err
					}
				}
			}

			// When rolling back votes and revocations, return unspent status
			// for tracked commitments.
			if (rec.TxType == stake.TxTypeSSGen) || (rec.TxType == stake.TxTypeSSRtx) {
				err = s.replaceTicketCommitmentUnminedSpent(ns, rec.TxType, &rec.MsgTx, true)
				if err != nil {
					return err
				}
			}
		}

		// reposition cursor before deleting this k/v pair and advancing to the
		// previous.
		it.reposition(it.elem.Height)

		// Avoid cursor deletion until bolt issue #620 is resolved.
		// err = it.delete()
		// if err != nil {
		// 	return err
		// }
	}
	if it.err != nil {
		return it.err
	}

	// Delete the block records outside of the iteration since cursor deletion
	// is broken.
	for _, h := range heightsToRemove {
		err = deleteBlockRecord(ns, h)
		if err != nil {
			return err
		}
	}

	for _, op := range coinBaseCredits {
		opKey := canonicalOutPoint(&op.Hash, op.Index)
		unminedKey := existsRawUnminedInput(ns, opKey)
		if unminedKey != nil {
			unminedVal := existsRawUnmined(ns, unminedKey)
			var unminedRec TxRecord
			copy(unminedRec.Hash[:], unminedKey) // Silly but need an array
			err = readRawTxRecord(&unminedRec.Hash, unminedVal, &unminedRec)
			if err != nil {
				return err
			}

			log.Debugf("Transaction %v spends a removed coinbase "+
				"output -- removing as well", unminedRec.Hash)
			err = s.RemoveUnconfirmed(ns, &unminedRec.MsgTx, &unminedRec.Hash)
			if err != nil {
				return err
			}
		}
	}

	err = putMinedBalance(ns, minedBalance)
	if err != nil {
		return err
	}

	// Mark block hash for height-1 as the new main chain tip.
	_, newTipBlockRecord := existsBlockRecord(ns, height-1)
	newTipHash := extractRawBlockRecordHash(newTipBlockRecord)
	err = ns.Put(rootTipBlock, newTipHash)
	if err != nil {
		return errors.E(errors.IO, err)
	}

	return nil
}

// outputCreditInfo fetches information about a credit from the database,
// fills out a credit struct, and returns it.
func (s *Store) outputCreditInfo(ns walletdb.ReadBucket, op wire.OutPoint, block *Block) (*Credit, error) {
	// It has to exists as a credit or an unmined credit.
	// Look both of these up. If it doesn't, throw an
	// error. Check unmined first, then mined.
	var minedCredV []byte
	unminedCredV := existsRawUnminedCredit(ns,
		canonicalOutPoint(&op.Hash, op.Index), s.chainParams)
	if unminedCredV == nil {
		if block != nil {
			credK := keyCredit(&op.Hash, op.Index, block)
			minedCredV = existsRawCredit(ns, credK)
		}
	}
	if minedCredV == nil && unminedCredV == nil {
		return nil, errors.E(errors.IO, errors.Errorf("missing credit for outpoint %v", &op))
	}

	// Error for DB inconsistency if we find any.
	if minedCredV != nil && unminedCredV != nil {
		return nil, errors.E(errors.IO, errors.Errorf("inconsistency: credit %v is marked mined and unmined", &op))
	}

	var amt dcrutil.Amount
	var skaAmt cointype.SKAAmount
	var opCode uint8
	var isCoinbase bool
	var hasExpiry bool
	var mined bool
	var blockTime time.Time
	var pkScript []byte
	var receiveTime time.Time
	var coinType cointype.CoinType // Dual-coin support: track coin type from TxOut

	if unminedCredV != nil {
		var err error
		amt, err = fetchRawUnminedCreditAmount(unminedCredV)
		if err != nil {
			return nil, err
		}

		opCode = fetchRawUnminedCreditTagOpCode(unminedCredV)
		hasExpiry = fetchRawCreditHasExpiry(unminedCredV, DBVersion)

		v := existsRawUnmined(ns, op.Hash[:])
		received, err := fetchRawUnminedReceiveTime(v)
		if err != nil {
			return nil, err
		}
		receiveTime = time.Unix(received, 0)

		var tx wire.MsgTx
		err = tx.Deserialize(bytes.NewReader(extractRawUnminedTx(v)))
		if err != nil {
			return nil, errors.E(errors.IO, err)
		}
		if op.Index >= uint32(len(tx.TxOut)) {
			return nil, errors.E(errors.IO, errors.Errorf("no output %d for tx %v", op.Index, &op.Hash))
		}
		pkScript = tx.TxOut[op.Index].PkScript
		coinType = tx.TxOut[op.Index].CoinType // Extract coin type from TxOut

		// Fetch SKA big.Int amount for unmined SKA credits
		if coinType.IsSKA() {
			unminedKey := canonicalOutPoint(&op.Hash, op.Index)
			var err error
			skaAmt, err = fetchSKAUnminedCreditAmount(ns, unminedKey)
			if err != nil {
				return nil, err
			}
		}
	} else {
		mined = true

		var err error
		amt, err = fetchRawCreditAmount(minedCredV)
		if err != nil {
			return nil, err
		}

		opCode = fetchRawCreditTagOpCode(minedCredV)
		isCoinbase = fetchRawCreditIsCoinbase(minedCredV)
		hasExpiry = fetchRawCreditHasExpiry(minedCredV, DBVersion)

		scrLoc := fetchRawCreditScriptOffset(minedCredV)
		scrLen := fetchRawCreditScriptLength(minedCredV)
		coinType = fetchRawCreditCoinType(minedCredV) // Read CoinType from database

		recK, recV := existsTxRecord(ns, &op.Hash, block)
		receiveTime = fetchRawTxRecordReceived(recV)
		pkScript, err = fetchRawTxRecordPkScript(recK, recV, op.Index,
			scrLoc, scrLen)
		if err != nil {
			return nil, err
		}

		// Fetch SKA big.Int amount for mined SKA credits
		if coinType.IsSKA() {
			credK := keyCredit(&op.Hash, op.Index, block)
			var err error
			skaAmt, err = fetchSKACreditAmount(ns, credK)
			if err != nil {
				return nil, err
			}
		}
	}

	op.Tree = wire.TxTreeRegular
	if opCode != opNonstake {
		op.Tree = wire.TxTreeStake
	}

	c := &Credit{
		OutPoint: op,
		BlockMeta: BlockMeta{
			Block: Block{Height: -1},
			Time:  blockTime,
		},
		Amount:       amt,
		SKAAmount:    skaAmt,   // SKA big.Int amount for values exceeding int64
		PkScript:     pkScript,
		Received:     receiveTime,
		FromCoinBase: isCoinbase,
		HasExpiry:    hasExpiry,
		CoinType:     coinType, // Include coin type in credit
	}
	if mined {
		c.BlockMeta.Block = *block
	}
	return c, nil
}

// UnspentOutputCount returns the number of mined unspent Credits (including
// those spent by unmined transactions).
// If coinType is nil, returns the count of all unspent outputs across all coin types.
// If coinType is specified, returns only the count for that specific coin type.
func (s *Store) UnspentOutputCount(dbtx walletdb.ReadTx, coinType *cointype.CoinType) int {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)

	if coinType != nil {
		// Count for specific coin type
		bucketName := bucketUnspentForCoinType(*coinType)
		bucket := ns.NestedReadBucket(bucketName)
		if bucket == nil {
			return 0
		}
		return bucket.KeyN()
	}

	// Count for all coin types (VAR + every active SKA bucket).
	totalCount := 0
	for _, ct := range s.getAllActiveCoinTypes() {
		bucketName := bucketUnspentForCoinType(ct)
		bucket := ns.NestedReadBucket(bucketName)
		if bucket != nil {
			totalCount += bucket.KeyN()
		}
	}
	return totalCount
}

// randomUTXOForCoinType returns a random unspent output for a specific coin type.
// The skip function can be used to filter outputs.
func (s *Store) randomUTXOForCoinType(dbtx walletdb.ReadTx, coinType cointype.CoinType,
	skip func(k, v []byte) bool) (k, v []byte) {

	ns := dbtx.ReadBucket(wtxmgrBucketKey)
	bucketName := bucketUnspentForCoinType(coinType)
	bucket := ns.NestedReadBucket(bucketName)

	if bucket == nil {
		return nil, nil // No UTXOs for this coin type
	}

	// Same random selection logic but on coin-type specific bucket
	r := make([]byte, 33)
	rand.Read(r)
	randKey := r[:32]
	prevFirst := r[32]&1 == 1

	c := bucket.ReadCursor()
	defer c.Close()

	// Seek to the random key.  If the random key is before all keys, seek
	// to the first key.  If it is after all keys, seek to the last key.
	// If the seek positions the cursor at the random key, this is extremely
	// unlikely, but invalidate the random key by treating it as if it
	// doesn't exist.
	seekedKey, seekedValue := c.Seek(randKey)
	if seekedKey == nil {
		seekedKey, seekedValue = c.Last()
		if seekedKey == nil {
			return nil, nil
		}
	}
	if bytes.Equal(seekedKey, randKey) {
		seekedKey = nil
	}

	// Iterate through all keys in a random order beginning at the random key.
	// If specified by the prevFirst bool, walk backwards to the beginning
	// first, then forwards from the seeked key to the end.  Otherwise, walk
	// forwards to the end first, then backwards from the seeked key to the
	// beginning.
	//
	// While iterating, randomly skip or add keys until a random output is
	// selected.
	forward := func() (k, v []byte) { return c.Next() }
	backward := func() (k, v []byte) { return c.Prev() }
	var iter func() (k, v []byte)
	if prevFirst {
		iter = backward
	} else {
		iter = forward
	}
	for k, v = seekedKey, seekedValue; k != nil; k, v = iter() {
		if skip(k, v) {
			continue
		}
		if rand.IntN(2) == 0 {
			c.Close()
			return k, v
		}
	}
	if prevFirst {
		iter = forward
		k, v = c.Seek(randKey)
		if bytes.Equal(k, randKey) {
			k, v = iter()
		}
	} else {
		iter = backward
		k, v = c.Seek(randKey)
		if bytes.Equal(k, randKey) {
			k, v = iter()
		}
		k, v = iter()
	}
	var keys [][]byte
	for ; k != nil; k, v = iter() {
		if len(keys) > 0 && !bytes.Equal(keys[0][:32], k[:32]) {
			break
		}
		if skip(k, v) {
			continue
		}
		keys = append(keys, append(make([]byte, 0, 36), k...))
	}
	if len(keys) > 0 {
		k, v = c.Seek(keys[rand.IntN(len(keys))])
		c.Close()
		return k, v
	}

	c.Close()
	return nil, nil
}

// RandomUTXO returns a random unspent Credit, or nil if none matching are
// found.
// The coinType parameter specifies which coin type to select from (VAR=0, SKA=1-255).
//
// As an optimization to avoid reading all unspent outputs, this method is
// limited only to mined outputs, and minConf may not be zero.
func (s *Store) RandomUTXO(dbtx walletdb.ReadTx, minConf, syncHeight int32, coinType cointype.CoinType) (*Credit, error) {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)

	if minConf == 0 {
		return nil, errors.E(errors.Invalid,
			"optimized random utxo selection not possible with minConf=0")
	}

	skip := func(k, v []byte) bool {
		if existsRawUnminedInput(ns, k) != nil {
			// Output is spent by an unmined transaction.
			return true
		}
		var block Block
		err := readUnspentBlock(v, &block)
		if err != nil || !confirmed(minConf, block.Height, syncHeight) {
			return true
		}
		return false
	}
	k, v := s.randomUTXOForCoinType(dbtx, coinType, skip)
	if k == nil {
		return nil, nil
	}
	var op wire.OutPoint
	var block Block
	err := readCanonicalOutPoint(k, &op)
	if err != nil {
		return nil, err
	}
	err = readUnspentBlock(v, &block)
	if err != nil {
		return nil, err
	}
	return s.outputCreditInfo(ns, op, &block)
}

// UnspentOutputs returns all unspent received transaction outputs for the specified coin type.
// The order is undefined.
func (s *Store) UnspentOutputs(dbtx walletdb.ReadTx, coinType cointype.CoinType) ([]*Credit, error) {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)
	var unspent []*Credit

	var op wire.OutPoint
	var block Block

	// Use specific coin type buckets only
	buckets := [][]byte{bucketUnspentForCoinType(coinType)}
	unminedBuckets := [][]byte{bucketUnminedCreditsForCoinType(coinType)}

	// Iterate through mined unspent outputs
	for _, bucketName := range buckets {
		bucket := ns.NestedReadBucket(bucketName)
		if bucket == nil {
			continue
		}

		c := bucket.ReadCursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			err := readCanonicalOutPoint(k, &op)
			if err != nil {
				c.Close()
				return nil, err
			}
			if existsRawUnminedInput(ns, k) != nil {
				// Output is spent by an unmined transaction.
				// Skip this k/v pair.
				continue
			}

			err = readUnspentBlock(v, &block)
			if err != nil {
				c.Close()
				return nil, err
			}

			cred, err := s.outputCreditInfo(ns, op, &block)
			if err != nil {
				c.Close()
				return nil, err
			}

			unspent = append(unspent, cred)
		}
		c.Close()
	}

	// Iterate through unmined credits
	for _, bucketName := range unminedBuckets {
		bucket := ns.NestedReadBucket(bucketName)
		if bucket == nil {
			continue
		}

		c := bucket.ReadCursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if existsRawUnminedInput(ns, k) != nil {
				// Output is spent by an unmined transaction.
				// Skip to next unmined credit.
				continue
			}

			// Skip outputs from unpublished transactions.
			txHash := k[:32]
			if existsUnpublished(ns, txHash) {
				continue
			}

			err := readCanonicalOutPoint(k, &op)
			if err != nil {
				c.Close()
				return nil, err
			}

			cred, err := s.outputCreditInfo(ns, op, nil)
			if err != nil {
				c.Close()
				return nil, err
			}

			unspent = append(unspent, cred)
		}
		c.Close()
	}

	log.Tracef("%v many utxos found in database", len(unspent))

	return unspent, nil
}

// UnspentOutput returns details for an unspent received transaction output.
// Returns error NotExist if the specified outpoint cannot be found or has been
// spent by a mined transaction. Mined transactions that are spent by a mempool
// transaction are not affected by this.
func (s *Store) UnspentOutput(ns walletdb.ReadBucket, op wire.OutPoint, includeMempool bool) (*Credit, error) {
	k := canonicalOutPoint(&op.Hash, op.Index)
	// Check if unspent output is in mempool (if includeMempool == true).
	if includeMempool && existsRawUnminedCredit(ns, k, s.chainParams) != nil {
		return s.outputCreditInfo(ns, op, nil)
	}
	// Check for unspent output in coin-type specific buckets for mined unspents.
	// Use existsRawUnspent which checks all coin-type buckets
	if credKey := existsRawUnspent(ns, k, s.chainParams); credKey != nil {
		// Extract block info from the credit key
		// Credit key format: txhash[32] + blockheight[4] + blockhash[32] + outputindex[4]
		var block Block
		if len(credKey) >= 68 {
			block.Height = int32(byteOrder.Uint32(credKey[32:36]))
			copy(block.Hash[:], credKey[36:68])
		}
		return s.outputCreditInfo(ns, op, &block)
	}
	return nil, errors.E(errors.NotExist, errors.Errorf("no unspent output %v", op))
}

// ForEachUnspentOutpoint calls f on each UTXO outpoint.
// If coinType is nil, iterates through all unspent outputs across all coin types.
// If coinType is specified, iterates only through outputs of that specific coin type.
// The order is undefined.
func (s *Store) ForEachUnspentOutpoint(dbtx walletdb.ReadTx, coinType *cointype.CoinType, f func(*wire.OutPoint) error) error {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)

	// Determine which buckets to iterate based on coinType parameter
	var buckets [][]byte
	if coinType == nil {
		// Iterate only active coin type buckets (VAR + active SKA)
		for _, ct := range s.getAllActiveCoinTypes() {
			bucketName := bucketUnspentForCoinType(ct)
			if ns.NestedReadBucket(bucketName) != nil {
				buckets = append(buckets, bucketName)
			}
		}
	} else {
		// Use specific coin type bucket
		buckets = [][]byte{bucketUnspentForCoinType(*coinType)}
	}

	// Iterate through selected buckets
	for _, bucketName := range buckets {
		bucket := ns.NestedReadBucket(bucketName)
		if bucket == nil {
			continue
		}

		c := bucket.ReadCursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var op wire.OutPoint
			err := readCanonicalOutPoint(k, &op)
			if err != nil {
				c.Close()
				return err
			}
			if existsRawUnminedInput(ns, k) != nil {
				// Output is spent by an unmined transaction.
				// Skip this k/v pair.
				continue
			}

			block := new(Block)
			err = readUnspentBlock(v, block)
			if err != nil {
				c.Close()
				return err
			}

			kC := keyCredit(&op.Hash, op.Index, block)
			vC := existsRawCredit(ns, kC)
			opCode := fetchRawCreditTagOpCode(vC)
			op.Tree = wire.TxTreeRegular
			if opCode != opNonstake {
				op.Tree = wire.TxTreeStake
			}

			if err := f(&op); err != nil {
				c.Close()
				return err
			}
		}
		c.Close()
	}

	// Iterate through unmined credits
	var unminedBuckets [][]byte
	if coinType == nil {
		// Iterate only active coin type unmined buckets (VAR + active SKA)
		for _, ct := range s.getAllActiveCoinTypes() {
			bucketName := bucketUnminedCreditsForCoinType(ct)
			if ns.NestedReadBucket(bucketName) != nil {
				unminedBuckets = append(unminedBuckets, bucketName)
			}
		}
	} else {
		// Use specific coin type unmined bucket
		unminedBuckets = [][]byte{bucketUnminedCreditsForCoinType(*coinType)}
	}

	for _, bucketName := range unminedBuckets {
		bucket := ns.NestedReadBucket(bucketName)
		if bucket == nil {
			continue
		}

		c := bucket.ReadCursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if existsRawUnminedInput(ns, k) != nil {
				// Output is spent by an unmined transaction.
				// Skip to next unmined credit.
				continue
			}

			// Skip outputs from unpublished transactions.
			txHash := k[:32]
			if existsUnpublished(ns, txHash) {
				continue
			}

			var op wire.OutPoint
			err := readCanonicalOutPoint(k, &op)
			if err != nil {
				c.Close()
				return err
			}

			opCode := fetchRawUnminedCreditTagOpCode(v)
			op.Tree = wire.TxTreeRegular
			if opCode != opNonstake {
				op.Tree = wire.TxTreeStake
			}

			if err := f(&op); err != nil {
				c.Close()
				return err
			}
		}
		c.Close()
	}

	return nil
}

// IsUnspentOutpoint returns whether the outpoint is recorded as a wallet UTXO.
func (s *Store) IsUnspentOutpoint(dbtx walletdb.ReadTx, op *wire.OutPoint) bool {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)

	// Outputs from unpublished transactions are not UTXOs yet.
	if existsUnpublished(ns, op.Hash[:]) {
		return false
	}

	k := canonicalOutPoint(&op.Hash, op.Index)
	// Check if exists in any coin-type specific unspent bucket
	if credKey := existsRawUnspent(ns, k, s.chainParams); credKey != nil {
		// Output is mined and not spent by any other mined tx, but may be spent
		// by an unmined transaction.
		return existsRawUnminedInput(ns, k) == nil
	}
	if v := existsRawUnminedCredit(ns, k, s.chainParams); v != nil {
		// Output is in an unmined transaction, but may be spent by another
		// unmined transaction.
		return existsRawUnminedInput(ns, k) == nil
	}
	return false
}

// UnspentTickets returns all unspent tickets that are known for this wallet.
// Tickets that have been spent by an unmined vote that is not a vote on the tip
// block are also considered unspent and are returned.  The order of the hashes
// is undefined.
func (s *Store) UnspentTickets(dbtx walletdb.ReadTx, syncHeight int32, includeImmature bool) ([]chainhash.Hash, error) {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)
	tipBlock, _ := s.MainChainTip(dbtx)
	var tickets []chainhash.Hash
	c := ns.NestedReadBucket(bucketTickets).ReadCursor()
	defer c.Close()
	var hash chainhash.Hash
	for ticketHash, _ := c.First(); ticketHash != nil; ticketHash, _ = c.Next() {
		copy(hash[:], ticketHash)

		// Skip over tickets that are spent by votes or revocations.  As long as
		// the ticket is relevant to the wallet, output zero is recorded as a
		// credit.  Use the credit's spent tracking to determine if the ticket
		// is spent or not.
		opKey := canonicalOutPoint(&hash, 0)
		if existsRawUnspent(ns, opKey, s.chainParams) == nil {
			// No unspent record indicates the output was spent by a mined
			// transaction.
			continue
		}
		if spenderHash := existsRawUnminedInput(ns, opKey); spenderHash != nil {
			// A non-nil record for the outpoint indicates that there exists an
			// unmined transaction that spends the output.  Determine if the
			// spender is a vote, and append the hash if the vote is not for the
			// tip block height.  Otherwise continue to the next ticket.
			serializedSpender := extractRawUnminedTx(existsRawUnmined(ns, spenderHash))
			if serializedSpender == nil {
				continue
			}
			var spender wire.MsgTx
			err := spender.Deserialize(bytes.NewReader(serializedSpender))
			if err != nil {
				return nil, errors.E(errors.IO, err)
			}
			if stake.IsSSGen(&spender) {
				voteBlock, _ := stake.SSGenBlockVotedOn(&spender)
				if voteBlock != tipBlock {
					goto Include
				}
			}

			continue
		}

		// When configured to exclude immature tickets, skip the transaction if
		// is unmined or has not reached ticket maturity yet.
		if !includeImmature {
			txRecKey, _ := latestTxRecord(ns, ticketHash)
			if txRecKey == nil {
				continue
			}
			var height int32
			err := readRawTxRecordBlockHeight(txRecKey, &height)
			if err != nil {
				return nil, err
			}
			if !ticketMatured(s.chainParams, height, syncHeight) {
				continue
			}
		}

	Include:
		tickets = append(tickets, hash)
	}
	return tickets, nil
}

// OwnTicket returns whether ticketHash is the hash of a ticket purchase
// transaction managed by the wallet.
func (s *Store) OwnTicket(dbtx walletdb.ReadTx, ticketHash *chainhash.Hash) bool {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)
	v := existsRawTicketRecord(ns, ticketHash[:])
	return v != nil
}

// Ticket embeds a TxRecord for a ticket purchase transaction, the block it is
// mined in (if any), and the transaction hash of the vote or revocation
// transaction that spends the ticket (if any).
type Ticket struct {
	TxRecord
	Block       Block          // Height -1 if unmined
	SpenderHash chainhash.Hash // Zero value if unspent
}

// TicketIterator is used to iterate over all ticket purchase transactions.
type TicketIterator struct {
	Ticket
	ns     walletdb.ReadBucket
	c      walletdb.ReadCursor
	ck, cv []byte
	err    error
}

// IterateTickets returns an object used to iterate over all ticket purchase
// transactions.
func (s *Store) IterateTickets(dbtx walletdb.ReadTx) *TicketIterator {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)
	c := ns.NestedReadBucket(bucketTickets).ReadCursor()
	ck, cv := c.First()
	return &TicketIterator{ns: ns, c: c, ck: ck, cv: cv}
}

// Next reads the next Ticket from the database, writing it to the iterator's
// embedded Ticket member.  Returns false after all tickets have been iterated
// over or an error occurs.
func (it *TicketIterator) Next() bool {
	if it.err != nil {
		return false
	}

	// Some tickets may be recorded in the tickets bucket but the transaction
	// records for them are missing because they were double spent and removed.
	// Add a label here so that the code below can branch back here to skip to
	// the next ticket.  This could also be implemented using a for loop, but at
	// the loss of an indent.
CheckNext:

	// The cursor value will be nil when all items in the bucket have been
	// iterated over.
	if it.cv == nil {
		return false
	}

	// Determine whether there is a mined transaction record for the ticket
	// purchase, an unmined transaction record, or no recorded transaction at
	// all.
	var ticketHash chainhash.Hash
	copy(ticketHash[:], it.ck)
	if k, v := latestTxRecord(it.ns, it.ck); v != nil {
		// Ticket is recorded mined
		err := readRawTxRecordBlock(k, &it.Block)
		if err != nil {
			it.err = err
			return false
		}
		err = readRawTxRecord(&ticketHash, v, &it.TxRecord)
		if err != nil {
			it.err = err
			return false
		}

		// Check if the ticket is spent or not.  Look up the credit for output 0
		// and check if either a debit is recorded or the output is spent by an
		// unmined transaction.
		_, credVal := existsCredit(it.ns, &ticketHash, 0, &it.Block)
		if credVal != nil {
			if extractRawCreditIsSpent(credVal) {
				debKey := extractRawCreditSpenderDebitKey(credVal)
				debHash := extractRawDebitHash(debKey)
				copy(it.SpenderHash[:], debHash)
			} else {
				it.SpenderHash = chainhash.Hash{}
			}
		} else {
			opKey := canonicalOutPoint(&ticketHash, 0)
			spenderVal := existsRawUnminedInput(it.ns, opKey)
			if spenderVal != nil {
				copy(it.SpenderHash[:], spenderVal)
			} else {
				it.SpenderHash = chainhash.Hash{}
			}
		}
	} else if v := existsRawUnmined(it.ns, ticketHash[:]); v != nil {
		// Ticket is recorded unmined
		it.Block = Block{Height: -1}
		// Unmined tickets cannot be spent
		it.SpenderHash = chainhash.Hash{}
		err := readRawTxRecord(&ticketHash, v, &it.TxRecord)
		if err != nil {
			it.err = err
			return false
		}
	} else {
		// Transaction was removed, skip to next
		it.ck, it.cv = it.c.Next()
		goto CheckNext
	}

	// Advance the cursor to the next item before returning.  Next expects the
	// cursor key and value to be set to the next item to read.
	it.ck, it.cv = it.c.Next()

	return true
}

// Err returns the final error state of the iterator.  It should be checked
// after iteration completes when Next returns false.
func (it *TicketIterator) Err() error { return it.err }

func (it *TicketIterator) Close() {
	if it.c != nil {
		it.c.Close()
	}
}

// MultisigCredit is a redeemable P2SH multisignature credit.
//
// CoinType identifies whether the credit is VAR or a specific SKA coin.
// Per-credit coin type is required because a single fromscraddress
// (P2SH script hash) may legitimately accumulate credits of mixed coin
// types — the redemption path must route each credit through the
// VAR-int64 or SKA-bigint code path according to its own type, not
// the caller's outer hint.
type MultisigCredit struct {
	OutPoint   *wire.OutPoint
	ScriptHash [ripemd160.Size]byte
	MSScript   []byte
	M          uint8
	N          uint8
	Amount     dcrutil.Amount
	CoinType   cointype.CoinType
}

// GetMultisigOutput takes an outpoint and returns multisignature
// credit data stored about it.
func (s *Store) GetMultisigOutput(ns walletdb.ReadBucket, op *wire.OutPoint) (*MultisigOut, error) {
	key := canonicalOutPoint(&op.Hash, op.Index)
	val := existsMultisigOutCopy(ns, key)
	if val == nil {
		return nil, errors.E(errors.NotExist, errors.Errorf("no multisig output for outpoint %v", op))
	}

	return fetchMultisigOut(key, val)
}

// UnspentMultisigCreditsForAddress returns all unspent multisignature P2SH
// credits in the wallet for some specified address.
func (s *Store) UnspentMultisigCreditsForAddress(dbtx walletdb.ReadTx, addr stdaddr.Address) ([]*MultisigCredit, error) {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)
	addrmgrNs := dbtx.ReadBucket(waddrmgrBucketKey)

	p2shAddr, ok := addr.(*stdaddr.AddressScriptHashV0)
	if !ok {
		return nil, errors.E(errors.Invalid, "address must be P2SH")
	}
	addrScrHash := p2shAddr.Hash160()

	var mscs []*MultisigCredit
	c := ns.NestedReadBucket(bucketMultisigUsp).ReadCursor()
	defer c.Close()
	for k, _ := c.First(); k != nil; k, _ = c.Next() {
		val := existsMultisigOutCopy(ns, k)
		if val == nil {
			return nil, errors.E(errors.IO, "missing multisig credit")
		}

		// Skip everything that's unrelated to the address
		// we're concerned about.
		scriptHash := fetchMultisigOutScrHash(val)
		if scriptHash != *addrScrHash {
			continue
		}

		var op wire.OutPoint
		err := readCanonicalOutPoint(k, &op)
		if err != nil {
			return nil, err
		}

		multisigScript, err := s.manager.redeemScriptForHash160(addrmgrNs, scriptHash[:])
		if err != nil {
			return nil, err
		}
		m, n := fetchMultisigOutMN(val)
		amount := fetchMultisigOutAmount(val)
		ct := fetchMultisigOutCoinType(val)
		op.Tree = fetchMultisigOutTree(val)

		// Use named-field literal so future field additions don't silently
		// rotate positional fields.
		msc := &MultisigCredit{
			OutPoint:   &op,
			ScriptHash: scriptHash,
			MSScript:   multisigScript,
			M:          m,
			N:          n,
			Amount:     amount,
			CoinType:   ct,
		}
		mscs = append(mscs, msc)
	}

	return mscs, nil
}

// confirmed checks whether a transaction at height txHeight has met minConf
// confirmations for a blockchain at height curHeight.
func confirmed(minConf, txHeight, curHeight int32) bool {
	return confirms(txHeight, curHeight) >= minConf
}

// confirms returns the number of confirmations for a transaction in a block at
// height txHeight (or -1 for an unconfirmed tx) given the chain height
// curHeight.
func confirms(txHeight, curHeight int32) int32 {
	switch {
	case txHeight == -1, txHeight > curHeight:
		return 0
	default:
		return curHeight - txHeight + 1
	}
}

// coinbaseMatured returns whether a transaction mined at txHeight has
// reached coinbase maturity in a chain with tip height curHeight.
func coinbaseMatured(params *chaincfg.Params, txHeight, curHeight int32) bool {
	return txHeight >= 0 && curHeight-txHeight+1 > int32(params.CoinbaseMaturity)
}

// ticketChangeMatured returns whether a ticket change mined at
// txHeight has reached ticket maturity in a chain with a tip height
// curHeight.
func ticketChangeMatured(params *chaincfg.Params, txHeight, curHeight int32) bool {
	return txHeight >= 0 && curHeight-txHeight+1 > int32(params.SStxChangeMaturity)
}

// SSFeeMatured returns whether an output of an SSFee transaction mined at
// txHeight has reached maturity in a chain with tip height curHeight.
//
// mond requires coinbase maturity for an output of a transaction with an
// expiry, and for an OP_SSGEN output while the treasury agenda (DCP0006) is
// active; otherwise it requires ticket change maturity.  The agenda expired in
// 2021, before mainnet and testnet began, so it can never activate on them.
//
// shortcut: simnet and regnet can vote the agenda in, so they keep coinbase
// maturity (late, never early); query the agenda state if that matters there.
func SSFeeMatured(params *chaincfg.Params, hasExpiry bool, txHeight, curHeight int32) bool {
	if !hasExpiry && (params.Net == wire.MainNet || params.Net == wire.TestNet3) {
		return ticketChangeMatured(params, txHeight, curHeight)
	}
	return coinbaseMatured(params, txHeight, curHeight)
}

// stakeGenMatured returns whether an OP_SSGEN or OP_SSRTX credit has reached
// maturity in a chain with tip height curHeight.  Votes and revocations need
// coinbase maturity; SSFee outputs may mature earlier (see SSFeeMatured).
func (s *Store) stakeGenMatured(ns walletdb.ReadBucket, cKey []byte, hasExpiry bool, curHeight int32) bool {
	txHeight := extractRawCreditHeight(cKey)
	if coinbaseMatured(s.chainParams, txHeight, curHeight) {
		return true
	}
	// Only SSFee markers are cached, so a vote's lookup reads its tx record:
	// keep it to credits that are not yet coinbase mature.
	return getSSFeeMarkerType(ns, cKey) != stake.SSFeeMarkerNone &&
		SSFeeMatured(s.chainParams, hasExpiry, txHeight, curHeight)
}

// StakeGenMatured returns whether an OP_SSGEN or OP_SSRTX credit returned by
// UnspentOutputs has reached maturity in a chain with tip height curHeight.
func (s *Store) StakeGenMatured(dbtx walletdb.ReadTx, c *Credit, curHeight int32) bool {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)
	return s.stakeGenMatured(ns, keyCredit(&c.Hash, c.Index, &c.Block), c.HasExpiry, curHeight)
}

// ticketMatured returns whether a ticket mined at txHeight has
// reached ticket maturity in a chain with a tip height curHeight.
func ticketMatured(params *chaincfg.Params, txHeight, curHeight int32) bool {
	// mond has an off-by-one in the calculation of the ticket
	// maturity, which results in maturity being one block higher
	// than the params would indicate.
	return txHeight >= 0 && curHeight-txHeight > int32(params.TicketMaturity)
}

func (s *Store) fastCreditPkScriptLookup(ns walletdb.ReadBucket, credKey []byte, unminedCredKey []byte) ([]byte, error) {
	// It has to exists as a credit or an unmined credit.
	// Look both of these up. If it doesn't, throw an
	// error. Check unmined first, then mined.
	var minedCredV []byte
	unminedCredV := existsRawUnminedCredit(ns, unminedCredKey, s.chainParams)
	if unminedCredV == nil {
		minedCredV = existsRawCredit(ns, credKey)
	}
	if minedCredV == nil && unminedCredV == nil {
		return nil, errors.E(errors.IO, "missing mined and unmined credit")
	}

	if unminedCredV != nil { // unmined
		var op wire.OutPoint
		err := readCanonicalOutPoint(unminedCredKey, &op)
		if err != nil {
			return nil, err
		}
		k := op.Hash[:]
		v := existsRawUnmined(ns, k)
		var tx wire.MsgTx
		err = tx.Deserialize(bytes.NewReader(extractRawUnminedTx(v)))
		if err != nil {
			return nil, errors.E(errors.IO, err)
		}
		if op.Index >= uint32(len(tx.TxOut)) {
			return nil, errors.E(errors.IO, errors.Errorf("no output %d for tx %v", op.Index, &op.Hash))
		}
		return tx.TxOut[op.Index].PkScript, nil
	}

	scrLoc := fetchRawCreditScriptOffset(minedCredV)
	scrLen := fetchRawCreditScriptLength(minedCredV)

	k := extractRawCreditTxRecordKey(credKey)
	v := existsRawTxRecord(ns, k)
	idx := extractRawCreditIndex(credKey)
	return fetchRawTxRecordPkScript(k, v, idx, scrLoc, scrLen)
}

// InputSource provides a method (SelectInputs) to incrementally select unspent
// outputs to use as transaction inputs.
type InputSource struct {
	source func(dcrutil.Amount, cointype.SKAAmount) (*txauthor.InputDetail, error)
}

// SelectInputs selects transaction inputs to redeem unspent outputs stored in
// the database.  It may be called multiple times with increasing target amounts
// to return additional inputs for a higher target amount.  It returns the total
// input amount referenced by the previous transaction outputs, a slice of
// transaction inputs referencing these outputs, and a slice of previous output
// scripts from each previous output referenced by the corresponding input.
//
// The two target arguments are coin-type-specific and mutually exclusive: pass
// `target` for VAR with `targetSKA` as cointype.Zero(); pass `targetSKA` for
// SKA with `target` as 0. See txauthor.InputSource for rationale.
func (s *InputSource) SelectInputs(target dcrutil.Amount, targetSKA cointype.SKAAmount) (*txauthor.InputDetail, error) {
	return s.source(target, targetSKA)
}

// MakeInputSourceWithCoinType creates an InputSource that filters UTXOs by coin type.
// This is essential for dual-coin transactions to ensure SKA transactions use SKA UTXOs
// and VAR transactions use VAR UTXOs.
//
// The coinType parameter must be in the range 0-255 where:
//   - 0 = VAR (Varta) coins - the mined network currency
//   - 1-255 = SKA (Skarb) coin types - asset-backed pre-emitted coins
//
// The returned InputSource will only select UTXOs matching the specified coin type.
// If no matching UTXOs exist, the InputSource will return an empty result.
// Invalid coin types (>255) will cause the InputSource to return an error.
//
// "No-target" sentinel: invoking the returned InputSource with `target == 0`
// (VAR) or `targetSKA.IsZero()` (SKA) signals "drain every eligible UTXO up
// to maxInputsPerTx" — the inherited wallet idiom used by sweep and
// consolidation flows. There is no supported way to request a real
// zero-atom target through this InputSource; callers that need to author a
// transaction with exactly zero atoms of the active coin type must build
// it manually.
func (s *Store) MakeInputSourceWithCoinType(dbtx walletdb.ReadTx, account uint32, minConf,
	syncHeight int32, ignore func(*wire.OutPoint) bool, coinType cointype.CoinType) InputSource {

	// Validate coin type parameter (0 = VAR, 1-255 = SKA types)
	if coinType > cointype.CoinTypeMax {
		return InputSource{source: func(target dcrutil.Amount, targetSKA cointype.SKAAmount) (*txauthor.InputDetail, error) {
			return nil, errors.E(errors.Invalid, errors.Errorf("invalid coin type: %d", coinType))
		}}
	}

	ns := dbtx.ReadBucket(wtxmgrBucketKey)
	addrmgrNs := dbtx.ReadBucket(waddrmgrBucketKey)

	type remainingKey struct {
		k       []byte
		unmined bool
	}

	// Current inputs and their total value.  These are closed over by the
	// returned input source and reused across multiple calls.
	var (
		currentTotal      dcrutil.Amount
		currentSKATotal   cointype.SKAAmount // For SKA coins that exceed int64
		currentInputs     []*wire.TxIn
		currentScripts    [][]byte
		redeemScriptSizes []int
		seen              = make(map[string]struct{}) // random unspent bucket keys
		numUnspent        = 0
		randTries         int
		remainingKeys     []remainingKey
	)

	// Get number of unspent outputs for this specific coin type
	unspentBucket := ns.NestedReadBucket(bucketUnspentForCoinType(coinType))
	if unspentBucket != nil {
		numUnspent = unspentBucket.KeyN()
	}

	if minConf != 0 {
		log.Debugf("Unspent bucket k/v count for coin type %d: %v", coinType, numUnspent)
	}

	skip := func(k, v []byte) bool {
		if existsRawUnminedInput(ns, k) != nil {
			// Output is spent by an unmined transaction.
			// Skip to next unmined credit.
			return true
		}
		var block Block
		err := readUnspentBlock(v, &block)
		if err != nil || !confirmed(minConf, block.Height, syncHeight) {
			return true
		}
		if _, ok := seen[string(k)]; ok {
			// already found by the random search
			return true
		}
		return false
	}

	isSKA := coinType.IsSKA()
	f := func(target dcrutil.Amount, targetSKA cointype.SKAAmount) (*txauthor.InputDetail, error) {
		// Defensive: reject negative targets up front. The
		// "consume everything" sentinel is target == 0 (or targetSKA.IsZero());
		// any negative value indicates a caller programming error.
		if !isSKA && target < 0 {
			return nil, errors.E(errors.Invalid,
				errors.Errorf("negative VAR target: %d", target))
		}
		if isSKA && targetSKA.IsNegative() {
			return nil, errors.E(errors.Invalid,
				errors.Errorf("negative SKA target"))
		}
		// Determine whether we've met the caller's target.
		// For VAR: currentTotal >= target (and target != 0).
		// For SKA: currentSKATotal >= targetSKA (and targetSKA != 0).
		// target/targetSKA == 0 means "no target — exhaust the UTXO set".
		targetMet := func() bool {
			if isSKA {
				if targetSKA.IsZero() {
					return false
				}
				return currentSKATotal.Cmp(targetSKA) >= 0
			}
			if target == 0 {
				return false
			}
			return currentTotal >= target
		}
		hasTarget := (!isSKA && target != 0) || (isSKA && !targetSKA.IsZero())
		for !targetMet() {
			var k, v []byte
			var err error
			if minConf != 0 && hasTarget && randTries < numUnspent/2 {
				randTries++
				k, v = s.randomUTXOForCoinType(dbtx, coinType, skip)
				if k != nil {
					seen[string(k)] = struct{}{}
				}
			} else if remainingKeys == nil {
				if randTries > 0 {
					log.Debugf("Abandoned random UTXO selection "+
						"attempts after %v tries", randTries)
				}
				// All remaining keys not discovered by the
				// random search (if any was performed) are read
				// into memory and shuffled, and then iterated
				// over.
				remainingKeys = make([]remainingKey, 0)
				b := ns.NestedReadBucket(bucketUnspentForCoinType(coinType))
				if b != nil {
					err = b.ForEach(func(k, v []byte) error {
						if skip(k, v) {
							return nil
						}
						kcopy := make([]byte, len(k))
						copy(kcopy, k)
						remainingKeys = append(remainingKeys, remainingKey{
							k: kcopy,
						})
						return nil
					})
					if err != nil {
						return nil, err
					}
				}
				if minConf == 0 {
					b = ns.NestedReadBucket(bucketUnminedCreditsForCoinType(coinType))
					if b != nil {
						err = b.ForEach(func(k, v []byte) error {
							if _, ok := seen[string(k)]; ok {
								return nil
							}
							if existsRawUnminedInput(ns, k) != nil {
								// Output is spent by an unmined transaction.
								return nil
							}
							// Skip unmined outputs from unpublished transactions.
							if txHash := k[:32]; existsUnpublished(ns, txHash) {
								return nil
							}
							// Skip ticket outputs, as only SSGen can spend these.
							opcode := fetchRawUnminedCreditTagOpCode(v)
							if opcode == txscript.OP_SSTX {
								return nil
							}
							// Skip outputs that are not mature.
							switch opcode {
							case txscript.OP_SSGEN, txscript.OP_SSTXCHANGE, txscript.OP_SSRTX,
								txscript.OP_TADD, txscript.OP_TGEN:
								return nil
							}

							kcopy := make([]byte, len(k))
							copy(kcopy, k)
							remainingKeys = append(remainingKeys, remainingKey{
								k:       kcopy,
								unmined: true,
							})
							return nil
						})
						if err != nil {
							return nil, err
						}
					}
				}
				rand.ShuffleSlice(remainingKeys)
			}

			var unmined bool
			if k == nil {
				if len(remainingKeys) == 0 {
					// No more UTXOs available.
					break
				}
				next := remainingKeys[0]
				remainingKeys = remainingKeys[1:]
				k, unmined = next.k, next.unmined
			}
			// Use coin-type specific buckets
			if !unmined {
				unspentBucket := ns.NestedReadBucket(bucketUnspentForCoinType(coinType))
				if unspentBucket != nil {
					v = unspentBucket.Get(k)
				}
			} else {
				unminedBucket := ns.NestedReadBucket(bucketUnminedCreditsForCoinType(coinType))
				if unminedBucket != nil {
					v = unminedBucket.Get(k)
				}
			}

			tree := wire.TxTreeRegular
			var op wire.OutPoint
			var amt dcrutil.Amount
			var skaAmt cointype.SKAAmount // For SKA coins that exceed int64
			var pkScript []byte

			if !unmined {
				cKey := make([]byte, 72)
				copy(cKey[0:32], k[0:32])   // Tx hash
				copy(cKey[32:36], v[0:4])   // Block height
				copy(cKey[36:68], v[4:36])  // Block hash
				copy(cKey[68:72], k[32:36]) // Output index

				cVal := existsRawCredit(ns, cKey)

				// No need to filter by coin type - already reading from coin-type specific bucket

				// Check the account first.
				pkScript, err = s.fastCreditPkScriptLookup(ns, cKey, nil)
				if err != nil {
					return nil, err
				}
				thisAcct, err := s.fetchAccountForPkScript(addrmgrNs, cVal, nil, pkScript)
				if err != nil {
					return nil, err
				}
				if account != thisAcct {
					continue
				}

				var spent bool
				amt, spent, err = fetchRawCreditAmountSpent(cVal)
				if err != nil {
					return nil, err
				}

				// For SKA, fetch the big.Int amount from SKA bucket
				if coinType.IsSKA() {
					skaAmt, err = fetchSKACreditAmount(ns, cKey)
					if err != nil {
						return nil, err
					}
				}

				// This should never happen since this is already in bucket
				// unspent, but let's be careful anyway.
				if spent {
					continue
				}

				// Skip zero value outputs.
				// For SKA, check the big.Int amount
				if coinType.IsSKA() {
					if skaAmt.IsZero() {
						continue
					}
				} else if amt == 0 {
					continue
				}

				// Skip ticket outputs, as only SSGen can spend these.
				opcode := fetchRawCreditTagOpCode(cVal)
				if opcode == txscript.OP_SSTX {
					continue
				}

				// Only include this output if it meets the required number of
				// confirmations.  Coinbase transactions must have reached
				// maturity before their outputs may be spent.
				txHeight := extractRawCreditHeight(cKey)
				if !confirmed(minConf, txHeight, syncHeight) {
					continue
				}

				// Skip outputs that are not mature.
				if opcode == opNonstake && fetchRawCreditIsCoinbase(cVal) {
					if !coinbaseMatured(s.chainParams, txHeight, syncHeight) {
						continue
					}
				}
				switch opcode {
				case txscript.OP_SSGEN, txscript.OP_SSRTX:
					hasExpiry := fetchRawCreditHasExpiry(cVal, DBVersion)
					if !s.stakeGenMatured(ns, cKey, hasExpiry, syncHeight) {
						continue
					}
				case txscript.OP_TADD, txscript.OP_TGEN:
					if !coinbaseMatured(s.chainParams, txHeight, syncHeight) {
						continue
					}
				}
				if opcode == txscript.OP_SSTXCHANGE {
					if !ticketChangeMatured(s.chainParams, txHeight, syncHeight) {
						continue
					}
				}

				// Determine the txtree for the outpoint by whether or not it's
				// using stake tagged outputs.
				if opcode != opNonstake {
					tree = wire.TxTreeStake
				}

				err = readCanonicalOutPoint(k, &op)
				if err != nil {
					return nil, err
				}
				op.Tree = tree

			} else {
				// No need to filter by coin type - already reading from coin-type specific bucket

				// Check the account first.
				pkScript, err = s.fastCreditPkScriptLookup(ns, nil, k)
				if err != nil {
					return nil, err
				}
				thisAcct, err := s.fetchAccountForPkScript(addrmgrNs, nil, v, pkScript)
				if err != nil {
					return nil, err
				}
				if account != thisAcct {
					continue
				}

				amt, err = fetchRawUnminedCreditAmount(v)
				if err != nil {
					return nil, err
				}

				// For SKA, fetch the big.Int amount from unmined SKA bucket
				if coinType.IsSKA() {
					skaAmt, err = fetchSKAUnminedCreditAmount(ns, k)
					if err != nil {
						return nil, err
					}
					// Skip zero value SKA outputs
					if skaAmt.IsZero() {
						continue
					}
				}

				// Determine the txtree for the outpoint by whether or not it's
				// using stake tagged outputs.
				tree = wire.TxTreeRegular
				opcode := fetchRawUnminedCreditTagOpCode(v)
				if opcode != opNonstake {
					tree = wire.TxTreeStake
				}

				err = readCanonicalOutPoint(k, &op)
				if err != nil {
					return nil, err
				}
				op.Tree = tree
			}

			if ignore != nil && ignore(&op) {
				continue
			}

			// For SKA, set ValueIn to 0 (actual value is in big.Int)
			// For VAR, use the int64 amount
			var valueIn int64
			if coinType.IsSKA() {
				valueIn = 0 // SKA uses big.Int, ValueIn is placeholder
			} else {
				valueIn = int64(amt)
			}
			input := wire.NewTxIn(&op, valueIn, nil)

			// Set SKAValueIn for SKA inputs (needed for V13 wire format).
			// Defense in depth: SKAAmount.BigInt() already returns a fresh
			// *big.Int per its current contract, so this copy is redundant
			// today. Kept so the wire TxIn stays safe if BigInt()'s contract
			// is ever weakened to alias the inner pointer. Matches the
			// convention at createtx.go:894, multisig.go:120,
			// methods.go:5286, methods.go:7888.
			if coinType.IsSKA() {
				input.SKAValueIn = new(big.Int).Set(skaAmt.BigInt())
			}

			// Unspent credits are currently expected to be either P2PKH or
			// P2PK, P2PKH/P2SH nested in a revocation/stakechange/vote output.
			// Ignore stake P2SH since it can pay to any script, which the
			// wallet may not recognize.
			var scriptSize int
			scriptClass := stdscript.DetermineScriptType(scriptVersionAssumed, pkScript)
			scriptSubClass, _ := txrules.StakeSubScriptType(scriptClass)
			switch scriptSubClass {
			case stdscript.STPubKeyHashEcdsaSecp256k1:
				scriptSize = txsizes.RedeemP2PKHSigScriptSize
			case stdscript.STPubKeyEcdsaSecp256k1:
				scriptSize = txsizes.RedeemP2PKSigScriptSize
			case stdscript.STScriptHash:
				scriptSize = txsizes.RedeemP2SHSigScriptSize
			default:
				continue
			}

			// Accumulate totals based on coin type
			if coinType.IsSKA() {
				currentSKATotal = currentSKATotal.Add(skaAmt)
			} else {
				currentTotal += amt
			}
			currentInputs = append(currentInputs, input)
			currentScripts = append(currentScripts, pkScript)
			redeemScriptSizes = append(redeemScriptSizes, scriptSize)
		}

		inputDetail := &txauthor.InputDetail{
			Amount:            currentTotal,
			SKAAmount:         currentSKATotal,
			Inputs:            currentInputs,
			Scripts:           currentScripts,
			RedeemScriptSizes: redeemScriptSizes,
		}

		return inputDetail, nil
	}

	return InputSource{source: f}
}

// balanceFullScan does a fullscan of the UTXO set to get the current balance.
// It is less efficient than the other balance functions, but works fine for
// accounts.
func (s *Store) balanceFullScan(dbtx walletdb.ReadTx, minConf int32, syncHeight int32) (map[uint32]*Balances, error) {
	ns := dbtx.ReadBucket(wtxmgrBucketKey)
	addrmgrNs := dbtx.ReadBucket(waddrmgrBucketKey)

	accountBalances := make(map[uint32]*Balances)

	// First, check coin-type-specific bucket for VAR (most common)
	varBucket := ns.NestedReadBucket(bucketUnspentForCoinType(cointype.CoinTypeVAR))
	if varBucket != nil {
		c := varBucket.ReadCursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if existsRawUnminedInput(ns, k) != nil {
				// Output is spent by an unmined transaction.
				// Skip to next unmined credit.
				continue
			}

			cKey := make([]byte, 72)
			copy(cKey[0:32], k[0:32])   // Tx hash
			copy(cKey[32:36], v[0:4])   // Block height
			copy(cKey[36:68], v[4:36])  // Block hash
			copy(cKey[68:72], k[32:36]) // Output index

			cVal := existsRawCredit(ns, cKey)
			if cVal == nil {
				c.Close()
				return nil, errors.E(errors.IO, "missing credit for unspent output")
			}

			// Check the account first.
			pkScript, err := s.fastCreditPkScriptLookup(ns, cKey, nil)
			if err != nil {
				c.Close()
				return nil, err
			}
			thisAcct, err := s.fetchAccountForPkScript(addrmgrNs, cVal, nil, pkScript)
			if err != nil {
				c.Close()
				return nil, err
			}

			utxoAmt, err := fetchRawCreditAmount(cVal)
			if err != nil {
				c.Close()
				return nil, err
			}

			height := extractRawCreditHeight(cKey)
			opcode := fetchRawCreditTagOpCode(cVal)
			coinType := fetchRawCreditCoinType(cVal)

			ab, ok := accountBalances[thisAcct]
			if !ok {
				ab = &Balances{
					Account:          thisAcct,
					CoinTypeBalances: make(map[cointype.CoinType]CoinBalance),
				}
				accountBalances[thisAcct] = ab
			}

			// Ensure coin type balance entry exists
			if _, exists := ab.CoinTypeBalances[coinType]; !exists {
				ab.CoinTypeBalances[coinType] = CoinBalance{
					CoinType: coinType,
				}
			}

			// Get current coin type balance for modification
			coinBalance := ab.CoinTypeBalances[coinType]

			switch opcode {
			case txscript.OP_TGEN:
				// Or add another type of balance?
				fallthrough
			case opNonstake:
				isConfirmed := confirmed(minConf, height, syncHeight)
				creditFromCoinbase := fetchRawCreditIsCoinbase(cVal)
				creditHasExpiry := fetchRawCreditHasExpiry(cVal, DBVersion)

				// Outputs with expiry require maturity like coinbase.
				// mond enforces CoinbaseMaturity for any output with expiry set.
				requiresMaturity := creditFromCoinbase || creditHasExpiry
				matureOutput := (requiresMaturity &&
					coinbaseMatured(s.chainParams, height, syncHeight))

				if (isConfirmed && !requiresMaturity) || matureOutput {
					// Update per-coin balance
					coinBalance.Spendable += utxoAmt
					// Update legacy VAR balance for backward compatibility
					if coinType == cointype.CoinTypeVAR {
						ab.Spendable += utxoAmt
					}
				} else if requiresMaturity && !matureOutput {
					// Update per-coin balance
					coinBalance.ImmatureCoinbaseRewards += utxoAmt
					// Update legacy VAR balance for backward compatibility
					if coinType == cointype.CoinTypeVAR {
						ab.ImmatureCoinbaseRewards += utxoAmt
					}
				}

				// Update per-coin total
				coinBalance.Total += utxoAmt
				// Update legacy VAR total for backward compatibility
				if coinType == cointype.CoinTypeVAR {
					ab.Total += utxoAmt
				}
			case txscript.OP_SSTX:
				// Update per-coin balance
				coinBalance.VotingAuthority += utxoAmt
				coinBalance.Total += utxoAmt
				// Update legacy VAR balance for backward compatibility
				if coinType == cointype.CoinTypeVAR {
					ab.VotingAuthority += utxoAmt
					ab.Total += utxoAmt
				}
			case txscript.OP_SSGEN:
				fallthrough
			case txscript.OP_SSRTX:
				if s.stakeGenMatured(ns, cKey, fetchRawCreditHasExpiry(cVal, DBVersion), syncHeight) {
					// Update per-coin balance
					coinBalance.Spendable += utxoAmt
					// Update legacy VAR balance for backward compatibility
					if coinType == cointype.CoinTypeVAR {
						ab.Spendable += utxoAmt
					}
				} else {
					// Update per-coin balance
					coinBalance.ImmatureStakeGeneration += utxoAmt
					// Update legacy VAR balance for backward compatibility
					if coinType == cointype.CoinTypeVAR {
						ab.ImmatureStakeGeneration += utxoAmt
					}
				}

				// Update per-coin total
				coinBalance.Total += utxoAmt
				// Update legacy VAR total for backward compatibility
				if coinType == cointype.CoinTypeVAR {
					ab.Total += utxoAmt
				}
			case txscript.OP_SSTXCHANGE:
				if ticketChangeMatured(s.chainParams, height, syncHeight) {
					// Update per-coin balance
					coinBalance.Spendable += utxoAmt
					// Update legacy VAR balance for backward compatibility
					if coinType == cointype.CoinTypeVAR {
						ab.Spendable += utxoAmt
					}
				}

				// Update per-coin total
				coinBalance.Total += utxoAmt
				// Update legacy VAR total for backward compatibility
				if coinType == cointype.CoinTypeVAR {
					ab.Total += utxoAmt
				}
			default:
				log.Warnf("Unhandled opcode: %v", opcode)
			}

			// Store updated coin balance back to map
			ab.CoinTypeBalances[coinType] = coinBalance
		}

		c.Close()
	}

	// Process confirmed credits for active SKA coin types
	for _, skaCoinType := range s.getActiveSKACoinTypes() {
		skaBucket := ns.NestedReadBucket(bucketUnspentForCoinType(skaCoinType))
		if skaBucket == nil {
			continue
		}
		c := skaBucket.ReadCursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if existsRawUnminedInput(ns, k) != nil {
				// Output is spent by an unmined transaction.
				// Skip to next unmined credit.
				continue
			}

			cKey := make([]byte, 72)
			copy(cKey[0:32], k[0:32])   // Tx hash
			copy(cKey[32:36], v[0:4])   // Block height
			copy(cKey[36:68], v[4:36])  // Block hash
			copy(cKey[68:72], k[32:36]) // Output index

			cVal := existsRawCredit(ns, cKey)
			if cVal == nil {
				c.Close()
				return nil, errors.E(errors.IO, "missing credit for unspent output")
			}

			// Check the account first.
			pkScript, err := s.fastCreditPkScriptLookup(ns, cKey, nil)
			if err != nil {
				c.Close()
				return nil, err
			}
			thisAcct, err := s.fetchAccountForPkScript(addrmgrNs, cVal, nil, pkScript)
			if err != nil {
				c.Close()
				return nil, err
			}

			// SKA branch: utxoAmt is intentionally zero. The int64 view of
			// fetchRawCreditAmount(cVal) for an SKA credit either truncates
			// (above int64 max) or duplicates the same atom count carried
			// by SKASpendable in big.Int form, so leaving the int64
			// CoinBalance fields at zero is the only correct contract for
			// SKA accounts. See the CoinBalance doc comment.
			utxoAmt := dcrutil.Amount(0)

			height := extractRawCreditHeight(cKey)
			opcode := fetchRawCreditTagOpCode(cVal)
			coinType := fetchRawCreditCoinType(cVal)

			ab, ok := accountBalances[thisAcct]
			if !ok {
				ab = &Balances{
					Account:          thisAcct,
					CoinTypeBalances: make(map[cointype.CoinType]CoinBalance),
				}
				accountBalances[thisAcct] = ab
			}

			// Ensure coin type balance entry exists with initialized SKA fields
			if _, exists := ab.CoinTypeBalances[coinType]; !exists {
				ab.CoinTypeBalances[coinType] = CoinBalance{
					CoinType:                   coinType,
					SKAImmatureCoinbaseRewards: cointype.Zero(),
					SKAImmatureStakeGeneration: cointype.Zero(),
					SKASpendable:               cointype.Zero(),
					SKATotal:                   cointype.Zero(),
					SKAUnconfirmed:             cointype.Zero(),
				}
			}

			// Get current coin type balance for modification
			coinBalance := ab.CoinTypeBalances[coinType]

			// For SKA, fetch big.Int amount from SKA amount bucket
			skaAmt, err := fetchSKACreditAmount(ns, cKey)
			if err != nil {
				return nil, err
			}

			switch opcode {
			case opNonstake:
				// SKA transactions: emission, transfers, and SSFee MF (miner fee)
				isConfirmed := confirmed(minConf, height, syncHeight)
				creditFromCoinbase := fetchRawCreditIsCoinbase(cVal)
				creditHasExpiry := fetchRawCreditHasExpiry(cVal, DBVersion)

				// Outputs with expiry (like SKA emissions) require maturity like coinbase.
				// mond enforces CoinbaseMaturity for any output with expiry set.
				requiresMaturity := creditFromCoinbase || creditHasExpiry
				matureOutput := (requiresMaturity &&
					coinbaseMatured(s.chainParams, height, syncHeight))

				if (isConfirmed && !requiresMaturity) || matureOutput {
					coinBalance.Spendable += utxoAmt
					coinBalance.SKASpendable = coinBalance.SKASpendable.Add(skaAmt)
				} else if requiresMaturity && !matureOutput {
					coinBalance.ImmatureCoinbaseRewards += utxoAmt
					coinBalance.SKAImmatureCoinbaseRewards = coinBalance.SKAImmatureCoinbaseRewards.Add(skaAmt)
				}
				coinBalance.Total += utxoAmt
				coinBalance.SKATotal = coinBalance.SKATotal.Add(skaAmt)
			case txscript.OP_SSGEN:
				// SSFee SF (staker fee) outputs for SKA use OP_SSGEN scripts
				// These are copied from vote reward outputs; see SSFeeMatured
				if s.stakeGenMatured(ns, cKey, fetchRawCreditHasExpiry(cVal, DBVersion), syncHeight) {
					coinBalance.Spendable += utxoAmt
					coinBalance.SKASpendable = coinBalance.SKASpendable.Add(skaAmt)
				} else {
					coinBalance.ImmatureStakeGeneration += utxoAmt
					coinBalance.SKAImmatureStakeGeneration = coinBalance.SKAImmatureStakeGeneration.Add(skaAmt)
				}
				coinBalance.Total += utxoAmt
				coinBalance.SKATotal = coinBalance.SKATotal.Add(skaAmt)
			default:
				// Skip VAR-specific opcodes for SKA coins (staking, coinbase, etc.)
				log.Warnf("Unexpected opcode %v for SKA coin type %v", opcode, coinType)
			}

			// Store updated coin balance back to map
			ab.CoinTypeBalances[coinType] = coinBalance
		}

		c.Close()
	}

	// Unconfirmed transaction output handling.
	// Process coin-type specific unmined credit buckets
	// First VAR bucket (most common)
	varUnminedBucket := ns.NestedReadBucket(bucketUnminedCreditsForCoinType(cointype.CoinTypeVAR))
	if varUnminedBucket != nil {
		c := varUnminedBucket.ReadCursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if existsRawUnminedInput(ns, k) != nil {
				continue
			}

			pkScript, err := s.fastCreditPkScriptLookup(ns, nil, k)
			if err != nil {
				c.Close()
				return nil, err
			}
			thisAcct, err := s.fetchAccountForPkScript(addrmgrNs, nil, v, pkScript)
			if err != nil {
				c.Close()
				return nil, err
			}

			utxoAmt, err := fetchRawUnminedCreditAmount(v)
			if err != nil {
				c.Close()
				return nil, err
			}

			ab, ok := accountBalances[thisAcct]
			if !ok {
				ab = &Balances{
					Account:          thisAcct,
					CoinTypeBalances: make(map[cointype.CoinType]CoinBalance),
				}
				accountBalances[thisAcct] = ab
			}

			coinType := fetchRawUnminedCreditCoinType(v)
			if _, exists := ab.CoinTypeBalances[coinType]; !exists {
				ab.CoinTypeBalances[coinType] = CoinBalance{
					CoinType: coinType,
				}
			}

			coinBalance := ab.CoinTypeBalances[coinType]
			opcode := fetchRawUnminedCreditTagOpCode(v)
			txHash := k[:32]
			unpublished := existsUnpublished(ns, txHash)

			switch opcode {
			case opNonstake:
				if minConf == 0 && !unpublished {
					coinBalance.Spendable += utxoAmt
					if coinType == cointype.CoinTypeVAR {
						ab.Spendable += utxoAmt
					}
				} else if !fetchRawCreditIsCoinbase(v) {
					coinBalance.Unconfirmed += utxoAmt
					if coinType == cointype.CoinTypeVAR {
						ab.Unconfirmed += utxoAmt
					}
				}
				coinBalance.Total += utxoAmt
				if coinType == cointype.CoinTypeVAR {
					ab.Total += utxoAmt
				}
			case txscript.OP_SSTX:
				coinBalance.VotingAuthority += utxoAmt
				coinBalance.Total += utxoAmt
				if coinType == cointype.CoinTypeVAR {
					ab.VotingAuthority += utxoAmt
					ab.Total += utxoAmt
				}
			case txscript.OP_SSGEN:
				fallthrough
			case txscript.OP_SSRTX:
				coinBalance.ImmatureStakeGeneration += utxoAmt
				coinBalance.Total += utxoAmt
				if coinType == cointype.CoinTypeVAR {
					ab.ImmatureStakeGeneration += utxoAmt
					ab.Total += utxoAmt
				}
			case txscript.OP_SSTXCHANGE:
				coinBalance.Total += utxoAmt
				if coinType == cointype.CoinTypeVAR {
					ab.Total += utxoAmt
				}
				ab.CoinTypeBalances[coinType] = coinBalance
				continue
			case txscript.OP_TGEN:
				// Only consider mined tspends for simpler balance accounting.
			default:
				log.Warnf("Unhandled unconfirmed opcode %v: %v", opcode, v)
			}

			ab.CoinTypeBalances[coinType] = coinBalance
		}
		c.Close()
	}

	// Process other coin type unmined credits (active SKA types only)
	for _, skaCoinType := range s.getActiveSKACoinTypes() {
		skaBucket := ns.NestedReadBucket(bucketUnminedCreditsForCoinType(skaCoinType))
		if skaBucket == nil {
			continue
		}
		c := skaBucket.ReadCursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if existsRawUnminedInput(ns, k) != nil {
				continue
			}

			pkScript, err := s.fastCreditPkScriptLookup(ns, nil, k)
			if err != nil {
				c.Close()
				return nil, err
			}
			thisAcct, err := s.fetchAccountForPkScript(addrmgrNs, nil, v, pkScript)
			if err != nil {
				c.Close()
				return nil, err
			}

			utxoAmt, err := fetchRawUnminedCreditAmount(v)
			if err != nil {
				c.Close()
				return nil, err
			}

			ab, ok := accountBalances[thisAcct]
			if !ok {
				ab = &Balances{
					Account:          thisAcct,
					CoinTypeBalances: make(map[cointype.CoinType]CoinBalance),
				}
				accountBalances[thisAcct] = ab
			}

			coinType := fetchRawUnminedCreditCoinType(v)
			if _, exists := ab.CoinTypeBalances[coinType]; !exists {
				ab.CoinTypeBalances[coinType] = CoinBalance{
					CoinType:                   coinType,
					SKAImmatureCoinbaseRewards: cointype.Zero(),
					SKAImmatureStakeGeneration: cointype.Zero(),
					SKASpendable:               cointype.Zero(),
					SKATotal:                   cointype.Zero(),
					SKAUnconfirmed:             cointype.Zero(),
				}
			}

			coinBalance := ab.CoinTypeBalances[coinType]
			opcode := fetchRawUnminedCreditTagOpCode(v)
			txHash := k[:32]
			unpublished := existsUnpublished(ns, txHash)

			// For SKA, fetch big.Int amount from SKA amount bucket
			skaAmt, err := fetchSKAUnminedCreditAmount(ns, k)
			if err != nil {
				return nil, err
			}

			switch opcode {
			case opNonstake:
				// SSFee MF (miner fee) or regular SKA transfers
				if minConf == 0 && !unpublished {
					coinBalance.Spendable += utxoAmt
					coinBalance.SKASpendable = coinBalance.SKASpendable.Add(skaAmt)
				} else if !fetchRawUnminedCreditTagIsCoinbase(v) {
					coinBalance.Unconfirmed += utxoAmt
					coinBalance.SKAUnconfirmed = coinBalance.SKAUnconfirmed.Add(skaAmt)
				}
				coinBalance.Total += utxoAmt
				coinBalance.SKATotal = coinBalance.SKATotal.Add(skaAmt)
			case txscript.OP_SSGEN:
				// SSFee SF (staker fee) - always immature when unmined
				coinBalance.ImmatureStakeGeneration += utxoAmt
				coinBalance.SKAImmatureStakeGeneration = coinBalance.SKAImmatureStakeGeneration.Add(skaAmt)
				coinBalance.Total += utxoAmt
				coinBalance.SKATotal = coinBalance.SKATotal.Add(skaAmt)
			default:
				log.Warnf("Unhandled unmined SKA opcode %v for coin type %v", opcode, coinType)
				coinBalance.Total += utxoAmt
				coinBalance.SKATotal = coinBalance.SKATotal.Add(skaAmt)
			}

			ab.CoinTypeBalances[coinType] = coinBalance
		}
		c.Close()
	}

	// Account for ticket commitments by iterating over the unspent commitments
	// index.
	it := makeUnspentTicketCommitsIterator(ns)
	for it.next() {
		if it.err != nil {
			return nil, it.err
		}

		if it.unminedSpent {
			// Some unmined tx is redeeming this commitment, so ignore it for
			// balance purposes.
			continue
		}

		ab, ok := accountBalances[it.account]
		if !ok {
			ab = &Balances{
				Account:          it.account,
				CoinTypeBalances: make(map[cointype.CoinType]CoinBalance),
			}
			accountBalances[it.account] = ab
		}

		ab.LockedByTickets += it.amount
		// Do NOT add to Total - the ticket value is already represented
		// by VotingAuthority from the submission output (OP_SSTX)
	}
	it.close()

	return accountBalances, nil
}

// CoinBalance represents balance breakdown for a specific coin type.
// For VAR coins, use the dcrutil.Amount fields.
// For SKA coins, the int64 dcrutil.Amount fields (Spendable, Total,
// ImmatureCoinbaseRewards, etc.) are uniformly zero — only the SKA*
// fields carry the actual atom counts. This avoids the truncation /
// double-count footgun where the int64 view of an SKA atom count is
// either silently zeroed (above int64 max) or duplicated against
// SKASpendable (when it fits).
type CoinBalance struct {
	CoinType                cointype.CoinType
	ImmatureCoinbaseRewards dcrutil.Amount
	ImmatureStakeGeneration dcrutil.Amount
	LockedByTickets         dcrutil.Amount
	Spendable               dcrutil.Amount
	Total                   dcrutil.Amount
	VotingAuthority         dcrutil.Amount
	Unconfirmed             dcrutil.Amount

	// SKA big.Int amounts for coins that exceed int64 capacity.
	// These are only populated for SKA coin types.
	SKAImmatureCoinbaseRewards  cointype.SKAAmount
	SKAImmatureStakeGeneration  cointype.SKAAmount // SKA fees distributed to stakers
	SKASpendable                cointype.SKAAmount
	SKATotal                    cointype.SKAAmount
	SKAUnconfirmed              cointype.SKAAmount
}

// Balances describes a breakdown of an account's balances in various
// categories. Extended to support multiple coin types while maintaining
// backward compatibility with existing VAR-only operations.
type Balances struct {
	Account uint32
	// VAR balance fields (maintained for backward compatibility)
	ImmatureCoinbaseRewards dcrutil.Amount
	ImmatureStakeGeneration dcrutil.Amount
	LockedByTickets         dcrutil.Amount
	Spendable               dcrutil.Amount
	Total                   dcrutil.Amount
	VotingAuthority         dcrutil.Amount
	Unconfirmed             dcrutil.Amount

	// Multi-coin support: breakdown by coin type
	CoinTypeBalances map[cointype.CoinType]CoinBalance
}

// AccountBalance returns a Balances struct for some given account at
// syncHeight block height with all UTXOS that have minConf many confirms.
func (s *Store) AccountBalance(dbtx walletdb.ReadTx, minConf int32, account uint32) (Balances, error) {
	balances, err := s.AccountBalances(dbtx, minConf)
	if err != nil {
		return Balances{}, err
	}

	balance, ok := balances[account]
	if !ok {
		// No balance for the account was found so must be zero.
		return Balances{
			Account:          account,
			CoinTypeBalances: make(map[cointype.CoinType]CoinBalance),
		}, nil
	}

	return *balance, nil
}

// AccountBalances returns a map of all account balances at syncHeight block
// height with all UTXOs that have minConf many confirms.
func (s *Store) AccountBalances(dbtx walletdb.ReadTx, minConf int32) (map[uint32]*Balances, error) {
	_, syncHeight := s.MainChainTip(dbtx)
	return s.balanceFullScan(dbtx, minConf, syncHeight)
}

// AccountBalanceByCoinType returns the balance for a specific coin type
// within an account. This is more efficient than AccountBalance as it only
// processes outputs for the specified coin type.
// For SKA coins, big.Int amounts are used via the SKA* fields in CoinBalance.
func (s *Store) AccountBalanceByCoinType(dbtx walletdb.ReadTx, minConf int32, account uint32, coinType cointype.CoinType) (CoinBalance, error) {
	_, syncHeight := s.MainChainTip(dbtx)

	ns := dbtx.ReadBucket(wtxmgrBucketKey)
	addrmgrNs := dbtx.ReadBucket(waddrmgrBucketKey)

	balance := CoinBalance{
		CoinType:                   coinType,
		SKAImmatureCoinbaseRewards: cointype.Zero(),
		SKASpendable:               cointype.Zero(),
		SKATotal:                   cointype.Zero(),
		SKAUnconfirmed:             cointype.Zero(),
	}

	isSKA := coinType.IsSKA()

	// Process confirmed credits for specified coin type
	bucketName := bucketUnspentForCoinType(coinType)
	bucket := ns.NestedReadBucket(bucketName)
	if bucket != nil {
		c := bucket.ReadCursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if existsRawUnminedInput(ns, k) != nil {
				// Output is spent by an unmined transaction.
				continue
			}

			cKey := make([]byte, 72)
			copy(cKey[0:32], k[0:32])   // Tx hash
			copy(cKey[32:36], v[0:4])   // Block height
			copy(cKey[36:68], v[4:36])  // Block hash
			copy(cKey[68:72], k[32:36]) // Output index

			cVal := existsRawCredit(ns, cKey)
			if cVal == nil {
				c.Close()
				return balance, errors.E(errors.IO, "missing credit for unspent output")
			}

			// Check the account
			pkScript, err := s.fastCreditPkScriptLookup(ns, cKey, nil)
			if err != nil {
				c.Close()
				return balance, err
			}
			thisAcct, err := s.fetchAccountForPkScript(addrmgrNs, cVal, nil, pkScript)
			if err != nil {
				c.Close()
				return balance, err
			}
			if account != thisAcct {
				continue
			}

			// For SKA, use big.Int amount from separate bucket. The int64
			// utxoAmt is intentionally left at zero for SKA UTXOs: feeding
			// fetchRawCreditAmount(cVal) into the int64 accumulators
			// either truncates (when SKAValue exceeds int64 max) or
			// double-counts (when it fits, since SKASpendable already
			// carries the same atoms in big.Int form). Callers must
			// consult the SKA* fields for SKA balances; the int64 fields
			// are uniformly zero for SKA accounts. See the CoinBalance
			// doc comment.
			var utxoAmt dcrutil.Amount
			var skaAmt cointype.SKAAmount
			if isSKA {
				skaAmt, err = fetchSKACreditAmount(ns, cKey)
				if err != nil {
					c.Close()
					return balance, err
				}
			} else {
				utxoAmt, err = fetchRawCreditAmount(cVal)
				if err != nil {
					c.Close()
					return balance, err
				}
			}

			height := extractRawCreditHeight(cKey)
			opcode := fetchRawCreditTagOpCode(cVal)

			switch opcode {
			case txscript.OP_TGEN:
				fallthrough
			case opNonstake:
				isConfirmed := confirmed(minConf, height, syncHeight)
				creditFromCoinbase := fetchRawCreditIsCoinbase(cVal)
				matureCoinbase := (creditFromCoinbase &&
					coinbaseMatured(s.chainParams, height, syncHeight))

				if (isConfirmed && !creditFromCoinbase) || matureCoinbase {
					balance.Spendable += utxoAmt
					if isSKA {
						balance.SKASpendable = balance.SKASpendable.Add(skaAmt)
					}
				} else if creditFromCoinbase && !matureCoinbase {
					balance.ImmatureCoinbaseRewards += utxoAmt
					if isSKA {
						balance.SKAImmatureCoinbaseRewards = balance.SKAImmatureCoinbaseRewards.Add(skaAmt)
					}
				}
				balance.Total += utxoAmt
				if isSKA {
					balance.SKATotal = balance.SKATotal.Add(skaAmt)
				}

			case txscript.OP_SSTX:
				balance.VotingAuthority += utxoAmt
				balance.Total += utxoAmt
				if isSKA {
					balance.SKATotal = balance.SKATotal.Add(skaAmt)
				}

			case txscript.OP_SSGEN:
				fallthrough
			case txscript.OP_SSRTX:
				if s.stakeGenMatured(ns, cKey, fetchRawCreditHasExpiry(cVal, DBVersion), syncHeight) {
					balance.Spendable += utxoAmt
					if isSKA {
						balance.SKASpendable = balance.SKASpendable.Add(skaAmt)
					}
				} else {
					// Check if this is a miner SSFee (goes to ImmatureCoinbaseRewards)
					// or staker SSFee/vote (goes to ImmatureStakeGeneration)
					ssfeeType := getSSFeeMarkerType(ns, cKey)
					if ssfeeType == stake.SSFeeMarkerMiner {
						balance.ImmatureCoinbaseRewards += utxoAmt
						if isSKA {
							balance.SKAImmatureCoinbaseRewards = balance.SKAImmatureCoinbaseRewards.Add(skaAmt)
						}
					} else {
						balance.ImmatureStakeGeneration += utxoAmt
						if isSKA {
							balance.SKAImmatureStakeGeneration = balance.SKAImmatureStakeGeneration.Add(skaAmt)
						}
					}
				}
				balance.Total += utxoAmt
				if isSKA {
					balance.SKATotal = balance.SKATotal.Add(skaAmt)
				}

			case txscript.OP_SSTXCHANGE:
				if ticketChangeMatured(s.chainParams, height, syncHeight) {
					balance.Spendable += utxoAmt
					if isSKA {
						balance.SKASpendable = balance.SKASpendable.Add(skaAmt)
					}
				}
				balance.Total += utxoAmt
				if isSKA {
					balance.SKATotal = balance.SKATotal.Add(skaAmt)
				}

			default:
				log.Warnf("Unhandled opcode: %v", opcode)
			}
		}
		c.Close()
	}

	// Process unmined credits for specified coin type
	if minConf == 0 {
		unminedBucketName := bucketUnminedCreditsForCoinType(coinType)
		unminedBucket := ns.NestedReadBucket(unminedBucketName)
		if unminedBucket != nil {
			c := unminedBucket.ReadCursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				// Check if this output is spent by an unmined transaction
				if existsRawUnminedInput(ns, k) != nil {
					// Output is spent by an unmined transaction.
					// Skip to next unmined credit.
					continue
				}

				// Check account
				pkScript, err := s.fastCreditPkScriptLookup(ns, nil, k)
				if err != nil {
					c.Close()
					return balance, err
				}
				thisAcct, err := s.fetchAccountForPkScript(addrmgrNs, nil, v, pkScript)
				if err != nil {
					c.Close()
					return balance, err
				}
				if account != thisAcct {
					continue
				}

				// Add to unconfirmed balance
				// For SKA, use big.Int amount from separate bucket
				if isSKA {
					skaAmt, err := fetchSKAUnminedCreditAmount(ns, k)
					if err != nil {
						c.Close()
						return balance, err
					}
					balance.SKAUnconfirmed = balance.SKAUnconfirmed.Add(skaAmt)
					balance.SKATotal = balance.SKATotal.Add(skaAmt)
					// Also update int64 fields for backward compatibility
					amt, _ := fetchRawUnminedCreditAmount(v)
					balance.Unconfirmed += amt
					balance.Total += amt
				} else {
					amt, err := fetchRawUnminedCreditAmount(v)
					if err != nil {
						c.Close()
						return balance, err
					}
					balance.Unconfirmed += amt
					balance.Total += amt
				}
			}
			c.Close()
		}
	}

	// Process tickets for VAR coin type only (tickets are always VAR)
	if coinType == cointype.CoinTypeVAR {
		// Account for ticket commitments using the unspent ticket commits iterator
		it := makeUnspentTicketCommitsIterator(ns)
		for it.next() {
			if it.err != nil {
				return balance, it.err
			}

			if it.unminedSpent {
				// Some unmined tx is redeeming this commitment, so ignore it
				continue
			}

			// Only include if it's for the requested account
			if it.account == account {
				balance.LockedByTickets += it.amount
				// Do NOT add to Total - the ticket value is already represented
				// by VotingAuthority from the submission output (OP_SSTX)
			}
		}
		it.close()
	}

	return balance, nil
}
