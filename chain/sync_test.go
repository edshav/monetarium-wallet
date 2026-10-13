package chain

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/gcs"
	"github.com/monetarium/monetarium-node/gcs/blockcf2"
	"github.com/monetarium/monetarium-node/wire"
	werrors "github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet"
	_ "github.com/monetarium/monetarium-wallet/wallet/drivers/bdb"
)

type fakeRescanner struct {
	found     map[chainhash.Hash][]*wire.MsgTx // blocks the node reports relevant txs for
	err       error
	requested []chainhash.Hash
}

func (f *fakeRescanner) Rescan(_ context.Context, blocks []chainhash.Hash,
	save func(*chainhash.Hash, []*wire.MsgTx) error) error {

	f.requested = append(f.requested, blocks...)
	if f.err != nil {
		return f.err
	}
	for i := range blocks {
		// Like mond, report only blocks that hold relevant transactions.
		if txs, ok := f.found[blocks[i]]; ok {
			if err := save(&blocks[i], txs); err != nil {
				return err
			}
		}
	}
	return nil
}

func testNode(height uint32) *wallet.BlockNode {
	header := &wire.BlockHeader{Height: height}
	hash := header.BlockHash()
	return wallet.NewBlockNode(header, &hash, nil)
}

// A block that joins the best chain without a blockconnected notification
// (header fetched after a restart, or a block reorged out earlier) has no
// relevantTxs entry. Its wallet transactions must be fetched from the node
// before ChainSwitch connects it, or they are lost: issue #7.
func TestFetchMissingRelevantTxs(t *testing.T) {
	sidechainBlock := testNode(38723) // reached the forest via getHeaders
	notifiedBlock := testNode(38724)  // arrived with blockconnected
	ticket := &wire.MsgTx{Version: 1, LockTime: 1}
	notifiedTx := &wire.MsgTx{Version: 1, LockTime: 2}

	relevantTxs := map[chainhash.Hash][]*wire.MsgTx{
		*notifiedBlock.Hash: {notifiedTx},
	}
	r := &fakeRescanner{found: map[chainhash.Hash][]*wire.MsgTx{
		*sidechainBlock.Hash: {ticket},
	}}

	chain := []*wallet.BlockNode{sidechainBlock, notifiedBlock}
	if err := fetchMissingRelevantTxs(context.Background(), r, chain, relevantTxs); err != nil {
		t.Fatal(err)
	}

	if len(r.requested) != 2 || r.requested[0] != *sidechainBlock.Hash ||
		r.requested[1] != *notifiedBlock.Hash {
		t.Errorf("rescanned %v, want %v and %v", r.requested,
			sidechainBlock.Hash, notifiedBlock.Hash)
	}
	if got := relevantTxs[*sidechainBlock.Hash]; len(got) != 1 || got[0] != ticket {
		t.Errorf("sidechain block txs = %v, want the ticket from the node", got)
	}
	if got := relevantTxs[*notifiedBlock.Hash]; len(got) != 1 || got[0] != notifiedTx {
		t.Errorf("notified block txs = %v, want them unchanged", got)
	}
}

func TestFetchMissingRelevantTxsNoneMissing(t *testing.T) {
	n := testNode(1)
	relevantTxs := map[chainhash.Hash][]*wire.MsgTx{*n.Hash: nil}
	r := &fakeRescanner{}

	err := fetchMissingRelevantTxs(context.Background(), r, []*wallet.BlockNode{n}, relevantTxs)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.requested) != 0 {
		t.Errorf("rescanned %v, want no rescan when every block has an entry", r.requested)
	}
}

func TestFetchMissingRelevantTxsRescanError(t *testing.T) {
	n := testNode(1)
	rescanErr := errors.New("node unreachable")
	r := &fakeRescanner{err: rescanErr}

	err := fetchMissingRelevantTxs(context.Background(), r, []*wallet.BlockNode{n},
		map[chainhash.Hash][]*wire.MsgTx{})
	if !errors.Is(err, rescanErr) {
		t.Errorf("err = %v, want the rescan error so the block is not connected without its txs", err)
	}
}

// mond rejects a rescan whose blocks do not form a chain, so a block with an
// entry between two blocks without one must be rescanned too, keeping its
// existing entry.
func TestFetchMissingRelevantTxsContiguous(t *testing.T) {
	a, b, c := testNode(10), testNode(11), testNode(12)
	knownTx := &wire.MsgTx{Version: 1, LockTime: 1}
	nodeTx := &wire.MsgTx{Version: 1, LockTime: 2}

	relevantTxs := map[chainhash.Hash][]*wire.MsgTx{*b.Hash: {knownTx}}
	r := &fakeRescanner{found: map[chainhash.Hash][]*wire.MsgTx{
		*b.Hash: {nodeTx},
		*c.Hash: {nodeTx},
	}}

	chain := []*wallet.BlockNode{a, b, c}
	if err := fetchMissingRelevantTxs(context.Background(), r, chain, relevantTxs); err != nil {
		t.Fatal(err)
	}

	want := []chainhash.Hash{*a.Hash, *b.Hash, *c.Hash}
	if len(r.requested) != len(want) {
		t.Fatalf("rescanned %v, want the contiguous run %v", r.requested, want)
	}
	for i := range want {
		if r.requested[i] != want[i] {
			t.Fatalf("rescanned %v, want the contiguous run %v", r.requested, want)
		}
	}
	if got := relevantTxs[*b.Hash]; len(got) != 1 || got[0] != knownTx {
		t.Errorf("block with an entry = %v, want its entry kept", got)
	}
	if got := relevantTxs[*c.Hash]; len(got) != 1 || got[0] != nodeTx {
		t.Errorf("last block txs = %v, want them from the node", got)
	}
}

// fakeNode serves handleBlockConnected the cfilters of known blocks and, like
// mond's rescan, the relevant transactions of the blocks it is asked about.
type fakeNode struct {
	fakeRescanner
	filters map[chainhash.Hash]*gcs.FilterV2
}

func (f *fakeNode) CFilterV2(_ context.Context, blockHash *chainhash.Hash) (*gcs.FilterV2, uint32, []chainhash.Hash, error) {
	filter, ok := f.filters[*blockHash]
	if !ok {
		return nil, 0, nil, errors.New("unknown block")
	}
	// makeBlock commits the filter hash as the header's stake root, which a
	// one-leaf inclusion proof (index 0, no siblings) verifies.
	return filter, 0, nil, nil
}

type syncHarness struct {
	t      *testing.T
	ctx    context.Context
	params *chaincfg.Params
	w      *wallet.Wallet
	node   *fakeNode
	s      *Syncer
}

func newSyncHarness(t *testing.T) *syncHarness {
	ctx := context.Background()
	params := chaincfg.SimNetParams()
	db, err := wallet.CreateDB("bdb", filepath.Join(t.TempDir(), "wallet.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	pubPass := []byte(wallet.InsecurePubPassphrase)
	if err := wallet.Create(ctx, db, pubPass, []byte("private"), nil, params); err != nil {
		t.Fatal(err)
	}
	w, err := wallet.Open(ctx, &wallet.Config{
		DB:            db,
		PubPassphrase: pubPass,
		GapLimit:      20,
		Params:        params,
	})
	if err != nil {
		t.Fatal(err)
	}
	node := &fakeNode{filters: make(map[chainhash.Hash]*gcs.FilterV2)}
	s := NewSyncer(w, &RPCOptions{})
	s.blockRPC = node
	return &syncHarness{t, ctx, params, w, node, s}
}

// makeBlock returns a header on top of parent whose cfilter the node serves.
// nonce tells sibling blocks apart.
func (h *syncHarness) makeBlock(parent *wire.BlockHeader, nonce uint32) *wire.BlockHeader {
	header := &wire.BlockHeader{
		PrevBlock: h.params.GenesisHash,
		Height:    1,
		Bits:      h.params.PowLimitBits,
		Nonce:     nonce,
	}
	if parent != nil {
		header.PrevBlock = parent.BlockHash()
		header.Height = parent.Height + 1
	}
	filter, err := blockcf2.Regular(&wire.MsgBlock{Header: *header}, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	header.StakeRoot = filter.Hash()
	h.node.filters[header.BlockHash()] = filter
	return header
}

// connect delivers a blockconnected notification for header.
func (h *syncHarness) connect(header *wire.BlockHeader, relevantTxs ...*wire.MsgTx) {
	h.t.Helper()
	if err := h.s.handleBlockConnected(h.ctx, header, relevantTxs, false); err != nil {
		h.t.Fatalf("block %d: %v", header.Height, err)
	}
}

// walletTx returns a transaction paying to a wallet address.
func (h *syncHarness) walletTx() *wire.MsgTx {
	addr, err := h.w.NewExternalAddress(h.ctx, 0)
	if err != nil {
		h.t.Fatal(err)
	}
	version, script := addr.PaymentScript()
	tx := wire.NewMsgTx()
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{1}}, 0, nil))
	tx.AddTxOut(&wire.TxOut{Value: 1e8, Version: version, PkScript: script})
	return tx
}

// assertMinedIn checks that tx is mined at header's height and that header is
// the main chain block there.  A nil header means not mined: unmined, or
// removed by PruneUnmined, whose inputs check drops it after a reorg because
// walletTx spends an output the wallet does not hold.
func (h *syncHarness) assertMinedIn(tx *wire.MsgTx, header *wire.BlockHeader) {
	h.t.Helper()
	txHash := tx.TxHash()
	got, _, err := h.w.TxBlock(h.ctx, &txHash) // zero hash when unmined
	if err != nil && !werrors.Is(err, werrors.NotExist) {
		h.t.Fatal(err)
	}
	var want chainhash.Hash
	if header != nil {
		want = header.BlockHash()
	}
	switch {
	case got == want:
	case got == chainhash.Hash{}:
		h.t.Errorf("tx not mined, want it in block %v at height %d", want, header.Height)
	case header == nil:
		h.t.Errorf("tx mined in %v, want it unmined", got)
	default:
		h.t.Errorf("tx mined in %v, want block %v at height %d", got, want, header.Height)
	}
}

func (h *syncHarness) assertTip(header *wire.BlockHeader) {
	h.t.Helper()
	if tip, _ := h.w.MainChainTip(h.ctx); tip != header.BlockHash() {
		h.t.Fatalf("tip %v, want %v at height %d", tip, header.BlockHash(), header.Height)
	}
}

func (h *syncHarness) assertRescanned(headers ...*wire.BlockHeader) {
	h.t.Helper()
	ok := len(h.node.requested) == len(headers)
	for i := 0; ok && i < len(headers); i++ {
		ok = h.node.requested[i] == headers[i].BlockHash()
	}
	if !ok {
		h.t.Errorf("node rescanned %v, want blocks at heights %v", h.node.requested, heights(headers))
	}
}

func heights(headers []*wire.BlockHeader) []uint32 {
	hs := make([]uint32, len(headers))
	for i, header := range headers {
		hs[i] = header.Height
	}
	return hs
}

// Issue #7: the wallet connects block A with its transaction (a ticket on
// mainnet), then restarts while the node has switched to sibling B, which holds
// the same transaction.  getHeaders adds B to the sidechain forest without its
// transactions.  When C arrives on top of B, the transaction must end up mined
// in B.
func TestHandleBlockConnectedSidechainHeader(t *testing.T) {
	h := newSyncHarness(t)
	tx := h.walletTx()

	b1 := h.makeBlock(nil, 0)
	a := h.makeBlock(b1, 0)
	h.connect(b1)
	h.connect(a, tx)
	h.assertMinedIn(tx, a)

	// What getHeaders does with a fetched header: a forest node and no
	// relevantTxs entry.
	b := h.makeBlock(b1, 1)
	bHash := b.BlockHash()
	h.s.sidechains.AddBlockNode(wallet.NewBlockNode(b, &bHash, h.node.filters[bHash]))
	h.node.found = map[chainhash.Hash][]*wire.MsgTx{bHash: {tx}}

	c := h.makeBlock(b, 0)
	h.connect(c)

	h.assertTip(c)
	h.assertMinedIn(tx, b)
	h.assertRescanned(b, c)
}

// A reorg moves blocks A2-A3 out of the main chain and into the sidechain
// forest without their transactions.  When a later reorg switches back to
// that chain, the transactions of A2-A3 must be fetched again.
func TestHandleBlockConnectedReorgBack(t *testing.T) {
	h := newSyncHarness(t)
	tx := h.walletTx()

	b1 := h.makeBlock(nil, 0)
	a2 := h.makeBlock(b1, 0)
	a3 := h.makeBlock(a2, 0)
	h.connect(b1)
	h.connect(a2, tx)
	h.connect(a3)
	h.assertMinedIn(tx, a2)

	b2 := h.makeBlock(b1, 1)
	b3 := h.makeBlock(b2, 1)
	b4 := h.makeBlock(b3, 1)
	h.connect(b2)
	h.connect(b3)
	h.connect(b4)
	h.assertTip(b4)
	h.assertMinedIn(tx, nil)
	if len(h.node.requested) != 0 {
		t.Fatalf("node rescanned %v while every block was notified", h.node.requested)
	}

	h.node.found = map[chainhash.Hash][]*wire.MsgTx{a2.BlockHash(): {tx}}
	a4 := h.makeBlock(a3, 0)
	a5 := h.makeBlock(a4, 0)
	h.connect(a4)
	h.connect(a5)

	h.assertTip(a5)
	h.assertMinedIn(tx, a2)
	h.assertRescanned(a2, a3, a4, a5)
}
