package chain

import (
	"context"
	"errors"
	"testing"

	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/wallet"
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
