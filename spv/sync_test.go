// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package spv

import (
	"context"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/monetarium/monetarium-node/addrmgr"
	blockchain "github.com/monetarium/monetarium-node/blockchain/standalone"
	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/gcs/blockcf2"
	"github.com/monetarium/monetarium-node/txscript"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/lru"
	"github.com/monetarium/monetarium-wallet/p2p"
	"github.com/monetarium/monetarium-wallet/wallet"
	_ "github.com/monetarium/monetarium-wallet/wallet/drivers/bdb"
)

// connectFakePeer connects to a remote peer advertising services which
// answers getdata with the given blocks and txs, whatever they contain.
func connectFakePeer(t *testing.T, services wire.ServiceFlag, blocks []*wire.MsgBlock, txs []*wire.MsgTx) *p2p.RemotePeer {
	t.Helper()
	params := chaincfg.SimNetParams()
	served := make(map[chainhash.Hash]wire.Message)
	for _, b := range blocks {
		served[b.BlockHash()] = b
	}
	for _, tx := range txs {
		served[tx.TxHash()] = tx
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		write := func(msg wire.Message) error {
			return wire.WriteMessage(c, msg, p2p.Pver, params.Net)
		}
		for {
			msg, _, err := wire.ReadMessage(c, p2p.Pver, params.Net)
			if err != nil {
				return
			}
			switch msg := msg.(type) {
			case *wire.MsgVersion:
				v := wire.NewMsgVersion(new(wire.NetAddress), new(wire.NetAddress), 1, 0)
				v.ProtocolVersion = int32(p2p.Pver)
				v.Services = services
				if write(v) != nil || write(wire.NewMsgVerAck()) != nil {
					return
				}
			case *wire.MsgGetData:
				for _, iv := range msg.InvList {
					if m, ok := served[iv.Hash]; ok && write(m) != nil {
						return
					}
				}
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	lp := p2p.NewLocalPeer(params, nil, addrmgr.New(t.TempDir()))
	rp, err := lp.ConnectOutbound(ctx, l.Addr().String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

func disconnected(rp *p2p.RemotePeer) bool {
	select {
	case <-rp.Done():
		return true
	default:
		return false
	}
}

// testBlocks returns a block on top of genesis whose one tx pays pkScript, and
// a forged copy with the same header, and so the same hash, but a tx the
// header's merkle root does not commit to.
func testBlocks(pkScript []byte) (block, forged *wire.MsgBlock) {
	params := chaincfg.SimNetParams()
	tx := wire.NewMsgTx()
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{1}}, 1e8, nil))
	tx.AddTxOut(wire.NewTxOut(1e8, pkScript))
	header := wire.BlockHeader{
		PrevBlock:  params.GenesisHash,
		Height:     1,
		Bits:       params.PowLimitBits,
		MerkleRoot: blockchain.CalcCombinedTxTreeMerkleRoot([]*wire.MsgTx{tx}, nil),
	}
	block = wire.NewMsgBlock(&header)
	block.AddTransaction(tx)

	other := tx.Copy()
	other.TxOut[0].Value--
	forged = wire.NewMsgBlock(&header)
	forged.AddTransaction(other)
	return block, forged
}

// replaceOnDisconnect swaps good in for bad once bad is disconnected, as the
// connection loop of Run would drop it and later connect another peer.
func replaceOnDisconnect(s *Syncer, bad, good *p2p.RemotePeer) {
	s.remotes = map[string]*p2p.RemotePeer{"bad": bad}
	go func() {
		<-bad.Done()
		s.remotesMu.Lock()
		delete(s.remotes, "bad")
		s.remotes["good"] = good
		if s.remoteAvailable != nil {
			close(s.remoteAvailable)
			s.remoteAvailable = nil
		}
		s.remotesMu.Unlock()
	}()
}

func newTestWallet(t *testing.T) *wallet.Wallet {
	t.Helper()
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
	return w
}

// TestBlocksRejectsForgedTransactions checks that Blocks does not return a
// block whose transactions do not match the merkle root of its header.  A
// block hash commits only to the header, so a peer can answer a request with
// the right header and any transactions.  The peer is disconnected and the
// blocks are fetched from another one.  The forged block comes second, so
// every block of a reply is checked, not only the first.
func TestBlocksRejectsForgedTransactions(t *testing.T) {
	first, _ := testBlocks([]byte{txscript.OP_TRUE})
	second, forged := testBlocks([]byte{txscript.OP_TRUE, txscript.OP_TRUE})
	bad := connectFakePeer(t, wire.SFNodeNetwork, []*wire.MsgBlock{first, forged}, nil)
	good := connectFakePeer(t, wire.SFNodeNetwork, []*wire.MsgBlock{first, second}, nil)
	s := &Syncer{}
	replaceOnDisconnect(s, bad, good)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	h1, h2 := first.BlockHash(), second.BlockHash()
	blocks, err := s.Blocks(ctx, []*chainhash.Hash{&h1, &h2})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := blocks[1].Transactions[0].TxHash(), second.Transactions[0].TxHash(); got != want {
		t.Fatalf("got block with tx %v, want %v", got, want)
	}
	if !disconnected(bad) {
		t.Fatal("peer serving the forged block was not disconnected")
	}
}

// TestBlocksAcceptsSKATransactions checks that an honest block holding an SKA
// tx passes the merkle root check.  The tx hashes to the merkle root only with
// its coin type and SKA amounts, which must survive the wire.
func TestBlocksAcceptsSKATransactions(t *testing.T) {
	params := chaincfg.SimNetParams()
	tx := payment(0, []byte{txscript.OP_TRUE}, 1, 1)
	header := wire.BlockHeader{
		PrevBlock:  params.GenesisHash,
		Height:     1,
		Bits:       params.PowLimitBits,
		MerkleRoot: blockchain.CalcCombinedTxTreeMerkleRoot([]*wire.MsgTx{tx}, nil),
	}
	block := wire.NewMsgBlock(&header)
	block.AddTransaction(tx)
	rp := connectFakePeer(t, wire.SFNodeNetwork, []*wire.MsgBlock{block}, nil)
	s := &Syncer{remotes: map[string]*p2p.RemotePeer{"rp": rp}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hash := block.BlockHash()
	blocks, err := s.Blocks(ctx, []*chainhash.Hash{&hash})
	if err != nil {
		t.Fatal(err)
	}
	if got := blocks[0].Transactions[0]; got.TxHash() != tx.TxHash() {
		t.Fatalf("got tx %v, want %v", got.TxHash(), tx.TxHash())
	}
	if disconnected(rp) {
		t.Fatal("honest peer disconnected")
	}
}

// TestRescanRejectsForgedTransactions checks the same for blocks fetched by
// Rescan because their cfilter matches the wallet.
func TestRescanRejectsForgedTransactions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	w := newTestWallet(t)
	addr, err := w.NewExternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, script := addr.PaymentScript()
	block, forged := testBlocks(script)

	// Put the block in the main chain with its cfilter.
	filter, err := blockcf2.Regular(block, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash := block.BlockHash()
	var forest wallet.SidechainForest
	node := wallet.NewBlockNode(&block.Header, &hash, filter)
	if _, err := w.ChainSwitch(ctx, &forest, []*wallet.BlockNode{node}, nil); err != nil {
		t.Fatal(err)
	}

	bad := connectFakePeer(t, wire.SFNodeNetwork, []*wire.MsgBlock{forged}, nil)
	good := connectFakePeer(t, wire.SFNodeNetwork, []*wire.MsgBlock{block}, nil)
	// The filter takes the stdaddr type, not the wallet's own.
	filterAddr, err := stdaddr.DecodeAddress(addr.String(), w.ChainParams())
	if err != nil {
		t.Fatal(err)
	}
	s := &Syncer{
		wallet:       w,
		filterData:   blockcf2.Entries{script},
		rescanFilter: wallet.NewRescanFilter([]stdaddr.Address{filterAddr}, nil),
	}
	replaceOnDisconnect(s, bad, good)

	var saved []*wire.MsgTx
	err = s.Rescan(ctx, []chainhash.Hash{hash}, func(_ *chainhash.Hash, txs []*wire.MsgTx) error {
		saved = append(saved, txs...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(saved) != 1 || saved[0].TxHash() != block.Transactions[0].TxHash() {
		t.Fatalf("rescan saved %v, want the tx of the real block", saved)
	}
	if !disconnected(bad) {
		t.Fatal("peer serving the forged block was not disconnected")
	}
}

// TestScanChainRejectsForgedTransactions checks the same for blocks fetched
// by scanChain while new headers are processed.
func TestScanChainRejectsForgedTransactions(t *testing.T) {
	script := []byte{txscript.OP_TRUE}
	block, forged := testBlocks(script)
	filter, err := blockcf2.Regular(block, nil)
	if err != nil {
		t.Fatal(err)
	}
	rp := connectFakePeer(t, wire.SFNodeNetwork, []*wire.MsgBlock{forged}, nil)
	// A real wallet, so a forged block that gets through fails the
	// assertions below instead of panicking.
	s := &Syncer{wallet: newTestWallet(t), filterData: blockcf2.Entries{script}}
	hash := block.BlockHash()
	node := wallet.NewBlockNode(&block.Header, &hash, filter)
	if _, err := s.scanChain(context.Background(), rp, []*wallet.BlockNode{node}, nil); err == nil {
		t.Fatal("forged block accepted")
	}
	if !disconnected(rp) {
		t.Fatal("peer serving the forged block was not disconnected")
	}
}

// TestHandleBlockInvsRejectsForgedTransactions checks the same for a block
// announced by inv.
func TestHandleBlockInvsRejectsForgedTransactions(t *testing.T) {
	_, forged := testBlocks([]byte{txscript.OP_TRUE})
	rp := connectFakePeer(t, wire.SFNodeNetwork, []*wire.MsgBlock{forged}, nil)
	ctx := context.Background()
	if err := rp.SendHeaders(ctx); err != nil {
		t.Fatal(err)
	}
	s := &Syncer{wallet: newTestWallet(t)}
	hash := forged.BlockHash()
	if err := s.handleBlockInvs(ctx, rp, []*chainhash.Hash{&hash}); err == nil {
		t.Fatal("forged block accepted")
	}
	if !disconnected(rp) {
		t.Fatal("peer serving the forged block was not disconnected")
	}
}

// txInvsWallet returns an unlocked wallet, the payment script of one of its
// addresses, and a Syncer for it whose filter matches that address and owned.
func txInvsWallet(t *testing.T) (*wallet.Wallet, uint16, []byte, func(owned ...*wire.OutPoint) *Syncer) {
	t.Helper()
	ctx := context.Background()
	w := newTestWallet(t)
	if err := w.Unlock(ctx, []byte("private"), nil); err != nil {
		t.Fatal(err)
	}
	addr, err := w.NewExternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	version, script := addr.PaymentScript()
	filterAddr, err := stdaddr.DecodeAddress(addr.String(), w.ChainParams())
	if err != nil {
		t.Fatal(err)
	}
	syncer := func(owned ...*wire.OutPoint) *Syncer {
		return &Syncer{
			wallet:       w,
			rescanFilter: wallet.NewRescanFilter([]stdaddr.Address{filterAddr}, owned),
			seenTxs:      lru.NewCache[chainhash.Hash](10),
		}
	}
	return w, version, script, syncer
}

// payment returns a tx paying script 1 VAR or 1 coin of an SKA type from an
// output the wallet does not own.
func payment(version uint16, script []byte, coinType cointype.CoinType, prev byte) *wire.MsgTx {
	tx := wire.NewMsgTx()
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{prev}}, 0, nil))
	out := &wire.TxOut{Value: 1e8, Version: version, PkScript: script}
	if coinType.IsSKA() {
		out = &wire.TxOut{Version: version, PkScript: script, CoinType: coinType,
			SKAValue: big.NewInt(1e18)}
	}
	tx.AddTxOut(out)
	return tx
}

// spendOf returns a tx spending output 0 of fund to script, signed by w
// unless sigScript is set.
func spendOf(t *testing.T, w *wallet.Wallet, fund *wire.MsgTx, script, sigScript []byte) *wire.MsgTx {
	t.Helper()
	out := fund.TxOut[0]
	in := wire.NewTxIn(&wire.OutPoint{Hash: fund.TxHash()}, out.Value, sigScript)
	if out.CoinType.IsSKA() {
		in.SKAValueIn = new(big.Int).Set(out.SKAValue)
	}
	spend := wire.NewMsgTx()
	spend.AddTxIn(in)
	spend.AddTxOut(&wire.TxOut{Value: out.Value, Version: out.Version, PkScript: script,
		CoinType: out.CoinType, SKAValue: out.SKAValue})
	if sigScript == nil {
		sigErrs, _, err := w.SignTransaction(context.Background(), spend, txscript.SigHashAll, nil, nil, nil)
		if err != nil || len(sigErrs) != 0 {
			t.Fatalf("sign: %v %v", err, sigErrs)
		}
	}
	return spend
}

func recorded(t *testing.T, w *wallet.Wallet, tx *wire.MsgTx) bool {
	t.Helper()
	hash := tx.TxHash()
	_, _, err := w.GetTransactionsByHashes(context.Background(), []*chainhash.Hash{&hash})
	if err != nil && !errors.Is(err, errors.NotExist) {
		t.Fatal(err)
	}
	return err == nil
}

func hashes(txs ...*wire.MsgTx) []*chainhash.Hash {
	hs := make([]*chainhash.Hash, len(txs))
	for i, tx := range txs {
		h := tx.TxHash()
		hs[i] = &h
	}
	return hs
}

// TestHandleTxInvsDisconnectsForgedSpend checks that a full node peer relaying
// a tx which spends a wallet output without a valid signature is
// disconnected.  A full node validates what it relays, so the tx can only be
// an attack.  An SPV peer cannot validate, so it stays connected.  The forged
// tx is not recorded either way, and a valid spend is recorded without a
// disconnect.
func TestHandleTxInvsDisconnectsForgedSpend(t *testing.T) {
	for _, tc := range []struct {
		name       string
		services   wire.ServiceFlag
		coinType   cointype.CoinType
		sigScript  []byte // nil: signed by the wallet
		disconnect bool
	}{
		{name: "full node, no signature", services: wire.SFNodeNetwork,
			sigScript: []byte{txscript.OP_TRUE}, disconnect: true},
		{name: "full node, unparsable signature", services: wire.SFNodeNetwork,
			sigScript: []byte{txscript.OP_PUSHDATA1}, disconnect: true},
		{name: "full node, SKA1, no signature", services: wire.SFNodeNetwork, coinType: 1,
			sigScript: []byte{txscript.OP_TRUE}, disconnect: true},
		{name: "SPV peer, no signature", sigScript: []byte{txscript.OP_TRUE}},
		{name: "full node, valid spend", services: wire.SFNodeNetwork},
		{name: "full node, SKA1, valid spend", services: wire.SFNodeNetwork, coinType: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			w, version, script, syncer := txInvsWallet(t)
			fund := payment(version, script, tc.coinType, 1)
			if err := w.AddTransaction(ctx, fund, nil); err != nil {
				t.Fatal(err)
			}
			spend := spendOf(t, w, fund, script, tc.sigScript)

			rp := connectFakePeer(t, tc.services, nil, []*wire.MsgTx{spend})
			syncer(&spend.TxIn[0].PreviousOutPoint).handleTxInvs(ctx, rp, hashes(spend))
			if got := disconnected(rp); got != tc.disconnect {
				t.Fatalf("disconnected = %v, want %v", got, tc.disconnect)
			}
			if got, want := recorded(t, w, spend), tc.sigScript == nil; got != want {
				t.Fatalf("recorded = %v, want %v", got, want)
			}
		})
	}
}

// TestHandleTxInvsKeepsPeerOnOtherErrors checks that a full node relaying a
// tx the wallet fails to record for a reason other than a forged spend of its
// outputs stays connected.  Here the tx double spends an unmined tx of the
// wallet, which the node need not have seen.
func TestHandleTxInvsKeepsPeerOnOtherErrors(t *testing.T) {
	ctx := context.Background()
	w, version, script, syncer := txInvsWallet(t)
	fund := payment(version, script, 0, 1)
	if err := w.AddTransaction(ctx, fund, nil); err != nil {
		t.Fatal(err)
	}
	first := spendOf(t, w, fund, script, nil)
	if err := w.AddTransaction(ctx, first, nil); err != nil {
		t.Fatal(err)
	}
	bad := spendOf(t, w, fund, []byte{txscript.OP_TRUE}, nil)

	rp := connectFakePeer(t, wire.SFNodeNetwork, nil, []*wire.MsgTx{bad})
	syncer(&bad.TxIn[0].PreviousOutPoint).handleTxInvs(ctx, rp, hashes(bad))
	if recorded(t, w, bad) {
		t.Fatal("double spend recorded")
	}
	if disconnected(rp) {
		t.Fatal("peer disconnected")
	}
}

// TestHandleTxInvsDropsBatchAfterForgedSpend checks that once a full node is
// disconnected for a forged spend, the rest of the txs it relayed in the same
// batch are not recorded: they come from a peer shown to lie, and are seen
// again when mined.
func TestHandleTxInvsDropsBatchAfterForgedSpend(t *testing.T) {
	ctx := context.Background()
	w, version, script, syncer := txInvsWallet(t)
	fund := payment(version, script, 0, 1)
	if err := w.AddTransaction(ctx, fund, nil); err != nil {
		t.Fatal(err)
	}
	forged := spendOf(t, w, fund, script, []byte{txscript.OP_TRUE})
	next := payment(version, script, 0, 2)

	rp := connectFakePeer(t, wire.SFNodeNetwork, nil, []*wire.MsgTx{forged, next})
	syncer(&forged.TxIn[0].PreviousOutPoint).handleTxInvs(ctx, rp, hashes(forged, next))
	if !disconnected(rp) {
		t.Fatal("peer relaying the forged spend was not disconnected")
	}
	if recorded(t, w, next) {
		t.Fatal("tx relayed after the forged spend was recorded")
	}
}
