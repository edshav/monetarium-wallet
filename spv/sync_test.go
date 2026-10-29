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

	"github.com/monetarium/monetarium-node/addrmgr"
	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
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
