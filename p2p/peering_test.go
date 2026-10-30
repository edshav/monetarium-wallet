// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package p2p

import (
	"context"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/monetarium/monetarium-node/addrmgr"
	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
)

// serveLikeNode accepts one connection, answers getdata with msgs and passes
// on the txs it receives.  Like mond, it negotiates the lower of its own
// maximum protocol version and the remote's, and encodes and decodes every
// message at that version.
func serveLikeNode(l net.Listener, cnet wire.CurrencyNet, maxPver uint32,
	msgs map[chainhash.Hash]wire.Message, received chan<- *wire.MsgTx) {

	c, err := l.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	pver := maxPver
	for {
		msg, _, err := wire.ReadMessage(c, pver, cnet)
		if err != nil {
			return
		}
		switch msg := msg.(type) {
		case *wire.MsgVersion:
			pver = min(pver, uint32(msg.ProtocolVersion))
			v := wire.NewMsgVersion(new(wire.NetAddress), new(wire.NetAddress), 1, 0)
			v.ProtocolVersion = int32(maxPver)
			v.Services = wire.SFNodeNetwork
			if wire.WriteMessage(c, v, pver, cnet) != nil ||
				wire.WriteMessage(c, wire.NewMsgVerAck(), pver, cnet) != nil {
				return
			}
		case *wire.MsgGetData:
			for _, iv := range msg.InvList {
				if m, ok := msgs[iv.Hash]; ok && wire.WriteMessage(c, m, pver, cnet) != nil {
					return
				}
			}
		case *wire.MsgTx:
			received <- msg
		}
	}
}

// TestTransactionsSurviveTheWire checks that a tx exchanged with a full node,
// alone or in a block and in either direction, keeps its coin type and amounts,
// and so its hash.  The coin type and SKA amounts exist on the wire only from
// SKABigIntVersion on, so a lower negotiated version strips them: an SKA tx
// then no longer matches the hash it was requested by or the merkle root of
// its block, and a node receives a different tx than the wallet sent.
func TestTransactionsSurviveTheWire(t *testing.T) {
	params := chaincfg.SimNetParams()
	ska := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	varTx := wire.NewMsgTx()
	varTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{1}}, 1e8, nil))
	varTx.AddTxOut(&wire.TxOut{Value: 1e8, PkScript: []byte{0x51}})
	skaTx := wire.NewMsgTx()
	in := wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{2}}, 0, nil)
	in.SKAValueIn = new(big.Int).Set(ska)
	skaTx.AddTxIn(in)
	skaTx.AddTxOut(&wire.TxOut{CoinType: cointype.CoinType(1), SKAValue: new(big.Int).Set(ska),
		PkScript: []byte{0x51}})

	for _, nodePver := range []uint32{wire.SKABigIntVersion, wire.ProtocolVersion} {
		for _, tx := range []*wire.MsgTx{varTx, skaTx} {
			name := fmt.Sprintf("node pver %d, %v", nodePver, tx.TxOut[0].CoinType)
			t.Run(name, func(t *testing.T) {
				block := wire.NewMsgBlock(&wire.BlockHeader{Height: 1})
				block.AddTransaction(tx)
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				received := make(chan *wire.MsgTx, 1)
				go serveLikeNode(l, params.Net, nodePver, map[chainhash.Hash]wire.Message{
					tx.TxHash():       tx,
					block.BlockHash(): block,
				}, received)

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				lp := NewLocalPeer(params, nil, addrmgr.New(t.TempDir()))
				rp, err := lp.ConnectOutbound(ctx, l.Addr().String(), 0)
				if err != nil {
					t.Fatal(err)
				}
				if rp.Pver() != wire.SKABigIntVersion {
					t.Fatalf("negotiated pver %d, want %d", rp.Pver(), wire.SKABigIntVersion)
				}

				check := func(what string, got *wire.MsgTx) {
					t.Helper()
					if got.TxHash() != tx.TxHash() {
						t.Fatalf("%s: got tx %v, want %v", what, got.TxHash(), tx.TxHash())
					}
					// The hash covers the outputs' coin type and SKA
					// amount, not the witness.
					want, v := tx.TxIn[0].SKAValueIn, got.TxIn[0].SKAValueIn
					if (want == nil) != (v == nil) || want != nil && v.Cmp(want) != 0 {
						t.Fatalf("%s: got SKAValueIn %v, want %v", what, v, want)
					}
				}
				txHash := tx.TxHash()
				txs, err := rp.Transactions(ctx, []*chainhash.Hash{&txHash})
				if err != nil {
					t.Fatalf("fetch tx: %v", err)
				}
				check("fetched tx", txs[0])
				blockHash := block.BlockHash()
				blocks, err := rp.Blocks(ctx, []*chainhash.Hash{&blockHash})
				if err != nil {
					t.Fatalf("fetch block: %v", err)
				}
				check("fetched block", blocks[0].Transactions[0])

				// spv answers a getdata for a published tx this way.
				if err := rp.SendMessage(ctx, tx); err != nil {
					t.Fatal(err)
				}
				select {
				case got := <-received:
					check("sent tx", got)
				case <-ctx.Done():
					t.Fatal("node received no tx")
				}
			})
		}
	}
}

// TestRejectsPeersWithoutSKAEncoding checks that a peer whose maximum protocol
// version predates SKABigIntVersion fails the handshake: every SKA tx
// exchanged with it would lose its SKA amounts.
func TestRejectsPeersWithoutSKAEncoding(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	params := chaincfg.SimNetParams()
	go serveLikeNode(l, params.Net, wire.DualCoinVersion, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lp := NewLocalPeer(params, nil, addrmgr.New(t.TempDir()))
	_, err = lp.ConnectOutbound(ctx, l.Addr().String(), 0)
	if !errors.Is(err, errors.Protocol) {
		t.Fatalf("got %v, want a protocol error", err)
	}
}
