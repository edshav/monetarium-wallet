// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package spv

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/monetarium/monetarium-node/addrmgr"
	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/p2p"
)

// connectRecordingPeer connects to a remote peer that passes on the tx and inv
// messages it receives and answers getinitstate with an empty initstate.
// With hangUp it closes the connection on the first ping, which it is then
// sent, and the returned peer can no longer send.
func connectRecordingPeer(t *testing.T, hangUp bool) (*p2p.RemotePeer, <-chan wire.Message) {
	t.Helper()
	params := chaincfg.SimNetParams()
	received := make(chan wire.Message, 100)
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
				v.Services = wire.SFNodeNetwork
				if write(v) != nil || write(wire.NewMsgVerAck()) != nil {
					return
				}
			case *wire.MsgPing:
				if hangUp {
					return
				}
			case *wire.MsgGetInitState:
				if write(wire.NewMsgInitState()) != nil {
					return
				}
			case *wire.MsgTx, *wire.MsgInv:
				received <- msg
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
	if hangUp {
		// Once a write fails, the peer's writer stops and every later
		// send waits for its context.
		deadline := time.Now().Add(10 * time.Second)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			err := rp.SendMessage(ctx, wire.NewMsgPing(0))
			cancel()
			if err != nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("peer can still send after the remote closed")
			}
		}
	}
	return rp, received
}

// receivedTx waits for the first tx or inv message of a recording peer and
// checks that it is tx itself, not an inv.
func receivedTx(t *testing.T, received <-chan wire.Message, tx *wire.MsgTx) {
	t.Helper()
	select {
	case msg := <-received:
		got, ok := msg.(*wire.MsgTx)
		if !ok {
			t.Fatalf("peer received %v, want the transaction", msg.Command())
		}
		if got.TxHash() != tx.TxHash() {
			t.Fatalf("peer received tx %v, want %v", got.TxHash(), tx.TxHash())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("peer received no transaction")
	}
}

// TestPublishTransactionsPushesTransactions checks that PublishTransactions
// sends the transaction itself to every connected peer, rather than an inv a
// peer may ignore, and still serves a getdata for it.
func TestPublishTransactionsPushesTransactions(t *testing.T) {
	for _, ct := range []cointype.CoinType{cointype.CoinTypeVAR, 1} {
		t.Run(ct.String(), func(t *testing.T) {
			_, version, script, syncer := txInvsWallet(t)
			s := syncer()
			a, aReceived := connectRecordingPeer(t, false)
			b, bReceived := connectRecordingPeer(t, false)
			s.remotes = map[string]*p2p.RemotePeer{"a": a, "b": b}

			tx := payment(version, script, ct, 1)
			if err := s.PublishTransactions(context.Background(), tx); err != nil {
				t.Fatal(err)
			}
			receivedTx(t, aReceived, tx)
			receivedTx(t, bReceived, tx)
			for _, rp := range []*p2p.RemotePeer{a, b} {
				if !rp.InvsSent().Contains(tx.TxHash()) {
					t.Errorf("%v would not serve a getdata for the tx", rp)
				}
			}
		})
	}
}

// TestPublishTransactionsWithoutPeers checks that publishing with no peer
// connected fails with errors.NoPeers.
func TestPublishTransactionsWithoutPeers(t *testing.T) {
	_, version, script, syncer := txInvsWallet(t)
	s := syncer()
	err := s.PublishTransactions(context.Background(), payment(version, script, cointype.CoinTypeVAR, 1))
	if !errors.Is(err, errors.NoPeers) {
		t.Fatalf("got %v, want a NoPeers error", err)
	}
}

// TestPublishTransactionsSurvivesDeadPeers checks that peers that can no
// longer send neither keep the others from getting the transaction nor hold
// the peer list while they stall, and that the call fails, with their error,
// only when no peer took it.
func TestPublishTransactionsSurvivesDeadPeers(t *testing.T) {
	_, version, script, syncer := txInvsWallet(t)
	tx := payment(version, script, cointype.CoinTypeVAR, 1)
	dead := make(map[string]*p2p.RemotePeer)
	for _, name := range []string{"d1", "d2", "d3"} {
		dead[name], _ = connectRecordingPeer(t, true)
	}
	// The dead peers' sends wait for this context.
	const stall = 2 * time.Second
	publish := func(s *Syncer) error {
		ctx, cancel := context.WithTimeout(context.Background(), stall)
		defer cancel()
		return s.PublishTransactions(ctx, tx)
	}

	s := syncer()
	s.remotes = dead
	result := make(chan error, 1)
	go func() { result <- publish(s) }()
	// Let the publish copy the peer list and start its sends first.
	time.Sleep(stall / 4)
	locked := make(chan struct{})
	go func() {
		s.remotesMu.Lock()
		s.remotesMu.Unlock()
		close(locked)
	}()
	select {
	case <-locked:
	case <-time.After(stall / 4):
		t.Fatal("remotesMu held while sends stall")
	}
	if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("no peer took the transaction, but PublishTransactions returned %v", err)
	}

	// The live peer must get the transaction long before the dead peers'
	// sends give up, whatever the map order puts ahead of it.
	live, received := connectRecordingPeer(t, false)
	for range 5 {
		s := syncer()
		s.remotes = map[string]*p2p.RemotePeer{"live": live}
		for name, rp := range dead {
			s.remotes[name] = rp
		}
		go func() { result <- publish(s) }()
		select {
		case msg := <-received:
			if got, ok := msg.(*wire.MsgTx); !ok || got.TxHash() != tx.TxHash() {
				t.Fatalf("live peer received %v, want the transaction", msg.Command())
			}
		case <-time.After(stall / 2):
			t.Fatal("live peer waited for the dead peers")
		}
		if err := <-result; err != nil {
			t.Fatalf("one peer took the transaction, but PublishTransactions returned %v", err)
		}
	}
}

// TestPeerStartupResendsUnmined checks that a newly connected peer gets the
// wallet's unmined transactions themselves, rather than an inv.
func TestPeerStartupResendsUnmined(t *testing.T) {
	for _, ct := range []cointype.CoinType{cointype.CoinTypeVAR, 1} {
		t.Run(ct.String(), func(t *testing.T) {
			ctx := context.Background()
			w, version, script, syncer := txInvsWallet(t)
			tx := payment(version, script, ct, 1)
			if err := w.AddTransaction(ctx, tx, (*chainhash.Hash)(nil)); err != nil {
				t.Fatal(err)
			}
			s := syncer()
			s.initialSyncDone = make(chan struct{})
			close(s.initialSyncDone)
			rp, received := connectRecordingPeer(t, false)

			if err := s.peerStartup(ctx, rp); err != nil {
				t.Fatal(err)
			}
			receivedTx(t, received, tx)
		})
	}
}
