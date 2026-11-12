// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package spv

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/decred/slog"
	"github.com/monetarium/monetarium-node/addrmgr"
	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/p2p"
	"github.com/monetarium/monetarium-wallet/wallet"
)

// connectRecordingPeer connects to a remote peer that passes on the tx and inv
// messages it receives and answers getinitstate with an empty initstate.
// With hangUp it closes the connection on the first ping, which it is then
// sent, and the returned peer has disconnected: its writer takes one more
// message, fails to write it and stops, so only its next send succeeds and
// every later one waits for its context.
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
		if err := rp.SendMessage(ctx, wire.NewMsgPing(0)); err != nil {
			t.Fatal(err)
		}
		select {
		case <-rp.Done():
		case <-time.After(10 * time.Second):
			t.Fatal("peer still connected after the remote closed")
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

// parentAndChild records in w an unmined payment to script and a signed
// unmined spend of it.
func parentAndChild(t *testing.T, w *wallet.Wallet, version uint16, script []byte, ct cointype.CoinType) []*wire.MsgTx {
	t.Helper()
	ctx := context.Background()
	parent := payment(version, script, ct, 1)
	if err := w.AddTransaction(ctx, parent, (*chainhash.Hash)(nil)); err != nil {
		t.Fatal(err)
	}
	child := spendOf(t, w, parent, script, nil)
	if err := w.AddTransaction(ctx, child, (*chainhash.Hash)(nil)); err != nil {
		t.Fatal(err)
	}
	return []*wire.MsgTx{parent, child}
}

// receivedAll checks that rp was sent every one of txs itself, in order, and
// would serve a getdata for each.
func receivedAll(t *testing.T, rp *p2p.RemotePeer, received <-chan wire.Message, txs []*wire.MsgTx) {
	t.Helper()
	for _, tx := range txs {
		receivedTx(t, received, tx)
		if !rp.InvsSent().Contains(tx.TxHash()) {
			t.Errorf("%v would not serve a getdata for %v", rp, tx.TxHash())
		}
	}
}

// TestPublishTransactionsPushesTransactions checks that PublishTransactions
// sends every transaction itself, in order, to every connected peer, rather
// than an inv a peer may ignore, and still serves a getdata for them.
func TestPublishTransactionsPushesTransactions(t *testing.T) {
	for _, ct := range []cointype.CoinType{cointype.CoinTypeVAR, 1} {
		t.Run(ct.String(), func(t *testing.T) {
			w, version, script, syncer := txInvsWallet(t)
			txs := parentAndChild(t, w, version, script, ct)
			s := syncer()
			a, aReceived := connectRecordingPeer(t, false)
			b, bReceived := connectRecordingPeer(t, false)
			s.remotes = map[string]*p2p.RemotePeer{"a": a, "b": b}

			if err := s.PublishTransactions(context.Background(), txs...); err != nil {
				t.Fatal(err)
			}
			receivedAll(t, a, aReceived, txs)
			receivedAll(t, b, bReceived, txs)
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
		rp, _ := connectRecordingPeer(t, true)
		// Spend the one send a hung-up peer has left.
		if err := rp.SendMessage(context.Background(), wire.NewMsgPing(0)); err != nil {
			t.Fatal(err)
		}
		dead[name] = rp
	}
	// The dead peers' sends wait for the context, so with no other peer the
	// call fails with its error.
	s := syncer()
	s.remotes = dead
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	err := s.PublishTransactions(ctx, tx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("no peer took the transaction, but PublishTransactions returned %v", err)
	}

	// With a live peer added, whatever the map order puts ahead of it, the
	// live peer gets the transaction and remotesMu is free while the dead
	// peers' sends still wait. The deadline only bounds a failing run: each
	// round cancels the context once both are seen. The live peer goes in
	// last, since a small map tends to iterate from the first key inserted.
	live, received := connectRecordingPeer(t, false)
	for range 10 {
		s := syncer()
		s.remotes = make(map[string]*p2p.RemotePeer)
		for name, rp := range dead {
			s.remotes[name] = rp
		}
		s.remotes["live"] = live
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		result := make(chan error, 1)
		go func() { result <- s.PublishTransactions(ctx, tx) }()
		select {
		case msg := <-received:
			if got, ok := msg.(*wire.MsgTx); !ok || got.TxHash() != tx.TxHash() {
				t.Fatalf("live peer received %v, want the transaction", msg.Command())
			}
		case err := <-result:
			t.Fatalf("PublishTransactions returned %v before the live peer got the transaction", err)
		}
		// The sends have started, and the dead ones end only with ctx.
		s.remotesMu.Lock()
		s.remotesMu.Unlock()
		if ctx.Err() != nil {
			t.Fatal("remotesMu held until the dead peers' sends gave up")
		}
		cancel()
		if err := <-result; err != nil {
			t.Fatalf("one peer took the transaction, but PublishTransactions returned %v", err)
		}
	}
}

// TestPublishTransactionsPartialPeer checks that a peer that took the parent
// but failed to take its child does not count as having taken the
// transactions, so with no other peer the call fails.
func TestPublishTransactionsPartialPeer(t *testing.T) {
	w, version, script, syncer := txInvsWallet(t)
	txs := parentAndChild(t, w, version, script, cointype.CoinTypeVAR)

	// The partial peer's send of the child waits for the context, so the
	// call fails with its error.
	s := syncer()
	partial, _ := connectRecordingPeer(t, true)
	s.remotes = map[string]*p2p.RemotePeer{"partial": partial}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	err := s.PublishTransactions(ctx, txs...)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the peer took only the parent, but PublishTransactions returned %v", err)
	}

	// With a live peer added, the call succeeds once the live peer has both
	// transactions. The deadline only bounds a failing run: the context is
	// cancelled once they arrive.
	s = syncer()
	partial, _ = connectRecordingPeer(t, true)
	live, received := connectRecordingPeer(t, false)
	s.remotes = map[string]*p2p.RemotePeer{"partial": partial, "live": live}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- s.PublishTransactions(ctx, txs...) }()
	receivedAll(t, live, received, txs)
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("one peer took the transactions, but PublishTransactions returned %v", err)
	}
}

// syncedLog collects the spv package's log lines.
type syncedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *syncedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *syncedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// TestPeerStartupLogsFailedResend checks that a resend to a new peer that
// cannot take it is logged as a warning, and that one cut short by shutdown
// is left to the caller.
func TestPeerStartupLogsFailedResend(t *testing.T) {
	const resendFailed = "[WRN] SYNC: Failed to resend unmined transactions"
	prev := log
	t.Cleanup(func() { UseLogger(prev) })
	w, version, script, syncer := txInvsWallet(t)
	parentAndChild(t, w, version, script, cointype.CoinTypeVAR)

	// startup runs peerStartup until it gets past its wait for the
	// initial sync, which it picks at random against a peer or context
	// that is already done, and returns what it logged. A hung-up peer
	// has no writer left, so every send of the resend ends with ctx.
	startup := func(ctx context.Context, hangUp bool) string {
		t.Helper()
		for range 50 {
			out := new(syncedLog)
			logger := slog.NewBackend(out).Logger("SYNC")
			logger.SetLevel(slog.LevelTrace)
			UseLogger(logger)
			s := syncer()
			s.initialSyncDone = make(chan struct{})
			close(s.initialSyncDone)
			rp, _ := connectRecordingPeer(t, hangUp)
			if hangUp {
				// Spend the one send a hung-up peer has left.
				if err := rp.SendMessage(context.Background(), wire.NewMsgPing(0)); err != nil {
					t.Fatal(err)
				}
			}
			_ = s.peerStartup(ctx, rp)
			if strings.Contains(out.String(), "Failed to get init state") {
				return out.String()
			}
		}
		t.Fatal("peerStartup never got past its wait for the initial sync")
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if out := startup(ctx, true); !strings.Contains(out, resendFailed) {
		t.Fatalf("a failed resend logged:\n%s\nwant a line with %q", out, resendFailed)
	}

	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if out := startup(ctx, true); strings.Contains(out, "unmined transactions") {
		t.Fatalf("a resend cut short by shutdown logged:\n%s", out)
	}
}

// TestPeerStartupResendsUnmined checks that a newly connected peer gets every
// unmined wallet transaction itself, a parent before its child, rather than
// an inv.
func TestPeerStartupResendsUnmined(t *testing.T) {
	for _, ct := range []cointype.CoinType{cointype.CoinTypeVAR, 1} {
		t.Run(ct.String(), func(t *testing.T) {
			ctx := context.Background()
			w, version, script, syncer := txInvsWallet(t)
			txs := parentAndChild(t, w, version, script, ct)
			s := syncer()
			s.initialSyncDone = make(chan struct{})
			close(s.initialSyncDone)
			rp, received := connectRecordingPeer(t, false)

			if err := s.peerStartup(ctx, rp); err != nil {
				t.Fatal(err)
			}
			receivedAll(t, rp, received, txs)
		})
	}
}
