// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/decred/slog"
	"github.com/monetarium/monetarium-node/blockchain/stake"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// lockOnTicketRecordDB locks the wallet when purchaseTickets opens the
// record of its nth ticket, so that ticket fails to sign.
type lockOnTicketRecordDB struct {
	walletdb.DB
	w       *Wallet
	n       int
	records int
}

func (d *lockOnTicketRecordDB) BeginReadWriteTx() (walletdb.ReadWriteTx, error) {
	if updateCalledBy(".(*Wallet).purchaseTickets") {
		d.records++
		if d.records == d.n {
			d.w.Lock()
		}
	}
	return d.DB.BeginReadWriteTx()
}

// failAddressDB fails the address writes purchaseTickets makes once it has
// opened the record of its first ticket, so the second ticket gets no
// addresses.
type failAddressDB struct {
	walletdb.DB
	records int
}

var errAddressWrite = errors.New("address write failed")

func (d *failAddressDB) BeginReadWriteTx() (walletdb.ReadWriteTx, error) {
	if updateCalledBy(".(*Wallet).purchaseTickets") {
		d.records++
	}
	// The split's record comes first, then the first ticket's.  The
	// closure persistReturnedChild returns is named by where the toolchain
	// inlines it ("persistReturnedChild.func1", ".1", ".func13").
	if d.records >= 2 && inCallersContaining(".(*Wallet).persistReturnedChild.") {
		return nil, errAddressWrite
	}
	return d.DB.BeginReadWriteTx()
}

// failAbandonDB fails every abandon.
type failAbandonDB struct{ walletdb.DB }

func (d failAbandonDB) BeginReadWriteTx() (walletdb.ReadWriteTx, error) {
	if inCallers(".(*Wallet).AbandonTransaction") {
		return nil, errors.New("abandon write failed")
	}
	return d.DB.BeginReadWriteTx()
}

// logLines collects what the package logger writes.
type logLines struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logLines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logLines) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// inCallersContaining returns whether a function whose name contains s is on
// the calling goroutine's stack.
func inCallersContaining(s string) bool {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	for {
		f, more := frames.Next()
		if strings.Contains(f.Function, s) {
			return true
		}
		if !more {
			return false
		}
	}
}

// updateCalledBy returns whether the calling goroutine is in walletdb.Update
// called directly by a function whose name ends with suffix.
func updateCalledBy(suffix string) bool {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	for {
		f, more := frames.Next()
		if strings.HasSuffix(f.Function, "/walletdb.Update") {
			next, _ := frames.Next()
			return strings.HasSuffix(next.Function, suffix)
		}
		if !more {
			return false
		}
	}
}

// unminedSet returns the wallet's unmined txs by hash.
func unminedSet(ctx context.Context, t *testing.T, w *Wallet) map[chainhash.Hash]*wire.MsgTx {
	t.Helper()
	set := make(map[chainhash.Hash]*wire.MsgTx)
	err := walletdb.View(ctx, w.db, func(dbtx walletdb.ReadTx) error {
		recs, err := w.txStore.UnminedTxs(dbtx)
		for _, rec := range recs {
			set[rec.Hash] = &rec.MsgTx
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// TestPurchaseTicketsStopAbandonsUnpublished checks that a purchase that
// stops before publishing every ticket drops the tickets it recorded but did
// not publish, and reports only the published ones.  The stops are a ticket
// that fails to sign while it is recorded, one that gets no address, a
// ticket that fails to publish, and a request cancelled before a ticket is
// published.  The split and the tickets published before the stop stay.  A
// ticket whose abandon fails stays, and the failure is logged.
func TestPurchaseTicketsStopAbandonsUnpublished(t *testing.T) {
	for _, tc := range []struct {
		name      string
		stop      string // "record", "address", "publish" or "cancel", at the second ticket
		wantErr   error
		published int // tickets published before the stop
		// failAbandon makes every abandon fail: the unpublished tickets
		// stay, and each failure is logged.
		failAbandon bool
	}{
		{name: "second ticket not recorded", stop: "record", wantErr: errors.Locked},
		{name: "second ticket gets no address", stop: "address", wantErr: errAddressWrite},
		{name: "second ticket not published", stop: "publish", wantErr: errPublish, published: 1},
		{name: "cancelled before the second publish", stop: "cancel", wantErr: context.Canceled, published: 1},
		{name: "second ticket not published, abandon fails", stop: "publish", wantErr: errPublish, published: 1,
			failAbandon: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Errors the package logs; registered first, so the logger
			// is restored after the wallet is closed.
			errLog := &logLines{}
			logger := slog.NewBackend(errLog).Logger("WLLT")
			logger.SetLevel(slog.LevelError)
			prev := log
			UseLogger(logger)
			t.Cleanup(func() { UseLogger(prev) })

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := newPurchaseFixture(ctx, t)
			p.pastSVH(ctx, t)
			for range 3 {
				p.fund(ctx, t, true, 1e8)
			}
			p.setQuote(ctx, t)
			if tc.failAbandon {
				p.w.db = failAbandonDB{p.w.db}
			}
			if tc.stop == "address" {
				p.w.db = &failAddressDB{DB: p.w.db}
			}
			if tc.stop == "record" {
				// The split's record comes first, then one per ticket.
				p.w.db = &lockOnTicketRecordDB{DB: p.w.db, w: p.w, n: 3}
			}

			var published []*wire.MsgTx
			var tickets int
			n := failPublishNetwork{fail: func(tx *wire.MsgTx) bool {
				if !stake.IsSStx(tx) {
					published = append(published, tx)
					return false
				}
				tickets++
				if tickets == 2 && tc.stop == "publish" {
					return true
				}
				published = append(published, tx)
				if tickets == 1 && tc.stop == "cancel" {
					cancel()
				}
				return false
			}}
			p.w.SetNetworkBackend(n)

			resp, err := p.w.PurchaseTickets(ctx, n, &PurchaseTicketsRequest{
				Count:     3,
				MinConf:   0,
				VSPClient: p.c,
			})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("PurchaseTickets: %v; want %v", err, tc.wantErr)
			}
			// Every ticket not held is skipped without an error; each
			// failed abandon of a held one is logged.
			wantLogged := 0
			if tc.failAbandon {
				wantLogged = 2 // the second and third tickets
			}
			if n := strings.Count(errLog.String(), "Cannot abandon"); n != wantLogged {
				t.Errorf("%d abandon errors logged, want %d:\n%s", n, wantLogged, errLog)
			}
			var split *wire.MsgTx
			switch {
			case tc.stop == "address":
				// That stop returns no response.
				if resp != nil {
					t.Fatalf("PurchaseTickets: response %+v, want none", resp)
				}
				split = published[0]
			case resp == nil || resp.SplitTx == nil:
				t.Fatalf("PurchaseTickets: no split in %+v", resp)
			default:
				split = resp.SplitTx
			}

			publishedSet := make(map[chainhash.Hash]bool)
			var publishedTickets []chainhash.Hash
			for _, tx := range published {
				publishedSet[tx.TxHash()] = true
				if stake.IsSStx(tx) {
					publishedTickets = append(publishedTickets, tx.TxHash())
				}
			}
			if len(publishedTickets) != tc.published {
				t.Fatalf("%d tickets published, want %d", len(publishedTickets), tc.published)
			}
			unmined := unminedSet(ctx, t, p.w)
			if unmined[split.TxHash()] == nil {
				t.Error("the split is gone from the wallet")
			}
			var kept int
			for hash, tx := range unmined {
				if stake.IsSStx(tx) && !publishedSet[hash] {
					kept++
				}
			}
			if kept != wantLogged {
				t.Errorf("%d unpublished tickets stay in the wallet, want %d", kept, wantLogged)
			}
			for _, hash := range publishedTickets {
				if unmined[hash] == nil {
					t.Errorf("published ticket %v is gone from the wallet", hash)
				}
			}
			if resp == nil {
				return
			}
			if len(resp.TicketHashes) != tc.published || len(resp.Tickets) != tc.published {
				t.Fatalf("response lists %d hashes and %d tickets, want the %d published",
					len(resp.TicketHashes), len(resp.Tickets), tc.published)
			}
			for i, hash := range resp.TicketHashes {
				if *hash != publishedTickets[i] || resp.Tickets[i].TxHash() != publishedTickets[i] {
					t.Errorf("response ticket %d is %v, want the published %v", i, hash, publishedTickets[i])
				}
			}
		})
	}
}
