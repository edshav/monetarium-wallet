// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/decred/slog"
	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/gcs/blockcf2"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// vspLogLines collects what a logger writes.
type vspLogLines struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *vspLogLines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *vspLogLines) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// mineEmpty connects n empty blocks on top of the fixture's tip in one chain
// switch.
func (f *vspPaymentFixture) mineEmpty(ctx context.Context, t *testing.T, n int) {
	t.Helper()
	var nodes []*BlockNode
	for range n {
		header := wire.BlockHeader{
			PrevBlock: f.tip.BlockHash(),
			Height:    f.tip.Height + 1,
			Bits:      f.cfg.Params.PowLimitBits,
			SBits:     f.sbits,
			PoolSize:  f.poolSize,
			VoteBits:  1,
		}
		filter, err := blockcf2.Regular(&wire.MsgBlock{Header: header}, nil)
		if err != nil {
			t.Fatal(err)
		}
		hash := header.BlockHash()
		nodes = append(nodes, NewBlockNode(&header, &hash, filter))
		f.tip = header
	}
	if _, err := f.w.ChainSwitch(ctx, &f.forest, nodes, nil); err != nil {
		t.Fatal(err)
	}
}

// rescanBetweenReadsDB runs rescan when the pruned check opens a second view
// of the wallet, as a rescan that finishes between two separate reads would.
type rescanBetweenReadsDB struct {
	walletdb.DB
	views  int
	rescan func()
	fail   bool // fail every view the pruned check opens
}

func (d *rescanBetweenReadsDB) BeginReadTx() (walletdb.ReadTx, error) {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	for {
		f, more := frames.Next()
		if strings.Contains(f.Function, ".(*vspFeePayment).ticketGone") {
			if d.fail {
				return nil, errors.New("view fails")
			}
			d.views++
			if d.views == 2 && d.rescan != nil {
				rescan := d.rescan
				d.rescan = nil
				rescan()
			}
			break
		}
		if !more {
			break
		}
	}
	return d.DB.BeginReadTx()
}

// testLastScheduled returns the name in the last "Scheduling" line of logs.
func testLastScheduled(logs *vspLogLines) string {
	out := logs.String()
	i := strings.LastIndex(out, "Scheduling \"")
	if i < 0 {
		return ""
	}
	out = out[i+len("Scheduling \""):]
	return "Scheduling " + out[:strings.IndexByte(out, '"')]
}

// testJob returns the client's job for ticket.
func testJob(c *VSPClient, ticket *VSPTicket) *vspFeePayment {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.jobs[*ticket.Hash()]
}

// testHoldsUnmined reports whether the wallet holds hash as an unmined tx.
func testHoldsUnmined(ctx context.Context, t *testing.T, w *Wallet, hash chainhash.Hash) bool {
	t.Helper()
	var held bool
	err := walletdb.View(ctx, w.db, func(dbtx walletdb.ReadTx) error {
		recs, err := w.txStore.UnminedTxs(dbtx)
		for _, rec := range recs {
			held = held || rec.Hash == hash
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return held
}

// testFeeAddressReply is the fake VSP's fee quote for ticket.
func testFeeAddressReply(ticket *VSPTicket, body []byte) (int, any) {
	return http.StatusOK, types.FeeAddressResponse{
		Timestamp:  time.Now().Unix(),
		FeeAddress: ticket.votingAddr.String(),
		FeeAmount:  1e7,
		Expiration: time.Now().Add(time.Hour).Unix(),
		Request:    body,
	}
}

// testPaidFee returns the hash of the fee tx a payfee request carries.
func testPaidFee(body []byte) (chainhash.Hash, bool) {
	var req types.PayFeeRequest
	if json.Unmarshal(body, &req) != nil {
		return chainhash.Hash{}, false
	}
	raw, err := hex.DecodeString(req.FeeTx)
	tx := new(wire.MsgTx)
	if err != nil || tx.FromBytes(raw) != nil {
		return chainhash.Hash{}, false
	}
	return tx.TxHash(), true
}

// TestVSPPrunedTicketAbandonsFeeTx checks the fee tx of a ticket that leaves
// the wallet unmined.  The job's next attempt abandons it if it is unpublished,
// so its input is spendable again, however it is funded: by a separate output,
// by the split's fee output, or by the job from the wallet's outputs.  So is
// the job's own fee tx it still holds after a failed write of the VSP's, and
// its fee tx the VSP holds, which is abandoned once and not again.  A
// published fee tx is kept, and so is one another ticket's record names, and
// the fee tx of a ticket still in the wallet, expired or spent: only a ticket
// gone unmined is handled here.  The attempts that check the ticket first
// abandon it: a scheduled reconcile or confirm, and Process.  While a rescan
// point remains, as during catch-up, the ticket may have been mined in a block
// not recorded yet: the attempt waits, sends nothing to the VSP and keeps the
// job, the fee tx and the record, and only the own fee tx the VSP replaced is
// abandoned.  Otherwise the job is removed, and the ticket's VSP record stays.
func TestVSPPrunedTicketAbandonsFeeTx(t *testing.T) {
	for _, tc := range []struct {
		name    string
		funding string // "separate", "split" or "job"
		// ownKept leaves the job's fee tx in ownFeeHash: the VSP holds
		// another, and recording that one's hash failed.
		ownKept     bool
		vspNamesOwn bool // the VSP holds the job's fee tx
		published   bool
		otherTicket bool // another ticket's record names the fee tx
		// otherNamesOther adds a record of another ticket naming
		// another fee tx.
		otherNamesOther bool
		ticket          string // "pruned" (default), "kept", "expired" or "spent"
		// attempt is the job's next attempt: "reconcile" (default),
		// "confirm", or "process", a Process call while the record
		// reads started.
		attempt string
		// catchUp leaves a rescan point after the prune: "headers", a
		// block connected without its txs; "unreadable", a marker
		// naming an unknown block; "rescan between reads", a rescan
		// that records the ticket as mined as soon as a second view of
		// the wallet opens in the pruned check; "view fails", the
		// pruned check's view of the wallet fails to open.
		catchUp     string
		wantUnspent bool
		// wantSkips counts the hashes abandonFeeTx declines: one the
		// wallet does not hold, or one it published.
		wantSkips int
	}{
		{name: "separate output", funding: "separate", wantUnspent: true},
		{name: "separate output, confirm attempt", funding: "separate", attempt: "confirm", wantUnspent: true},
		{name: "separate output, Process", funding: "separate", attempt: "process", wantUnspent: true},
		{name: "split's fee output", funding: "split", wantUnspent: true},
		{name: "made by the job", funding: "job", wantUnspent: true},
		{name: "job's own fee tx after a failed write", funding: "separate", ownKept: true, wantUnspent: true,
			wantSkips: 1},
		{name: "VSP holds the job's fee tx", funding: "separate", ownKept: true, vspNamesOwn: true,
			wantUnspent: true},
		{name: "fee tx published", funding: "separate", published: true, wantSkips: 1},
		{name: "another ticket names the fee tx", funding: "separate", otherTicket: true, wantSkips: 1},
		{name: "another ticket names another fee tx", funding: "separate", otherNamesOther: true, wantUnspent: true},
		{name: "separate output during catch-up", funding: "separate", catchUp: "headers"},
		{name: "separate output, confirm attempt during catch-up", funding: "separate", attempt: "confirm",
			catchUp: "headers"},
		{name: "separate output, Process during catch-up", funding: "separate", attempt: "process",
			catchUp: "headers"},
		{name: "job's own fee tx after a failed write, during catch-up", funding: "separate", ownKept: true,
			catchUp: "headers", wantUnspent: true},
		{name: "VSP holds the job's fee tx, during catch-up", funding: "separate", ownKept: true, vspNamesOwn: true,
			catchUp: "headers"},
		{name: "rescan point unreadable", funding: "separate", catchUp: "unreadable"},
		{name: "pruned check's view fails", funding: "separate", catchUp: "view fails"},
		{name: "rescan records the ticket between reads", funding: "separate", catchUp: "rescan between reads"},
		{name: "ticket still in the wallet", funding: "separate", ticket: "kept"},
		{name: "ticket expired", funding: "separate", ticket: "expired"},
		{name: "ticket spent", funding: "separate", ticket: "spent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var ticket *VSPTicket
			vspHash := chainhash.Hash{0xfe}
			var requests atomic.Int32
			c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				requests.Add(1)
				// failVSPWrites lengthens the URL's path.
				switch path[strings.Index(path, "/api/v3/"):] {
				case "/api/v3/feeaddress":
					if tc.ownKept {
						return apiError(types.ErrFeeAlreadyReceived)
					}
					return testFeeAddressReply(ticket, body)
				case "/api/v3/payfee":
					return http.StatusOK, types.PayFeeResponse{Request: body}
				case "/api/v3/ticketstatus":
					return http.StatusOK, types.TicketStatusResponse{
						FeeTxStatus: "received",
						FeeTxHash:   vspHash.String(),
						Request:     body,
					}
				}
				return apiError(types.ErrInternalError)
			})
			w := c.wallet
			skips := &vspLogLines{}
			c.log = slog.NewBackend(skips).Logger("VSP")
			c.log.SetLevel(slog.LevelDebug)

			// op is the output the fee tx spends.
			var op *wire.OutPoint
			if tc.funding == "split" {
				addr, err := w.NewInternalAddress(ctx, 0)
				if err != nil {
					t.Fatal(err)
				}
				ver, script := addr.(Address).PaymentScript()
				split := wire.NewMsgTx()
				split.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{0x02}}, 2e8, nil))
				split.AddTxOut(&wire.TxOut{Value: 1e8, Version: ver, PkScript: script})
				split.AddTxOut(&wire.TxOut{Value: 1e8, Version: ver, PkScript: script})
				if err := w.AddTransaction(ctx, split, nil); err != nil {
					t.Fatal(err)
				}
				splitHash := split.TxHash()
				ticket = testVSPTicketSpending(ctx, t, c, wire.OutPoint{Hash: splitHash})
				op = &wire.OutPoint{Hash: splitHash, Index: 1}
			} else if tc.funding == "job" {
				// Coin selection takes only mined outputs.
				f := &vspPaymentFixture{w: w, cfg: basicWalletConfig,
					tip: basicWalletConfig.Params.GenesisBlock.Header}
				op = &wire.OutPoint{Hash: f.fund(ctx, t, true, 1e8).TxHash()}
				ticket = testVSPTicket(ctx, t, c, 1)
			} else {
				op = testWalletOutput(ctx, t, w, 2)
				ticket = testVSPTicket(ctx, t, c, 1)
			}
			before := testSpendable(ctx, t, w)

			var fp *vspFeePayment
			var feeHash chainhash.Hash
			switch {
			case tc.funding == "job":
				// The job funds the fee tx from op, the only output.
				if err := c.Process(ctx, ticket, nil); err != nil {
					t.Fatal(err)
				}
				fp = testJob(c, ticket)
				if fp == nil {
					t.Fatal("Process left no job")
				}
				fp.stop()
				feeHash = fp.feeHash
			default:
				fee := wire.NewMsgTx()
				fee.AddTxIn(wire.NewTxIn(op, 1e8, nil))
				if err := w.CreateVspPayment(ctx, fee, 1e7, ticket.votingAddr, 0, 0); err != nil {
					t.Fatal(err)
				}
				feeHash = fee.TxHash()
				// Process takes a paid record under another URL for
				// another VSP's.
				record := ticket.UpdateFeePaid
				if tc.ownKept || tc.attempt == "process" {
					record = ticket.UpdateFeeStarted
				}
				if err := record(ctx, feeHash, c.URL, c.PubKey); err != nil {
					t.Fatal(err)
				}
				if tc.vspNamesOwn {
					vspHash = feeHash
					if err := c.Process(ctx, ticket, nil); err != nil {
						t.Fatal(err)
					}
					fp = testJob(c, ticket)
				} else if tc.ownKept {
					// The VSP names another fee tx, which the wallet
					// cannot record.
					url := c.URL
					failVSPWrites(c)
					if err := c.Process(ctx, ticket, nil); err == nil {
						t.Fatal("Process: want the failed write's error")
					}
					c.URL = url
					fp = testJob(c, ticket)
				} else {
					// The job a restart makes from the record.
					fp = c.feePayment(ctx, ticket, true)
				}
				if fp == nil {
					t.Fatal("no job for the ticket")
				}
				fp.stop()
			}
			if !testHoldsUnmined(ctx, t, w, feeHash) {
				t.Fatal("no fee tx")
			}
			if tc.published {
				if err := w.SetPublished(ctx, &feeHash, true); err != nil {
					t.Fatal(err)
				}
			}
			if tc.otherTicket {
				other := testVSPTicket(ctx, t, c, 3)
				if err := other.UpdateFeeStarted(ctx, feeHash, c.URL, c.PubKey); err != nil {
					t.Fatal(err)
				}
				// Records naming another fee tx first and last in key
				// order, so the naming one is neither, whatever the
				// tickets' hashes.
				err := walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
					first := chainhash.Hash{31: 0x01}
					last := chainhash.Hash{}
					for i := range last {
						last[i] = 0xff
					}
					for _, h := range []chainhash.Hash{first, last} {
						rec := &udb.VSPTicket{FeeHash: chainhash.Hash{0x77}, Host: c.URL, PubKey: c.PubKey}
						if err := udb.SetVSPTicket(dbtx, &h, rec); err != nil {
							return err
						}
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			if tc.otherNamesOther {
				other := testVSPTicket(ctx, t, c, 3)
				if err := other.UpdateFeeStarted(ctx, chainhash.Hash{0x77}, c.URL, c.PubKey); err != nil {
					t.Fatal(err)
				}
			}

			switch tc.ticket {
			case "", "pruned":
				if err := w.AbandonTransaction(ctx, ticket.Hash()); err != nil {
					t.Fatal(err)
				}
				f := &vspPaymentFixture{w: w, cfg: basicWalletConfig,
					tip: basicWalletConfig.Params.GenesisBlock.Header}
				switch tc.catchUp {
				case "headers", "rescan between reads":
					f.mineEmpty(ctx, t, 1)
				case "unreadable":
					// The store's marker key, written directly: its
					// setter refuses a block it does not know.
					err := walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
						unknown := chainhash.Hash{0xbb}
						return dbtx.ReadWriteBucket(wtxmgrNamespaceKey).Put([]byte("lasttxsblock"), unknown[:])
					})
					if err != nil {
						t.Fatal(err)
					}
				}
				if tc.catchUp == "view fails" {
					d := &rescanBetweenReadsDB{DB: w.db, fail: true}
					w.db = d
					t.Cleanup(func() { w.db = d.DB })
				}
				if tc.catchUp == "rescan between reads" {
					d := &rescanBetweenReadsDB{DB: w.db}
					d.rescan = func() {
						f.mine(ctx, t, ticket.rawTx)
						err := walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
							tip, _ := w.txStore.MainChainTip(dbtx)
							return w.txStore.UpdateProcessedTxsBlockMarker(dbtx, &tip)
						})
						if err != nil {
							t.Error(err)
						}
					}
					w.db = d
					t.Cleanup(func() { w.db = d.DB })
				}

			case "expired":
				f := &vspPaymentFixture{w: w, cfg: basicWalletConfig,
					tip: basicWalletConfig.Params.GenesisBlock.Header}
				// A ticket mined below height 2 counts as unmined.
				f.mineEmpty(ctx, t, 1)
				f.mine(ctx, t, ticket.rawTx)
				p := w.chainParams
				f.mineEmpty(ctx, t, int(p.TicketMaturity)+int(p.TicketExpiry)+1)
				if !ticket.Expired(ctx) || ticket.Pruned(ctx) {
					t.Fatal("the ticket is not expired")
				}
				// As after the rescan of those blocks.
				err := walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
					tip, _ := w.txStore.MainChainTip(dbtx)
					return w.txStore.UpdateProcessedTxsBlockMarker(dbtx, &tip)
				})
				if err != nil {
					t.Fatal(err)
				}
			case "spent":
				// Mined, then spent by an unmined tx.
				f := &vspPaymentFixture{w: w, cfg: basicWalletConfig,
					tip: basicWalletConfig.Params.GenesisBlock.Header}
				f.mine(ctx, t, ticket.rawTx)
				spender := wire.NewMsgTx()
				spender.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: *ticket.Hash(), Tree: wire.TxTreeStake}, 1e8, nil))
				spender.AddTxOut(&wire.TxOut{Value: 1e8, PkScript: []byte{0x51}})
				err := walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
					rec, err := udb.NewTxRecordFromMsgTx(spender, time.Now())
					if err != nil {
						return err
					}
					return w.txStore.InsertMemPoolTx(dbtx, rec)
				})
				if err != nil {
					t.Fatal(err)
				}
			}

			// The job's next attempt.
			recBefore, err := ticket.VSPTicketInfo(ctx)
			if err != nil {
				t.Fatal(err)
			}
			skipsBefore := strings.Count(skips.String(), "not abandoning")
			requestsBefore := requests.Load()
			fp.mu.Lock()
			ownBefore, feeBefore := fp.ownFeeHash, fp.feeHash
			fp.mu.Unlock()
			if tc.attempt == "process" {
				err = c.Process(ctx, ticket, nil)
			} else {
				next := fp.reconcilePayment
				if tc.attempt == "confirm" {
					next = fp.confirmPayment
				}
				fp.procMu.Lock()
				err = next()
				fp.procMu.Unlock()
			}
			// A view that fails leaves the job as if the ticket were there.
			goesOn := tc.ticket == "kept" || tc.catchUp == "view fails"
			delayed := tc.ticket == "" && tc.catchUp != "" && tc.catchUp != "view fails"
			if delayed {
				// The replaced own fee tx is abandoned once; one the VSP
				// holds stays the job's.
				fp.mu.Lock()
				own := fp.ownFeeHash
				fp.mu.Unlock()
				want := chainhash.Hash{}
				if ownBefore == feeBefore {
					want = ownBefore
				}
				if own != want {
					t.Fatalf("job keeps own fee tx %v, want %v", own, want)
				}
				next := "reconcile payment"
				if tc.attempt == "confirm" {
					next = "confirm payment"
				}
				if !timerSet(fp) || !strings.HasSuffix(testLastScheduled(skips), next) {
					t.Fatalf("scheduled %q, timer set %v; want %q", testLastScheduled(skips), timerSet(fp), next)
				}
				if n := requests.Load() - requestsBefore; n != 0 {
					t.Fatalf("%d VSP requests while the wallet catches up", n)
				}
			}
			fp.stop()
			if stopped := !goesOn && !delayed; stopped != errors.Is(err, errStopped) {
				t.Fatalf("attempt: %v; want errStopped %v", err, stopped)
			}
			if delayed != errors.Is(err, errCatchingUp) {
				t.Fatalf("attempt: %v; want errCatchingUp %v", err, delayed)
			}
			if listed := testJob(c, ticket) != nil; listed != (goesOn || delayed) {
				t.Fatalf("job listed = %v after the attempt", listed)
			}

			if n := strings.Count(skips.String(), "not abandoning") - skipsBefore; n != tc.wantSkips {
				t.Errorf("%d fee txs not abandoned, want %d:\n%s", n, tc.wantSkips, skips)
			}
			if unspent := testUnspentOutputs(ctx, t, w)[*op]; unspent != tc.wantUnspent {
				t.Fatalf("fee tx input unspent = %v, want %v", unspent, tc.wantUnspent)
			}
			if held := testHoldsUnmined(ctx, t, w, feeHash); held == tc.wantUnspent {
				t.Fatalf("wallet holds the fee tx = %v, want %v", held, !tc.wantUnspent)
			}
			// The split's ticket output comes back too.
			if after := testSpendable(ctx, t, w); tc.wantUnspent && tc.funding != "split" && after != before {
				t.Fatalf("spendable balance %v after the abandon, want %v as before the fee tx", after, before)
			}
			rec, err := ticket.VSPTicketInfo(ctx)
			if err != nil {
				t.Fatalf("the ticket's VSP record: %v", err)
			}
			// The record still names the fee tx, for the attempt after the
			// rescan.  Process marks it errored without a fee hash, as on
			// main, once the ticket is found gone.
			if tc.ticket == "" && tc.catchUp != "view fails" {
				want := recBefore.FeeHash
				if tc.attempt == "process" && !delayed {
					want = chainhash.Hash{}
				}
				if rec.FeeHash != want {
					t.Fatalf("record names %v, want %v", rec.FeeHash, want)
				}
			}
		})
	}
}

// TestVSPTicketPrunedMidAttemptAbandonsFeeTx checks a ticket pruned while an
// attempt waits for the VSP's fee quote: the attempt makes the fee tx, and
// submitPayment's check stops it before paying, through Process and through a
// scheduled reconcile.  The fee tx is abandoned and the job removed, or, while a
// rescan point remains, both are kept and the record still names the fee tx.
func TestVSPTicketPrunedMidAttemptAbandonsFeeTx(t *testing.T) {
	for _, tc := range []struct {
		via     string
		catchUp bool
	}{
		{via: "Process"},
		{via: "reconcile"},
		{via: "Process", catchUp: true},
		{via: "reconcile", catchUp: true},
	} {
		via := tc.via
		name := via
		if tc.catchUp {
			name += " during catch-up"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			var ticket *VSPTicket
			var c *VSPClient
			var f *vspPaymentFixture
			var payfee atomic.Bool
			c = testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				switch path {
				case "/api/v3/feeaddress":
					if err := c.wallet.AbandonTransaction(ctx, ticket.Hash()); err != nil {
						t.Error(err)
					}
					if tc.catchUp {
						// A block connected without its txs.
						f.mineEmpty(ctx, t, 1)
					}
					return testFeeAddressReply(ticket, body)
				case "/api/v3/payfee":
					payfee.Store(true)
					return http.StatusOK, types.PayFeeResponse{Request: body}
				}
				return apiError(types.ErrInternalError)
			})
			w := c.wallet
			logs := &vspLogLines{}
			c.log = slog.NewBackend(logs).Logger("VSP")
			c.log.SetLevel(slog.LevelDebug)
			// Coin selection takes only mined outputs.
			f = &vspPaymentFixture{w: w, cfg: basicWalletConfig,
				tip: basicWalletConfig.Params.GenesisBlock.Header}
			op := wire.OutPoint{Hash: f.fund(ctx, t, true, 1e8).TxHash()}
			ticket = testVSPTicket(ctx, t, c, 1)

			var err error
			if via == "Process" {
				err = c.Process(ctx, ticket, nil)
			} else {
				fp := c.feePayment(ctx, ticket, false)
				fp.stop()
				fp.procMu.Lock()
				err = fp.reconcilePayment()
				fp.procMu.Unlock()
			}
			want := errStopped
			if tc.catchUp {
				want = errCatchingUp
			}
			if !errors.Is(err, want) {
				t.Fatalf("attempt: %v; want %v", err, want)
			}
			// While the wallet catches up the job waits for the rescan.
			fp := testJob(c, ticket)
			if (fp != nil) != tc.catchUp {
				t.Fatalf("job listed = %v", fp != nil)
			}
			var retry func() error
			if fp != nil {
				if got := testLastScheduled(logs); got != "Scheduling reconcile payment" || !timerSet(fp) {
					t.Fatalf("%q, timer set %v; want the reconcile scheduled", got, timerSet(fp))
				}
				retry = testTakeScheduled(t, fp)
			}
			info, err := ticket.VSPTicketInfo(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if tc.catchUp && info.FeeHash == (chainhash.Hash{}) {
				t.Fatal("the record names no fee tx")
			}
			held := testHoldsUnmined(ctx, t, w, info.FeeHash)
			if payfee.Load() || held != tc.catchUp || testUnspentOutputs(ctx, t, w)[op] == tc.catchUp {
				t.Fatalf("paid %v; wallet holds the fee tx %v; want no payment, and the fee tx held = %v",
					payfee.Load(), held, tc.catchUp)
			}

			if !tc.catchUp {
				return
			}
			// The rescan records the ticket as mined; the scheduled
			// reconcile pays the fee tx the attempt made.
			f.mine(ctx, t, ticket.rawTx)
			err = walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
				tip, _ := w.txStore.MainChainTip(dbtx)
				return w.txStore.UpdateProcessedTxsBlockMarker(dbtx, &tip)
			})
			if err != nil {
				t.Fatal(err)
			}
			err = retry()
			// Paid: the job goes on to confirm the fee.
			if got := testLastScheduled(logs); got != "Scheduling confirm payment" || !timerSet(fp) {
				t.Errorf("after paying: %q, timer set %v; want the confirm scheduled", got, timerSet(fp))
			}
			fp.stop()
			after, infoErr := ticket.VSPTicketInfo(ctx)
			if infoErr != nil {
				t.Fatal(infoErr)
			}
			if !payfee.Load() || after.FeeHash != info.FeeHash ||
				after.FeeTxStatus != uint32(udb.VSPFeeProcessPaid) {
				t.Fatalf("after the rescan: %v; paid %v, record %+v, want paid with %v",
					err, payfee.Load(), after, info.FeeHash)
			}
		})
	}
}

// TestVSPPrunedTicketResumesPayment checks that once a pruned ticket is mined
// after all, a Process call and the attempt it schedules resume its payment
// after the abandon: they record a fee the VSP holds and leave it to the VSP,
// and make a new fee tx when the VSP's fee errored or it never got the fee,
// even with the record paid.
func TestVSPPrunedTicketResumesPayment(t *testing.T) {
	for _, tc := range []struct {
		name      string
		paid      bool   // the record says paid, not started
		vspStatus string // the VSP's FeeTxStatus
		wantNew   bool   // a new fee tx is made and paid
	}{
		{name: "VSP holds the fee", paid: true, vspStatus: "received"},
		{name: "VSP's fee errored", paid: true, vspStatus: "error", wantNew: true},
		// makeFeeTx records the fee paid before payfee.
		{name: "payfee never reached the VSP", paid: true, vspStatus: "none", wantNew: true},
		{name: "fee never paid", vspStatus: "none", wantNew: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var ticket *VSPTicket
			var ownHash chainhash.Hash
			var paid atomic.Value // chainhash.Hash
			c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				switch path {
				case "/api/v3/feeaddress":
					if tc.vspStatus == "received" {
						return apiError(types.ErrFeeAlreadyReceived)
					}
					return testFeeAddressReply(ticket, body)
				case "/api/v3/payfee":
					hash, ok := testPaidFee(body)
					if !ok {
						return apiError(types.ErrBadRequest)
					}
					paid.Store(hash)
					return http.StatusOK, types.PayFeeResponse{Request: body}
				case "/api/v3/ticketstatus":
					return http.StatusOK, types.TicketStatusResponse{
						FeeTxStatus: tc.vspStatus,
						FeeTxHash:   ownHash.String(),
						Request:     body,
					}
				}
				return apiError(types.ErrInternalError)
			})
			w := c.wallet
			// Coin selection for the new fee tx takes only mined outputs.
			f := &vspPaymentFixture{w: w, cfg: basicWalletConfig,
				tip: basicWalletConfig.Params.GenesisBlock.Header}
			op := &wire.OutPoint{Hash: f.fund(ctx, t, true, 1e8).TxHash()}
			ticket = testVSPTicket(ctx, t, c, 1)
			fee := wire.NewMsgTx()
			fee.AddTxIn(wire.NewTxIn(op, 1e8, nil))
			if err := w.CreateVspPayment(ctx, fee, 1e7, ticket.votingAddr, 0, 0); err != nil {
				t.Fatal(err)
			}
			ownHash = fee.TxHash()
			record := ticket.UpdateFeeStarted
			if tc.paid {
				record = ticket.UpdateFeePaid
			}
			if err := record(ctx, ownHash, c.URL, c.PubKey); err != nil {
				t.Fatal(err)
			}

			// Pruned, and the job's attempt abandons the fee tx.
			fp := c.feePayment(ctx, ticket, tc.paid)
			fp.stop()
			if err := w.AbandonTransaction(ctx, ticket.Hash()); err != nil {
				t.Fatal(err)
			}
			fp.procMu.Lock()
			err := fp.reconcilePayment()
			fp.procMu.Unlock()
			if !errors.Is(err, errStopped) || testHoldsUnmined(ctx, t, w, ownHash) {
				t.Fatalf("reconcilePayment: %v; the fee tx is not abandoned", err)
			}

			// The ticket is mined after all.
			f.mine(ctx, t, ticket.rawTx)
			if ticket.Pruned(ctx) {
				t.Fatal("the mined ticket is not in the wallet")
			}
			if err := c.Process(ctx, ticket, nil); err != nil {
				t.Fatal(err)
			}
			// Process leaves an attempt scheduled; run it now.
			fp = testJob(c, ticket)
			if fp == nil || !timerSet(fp) {
				t.Fatal("Process left no attempt scheduled")
			}
			fp.stop()
			// confirmPayment schedules itself while the VSP holds the
			// fee, and leaves the job's first reconcile otherwise.
			next := fp.reconcilePayment
			if tc.vspStatus == "received" {
				next = fp.confirmPayment
			}
			fp.procMu.Lock()
			err = next()
			fp.procMu.Unlock()
			fp.stop()
			if err != nil {
				t.Fatal(err)
			}

			info, err := ticket.VSPTicketInfo(ctx)
			if err != nil {
				t.Fatal(err)
			}
			newHash, _ := paid.Load().(chainhash.Hash)
			if !tc.wantNew {
				if newHash != (chainhash.Hash{}) || info.FeeHash != ownHash {
					t.Fatalf("paid %v, record names %v; want no new fee tx and the VSP's %v",
						newHash, info.FeeHash, ownHash)
				}
				return
			}
			if newHash == (chainhash.Hash{}) || newHash == ownHash {
				t.Fatalf("paid fee tx %v, want a new one", newHash)
			}
			if info.FeeHash != newHash || !testHoldsUnmined(ctx, t, w, newHash) {
				t.Fatalf("record names %v, wallet holds the new %v: %v",
					info.FeeHash, newHash, testHoldsUnmined(ctx, t, w, newHash))
			}
		})
	}
}
