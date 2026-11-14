// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/decred/vspd/types/v3"
	"github.com/monetarium/monetarium-node/chaincfg/chainhash"
	"github.com/monetarium/monetarium-node/cointype"
	"github.com/monetarium/monetarium-node/wire"
	"github.com/monetarium/monetarium-wallet/wallet/udb"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// TestVSPFeeAlreadyReceivedRecordsFee checks that when the VSP answers a fee
// address request saying it already holds the ticket's fee, the wallet records
// the VSP's fee tx as paid, and as confirmed once the VSP reports it so, both
// when processing a ticket and when a fee payment job retries.  A ticket
// purchase's fee tx passed to Process is left unused and its input unlocked.
func TestVSPFeeAlreadyReceivedRecordsFee(t *testing.T) {
	paths := []struct {
		name     string
		purchase bool // a ticket purchase's fee tx goes to Process
		run      func(ctx context.Context, c *VSPClient, ticket *VSPTicket, feeTx *wire.MsgTx, reserved []Input) error
	}{{
		name:     "Process",
		purchase: true,
		run: func(ctx context.Context, c *VSPClient, ticket *VSPTicket, feeTx *wire.MsgTx, reserved []Input) error {
			return c.wallet.payPurchaseFee(ctx, c, ticket, feeTx, reserved)
		},
	}, {
		name: "reconcilePayment",
		run: func(ctx context.Context, c *VSPClient, ticket *VSPTicket, _ *wire.MsgTx, _ []Input) error {
			return c.jobs[*ticket.Hash()].reconcilePayment()
		},
	}}
	statuses := []struct {
		vspStatus string
		want      udb.FeeStatus
	}{
		{"received", udb.VSPFeeProcessPaid},
		{"confirmed", udb.VSPFeeProcessConfirmed},
	}
	for _, path := range paths {
		for _, st := range statuses {
			t.Run(path.name+"/"+st.vspStatus, func(t *testing.T) {
				ctx := context.Background()
				vspFeeHash := chainhash.Hash{0xfe}
				c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
					switch path {
					case "/api/v3/feeaddress":
						return apiError(types.ErrFeeAlreadyReceived)
					case "/api/v3/ticketstatus":
						return http.StatusOK, types.TicketStatusResponse{
							FeeTxStatus: st.vspStatus,
							FeeTxHash:   vspFeeHash.String(),
							Request:     body,
						}
					}
					return apiError(types.ErrInternalError)
				})
				ticket := testVSPTicket(ctx, t, c, 1)
				// A job of its own keeps feePayment from scheduling a
				// concurrent attempt.
				fp := &vspFeePayment{
					client: c,
					ctx:    ctx,
					ticket: ticket,
					policy: c.policy,
					params: c.wallet.chainParams,
				}
				c.jobs[*ticket.Hash()] = fp
				var purchaseTx *wire.MsgTx
				var reserved []Input
				if path.purchase {
					purchaseTx, reserved = testPurchaseFeeTx(c.wallet)
				}

				if err := path.run(ctx, c, ticket, purchaseTx, reserved); err != nil {
					t.Fatal(err)
				}
				if path.purchase {
					checkPurchaseFeeTxUnused(t, fp, purchaseTx, reserved)
				}
				info, err := ticket.VSPTicketInfo(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if got := udb.FeeStatus(info.FeeTxStatus); got != st.want {
					t.Fatalf("fee status %v, want %v", got, st.want)
				}
				if info.FeeHash != vspFeeHash {
					t.Fatalf("fee hash %v, want the VSP's %v", info.FeeHash, vspFeeHash)
				}
			})
		}
	}
}

// TestVSPFeeAlreadyReceivedStatusFails checks that when the VSP says it holds
// the fee but cannot report it, or reports no fee tx, nothing is recorded as
// paid, the retry asks the VSP for the fee again instead of paying the quote
// the job already holds, and does not build on the ticket purchase's fee tx,
// whose input the purchase unlocks.
func TestVSPFeeAlreadyReceivedStatusFails(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status func(body []byte) (int, any)
	}{{
		name: "status error",
		status: func([]byte) (int, any) {
			return apiError(types.ErrInternalError)
		},
	}, {
		name: "no fee tx hash",
		status: func(body []byte) (int, any) {
			return http.StatusOK, types.TicketStatusResponse{
				FeeTxStatus: "received",
				Request:     body,
			}
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				switch path {
				case "/api/v3/feeaddress":
					return apiError(types.ErrFeeAlreadyReceived)
				case "/api/v3/ticketstatus":
					return tc.status(body)
				}
				return apiError(types.ErrInternalError)
			})
			ticket := testVSPTicket(ctx, t, c, 1)
			fp := &vspFeePayment{
				client:  c,
				ctx:     ctx,
				ticket:  ticket,
				policy:  c.policy,
				params:  c.wallet.chainParams,
				fee:     1e7,
				feeAddr: ticket.votingAddr,
			}
			c.jobs[*ticket.Hash()] = fp
			purchaseTx, reserved := testPurchaseFeeTx(c.wallet)

			if err := c.wallet.payPurchaseFee(ctx, c, ticket, purchaseTx, reserved); err == nil {
				t.Fatal("Process: want an error")
			}
			checkPurchaseFeeTxUnused(t, fp, purchaseTx, reserved)
			fp.timerMu.Lock()
			retry := fp.timer != nil
			fp.timerMu.Unlock()
			fp.mu.Lock()
			fee, feeTx := fp.fee, fp.feeTx
			fp.mu.Unlock()
			if !retry || fee != 0 || feeTx != nil {
				t.Fatalf("retry scheduled = %v, fee = %v, fee tx kept = %v; "+
					"want a retry that asks for the fee again", retry, fee, feeTx != nil)
			}
			info, err := ticket.VSPTicketInfo(ctx)
			if err == nil && udb.FeeStatus(info.FeeTxStatus) == udb.VSPFeeProcessPaid {
				t.Fatalf("ticket recorded as paid with hash %v", info.FeeHash)
			}
		})
	}
}

// testPurchaseFeeTx returns a fee tx as a ticket purchase offers it: one input,
// locked in the wallet for the fee, and no outputs.
func testPurchaseFeeTx(w *Wallet) (*wire.MsgTx, []Input) {
	op := wire.OutPoint{Hash: chainhash.Hash{0xca}}
	w.LockOutpoint(&op.Hash, op.Index)
	tx := wire.NewMsgTx()
	tx.AddTxIn(wire.NewTxIn(&op, 1e8, nil))
	return tx, []Input{{OutPoint: op}}
}

// checkPurchaseFeeTxUnused checks that Process left a ticket purchase's fee tx
// unused: the job does not hold it, it has no outputs, and its input is
// unlocked.
func checkPurchaseFeeTxUnused(t *testing.T, fp *vspFeePayment, feeTx *wire.MsgTx, reserved []Input) {
	t.Helper()
	fp.mu.Lock()
	held := fp.feeTx == feeTx
	fp.mu.Unlock()
	if held || len(feeTx.TxOut) != 0 {
		t.Fatalf("job holds the purchase's fee tx = %v, its outputs = %d; want neither",
			held, len(feeTx.TxOut))
	}
	w := fp.client.wallet
	if op := reserved[0].OutPoint; w.LockedOutpoint(&op.Hash, op.Index) {
		t.Fatal("the purchase's reserved input stays locked")
	}
}

// TestVSPProcessPaidKeepsVSPFeeHash checks that confirming a paid ticket whose
// fee tx the wallet does not hold keeps the recorded fee hash.
func TestVSPProcessPaidKeepsVSPFeeHash(t *testing.T) {
	ctx := context.Background()
	vspFeeHash := chainhash.Hash{0xfe}
	c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
		if path != "/api/v3/ticketstatus" {
			return apiError(types.ErrInternalError)
		}
		return http.StatusOK, types.TicketStatusResponse{
			FeeTxStatus: "confirmed",
			FeeTxHash:   vspFeeHash.String(),
			Request:     body,
		}
	})
	ticket := testVSPTicket(ctx, t, c, 1)
	err := ticket.UpdateFeePaid(ctx, vspFeeHash, c.Client.URL, c.Client.PubKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Process(ctx, ticket, nil); err != nil {
		t.Fatal(err)
	}
	info, err := ticket.VSPTicketInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if udb.FeeStatus(info.FeeTxStatus) != udb.VSPFeeProcessConfirmed || info.FeeHash != vspFeeHash {
		t.Fatalf("fee status %v, hash %v; want confirmed, %v",
			udb.FeeStatus(info.FeeTxStatus), info.FeeHash, vspFeeHash)
	}
}

// TestVSPPurchaseFeeUnlocksUnusedInputs checks the inputs a ticket purchase
// reserved for the fee once Process pays it: when Process pays the fee tx a
// scheduled attempt made from other inputs, the reserved inputs are unlocked
// and still unspent; when it pays with them, they are spent.  A paid fee tx
// that spends them but is not recorded in the wallet keeps them locked.
func TestVSPPurchaseFeeUnlocksUnusedInputs(t *testing.T) {
	for _, tc := range []struct {
		name         string
		attemptFeeTx bool // a scheduled attempt made a fee tx first
		// unrecorded: a scheduled attempt finished the purchase's fee
		// tx in place but failed to record it.
		unrecorded  bool
		wantUnspent bool
		wantLocked  bool
	}{
		{name: "scheduled attempt's fee tx", attemptFeeTx: true, wantUnspent: true},
		{name: "purchase's fee tx"},
		{name: "unrecorded purchase's fee tx", unrecorded: true, wantUnspent: true, wantLocked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var ticket *VSPTicket
			c := testVSPClient(ctx, t, func(path string, body []byte) (int, any) {
				switch path {
				case "/api/v3/feeaddress":
					return http.StatusOK, types.FeeAddressResponse{
						Timestamp:  time.Now().Unix(),
						FeeAddress: ticket.votingAddr.String(),
						FeeAmount:  1e7,
						Expiration: time.Now().Add(time.Hour).Unix(),
						Request:    body,
					}
				case "/api/v3/payfee":
					return http.StatusOK, types.PayFeeResponse{
						Timestamp: time.Now().Unix(),
						Request:   body,
					}
				}
				return apiError(types.ErrInternalError)
			})
			w := c.wallet
			ticket = testVSPTicket(ctx, t, c, 1)
			fp := &vspFeePayment{
				client: c,
				ctx:    ctx,
				ticket: ticket,
				policy: c.policy,
				params: w.chainParams,
			}
			c.jobs[*ticket.Hash()] = fp // stopped on cleanup
			if tc.attemptFeeTx {
				attemptTx := wire.NewMsgTx()
				attemptTx.AddTxIn(wire.NewTxIn(testWalletOutput(ctx, t, w, 2), 1e8, nil))
				err := w.CreateVspPayment(ctx, attemptTx, 1e7, ticket.votingAddr, 0, 0)
				if err != nil {
					t.Fatal(err)
				}
				fp.feeTx = attemptTx
				fp.feeHash = attemptTx.TxHash()
			}
			reservedOp := testWalletOutput(ctx, t, w, 3)
			w.LockOutpoint(&reservedOp.Hash, reservedOp.Index)
			reserved := []Input{{OutPoint: *reservedOp}}
			purchaseTx := wire.NewMsgTx()
			purchaseTx.AddTxIn(wire.NewTxIn(reservedOp, 1e8, nil))
			if tc.unrecorded {
				purchaseTx.AddTxOut(wire.NewTxOut(1e7, []byte{0x51}))
				fp.feeTx = purchaseTx
				fp.feeHash = purchaseTx.TxHash()
			}

			if err := w.payPurchaseFee(ctx, c, ticket, purchaseTx, reserved); err != nil {
				t.Fatal(err)
			}
			unspent := testUnspentOutputs(ctx, t, w)[*reservedOp]
			locked := w.LockedOutpoint(&reservedOp.Hash, reservedOp.Index)
			if unspent != tc.wantUnspent || locked != tc.wantLocked {
				t.Fatalf("reserved input unspent = %v, locked = %v; want %v, %v",
					unspent, locked, tc.wantUnspent, tc.wantLocked)
			}
		})
	}
}

// testUnspentOutputs returns the wallet's spendable VAR outputs at minconf 0.
func testUnspentOutputs(ctx context.Context, t *testing.T, w *Wallet) map[wire.OutPoint]bool {
	t.Helper()
	unspent := make(map[wire.OutPoint]bool)
	err := walletdb.View(ctx, w.db, func(dbtx walletdb.ReadTx) error {
		_, tip := w.txStore.MainChainTip(dbtx)
		src := w.txStore.MakeInputSourceWithCoinType(dbtx, 0, 0,
			tip, nil, cointype.CoinTypeVAR)
		detail, err := src.SelectInputs(0, cointype.Zero())
		if err != nil {
			return err
		}
		for _, in := range detail.Inputs {
			unspent[in.PreviousOutPoint] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return unspent
}

// testWalletOutput records a tx paying 1e8 to the wallet and returns that
// output.  id makes each tx distinct.
func testWalletOutput(ctx context.Context, t *testing.T, w *Wallet, id byte) *wire.OutPoint {
	t.Helper()
	addr, err := w.NewInternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	ver, script := addr.(Address).PaymentScript()
	fund := wire.NewMsgTx()
	fund.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{id}}, 1e8, nil))
	fund.AddTxOut(&wire.TxOut{Value: 1e8, Version: ver, PkScript: script})
	if err := w.AddTransaction(ctx, fund, nil); err != nil {
		t.Fatal(err)
	}
	return &wire.OutPoint{Hash: fund.TxHash()}
}
