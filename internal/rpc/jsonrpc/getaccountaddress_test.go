// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package jsonrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/dcrutil"
	"github.com/monetarium/monetarium-wallet/internal/loader"
	"github.com/monetarium/monetarium-wallet/rpc/jsonrpc/types"
	"github.com/monetarium/monetarium-wallet/wallet"
	_ "github.com/monetarium/monetarium-wallet/wallet/drivers/bdb"
)

// TestGetAccountAddress checks that getaccountaddress returns the same address
// on every call, that getaddressesbyaccount lists it, and that getnewaddress
// does not return it.
func TestGetAccountAddress(t *testing.T) {
	ctx := context.Background()
	params := chaincfg.SimNetParams()
	ldr := loader.NewLoader(params, t.TempDir(), false, 20, 0, false,
		dcrutil.Amount(1e5), 0, 1, true, false, false, 0, nil)
	seed := bytes.Repeat([]byte{0x42}, 32)
	if _, err := ldr.CreateNewWallet(ctx, []byte(wallet.InsecurePubPassphrase), []byte("private"), seed); err != nil {
		t.Fatal(err)
	}
	defer ldr.UnloadWallet()
	s := &Server{walletLoader: ldr, activeNet: params}

	call := func(f func(context.Context, any) (any, error), cmd any) any {
		t.Helper()
		res, err := f(ctx, cmd)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	accountAddress := func() string {
		t.Helper()
		return call(s.getAccountAddress, &types.GetAccountAddressCmd{Account: "default"}).(string)
	}
	listed := func() []string {
		t.Helper()
		b, err := json.Marshal(call(s.getAddressesByAccount, &types.GetAddressesByAccountCmd{Account: "default"}))
		if err != nil {
			t.Fatal(err)
		}
		var addrs []string
		if err := json.Unmarshal(b, &addrs); err != nil {
			t.Fatal(err)
		}
		return addrs
	}

	addr := accountAddress()
	for range 40 {
		if got := accountAddress(); got != addr {
			t.Fatalf("getaccountaddress returned %v, then %v", addr, got)
		}
	}
	if !slices.Contains(listed(), addr) {
		t.Fatalf("getaddressesbyaccount does not list %v", addr)
	}
	newAddr := call(s.getNewAddress, &types.GetNewAddressCmd{}).(string)
	if newAddr == addr {
		t.Fatalf("getnewaddress returned %v, already returned by getaccountaddress", addr)
	}
	if got := accountAddress(); got == addr || got == newAddr {
		t.Fatalf("getaccountaddress returned %v after getnewaddress returned %v", got, newAddr)
	}
}
