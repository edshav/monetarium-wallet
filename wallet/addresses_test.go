// Copyright (c) 2018-2023 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/monetarium/monetarium-node/chaincfg"
	"github.com/monetarium/monetarium-node/hdkeychain"
	"github.com/monetarium/monetarium-node/txscript/stdaddr"
	"github.com/monetarium/monetarium-wallet/wallet/walletdb"
)

// expectedAddr is used to house the expected return values from a managed
// address.  Not all fields for used for all managed address types.
type expectedAddr struct {
	address     string
	addressHash []byte
	branch      uint32
	pubKey      []byte
}

// testContext is used to store context information about a running test which
// is passed into helper functions.
type testContext struct {
	t            *testing.T
	account      uint32
	watchingOnly bool
}

// hexToBytes is a wrapper around hex.DecodeString that panics if there is an
// error.  It MUST only be used with hard coded values in the tests.
func hexToBytes(origHex string) []byte {
	buf, err := hex.DecodeString(origHex)
	if err != nil {
		panic(err)
	}
	return buf
}

var (
	// seed is the master seed used throughout the tests.
	seed = []byte{
		0xb4, 0x6b, 0xc6, 0x50, 0x2a, 0x30, 0xbe, 0xb9, 0x2f,
		0x0a, 0xeb, 0xc7, 0x76, 0x40, 0x3c, 0x3d, 0xbf, 0x11,
		0xbf, 0xb6, 0x83, 0x05, 0x96, 0x7c, 0x36, 0xda, 0xc9,
		0xef, 0x8d, 0x64, 0x15, 0x67,
	}

	defaultAccount     = uint32(0)
	defaultAccountName = "default"

	waddrmgrBucketKey = []byte("waddrmgr")

	expectedInternalAddrs = []expectedAddr{
		{
			address:     "SsrFKd8aX4KHabWSQfbmEaDv3BJCpSH2ySj",
			addressHash: hexToBytes("f032b89ec075ab2847e2ec186ad000be16cf354b"),
			branch:      1,
			pubKey:      hexToBytes("03d1ad44eeac8eb59e9598f7e530a1cbe2c1684c0aa5f45ab24d33d38a2102dd1a"),
		},
		{
			address:     "SsW4roiFKWkbbhiAeEV5byet1pLKAP4xRks",
			addressHash: hexToBytes("12d5a8e19b9a070d6d5e6e425b593c2c137285e3"),
			branch:      1,
			pubKey:      hexToBytes("02cbcf5c1aa84bf8e6d04412d867eccbaa6cc12ebb792f3f1eaf4d2887f8e884f3"),
		},
		{
			address:     "SscaK4A6V94dawc6ZBRCGUxPjdf7um1GJgD",
			addressHash: hexToBytes("5a38638f09937214b07481c656d0c9c73020f8bf"),
			branch:      1,
			pubKey:      hexToBytes("0392735a0eee9026425556ef5c5ae23ad3e54598132a1ca0d74dbcac7bfe31bfa4"),
		},
		{
			address:     "Ssm4BeTKgwKGTqNR63WiGtP1FJaKCRJsN1S",
			addressHash: hexToBytes("b73edb8f32957800e2e3b9424c3b659acac51b7f"),
			branch:      1,
			pubKey:      hexToBytes("037c1e500884c6c3cb044390b52525d324fd67c031fdd9a47d742d0323fe5de73f"),
		},
		{
			address:     "SssBoVxTkCUb6xs7vph3BHdPmki3weVvRsF",
			addressHash: hexToBytes("fa8073fcb670ba7312a1ef0d908cfb05c59b70b9"),
			branch:      1,
			pubKey:      hexToBytes("0327540e546f9cfac45f51699e2656732727507971060641ead554d78eeea88aa6"),
		},
	}

	expectedExternalAddrs = []expectedAddr{
		{
			address:     "SsfPTmZmaXGkXfcNGjftRPmoGGCqtNPCHKx",
			addressHash: hexToBytes("791376f67fb3becf392b071d25d7c99c82139ee3"),
			pubKey:      hexToBytes("031634efb3e83c834a82cdc898000f85215a09dc742d5b3b82ace7221ca1bb0938"),
		},
		{
			address:     "SsXhSHBiaEan7Ls36bvhLspZ3LC1NKzuwQz",
			addressHash: hexToBytes("24b8b3d89f987bf3cd80a8c16d9368d683217fa4"),
			pubKey:      hexToBytes("0280beb72c6ef42ce3133fd6d340fd5bedcfccaded5a6eabb6d2430e3958bf7c85"),
		},
		{
			address:     "SspSfaWDNwc9TA31Q9iR2jot2eV1hk2ix6U",
			addressHash: hexToBytes("dc67b3d95adb1789efe4aa73607d8a8c57eee2bb"),
			pubKey:      hexToBytes("03b120e0e073a12a1957680251a1562c5c6e30e547797fb5411107eac19699f601"),
		},
		{
			address:     "SsrSYTB9MQQ1czAfPmWE66ZFqv7NrwzqfQT",
			addressHash: hexToBytes("f252015c8e0059c21cae623704d8588d12ca5c74"),
			pubKey:      hexToBytes("0350822c9bd61f524f4d68fa605e850c34c5e8ccc9b5cf278782131c1e21dd261b"),
		},
		{
			address:     "SsqBcGBre8SZrG61cd5M5e2GaMJbK2CMdEa",
			addressHash: hexToBytes("e486d22d1244becac5a30b38dda1c8c4c1b3bdeb"),
			pubKey:      hexToBytes("031c494068c9c454bef7de35fa4717f21c07dec4471bd8500650b133d57e49a81d"),
		},
	}
)

type newAddressFunc func(*Wallet, context.Context, uint32, ...NextAddressCallOption) (stdaddr.Address, error)

func testKnownAddresses(ctx context.Context, tc *testContext, prefix string, unlock bool, newAddr newAddressFunc, tests []expectedAddr) {
	w, teardown := testWallet(ctx, tc.t, &basicWalletConfig, seed)
	defer teardown()

	if unlock {
		err := w.Unlock(ctx, testPrivPass, nil)
		if err != nil {
			tc.t.Fatal(err)
		}
	}

	if tc.watchingOnly {
		err := walletdb.Update(ctx, w.db, func(tx walletdb.ReadWriteTx) error {
			ns := tx.ReadWriteBucket(waddrmgrBucketKey)
			return w.manager.ConvertToWatchingOnly(ns)
		})
		if err != nil {
			tc.t.Fatalf("%s: failed to convert wallet to watching only: %v",
				prefix, err)
		}
	}

	for i := 0; i < len(tests); i++ {
		addr, err := newAddr(w, ctx, defaultAccount)
		if err != nil {
			tc.t.Fatalf("%s: failed to generate external address: %v",
				prefix, err)
		}

		ka, err := w.KnownAddress(ctx, addr)
		if err != nil {
			tc.t.Errorf("Unexpected error: %v", err)
			continue
		}

		if ka.AccountName() != defaultAccountName {
			tc.t.Errorf("%s: expected account %v got %v", prefix,
				defaultAccount, ka.AccountName())
		}

		if ka.String() != tests[i].address {
			tc.t.Errorf("%s: expected address %v got %v", prefix,
				tests[i].address, ka)
		}
		a := ka.(BIP0044Address)
		if !bytes.Equal(a.PubKeyHash(), tests[i].addressHash) {
			tc.t.Errorf("%s: expected address hash %v got %v", prefix,
				hex.EncodeToString(tests[i].addressHash),
				hex.EncodeToString(a.PubKeyHash()))
		}

		if _, branch, _ := a.Path(); branch != tests[i].branch {
			tc.t.Errorf("%s: expected branch of %v got %v", prefix,
				tests[i].branch, branch)
		}

		pubKey, err := a.PubKey()
		if err != nil {
			tc.t.Errorf("%s: PubKey: %v", prefix, err)
		}
		if !bytes.Equal(pubKey, tests[i].pubKey) {
			tc.t.Errorf("%s: expected pubkey %v got %v",
				prefix, hex.EncodeToString(tests[i].pubKey),
				hex.EncodeToString(pubKey))
		}
	}
}

func TestAddresses(t *testing.T) {
	ctx := context.Background()

	testAddresses(ctx, t, false)
	testAddresses(ctx, t, true)
}

func testAddresses(ctx context.Context, t *testing.T, unlock bool) {
	testKnownAddresses(ctx, &testContext{
		t:            t,
		account:      defaultAccount,
		watchingOnly: false,
	}, "testInternalAddresses", unlock, (*Wallet).NewInternalAddress, expectedInternalAddrs)

	testKnownAddresses(ctx, &testContext{
		t:            t,
		account:      defaultAccount,
		watchingOnly: true,
	}, "testInternalAddresses", unlock, (*Wallet).NewInternalAddress, expectedInternalAddrs)

	testKnownAddresses(ctx, &testContext{
		t:            t,
		account:      defaultAccount,
		watchingOnly: false,
	}, "testExternalAddresses", unlock, (*Wallet).NewExternalAddress, expectedExternalAddrs)

	testKnownAddresses(ctx, &testContext{
		t:            t,
		account:      defaultAccount,
		watchingOnly: true,
	}, "testExternalAddresses", unlock, (*Wallet).NewExternalAddress, expectedExternalAddrs)
}

func TestAccountIndexes(t *testing.T) {
	ctx := context.Background()

	cfg := basicWalletConfig
	w, teardown := testWallet(ctx, t, &cfg, nil)
	defer teardown()

	w.SetNetworkBackend(mockNetwork{})

	tests := []struct {
		f       func(ctx context.Context, t *testing.T, w *Wallet)
		indexes accountIndexes
	}{
		{nil, accountIndexes{{^uint32(0), 0}, {^uint32(0), 0}}},
		{nextAddresses(1), accountIndexes{{^uint32(0), 1}, {^uint32(0), 0}}},
		{nextAddresses(19), accountIndexes{{^uint32(0), 20}, {^uint32(0), 0}}},
		{watchFutureAddresses, accountIndexes{{^uint32(0), 20}, {^uint32(0), 0}}},
		{useAddress(10), accountIndexes{{10, 9}, {^uint32(0), 0}}},
		{nextAddresses(1), accountIndexes{{10, 10}, {^uint32(0), 0}}},
		{nextAddresses(10), accountIndexes{{10, 20}, {^uint32(0), 0}}},
		{useAddress(30), accountIndexes{{30, 0}, {^uint32(0), 0}}},
		{useAddress(31), accountIndexes{{31, 0}, {^uint32(0), 0}}},
	}
	for i, test := range tests {
		if test.f != nil {
			test.f(ctx, t, w)
		}
		w.addressBuffersMu.Lock()
		b := w.addressBuffers[0]
		t.Logf("ext last=%d, ext cursor=%d, int last=%d, int cursor=%d",
			b.albExternal.lastUsed, b.albExternal.cursor, b.albInternal.lastUsed, b.albInternal.cursor)
		check := func(what string, a, b uint32) {
			if a != b {
				t.Fatalf("%d: %s do not match: %d != %d", i, what, a, b)
			}
		}
		check("external last indexes", b.albExternal.lastUsed, test.indexes[0].last)
		check("external cursors", b.albExternal.cursor, test.indexes[0].cursor)
		check("internal last indexes", b.albInternal.lastUsed, test.indexes[1].last)
		check("internal cursors", b.albInternal.cursor, test.indexes[1].cursor)
		w.addressBuffersMu.Unlock()
	}
}

type accountIndexes [2]struct {
	last, cursor uint32
}

func nextAddresses(n int) func(ctx context.Context, t *testing.T, w *Wallet) {
	return func(ctx context.Context, t *testing.T, w *Wallet) {
		for i := 0; i < n; i++ {
			_, err := w.NewExternalAddress(ctx, 0)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

func watchFutureAddresses(ctx context.Context, t *testing.T, w *Wallet) {
	n, _ := w.NetworkBackend()
	_, err := w.watchHDAddrs(ctx, false, n)
	if err != nil {
		t.Fatal(err)
	}
}

func useAddress(child uint32) func(ctx context.Context, t *testing.T, w *Wallet) {
	return func(ctx context.Context, t *testing.T, w *Wallet) {
		w.addressBuffersMu.Lock()
		xbranch := w.addressBuffers[0].albExternal.branchXpub
		w.addressBuffersMu.Unlock()
		addr, err := deriveChildAddress(xbranch, child, basicWalletConfig.Params)
		if err != nil {
			t.Fatal(err)
		}
		err = walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
			ns := dbtx.ReadWriteBucket(waddrmgrBucketKey)
			ma, err := w.manager.Address(ns, addr)
			if err != nil {
				return err
			}
			return w.markUsedAddress("", dbtx, ma)
		})
		if err != nil {
			t.Fatal(err)
		}
		watchFutureAddresses(ctx, t, w)
	}
}

// TestXpubAddressPubKeyError verifies that xpubAddress.PubKey() returns an
// error rather than panicking when the underlying HD derivation fails. This
// is the regression test for the inherited-from-upstream `panic(err)` calls
// removed in favor of explicit error propagation: a hardened branch index
// against a public-only extended key is the canonical case where Child()
// fails (hdkeychain.ErrDeriveHardFromPublic), and a long-running RPC server
// must surface this as an error rather than dropping the goroutine.
func TestXpubAddressPubKeyError(t *testing.T) {
	// Build a real public-only extended key from a deterministic seed.
	seed := bytes.Repeat([]byte{0x42}, hdkeychain.RecommendedSeedLen)
	master, err := hdkeychain.NewMaster(seed, chaincfg.SimNetParams())
	if err != nil {
		t.Fatalf("NewMaster: %v", err)
	}
	xpub := master.Neuter()

	t.Run("hardened branch fails on xpub", func(t *testing.T) {
		x := &xpubAddress{
			xpub:   xpub,
			branch: hdkeychain.HardenedKeyStart, // unreachable from a public xpub
			child:  0,
		}
		got, err := x.PubKey()
		if err == nil {
			t.Fatalf("expected error from hardened-branch derivation, got bytes %x", got)
		}
		if got != nil {
			t.Errorf("expected nil pubkey on error, got %x", got)
		}
	})

	t.Run("hardened child fails on xpub", func(t *testing.T) {
		x := &xpubAddress{
			xpub:   xpub,
			branch: 0,
			child:  hdkeychain.HardenedKeyStart,
		}
		got, err := x.PubKey()
		if err == nil {
			t.Fatalf("expected error from hardened-child derivation, got bytes %x", got)
		}
		if got != nil {
			t.Errorf("expected nil pubkey on error, got %x", got)
		}
	})

	t.Run("valid branch and child succeed", func(t *testing.T) {
		x := &xpubAddress{
			xpub:   xpub,
			branch: 0,
			child:  0,
		}
		got, err := x.PubKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) == 0 {
			t.Fatal("expected non-empty pubkey")
		}
	})
}

// TestCurrentAddressAndPersist checks that getaccountaddress returns the same
// address on every call until it is used, a new address is returned or the
// wallet restarts.  Advancing on every call would use up the gap limit, and
// payments beyond it are not found when the wallet is restored from seed.  The
// address is the one CurrentAddress reports, getaddressesbyaccount lists it,
// and getnewaddress never returns it.
func TestCurrentAddressAndPersist(t *testing.T) {
	ctx := context.Background()
	cfg := basicWalletConfig
	w, teardown := testWallet(ctx, t, &cfg, nil)
	defer teardown()

	w.addressBuffersMu.Lock()
	xbranch := w.addressBuffers[0].albExternal.branchXpub
	w.addressBuffersMu.Unlock()
	child := func(i uint32) string {
		addr, err := deriveChildAddress(xbranch, i, cfg.Params)
		if err != nil {
			t.Fatal(err)
		}
		return addr.String()
	}
	current := func(want uint32) {
		t.Helper()
		addr, err := w.CurrentAddressAndPersist(ctx, 0)
		if err != nil {
			t.Fatal(err)
		}
		if addr.String() != child(want) {
			t.Fatalf("current address %v, want child %d (%v)", addr, want, child(want))
		}
		peek, err := w.CurrentAddress(0)
		if err != nil {
			t.Fatal(err)
		}
		if peek.String() != addr.String() {
			t.Fatalf("CurrentAddress %v after getaccountaddress returned %v", peek, addr)
		}
		// getaddressesbyaccount lists the children below this index.
		ext, _, err := w.BIP0044BranchNextIndexes(ctx, 0)
		if err != nil {
			t.Fatal(err)
		}
		if ext <= want {
			t.Fatalf("getaddressesbyaccount lists children below %d, not child %d", ext, want)
		}
	}

	for range 2 * cfg.GapLimit {
		current(0)
	}
	addr, err := w.NewExternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != child(1) {
		t.Fatalf("new address %v, want child 1 (%v)", addr, child(1))
	}
	current(2)
	current(2)

	// The address is kept in memory only, so a restart moves it on.
	w, err = Open(ctx, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	w.SetNetworkBackend(mockNetwork{})
	current(3)
	current(3)

	useAddress(3)(ctx, t, w)
	current(4)
	current(4)
}

// TestCurrentAddressAndPersistGapLimit checks that, with the gap limit's
// worth of unused addresses already returned, getaccountaddress returns none of
// them and leaves the cursor every caller shares where it was.
func TestCurrentAddressAndPersistGapLimit(t *testing.T) {
	ctx := context.Background()
	cfg := basicWalletConfig
	w, teardown := testWallet(ctx, t, &cfg, nil)
	defer teardown()

	returned := make(map[string]bool)
	for range cfg.GapLimit {
		addr, err := w.NewExternalAddress(ctx, 0)
		if err != nil {
			t.Fatal(err)
		}
		returned[addr.String()] = true
	}
	addr, err := w.CurrentAddressAndPersist(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if returned[addr.String()] {
		t.Fatalf("getaccountaddress returned %v, already returned by getnewaddress", addr)
	}
	ext, _, err := w.BIP0044BranchNextIndexes(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ext != cfg.GapLimit+1 {
		t.Fatalf("next external index %d, want %d", ext, cfg.GapLimit+1)
	}
}

// TestCurrentAddressAndPersistAccounts checks that a new address on one
// account leaves the address getaccountaddress returns on another alone.
func TestCurrentAddressAndPersistAccounts(t *testing.T) {
	ctx := context.Background()
	cfg := basicWalletConfig
	cfg.AccountGapLimit = 2
	w, teardown := testWallet(ctx, t, &cfg, nil)
	defer teardown()
	if err := w.Unlock(ctx, testPrivPass, nil); err != nil {
		t.Fatal(err)
	}
	acct, err := w.NextAccount(ctx, "second")
	if err != nil {
		t.Fatal(err)
	}

	want, err := w.CurrentAddressAndPersist(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.CurrentAddressAndPersist(ctx, acct); err != nil {
		t.Fatal(err)
	}
	if _, err := w.NewExternalAddress(ctx, acct); err != nil {
		t.Fatal(err)
	}
	got, err := w.CurrentAddressAndPersist(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != want.String() {
		t.Fatalf("account 0 address moved from %v to %v after a new address on account %d", want, got, acct)
	}
}

// TestCurrentAddressAndPersistConcurrent checks that concurrent getaccountaddress
// and getnewaddress calls never return one address to both.
func TestCurrentAddressAndPersistConcurrent(t *testing.T) {
	ctx := context.Background()
	cfg := basicWalletConfig
	w, teardown := testWallet(ctx, t, &cfg, nil)
	defer teardown()

	var mu sync.Mutex
	current := make(map[string]bool)
	fresh := make(map[string]bool)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 10 {
				addr, err := w.CurrentAddressAndPersist(ctx, 0)
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				current[addr.String()] = true
				mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			for range 5 {
				addr, err := w.NewExternalAddress(ctx, 0, WithGapPolicyIgnore())
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				fresh[addr.String()] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	for addr := range current {
		if fresh[addr] {
			t.Errorf("%v returned by both getaccountaddress and getnewaddress", addr)
		}
	}
}

// TestCurrentAddressAndPersistConcurrentFirstCall checks that concurrent
// calls on an account with no remembered address all return one address.
func TestCurrentAddressAndPersistConcurrentFirstCall(t *testing.T) {
	ctx := context.Background()
	cfg := basicWalletConfig
	w, teardown := testWallet(ctx, t, &cfg, nil)
	defer teardown()

	const n = 8
	addrs := make([]string, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			addr, err := w.CurrentAddressAndPersist(ctx, 0)
			if err != nil {
				t.Error(err)
				return
			}
			addrs[i] = addr.String()
		}()
	}
	close(start)
	wg.Wait()
	for i := 1; i < n; i++ {
		if addrs[i] != addrs[0] {
			t.Fatalf("concurrent calls returned %v and %v", addrs[0], addrs[i])
		}
	}
	// Only one index was used up.
	next, err := w.NewExternalAddress(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if child := next.(*xpubAddress).child; child != 1 {
		t.Errorf("next address is child %d, want 1", child)
	}
}
