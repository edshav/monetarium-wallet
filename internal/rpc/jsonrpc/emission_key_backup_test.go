// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package jsonrpc

import (
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/monetarium/monetarium-node/dcrec/secp256k1"
	"golang.org/x/crypto/scrypt"
)

// encryptArbitraryPlaintextV3 builds a v3-format emission backup blob over an
// arbitrary plaintext, bypassing the secp256k1 input contract. Used by tests
// that need to forge non-32-byte or zero-scalar payloads which the production
// encrypt path can't generate.
func encryptArbitraryPlaintextV3(plaintext []byte, passphrase string) (string, error) {
	salt := make([]byte, emissionKDFSaltLen)
	if _, err := cryptorand.Read(salt); err != nil {
		return "", err
	}
	key, err := scrypt.Key([]byte(passphrase), salt,
		emissionKDFN, emissionKDFR, emissionKDFP, emissionKDFKeyLen)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := cryptorand.Read(nonce); err != nil {
		return "", err
	}
	aad := emissionBackupAAD(emissionKDFVersion, salt, emissionKDFN, emissionKDFR, emissionKDFP)
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	return fmt.Sprintf("aes256gcm:%s:%s:%d:%d:%d:%s:%s",
		emissionKDFVersion, hex.EncodeToString(salt),
		emissionKDFN, emissionKDFR, emissionKDFP,
		hex.EncodeToString(nonce), hex.EncodeToString(ciphertext)), nil
}

// TestEmissionKeyBackupSaltNonDeterminism exercises the CRITICAL code-review
// fix: encrypting the same private key under the same passphrase twice must
// produce two different ciphertexts (because the salt and nonce are fresh
// random per call). If the old sha256(passphrase) KDF is reintroduced this
// test fails immediately.
func TestEmissionKeyBackupSaltNonDeterminism(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	const passphrase = "correct horse battery staple"

	blob1, err := encryptPrivateKeyWithPassphrase(priv, passphrase)
	if err != nil {
		t.Fatalf("encrypt #1: %v", err)
	}
	blob2, err := encryptPrivateKeyWithPassphrase(priv, passphrase)
	if err != nil {
		t.Fatalf("encrypt #2: %v", err)
	}
	if blob1 == blob2 {
		t.Fatalf("two encryptions of the same key+passphrase produced identical ciphertext %q — missing salt/nonce", blob1)
	}
	if !strings.HasPrefix(blob1, "aes256gcm:v3:") || !strings.HasPrefix(blob2, "aes256gcm:v3:") {
		t.Fatalf("new blobs must carry the v3 prefix; got %q / %q", blob1, blob2)
	}
}

// TestEmissionKeyBackupRoundTrip covers the round trip for v3 blobs across a
// variety of passphrase shapes including long unicode. Decrypting must yield
// the same private key bytes the caller encrypted.
func TestEmissionKeyBackupRoundTrip(t *testing.T) {
	passphrases := []string{
		"s",
		"short",
		"a somewhat longer passphrase with spaces and 7 digits 1234567",
		"パスワードつきUnicodeテスト — correct horse battery staple 🙂",
	}
	for _, pass := range passphrases {
		t.Run(pass, func(t *testing.T) {
			priv, err := secp256k1.GeneratePrivateKey()
			if err != nil {
				t.Fatalf("GeneratePrivateKey: %v", err)
			}
			blob, err := encryptPrivateKeyWithPassphrase(priv, pass)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			roundTripped, err := decryptPrivateKeyWithPassphrase(blob, pass)
			if err != nil {
				t.Fatalf("decrypt with correct passphrase: %v", err)
			}
			if got, want := roundTripped.Serialize(), priv.Serialize(); !equalBytes(got, want) {
				t.Fatalf("round-tripped key differs from original")
			}
		})
	}
}

// TestEmissionKeyBackupWrongPassphraseFails confirms GCM authentication trips
// when a caller provides the wrong passphrase. It is NOT a timing-attack
// check, just a functional guard.
func TestEmissionKeyBackupWrongPassphraseFails(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	blob, err := encryptPrivateKeyWithPassphrase(priv, "right")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := decryptPrivateKeyWithPassphrase(blob, "wrong"); err == nil {
		t.Fatal("decrypt with wrong passphrase must fail")
	}
}

// TestEmissionKeyBackupV1Rejected locks in the chosen migration policy: old
// sha256(passphrase) v1 blobs are refused with an actionable error, not
// silently decrypted. A user with a v1 backup is forced to re-export from the
// canonical wallet DB under the new KDF.
func TestEmissionKeyBackupV1Rejected(t *testing.T) {
	// Shape of a v1 blob: "aes256gcm:<hex-iv>:<hex-ct>" — 3 parts.
	const v1Blob = "aes256gcm:0123456789abcdef01234567:deadbeefcafebabe"
	_, err := decryptPrivateKeyWithPassphrase(v1Blob, "whatever")
	if err == nil {
		t.Fatal("v1 blob must be rejected")
	}
	if !strings.Contains(err.Error(), "v1") || !strings.Contains(err.Error(), "insecure") {
		t.Fatalf("rejection error must mention v1 insecurity; got %v", err)
	}
}

// TestEmissionKeyBackupV2Rejected mirrors V1Rejected for the v2 cutover. v2
// blobs (scrypt+AES-GCM but no AAD on the KDF parameters) are refused with an
// actionable error so users with v2 backups know they must re-export under v3.
func TestEmissionKeyBackupV2Rejected(t *testing.T) {
	// Syntactically well-formed v2 blob; rejection must fire on the version
	// prefix before any scrypt or GCM work is attempted.
	const v2Blob = "aes256gcm:v2:00:32768:8:1:000000000000000000000000:aa"
	_, err := decryptPrivateKeyWithPassphrase(v2Blob, "whatever")
	if err == nil {
		t.Fatal("v2 blob must be rejected")
	}
	if !strings.Contains(err.Error(), "v2") || !strings.Contains(err.Error(), "AAD") {
		t.Fatalf("rejection error must mention v2 and missing AAD; got %v", err)
	}
}

// TestEmissionKeyBackupAADTamperRejected verifies that the v3 format
// authenticates the scrypt KDF parameters via AES-GCM additional-data.
// Tampering with any of salt / N / r / p in transit must cause gcm.Open to
// fail, even if the ciphertext and nonce are untouched.
func TestEmissionKeyBackupAADTamperRejected(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	const passphrase = "correct horse battery staple"
	blob, err := encryptPrivateKeyWithPassphrase(priv, passphrase)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	parts := strings.Split(blob, ":")
	if len(parts) != 8 || parts[1] != "v3" {
		t.Fatalf("unexpected blob shape: %q", blob)
	}

	mutateField := func(idx int, newVal string) string {
		clone := append([]string(nil), parts...)
		clone[idx] = newVal
		return strings.Join(clone, ":")
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	salt[0] ^= 0xff

	// A second valid scrypt N would also pass parsing — the AAD binding is
	// what catches the swap. The original blob uses N=32768; swap to 16384
	// (also a valid power of two within bounds).
	cases := []struct {
		name string
		blob string
	}{
		// salt index = 2; flip the first byte. Still hex-decodes, still
		// non-empty, still passes parsing. A fixed value would leave the
		// blob unchanged when the random salt already starts with it.
		{"salt swap", mutateField(2, hex.EncodeToString(salt))},
		{"N swap", mutateField(3, "16384")},
		{"r swap", mutateField(4, "4")},
		{"p swap", mutateField(5, "2")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decryptPrivateKeyWithPassphrase(tc.blob, passphrase); err == nil {
				t.Fatalf("AAD-bound field tamper (%s) must trip gcm.Open", tc.name)
			}
		})
	}
}

// TestDecryptRejectsBadLength verifies that the decrypt path enforces the
// 32-byte plaintext invariant. secp256k1.PrivKeyFromBytes silently
// truncates >32 bytes and mod-reduces, so a malicious-or-corrupt blob whose
// AAD-authenticated plaintext is the wrong length must be rejected upfront.
func TestDecryptRejectsBadLength(t *testing.T) {
	for _, n := range []int{31, 33, 64} {
		t.Run(string(rune('0'+n%10))+"bytes", func(t *testing.T) {
			plaintext := make([]byte, n)
			for i := range plaintext {
				plaintext[i] = byte(i + 1)
			}
			blob, err := encryptArbitraryPlaintextV3(plaintext, "test-bad-length-passphrase")
			if err != nil {
				t.Fatalf("forge blob: %v", err)
			}
			_, err = decryptPrivateKeyWithPassphrase(blob, "test-bad-length-passphrase")
			if err == nil {
				t.Fatalf("decrypt must reject %d-byte plaintext", n)
			}
			if !strings.Contains(err.Error(), "32 bytes") {
				t.Fatalf("rejection should mention 32-byte invariant; got %v", err)
			}
		})
	}
}

// TestDecryptRejectsZeroScalar verifies that a 32-byte all-zero plaintext is
// rejected post-decrypt. secp256k1's scalar mod-reduces this to zero, which
// would silently yield a key colliding with every other zero-scalar import.
func TestDecryptRejectsZeroScalar(t *testing.T) {
	plaintext := make([]byte, 32) // all-zero
	blob, err := encryptArbitraryPlaintextV3(plaintext, "test-zero-scalar-passphrase")
	if err != nil {
		t.Fatalf("forge blob: %v", err)
	}
	_, err = decryptPrivateKeyWithPassphrase(blob, "test-zero-scalar-passphrase")
	if err == nil {
		t.Fatal("decrypt must reject zero-scalar plaintext")
	}
	if !strings.Contains(err.Error(), "zero") {
		t.Fatalf("rejection should mention zero key; got %v", err)
	}
}

// TestEmissionKeyBackupMalformedRejected guards the parser against a handful
// of obviously invalid shapes. We do not enumerate every failure mode — the
// goal is a smoke test that malformed input never reaches the cipher.
func TestEmissionKeyBackupMalformedRejected(t *testing.T) {
	cases := []string{
		"",                                                         // empty
		"aes128gcm:v3:00:32768:8:1:000000000000000000000000:aa",    // wrong alg prefix
		"aes256gcm:v3:zz:32768:8:1:000000000000000000000000:aa",    // non-hex salt
		"aes256gcm:v3:00:abc:8:1:000000000000000000000000:aa",      // non-integer N
		"aes256gcm:v3:00:32768:8:1:00:aa",                          // nonce wrong length
		"aes256gcm:v3:00:32768:8:1:000000000000000000000000",       // truncated (7 parts, not 8)
	}
	for _, blob := range cases {
		t.Run(blob, func(t *testing.T) {
			if _, err := decryptPrivateKeyWithPassphrase(blob, "x"); err == nil {
				t.Fatalf("malformed blob %q must be rejected", blob)
			}
		})
	}
}

// TestEmissionKeyBackupScryptNUpperBound regression test for the DoS vector
// where a malicious blob carrying N = 1<<25 (a power of two, but absurdly
// large) would force a multi-GiB scrypt allocation. The decryptor must reject
// it before invoking scrypt.
func TestEmissionKeyBackupScryptNUpperBound(t *testing.T) {
	// 1<<25 = 33_554_432; well above the 1<<20 hard cap and far above the
	// 1<<15 used by encryption. Other fields are syntactically valid; only
	// the N parameter is hostile.
	const blob = "aes256gcm:v3:00:33554432:8:1:000000000000000000000000:aa"
	_, err := decryptPrivateKeyWithPassphrase(blob, "anything")
	if err == nil {
		t.Fatal("scrypt N above the hard cap must be rejected before scrypt is called")
	}
	if !strings.Contains(err.Error(), "scrypt N") {
		t.Fatalf("rejection should mention scrypt N; got %v", err)
	}
}

// TestEmissionKeyBackupScryptRPUpperBound parallels the N-cap test for the r
// and p parameters: scrypt's contract honours arbitrarily large r and p, so a
// malicious blob with (e.g.) p = 1<<10 would burn CPU on every decrypt
// attempt.  The decryptor must reject out-of-range values before invoking
// scrypt.
func TestEmissionKeyBackupScryptRPUpperBound(t *testing.T) {
	cases := []struct {
		name     string
		blob     string
		mustSay  string
	}{
		{
			name:    "r over 16 rejected",
			blob:    "aes256gcm:v3:00:32768:17:1:000000000000000000000000:aa",
			mustSay: "scrypt r",
		},
		{
			name:    "p over 16 rejected",
			blob:    "aes256gcm:v3:00:32768:8:17:000000000000000000000000:aa",
			mustSay: "scrypt p",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decryptPrivateKeyWithPassphrase(tc.blob, "anything")
			if err == nil {
				t.Fatal("out-of-range scrypt parameter must be rejected before scrypt is called")
			}
			if !strings.Contains(err.Error(), tc.mustSay) {
				t.Fatalf("rejection should mention %q; got %v", tc.mustSay, err)
			}
		})
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestPrivKeyFromBytesCopiesInput pins the upstream secp256k1 contract that
// decryptPrivateKeyWithPassphrase relies on: PrivKeyFromBytes copies the
// caller's byte slice into the returned key's internal scalar limbs before
// returning, so wiping the input slice does not mutate the returned key.
//
// If a future bump of monetarium-node/dcrec/secp256k1 changes ModNScalar
// .SetByteSlice to alias the input instead of copying, this test fails
// immediately — at which point the deferred zeroBytes(privateKeyBytes) at
// the end of decryptPrivateKeyWithPassphrase would silently corrupt every
// imported emission key.
//
// See MEDIUM-#4 in the 2026-05-02 code review.
func TestPrivKeyFromBytesCopiesInput(t *testing.T) {
	// Generate a fresh key, serialize, then reconstruct from bytes (mirrors
	// the decrypt path in decryptPrivateKeyWithPassphrase).
	original, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	originalBytes := original.Serialize()
	if len(originalBytes) != 32 {
		t.Fatalf("expected 32-byte serialization, got %d", len(originalBytes))
	}

	// Allocate a fresh buffer (matching decryptPrivateKeyWithPassphrase's
	// gcm.Open output) and reconstruct the key.
	buf := make([]byte, len(originalBytes))
	copy(buf, originalBytes)

	priv := secp256k1.PrivKeyFromBytes(buf)
	if priv == nil {
		t.Fatalf("PrivKeyFromBytes returned nil")
	}

	// Capture pre-wipe serialization. If PrivKeyFromBytes aliased buf, this
	// would already match buf — but it might also change after wiping.
	preWipe := priv.Serialize()

	// Wipe the input buffer (the same operation decryptPrivateKeyWithPassphrase
	// does via defer zeroBytes(privateKeyBytes)).
	for i := range buf {
		buf[i] = 0
	}

	// Sanity: buf is now zero.
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Fatal("test bug: buf was not actually wiped")
	}

	postWipe := priv.Serialize()
	if !equalBytes(preWipe, postWipe) {
		t.Fatalf("priv.Serialize() changed after input wipe: pre=%x post=%x — PrivKeyFromBytes is aliasing the input slice",
			preWipe, postWipe)
	}
	if !equalBytes(postWipe, originalBytes) {
		t.Errorf("reconstructed key bytes differ from original: got %x, want %x",
			postWipe, originalBytes)
	}
	if priv.Key.IsZero() {
		t.Fatal("priv.Key.IsZero() after wipe — input was aliased and zeroed")
	}
}

// TestDecryptPrivateKeyZeroAfterUseSafe is the higher-level companion test:
// it round-trips through decryptPrivateKeyWithPassphrase and verifies that
// the returned key is usable (has the correct serialization) — which would
// silently fail if the deferred zeroBytes wiped a key still aliased by the
// returned *PrivateKey.
func TestDecryptPrivateKeyZeroAfterUseSafe(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	const passphrase = "test-zero-safe"
	blob, err := encryptPrivateKeyWithPassphrase(priv, passphrase)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := decryptPrivateKeyWithPassphrase(blob, passphrase)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got == nil {
		t.Fatal("decrypt returned nil key")
	}
	// The deferred zeroBytes has already run by the time we observe the
	// result here. If the returned key had aliased the wiped buffer, its
	// scalar would now be zero or garbled.
	if got.Key.IsZero() {
		t.Fatal("decrypted key is zero — defer zeroBytes mutated the returned key")
	}
	if !equalBytes(priv.Serialize(), got.Serialize()) {
		t.Errorf("round-trip mismatch: original %x, got %x", priv.Serialize(), got.Serialize())
	}
}

// TestRequireBackupPassphrase locks in the RPC-layer policy that emission-key
// backup encrypt/decrypt paths refuse passphrases shorter than
// minBackupPassphraseLen. A leaked encrypted blob is a permanent capability;
// an empty or short passphrase reduces it to a trivially-decryptable artifact.
func TestRequireBackupPassphrase(t *testing.T) {
	cases := []struct {
		name       string
		passphrase string
		wantErr    bool
	}{
		{"empty", "", true},
		{"one char", "x", true},
		{"eleven chars", "12345678901", true},
		{"twelve chars", "123456789012", false},
		{"long", "correct horse battery staple", false},
		{"unicode long", "パスワード-correct-horse", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireBackupPassphrase(tc.passphrase)
			if tc.wantErr && err == nil {
				t.Fatalf("passphrase %q (len=%d) must be rejected", tc.passphrase, len(tc.passphrase))
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("passphrase %q (len=%d) must be accepted; got %v", tc.passphrase, len(tc.passphrase), err)
			}
			if err != nil && strings.Contains(err.Error(), tc.passphrase) && tc.passphrase != "" {
				t.Fatalf("error must not echo the passphrase value; got %v", err)
			}
		})
	}
}
