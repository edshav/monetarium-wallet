# Security Policy

## Reporting a Vulnerability

Please report vulnerabilities privately through [GitHub's private vulnerability reporting](https://github.com/monetarium/monetarium-wallet/security/advisories/new). Do not open a public issue or pull request, or post details in public channels, until the fix has shipped.

Send one report per issue, with the affected version and a way to reproduce it, ideally a failing test.

Monetarium does not currently run a bug bounty program.

## Supported Versions

All bugs must be reproducible in the latest production release or the main branch of the code.

## Passphrase handling

The wallet master passphrase and the emission-key backup passphrase enter the
process via JSON-RPC request bodies. The local `[]byte` copies that the wallet
holds during cryptographic operations are zeroized after use, but the original
Go `string` allocated by the JSON-RPC parser is immutable and remains in heap
memory until the garbage collector reclaims it. As a result, operators should:

- Treat passphrases as exposed to the host process memory for the request
  lifetime plus an unbounded GC delay.
- Prefer dedicated machines / processes for the wallet daemon and avoid
  reusing a master passphrase across services.
- Rotate passphrases promptly after suspected host compromise rather than
  relying on the in-process zeroization to limit exposure.

Encrypted emission-key backups protected with `requireBackupPassphrase` use
scrypt(N=2^15, r=8, p=1) → AES-256-GCM and require a minimum length of 12
characters; the same memory-lifetime caveat applies to that passphrase too.

## Offline / cold SKA signing

The transaction sighash used by Monetarium (`SigHashAll`) commits to every
input's `SKAValueIn` and every output's `CoinType` and `SKAValue`, in
addition to the upstream Decred prefix fields (`TxOut.Value`, `PkScript`,
`Version`). An offline / cold signer (hardware wallet, air-gapped
machine, multisig coordinator) presented with `(tx, prevPkScript)` will
therefore produce a signature that does not match if the host has lied
about the SKA atom amount being authorized — the digest mismatch means
the resulting signature will be rejected by the network's CHECKSIG.

Encoding details (Monetarium prefix extension on top of the upstream
Decred sighash format):

- Per input, after the existing prevout / sequence fields, the prefix
  appends one byte for `len(SKAValueIn.Bytes())` followed by the
  big-endian bytes themselves; VAR inputs and zero-value SKA inputs
  encode as a single `0x00` length byte with no following bytes.
- Per output, after the existing amount / pkscript fields, the prefix
  appends one byte for `CoinType` followed by the same length-prefixed
  `SKAValue` encoding. The `SigHashSingle` substitution that clears
  `value`/`pkScript` for non-corresponding outputs also clears the new
  CoinType byte (to `0x00`) and the `SKAValue` length byte (to `0x00`).

Operator-facing helpers (`cmd/movefunds` `sign.sh` flow and others) still
display `skaValueIn` for every SKA input so reviewers can verify the
amount before signing, but the verification is now cryptographically
enforced rather than purely advisory: any tampering with `SKAValueIn` or
`SKAValue` between display and signing will invalidate the signature.

