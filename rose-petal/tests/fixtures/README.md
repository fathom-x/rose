# Fixtures

None of this is secret, and nothing here is trusted by the library except AWS's root. The
attestation fixtures from bootproof are MIT (bootproof-sdk's license); the Locksmith fixtures
come from an AGPL-3.0-only repository, see below.

## `attestation/`

- `nitro-root.der`: AWS's Nitro Enclaves root certificate (`CN=aws.nitro-enclaves`), as AWS
  publishes it; SHA-256 `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`.
  Embedded by `nitro.rs` as the production trust anchor (a test pins the hash).
- `aws-test.cbor`: a real attestation document from an enclave, from bootproof's SDK
  (Caution, MIT), with its nonce `d041b23b...`, PCRs and issue time in `nitro.rs`'s tests.
- `historical-test-root.der`, `historical-test-leaf.der`, `historical-test-key.pk8`:
  bootproof's synthetic P-384 root (valid 2020 to 2040), the leaf it issued (valid
  2025-12-23 17:06 to 20:06 UTC) and the leaf's public test private key. The test server
  signs its documents with them; `Verifier::with_root` is the only way to trust the root.
- `rose-deploy-2026-10-28.json`, `rose-deploy-2026-10-28.hashes.json`: the document a rose
  deployment recorded on 2026-10-28, fetched from its enclave with the deployed commit
  `c502c976...` as the nonce, and the hashes file it was checked against. Verified at its own
  timestamp (the leaf has expired).

## `locksmith-v0/`

Copied verbatim from Locksmith's repository (codeberg.org/caution/locksmith, commit
`ab0d216`, `tests/fixtures/v0/` and `tests/fixtures/v1-contract.json`). **Locksmith is
licensed AGPL-3.0-only (or Caution's commercial license).** What is copied is test data its
`generate_fixture` test produced, not code: random keys sequoia's `CertBuilder` generated,
ciphertext keyfork-shard dealt from a constant, and the JSON that wraps them. Upstream's own
fixture README calls every private key here "deliberately public test data" never to be used
in production, and this tree treats the files as uncopyrightable generated material carried
for interoperability testing, with their origin stated here. No code from Locksmith is in
this tree; the client was written to the wire protocol.

- `bundle.json`: a 2-of-2 raw V0 bundle dealt by keyfork-shard through sequoia-openpgp from
  the secret `[7; 32]`.
- `alice.private.asc`, `bob.private.asc`: the two holders' public test keys (user ids
  "Alice V0 public TEST KEY" and "Bob V0 public TEST KEY", created at Unix 1700000000).
- `imported.json`: the ImportedV0 artifact upstream's import wrote for the bundle.
- `v1-contract.json`: upstream's V1 encoding contract: a bundle with its canonical CBOR and
  SHA-256, which pins the bundle hash byte for byte.

Because an independent implementation made the bundle, it is the interoperability check for
the shardfile decoder, the inner share signature and the Shamir field (`[7; 32]` must come
back); it is what caught rpgp's handling of sequoia's partial-length packets and blahaj's
0x11d field polynomial. The crate's own tests also generate quorums with rpgp
(`test_server::make_fixture`), so dropping these files would cost only the cross-implementation
check.
