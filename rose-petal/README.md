# rose-petal

The shard holder's client for a [rose](https://github.com/fathom-x/rose) enclave deployment:
[Locksmith](https://codeberg.org/caution/locksmith)'s recovery protocol in pure Rust, plus a
Nitro attestation checker. Two binaries over one library, published from the same tree as
`rosed` and `rose-cli`.

A deployment of `rosed` in an AWS Nitro enclave starts with no secrets. Locksmith's daemon
inside the enclave waits for a threshold of holders to release their Shamir shares of the
quorum secret, recombines it and decrypts the wallet's secrets with it. `rose-petal` is what
a holder runs on their own machine to release one share:

```sh
rose-petal send <host[:port]> trusted_hashes.json quorum-bundle.json --keyring holder.private.asc
```

It decrypts and checks the holder's share first, then connects (port 49504 by default), sends
a fresh nonce, verifies the enclave's attestation document (the chain to AWS's Nitro root,
the ES384 signature, PCR0-2 against the hashes file, the nonce), derives an AES-256-GCM key
from an X25519 exchange with the attested public key, encrypts the share request to it, signs
the encrypted request with the holder's OpenPGP key and sends it. Exit 0 when the enclave
accepted the share, 1 when it rejected it (the reason on stdout) or anything failed, 2 for
usage. All-zero PCRs in the hashes file mean a debug enclave whose attestation proves
nothing; they are refused unless `--allow-zero-pcrs`.

```sh
rose-petal inspect quorum-bundle.json [--keyring holder.private.asc]   # what the bundle says
rose-petal import quorum-bundle.json --keyring holder.private.asc -o imported.json
attestation-check --document attestation.json --pcrs trusted_hashes.json --nonce <base64> [--instance i-...] [--archived]
```

`inspect` prints the bundle's form, label and declared quorum and, with a keyring, the
threshold, the holders in shard order and this keyring's position from the encrypted
metadata. `import` writes upstream's ImportedV0 artifact for a raw V0 bundle, which the
current Locksmith daemon takes with `--allow-legacy` and whose content hash both sides then
check. `attestation-check` verifies a saved document against a deployment's record and prints
a JSON verdict, one entry per check; `--archived` checks the chain at the document's own
timestamp (the leaf certificate lives three hours), which proves what was true when it was
issued, not that the enclave is up now.

## The library

- `nitro`: parse a document, verify it against a `Pcrs` set at a time (`At::now()` with a
  minute of forward skew, or `At::DocumentTimestamp`) and an expected nonce.
- `bundle`: the three bundle forms (raw V0, ImportedV0, proofed V1), the shardfile decoder
  (keyfork-shard's layout: a metadata message encrypted to every holder, then one signed
  share message per holder, every recipient anonymous), and the content hash (canonical CBOR
  as serde_cbor orders it, pinned against upstream's contract fixture).
- `holder`: a holder's transferable secret keys, which holder they are (by fingerprint among
  the metadata's holders, needing both a signing and a storage-encryption secret key), their
  share (exactly one good inner signature by the quorum's signing certificate, the coordinate
  checked), and the text-mode detached signature over the request, stamped thirty seconds in
  the past because the enclave refuses a signature from its future.
- `protocol`: the frames (a 4-byte length, a SHA-256, a JSON body; 32..=1 MiB), the session
  (HKDF-SHA256 over the X25519 secret, info `key` and `nonce`), the request and reply models
  with their exact field order, and `send_shard`.
- `test_server` (feature `test-server`): an in-process stand-in that applies every rule the
  upstream daemon applies, over a synthetic attestation signed by a public test leaf, for
  the end-to-end tests and for a deployment's rehearsal (`rose-petal test-server`, with the
  rehearsal-only `--trust-root` and `--verify-at` flags on `send`).

The protocol the client speaks is upstream Locksmith's as of 2026-10 (bundle hash, holder
binding, frame bounds, clock skew), a superset of what the daemon pinned by the first
deployment enforces, so one client serves both. Caution's hosted WebAuthn release flow and
the V1 necroproof (the Keymaker enclave's attestation over a bundle, the daemon's to check
under a PCR policy) are out of scope.

## Dependencies

All from crates.io, no C beyond `ring`'s: `tokio`, `serde`, `serde_json`, `sha2`, `hex`,
`x25519-dalek`, `hkdf`, `aes-gcm`, `rand`, `zeroize`, `coset` and `ciborium` for the COSE
document, `rustls-webpki` on `ring` for the certificate chain and ES384, `pgp` (rpgp) for the
shard's ECDH decryption and the holder's EdDSA signature, `rpassword` for a locked keyring,
`base64` for the checker's inputs. MIT OR Apache-2.0, like the rest of rose.

## Fixtures

`tests/fixtures/attestation/`: a real document from an enclave with its PCRs and nonce
(`aws-test.cbor`, bootproof's), AWS's root, bootproof's synthetic test root, leaf and key
(public test data, MIT), and the document and hashes a rose deployment recorded on
2026-10-28 (fetched with its deployed commit as the nonce). `tests/fixtures/locksmith-v0/`:
Locksmith's frozen 2-of-2 V0 fixture, dealt by keyfork-shard from the secret `[7; 32]`
(sequoia-made, so it is the interoperability check for the decoder, the inner signature and
the Shamir field), the two holders' public test keys, the imported artifact, and the V1
contract fixture that pins the bundle hash. None of it is secret.
