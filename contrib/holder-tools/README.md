# holder-tools

The two programs a shard holder runs on their own machine to unlock an enclave deployment
of rose, released from this tree so that a deployment's holders need neither docker nor a
Rust toolchain. Both are binaries of the [`rose-petal`](../../rose-petal/) crate, a
workspace member published to crates.io beside `rosed` and `rose-cli`:

| Binary | What |
|---|---|
| `rose-petal` | The shard client: Locksmith's recovery protocol in pure Rust. `rose-petal send <host[:port]> <trusted_hashes.json> <bundle.json> --keyring <file|dir>` verifies the enclave's Nitro attestation against the PCRs in the hashes file, decrypts this holder's share from the bundle's shardfile, encrypts it to the attested key, signs the request and sends it. `inspect` reads a bundle, `import` writes the ImportedV0 artifact for a raw V0 one. |
| `attestation-check` | A saved attestation document against a deployment's record: the AWS chain and COSE signature, the nonce echoed, PCR0-2 against the hashes file, the module id against an instance, as a JSON verdict. |

This directory keeps only `build.sh`, the reproducible Linux build: both binaries as static
musl from a clean export of the tree, in the pinned `rust:alpine` image `Dockerfile.arm64`
builds the product from, with the same determinism knobs. `.github/workflows/holder-tools.yml`
runs it on every push that changes the crate (or this directory, or the workflow, or
`Cargo.lock`) and publishes a release `holder-tools-<sha7>` with a `SHA256SUMS`: linux-amd64
from `build.sh`, darwin-arm64 with plain cargo on the pinned toolchain on a macOS runner.
Until 2026-10 the tools here were Locksmith's own client and bootproof's verifier, built
from Locksmith's pinned source.

## What a holder trusts

Not the release. A deployment repository (rose-deploy) pins a release in a manifest it
commits under its own developer signature: the tag, the commit it was built from, and the
sha256 of every asset. The holder's install step requires that manifest commit to be signed
through the deployment's key chain, and requires the commit the release was built from to be
signed by a key in this tree's allowlist (`contrib/verify-commits/`, from the holder's
pinned product root), then checks every download against the manifest. The deployment
chooses which release its holders run; this tree's maintainers vouch for the sources it was
built from; and the linux build reproduces, so anyone can rebuild it from the signed commit
and compare (the deployment's `pin` does). The macOS build is made with the same pinned
toolchain and the same determinism flags, so it is expected to reproduce on another Mac with
that toolchain; until a second builder has confirmed it, its hash rests on the two
signatures.

So a release is pinnable only when it was built from a commit signed by a listed key: after
merging a change here, push a signed commit (an empty one will do) and dispatch the workflow
on it, or dispatch it on any later signed commit.
