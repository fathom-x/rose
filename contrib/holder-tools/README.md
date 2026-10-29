# holder-tools

The two programs a shard holder runs on their own machine to unlock an enclave deployment
of rose, built from [Locksmith](https://codeberg.org/caution/locksmith)'s pinned source and
released from this tree so that a deployment's holders need neither docker nor a Rust
toolchain.

| File | What |
|---|---|
| `locksmith-send-shard.rs` | Locksmith's own shard client at an address of the caller's choosing (`locksmith::client::send_shard`): sends a fresh nonce, verifies the enclave's Nitro attestation against the PCRs in a hashes file, takes the enclave's public key from the attested user data, decrypts the holder's shard with their keyring, re-encrypts it to that key and signs the request. For an enclave a deployment hosts itself, where no Caution API knows the address. |
| `attestation-check/` | bootproof's verifier over a saved attestation document (AWS chain and COSE signature, the nonce echoed, PCR0-2 against a hashes file, the module id against an instance), with a JSON verdict. Its own cargo crate, outside the workspace, for a plain `cargo build`. |
| `build.sh` | Both tools as bins of Locksmith's crate at its pinned commit, built in Locksmith's StageX image: static musl, reproducible. |
| `../../.github/workflows/holder-tools.yml` | On every push that changes this directory, builds linux-amd64 (`build.sh`) and darwin-arm64 (plain cargo on a macOS runner, with gmp and nettle built statically from pinned tarballs) and publishes a release `holder-tools-<sha7>` with a `SHA256SUMS`. |

## What a holder trusts

Not the release. A deployment repository (rose-deploy) pins a release in a manifest it
commits under its own developer signature: the tag, the commit it was built from, and the
sha256 of every asset. The holder's install step requires that manifest commit to be signed
through the deployment's key chain, and requires the commit the release was built from to be
signed by a key in this tree's allowlist (`contrib/verify-commits/`, from the holder's
pinned product root), then checks every download against the manifest. The deployment
chooses which release its holders run; this tree's maintainers vouch for the sources it was
built from; and the linux build reproduces, so anyone can rebuild it from the signed commit
and compare (the deployment's `pin` does). The macOS build does not reproduce: its hash
rests on the two signatures alone.

So a release is pinnable only when it was built from a commit signed by a listed key: after
merging a change here, push a signed commit (an empty one will do) and dispatch the workflow
on it, or dispatch it on any later signed commit.
