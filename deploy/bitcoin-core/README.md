# Bitcoin Core release provenance (v30.2)

The pinned Bitcoin Core release that the BDK engine's tooling runs against - the CI
`btc-e2e` job (`.github/workflows/regtest.yml`) and the manual regtest stack
(`../docker-compose.btc-regtest.yml`, plus its public-testnet siblings
`../docker-compose.btc-testnet{3,4}.yml`). Two files, both copied verbatim from
`https://bitcoincore.org/bin/bitcoin-core-30.2/` and independently verified before commit:

- `SHA256SUMS` - the release's checksum manifest, covering every 30.2 artifact (the CI
  job checks its linux-x86_64 tarball against this file; the macOS/ARM lines serve manual
  downloads). Verified two ways on 2026-08-25:
  - **Reproducible-build attestations**: 15 independent builders in
    <https://github.com/bitcoin-core/guix.sigs> (`30.2/*/all.SHA256SUMS`) attest the same
    artifact hashes this file carries.
  - **OpenTimestamps**: this file's own sha256
    (`11113f40ed9e963fbe98e37751818929a2dd53cea0588452fc0b9fbb24bf2405`) is committed into
    the Bitcoin blockchain by the proof below.
- `SHA256SUMS.ots` - the release's OpenTimestamps proof, **upgraded** (the calendar
  attestations have been resolved to their Bitcoin block anchors: mainnet heights 931734,
  931756 and 931820, mined 2026-01-10 - months before this copy was fetched, so the
  manifest provably predates it and cannot have been minted for our download). Committing
  the upgraded proof makes re-verification self-contained: against a synced mainnet
  bitcoind,

  ```sh
  pip install opentimestamps-client
  ots verify SHA256SUMS.ots      # completes with zero third-party trust
  ```

Bumping the pinned version = replacing both files and re-running the same two checks:
download the new `SHA256SUMS` + `SHA256SUMS.ots`, cross-check against `guix.sigs/<ver>/`
(`grep <tarball> */all.SHA256SUMS | sort | uniq -c` - expect a broad builder consensus),
`ots upgrade SHA256SUMS.ots`, verify, commit. Update the version in the CI job and the
compose files in the same change.
