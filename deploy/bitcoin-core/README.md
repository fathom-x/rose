# Bitcoin Core release provenance (v30.4)

The pinned Bitcoin Core release that the BDK engine's tooling runs against - the CI
`btc-e2e` job (`.github/workflows/regtest.yml`) and the manual regtest stack
(`../docker-compose.btc-regtest.yml`, plus its public-testnet siblings
`../docker-compose.btc-testnet{3,4}.yml`). Two files, both copied verbatim from
`https://bitcoincore.org/bin/bitcoin-core-30.4/` and independently verified before commit:

- `SHA256SUMS` - the release's checksum manifest, covering every 30.4 artifact (the CI
  job checks its linux-x86_64 tarball against this file; the macOS/ARM lines serve manual
  downloads). Verified two ways on 2026-10-28 (30.2's copy had been verified the same way on
  2026-08-25):
  - **Reproducible-build attestations**: 12 independent builders in
    <https://github.com/bitcoin-core/guix.sigs> (`30.4/*/all.SHA256SUMS`) attest the same
    artifact hashes this file carries (all 28 lines, checked line by line).
  - **OpenTimestamps**: this file's own sha256
    (`d1c70ff2bc5af4318c61323753528625a8cb46f518f1a769c5004afbbdf65426`) is committed into
    the Bitcoin blockchain by the proof below.
- `SHA256SUMS.ots` - the release's OpenTimestamps proof, **upgraded** (the calendar
  attestations have been resolved to their Bitcoin block anchors: mainnet heights 973549,
  973564 and 973580, mined 2026-10-28, the release day, hours before this copy was
  fetched; the three merkle roots were read back from our own mainnet node, so the proof
  was verified with zero third-party trust). 30.4 was fetched on its release day because
  it fixes a disclosed denial of service (the paused-peer send queue, bitcoin/bitcoin#36667), so the
  anchors are not months old as 30.2's were; the builder consensus above is the stronger
  check in that case. Committing the upgraded proof makes re-verification
  self-contained: against a synced mainnet bitcoind,

  ```sh
  pip install opentimestamps-client
  ots verify SHA256SUMS.ots      # completes with zero third-party trust
  ```

Bumping the pinned version = replacing both files and re-running the same two checks:
download the new `SHA256SUMS` + `SHA256SUMS.ots`, cross-check against `guix.sigs/<ver>/`
(`grep <tarball> */all.SHA256SUMS | sort | uniq -c` - expect a broad builder consensus),
`ots upgrade SHA256SUMS.ots`, verify, commit. Update the version in the CI job and the
compose files in the same change.
