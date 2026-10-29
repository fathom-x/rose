#!/usr/bin/env bash
# The holder tools, built from Locksmith's pinned source in Locksmith's own StageX image
# (static musl, reproducible): locksmith-send-shard (locksmith-send-shard.rs, Locksmith's
# shard client at an address of the caller's choosing, for a self-hosted enclave) and
# attestation-check (attestation-check/src/main.rs, bootproof's verifier over a saved
# document; also its own cargo crate for a plain `cargo build`). The image is tagged by a
# digest of its inputs (the Locksmith commit, the two sources, this script), so a change
# rebuilds and an unchanged tree reuses the image. Several minutes.
#
#   contrib/holder-tools/build.sh [--rebuild] [--out DIR]
#
# Prints the image tag. With --out, copies the two binaries into DIR as
# locksmith-send-shard-linux-<arch> and attestation-check-linux-<arch>, the names the
# release uses. The holder-tools workflow runs this for the linux release assets, and a
# deployment repository reruns it to check that a release reproduces (rose-deploy's
# `scripts/holder-tools.sh pin`). Needs docker with BuildKit. A holder never runs this:
# they install the released binaries their deployment pins.
set -euo pipefail
LOCKSMITH_REPO=https://codeberg.org/caution/locksmith
LOCKSMITH_COMMIT=7b411721068944fcae89acb3ed2b8c692689383f   # 2026-09-02
rebuild=""; out=""
while [ $# -gt 0 ]; do case "$1" in
  --rebuild) rebuild=1; shift;; --out) out=$2; shift 2;;
  *) echo "usage: $0 [--rebuild] [--out DIR]" >&2; exit 2;; esac; done
case "$out" in ""|/*) ;; *) out=$PWD/$out;; esac   # relative to the caller, not to this directory
self=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
cd "$(dirname "$self")"
command -v docker >/dev/null || { echo "error: docker is required (the tools build in Locksmith's StageX image)" >&2; exit 1; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; }
inputs=$(cat "$self" locksmith-send-shard.rs attestation-check/src/main.rs | sha256 | cut -c1-12)
IMAGE=rose-holder-tools:${LOCKSMITH_COMMIT:0:12}-$inputs
if [ -n "$rebuild" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "building $IMAGE from $LOCKSMITH_REPO@${LOCKSMITH_COMMIT:0:7} (several minutes)" >&2
  work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
  git clone -q "$LOCKSMITH_REPO" "$work/locksmith" && git -C "$work/locksmith" checkout -q "$LOCKSMITH_COMMIT"
  cp locksmith-send-shard.rs "$work/locksmith/crates/locksmith/src/bin/locksmith-send-shard.rs"
  cp attestation-check/src/main.rs "$work/locksmith/crates/locksmith/src/bin/attestation-check.rs"
  sed -e 's/--bin keymaker/--bin locksmith-send-shard --bin attestation-check/' \
      -e 's|^COPY --from=build /target/\*-unknown-linux-musl/release/keymaker /$|COPY --from=build /target/*-unknown-linux-musl/release/locksmith-send-shard /target/*-unknown-linux-musl/release/attestation-check /|' \
    "$work/locksmith/Containerfile" > "$work/locksmith/Containerfile.tools"
  grep -q 'attestation-check /$' "$work/locksmith/Containerfile.tools" || { echo "error: Locksmith's Containerfile changed shape; update this script" >&2; exit 1; }
  docker build -q -f "$work/locksmith/Containerfile.tools" -t "$IMAGE" "$work/locksmith" >/dev/null
fi
echo "$IMAGE"
if [ -n "$out" ]; then
  arch=$(uname -m); case $arch in x86_64) arch=amd64;; aarch64) arch=arm64;; esac
  mkdir -p "$out"
  id=$(docker create "$IMAGE" /attestation-check)
  docker cp "$id:/locksmith-send-shard" "$out/locksmith-send-shard-linux-$arch"
  docker cp "$id:/attestation-check" "$out/attestation-check-linux-$arch"
  docker rm "$id" >/dev/null
  chmod 755 "$out/locksmith-send-shard-linux-$arch" "$out/attestation-check-linux-$arch"
fi
