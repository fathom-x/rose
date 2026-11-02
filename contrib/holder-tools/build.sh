#!/usr/bin/env bash
# The holder tools for Linux, built reproducibly: `rose-petal` (the shard client, the
# `rose-petal` crate) and `attestation-check` (the Nitro attestation checker, a second binary
# of the same crate), as static musl binaries from this tree in the same pinned
# `rust:alpine` image `Dockerfile.arm64` builds the product from, with the same determinism
# knobs (SOURCE_DATE_EPOCH, CARGO_INCREMENTAL=0, codegen-units=1, +crt-static,
# --build-id=none, a fixed build path). A deployment repository reruns this to check that a
# release reproduces before pinning it (rose-deploy's `scripts/holder-tools.sh pin`); the
# holder-tools workflow runs it for the linux-amd64 release assets. A holder never runs it:
# they install the released binaries their deployment pins.
#
#   contrib/holder-tools/build.sh [--out DIR]
#
# With --out, copies the two binaries into DIR as rose-petal-linux-<arch> and
# attestation-check-linux-<arch>, the names the release uses. Needs docker and network
# access (cargo fetches the locked dependencies). Several minutes on a cold cache.
set -euo pipefail
# rust:1.97.1-alpine3.24 by its multi-arch index digest: keep in lockstep with Dockerfile.arm64.
IMAGE=rust:1.97.1-alpine3.24@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900
out=""
while [ $# -gt 0 ]; do case "$1" in
  --out) out=$2; shift 2;;
  *) echo "usage: $0 [--out DIR]" >&2; exit 2;; esac; done
case "$out" in ""|/*) ;; *) out=$PWD/$out;; esac   # relative to the caller, not to this directory
root=$(cd "$(dirname "$0")/../.." && pwd)
command -v docker >/dev/null || { echo "error: docker is required (the tools build in the pinned rust:alpine image)" >&2; exit 1; }
arch=$(uname -m); case $arch in x86_64) arch=amd64; target=x86_64-unknown-linux-musl;; aarch64) arch=arm64; target=aarch64-unknown-linux-musl;; *) echo "error: unsupported architecture $arch" >&2; exit 1;; esac
# The container runs as root (apk and the cargo registry need it) and hands the tree back to
# this user before it exits; should it die first, a root-owned target/ stays in $work, which
# the trap then cannot remove: say so, never fail a finished build over it.
work=$(mktemp -d); trap 'rm -rf "$work" 2>/dev/null || echo "note: could not remove $work (root-owned build files); remove it with sudo" >&2' EXIT
# The tree as git has it (a clean export, so a dirty checkout or a target/ never leaks in),
# at the fixed path the build runs from. A deployment's pin runs this script from a `git
# archive` of the product commit, which is already that export and has no repository: copy it.
if git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$root" archive --format=tar --prefix=rose/ HEAD | tar -x -C "$work"
else
  mkdir -p "$work/rose" && tar -C "$root" --exclude=./target -cf - . | tar -x -C "$work/rose"
fi
docker run --rm \
  -v "$work/rose:/usr/src/rose" -w /usr/src/rose \
  -e RUSTUP_TOOLCHAIN=1.97.1 -e SOURCE_DATE_EPOCH=1 -e CARGO_INCREMENTAL=0 -e CARGO_NET_RETRY=10 \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  -e RUSTFLAGS="-C codegen-units=1 -C target-feature=+crt-static -C link-arg=-Wl,--build-id=none" \
  "$IMAGE" sh -euc "
    apk add --no-cache build-base=0.5-r4 gcc=15.2.0-r5 g++=15.2.0-r5 musl-dev=1.2.6-r2 binutils=2.45.1-r1 make=4.4.1-r4 >/dev/null
    cargo build --release --locked --offline -p rose-petal --bins --target $target 2>/dev/null \
      || cargo build --release --locked -p rose-petal --bins --target $target
    install -d /usr/src/rose/.built
    install -m 0755 target/$target/release/rose-petal target/$target/release/attestation-check /usr/src/rose/.built/
    chown -R \"\$HOST_UID:\$HOST_GID\" /usr/src/rose
  "
# The binaries land in .built/, not the tree root: rose-petal/ there is the crate's directory.
sha256sum "$work/rose/.built/rose-petal" "$work/rose/.built/attestation-check" | sed "s|$work/rose/.built/||"
if [ -n "$out" ]; then
  mkdir -p "$out"
  install -m 0755 "$work/rose/.built/rose-petal" "$out/rose-petal-linux-$arch"
  install -m 0755 "$work/rose/.built/attestation-check" "$out/attestation-check-linux-$arch"
fi
