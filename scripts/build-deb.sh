#!/usr/bin/env bash
#
# Build a reproducible Debian package (.deb) for rose from the two pre-built binaries, the
# `rosed` daemon and the `rose` command line.
#
# The binaries themselves are expected to already be *reproducible* artifacts - in CI they are
# extracted from the `export` stage of the StageX (amd64) / pinned-Alpine (arm64)
# Dockerfiles, which carry all the determinism flags (SOURCE_DATE_EPOCH, codegen-units=1,
# --build-id=none) and produce a static musl binary on both architectures. This script only
# wraps that binary, so it must not reintroduce nondeterminism: every file gets a fixed mtime
# (SOURCE_DATE_EPOCH), `dpkg-deb --root-owner-group` pins uid/gid to root:root, and gzip is
# invoked with `-n` so the changelog has no embedded name/timestamp. dpkg-deb (>= 1.18.11) then
# honors SOURCE_DATE_EPOCH for the ar member timestamps, yielding a bit-for-bit identical .deb.
#
# Usage:
#   scripts/build-deb.sh <rosed-path> <rose-path> <version> <deb-arch> <output-dir>
#
#   <rosed-path>   path to the compiled `rosed` daemon binary
#   <rose-path>    path to the compiled `rose` command-line binary
#   <version>      package version, e.g. 0.1.0 (no leading "v")
#   <deb-arch>     Debian architecture: amd64 | arm64
#   <output-dir>   directory the .deb is written to (created if missing)

set -euo pipefail

DAEMON_PATH="${1:?usage: build-deb.sh <rosed-path> <rose-path> <version> <deb-arch> <output-dir>}"
CLI_PATH="${2:?missing rose-path}"
VERSION="${3:?missing version}"
DEB_ARCH="${4:?missing deb-arch}"
OUTPUT_DIR="${5:?missing output-dir}"

# Determinism anchor - keep in lockstep with the Dockerfiles' SOURCE_DATE_EPOCH.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
chmod 0755 "$STAGE"   # mktemp -d is 0700; the package root (./) should be world-readable

# --- Filesystem layout -----------------------------------------------------------------
install -D -m 0755 "$DAEMON_PATH"                       "$STAGE/usr/bin/rosed"
install -D -m 0755 "$CLI_PATH"                          "$STAGE/usr/bin/rose"
install -D -m 0644 "$REPO_ROOT/rose.example.toml"       "$STAGE/usr/share/doc/rose/rose.example.toml"
install -D -m 0644 "$REPO_ROOT/README.md"               "$STAGE/usr/share/doc/rose/README.md"
# Third-party license bundle - rose is statically linked, so these notices ship with it.
install -D -m 0644 "$REPO_ROOT/THIRD-PARTY-LICENSES.txt" "$STAGE/usr/share/doc/rose/THIRD-PARTY-LICENSES.txt"

# systemd unit (installed, not enabled - the admin opts in with `systemctl enable rose`).
install -D -m 0644 /dev/stdin "$STAGE/lib/systemd/system/rose.service" <<'UNIT'
[Unit]
Description=rose - Bitcoin-Core-style JSON-RPC server for shielded-first Zcash
Documentation=https://github.com/fathom-x/rose
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=rose
Group=rose
ExecStart=/usr/bin/rosed --datadir /var/lib/rose
Restart=on-failure
RestartSec=5

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/lib/rose

[Install]
WantedBy=multi-user.target
UNIT

# Debian copyright file (dual MIT / Apache-2.0).
install -D -m 0644 /dev/stdin "$STAGE/usr/share/doc/rose/copyright" <<'COPYRIGHT'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: rose
Source: https://github.com/fathom-x/rose

Files: *
Copyright: The rose authors
License: MIT or Apache-2.0
 rose is dual-licensed under the MIT and Apache-2.0 licenses. The full texts are
 distributed with the source at https://github.com/fathom-x/rose
 (LICENSE-MIT and LICENSE-APACHE). The licenses of the third-party crates compiled
 into the statically linked binary are reproduced in
 /usr/share/doc/rose/THIRD-PARTY-LICENSES.txt.
COPYRIGHT

# Debian changelog (gzip -n keeps it timestamp/name free for reproducibility).
CHANGELOG_TMP="$(mktemp)"
cat > "$CHANGELOG_TMP" <<CHANGELOG
rose (${VERSION}) unstable; urgency=medium

  * Release ${VERSION}. See https://github.com/fathom-x/rose/releases for notes.

 -- rose <noreply@users.noreply.github.com>  Thu, 01 Jan 1970 00:00:00 +0000
CHANGELOG
gzip -9nc "$CHANGELOG_TMP" > "$STAGE/usr/share/doc/rose/changelog.Debian.gz"
chmod 0644 "$STAGE/usr/share/doc/rose/changelog.Debian.gz"
rm -f "$CHANGELOG_TMP"

# --- Control archive -------------------------------------------------------------------
INSTALLED_SIZE="$(du -k -s "$STAGE/usr" | cut -f1)"
install -D -m 0644 /dev/stdin "$STAGE/DEBIAN/control" <<CONTROL
Package: rose
Version: ${VERSION}
Architecture: ${DEB_ARCH}
Maintainer: rose <noreply@users.noreply.github.com>
Installed-Size: ${INSTALLED_SIZE}
Section: net
Priority: optional
Homepage: https://github.com/fathom-x/rose
Description: Bitcoin-Core-style JSON-RPC wallet server (Bitcoin and Zcash)
 rose speaks bitcoind's JSON-RPC dialect (method names, response shapes, error
 codes, HTTP auth) over a BDK Bitcoin wallet engine (a local bitcoind or the
 kyoto light client) and a librustzcash Zcash engine (Ironwood, Orchard and
 Sapling, plus opt-in transparent, against a local zebrad). The package ships
 the rosed daemon and the rose command line.
CONTROL

# conffiles: none under /etc - the example config ships read-only under /usr/share/doc.

# Maintainer scripts: create the service user/datadir and refresh systemd.
install -D -m 0755 /dev/stdin "$STAGE/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    if ! getent group rose >/dev/null; then
        addgroup --system rose
    fi
    if ! getent passwd rose >/dev/null; then
        adduser --system --ingroup rose --home /var/lib/rose \
            --no-create-home --gecos "rose daemon" rose
    fi
    install -d -o rose -g rose -m 0750 /var/lib/rose
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
fi
exit 0
POSTINST

install -D -m 0755 /dev/stdin "$STAGE/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "deconfigure" ]; then
    if [ -d /run/systemd/system ]; then
        systemctl stop rose.service >/dev/null 2>&1 || true
    fi
fi
exit 0
PRERM

install -D -m 0755 /dev/stdin "$STAGE/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
POSTRM

# --- Normalize mtimes, then build -------------------------------------------------------
# Clamp every path to SOURCE_DATE_EPOCH so the data/control tarballs are byte-stable.
find "$STAGE" -exec touch --no-dereference --date="@${SOURCE_DATE_EPOCH}" {} +

mkdir -p "$OUTPUT_DIR"
DEB_PATH="${OUTPUT_DIR}/rose_${VERSION}_${DEB_ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB_PATH"

echo "$DEB_PATH"
