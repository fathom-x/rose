# syntax=docker/dockerfile:1
#
# Reproducible multi-stage build on StageX (https://stagex.tools), mirroring zallet's
# Dockerfile: every base image is full-source-bootstrapped and pinned by digest, the
# binaries are statically linked against musl, and the build is deterministic
# (SOURCE_DATE_EPOCH, codegen-units=1, --build-id=none) so independent builders can
# reproduce the image bit-for-bit. (Until `age` 0.12 that also required a vendored
# i18n-embed-fl patch; age now depends on i18n-embed-fl 0.10, which carries the fix, so the
# tree has no [patch.crates-io] entries at all.)
#
#   docker build -t rose .                      # the image (the runtime image, nothing baked in)
#   docker build --target export -o ./out .     # extract the static binaries
#   docker build --target enclave --build-arg ROSE_BAKE=<dir> .   # + a file tree baked in (a TEE deployment)
#
# A deployment repository that carries this tree as a subtree builds it from its own root:
#   docker build -f rose/Dockerfile --build-arg ROSE_SRC=rose --build-arg ROSE_BAKE=bake \
#     --build-arg ROSE_CARGO_FEATURES="--no-default-features --features bitcoin,server,cli" \
#     --build-arg ROSE_CLI_CARGO_FEATURES="--no-default-features --features bitcoin" .
#
# Dependencies are released crates from crates.io - the Zakura Common `zakura-*` forks of
# librustzcash plus the upstream crates they leave in place (versions pinned by the committed
# Cargo.lock), so the build needs network access to fetch them.

# Rust 1.97 is the Zakura Common 4.0 family's MSRV. The digest is the linux/amd64 manifest
# within the tag's index, like the other pins here.
FROM stagex/pallet-rust:1.97.1@sha256:6033fb215dd7c87c885dd7b1c12de42464606dcc0323fc57339318d61f010a30 AS pallet-rust
# protoc (+ the abseil it links) is needed by zcash_client_backend's build script.
FROM stagex/user-protobuf:26.1@sha256:b399bb058216a55130d83abcba4e5271d8630fff55abbb02ed40818b0d96ced1 AS protobuf
FROM stagex/user-abseil-cpp:20240116.2@sha256:183e8aff7b3e8b37ab8e89a20a364a21d99ce506ae624028b92d3bed747d2c06 AS abseil-cpp
FROM stagex/core-ca-certificates:sx2026.05.0@sha256:f5b60a5f79003c039d4994269d7a646cc039d657d5c1503104467381b476f6fa AS ca-certificates

# --- Stage 1: Build with Rust --- (amd64)
FROM pallet-rust AS builder
COPY --from=protobuf . /
COPY --from=abseil-cpp . /

ENV SOURCE_DATE_EPOCH=1
ENV TARGET_ARCH=x86_64-unknown-linux-musl
ENV CFLAGS=-target\ x86_64-unknown-linux-musl
ENV CARGO_HOME=/usr/local/cargo
ENV CARGO_TARGET_DIR="/usr/src/rose/target"
ENV CARGO_INCREMENTAL=0
ENV RUST_BACKTRACE=1
# Resilience against transient crates.io fetch flakes in CI (seen as curl "[16] Error in the
# HTTP2 framing layer"). Such HTTP/2 errors are classified spurious/retryable by cargo since
# rust-lang/cargo#6861, so a higher retry count is the right lever - no protocol downgrade
# needed. Network-only knob - it doesn't affect the emitted binary, so the build stays
# bit-for-bit reproducible.
ENV CARGO_NET_RETRY=10
ENV RUSTFLAGS="\
-C codegen-units=1 \
-C target-feature=+crt-static \
-C linker=clang \
-C link-arg=-fuse-ld=lld \
-C link-arg=-Wl,--allow-multiple-definition \
-C link-arg=-ldl \
-C link-arg=-lm \
-C link-arg=-Wl,--build-id=none"
WORKDIR /usr/src/rose
# Where this tree sits in the build context: `.` when it is the context, `rose` for a
# deployment repository that carries it as a subtree and builds with its own root as the
# context (so its bake tree, below, is in the context too). The layer's content is the
# same either way; the deployment's `.dockerignore` must allow the same files this one does.
ARG ROSE_SRC=.
COPY ${ROSE_SRC}/ .
# The cargo feature flags of the shipped daemon. The default is the image everyone gets:
# both engines, so one image serves a Zcash or a Bitcoin wallet (a bare `cargo build` is
# Bitcoin-only; `zcash` is the opt-in). A deployment that needs one engine builds a smaller
# binary faster by overriding this ARG - the enclave deployment passes the Bitcoin-only
# set, `--no-default-features --features bitcoin,server,cli`, dropping the
# Zcash stack's ~190 crates. Only features change; the runtime contract below does not.
ARG ROSE_CARGO_FEATURES="--features bitcoin,zcash"
# The same choice for the `rose` command line (rose-cli/), whose engine features mirror the
# daemon's (no allocator feature: it proves nothing). Keep the two ARGs on the same engines.
ARG ROSE_CLI_CARGO_FEATURES="--features bitcoin,zcash"

# Fetch dependencies
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo fetch \
        --locked \
        --target ${TARGET_ARCH}

# Build the two rose binaries: `rosed` (the daemon) and `rose` (the command line)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/src/rose/target \
    cargo install \
        --frozen \
        --path . \
        --bin rosed \
        --target ${TARGET_ARCH} \
        # musl's own malloc-ng is ~5-6x slower than glibc under Orchard proving's
        # multi-threaded allocation churn, and the `mimalloc-secure` feature exists to replace
        # it with hardened mimalloc (Dockerfile.arm64 takes it). Not here: StageX's musl (from
        # the 1.97.1 pallet) already does - its libc.a carries `mimalloc-secure.o` as `malloc`,
        # so `System` is hardened mimalloc with no crate. Linking the crate as well puts a
        # second, different mimalloc beside it, and `--allow-multiple-definition` (above)
        # merges the two copies' shared globals (`_mi_heap_main` among them): the binary died
        # with SIGBUS on its first realloc, before printing `--version`. So the ARG's default
        # names no allocator feature, and a deployment overriding it must not add one.
        # `zcash` is the librustzcash wallet engine, off by default for `cargo build`; the
        # shipped image carries both engines so one image serves a Zcash or a Bitcoin wallet
        # (a binary without an engine refuses its `coin` at config resolve).
        # THIRD-PARTY-LICENSES.txt is generated with `mimalloc-secure` as well (the arm64
        # image's set, a superset of this one) - keep scripts/generate-licenses.sh in step.
        ${ROSE_CARGO_FEATURES} \
    && cargo install \
        --frozen \
        --path rose-cli \
        --bin rose \
        --target ${TARGET_ARCH} \
        ${ROSE_CLI_CARGO_FEATURES} \
    # Skeleton dirs for the scratch runtime, COPY'd below with --chown so the
    # unprivileged runtime user can write its datadirs (and SQLite its temp files).
    && install -d -m 0755 /rootfs/var/lib/rose \
    && install -d -m 1777 /rootfs/tmp \
    # The license texts, staged with their modes pinned in-container: a file COPY'd straight
    # from the build context keeps the mode git checked it out with, which is the build
    # host's umask (0644 or 0664) - identical content, one mode bit apart, and any
    # measurement over the image (a Nitro enclave's PCR, say) differs by host. `install -m`
    # is immune; the runtime stage copies this directory rather than the context files.
    && install -d -m 0755 /licenses \
    && install -m 0644 LICENSE-MIT LICENSE-APACHE THIRD-PARTY-LICENSES.txt /licenses/

# --- Stage 2: layer for local binary extraction ---
FROM scratch AS export

# Binaries at the root for easy extraction
COPY --from=builder /usr/local/cargo/bin/rosed /rosed
COPY --from=builder /usr/local/cargo/bin/rose /rose

# --- Stage 3: Minimal runtime with stagex ---
FROM scratch AS runtime
COPY --from=export /rosed /usr/local/bin/rosed
COPY --from=export /rose /usr/local/bin/rose
# License texts - rose is statically linked, so the third-party notices ship with it.
COPY --from=builder /licenses/ /usr/share/doc/rose/
# CA bundle so native TLS roots can validate public lightwalletd endpoints (e.g. zec.rocks).
COPY --from=ca-certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
COPY --from=builder --chown=10001:10001 /rootfs/ /
USER 10001:10001
WORKDIR /var/lib/rose
# rose JSON-RPC (mainnet 8232 / testnet 18232) + health (9233).
EXPOSE 8232 18232 9233
# The daemon. The command line is beside it: `docker run --entrypoint rose ... init`.
ENTRYPOINT ["rosed"]
CMD ["--datadir", "/var/lib/rose"]

# --- Stage 4: the enclave image: the runtime image plus a file tree baked in ---
#
# A TEE deployment (a Caution or AWS Nitro enclave; docs/dev/BUILD_AND_RELEASE.md) runs the
# runtime image with its configuration and its sealed secrets inside the image, since the
# enclave has no storage and no shell: rose.toml, Locksmith's quorum bundle and the
# encrypted secrets, each at the path the enclave reads it from. ROSE_BAKE names a directory
# in the build context laid out as the root filesystem it is copied onto
# (etc/rose/rose.toml, etc/caution/bundle.json, etc/caution/secrets/<NAME>.asc). The
# default is an empty tree, so `docker build .` (this stage is the last, hence the default
# target) is the runtime image with nothing added; `--target runtime` is that image without
# this stage's empty layer. The tree is staged in a stage with a shell and its modes pinned
# there, never COPY'd straight onto the runtime image: an enclave measures the filesystem
# verbatim (Nitro's PCR2), and a context file keeps the build host's umask (the rule the
# license texts follow above). A `.keep` placeholder is dropped, nothing else is.
FROM builder AS enclave-files
ARG ROSE_BAKE=deploy/bake
COPY ${ROSE_BAKE}/ /staged/
RUN find /staged -name .keep -delete \
    && find /staged -type d -exec chmod 0755 {} + \
    && find /staged -type f -exec chmod 0644 {} +

FROM runtime AS enclave
COPY --from=enclave-files /staged/ /
