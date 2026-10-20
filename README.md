# rose: a Bitcoin wallet server

Rose is a Bitcoin wallet server that speaks Bitcoin Core's JSON-RPC: the same method names,
response shapes, authentication and error codes. Most existing bitcoind clients work with it
unchanged.

It runs with or without a node: the built-in [Kyoto](https://github.com/2140-dev/kyoto) light
client follows the chain with BIP 157/158 compact block filters, so a wallet needs nothing but
peers on the Bitcoin network.

### Key features

- Stateless: every wallet is recoverable from its seed phrase (BIP 39, BIP 84 native SegWit).
- Kyoto compact block filter light client built in; your own Bitcoin Core node is optional.
- Watch-only wallets from an account xpub.
- Designed to run inside trusted execution environments (TEEs), supporting AWS Nitro Enclaves
  today.
- Mainnet, testnet4, testnet3 and regtest.

## Two binaries

Rose ships as two crates over one library, released together:

- **`rosed`** ([crates.io](https://crates.io/crates/rosed)) is the daemon, bitcoind's analog:
  no subcommands, `rosed --datadir ./data` serves JSON-RPC. The same crate is the library
  behind it, for embedding the wallet server in a Rust program without a socket in between.
- **`rose`** (the [`rose-cli`](https://crates.io/crates/rose-cli) crate) is its command line:
  wallet setup and configuration (`rose init`, `rose rescan`, `rose config check|show`,
  `rose derive-address`, `rose export-xpub`, `rose rpcauth`, `rose example-config`,
  `rose licenses`, `rose chain-info`) plus a `bitcoin-cli`-style JSON-RPC client - any other
  first word is a method sent to the running daemon (`rose getbalance`,
  `rose --rpcwallet btc listunspent 1`).

```sh
cargo install rosed rose-cli
rose --datadir ./data --testnet init --wallet btc
rosed --datadir ./data --testnet           # serves JSON-RPC; writes <datadir>/.cookie
rose --datadir ./data --testnet getblockchaininfo
```

The default build serves Bitcoin wallets; `--features zcash` adds the Zcash engine. The Docker
images (`ghcr.io/fathom-x/rose`), the release tarballs and the `.deb` ship both binaries with
both engines; the image's entrypoint is `rosed` (`docker run --entrypoint rose ... init` for the
command line). `rose example-config` prints the annotated configuration reference.

## License

Dual-licensed under Apache-2.0 or MIT.
