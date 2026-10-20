# rose-cli

`rose` is the operator's command line for [`rosed`](https://crates.io/crates/rosed), a
Bitcoin-Core-style JSON-RPC wallet server. It is two tools in one binary, modeled on
`bitcoin-cli` plus Bitcoin Core's wallet tooling:

- **Wallet setup and configuration**: `rose init`, `rose rescan`, `rose config check|show`,
  `rose derive-address`, `rose export-xpub` / `export-ufvk`, `rose rpcauth`,
  `rose example-config`, `rose licenses`, `rose chain-info`.
- **A JSON-RPC client**: any other first word is a method sent to the running daemon -
  `rose getbalance`, `rose --rpcwallet btc listunspent 1`, `rose sendtoaddress <address>
  0.001` - each parameter parsed as JSON, else taken as a string. The daemon is found through
  the same configuration `rosed` reads (`--conf`, `--datadir`, `[rpc]`), its cookie file or
  `--rpcuser`/`--rpcpassword`; results print as `bitcoin-cli` prints them, and an RPC error is
  reported as `error code:` / `error message:` with the code's magnitude as the exit status.

```sh
cargo install rosed rose-cli            # the daemon and this command line
rose --datadir ./data --testnet init --wallet btc
rosed --datadir ./data --testnet         # serves JSON-RPC; writes <datadir>/.cookie
rose --datadir ./data --testnet getblockchaininfo
```

The default build serves Bitcoin wallets (BDK, over a local bitcoind or the kyoto BIP-157
light client); `--features zcash` adds the Zcash engine, matching `rosed`'s own features.
The full documentation is `rosed`'s README; both crates are released together from
[fathom-x/rose](https://github.com/fathom-x/rose).

Dual-licensed under MIT or Apache-2.0.
