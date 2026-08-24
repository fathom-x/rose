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

## License

Dual-licensed under Apache-2.0 or MIT.
