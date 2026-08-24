//! The BDK-backed Bitcoin wallet engine, behind the `bitcoin` cargo feature.
//!
//! A coin is an engine, not a parameter (see the shared-layer boundary in the project docs): this module
//! is the Bitcoin counterpart of the librustzcash-backed `wallet/`+`sync/`+`chain/` stack,
//! self-contained behind the two sanctioned seams - the wallet registry
//! (`wallet::CoinWallet`) and the RPC handlers. No `bdk_wallet` type may appear in a shared
//! signature, config struct, or cross-coin enum; everything the engine needs from BDK arrives
//! through the one `bdk_wallet` dependency (which re-exports `bitcoin`, `miniscript` and
//! `bdk_chain`).
//!
//! Phase 1 scope: key derivation from the shared BIP-39 seed (BIP 84 descriptors), on-disk
//! persistence over zecd's own rusqlite, a single-writer actor mirroring the Zcash one, and
//! the wallet-shaped read slice of the RPC surface. Chain access (a bitcoind or Electrum
//! backend feeding sync) is the next phase; until it lands a Bitcoin wallet reports itself
//! unsynced and its balances reflect only what the local database holds.

pub mod actor;
pub mod keys;
pub mod store;
