//! The BDK-backed Bitcoin wallet engine, behind the `bitcoin` cargo feature.
//!
//! A coin is an engine and an engine is a feature (see the shared-layer boundary in the project docs):
//! this module is the Bitcoin counterpart of the librustzcash-backed `wallet/`+`sync/`+
//! `chain/` stack, which rides the `zcash` feature the same way - so zecd builds with either
//! engine or both, and `--no-default-features --features bitcoin,server,cli` is a
//! bitcoin-only daemon carrying no Zcash crate at all. Each is self-contained behind the two
//! sanctioned seams - the wallet registry (`wallet::CoinWallet`) and the RPC handlers. No `bdk_wallet` type may appear in a shared
//! signature, config struct, or cross-coin enum; everything the engine needs from BDK arrives
//! through the one `bdk_wallet` dependency (which re-exports `bitcoin`, `miniscript` and
//! `bdk_chain`).
//!
//! Phase 1 delivered key derivation from the shared BIP-39 seed (BIP 84 descriptors),
//! on-disk persistence over zecd's own rusqlite, a single-writer actor mirroring the Zcash
//! one, and the wallet-shaped read slice of the RPC surface. Phase 2 added the chain source:
//! a local bitcoind over JSON-RPC (`chain`), the actor's sync loop and mempool pass, and the
//! spend path (seed-derived signers per send, never persisted) - so a bitcoin wallet
//! receives, tracks confirmations, and sends. Phase 3 (this tree) adds the second backend:
//! `kyoto`, a BIP-157/158 light client that peers over P2P with no server and no
//! credentials, behind `chain::BtcEndpoint`; `fees` is the mempool.space fee oracle that
//! backend's spend path needs, since a filter client has no `estimatesmartfee`; and
//! `mempool_feed` is that backend's opt-in 0-conf source - a mempool.space websocket, or
//! `p2p_feed`'s own relay connection to the trusted peer - whose transactions the wallet
//! matches locally, since filters cover blocks only.

pub mod actor;
pub mod birthdays;
pub mod chain;
pub mod fees;
pub mod keys;
pub mod kyoto;
pub mod mempool_feed;
pub mod p2p_feed;
pub mod store;
