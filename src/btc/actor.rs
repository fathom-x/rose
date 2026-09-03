//! The Bitcoin wallet's single-writer actor, mirroring the Zcash one
//! (`crate::wallet::actor`): it owns the [`PersistedWallet`], services commands from an mpsc
//! channel, is the only writer of the wallet database, and runs the background sync loop
//! against the wallet's bitcoind upstream (`crate::btc::chain`). Sends funnel through the
//! command channel, so they serialize and cannot double-spend - the `cs_wallet` analog, same
//! as the Zcash side.
//!
//! The sync loop drives `bdk_bitcoind_rpc`'s checkpoint-anchored
//! [`Emitter`](bdk_bitcoind_rpc::Emitter): blocks are emitted from the wallet's own latest
//! checkpoint (so restarts resume, and reorgs walk back to the fork point), applied with
//! [`bdk_wallet::Wallet::apply_block_connected_to`], and persisted per pass. Once the tip is
//! reached, a mempool pass ([`Emitter::mempool`](bdk_bitcoind_rpc::Emitter::mempool)) applies
//! unconfirmed transactions - the 0-conf visibility the Zcash mempool stream provides - and
//! reports evictions. A dead upstream is retried with the shared exponential backoff
//! (`crate::backoff`), reconnect WARNs once per outage then drops to DEBUG, per the logging
//! conventions.
//!
//! The spend path derives its signers from the seed **per send** (a throwaway in-memory
//! signing wallet over the private BIP 84 descriptors - `keys::signing_wallet`), so no
//! spending material ever lands on disk; the persisted wallet holds public descriptors only.

use std::path::PathBuf;
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bdk_bitcoind_rpc::Emitter;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, OutPoint, Psbt, Transaction, Txid};
use bdk_wallet::{KeychainKind, PersistedWallet, SignOptions, Wallet};
use secrecy::SecretVec;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, error, info, info_span, warn, Instrument as _};

use crate::backoff::Backoff;
use crate::btc::chain::{BitcoindRpc, BroadcastError, BtcEndpoint};
use crate::btc::keys::{self, AccountKeys};
use crate::btc::kyoto::{KyotoConn, KyotoFailure};
use crate::btc::store::Persister;
use crate::coin::BitcoinNetwork;
use crate::error::{codes, RpcError};

/// Command channel depth; matches the Zcash actor's order of magnitude.
const COMMAND_BUFFER: usize = 64;

/// Blocks applied per sync pass before the loop returns to service queued commands, so a
/// deep initial sync doesn't starve sends and reads (`sync_step` is one-batch-per-call,
/// like the Zcash engine's).
const SYNC_BLOCKS_PER_PASS: usize = 512;

/// The confirmation target for wallet-built sends: handed to bitcoind's `estimatesmartfee`,
/// and read as `crate::btc::fees::TARGET_BLOCKS` from each HTTP fee oracle on the kyoto
/// backend, so switching backends does not silently reprice a send. One number, here.
pub(crate) const FEE_TARGET_BLOCKS: u16 = 6;

/// The most a subtract-fee build's fee may overshoot the converged guess and still be
/// accepted: the conservative dust bound (546 sat, P2PKH's - above the ~294 sat bound of
/// the P2WPKH change this wallet actually produces). BDK only drops a change output whose
/// value is at or below its script's dust limit, so a changeless overshoot is always under
/// this; anything larger means the loop has genuinely not converged.
const DUST_SLACK_SAT: u64 = 546;

/// The wallet's balance in satoshis, bucketed the way BDK reports it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BtcBalance {
    /// Confirmed and spendable.
    pub confirmed: u64,
    /// Unconfirmed change (trusted: our own transactions).
    pub trusted_pending: u64,
    /// Unconfirmed receives from others.
    pub untrusted_pending: u64,
    /// Immature coinbase value.
    pub immature: u64,
}

/// One unspent output, in wire-friendly primitives (the handle's callers are RPC handlers,
/// which must not see engine types).
#[derive(Clone, Debug)]
pub struct BtcUtxo {
    /// Display-order transaction id (hex).
    pub txid: String,
    pub vout: u32,
    pub amount_sat: u64,
    /// The output's address, when its script has an address form.
    pub address: Option<String>,
    /// Whether the output pays the internal (change) keychain.
    pub change: bool,
    /// Confirmation count against the wallet's synced tip (0 = unconfirmed).
    pub confirmations: u64,
    /// Bitcoin Core's "trusted" notion for an unconfirmed output: it was created by the
    /// wallet's own transaction (change from a send), as opposed to an unconfirmed receive
    /// from a foreign sender. Always true once confirmed. Drives `listunspent.safe` and the
    /// `getbalance` trusted-funds rule.
    pub trusted: bool,
}

/// What the engine knows about an address, for `getaddressinfo`-shaped reads.
#[derive(Clone, Debug)]
pub struct BtcAddressInfo {
    pub is_mine: bool,
    /// `Some((change, index))` when the address is one of the wallet's own derived
    /// addresses: which keychain (change or external) and the derivation index.
    pub derivation: Option<(bool, u32)>,
}

/// One wallet-relevant output of a wallet transaction - Bitcoin Core's per-output history
/// vocabulary, the same accounting the Zcash side's `tx_entries` uses: a multi-recipient
/// send yields one `send` detail per recipient, a payment to one of the wallet's own
/// external addresses yields a send+receive pair, and change (internal keychain) is hidden.
#[derive(Clone, Debug)]
pub struct BtcTxDetail {
    /// `"send"` (the wallet funded this output away) or `"receive"` (it pays the wallet).
    pub category: &'static str,
    /// This output's value in satoshis, negative for `send` (fees are reported separately,
    /// like Core).
    pub amount_sat: i64,
    /// The output's address, when its script encodes one (`None` for e.g. OP_RETURN).
    pub address: Option<String>,
    /// The output index - a real transparent outpoint index, unlike the Zcash side's
    /// per-pool `vout`.
    pub vout: u32,
}

/// One wallet transaction with its per-output fan-out ([`BtcTxDetail`]): the tx-level fields
/// `gettransaction` reports once, plus the details `listtransactions` flattens.
#[derive(Clone, Debug)]
pub struct BtcTxRecord {
    pub txid: String,
    /// The fee in satoshis when the wallet funded the transaction and every input is
    /// known (Core reports fee only on sends).
    pub fee_sat: Option<u64>,
    pub confirmations: u64,
    pub height: Option<u32>,
    pub blockhash: Option<String>,
    /// Block time for mined transactions, first-seen time for mempool ones (0 when neither
    /// is known - a transaction applied without a mempool sighting, pre-confirmation).
    pub time: u64,
    /// Whether the transaction signals BIP 125 replaceability (`bip125-replaceable` is
    /// `"yes"` only while it is also unconfirmed, like Core).
    pub explicit_rbf: bool,
    /// Raw transaction hex (`gettransaction`'s `hex` field).
    pub hex: String,
    /// The wallet-relevant outputs, in `vout` order. Empty for a transaction with no
    /// visible entry (every output is change), which `listtransactions` then omits while
    /// `gettransaction` still resolves.
    pub details: Vec<BtcTxDetail>,
}

/// Connection state of the wallet's upstream, `SyncStatus.conn_state`'s vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcConnState {
    /// No connection (dialing/backing off), or no upstream configured.
    Down,
    /// Connected, catching up to the node's tip.
    Syncing,
    /// Connected and caught up (mempool pass running each interval).
    Ready,
}

/// The actor's published sync status, mirrored after the Zcash `SyncStatus` at the scale the
/// engine needs: what `getwalletinfo`/`getblockcount` read, via [`BtcWalletHandle::status`].
#[derive(Clone, Debug)]
pub struct BtcSyncStatus {
    pub conn_state: BtcConnState,
    /// The wallet's fully-applied chain height (its latest checkpoint).
    pub synced_height: u32,
    /// The hash at `synced_height` (display order).
    pub synced_hash: String,
}

enum BtcCommand {
    NewAddress {
        reply: oneshot::Sender<Result<String, RpcError>>,
    },
    Balance {
        reply: oneshot::Sender<Result<BtcBalance, RpcError>>,
    },
    ListUnspent {
        reply: oneshot::Sender<Result<Vec<BtcUtxo>, RpcError>>,
    },
    AddressInfo {
        address: String,
        reply: oneshot::Sender<Result<BtcAddressInfo, RpcError>>,
    },
    Send {
        /// `(address, amount in satoshis)` per recipient.
        recipients: Vec<(String, u64)>,
        options: BtcSendOptions,
        reply: oneshot::Sender<Result<String, RpcError>>,
    },
    Broadcast {
        hex: String,
        reply: oneshot::Sender<Result<String, RpcError>>,
    },
    ListTransactions {
        reply: oneshot::Sender<Result<Vec<BtcTxRecord>, RpcError>>,
    },
    GetTransaction {
        txid: String,
        reply: oneshot::Sender<Result<Option<BtcTxRecord>, RpcError>>,
    },
}

/// Caller-supplied send options - the optional `sendtoaddress`/`sendmany` parameters the
/// engine honors. Wire-friendly primitives only (the RPC layer builds this, and engine types
/// must not cross that seam); `Default` is a plain estimated-fee send.
#[derive(Clone, Debug, Default)]
pub struct BtcSendOptions {
    /// An explicit fee rate in sat/kvB - the caller's sat/vB scaled by 1000, Core's own
    /// `fee_rate` precision (see `crate::amount::value_to_sat_per_kvb`). `None` estimates
    /// via the upstream. An explicit rate still passes the sanity ceiling at the `do_send`
    /// chokepoint: a fat-fingered 100000 sat/vB burns funds exactly like a dishonest signal.
    pub fee_rate_sat_per_kvb: Option<u64>,
    /// Indices into `recipients` whose amounts pay the fee (`subtractfeefromamount` /
    /// `subtractfeefrom`): the fee is divided equally among them, the first paying
    /// recipient **in recipient order** also covering the remainder - Core's split, which
    /// keys on output order, not the order the `subtractfeefrom` array listed them.
    /// Empty = the sender's change pays, as ever.
    pub subtract_fee_from: Vec<usize>,
}

/// A handle to a running Bitcoin wallet actor - the registry's
/// (`crate::wallet::CoinWallet::Bitcoin`) payload, as `WalletHandle` is the Zcash variant's.
#[derive(Clone, Debug)]
pub struct BtcWalletHandle {
    pub name: String,
    pub network: BitcoinNetwork,
    /// Whether the wallet's `keys.toml` holds a seed: false for a watch-only wallet built
    /// from an imported account xpub, so `getwalletinfo` reports `private_keys_enabled`
    /// (and `listunspent` its `spendable`) from the same signal the Zcash side does.
    pub has_seed: bool,
    cmd_tx: mpsc::Sender<BtcCommand>,
    status_rx: watch::Receiver<BtcSyncStatus>,
}

impl BtcWalletHandle {
    async fn dispatch<T>(
        &self,
        make: impl FnOnce(oneshot::Sender<Result<T, RpcError>>) -> BtcCommand,
    ) -> Result<T, RpcError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(make(tx))
            .await
            .map_err(|_| RpcError::misc("wallet actor is not running"))?;
        rx.await
            .map_err(|_| RpcError::misc("wallet actor dropped the reply"))?
    }

    /// Reveal the next external address (`getnewaddress`).
    pub async fn new_address(&self) -> Result<String, RpcError> {
        self.dispatch(|reply| BtcCommand::NewAddress { reply })
            .await
    }

    pub async fn balance(&self) -> Result<BtcBalance, RpcError> {
        self.dispatch(|reply| BtcCommand::Balance { reply }).await
    }

    pub async fn list_unspent(&self) -> Result<Vec<BtcUtxo>, RpcError> {
        self.dispatch(|reply| BtcCommand::ListUnspent { reply })
            .await
    }

    pub async fn address_info(&self, address: String) -> Result<BtcAddressInfo, RpcError> {
        self.dispatch(|reply| BtcCommand::AddressInfo { address, reply })
            .await
    }

    /// Build, sign, broadcast, and record a send paying `recipients`. Returns the txid.
    pub async fn send(
        &self,
        recipients: Vec<(String, u64)>,
        options: BtcSendOptions,
    ) -> Result<String, RpcError> {
        self.dispatch(|reply| BtcCommand::Send {
            recipients,
            options,
            reply,
        })
        .await
    }

    /// Broadcast a caller-built raw transaction (`sendrawtransaction`). Returns the txid.
    pub async fn broadcast(&self, hex: String) -> Result<String, RpcError> {
        self.dispatch(|reply| BtcCommand::Broadcast { hex, reply })
            .await
    }

    pub async fn list_transactions(&self) -> Result<Vec<BtcTxRecord>, RpcError> {
        self.dispatch(|reply| BtcCommand::ListTransactions { reply })
            .await
    }

    pub async fn get_transaction(&self, txid: String) -> Result<Option<BtcTxRecord>, RpcError> {
        self.dispatch(|reply| BtcCommand::GetTransaction { txid, reply })
            .await
    }

    /// The actor's latest published sync status.
    pub fn status(&self) -> BtcSyncStatus {
        self.status_rx.borrow().clone()
    }
}

/// The stored wallet disagrees with what the seed derives (or with the configured network):
/// evidence the wallet database was replaced. The spawn loop treats this as fatal for the
/// whole node, mirroring `wallet::binding::BindingMismatch` on the Zcash side.
#[derive(Debug)]
pub struct BtcBindingMismatch(pub String);

impl std::fmt::Display for BtcBindingMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "bitcoin wallet database does not match this wallet's keys: {}",
            self.0
        )
    }
}

impl std::error::Error for BtcBindingMismatch {}

/// What `spawn` needs to bring a Bitcoin wallet up.
pub struct BtcActorConfig {
    pub name: String,
    pub engine_dir: PathBuf,
    pub network: BitcoinNetwork,
    /// The decrypted wallet seed. Required to create a wallet database that does not exist
    /// yet, used - when present - to verify an existing database's descriptors against
    /// the seed (the binding check: a swapped database fails closed instead of silently
    /// serving foreign keys, mirroring `wallet::binding` on the Zcash side), and retained
    /// by the actor for per-send signer derivation.
    pub seed: Option<SecretVec<u8>>,
    /// Whether the wallet's `keys.toml` holds a seed at all - distinct from `seed`, which is
    /// absent for a passphrase-encrypted wallet at startup even though the wallet is a
    /// spender. Drives the handle's `has_seed` (and thus watch-only reporting).
    pub wallet_holds_seed: bool,
    /// A watch-only wallet's imported account keys (`keys.toml`'s `xpub` pin, parsed by the
    /// caller for the wallet's network). Plays the seed's role for everything but signing:
    /// creates a missing database and verifies an existing one's descriptors. `None` for a
    /// seed wallet; a wallet with neither is refused at spawn.
    pub imported_keys: Option<AccountKeys>,
    /// The wallet's bitcoind upstream. `None` runs the actor with no sync loop (offline
    /// command service - what the pre-chain-source engine always did, kept for tests).
    pub endpoint: Option<BtcEndpoint>,
    /// The fee-oracle chain (`[fees]`), consulted only on the kyoto backend - a bitcoind
    /// upstream answers with `estimatesmartfee` and never reaches it.
    pub fees: crate::config::FeesConfig,
    /// The height the block scan starts from on an empty chain state (recorded by init).
    pub birthday: u32,
    /// The operator's `--birthday` date when init could only record it approximately (the
    /// kyoto date path - see `WalletStore::birthday_time`); the kyoto first sync resolves
    /// it to a real `(height, hash)` anchor. `None` everywhere else.
    pub birthday_time: Option<u64>,
    /// How often to poll the upstream once caught up (`[sync] interval_secs`).
    pub sync_interval: Duration,
    /// Reconnect backoff bounds (`[backend] reconnect_base_secs`/`reconnect_max_secs`).
    pub reconnect_base: Duration,
    pub reconnect_max: Duration,
    /// Graceful-shutdown signal; the loop exits between passes when it flips true.
    pub shutdown: watch::Receiver<bool>,
}

/// Open (or create) the wallet database and spawn the actor task. Synchronous DB work happens
/// here, before the task starts, so a broken wallet fails the spawn rather than the first
/// command. Returns the handle plus the actor task (awaited at shutdown so the wallet
/// database closes cleanly before the datadir lock is released).
pub fn spawn(
    config: BtcActorConfig,
) -> anyhow::Result<(BtcWalletHandle, tokio::task::JoinHandle<()>)> {
    let BtcActorConfig {
        name,
        engine_dir,
        network,
        seed,
        wallet_holds_seed: has_seed,
        imported_keys,
        endpoint,
        fees,
        birthday,
        birthday_time,
        sync_interval,
        reconnect_base,
        reconnect_max,
        shutdown,
    } = config;
    // The account's public keys, from whichever source this wallet has: the seed for a
    // spending wallet (absent at startup for a passphrase-encrypted one), the imported
    // xpub for a watch-only wallet. Either is enough to create and to verify the database.
    let keys = match &seed {
        Some(seed) => Some(AccountKeys::from_seed(seed, network)?),
        None => imported_keys,
    };
    let mut persister = Persister::open(&engine_dir)?;
    let mut load = Wallet::load().check_network(keys::network(network));
    if let Some(keys) = &keys {
        // Assert the stored descriptors against the known ones (seed-derived, or the
        // pinned import); a mismatch fails the load (and thus the spawn) with a descriptor
        // error.
        load = load
            .descriptor(
                KeychainKind::External,
                Some(keys.descriptor(KeychainKind::External)),
            )
            .descriptor(
                KeychainKind::Internal,
                Some(keys.descriptor(KeychainKind::Internal)),
            );
    }
    let wallet = match PersistedWallet::load(&mut persister, load).map_err(|e| {
        match &e {
            // The database was created for a different Bitcoin network than this daemon
            // resolves for the wallet - a configuration change (the `btc_testnet` key, or
            // the daemon's network environment), not tampering. Name the knob and the fix
            // instead of reporting a binding mismatch.
            bdk_wallet::LoadWithPersistError::InvalidChangeSet(
                bdk_wallet::LoadError::Mismatch(bdk_wallet::LoadMismatch::Network {
                    loaded,
                    expected,
                }),
            ) => anyhow::anyhow!(
                "bitcoin wallet database was created for {loaded} but this daemon is \
                 configured for {expected}: restore the previous network settings (the \
                 top-level btc_testnet key selects between testnet3 and testnet4), or point \
                 this wallet at a fresh directory for the new network"
            ),
            // A stored descriptor that disagrees with the seed-derived one is the Bitcoin
            // analog of `wallet::binding::BindingMismatch`: evidence the wallet database was
            // replaced, not an ordinary open failure. Type it so the spawn loop can treat it
            // as fatal for the whole node, exactly as the Zcash binding check is.
            bdk_wallet::LoadWithPersistError::InvalidChangeSet(
                bdk_wallet::LoadError::Mismatch(mismatch),
            ) => anyhow::Error::new(BtcBindingMismatch(format!("{mismatch:?}"))),
            _ => anyhow::Error::new(e),
        }
    })? {
        Some(wallet) => wallet,
        None => {
            let keys = keys.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "wallet database is empty and no key material (seed or imported xpub) \
                     is available to create it (run `zecd init` for this wallet first)"
                )
            })?;
            PersistedWallet::create(
                &mut persister,
                Wallet::create(
                    keys.descriptor(KeychainKind::External),
                    keys.descriptor(KeychainKind::Internal),
                )
                .network(keys.network),
            )?
        }
    };

    // The recorded birthday anchor, when one exists (written by init against a bitcoind, or
    // by an earlier kyoto first sync's resolution): what lets a kyoto first scan start at
    // the birthday instead of the shipped floor. An unparseable stored hash is treated as
    // absent - the floor path re-resolves and rewrites it - never as fatal.
    let birthday_anchor = match persister.load_birthday_anchor() {
        Ok(anchor) => anchor.and_then(|(height, hash)| match hash.parse() {
            Ok(hash) => Some((height, hash)),
            Err(e) => {
                warn!(height, "ignoring unparseable recorded birthday anchor: {e}");
                None
            }
        }),
        Err(e) => {
            warn!("could not read the recorded birthday anchor: {e:#}");
            None
        }
    };

    let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_BUFFER);
    let (status_tx, status_rx) = watch::channel(status_of(&wallet, BtcConnState::Down));
    let span = info_span!("wallet", name = %name);
    let actor = BtcActor {
        wallet,
        persister,
        seed,
        watch_only: !has_seed,
        network,
        endpoint,
        fees,
        birthday,
        birthday_time,
        birthday_anchor,
        conn: None,
        at_tip: false,
        backoff: Backoff::new(reconnect_base, reconnect_max),
        next_attempt: Instant::now(),
        reconnect_warned: false,
        header_sync_failures: 0,
        sync_interval,
        status_tx,
        cmd_rx,
        shutdown,
    };
    let task = tokio::spawn(actor.run().instrument(span));
    Ok((
        BtcWalletHandle {
            name,
            network,
            has_seed,
            cmd_tx,
            status_rx,
        },
        task,
    ))
}

/// A live upstream connection, in whichever dialect the endpoint resolved to. Dropped (and
/// rebuilt on reconnect) after any transport error.
///
/// The two variants are shaped by their protocols and share no state: bitcoind is a blocking
/// pull whose position lives in the emitter, kyoto an async push whose updates arrive over a
/// channel its own task feeds. What *is* shared - whether the last pass reached tip - lives on
/// the actor as [`BtcActor::at_tip`], since both dialects report it and neither owns it.
// One instance per actor, never in a collection - the same reasoning `chain::AnySource`
// records for the Zcash side, where boxing the larger variant would buy indirection and no
// memory.
#[allow(clippy::large_enum_variant)]
enum Conn {
    Bitcoind {
        rpc: BitcoindRpc,
        emitter: Emitter<Arc<bdk_bitcoind_rpc::bitcoincore_rpc::Client>>,
    },
    Kyoto(KyotoConn),
}

struct BtcActor {
    wallet: PersistedWallet<Persister>,
    persister: Persister,
    seed: Option<SecretVec<u8>>,
    /// True for a wallet with no seed on disk at all (an imported-xpub watch-only wallet),
    /// as opposed to one whose seed is merely absent right now: the send refusal names the
    /// right one of the two.
    watch_only: bool,
    network: BitcoinNetwork,
    endpoint: Option<BtcEndpoint>,
    /// See [`BtcActorConfig::fees`].
    fees: crate::config::FeesConfig,
    birthday: u32,
    /// See [`BtcActorConfig::birthday_time`].
    birthday_time: Option<u64>,
    /// The recorded (or just-resolved) birthday anchor a kyoto first scan starts from -
    /// loaded from the engine database at spawn, updated in place when the resolution task
    /// delivers one mid-sync.
    birthday_anchor: Option<(u32, bdk_wallet::bitcoin::BlockHash)>,
    conn: Option<Conn>,
    /// Whether the last sync pass reached the upstream's tip (drives Ready vs Syncing).
    at_tip: bool,
    backoff: Backoff,
    next_attempt: Instant,
    /// WARN once per outage, then DEBUG (the logging convention for reconnect streams).
    reconnect_warned: bool,
    /// Kyoto only: header-sync failures since the last delivered update. Each one deepens
    /// the next redial's restart checkpoint (`kyoto::resync_depth`), so a fork the light
    /// client cannot reorg onto from 7 blocks back is retried from further down the
    /// wallet's own chain rather than from the same stale tip forever.
    header_sync_failures: u32,
    sync_interval: Duration,
    status_tx: watch::Sender<BtcSyncStatus>,
    cmd_rx: mpsc::Receiver<BtcCommand>,
    shutdown: watch::Receiver<bool>,
}

fn status_of(wallet: &Wallet, conn_state: BtcConnState) -> BtcSyncStatus {
    let cp = wallet.latest_checkpoint();
    BtcSyncStatus {
        conn_state,
        synced_height: cp.height(),
        synced_hash: cp.hash().to_string(),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl BtcActor {
    async fn run(mut self) {
        match &self.endpoint {
            Some(endpoint) => info!(
                network = %self.wallet.network(),
                upstream = %endpoint.describe(),
                "bitcoin wallet actor started"
            ),
            None => info!(
                network = %self.wallet.network(),
                "bitcoin wallet actor started (no upstream configured; offline command \
                 service only)"
            ),
        }
        loop {
            if *self.shutdown.borrow() {
                break;
            }
            // Service everything queued before the next sync pass, so a deep catch-up
            // cannot starve sends and reads.
            let mut closed = false;
            loop {
                match self.cmd_rx.try_recv() {
                    Ok(cmd) => self.handle(cmd).await,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        closed = true;
                        break;
                    }
                }
            }
            if closed || *self.shutdown.borrow() {
                break;
            }
            let worked = if self.endpoint.is_some() {
                self.sync_step()
            } else {
                false
            };
            if worked {
                continue;
            }
            // Idle: wake on a command, shutdown, or the next scheduled pass (the sync
            // interval while connected, the backoff deadline while not).
            let wait = if self.conn.is_some() {
                self.sync_interval
            } else if self.endpoint.is_some() {
                self.next_attempt
                    .saturating_duration_since(Instant::now())
                    .max(Duration::from_millis(100))
            } else {
                // No upstream: nothing scheduled, park until a command or shutdown.
                Duration::from_secs(3600)
            };
            tokio::select! {
                _ = self.shutdown.changed() => {}
                maybe_cmd = self.cmd_rx.recv() => match maybe_cmd {
                    Some(cmd) => self.handle(cmd).await,
                    None => break,
                },
                _ = tokio::time::sleep(wait) => {}
            }
        }
        // Final persist so nothing staged is lost at shutdown; the task ending is what lets
        // `node::stop_actors` release the datadir lock knowing the database is closed.
        self.persist("shutdown");
        info!("bitcoin wallet actor stopped");
    }

    /// One bounded sync pass. Returns true when it did work (caller loops straight back to
    /// command service), false to idle.
    fn sync_step(&mut self) -> bool {
        if self.conn.is_none() {
            if Instant::now() < self.next_attempt {
                return false;
            }
            if !self.connect() {
                return false;
            }
        }
        let Some(conn) = self.conn.as_mut() else {
            return false;
        };
        let mut reached_tip = false;
        let mut resolved_anchor = None;
        let result = match conn {
            // Bitcoind: a bounded blocking pull. The emitter's RPC calls block, so relocate
            // the worker's other tasks for the duration, exactly as the Zcash scan does.
            Conn::Bitcoind { emitter, .. } => tokio::task::block_in_place(|| {
                let mut applied = 0usize;
                while applied < SYNC_BLOCKS_PER_PASS {
                    match emitter.next_block() {
                        Ok(Some(event)) => {
                            let height = event.block_height();
                            self.wallet
                                .apply_block_connected_to(
                                    &event.block,
                                    height,
                                    event.connected_to(),
                                )
                                .map_err(|e| anyhow::anyhow!("apply block {height}: {e}"))?;
                            applied += 1;
                        }
                        Ok(None) => {
                            reached_tip = true;
                            // Caught up: one mempool pass gives 0-conf visibility and eviction
                            // handling (evictions are only reported once the emitter is at tip).
                            let event = emitter
                                .mempool()
                                .map_err(|e| anyhow::anyhow!("mempool: {e}"))?;
                            self.wallet.apply_unconfirmed_txs(event.update);
                            self.wallet.apply_evicted_txs(event.evicted);
                            return Ok(applied);
                        }
                        Err(e) => return Err(anyhow::anyhow!("next_block: {e}")),
                    }
                }
                Ok(applied)
            }),
            // Kyoto: a non-blocking poll of the bridge channel. An `Update` is a whole
            // sync-to-tip rather than one block, so its arrival *is* the tip signal - and
            // there is no mempool pass to follow it, the divergence `kyoto`'s module doc
            // records. `applied` counts updates, only to decide whether the pass did work.
            Conn::Kyoto(kyoto) => match kyoto.try_next_update() {
                Ok(Some(update)) => {
                    reached_tip = true;
                    self.header_sync_failures = 0;
                    self.wallet
                        .apply_update(update)
                        .map_err(|e| anyhow::anyhow!("apply kyoto update: {e}"))
                        .map(|()| 1usize)
                }
                // No update yet: the client is still finding peers or downloading filters.
                // The idle poll is also where a resolved birthday anchor arrives (it can
                // only exist before the first update - `scan_plan` launches the resolution
                // only for a checkpoint-less wallet, and an applied update writes the
                // checkpoint that retires the whole mechanism).
                Ok(None) => {
                    resolved_anchor = kyoto.try_resolved_anchor();
                    Ok(0)
                }
                // The node parked itself on a rejected header batch: count it, so the
                // redial below (via `drop_conn`) restarts from an older checkpoint.
                Err(e @ KyotoFailure::HeaderSync(_)) => {
                    self.header_sync_failures = self.header_sync_failures.saturating_add(1);
                    Err(anyhow::anyhow!(e))
                }
                Err(e) => Err(anyhow::anyhow!(e)),
            },
        };
        // Act on a resolved anchor only while the wallet is still checkpoint-less: the
        // resolution races the first update, and if an earlier pass applied one, the scan
        // is done - restarting a synced light client would tear down a healthy connection
        // for nothing, and the anchor is moot from then on (`ScanType::Sync` resumes from
        // the wallet's own checkpoint forever after).
        if let Some((height, hash)) =
            resolved_anchor.filter(|_| self.wallet.latest_checkpoint().height() == 0)
        {
            // Persist first, restart second: the anchor is what makes an interrupted first
            // sync resume at the birthday instead of the floor, so it must survive even if
            // the restart below never completes. A failed write only costs that
            // durability - the in-memory anchor still steers the restart.
            if let Err(e) = self
                .persister
                .save_birthday_anchor(height, &hash.to_string())
            {
                warn!("failed to record the resolved birthday anchor: {e:#}");
            }
            self.birthday_anchor = Some((height, hash));
            info!(
                anchor = height,
                "birthday resolved against the synced headers; restarting the light client \
                 at it (skipping the floor-to-birthday filter band)"
            );
            // A deliberate restart, not an outage: drop the connection without touching the
            // backoff, so the next pass redials immediately and `scan_plan` picks the
            // anchor up.
            self.conn = None;
            self.at_tip = false;
            self.status_tx
                .send_replace(status_of(&self.wallet, BtcConnState::Syncing));
            return true;
        }
        match result {
            Ok(applied) => {
                self.persist("sync pass");
                if reached_tip {
                    self.at_tip = true;
                }
                let state = if self.at_tip {
                    BtcConnState::Ready
                } else {
                    BtcConnState::Syncing
                };
                let status = status_of(&self.wallet, state);
                if applied > 0 {
                    debug!(
                        blocks = applied,
                        height = status.synced_height,
                        "applied block range"
                    );
                }
                self.status_tx.send_replace(status);
                applied > 0
            }
            Err(e) => {
                // Transport or apply failure: drop the connection and retry with backoff.
                // (An apply failure would recur, but reconnecting rebuilds the emitter from
                // the wallet's own checkpoint, which is also the reorg recovery path.)
                warn!("sync error against the upstream (reconnecting with backoff): {e:#}");
                self.drop_conn();
                true
            }
        }
    }

    /// Dial the endpoint and build the emitter. Returns whether a connection now exists.
    fn connect(&mut self) -> bool {
        let Some(endpoint) = self.endpoint.clone() else {
            return false;
        };
        let dial = match &endpoint {
            BtcEndpoint::Bitcoind(e) => {
                tokio::task::block_in_place(|| e.connect_blocking()).map(|rpc| {
                    info!(
                        upstream = %endpoint.describe(),
                        node_tip = rpc.tip_at_connect,
                        wallet_height = self.wallet.latest_checkpoint().height(),
                        "connected to the upstream"
                    );
                    // Hand the emitter the wallet's unconfirmed transactions so mempool
                    // evictions of them are reported (a wallet with none is the empty set).
                    let expected: Vec<Arc<Transaction>> = self
                        .wallet
                        .transactions()
                        .filter(|wtx| !wtx.chain_position.is_confirmed())
                        .map(|wtx| wtx.tx_node.tx.clone())
                        .collect();
                    let emitter = Emitter::new(
                        rpc.client(),
                        self.wallet.latest_checkpoint(),
                        self.birthday,
                        expected,
                    );
                    Conn::Bitcoind { rpc, emitter }
                })
            }
            // Kyoto "connects" by starting its node task; peer discovery and header sync
            // run in the background, so this returns before the client has a tip. There is
            // nothing to hand it about unconfirmed transactions - it has no mempool.
            BtcEndpoint::Kyoto(e) => {
                let birthday = crate::btc::kyoto::KyotoBirthday {
                    height: self.birthday,
                    time: self.birthday_time,
                    anchor: self.birthday_anchor,
                };
                let resync = crate::btc::kyoto::resync_depth(self.header_sync_failures);
                e.connect(&self.wallet, &birthday, resync).map(|kyoto| {
                    info!(
                        upstream = %endpoint.describe(),
                        wallet_height = self.wallet.latest_checkpoint().height(),
                        "started the light client (peer discovery runs in the background)"
                    );
                    Conn::Kyoto(kyoto)
                })
            }
        };
        match dial {
            Ok(conn) => {
                self.conn = Some(conn);
                self.at_tip = false;
                self.backoff.reset();
                self.reconnect_warned = false;
                self.status_tx
                    .send_replace(status_of(&self.wallet, BtcConnState::Syncing));
                true
            }
            Err(e) => {
                let delay = self.backoff.next_delay();
                if self.reconnect_warned {
                    debug!("connect to the upstream failed (retrying in {delay:?}): {e:#}");
                } else {
                    warn!("connect to the upstream failed (retrying in {delay:?}): {e:#}");
                    self.reconnect_warned = true;
                }
                self.next_attempt = Instant::now() + delay;
                self.status_tx
                    .send_replace(status_of(&self.wallet, BtcConnState::Down));
                false
            }
        }
    }

    fn drop_conn(&mut self) {
        self.conn = None;
        self.at_tip = false;
        self.next_attempt = Instant::now() + self.backoff.next_delay();
        self.status_tx
            .send_replace(status_of(&self.wallet, BtcConnState::Down));
    }

    fn persist(&mut self, what: &str) {
        if let Err(e) = self.wallet.persist(&mut self.persister) {
            // A persist failure loses staged data on restart, not live correctness; keep
            // serving and say so loudly.
            error!("failed to persist wallet changes after {what}: {e:#}");
        }
    }

    fn tip_height(&self) -> u32 {
        self.wallet.latest_checkpoint().height()
    }

    fn confirmations(&self, anchor_height: Option<u32>) -> u64 {
        match anchor_height {
            Some(h) => u64::from(self.tip_height().saturating_sub(h)) + 1,
            None => 0,
        }
    }

    async fn handle(&mut self, cmd: BtcCommand) {
        match cmd {
            BtcCommand::NewAddress { reply } => {
                let address = self.wallet.reveal_next_address(KeychainKind::External);
                let result = self
                    .wallet
                    .persist(&mut self.persister)
                    .map(|_| address.to_string())
                    .map_err(|e| RpcError::misc(format!("persist revealed address: {e:#}")));
                let _ = reply.send(result);
            }
            BtcCommand::Balance { reply } => {
                let b = self.wallet.balance();
                let _ = reply.send(Ok(BtcBalance {
                    confirmed: b.confirmed.to_sat(),
                    trusted_pending: b.trusted_pending.to_sat(),
                    untrusted_pending: b.untrusted_pending.to_sat(),
                    immature: b.immature.to_sat(),
                }));
            }
            BtcCommand::ListUnspent { reply } => {
                let network = self.wallet.network();
                let tip = self.tip_height();
                // Core's trust rule for unconfirmed outputs: trusted iff created by the
                // wallet's own transaction (we funded it - change), never by a foreign
                // sender's unconfirmed payment. Collected once per call, not per output.
                let own_txids: std::collections::HashSet<Txid> = self
                    .wallet
                    .transactions()
                    .filter(|wtx| self.wallet.sent_and_received(&wtx.tx_node.tx).0 > Amount::ZERO)
                    .map(|wtx| wtx.tx_node.txid)
                    .collect();
                let utxos = self
                    .wallet
                    .list_unspent()
                    .map(|output| {
                        let confirmations = match &output.chain_position {
                            bdk_wallet::chain::ChainPosition::Confirmed { anchor, .. } => {
                                u64::from(tip.saturating_sub(anchor.block_id.height)) + 1
                            }
                            bdk_wallet::chain::ChainPosition::Unconfirmed { .. } => 0,
                        };
                        BtcUtxo {
                            txid: output.outpoint.txid.to_string(),
                            vout: output.outpoint.vout,
                            amount_sat: output.txout.value.to_sat(),
                            address: Address::from_script(
                                output.txout.script_pubkey.as_script(),
                                network,
                            )
                            .ok()
                            .map(|a| a.to_string()),
                            change: output.keychain == KeychainKind::Internal,
                            confirmations,
                            trusted: confirmations > 0 || own_txids.contains(&output.outpoint.txid),
                        }
                    })
                    .collect();
                let _ = reply.send(Ok(utxos));
            }
            BtcCommand::AddressInfo { address, reply } => {
                let result = match Address::from_str(&address)
                    .and_then(|a| a.require_network(self.wallet.network()))
                {
                    Ok(address) => {
                        let spk = address.script_pubkey();
                        Ok(BtcAddressInfo {
                            is_mine: self.wallet.is_mine(spk.clone()),
                            derivation: self.wallet.derivation_of_spk(spk).map(
                                |(keychain, index)| (keychain == KeychainKind::Internal, index),
                            ),
                        })
                    }
                    Err(_) => Err(RpcError::invalid_address_or_key(format!(
                        "Invalid Bitcoin address: {address}"
                    ))),
                };
                let _ = reply.send(result);
            }
            BtcCommand::Send {
                recipients,
                options,
                reply,
            } => {
                let result = self.do_send(recipients, options).await;
                let _ = reply.send(result);
            }
            BtcCommand::Broadcast { hex, reply } => {
                let result = self.do_broadcast(hex).await;
                let _ = reply.send(result);
            }
            BtcCommand::ListTransactions { reply } => {
                let _ = reply.send(Ok(self.tx_entries()));
            }
            BtcCommand::GetTransaction { txid, reply } => {
                let result = match Txid::from_str(&txid) {
                    Ok(txid) => Ok(self
                        .tx_entries()
                        .into_iter()
                        .find(|e| e.txid == txid.to_string())),
                    Err(_) => Err(RpcError::invalid_address_or_key(format!(
                        "Invalid txid: {txid}"
                    ))),
                };
                let _ = reply.send(result);
            }
        }
    }

    /// Every wallet transaction as a wire-shaped record with its per-output fan-out, oldest
    /// first (confirmed by height, then unconfirmed by first-seen).
    fn tx_entries(&self) -> Vec<BtcTxRecord> {
        let network = self.wallet.network();
        let mut entries: Vec<(u64, BtcTxRecord)> = self
            .wallet
            .transactions()
            .map(|wtx| {
                let tx = wtx.tx_node.tx.clone();
                let txid = wtx.tx_node.txid;
                let (sent, _received) = self.wallet.sent_and_received(&tx);
                let fee = self.wallet.calculate_fee(&tx).ok().map(|a| a.to_sat());
                let (height, blockhash, time, sort_key) = match &wtx.chain_position {
                    bdk_wallet::chain::ChainPosition::Confirmed { anchor, .. } => (
                        Some(anchor.block_id.height),
                        Some(anchor.block_id.hash.to_string()),
                        anchor.confirmation_time,
                        u64::from(anchor.block_id.height),
                    ),
                    bdk_wallet::chain::ChainPosition::Unconfirmed {
                        first_seen,
                        last_seen,
                    } => {
                        let seen = first_seen.or(*last_seen).unwrap_or(0);
                        // Unconfirmed sorts after every mined transaction.
                        (None, None, seen, u64::MAX)
                    }
                };
                let funded = sent > Amount::ZERO;
                let mut details = Vec::new();
                for (vout, txout) in tx.output.iter().enumerate() {
                    let vout = u32::try_from(vout).unwrap_or(u32::MAX);
                    let keychain = self
                        .wallet
                        .derivation_of_spk(txout.script_pubkey.clone())
                        .map(|(keychain, _)| keychain);
                    let address = Address::from_script(&txout.script_pubkey, network)
                        .ok()
                        .map(|a| a.to_string());
                    let value = i64::try_from(txout.value.to_sat()).unwrap_or(i64::MAX);
                    // Core's accounting (and the Zcash side's `tx_entries`): on a funded
                    // transaction, a foreign output is a `send`, an own external-keychain
                    // output is a self-payment (send+receive pair), and change (internal
                    // keychain) is hidden. On a transaction the wallet did not fund, only
                    // the wallet's own outputs appear, as `receive`.
                    let categories: &[&'static str] = match (funded, keychain) {
                        (true, None) => &["send"],
                        (true, Some(KeychainKind::External)) => &["send", "receive"],
                        (true, Some(KeychainKind::Internal)) => &[],
                        (false, Some(_)) => &["receive"],
                        (false, None) => &[],
                    };
                    for category in categories {
                        details.push(BtcTxDetail {
                            category,
                            amount_sat: if *category == "send" { -value } else { value },
                            address: address.clone(),
                            vout,
                        });
                    }
                }
                let entry = BtcTxRecord {
                    txid: txid.to_string(),
                    fee_sat: funded.then_some(fee).flatten(),
                    confirmations: self.confirmations(height),
                    height,
                    blockhash,
                    time,
                    explicit_rbf: tx.is_explicitly_rbf(),
                    hex: bdk_wallet::bitcoin::consensus::encode::serialize_hex(tx.as_ref()),
                    details,
                };
                (sort_key, entry)
            })
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.time.cmp(&b.1.time)));
        entries.into_iter().map(|(_, e)| e).collect()
    }

    /// The upstream's fee rate for a send, in whichever dialect is connected.
    ///
    /// Bitcoind answers with `estimatesmartfee`. Kyoto has no such call and answers with a
    /// far coarser signal - see [`KyotoConn::estimate_fee_rate`] - so the mainnet fallback
    /// rule below is doing more work on that backend than on this one.
    async fn upstream_fee_rate(&mut self) -> anyhow::Result<Option<bdk_wallet::bitcoin::FeeRate>> {
        let requester = match self.conn.as_ref() {
            // Blocking and synchronous: answer here, before any await exists.
            Some(Conn::Bitcoind { rpc, .. }) => {
                return tokio::task::block_in_place(|| {
                    rpc.estimate_fee_rate_blocking(FEE_TARGET_BLOCKS)
                });
            }
            Some(Conn::Kyoto(kyoto)) => kyoto.requester(),
            None => return Err(anyhow::anyhow!("no upstream connection")),
        };
        // Kyoto has no fee estimator of its own worth the name, so walk the configured oracle
        // chain (`[fees] sources`, by default mempool.space then Esplora then the on-chain
        // signals) and take the first answer. A tier failing is not a failed send - the chain
        // degrades to the next one, whichever kind it is: an operator who lists `peer_median`
        // first gets the HTTP oracles only when the peers cannot answer, which is the
        // privacy-maximal order and the reason the list is ordered at all. Only the LAST tier's
        // failure is the chain's failure, and it is reported as that tier reported it (an HTTP
        // tier's `Err` becomes the `Ok(None)` below; the peer tier's `Err` stays an `Err`, as
        // it always was when it stood alone at the end). `crate::btc::fees` documents what the
        // lookups do and do not reveal, and how to point them at an instance the operator runs.
        let chain = crate::btc::fees::oracle_chain(&self.fees, self.network);
        let last = chain.len().saturating_sub(1);
        for (i, tier) in chain.into_iter().enumerate() {
            match tier {
                crate::btc::fees::FeeTier::Http { source, url } => {
                    match crate::btc::fees::http_fee_rate(source, &url).await {
                        Ok(rate) => return Ok(Some(rate)),
                        Err(e) => warn!(
                            source = source.as_str(),
                            %url,
                            "fee lookup failed ({e:#}); falling through to the next fee source"
                        ),
                    }
                }
                crate::btc::fees::FeeTier::PeerMedian => {
                    let attempt = crate::btc::kyoto::estimate_fee_rate(requester.clone()).await;
                    if i == last {
                        return attempt;
                    }
                    match attempt {
                        Ok(Some(rate)) => return Ok(Some(rate)),
                        Ok(None) => warn!(
                            "the peer-derived fee median had no answer; falling through to the \
                             next fee source"
                        ),
                        Err(e) => warn!(
                            "peer-derived fee median failed ({e:#}); falling through to the next \
                             fee source"
                        ),
                    }
                }
            }
        }
        // Every tier was skipped (no endpoint for this network) or failed. `do_send` turns
        // this into the same refusal-on-mainnet / 1 sat/vB-on-testnet posture a bitcoind with
        // no fee data gets, so an operator who removed `peer_median` from the chain lands
        // there deliberately rather than on a peer-dictated rate.
        Ok(None)
    }

    /// Broadcast in whichever dialect is connected: bitcoind's `sendrawtransaction`, or a
    /// kyoto submission to the P2P peers. Failures come back as [`BroadcastError`]:
    /// bitcoind classifies rejection vs transport itself, and every kyoto failure is
    /// transport-shaped - a rejection there surfaces asynchronously in the log stream, so
    /// this call failing only ever means "no verdict" (see [`crate::btc::kyoto::broadcast`]).
    async fn upstream_broadcast(&mut self, tx: &Transaction) -> Result<Txid, BroadcastError> {
        let requester = match self.conn.as_ref() {
            Some(Conn::Bitcoind { rpc, .. }) => {
                return tokio::task::block_in_place(|| rpc.broadcast_blocking(tx));
            }
            Some(Conn::Kyoto(kyoto)) => kyoto.requester(),
            None => {
                return Err(BroadcastError::Transport(anyhow::anyhow!(
                    "no upstream connection"
                )))
            }
        };
        crate::btc::kyoto::broadcast(requester, tx)
            .await
            .map_err(BroadcastError::Transport)
    }

    /// Map a broadcast failure onto the RPC vocabulary. A rejection passes the node's own
    /// verify-family code and message through (the node answered; retrying the same bytes
    /// cannot succeed). A transport failure is `-4` - retry semantics, the opposite
    /// instruction - and drops a bitcoind connection so the next operation redials with
    /// backoff (the `Conn` convention); a kyoto connection is deliberately kept, since the
    /// light client itself holds the still-queued transaction and tearing it down would
    /// discard the pending relay.
    fn broadcast_failure(&mut self, e: BroadcastError) -> RpcError {
        match e {
            BroadcastError::Rejected { code, message } => RpcError::new(code, message),
            BroadcastError::Transport(err) => {
                if matches!(self.conn, Some(Conn::Bitcoind { .. })) {
                    self.drop_conn();
                }
                RpcError::new(
                    codes::RPC_WALLET_ERROR,
                    format!(
                        "broadcast failed before the upstream gave a verdict: {err:#}. The \
                         transaction was not recorded (its inputs stay unlocked); retry \
                         once the upstream is reachable"
                    ),
                )
            }
        }
    }

    async fn do_send(
        &mut self,
        recipients: Vec<(String, u64)>,
        options: BtcSendOptions,
    ) -> Result<String, RpcError> {
        // Checked here but borrowed only at the signing step below: the fee and broadcast
        // calls take `&mut self`, so holding a `&self.seed` across them would not borrow-check.
        if self.seed.is_none() {
            // Bitcoin Core's -4 for a wallet that cannot sign, worded for which of the two
            // shapes this is: a watch-only wallet has nothing to unlock, ever; a locked
            // spending wallet has a seed the custody model did not hand over.
            return Err(RpcError::new(
                codes::RPC_WALLET_ERROR,
                if self.watch_only {
                    "Error: Private keys are disabled for this wallet (watch-only, built from \
                     an imported xpub); spend from the paired spending wallet"
                } else {
                    "Error: Private keys are disabled for this wallet, or the wallet is locked \
                     (bitcoin wallets have no walletpassphrase yet - use an identity-file \
                     wallet with auto_unlock for unattended sending)"
                },
            ));
        }
        if self.conn.is_none() {
            return Err(RpcError::new(
                codes::RPC_WALLET_ERROR,
                "no connection to the upstream (fee estimation and broadcast need it); retry \
                 once it is reachable",
            ));
        }
        // Fee rate: the caller's explicit `fee_rate` when given (no estimation dial at all -
        // on the kyoto backend this is the one way to price a send without trusting
        // mempool.space or the peers' coarse signals), else the upstream's estimate, or -
        // matching bitcoind's fallbackfee posture - a 1 sat/vB floor on test networks only
        // (mainnet refuses rather than guessing). Whatever the source - the caller,
        // estimatesmartfee, mempool.space, or the kyoto peers' relay floor and block
        // medians - the rate passes the sanity ceiling HERE, at the one chokepoint every
        // send goes through, so no source (present or future) can dictate an absurd fee: it
        // becomes a refusal naming the number instead of a payment.
        let fee_rate = match options.fee_rate_sat_per_kvb {
            // sat/kvB -> sat/kwu is a /4 (1 vB = 4 WU), ceiling-divided so the built
            // transaction never pays under the rate the caller named - by weight, which is
            // how BDK prices every fee (against a rounded-up vsize the realized rate can
            // read fractionally under; the conservative satisfaction-weight estimate is
            // what covers relay floors in practice, same as the estimated-rate path).
            Some(kvb) => Some(FeeRate::from_sat_per_kwu(kvb.div_ceil(4))),
            None => self
                .upstream_fee_rate()
                .await
                .map_err(|e| RpcError::new(codes::RPC_WALLET_ERROR, format!("{e:#}")))?,
        };
        let fee_rate = match fee_rate {
            Some(rate) => crate::btc::fees::enforce_sanity_ceiling(rate)
                .map_err(|e| RpcError::new(codes::RPC_WALLET_ERROR, format!("{e:#}")))?,
            None if self.network == BitcoinNetwork::Main => {
                return Err(RpcError::new(
                    codes::RPC_WALLET_ERROR,
                    "Fee estimation failed and no fallback applies on mainnet; retry once \
                     the node has fee data (or pass an explicit fee_rate)",
                ))
            }
            None => FeeRate::from_sat_per_vb_u32(1),
        };
        let network = self.wallet.network();
        let mut parsed = Vec::with_capacity(recipients.len());
        for (addr, sats) in &recipients {
            let address = Address::from_str(addr)
                .and_then(|a| a.require_network(network))
                .map_err(|_| {
                    RpcError::invalid_address_or_key(format!("Invalid Bitcoin address: {addr}"))
                })?;
            if *sats == 0 {
                return Err(RpcError::invalid_parameter("Invalid amount for send"));
            }
            parsed.push((address, Amount::from_sat(*sats)));
        }

        let started = Instant::now();
        let mut psbt = if options.subtract_fee_from.is_empty() {
            let mut builder = self.wallet.build_tx();
            for (address, amount) in &parsed {
                builder.add_recipient(address.script_pubkey(), *amount);
            }
            builder.fee_rate(fee_rate);
            builder.finish().map_err(map_create_tx_error)?
        } else {
            self.build_subtract_fee_psbt(&parsed, &options.subtract_fee_from, fee_rate)?
        };

        // Signers are derived from the seed per send and dropped with this scope - the
        // custody model's spend half (the persisted wallet holds public descriptors only).
        let seed = self
            .seed
            .as_ref()
            .expect("seed presence checked at the top of do_send");
        let signing = keys::signing_wallet(seed, self.network)
            .map_err(|e| RpcError::misc(format!("derive signing descriptors: {e:#}")))?;
        let finalized = signing
            .sign(&mut psbt, SignOptions::default())
            .map_err(|e| RpcError::misc(format!("sign: {e}")))?;
        if !finalized {
            return Err(RpcError::misc(
                "failed to finalize the transaction (signer did not complete all inputs)",
            ));
        }
        let tx = psbt
            .extract_tx()
            .map_err(|e| RpcError::misc(format!("extract transaction: {e:?}")))?;
        let txid = match self.upstream_broadcast(&tx).await {
            Ok(txid) => txid,
            Err(e) => return Err(self.broadcast_failure(e)),
        };
        // Record our own send immediately (0-conf), which also locks its inputs against
        // reuse by the next send's coin selection.
        self.wallet
            .apply_unconfirmed_txs(vec![(Arc::new(tx), unix_now())]);
        self.persist("send");
        info!(
            %txid,
            recipients = recipients.len(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "sent transaction"
        );
        Ok(txid.to_string())
    }

    /// Build the PSBT for a subtract-fee send: the listed recipients pay the fee out of
    /// their own amounts, so coin selection must target the stated amounts alone - the
    /// defining property of a subtract-fee send, and what makes "send the whole balance"
    /// work at all (selecting for amounts *plus* fee would refuse it as insufficient).
    ///
    /// BDK's `TxBuilder` has no subtract-fee mode, so this converges on one: a zero-fee
    /// build picks the inputs, then rate-priced rebuilds over those pinned inputs walk the
    /// fee to a fixed point via [`subtract_fee_from_amounts`]. With the inputs pinned, the
    /// fee for a given output structure is deterministic, so the loop settles as soon as
    /// the change output's presence does - two or three builds; the iteration cap is a
    /// backstop, not a path. Note each change-producing build reveals an internal keychain
    /// index into BDK's staged changeset (persisted on the next `persist`, broadcast or
    /// not), so a subtract-fee send can consume two or three internal indices with only
    /// the last funded - gap-limit-scale noise, but not nothing: don't add builds here
    /// casually.
    ///
    /// One shape has no fixed point: when the pinned inputs exceed the amounts by less
    /// than a change output's dust bound, BDK folds that surplus into the fee (as Core
    /// does with sub-dust change), so the observed fee sits that fixed surplus above the
    /// guess on every changeless iteration. The acceptance below therefore takes a
    /// changeless build whose fee overshoots the guess by at most [`DUST_SLACK_SAT`]:
    /// the recipients still pay only the guess, and the surplus could never have come
    /// back as change anyway.
    fn build_subtract_fee_psbt(
        &mut self,
        parsed: &[(Address, Amount)],
        subtract: &[usize],
        fee_rate: FeeRate,
    ) -> Result<Psbt, RpcError> {
        let inputs: Vec<OutPoint> = {
            let mut builder = self.wallet.build_tx();
            for (address, amount) in parsed {
                builder.add_recipient(address.script_pubkey(), *amount);
            }
            builder.fee_absolute(Amount::ZERO);
            let psbt = builder.finish().map_err(map_create_tx_error)?;
            psbt.unsigned_tx
                .input
                .iter()
                .map(|i| i.previous_output)
                .collect()
        };
        let mut fee_sat = 0u64;
        for _ in 0..8 {
            let reduced = subtract_fee_from_amounts(parsed, subtract, fee_sat)?;
            let mut builder = self.wallet.build_tx();
            builder
                .add_utxos(&inputs)
                .map_err(|e| RpcError::misc(format!("re-select inputs: {e:?}")))?;
            builder.manually_selected_only();
            for (address, amount) in &reduced {
                builder.add_recipient(address.script_pubkey(), *amount);
            }
            builder.fee_rate(fee_rate);
            match builder.finish() {
                Ok(psbt) => {
                    let actual = psbt
                        .fee()
                        .map_err(|e| RpcError::misc(format!("compute the psbt fee: {e}")))?
                        .to_sat();
                    // Exact convergence, or the changeless sub-dust window (see the doc
                    // comment): a build with no change output whose fee exceeds the guess
                    // by at most a dust bound is the folded-surplus fixed point.
                    let changeless = psbt.unsigned_tx.output.len() == reduced.len();
                    if actual == fee_sat
                        || (changeless && actual > fee_sat && actual - fee_sat <= DUST_SLACK_SAT)
                    {
                        return Ok(psbt);
                    }
                    fee_sat = actual;
                }
                // The pinned inputs cover the amounts but not amounts + fee - the guess is
                // still low (a whole-balance send's first pass always lands here): the
                // shortfall IS the missing fee, so fold it in and go around.
                Err(bdk_wallet::error::CreateTxError::CoinSelection(
                    bdk_wallet::coin_selection::InsufficientFunds { needed, available },
                )) => {
                    fee_sat += needed.to_sat().saturating_sub(available.to_sat());
                }
                Err(e) => return Err(map_create_tx_error(e)),
            }
        }
        Err(RpcError::new(
            codes::RPC_WALLET_ERROR,
            "fee subtraction did not converge; retry, or send without subtractfeefromamount",
        ))
    }

    async fn do_broadcast(&mut self, hex: String) -> Result<String, RpcError> {
        if self.conn.is_none() {
            return Err(RpcError::new(
                codes::RPC_WALLET_ERROR,
                "no connection to the upstream; retry once it is reachable",
            ));
        }
        let tx: Transaction = bdk_wallet::bitcoin::consensus::encode::deserialize_hex(&hex)
            .map_err(|e| {
                RpcError::new(
                    codes::RPC_DESERIALIZATION_ERROR,
                    format!("TX decode failed: {e}"),
                )
            })?;
        let txid = match self.upstream_broadcast(&tx).await {
            Ok(txid) => txid,
            Err(e) => return Err(self.broadcast_failure(e)),
        };
        // If the transaction touches this wallet, record it at 0-conf (the apply filters
        // relevance itself, so a foreign transaction is a no-op).
        self.wallet
            .apply_unconfirmed_txs(vec![(Arc::new(tx), unix_now())]);
        self.persist("broadcast");
        Ok(txid.to_string())
    }
}

/// Divide `fee_sat` across the `subtract` recipients and return the reduced amounts -
/// Core's split: `fee / n` each, with the first paying recipient **in recipient order**
/// also covering the remainder (Core keys on output order, not on the order the
/// `subtractfeefrom` array named them). A recipient whose amount cannot cover its share
/// is a refusal naming the problem, matching Core's "too small to pay the fee" behavior
/// rather than sending dust or underflowing.
fn subtract_fee_from_amounts(
    parsed: &[(Address, Amount)],
    subtract: &[usize],
    fee_sat: u64,
) -> Result<Vec<(Address, Amount)>, RpcError> {
    let n = subtract.len() as u64;
    let share = fee_sat / n;
    let remainder = fee_sat % n;
    let first_paying = subtract.iter().min().copied();
    let mut out = parsed.to_vec();
    for idx in subtract {
        let cut = share
            + if Some(*idx) == first_paying {
                remainder
            } else {
                0
            };
        let entry = out
            .get_mut(*idx)
            .ok_or_else(|| RpcError::invalid_parameter("subtractfeefrom index out of range"))?;
        let have = entry.1.to_sat();
        if have <= cut {
            return Err(RpcError::new(
                codes::RPC_WALLET_ERROR,
                "The transaction amount is too small to pay the fee",
            ));
        }
        entry.1 = Amount::from_sat(have - cut);
    }
    Ok(out)
}

/// Map BDK's transaction-build failure onto the Bitcoin Core error vocabulary: insufficient
/// funds is `-6` with the amounts (self-diagnosing, like the Zcash `-6` enrichment),
/// everything else `-4`.
fn map_create_tx_error(e: bdk_wallet::error::CreateTxError) -> RpcError {
    use bdk_wallet::coin_selection::InsufficientFunds;
    use bdk_wallet::error::CreateTxError;
    match e {
        CreateTxError::CoinSelection(InsufficientFunds { needed, available }) => RpcError::new(
            codes::RPC_WALLET_INSUFFICIENT_FUNDS,
            format!("Insufficient funds: {needed} needed, {available} available"),
        ),
        other => RpcError::new(codes::RPC_WALLET_ERROR, format!("{other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc::keys::tests::bip84_seed;

    pub(crate) fn offline_config(
        dir: &std::path::Path,
        seed: Option<SecretVec<u8>>,
    ) -> BtcActorConfig {
        BtcActorConfig {
            name: "btc-test".to_string(),
            engine_dir: dir.join("btc").join("bdk"),
            network: BitcoinNetwork::Main,
            wallet_holds_seed: seed.is_some(),
            seed,
            imported_keys: None,
            endpoint: None,
            fees: crate::config::FeesConfig::default(),
            birthday: 0,
            birthday_time: None,
            sync_interval: Duration::from_secs(20),
            reconnect_base: Duration::from_secs(1),
            reconnect_max: Duration::from_secs(60),
            shutdown: tokio::sync::watch::channel(false).1,
        }
    }

    /// The full handle surface against a fresh wallet: addresses come out in BIP 84 order,
    /// the empty wallet reports zero balances and no UTXOs, and address attribution
    /// distinguishes own external, own change (derivation), and foreign addresses.
    #[tokio::test(flavor = "multi_thread")]
    async fn handle_serves_addresses_balances_and_attribution() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, _task) = spawn(offline_config(dir.path(), Some(bip84_seed()))).unwrap();
        assert!(handle.has_seed);
        let a0 = handle.new_address().await.unwrap();
        assert_eq!(a0, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        let a1 = handle.new_address().await.unwrap();
        assert_eq!(a1, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
        assert_eq!(handle.balance().await.unwrap(), BtcBalance::default());
        assert!(handle.list_unspent().await.unwrap().is_empty());
        assert!(handle.list_transactions().await.unwrap().is_empty());

        // With no upstream configured the status is Down at the genesis checkpoint.
        let status = handle.status();
        assert_eq!(status.conn_state, BtcConnState::Down);
        assert_eq!(status.synced_height, 0);

        let own = handle.address_info(a0).await.unwrap();
        assert!(own.is_mine);
        assert_eq!(own.derivation, Some((false, 0)));
        // A foreign (but valid, mainnet) address: BIP 84's own first change address is not
        // revealed as *receiving* but is still the wallet's - use an unrelated known address.
        let foreign = handle
            .address_info("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string())
            .await
            .unwrap();
        assert!(!foreign.is_mine);
        assert_eq!(foreign.derivation, None);
        // A testnet address on a mainnet wallet is invalid, not foreign.
        let err = handle
            .address_info("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string())
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_ADDRESS_OR_KEY);
    }

    /// A second spawn over the same directory verifies the stored descriptors against the
    /// seed (the binding check): the right seed loads, a different seed fails the spawn.
    #[tokio::test(flavor = "multi_thread")]
    async fn respawn_verifies_descriptors_against_the_seed() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (handle, _task) = spawn(offline_config(dir.path(), Some(bip84_seed()))).unwrap();
            handle.new_address().await.unwrap();
        }
        // Same seed: loads, and the address cursor advanced past the persisted reveal.
        let (handle, _task) = spawn(offline_config(dir.path(), Some(bip84_seed()))).unwrap();
        assert_eq!(
            handle.new_address().await.unwrap(),
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
        );
        // A different seed must fail closed, with the typed mismatch the spawn loop treats
        // as fatal (the Bitcoin analog of wallet::binding::BindingMismatch).
        let other = SecretVec::new(vec![7u8; 64]);
        let err = spawn(offline_config(dir.path(), Some(other))).unwrap_err();
        assert!(
            err.downcast_ref::<BtcBindingMismatch>().is_some(),
            "expected BtcBindingMismatch, got: {err:#}"
        );
    }

    /// A wallet database created for one Bitcoin testnet refuses to load under the other -
    /// testnet3 and testnet4 derive identical keys, so the recorded network is what tells
    /// the chains apart - and the error is an actionable configuration message naming the
    /// `btc_testnet` knob, NOT the binding mismatch (nothing was tampered with).
    #[tokio::test(flavor = "multi_thread")]
    async fn switching_the_testnet_over_an_existing_database_is_an_actionable_error() {
        let dir = tempfile::tempdir().unwrap();
        let testnet3 = BtcActorConfig {
            network: BitcoinNetwork::Testnet3,
            ..offline_config(dir.path(), Some(bip84_seed()))
        };
        {
            let (handle, _task) = spawn(testnet3).unwrap();
            let address = handle.new_address().await.unwrap();
            assert!(address.starts_with("tb1"), "{address}");
        }
        let testnet4 = BtcActorConfig {
            network: BitcoinNetwork::Testnet4,
            ..offline_config(dir.path(), Some(bip84_seed()))
        };
        let err = spawn(testnet4).unwrap_err();
        assert!(
            err.downcast_ref::<BtcBindingMismatch>().is_none(),
            "a network flip is configuration, not tampering: {err:#}"
        );
        assert!(err.to_string().contains("btc_testnet"), "{err:#}");
    }

    /// The watch-only shape: imported keys alone create the database and serve the same
    /// addresses the seed wallet would; a send is refused with Core's -4 naming the
    /// watch-only custody; the seed then loads the same database (the descriptors match),
    /// and a foreign import over it is the binding mismatch, exactly as a swapped
    /// database is for a seed wallet.
    #[tokio::test(flavor = "multi_thread")]
    async fn imported_xpub_builds_a_watch_only_wallet_the_seed_can_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let keys = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Main).unwrap();
        let imported = AccountKeys::from_xpub(&keys.export(), BitcoinNetwork::Main).unwrap();
        let first_address = {
            let cfg = BtcActorConfig {
                imported_keys: Some(imported.clone()),
                ..offline_config(dir.path(), None)
            };
            let (handle, _task) = spawn(cfg).unwrap();
            assert!(!handle.has_seed, "no seed on disk");
            let err = handle
                .send(
                    vec![(
                        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                        10_000,
                    )],
                    BtcSendOptions::default(),
                )
                .await
                .unwrap_err();
            assert_eq!(err.code, codes::RPC_WALLET_ERROR);
            assert!(err.message.contains("watch-only"), "{}", err.message);
            handle.new_address().await.unwrap()
        };
        // The BIP 84 reference vector's first address: the import derived the seed's keys.
        assert_eq!(first_address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");

        // The seed reopens the database the import created (descriptor check passes) and
        // continues the same keychain.
        {
            let (handle, _task) = spawn(offline_config(dir.path(), Some(bip84_seed()))).unwrap();
            assert!(handle.has_seed);
            assert_eq!(
                handle.new_address().await.unwrap(),
                "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
            );
        }

        // A different account's import over this database is tampering, typed as such.
        let other_seed = SecretVec::new(vec![7u8; 64]);
        let other = AccountKeys::from_seed(&other_seed, BitcoinNetwork::Main).unwrap();
        let err = spawn(BtcActorConfig {
            imported_keys: Some(other),
            ..offline_config(dir.path(), None)
        })
        .unwrap_err();
        assert!(
            err.downcast_ref::<BtcBindingMismatch>().is_some(),
            "a foreign import over an existing database is a binding mismatch: {err:#}"
        );
    }

    /// Core's subtract-fee division: `fee / n` per listed recipient, the first paying
    /// recipient in **recipient order** covering the remainder (whatever order the
    /// `subtractfeefrom` array named them - Core keys on output order), unlisted
    /// recipients untouched, and an amount that cannot cover its share refusing rather
    /// than underflowing.
    #[test]
    fn subtract_fee_from_amounts_splits_like_core() {
        let addr = |s: &str| Address::from_str(s).unwrap().assume_checked();
        let a = addr("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let parsed = vec![
            (a.clone(), Amount::from_sat(10_000)),
            (a.clone(), Amount::from_sat(20_000)),
            (a.clone(), Amount::from_sat(30_000)),
        ];

        // One payer takes the whole fee.
        let out = subtract_fee_from_amounts(&parsed, &[1], 151).unwrap();
        assert_eq!(out[0].1.to_sat(), 10_000);
        assert_eq!(out[1].1.to_sat(), 19_849);
        assert_eq!(out[2].1.to_sat(), 30_000);

        // Two payers split it; the odd satoshi lands on the earliest recipient among the
        // payers, not on the array's first entry.
        let out = subtract_fee_from_amounts(&parsed, &[2, 0], 151).unwrap();
        assert_eq!(out[0].1.to_sat(), 10_000 - 76);
        assert_eq!(out[2].1.to_sat(), 30_000 - 75);
        assert_eq!(out[1].1.to_sat(), 20_000);

        // A zero fee is the identity (the convergence loop's first pass).
        let out = subtract_fee_from_amounts(&parsed, &[0], 0).unwrap();
        assert_eq!(out[0].1.to_sat(), 10_000);

        // An amount at or below its share refuses with -4 naming the problem.
        let err = subtract_fee_from_amounts(&parsed, &[0], 10_000).unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_WALLET_ERROR);
        assert!(err.message.contains("too small to pay the fee"), "{err:?}");

        // A bad index is a parameter error, never a panic on the actor.
        let err = subtract_fee_from_amounts(&parsed, &[7], 100).unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_PARAMETER);
    }

    /// A missing database with no seed is an error naming init, not a silently empty wallet.
    #[tokio::test(flavor = "multi_thread")]
    async fn missing_database_without_seed_fails_the_spawn() {
        let dir = tempfile::tempdir().unwrap();
        let err = spawn(offline_config(dir.path(), None)).unwrap_err();
        assert!(err.to_string().contains("zecd init"), "{err:#}");
    }

    /// Sends and broadcasts against a wallet with no upstream fail actionably (`-4`), and a
    /// seedless (locked/watch-only) wallet's send names the custody problem - both without
    /// touching the network.
    #[tokio::test(flavor = "multi_thread")]
    async fn offline_send_and_broadcast_fail_actionably() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, _task) = spawn(offline_config(dir.path(), Some(bip84_seed()))).unwrap();
        let err = handle
            .send(
                vec![(
                    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                    10_000,
                )],
                BtcSendOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_WALLET_ERROR);
        // Dialect-neutral since the engine grew a second backend: the wallet may be offline
        // from a bitcoind or from a kyoto light client, and the message names neither.
        assert!(err.message.contains("upstream"), "{}", err.message);
        let err = handle.broadcast("00".repeat(20)).await.unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_WALLET_ERROR);

        // The graceful-shutdown path: flip the signal and the task ends.
        let dir2 = tempfile::tempdir().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let mut config = offline_config(dir2.path(), Some(bip84_seed()));
        config.shutdown = shutdown_rx;
        let (_handle, task) = spawn(config).unwrap();
        shutdown_tx.send_replace(true);
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("actor exits on shutdown")
            .unwrap();
    }
}
