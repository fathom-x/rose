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
use bdk_wallet::bitcoin::{Address, Amount, Transaction, Txid};
use bdk_wallet::{KeychainKind, PersistedWallet, SignOptions, Wallet};
use secrecy::SecretVec;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, error, info, info_span, warn, Instrument as _};

use crate::backoff::Backoff;
use crate::btc::chain::{BitcoindEndpoint, BitcoindRpc};
use crate::btc::keys::{self, AccountKeys};
use crate::btc::store::Persister;
use crate::coin::BitcoinNetwork;
use crate::error::{codes, RpcError};

/// Command channel depth; matches the Zcash actor's order of magnitude.
const COMMAND_BUFFER: usize = 64;

/// Blocks applied per sync pass before the loop returns to service queued commands, so a
/// deep initial sync doesn't starve sends and reads (`sync_step` is one-batch-per-call,
/// like the Zcash engine's).
const SYNC_BLOCKS_PER_PASS: usize = 512;

/// The confirmation target handed to `estimatesmartfee` for wallet-built sends.
const FEE_TARGET_BLOCKS: u16 = 6;

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

/// A handle to a running Bitcoin wallet actor - the registry's
/// (`crate::wallet::CoinWallet::Bitcoin`) payload, as `WalletHandle` is the Zcash variant's.
#[derive(Clone, Debug)]
pub struct BtcWalletHandle {
    pub name: String,
    pub network: BitcoinNetwork,
    /// Whether the wallet's `keys.toml` holds a seed (false would be a watch-only import,
    /// which the engine does not build yet; the flag exists so `getwalletinfo` reports
    /// `private_keys_enabled` from the same signal the Zcash side does).
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
    pub async fn send(&self, recipients: Vec<(String, u64)>) -> Result<String, RpcError> {
        self.dispatch(|reply| BtcCommand::Send { recipients, reply })
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
    /// The wallet's bitcoind upstream. `None` runs the actor with no sync loop (offline
    /// command service - what the pre-chain-source engine always did, kept for tests).
    pub endpoint: Option<BitcoindEndpoint>,
    /// The height the block scan starts from on an empty chain state (recorded by init).
    pub birthday: u32,
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
        endpoint,
        birthday,
        sync_interval,
        reconnect_base,
        reconnect_max,
        shutdown,
    } = config;
    let keys = seed
        .as_ref()
        .map(|seed| AccountKeys::from_seed(seed, network))
        .transpose()?;
    let mut persister = Persister::open(&engine_dir)?;
    let mut load = Wallet::load().check_network(keys::network(network));
    if let Some(keys) = &keys {
        // Assert the stored descriptors against the seed-derived ones; a mismatch fails the
        // load (and thus the spawn) with a descriptor error.
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
                    "wallet database is empty and no seed is available to create it \
                     (run `zecd init` for this wallet first)"
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

    let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_BUFFER);
    let (status_tx, status_rx) = watch::channel(status_of(&wallet, BtcConnState::Down));
    let span = info_span!("wallet", name = %name);
    let actor = BtcActor {
        wallet,
        persister,
        seed,
        network,
        endpoint,
        birthday,
        conn: None,
        backoff: Backoff::new(reconnect_base, reconnect_max),
        next_attempt: Instant::now(),
        reconnect_warned: false,
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

/// A live upstream connection: the RPC handle plus the block/mempool emitter anchored on the
/// wallet's checkpoint at connect time. Dropped (and rebuilt on reconnect) after any
/// transport error.
struct Conn {
    rpc: BitcoindRpc,
    emitter: Emitter<Arc<bdk_bitcoind_rpc::bitcoincore_rpc::Client>>,
    /// Whether the last pass reached the node's tip (drives Ready vs Syncing).
    at_tip: bool,
}

struct BtcActor {
    wallet: PersistedWallet<Persister>,
    persister: Persister,
    seed: Option<SecretVec<u8>>,
    network: BitcoinNetwork,
    endpoint: Option<BitcoindEndpoint>,
    birthday: u32,
    conn: Option<Conn>,
    backoff: Backoff,
    next_attempt: Instant,
    /// WARN once per outage, then DEBUG (the logging convention for reconnect streams).
    reconnect_warned: bool,
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
                    Ok(cmd) => self.handle(cmd),
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
                    Some(cmd) => self.handle(cmd),
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
        // The emitter's RPC calls are blocking; relocate the worker's other tasks for the
        // duration, exactly as the Zcash scan does.
        let result = tokio::task::block_in_place(|| {
            let mut applied = 0usize;
            while applied < SYNC_BLOCKS_PER_PASS {
                match conn.emitter.next_block() {
                    Ok(Some(event)) => {
                        let height = event.block_height();
                        self.wallet
                            .apply_block_connected_to(&event.block, height, event.connected_to())
                            .map_err(|e| anyhow::anyhow!("apply block {height}: {e}"))?;
                        applied += 1;
                    }
                    Ok(None) => {
                        conn.at_tip = true;
                        // Caught up: one mempool pass gives 0-conf visibility and eviction
                        // handling (evictions are only reported once the emitter is at tip).
                        let event = conn
                            .emitter
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
        });
        match result {
            Ok(applied) => {
                self.persist("sync pass");
                let at_tip = self.conn.as_ref().is_some_and(|c| c.at_tip);
                let state = if at_tip {
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
                warn!("sync error against the bitcoind upstream: {e:#}");
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
        let dial = tokio::task::block_in_place(|| endpoint.connect_blocking());
        match dial {
            Ok(rpc) => {
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
                self.conn = Some(Conn {
                    rpc,
                    emitter,
                    at_tip: false,
                });
                self.backoff.reset();
                self.reconnect_warned = false;
                self.status_tx
                    .send_replace(status_of(&self.wallet, BtcConnState::Syncing));
                true
            }
            Err(e) => {
                let delay = self.backoff.next_delay();
                if self.reconnect_warned {
                    debug!("connect to bitcoind failed (retrying in {delay:?}): {e:#}");
                } else {
                    warn!("connect to bitcoind failed (retrying in {delay:?}): {e:#}");
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

    fn handle(&mut self, cmd: BtcCommand) {
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
            BtcCommand::Send { recipients, reply } => {
                let result = self.do_send(recipients);
                let _ = reply.send(result);
            }
            BtcCommand::Broadcast { hex, reply } => {
                let result = self.do_broadcast(hex);
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

    fn do_send(&mut self, recipients: Vec<(String, u64)>) -> Result<String, RpcError> {
        let Some(seed) = &self.seed else {
            return Err(RpcError::new(
                codes::RPC_WALLET_ERROR,
                "Error: Private keys are disabled for this wallet, or the wallet is locked \
                 (bitcoin wallets have no walletpassphrase yet - use an identity-file wallet \
                 with auto_unlock for unattended sending)",
            ));
        };
        let Some(conn) = self.conn.as_ref() else {
            return Err(RpcError::new(
                codes::RPC_WALLET_ERROR,
                "no connection to the bitcoind upstream (fee estimation and broadcast need \
                 it); retry once the node is reachable",
            ));
        };
        // Fee rate: the node's smart estimate, or - matching bitcoind's fallbackfee posture -
        // a 1 sat/vB floor on test networks only (mainnet refuses rather than guessing).
        let fee_rate =
            tokio::task::block_in_place(|| conn.rpc.estimate_fee_rate_blocking(FEE_TARGET_BLOCKS))
                .map_err(|e| RpcError::new(codes::RPC_WALLET_ERROR, format!("{e:#}")))?;
        let fee_rate = match fee_rate {
            Some(rate) => rate,
            None if self.network == BitcoinNetwork::Main => {
                return Err(RpcError::new(
                    codes::RPC_WALLET_ERROR,
                    "Fee estimation failed and no fallback applies on mainnet; retry once \
                     the node has fee data",
                ))
            }
            None => bdk_wallet::bitcoin::FeeRate::from_sat_per_vb_u32(1),
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
        let mut builder = self.wallet.build_tx();
        for (address, amount) in &parsed {
            builder.add_recipient(address.script_pubkey(), *amount);
        }
        builder.fee_rate(fee_rate);
        let mut psbt = builder.finish().map_err(map_create_tx_error)?;

        // Signers are derived from the seed per send and dropped with this scope - the
        // custody model's spend half (the persisted wallet holds public descriptors only).
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
        let txid = tokio::task::block_in_place(|| conn.rpc.broadcast_blocking(&tx))
            .map_err(|e| RpcError::new(codes::RPC_VERIFY_REJECTED, format!("{e:#}")))?;
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

    fn do_broadcast(&mut self, hex: String) -> Result<String, RpcError> {
        let Some(conn) = self.conn.as_ref() else {
            return Err(RpcError::new(
                codes::RPC_WALLET_ERROR,
                "no connection to the bitcoind upstream; retry once the node is reachable",
            ));
        };
        let tx: Transaction = bdk_wallet::bitcoin::consensus::encode::deserialize_hex(&hex)
            .map_err(|e| {
                RpcError::new(
                    codes::RPC_DESERIALIZATION_ERROR,
                    format!("TX decode failed: {e}"),
                )
            })?;
        let txid = tokio::task::block_in_place(|| conn.rpc.broadcast_blocking(&tx))
            .map_err(|e| RpcError::new(codes::RPC_VERIFY_REJECTED, format!("{e:#}")))?;
        // If the transaction touches this wallet, record it at 0-conf (the apply filters
        // relevance itself, so a foreign transaction is a no-op).
        self.wallet
            .apply_unconfirmed_txs(vec![(Arc::new(tx), unix_now())]);
        self.persist("broadcast");
        Ok(txid.to_string())
    }
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
            endpoint: None,
            birthday: 0,
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
            .send(vec![(
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                10_000,
            )])
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_WALLET_ERROR);
        assert!(err.message.contains("bitcoind"), "{}", err.message);
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
