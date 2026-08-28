//! The BDK engine's second chain source: **Kyoto**, a BIP-157/158 compact-block-filter light
//! client that peers over the Bitcoin P2P layer.
//!
//! The privacy and operational contrast with [`super::chain`]'s bitcoind backend is the whole
//! point of having two:
//!
//!  * **No credentials.** There is no RPC to authenticate against, so the cleartext-credential
//!    locality gate that constrains `bitcoind://` to loopback/RFC1918 simply does not apply -
//!    nothing secret crosses the wire. This is what makes a remote-node deployment tractable
//!    without a tunnel or an rpcauth hash to provision.
//!  * **No server.** Peers come from the network's DNS seeds (or explicit `kyoto://host:port`
//!    trusted peers), and only *filters* are fetched wholesale - a block is downloaded only
//!    when its filter matches one of the wallet's scripts, so a passive observer learns far
//!    less than Electrum/Esplora's per-address queries reveal.
//!
//! ## Shape: async push, not blocking pull
//!
//! The bitcoind backend is a blocking *pull* (`Emitter::next_block` under `block_in_place`).
//! Kyoto is the opposite: the node runs as its own `tokio` task and the application *awaits*
//! curated [`Update`]s. Two consequences drive the design here:
//!
//!  1. [`UpdateSubscriber::update`](bdk_kyoto::UpdateSubscriber::update) is documented as
//!     **not cancel-safe** - it may not sit in a `tokio::select!` arm. The actor's run loop is
//!     built entirely out of `select!`, so the subscriber cannot live there.
//!  2. Each `update()` resolves only once the client has synced to the network tip, which for
//!     a recovery is minutes, not milliseconds. Awaiting it inline would starve command
//!     service (sends, balance reads) for the whole scan.
//!
//! [`KyotoConn`] resolves both with a **bridge task**: one task owns the subscriber, awaits
//! updates in a plain loop, and forwards each over a bounded channel. The actor then does a
//! non-blocking `try_recv()`, which is exactly the shape its bitcoind pull already has, and
//! the un-cancel-safe await never crosses a `select!`.
//!
//! ## What this backend cannot do
//!
//! Filters are derived from *blocks*, so there is no mempool: no 0-conf visibility for
//! incoming payments and no eviction reporting (`Emitter::mempool`'s two jobs). A payment is
//! seen when it confirms. This is strictly weaker than the Zcash light mode, which does carry
//! a mempool stream - so "the lightwalletd analog" holds for privacy, not for feature parity.
//!
//! Fee estimation has no `estimatesmartfee` equivalent either; see [`KyotoConn::estimate_fee_rate`]
//! for what is used instead and how coarse it is.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _};
use bdk_kyoto::bip157::{AddrV2, ServiceFlags};
use bdk_kyoto::builder::{Builder, BuilderExt as _};
use bdk_kyoto::{HashCheckpoint, Requester, ScanType, TrustedPeer, Update};
use bdk_wallet::bitcoin::{BlockHash, FeeRate, Transaction, Txid};
use bdk_wallet::Wallet;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::coin::BitcoinNetwork;

/// How many peers the node keeps connected. Two is kyoto's own example value and the point
/// where a single dishonest peer withholding filters is detectable by disagreement, without
/// the connection cost of a full node's eight.
const DEFAULT_REQUIRED_PEERS: u8 = 2;

/// Depth of the bridge channel between the update task and the actor. Each `Update` is a
/// whole sync-to-tip, so the actor consumes them roughly as fast as they arrive; a couple of
/// slots absorb an update landing while the actor is busy servicing commands.
const UPDATE_CHANNEL_BOUND: usize = 2;

/// How long a peer has to answer before kyoto drops it. The default is tuned for local
/// networks; P2P peers over the open internet want more headroom.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long [`broadcast`] waits for a peer to ask for the transaction before giving up.
///
/// `submit_package`'s future resolves when a peer sends a `getdata` for the announced txid,
/// which needs a connected peer that wants it - with none, nothing ever resolves it. Since
/// the actor awaits its command handlers one at a time, an unbounded wait here would wedge
/// every other command for the wallet (balance reads included) and block the shutdown
/// flush. 30s is far above the sub-second round trip a healthy peer takes, so this only
/// ever fires on the pathological case it exists for.
const BROADCAST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long [`estimate_fee_rate`] waits for the tip block before pricing on the relay floor
/// alone.
///
/// Unlike the other two requests it makes, `average_fee_rate` needs a *block* off the
/// network, and kyoto queues that request with no deadline of its own - its own docs say it
/// "may take an indefinite amount of time, until a peer responds". A stalled peer must not
/// hold a send (and with it the actor) open, and the floor is already a usable answer.
const FEE_BLOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// A shipped recovery checkpoint sitting below the birthday of **every generated zecd
/// Bitcoin wallet that will ever exist** on its network - each block was mined before
/// zecd's first release.
///
/// The reasoning that makes this sound: zecd creates a Bitcoin wallet in exactly two ways.
/// A **generated** wallet anchors its birthday at the chain tip minus the reorg margin, so
/// its birthday is at or after the release that generated it - and no release predates these
/// blocks, so no generated wallet's birthday ever will. A **restored** one defaults to the
/// BIP 84 history floor and may hold history from any point in its past. Only the first
/// case can skip ahead, and it is the common one: a fresh wallet need not scan the chain's
/// whole filter history to find funds that provably cannot predate its own creation.
///
/// That matters more than an optimization normally would, because `bip157` 0.6.x persists no
/// headers and only emits an `Update` at tip: a first sync that does not finish restarts from
/// the beginning (see this directory's README). Starting a few thousand blocks back instead
/// of hundreds of thousands (millions, on testnet3) is what lets it finish.
///
/// Correctness never depends on these values: [`recovery_floor`] compares a floor against
/// each wallet's own birthday and applies it only when the birthday is at or above it, so a
/// floor that is "too high" for some wallet merely sends that wallet down the slow
/// full-history path - it cannot skip funds.
///
/// The constants' one rule: they are **fixed anchors, not per-release moving targets**.
/// Every floor predates zecd's *first* release, so a wallet generated by any release -
/// past or future - has a birthday above every build's floor, and every build resolves
/// the same wallet the same way. Bumping a floor would strand a not-yet-synced wallet
/// from an older release below the newer floor (its birthday no longer clears it),
/// silently demoting it to the full-history path - the backward-compatibility break the
/// fixed anchor exists to avoid. The accepted cost is a first sync that grows with the
/// chain (~50k blocks/year on mainnet, faster on testnet3); the long-term fix is
/// recording the birthday *hash* at init (see this directory's README), not moving the
/// floor. The blocks are deeply buried (the mainnet one had 4389 confirmations when
/// recorded), so no reorg can orphan them.
struct ScanFloor {
    height: u32,
    hash: &'static str,
    /// The block's own header time: what [`birthday_height_for_date`] resolves a date
    /// against.
    time: u64,
}

/// Mainnet: block 960000, mined 2026-07-28.
const BTC_KYOTO_SCAN_FLOOR: ScanFloor = ScanFloor {
    height: 960_000,
    hash: "000000000000000000001268aab06132c2dd203f77b6020462cd177942d6959d",
    time: 1_785_256_412,
};

/// Testnet3: block 5080000, mined 2026-07-22. Its chain is over 5M blocks - many times
/// mainnet's filter volume - so the floor matters *more* there, not less: a first sync
/// from genesis effectively never finishes.
const BTC_KYOTO_SCAN_FLOOR_TESTNET3: ScanFloor = ScanFloor {
    height: 5_080_000,
    hash: "0000000000000d5aa125a1e782e9818dff7cd532f1701c4ef228db86d75011de",
    time: 1_784_719_269,
};

/// Testnet4: block 146000, mined 2026-07-27.
const BTC_KYOTO_SCAN_FLOOR_TESTNET4: ScanFloor = ScanFloor {
    height: 146_000,
    hash: "00000000000774b867c9eabbc5eba5919e97bb8f7b06f9e86547c7f86966f054",
    time: 1_785_193_403,
};

/// The offline resolution of a date birthday for a kyoto wallet (`init` will not start a
/// P2P node to read the chain): a date at or after the network's shipped scan floor - with
/// a day of slack over the floor block's own header time - maps to the floor height, which
/// serves *exactly* as well as the true height, since [`recovery_floor`] starts a first
/// scan at the floor for any birthday at or above it. An earlier date (or regtest, which
/// ships no floor) has no offline reference; the caller falls back to the BIP 84 history
/// floor.
pub(crate) fn birthday_height_for_date(network: BitcoinNetwork, date: u64) -> Option<u32> {
    let floor = scan_floor(network)?;
    (date >= floor.time + 24 * 60 * 60).then_some(floor.height)
}

/// The network's shipped floor. Regtest has none: its chains are built per run and stay
/// tiny, so a fresh wallet's scan from genesis is already short.
fn scan_floor(network: BitcoinNetwork) -> Option<&'static ScanFloor> {
    match network {
        BitcoinNetwork::Main => Some(&BTC_KYOTO_SCAN_FLOOR),
        BitcoinNetwork::Testnet3 => Some(&BTC_KYOTO_SCAN_FLOOR_TESTNET3),
        BitcoinNetwork::Testnet4 => Some(&BTC_KYOTO_SCAN_FLOOR_TESTNET4),
        BitcoinNetwork::Regtest => None,
    }
}

/// The gap-limit hint given to a recovery scan: how many scripts of each keychain kyoto
/// should watch for. The engine reveals addresses on demand, so this only has to cover the
/// unused lookahead beyond what the wallet has already revealed.
const RECOVERY_SCRIPT_LOOKAHEAD: u32 = 100;

/// A resolved kyoto endpoint. Unlike [`BitcoindEndpoint`](super::chain::BitcoindEndpoint)
/// there are no credentials to carry or gate - the P2P layer authenticates nothing - so this
/// holds only peer selection and where kyoto keeps its own header/filter database.
#[derive(Clone, Debug)]
pub struct KyotoEndpoint {
    network: BitcoinNetwork,
    /// Explicit trusted peers from `kyoto://host:port` tokens. Empty means discovery through
    /// the network's DNS seeds, which is the bare `kyoto` token's meaning.
    peers: Vec<(IpAddr, Option<u16>)>,
    /// Where kyoto is *told* to keep its store, beside the BDK wallet database at
    /// `<wallet>/btc/kyoto`.
    ///
    /// **Inert in `bip157` 0.6.x**: `Builder::data_dir` records the path and `node.rs`
    /// destructures it as `data_path: _`, so nothing is written - the crate's own
    /// `write_tables` for the peer book is `#[allow(unused)]`. The wiring is kept because it
    /// is the documented API and the store is the crate's stated direction, but do not read
    /// an empty directory here as a bug. The practical consequence is in `scan_type`: with
    /// no header store, a scan that does not reach the tip resumes from nothing.
    data_dir: PathBuf,
    required_peers: u8,
}

impl KyotoEndpoint {
    /// Build an endpoint from a resolved peer list and the wallet's kyoto data directory.
    pub fn new(
        network: BitcoinNetwork,
        peers: Vec<(IpAddr, Option<u16>)>,
        data_dir: PathBuf,
    ) -> Self {
        // With an explicit peer list the node is whitelist-only (see `connect`), so a
        // requirement above the number of peers named can never be satisfied: kyoto keeps
        // waiting for connections and never advances past the header sync to request
        // filters. Cap it at what the operator actually named.
        let required_peers = if peers.is_empty() {
            DEFAULT_REQUIRED_PEERS
        } else {
            u8::try_from(peers.len())
                .unwrap_or(u8::MAX)
                .min(DEFAULT_REQUIRED_PEERS)
        };
        Self {
            network,
            peers,
            data_dir,
            required_peers,
        }
    }

    pub fn describe(&self) -> String {
        match self.peers.len() {
            0 => "kyoto (p2p, dns-seeded peers)".to_string(),
            1 => {
                let (ip, port) = self.peers[0];
                match port {
                    Some(p) => format!("kyoto (p2p, trusted peer {ip}:{p})"),
                    None => format!("kyoto (p2p, trusted peer {ip})"),
                }
            }
            n => format!("kyoto (p2p, {n} trusted peers)"),
        }
    }

    /// The configuration-only checks a connect would fail on, so `zecd config check` reports
    /// them offline - the kyoto counterpart of
    /// [`BitcoindEndpoint::preflight`](super::chain::BitcoindEndpoint::preflight).
    ///
    /// There is no credential gate here (nothing secret crosses a P2P link), so the only
    /// unreachable-by-construction case is a network with no peers to find: regtest has no
    /// DNS seeds, so the bare `kyoto` token can never discover anything there.
    pub fn preflight(&self) -> anyhow::Result<()> {
        if self.network == BitcoinNetwork::Regtest && self.peers.is_empty() {
            bail!(
                "the bare 'kyoto' token cannot work on regtest: the light client finds peers \
                 through the network's DNS seeds, and regtest has none. Name the local node \
                 explicitly as 'kyoto://127.0.0.1:18444' (it must run with \
                 -blockfilterindex=1 -peerblockfilters=1), or use the 'bitcoind' backend, \
                 which is what the regtest harness runs."
            );
        }
        Ok(())
    }

    /// Start the light client for `wallet` and return the live connection.
    ///
    /// Async, unlike the bitcoind dial: `LightClient::start` spawns the node onto the current
    /// `tokio` runtime, and the bridge task is spawned here too. Returns as soon as the node
    /// is running - peer discovery and header sync proceed in the background, so a caller
    /// gets a connection before the first `Update` is available.
    pub fn connect(&self, wallet: &Wallet, birthday: u32) -> anyhow::Result<KyotoConn> {
        self.preflight()?;
        let network = crate::btc::keys::network(self.network);
        let scan_type = self.scan_type(wallet, birthday);

        // Created so the path exists the moment the crate starts honoring it; today it stays
        // empty (see `data_dir`). Cheap, and it keeps the failure mode "empty directory"
        // rather than "kyoto silently declines a path it cannot write".
        std::fs::create_dir_all(&self.data_dir).with_context(|| {
            format!(
                "create the kyoto header/filter store at {}",
                self.data_dir.display()
            )
        })?;

        let mut builder = Builder::new(network)
            .data_dir(self.data_dir.clone())
            .required_peers(self.required_peers)
            .response_timeout(RESPONSE_TIMEOUT);
        for (ip, port) in &self.peers {
            // `AddrV2` is the P2P address encoding; it has no blanket `From<IpAddr>`, so pick
            // the variant per family.
            let addr = match ip {
                IpAddr::V4(v4) => AddrV2::Ipv4(*v4),
                IpAddr::V6(v6) => AddrV2::Ipv6(*v6),
            };
            builder = builder.add_peer(TrustedPeer::new(addr, *port, ServiceFlags::NONE));
        }
        // With explicit peers the operator has named the nodes they trust to serve filters;
        // honor that exclusively rather than topping up from DNS seeds behind their back.
        if !self.peers.is_empty() {
            builder = builder.whitelist_only();
        }

        let client = builder
            .build_with_wallet(wallet, scan_type)
            .map_err(|e| anyhow!("build the kyoto light client: {e}"))
            .with_context(|| format!("connect to {}", self.describe()))?;

        let (client, logging, mut updates) = client.subscribe();
        let client = client.start();
        let requester = client.requester();

        // Kyoto's info/warning streams are the only visibility into peer discovery and
        // filter progress; route them into zecd's tracing rather than dropping them. The
        // two drains are joined, not `select!`ed with a shared break: one stream closing
        // must not discard the survivor - the warning stream carries the sole surfacing
        // of a P2P broadcast rejection (see `broadcast`).
        let describe = self.describe();
        let logs = tokio::spawn(async move {
            let mut info = logging.info_subscriber;
            let mut warns = logging.warning_subscriber;
            let info_drain = async {
                while let Some(msg) = info.recv().await {
                    debug!(upstream = %describe, "kyoto: {msg}");
                }
            };
            let warn_drain = async {
                while let Some(msg) = warns.recv().await {
                    warn!(upstream = %describe, "kyoto: {msg}");
                }
            };
            tokio::join!(info_drain, warn_drain);
        });

        // The bridge: `update()` is not cancel-safe and resolves only at tip, so it gets a
        // task of its own and hands the actor a channel it can poll without blocking.
        let (tx, rx) = mpsc::channel(UPDATE_CHANNEL_BOUND);
        let bridge = tokio::spawn(async move {
            loop {
                match updates.update().await {
                    Ok(update) => {
                        if tx.send(Ok(update)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("{e}"))).await;
                        break;
                    }
                }
            }
        });

        info!(
            upstream = %self.describe(),
            scan = ?scan_type,
            "kyoto light client started"
        );
        Ok(KyotoConn {
            updates: rx,
            requester,
            bridge,
            logs,
        })
    }

    /// Where a fresh scan starts.
    ///
    /// A wallet that has synced before resumes from its own checkpoint
    /// ([`ScanType::Sync`], which kyoto walks back by a reorg margin itself); everything
    /// below is the first-sync case.
    fn scan_type(&self, wallet: &Wallet, birthday: u32) -> ScanType {
        if wallet.latest_checkpoint().height() > 0 {
            return ScanType::Sync;
        }
        let floor = recovery_floor(self.network, birthday);
        debug!(birthday, floor = floor.height, "kyoto recovery scan start");
        ScanType::Recovery {
            used_script_index: RECOVERY_SCRIPT_LOOKAHEAD,
            checkpoint: floor,
        }
    }
}

/// A live kyoto connection: the channel the bridge task feeds, plus the requester used for
/// broadcast and the fee signals. Dropping it aborts both tasks, which shuts the node down.
pub struct KyotoConn {
    updates: mpsc::Receiver<Result<Update, String>>,
    requester: Requester,
    bridge: JoinHandle<()>,
    logs: JoinHandle<()>,
}

impl KyotoConn {
    /// The next completed sync, or `None` when the client has not reached tip since the last
    /// one. Never blocks - the awaiting happens in the bridge task.
    ///
    /// An `Err` means the update stream died (the node stopped, or lost every peer); the
    /// actor treats it like a bitcoind transport error and reconnects with backoff.
    pub fn try_next_update(&mut self) -> anyhow::Result<Option<Update>> {
        match self.updates.try_recv() {
            Ok(Ok(update)) => Ok(Some(update)),
            Ok(Err(e)) => Err(anyhow!("kyoto update stream failed: {e}")),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Err(anyhow!("the kyoto node stopped running"))
            }
        }
    }

    /// A handle for the async requests (broadcast, fee signals) the free functions below
    /// make.
    ///
    /// Handed out by value rather than borrowed because the caller is the wallet actor,
    /// whose future must stay `Send`: it may not hold a `&self` across an await, since its
    /// rusqlite persister is not `Sync`. `Requester` is a clone of a channel sender, so this
    /// costs nothing.
    pub fn requester(&self) -> Requester {
        self.requester.clone()
    }

    /// The node's current tip height, for progress reporting and `init`'s birthday anchor.
    pub async fn tip_height(&self) -> anyhow::Result<u32> {
        tip_height(self.requester.clone()).await
    }
}

/// The block a first filter scan starts from, for a wallet with nothing persisted yet.
///
/// Kyoto anchors a recovery on a [`HashCheckpoint`] - a height *and* a hash - while `init`
/// records only a birthday height, so the start cannot simply be the birthday. It is instead
/// the highest floor known to be at or below it:
///
///  * birthday at or after the network's shipped floor ([`scan_floor`]): that checkpoint.
///    This is the generated-wallet case, and skips the filter history it provably cannot
///    need - ~9 years on mainnet, over 5M blocks on testnet3.
///  * mainnet, birthday below it: SegWit activation - a restore of an older seed, whose
///    history may sit anywhere after the first block a BIP 84 output could exist in.
///  * test networks, birthday below the floor: genesis (`segwit_activation` is a mainnet
///    block). Regtest ships no floor at all - its chains are built per run and stay tiny.
///
/// The `birthday >= height` comparison is the correctness gate, and it is per-wallet: the
/// shipped floor is used only for wallets whose birthday proves they cannot have funds below
/// it. Scanning from too early is only slow; this function is what makes "too late"
/// unreachable no matter what value the constants hold.
fn recovery_floor(network: BitcoinNetwork, birthday: u32) -> HashCheckpoint {
    let Some(floor) = scan_floor(network) else {
        return HashCheckpoint::from_genesis(crate::btc::keys::network(network));
    };
    if birthday >= floor.height {
        let hash = floor
            .hash
            .parse::<BlockHash>()
            .expect("scan floors are literal block hashes; covered by a unit test");
        return HashCheckpoint::new(floor.height, hash);
    }
    if network == BitcoinNetwork::Main {
        return HashCheckpoint::segwit_activation();
    }
    HashCheckpoint::from_genesis(crate::btc::keys::network(network))
}

/// Broadcast a transaction over the P2P layer.
///
/// Unlike bitcoind's `sendrawtransaction`, acceptance here is a peer relaying it, not a node
/// validating it against its own mempool policy - so a rejection surfaces asynchronously as a
/// `Warning` in the log stream rather than as an error from this call. The returned txid is
/// the transaction's own, not a node's acknowledgement.
///
/// Bounded by [`BROADCAST_TIMEOUT`]: the future underneath resolves on a peer's `getdata`,
/// so with no connected peer it would otherwise never resolve. A timeout is reported as an
/// error, which leaves the caller *not* recording the transaction - while kyoto keeps it
/// queued for the next peer, so it may still go out later.
pub async fn broadcast(requester: Requester, tx: &Transaction) -> anyhow::Result<Txid> {
    tokio::time::timeout(BROADCAST_TIMEOUT, requester.submit_package(tx.clone()))
        .await
        .map_err(|_| {
            anyhow!(
                "no peer requested the transaction within {}s, so it is not known to have \
                 been relayed; it stays queued for the next peer that connects, but the \
                 wallet has not recorded it. Check peer connectivity and, if it does not \
                 appear once the node has peers, send again",
                BROADCAST_TIMEOUT.as_secs()
            )
        })?
        .map_err(|e| anyhow!("broadcast over the kyoto p2p layer: {e}"))?;
    Ok(tx.compute_txid())
}

/// The node's current tip height.
pub async fn tip_height(requester: Requester) -> anyhow::Result<u32> {
    let tip = requester
        .chain_tip()
        .await
        .map_err(|e| anyhow!("kyoto chain tip: {e}"))?;
    Ok(tip.height)
}

/// How many recent blocks feed the fee median. Five blunts a single outlier block (the
/// upstream's own caveat: averages are skewed by outliers, and one high-fee or empty block
/// should not set the price) while capping the worst case at five concurrent block
/// downloads, all bounded together by [`FEE_BLOCK_TIMEOUT`].
const FEE_MEDIAN_BLOCKS: u32 = 5;

/// Upward bias, in percent, applied to the block-derived median. A block average is
/// backward-looking and lags a rising market, and zecd has no `bumpfee` yet, so a slight
/// overbid is the only lever against a send sitting unconfirmed - 20% of a sane fee is
/// cheap insurance.
const MARKET_LAG_BIAS_PERCENT: u64 = 20;

/// A fee rate for a send, from the only signals a filter-based light client has.
///
/// **This is not `estimatesmartfee` and does not predict confirmation time.** It is the
/// greater of:
///
///  * the **median** of the last [`FEE_MEDIAN_BLOCKS`] blocks' average fee rates (each
///    derived from the coinbase as `(output - subsidy) / weight`), biased up by
///    [`MARKET_LAG_BIAS_PERCENT`]. The averages are anchored to header-committed data - a
///    coinbase rides the merkle root of a PoW-validated header - so unlike the feefilter a
///    peer cannot inflate one without mining, and the median blunts the single-block
///    outliers the upstream warns about; and
///  * the maximum BIP-133 fee filter across connected peers, which is the floor for the
///    transaction to propagate at all - and which IS a free, unverifiable peer claim.
///
/// Taking the max means the result is never below the relay floor, so a send does not
/// silently fail to propagate. Neither signal is capped here: `do_send` passes every rate
/// from every source through `fees::enforce_sanity_ceiling`, so a peer advertising an
/// absurd feefilter turns into a refusal at that chokepoint rather than a payment. An
/// explicit `fee_rate` argument on the send RPCs remains unimplemented.
pub async fn estimate_fee_rate(requester: Requester) -> anyhow::Result<Option<FeeRate>> {
    let tip = requester
        .chain_tip()
        .await
        .map_err(|e| anyhow!("kyoto chain tip: {e}"))?;
    let floor = requester
        .broadcast_min_feerate()
        .await
        .map_err(|e| anyhow!("kyoto broadcast fee filter: {e}"))?;
    // Each average needs a *block* off the network, and the request carries no deadline of
    // its own - so the fetches run concurrently, each under its own FEE_BLOCK_TIMEOUT (the
    // batch's wall clock is one timeout, not five), and the median is taken over whatever
    // arrived. The relay floor alone is a usable answer, so a quiet network degrades to it
    // rather than hanging or failing the send.
    let mut fetches = tokio::task::JoinSet::new();
    let first = tip.height.saturating_sub(FEE_MEDIAN_BLOCKS - 1);
    for height in first..=tip.height {
        let requester = requester.clone();
        fetches.spawn(async move {
            tokio::time::timeout(FEE_BLOCK_TIMEOUT, async {
                let header = requester.get_header(height).await.ok().flatten()?;
                requester
                    .average_fee_rate(header.header.block_hash())
                    .await
                    .ok()
            })
            .await
            .ok()
            .flatten()
        });
    }
    let mut averages = Vec::new();
    while let Some(joined) = fetches.join_next().await {
        if let Ok(Some(rate)) = joined {
            averages.push(rate);
        }
    }
    let estimate = match median_fee_rate(&mut averages) {
        Some(median) => bias_for_market_lag(median),
        None => {
            warn!(
                "no peer served any of the last {FEE_MEDIAN_BLOCKS} blocks for a fee median \
                 within {}s; falling back to the peers' relay floor alone",
                FEE_BLOCK_TIMEOUT.as_secs()
            );
            floor
        }
    };
    Ok(Some(estimate.max(floor)))
}

/// The median of the collected block averages, or `None` when nothing arrived. Sorts in
/// place; an even count takes the upper-middle element, erring high like the bias does.
fn median_fee_rate(averages: &mut [FeeRate]) -> Option<FeeRate> {
    if averages.is_empty() {
        return None;
    }
    averages.sort_unstable();
    Some(averages[averages.len() / 2])
}

/// The median plus [`MARKET_LAG_BIAS_PERCENT`], in sat/kwu so sub-sat/vB precision
/// survives the multiplication.
fn bias_for_market_lag(rate: FeeRate) -> FeeRate {
    let per_kwu = rate.to_sat_per_kwu();
    FeeRate::from_sat_per_kwu(per_kwu.saturating_add(per_kwu * MARKET_LAG_BIAS_PERCENT / 100))
}

impl Drop for KyotoConn {
    fn drop(&mut self) {
        // Order matters. `shutdown()` is what actually stops the node task `start()` spawned
        // onto the runtime - aborting the bridge and log tasks does not, since neither owns
        // it. Without this the node outlives its connection: a reconnect would stack a second
        // node on the same data directory, and the header store would never be flushed,
        // leaving every restart to re-download the whole header chain.
        if let Err(e) = self.requester.shutdown() {
            debug!("kyoto node was already stopped at shutdown: {e}");
        }
        self.bridge.abort();
        self.logs.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(network: BitcoinNetwork, peers: Vec<(IpAddr, Option<u16>)>) -> KyotoEndpoint {
        KyotoEndpoint::new(network, peers, PathBuf::from("/tmp/zecd-kyoto-test"))
    }

    #[test]
    fn bare_token_is_refused_on_regtest_and_named_actionably() {
        let err = endpoint(BitcoinNetwork::Regtest, vec![])
            .preflight()
            .unwrap_err()
            .to_string();
        assert!(err.contains("DNS seeds"), "{err}");
        assert!(err.contains("kyoto://127.0.0.1:18444"), "{err}");
        assert!(err.contains("peerblockfilters"), "{err}");
    }

    #[test]
    fn an_explicit_peer_makes_regtest_legal() {
        let peer = ("127.0.0.1".parse::<IpAddr>().unwrap(), Some(18444));
        endpoint(BitcoinNetwork::Regtest, vec![peer])
            .preflight()
            .unwrap();
    }

    #[test]
    fn public_networks_need_no_peers_configured() {
        for network in [
            BitcoinNetwork::Main,
            BitcoinNetwork::Testnet3,
            BitcoinNetwork::Testnet4,
        ] {
            endpoint(network, vec![]).preflight().unwrap();
        }
    }

    #[test]
    fn every_scan_floor_is_a_parseable_block_hash() {
        // `recovery_floor` unwraps these; a typo would panic at the first sync on that
        // network rather than here.
        for network in [
            BitcoinNetwork::Main,
            BitcoinNetwork::Testnet3,
            BitcoinNetwork::Testnet4,
        ] {
            let floor = scan_floor(network).expect("public networks ship a floor");
            let parsed = floor.hash.parse::<BlockHash>().expect("literal block hash");
            assert_eq!(
                HashCheckpoint::new(floor.height, parsed).height,
                floor.height
            );
            // The hash has the leading zeros proof-of-work implies; a truncated paste
            // would not. Mainnet difficulty gives it far more than the testnets'.
            let zeros = if network == BitcoinNetwork::Main {
                "00000000000000000000"
            } else {
                "00000000000"
            };
            assert!(floor.hash.starts_with(zeros), "{network:?} {}", floor.hash);
        }
        assert!(scan_floor(BitcoinNetwork::Regtest).is_none());
    }

    #[test]
    fn a_generated_wallets_birthday_skips_to_the_release_floor() {
        // The whole point: a wallet created after the floor need not scan the chain's
        // whole filter history - on any public network.
        for network in [
            BitcoinNetwork::Main,
            BitcoinNetwork::Testnet3,
            BitcoinNetwork::Testnet4,
        ] {
            let floor_height = scan_floor(network).unwrap().height;
            for birthday in [floor_height, floor_height + 1, floor_height + 4_300] {
                let cp = recovery_floor(network, birthday);
                assert_eq!(cp.height, floor_height, "{network:?} birthday {birthday}");
            }
        }
    }

    #[test]
    fn an_older_birthday_falls_back_to_segwit_activation() {
        // A restore may hold history from before the floor, so the floor must not apply.
        let floor_height = BTC_KYOTO_SCAN_FLOOR.height;
        let segwit = HashCheckpoint::segwit_activation();
        for birthday in [0, 481_824, floor_height - 1] {
            let cp = recovery_floor(BitcoinNetwork::Main, birthday);
            assert_eq!(cp.height, segwit.height, "birthday {birthday}");
        }
        // The test networks have no shipped SegWit checkpoint (`segwit_activation` is a
        // mainnet block), so a pre-floor restore starts at genesis there.
        for network in [BitcoinNetwork::Testnet3, BitcoinNetwork::Testnet4] {
            let floor_height = scan_floor(network).unwrap().height;
            let cp = recovery_floor(network, floor_height - 1);
            assert_eq!(cp.height, 0, "{network:?}");
        }
    }

    #[test]
    fn the_floor_never_skips_a_block_the_wallet_could_hold_funds_in() {
        // The one rule that matters: starting too early is merely slow, starting too late
        // silently misses funds and reports a false zero balance.
        //
        // Note this is NOT "the floor is at or below the birthday". On mainnet a birthday
        // below SegWit activation still starts at SegWit activation, and that is correct
        // rather than a violation: the engine is BIP 84 only, so no output it can own exists
        // in an earlier block. The real bound is the earliest block this wallet could hold a
        // BIP 84 output in.
        let floor_height = BTC_KYOTO_SCAN_FLOOR.height;
        let segwit = HashCheckpoint::segwit_activation().height;
        for network in [
            BitcoinNetwork::Main,
            BitcoinNetwork::Testnet3,
            BitcoinNetwork::Testnet4,
            BitcoinNetwork::Regtest,
        ] {
            for birthday in [
                0,
                1,
                481_823,
                481_824,
                floor_height - 1,
                floor_height,
                floor_height + 1,
                u32::MAX,
            ] {
                let earliest_possible = if network == BitcoinNetwork::Main {
                    birthday.max(segwit)
                } else {
                    birthday
                };
                let cp = recovery_floor(network, birthday);
                assert!(
                    cp.height <= earliest_possible,
                    "{network:?} birthday {birthday}: floor {} is above the earliest block \
                     this wallet could hold funds in ({earliest_possible})",
                    cp.height
                );
            }
        }
    }

    #[test]
    fn the_fee_median_blunts_outlier_blocks() {
        let vb = FeeRate::from_sat_per_vb_u32;
        assert_eq!(median_fee_rate(&mut []), None);
        assert_eq!(median_fee_rate(&mut [vb(7)]), Some(vb(7)));
        // One absurd (or empty) block does not set the price - the caveat the upstream's
        // own docs raise about averages is exactly what the median absorbs.
        assert_eq!(
            median_fee_rate(&mut [vb(3), vb(5_000), vb(4), vb(5), vb(4)]),
            Some(vb(4))
        );
        assert_eq!(
            median_fee_rate(&mut [vb(0), vb(0), vb(4), vb(5), vb(6)]),
            Some(vb(4))
        );
        // An even count takes the upper-middle element, erring high like the bias.
        assert_eq!(median_fee_rate(&mut [vb(2), vb(8)]), Some(vb(8)));
    }

    #[test]
    fn the_market_lag_bias_raises_the_estimate_by_a_fifth() {
        let rate = FeeRate::from_sat_per_kwu(1_000);
        assert_eq!(bias_for_market_lag(rate).to_sat_per_kwu(), 1_200);
        // A rate too small to carry the percentage survives unshrunk.
        let tiny = FeeRate::from_sat_per_kwu(3);
        assert_eq!(bias_for_market_lag(tiny).to_sat_per_kwu(), 3);
    }

    #[test]
    fn a_date_birthday_resolves_to_the_floor_only_when_safely_after_it() {
        let day = 24 * 60 * 60;
        for network in [
            BitcoinNetwork::Main,
            BitcoinNetwork::Testnet3,
            BitcoinNetwork::Testnet4,
        ] {
            let floor = scan_floor(network).unwrap();
            // A full day past the floor block's own header time: the floor height serves.
            assert_eq!(
                birthday_height_for_date(network, floor.time + day),
                Some(floor.height),
                "{network:?}"
            );
            // Anything closer has no safe offline answer (timestamps skew ~2h), nor does
            // an earlier date - the caller falls back to the BIP 84 history floor.
            assert_eq!(
                birthday_height_for_date(network, floor.time + day - 1),
                None,
                "{network:?}"
            );
            assert_eq!(birthday_height_for_date(network, 0), None, "{network:?}");
        }
        // Regtest ships no floor, so no date resolves.
        assert_eq!(
            birthday_height_for_date(BitcoinNetwork::Regtest, u64::MAX),
            None
        );
    }

    #[test]
    fn regtest_starts_at_genesis() {
        // Regtest ships no floor: its chains are built per run and stay tiny, so any
        // birthday starts a first scan at genesis.
        for birthday in [0, 964_300, u32::MAX] {
            let cp = recovery_floor(BitcoinNetwork::Regtest, birthday);
            assert_eq!(cp.height, 0, "birthday {birthday}");
        }
    }

    #[test]
    fn one_pinned_peer_lowers_the_connection_requirement() {
        // whitelist_only + required_peers(2) + one peer is unsatisfiable: the client syncs
        // headers and then waits forever instead of requesting filters. Observed against a
        // real node before this cap existed.
        let one = vec![("127.0.0.1".parse::<IpAddr>().unwrap(), Some(8333))];
        assert_eq!(endpoint(BitcoinNetwork::Main, one).required_peers, 1);
        // DNS-seeded discovery can reach the default, so it keeps it.
        assert_eq!(
            endpoint(BitcoinNetwork::Main, vec![]).required_peers,
            DEFAULT_REQUIRED_PEERS
        );
        // More peers than the default does not raise it.
        let three = vec![
            ("127.0.0.1".parse::<IpAddr>().unwrap(), None),
            ("10.0.0.1".parse::<IpAddr>().unwrap(), None),
            ("10.0.0.2".parse::<IpAddr>().unwrap(), None),
        ];
        assert_eq!(
            endpoint(BitcoinNetwork::Main, three).required_peers,
            DEFAULT_REQUIRED_PEERS
        );
    }

    #[test]
    fn describe_names_the_peer_selection() {
        assert!(endpoint(BitcoinNetwork::Main, vec![])
            .describe()
            .contains("dns-seeded"));
        let peer = ("10.0.0.9".parse::<IpAddr>().unwrap(), Some(8333));
        assert!(endpoint(BitcoinNetwork::Main, vec![peer])
            .describe()
            .contains("10.0.0.9:8333"));
        let two = vec![
            ("10.0.0.9".parse::<IpAddr>().unwrap(), None),
            ("10.0.0.10".parse::<IpAddr>().unwrap(), None),
        ];
        assert!(endpoint(BitcoinNetwork::Main, two)
            .describe()
            .contains("2 trusted peers"));
    }
}
