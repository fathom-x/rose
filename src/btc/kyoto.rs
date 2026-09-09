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
//!
//! ## A header-sync failure is a reconnect, escalating to an older checkpoint
//!
//! `bip157` reports a header batch it cannot accept as a [`Warning::UnexpectedSyncError`],
//! bans the peer, and keeps its in-memory header tree - which, when the rejection was the
//! tree's own fault, leaves the node parked on a stale tip forever: no update ever arrives,
//! and nothing else in the stream says so. The case that made this concrete (2026-09-03, the
//! testnet4 wallet): `BlockTree::accept_header` requires a header that *extends a fork* to
//! carry the fork parent's `bits`, a rule that is only true between mainnet retargets. On a
//! min-difficulty network the bits alternate block by block (the 20-minute rule lets CPU
//! miners produce `1d00ffff` blocks between ASIC blocks at the real target), so a fork whose
//! second header is ASIC-mined - the ordinary shape of a testnet4 reorg - is rejected, the
//! reorg never happens, and the wallet reports `Ready` at a height the network abandoned.
//! Still present in upstream master.
//!
//! zecd works around it at its seam rather than patching the crate: the warning drain
//! classifies that warning ([`fatal_sync_warning`]) and fails the update stream with
//! [`KyotoFailure::HeaderSync`], which the actor treats like any transport failure - drop
//! the connection, redial with backoff. A redial builds a **fresh** header tree from the
//! wallet's own checkpoint chain, whose tip carries no bits requirement, so the fork is
//! accepted on the retry. bdk_kyoto's `ScanType::Sync` starts that tree 7 blocks back, which
//! covers a shallow fork; deeper ones (testnet reorgs run tens of blocks) would restart *on*
//! the stale branch and fail again, so the actor counts consecutive header-sync failures and
//! [`resync_depth`] escalates each further redial geometrically from the wallet's checkpoint
//! chain ([`resync_checkpoint`]), bottoming out at the first-scan start (the recorded
//! birthday anchor or the shipped floor) - never genesis. A delivered update resets the count.
//! While it lasts the outage is honest: the wallet reports `Down`/`Syncing`, not `Ready`.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _};
use bdk_kyoto::bip157::{AddrV2, ServiceFlags};
use bdk_kyoto::builder::{Builder, BuilderExt as _};
use bdk_kyoto::{HashCheckpoint, Requester, ScanType, TrustedPeer, Update, Warning};
use bdk_wallet::bitcoin::{BlockHash, FeeRate, Transaction};
use bdk_wallet::chain::CheckPoint;
use bdk_wallet::Wallet;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::coin::BitcoinNetwork;
use crate::init::{HeightSearch, BIRTHDAY_DATE_MARGIN_SECS};

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
/// fixed anchor exists to avoid. The growing floor-to-tip gap is instead absorbed by the
/// **per-wallet birthday anchor**: `init` records a resolved
/// `(height, hash)` pair whenever it dialed a bitcoind anyway, and an anchor-less kyoto
/// first scan resolves one against its own headers ([`resolve_birthday_anchor`]) and
/// restarts there - so these floors serve as the trusted base a resolution chains from
/// and the fallback for wallets that predate the anchor, not as the common scan start.
/// The blocks are deeply buried (the mainnet one had 4389 confirmations when recorded),
/// so no reorg can orphan them.
pub(crate) struct ScanFloor {
    pub(crate) height: u32,
    pub(crate) hash: &'static str,
    /// The block's own header time: what [`birthday_height_for_date`] resolves a date
    /// against.
    pub(crate) time: u64,
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
/// P2P node to read the chain) when the shipped per-day table
/// ([`super::birthdays::anchor_for_date`], mainnet only, consulted first) does not cover
/// the date: a date at or after the network's shipped scan floor - with a day of slack
/// over the floor block's own header time - maps to the floor height, the height an
/// anchor-less first scan starts at for any birthday at or above it ([`recovery_floor`]).
/// The date itself is recorded alongside (`WalletStore::birthday_time`), and the first
/// sync refines it to the true height via [`resolve_birthday_anchor`]. An earlier date
/// (or regtest, which ships no floor) has no offline reference; the caller falls back to
/// the BIP 84 history floor.
pub(crate) fn birthday_height_for_date(network: BitcoinNetwork, date: u64) -> Option<u32> {
    let floor = scan_floor(network)?;
    (date >= floor.time + 24 * 60 * 60).then_some(floor.height)
}

/// The network's shipped floor. Regtest has none: its chains are built per run and stay
/// tiny, so a fresh wallet's scan from genesis is already short.
pub(crate) fn scan_floor(network: BitcoinNetwork) -> Option<&'static ScanFloor> {
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

/// How far back the *second* consecutive header-sync failure restarts the light client, in
/// blocks below the wallet's checkpoint tip, and the factor each further failure multiplies
/// it by (see [`resync_depth`]). The first failure needs no depth of its own: a plain redial
/// already starts 7 blocks back (bdk_kyoto's `ScanType::Sync`), enough for a shallow fork.
/// 16 then 64 covers the reorg depths testnet actually produces within two more redials;
/// past that the schedule is only there to guarantee convergence on the first-scan start.
const RESYNC_BASE_DEPTH: u32 = 16;
const RESYNC_ESCALATION: u32 = 4;

/// Why the update stream stopped delivering. The actor reacts to both by dropping the
/// connection and redialing with backoff; only [`Self::HeaderSync`] additionally counts
/// toward the escalating resync depth (see the module doc), so a node that merely stopped
/// does not push the next redial deeper into the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KyotoFailure {
    /// The node rejected a header batch (a [`Warning::UnexpectedSyncError`]) and will not
    /// advance until it is rebuilt from an older checkpoint.
    HeaderSync(String),
    /// The node stopped, or lost every peer: the bridge's own `update()` failed or the
    /// channel closed.
    Stream(String),
}

impl std::fmt::Display for KyotoFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderSync(why) => write!(
                f,
                "kyoto rejected a header batch and is parked on its current tip: {why}"
            ),
            Self::Stream(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for KyotoFailure {}

/// The warnings after which the node makes no further progress on its own - a rejected
/// header batch parks it on its current tip (the module doc's fork case), so the only way
/// forward is a rebuilt tree. Every other warning is transient or informational (peer
/// churn, a fork under evaluation, a rejected broadcast) and the node handles it itself.
pub(crate) fn fatal_sync_warning(warning: &Warning) -> Option<String> {
    match warning {
        Warning::UnexpectedSyncError { warning } => Some(warning.clone()),
        _ => None,
    }
}

/// How far below the wallet's checkpoint tip the next redial should rebuild the light
/// client, given how many header-sync failures in a row preceded it. `None` is a plain
/// `ScanType::Sync` redial (which bdk_kyoto already starts 7 blocks back): the first retry,
/// and the steady state. From the second failure on, [`RESYNC_BASE_DEPTH`] multiplied by
/// [`RESYNC_ESCALATION`] per further failure, saturating - a saturated depth resolves to the
/// first-scan start in [`resync_checkpoint`].
pub(crate) fn resync_depth(consecutive_header_failures: u32) -> Option<u32> {
    let escalations = consecutive_header_failures.checked_sub(2)?;
    Some(RESYNC_BASE_DEPTH.saturating_mul(RESYNC_ESCALATION.saturating_pow(escalations)))
}

/// The checkpoint a resync `depth` blocks below `tip` restarts from: the wallet's own
/// checkpoint at that height, or the nearest one below it (the chain is sparse away from
/// the tip), clamped at `first_scan_start` - the recorded birthday anchor or the shipped
/// floor - because nothing the wallet holds predates that and a restart at genesis would
/// re-download every filter on the network.
pub(crate) fn resync_checkpoint(
    tip: &CheckPoint,
    depth: u32,
    first_scan_start: HashCheckpoint,
) -> HashCheckpoint {
    let target = tip.height().saturating_sub(depth);
    match tip.floor_at(target) {
        Some(cp) if cp.height() > first_scan_start.height => {
            HashCheckpoint::new(cp.height(), cp.hash())
        }
        _ => first_scan_start,
    }
}

/// What a kyoto connect knows about the wallet's birthday, assembled by the actor from
/// `keys.toml` (`height`, `time`) and the engine database's recorded anchor (`anchor`,
/// via `btc::store::Persister::load_birthday_anchor`).
///
/// Together these drive [`KyotoEndpoint::scan_plan`]: a recorded anchor starts the first
/// scan at the birthday itself; otherwise the scan starts at [`recovery_floor`] and, when
/// `time` is present or `height` sits above that start, a background task resolves the
/// birthday to a `(height, hash)` anchor against the light client's own headers so the
/// actor can persist it and restart the scan there (the per-wallet anchor).
pub struct KyotoBirthday {
    /// The recorded birthday height (`keys.toml`).
    pub height: u32,
    /// The operator's `--birthday` date (unix seconds of its UTC midnight), present only
    /// when `init` could not resolve it precisely - see `WalletStore::birthday_time`.
    pub time: Option<u64>,
    /// The persisted resolved anchor, once one exists.
    pub anchor: Option<(u32, BlockHash)>,
    /// The birthday block's header time, once known. `None` asks the connect to resolve it
    /// against the light client's headers ([`resolve_birthday_time`]) - display only, for
    /// `getwalletinfo`'s `birthday.time` and `listdescriptors`' `timestamp`; nothing in the
    /// scan depends on it.
    pub block_time: Option<u64>,
}

/// A resolved birthday anchor: the height and hash a first scan can start from.
type BirthdayAnchor = (u32, BlockHash);

/// The birthday the anchor-resolution task is asked to resolve against the synced headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AnchorTarget {
    /// An exact recorded height: one `get_header` fetches its hash.
    Height(u32),
    /// An operator date (unix seconds of its UTC midnight): an interpolated header-time
    /// search ([`HeightSearch`]), erring low by the shared one-day margin.
    Date(u64),
}

/// How often the anchor-resolution task re-checks whether the header chain has grown far
/// enough to answer. Header sync from the recovery start takes seconds to a minute or two,
/// so a coarse poll costs nothing while keeping the task off the hot path.
const ANCHOR_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// How far below the node's synced tip a resolved anchor must sit, per network. An anchor
/// is a `(height, hash)` pair the *next* first scan trusts verbatim, so a block that could
/// still reorg out must never be recorded - a stale hash would strand that scan on a
/// checkpoint no peer can extend (nothing clears a bad persisted anchor today), and
/// capping the anchor deeper merely scans a few extra blocks. So the depth is priced per
/// network by how deep reorgs actually go there:
///
///  * **mainnet**: the engine's fresh-wallet reorg margin
///    (`init::BTC_FRESH_WALLET_BIRTHDAY_MARGIN`, 6) - the same judgment call made once
///    already; at mainnet's hashrate a deeper reorg is effectively unheard of.
///  * **testnet3/testnet4**: 100. The 20-minute difficulty-reset rule invites block storms
///    whose reorgs run tens of blocks - far past 6 - and testnet blocks are small and
///    plentiful, so the extra scanned band costs seconds.
///  * **regtest**: the mainnet margin. Chains there are operator-mined and tiny; a
///    100-block cap would leave `ceiling <= scan_start` on most test chains and the
///    resolution would simply never fire.
///
/// Hardcoded convention, not a measurement: nothing observes live reorg depth. The values
/// only trade scan work for safety margin, so erring deep is cheap everywhere it matters.
/// `pub(crate)` because `init`'s bitcoind paths record an anchor too
/// (`init::init_anchor_height`) and must respect the same depth - a tip-proximate anchor
/// recorded at init is exactly as reorg-able as one resolved here.
pub(crate) fn anchor_reorg_margin(network: BitcoinNetwork) -> u32 {
    match network {
        BitcoinNetwork::Main | BitcoinNetwork::Regtest => {
            crate::init::BTC_FRESH_WALLET_BIRTHDAY_MARGIN
        }
        BitcoinNetwork::Testnet3 | BitcoinNetwork::Testnet4 => 100,
    }
}

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
    /// The node, its bridge and log drains, and the anchor resolver all run on a **runtime
    /// of their own**, owned by the returned [`KyotoConn`], so dropping the connection
    /// tears down every task the light client spawned - its per-peer tasks included.
    /// `bip157`'s `shutdown()` alone does not: it only returns from the node loop, and each
    /// peer task it had spawned keeps its socket and its `Arc` of the shared broadcast
    /// queue, answering `None => continue` when the node's channel to it closes. That
    /// leaked peer would go on serving `getdata` for a transaction the wallet had since
    /// abandoned (seen live: a stopped peer, resumed after the abandonment, fetched the
    /// transaction from the dead node's peer task), and would spin on the closed channel
    /// until the remote hung up. Returns as soon as the node is running - peer discovery
    /// and header sync proceed in the background, so a caller gets a connection before the
    /// first `Update` is available.
    ///
    /// `resync` is the escalating restart depth from [`resync_depth`] - `None` on a healthy
    /// (re)dial, `Some` after repeated header-sync failures (see the module doc).
    pub fn connect(
        &self,
        wallet: &Wallet,
        birthday: &KyotoBirthday,
        resync: Option<u32>,
    ) -> anyhow::Result<KyotoConn> {
        self.preflight()?;
        let network = crate::btc::keys::network(self.network);
        let (scan_type, resolution) = self.scan_plan(wallet, birthday, resync);

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

        // Everything the light client spawns goes onto this runtime (`LightClient::start`
        // and the tasks below all use `tokio::spawn`, which targets the entered context),
        // so `KyotoConn`'s drop can end the lot. Two workers: the node loop plus a peer or
        // a block download at a time is all it ever runs concurrently.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("zecd-kyoto")
            .enable_all()
            .build()
            .context("start the kyoto light client's runtime")?;
        let entered = runtime.enter();
        let (client, logging, mut updates) = client.subscribe();
        let client = client.start();
        let requester = client.requester();

        // Kyoto's info/warning streams are the only visibility into peer discovery and
        // filter progress; route them into zecd's tracing rather than dropping them. The
        // two drains are joined, not `select!`ed with a shared break: one stream closing
        // must not discard the survivor - the warning stream carries the sole surfacing
        // of a P2P broadcast rejection (see `broadcast`).
        // The bridge channel: `update()` is not cancel-safe and resolves only at tip, so it
        // gets a task of its own (below) and hands the actor a channel it can poll without
        // blocking. The warning drain holds a sender too - a fatal warning is the one signal
        // that the node has parked itself, and it only ever surfaces on that stream.
        let (tx, rx) = mpsc::channel(UPDATE_CHANNEL_BOUND);
        let fail_tx = tx.clone();
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
                    if let Some(why) = fatal_sync_warning(&msg) {
                        // A closed channel means the actor already dropped this
                        // connection; nothing left to tell it.
                        let _ = fail_tx.send(Err(KyotoFailure::HeaderSync(why))).await;
                    }
                }
            };
            tokio::join!(info_drain, warn_drain);
        });

        let bridge = tokio::spawn(async move {
            loop {
                match updates.update().await {
                    Ok(update) => {
                        if tx.send(Ok(update)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx
                            .send(Err(KyotoFailure::Stream(format!(
                                "kyoto update stream failed: {e}"
                            ))))
                            .await;
                        break;
                    }
                }
            }
        });

        // A first scan starting below the birthday gets a resolver: a task that waits for
        // the node's own header chain to cover the birthday, resolves it to a
        // `(height, hash)` anchor, and hands the pair to the actor (which persists it and
        // restarts the scan there). It rides the same channel-fed shape as the bridge - the
        // actor polls, nothing blocks - and dies with the connection.
        let anchor = resolution.map(|(scan_start, target)| {
            let requester = requester.clone();
            let margin = anchor_reorg_margin(self.network);
            let (tx, rx) = oneshot::channel();
            let task = tokio::spawn(async move {
                if let Some(anchor) =
                    resolve_birthday_anchor(requester, scan_start, target, margin).await
                {
                    let _ = tx.send(anchor);
                }
            });
            (rx, task)
        });

        // The birthday block's time, for display, when the actor does not know it yet: the
        // same channel-fed shape, dying with the connection, polled beside the anchor.
        let birthday_time = birthday.block_time.is_none().then(|| {
            let requester = requester.clone();
            let (height, anchor) = (birthday.height, birthday.anchor);
            let (tx, rx) = oneshot::channel();
            let task = tokio::spawn(async move {
                if let Some(time) = resolve_birthday_time(requester, height, anchor).await {
                    let _ = tx.send(time);
                }
            });
            (rx, task)
        });

        drop(entered);

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
            anchor,
            runtime: Some(runtime),
            birthday_time,
        })
    }

    /// Where a fresh scan starts, and whether a birthday-anchor resolution should run
    /// beside it.
    ///
    /// A wallet that has synced before resumes from its own checkpoint
    /// ([`ScanType::Sync`], which kyoto walks back by a reorg margin itself); everything
    /// below is the first-sync case. A recorded anchor - resolved by an earlier run of the
    /// task below, or by `init` against a bitcoind - starts the scan at the birthday
    /// itself. Only the anchor-less first scan starts at [`recovery_floor`], and it is the
    /// one case that wants a resolution: the task turns the recorded birthday into an
    /// anchor so every *later* first-scan attempt (this one restarts the moment it
    /// resolves) skips the floor-to-birthday filter band - the band that grows without
    /// bound as the fixed shipped floors age.
    ///
    /// A synced wallet redialing after repeated header-sync failures (`resync`) restarts
    /// that many blocks below its own tip instead, as a recovery scan over the same script
    /// lookahead a first scan uses - a superset of what `Sync` would watch, so the rescanned
    /// band cannot miss a script the wallet has revealed since.
    fn scan_plan(
        &self,
        wallet: &Wallet,
        birthday: &KyotoBirthday,
        resync: Option<u32>,
    ) -> (ScanType, Option<(u32, AnchorTarget)>) {
        let tip = wallet.latest_checkpoint();
        if tip.height() > 0 {
            let Some(depth) = resync else {
                return (ScanType::Sync, None);
            };
            let checkpoint = resync_checkpoint(&tip, depth, self.first_scan_start(birthday));
            info!(
                depth,
                from = checkpoint.height,
                wallet_tip = tip.height(),
                "kyoto resync after repeated header-sync failures: rebuilding the light \
                 client from an older checkpoint"
            );
            let scan = ScanType::Recovery {
                used_script_index: RECOVERY_SCRIPT_LOOKAHEAD,
                checkpoint,
            };
            return (scan, None);
        }
        if let Some((height, hash)) = birthday.anchor {
            debug!(
                birthday = birthday.height,
                anchor = height,
                "kyoto recovery scan start (recorded birthday anchor)"
            );
            let scan = ScanType::Recovery {
                used_script_index: RECOVERY_SCRIPT_LOOKAHEAD,
                checkpoint: HashCheckpoint::new(height, hash),
            };
            return (scan, None);
        }
        let floor = recovery_floor(self.network, birthday.height);
        let resolution = resolution_target(floor.height, birthday);
        debug!(
            birthday = birthday.height,
            floor = floor.height,
            resolving = resolution.is_some(),
            "kyoto recovery scan start"
        );
        let scan = ScanType::Recovery {
            used_script_index: RECOVERY_SCRIPT_LOOKAHEAD,
            checkpoint: floor,
        };
        (scan, resolution.map(|target| (floor.height, target)))
    }
}

impl KyotoEndpoint {
    /// Where a first scan of this wallet starts: the recorded birthday anchor when there is
    /// one, else the network's recovery floor for the birthday - the lowest block a resync
    /// ever restarts from, since nothing the wallet holds can predate it.
    fn first_scan_start(&self, birthday: &KyotoBirthday) -> HashCheckpoint {
        match birthday.anchor {
            Some((height, hash)) => HashCheckpoint::new(height, hash),
            None => recovery_floor(self.network, birthday.height),
        }
    }
}

/// Whether an anchor-less first scan starting at `scan_start` can be improved by resolving
/// the recorded birthday, and to what target. A date always resolves (its offline record
/// was the floor, so the true height is only known from headers); a height resolves only
/// when it actually sits above the scan start - anchoring *at* the start would change
/// nothing, and a birthday below it (the mainnet pre-floor restore, clamped up to SegWit
/// activation) must not drag the scan lower.
fn resolution_target(scan_start: u32, birthday: &KyotoBirthday) -> Option<AnchorTarget> {
    if let Some(time) = birthday.time {
        return Some(AnchorTarget::Date(time));
    }
    (birthday.height > scan_start).then_some(AnchorTarget::Height(birthday.height))
}

/// A header by height off the running node, `None` while the synced chain does not cover
/// it (or the request fails - the caller retries on its next poll either way).
async fn header_at(
    requester: &Requester,
    height: u32,
) -> Option<bdk_wallet::bitcoin::block::Header> {
    requester
        .get_header(height)
        .await
        .ok()
        .flatten()
        .map(|indexed| indexed.header)
}

/// The birthday block's header time, read off the running node once its headers cover the
/// birthday: the display value behind `getwalletinfo`'s `birthday.time`. The header tree
/// never holds its own anchor (see [`resolve_birthday_anchor`]), so a birthday that *is*
/// the recorded anchor is fetched as a block by its hash instead - one download, once. A
/// birthday the tree covers neither way (it sits at an anchor-less scan start) is given up
/// on rather than polled forever; the caller's offline fallbacks stand. `None` also when
/// the node stops (the next connect spawns a fresh task).
async fn resolve_birthday_time(
    requester: Requester,
    birthday: u32,
    anchor: Option<BirthdayAnchor>,
) -> Option<u64> {
    loop {
        tokio::time::sleep(ANCHOR_POLL_INTERVAL).await;
        let tip = match requester.chain_tip().await {
            Ok(tip) => tip,
            Err(_) => return None,
        };
        if tip.height < birthday {
            continue;
        }
        if let Some(header) = header_at(&requester, birthday).await {
            return Some(u64::from(header.time));
        }
        match anchor {
            Some((height, hash)) if height == birthday => match requester.get_block(hash).await {
                Ok(indexed) => return Some(u64::from(indexed.block.header.time)),
                Err(_) => continue,
            },
            _ => return None,
        }
    }
}

/// Resolve the wallet's birthday to a `(height, hash)` anchor against the light client's
/// own synced headers - the half the per-wallet anchor deferred (the bitcoind `init` paths record
/// theirs up front).
///
/// The task polls until the header chain, which starts at the recovery checkpoint the scan
/// was launched with (`scan_start`), has grown far enough to answer, then:
///
///  * [`AnchorTarget::Height`]: one header fetch at the recorded height, made only once
///    the synced chain extends `margin` blocks past it ([`anchor_reorg_margin`], per
///    network) - so the anchor cannot name a block that could still reorg out, and a
///    partially-synced header chain cannot cap it low.
///  * [`AnchorTarget::Date`]: the shared interpolated header-time search
///    ([`HeightSearch`], bracketed at `scan_start` where headers begin), for the last
///    header at or before the date minus the shared one-day margin - erring low exactly as
///    `init`'s bitcoind date search does. Single-digit probes, one P2P header request
///    apiece.
///
/// Returns `None` - ending the task, leaving the floor-anchored scan to run as before this
/// mechanism existed - when the resolution cannot improve on `scan_start` (the date
/// predates the checkpoint's own time) or a request fails outright (the node stopped; the
/// next connect spawns a fresh task). Headers not yet covering a probe merely re-poll.
async fn resolve_birthday_anchor(
    requester: Requester,
    scan_start: u32,
    target: AnchorTarget,
    margin: u32,
) -> Option<BirthdayAnchor> {
    loop {
        tokio::time::sleep(ANCHOR_POLL_INTERVAL).await;
        let tip = match requester.chain_tip().await {
            Ok(tip) => tip,
            Err(_) => return None,
        };
        let ceiling = tip.height.saturating_sub(margin);
        if ceiling <= scan_start {
            continue;
        }
        let goal = match target {
            AnchorTarget::Height(height) => {
                // Wait until the synced headers reach the birthday plus the margin before
                // recording anything: a partially-synced ceiling caught mid-header-sync
                // would otherwise cap the anchor at wherever this poll happened to land -
                // permanently, since a recorded anchor suppresses re-resolution. (The Date
                // arm's ceiling-time check below is the same guard in time units.)
                if ceiling < height {
                    continue;
                }
                height
            }
            AnchorTarget::Date(time) => {
                let target_time = time.saturating_sub(BIRTHDAY_DATE_MARGIN_SECS);
                // The header tree never holds the recovery anchor itself: bip157's
                // `BlockTree::new` starts empty with only the anchor's *hash* as tip, and
                // headers are inserted from anchor+1 upward - so `get_header(scan_start)`
                // answers `None` forever and a bracket probing it would never complete.
                // The search therefore starts one above the scan start.
                let search_lo = scan_start + 1;
                // The search's upper endpoint must be a synced header past the target
                // date; until the chain reaches it, keep waiting.
                let Some(ceiling_header) = header_at(&requester, ceiling).await else {
                    continue;
                };
                if u64::from(ceiling_header.time) < target_time {
                    continue;
                }
                let mut search = HeightSearch::bracketed(search_lo, ceiling, target_time);
                let mut chain_moved = false;
                while let Some(probe) = search.next_probe() {
                    match header_at(&requester, probe).await {
                        Some(header) => search.observe(probe, u64::from(header.time)),
                        // A header the tip check implied should exist (a reorg mid-search,
                        // a flaky peer): restart the whole attempt on the next poll.
                        None => {
                            chain_moved = true;
                            break;
                        }
                    }
                }
                if chain_moved {
                    continue;
                }
                let answer = search.answer();
                if answer <= search_lo {
                    // Either the date sits at or before the first synced header (nothing
                    // to improve - and anchoring at `search_lo` when its own time is past
                    // the target would skip the filter of a block that could hold funds),
                    // or the genuine answer IS the first block; one block of foregone
                    // improvement is the price of not telling those apart.
                    return None;
                }
                answer
            }
        };
        match header_at(&requester, goal).await {
            Some(header) => return Some((goal, header.block_hash())),
            None => continue,
        }
    }
}

/// A live kyoto connection: the channel the bridge task feeds, plus the requester used for
/// broadcast and the fee signals. Dropping it shuts the node down and then shuts down the
/// runtime every light-client task lives on, so nothing of the connection survives it (see
/// [`KyotoEndpoint::connect`] for why the runtime exists).
pub struct KyotoConn {
    updates: mpsc::Receiver<Result<Update, KyotoFailure>>,
    requester: Requester,
    bridge: JoinHandle<()>,
    logs: JoinHandle<()>,
    /// The light client's own runtime. `Option` only so `Drop` can take it: shutting a
    /// runtime down consumes it.
    runtime: Option<tokio::runtime::Runtime>,
    /// The birthday-anchor resolution, when this connect launched one (see
    /// [`resolve_birthday_anchor`]): the channel its result arrives on plus the task
    /// itself, taken on delivery and aborted with the connection otherwise.
    anchor: Option<(oneshot::Receiver<BirthdayAnchor>, JoinHandle<()>)>,
    /// The birthday block-time resolution ([`resolve_birthday_time`]), when this connect
    /// launched one - polled like the anchor's.
    birthday_time: Option<(oneshot::Receiver<u64>, JoinHandle<()>)>,
}

impl KyotoConn {
    /// The birthday block's header time, once the resolution task has it; `None` while it
    /// is still waiting or once it has given up.
    pub fn try_resolved_birthday_time(&mut self) -> Option<u64> {
        let (rx, _task) = self.birthday_time.as_mut()?;
        match rx.try_recv() {
            Ok(time) => {
                self.birthday_time.take();
                Some(time)
            }
            Err(oneshot::error::TryRecvError::Empty) => None,
            Err(oneshot::error::TryRecvError::Closed) => {
                self.birthday_time.take();
                None
            }
        }
    }

    /// The next completed sync, or `None` when the client has not reached tip since the last
    /// one. Never blocks - the awaiting happens in the bridge task.
    ///
    /// An `Err` means the stream will deliver nothing more on this connection - the node
    /// stopped or lost every peer ([`KyotoFailure::Stream`]), or parked itself on a header
    /// batch it rejected ([`KyotoFailure::HeaderSync`]); the actor treats both like a
    /// bitcoind transport error and reconnects with backoff, the latter deeper each time.
    pub fn try_next_update(&mut self) -> Result<Option<Update>, KyotoFailure> {
        match self.updates.try_recv() {
            Ok(Ok(update)) => Ok(Some(update)),
            Ok(Err(e)) => Err(e),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(KyotoFailure::Stream(
                "the kyoto node stopped running".to_string(),
            )),
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

    /// The resolved birthday anchor, once the resolution task delivers one - polled by the
    /// actor's sync pass exactly like [`Self::try_next_update`]. Never blocks. Returns the
    /// anchor at most once; a finished (or never-launched, or failed) resolution answers
    /// `None` forever after.
    pub fn try_resolved_anchor(&mut self) -> Option<BirthdayAnchor> {
        let (rx, _task) = self.anchor.as_mut()?;
        match rx.try_recv() {
            Ok(anchor) => {
                self.anchor.take();
                Some(anchor)
            }
            Err(oneshot::error::TryRecvError::Empty) => None,
            // The task ended without an answer (nothing to improve, or the node stopped):
            // stop polling; the floor-anchored scan simply runs to completion.
            Err(oneshot::error::TryRecvError::Closed) => {
                self.anchor.take();
                None
            }
        }
    }
}

/// The block a first filter scan starts from, for a wallet with nothing persisted yet
/// **and no recorded birthday anchor** (`scan_plan` prefers the anchor when one exists).
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
///  * on top of those, the shipped per-day table ([`super::birthdays`], mainnet only): the
///    last day entry at or below the birthday, when it is higher than the floor above.
///    That is within a day of blocks of any birthday the table covers, and the table's
///    newest entry for a birthday past its end - so the mainnet shipped floor is in
///    practice the fallback for a birthday between the two, and the aging cost of the
///    fixed floor is bounded by how old the build is rather than how old the floor is.
///
/// The `birthday >= height` comparison is the correctness gate, and it is per-wallet: a
/// floor is used only for wallets whose birthday proves they cannot have funds below it.
/// Scanning from too early is only slow; this function is what makes "too late"
/// unreachable no matter what value the constants (or the table) hold.
fn recovery_floor(network: BitcoinNetwork, birthday: u32) -> HashCheckpoint {
    let shipped = match scan_floor(network) {
        None => HashCheckpoint::from_genesis(crate::btc::keys::network(network)),
        Some(floor) if birthday >= floor.height => {
            let hash = floor
                .hash
                .parse::<BlockHash>()
                .expect("scan floors are literal block hashes; covered by a unit test");
            HashCheckpoint::new(floor.height, hash)
        }
        Some(_) if network == BitcoinNetwork::Main => HashCheckpoint::segwit_activation(),
        Some(_) => HashCheckpoint::from_genesis(crate::btc::keys::network(network)),
    };
    match super::birthdays::anchor_for_height(network, birthday) {
        Some(entry) if entry.height > shipped.height => {
            HashCheckpoint::new(entry.height, entry.hash)
        }
        _ => shipped,
    }
}

/// Announce a transaction to the peers and report whether one asked for it within
/// Announce a transaction to the peers and report whether one asked for it within
/// [`BROADCAST_TIMEOUT`]: `Ok(true)` when a peer's `getdata` arrived (the bytes went out),
/// `Ok(false)` when none did. Unlike bitcoind's `sendrawtransaction`, acceptance here is a
/// peer relaying the transaction, not a node validating it against its mempool policy - a
/// rejection surfaces asynchronously as a `Warning` in the log stream, never from this
/// call. `Ok(false)` is not a failure in itself: a peer that already holds the transaction
/// never requests it again (the rebroadcast pass reads it as "nothing to do"), and with no
/// responsive peer the light client keeps the transaction queued and re-announces it to
/// every peer that completes a handshake from here on - which is why the send path records
/// the transaction on `Ok(false)` rather than dropping it (see `actor::Relay::Queued`). An
/// `Err` is the node itself having stopped: nothing was queued.
pub async fn announce(requester: Requester, tx: &Transaction) -> anyhow::Result<bool> {
    match tokio::time::timeout(BROADCAST_TIMEOUT, requester.submit_package(tx.clone())).await {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(e)) => Err(anyhow!("broadcast over the kyoto p2p layer: {e}")),
        Err(_) => Ok(false),
    }
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
        // Order matters. `shutdown()` asks the node loop to return, which is the polite half;
        // it does not reach the per-peer tasks the node spawned (see `connect`). Shutting the
        // runtime down is what ends those - every task on it is cancelled, so each peer's
        // socket closes and the shared broadcast queue dies with the last `Arc`. Without both
        // a reconnect would stack a second node on the same data directory beside the leaked
        // peers of the first. `shutdown_background` because this runs inside the actor's own
        // runtime, where a blocking shutdown is not allowed; nothing waits on the node's exit,
        // since `bip157` 0.6 persists nothing it would need to flush.
        if let Err(e) = self.requester.shutdown() {
            debug!("kyoto node was already stopped at shutdown: {e}");
        }
        self.bridge.abort();
        self.logs.abort();
        if let Some((_, task)) = &self.anchor {
            task.abort();
        }
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
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
        // whole filter history - on any public network. The testnets have only their
        // shipped floor; mainnet's per-day table places the start within a day of
        // blocks below the birthday, or at the table's newest entry past its end.
        for network in [BitcoinNetwork::Testnet3, BitcoinNetwork::Testnet4] {
            let floor_height = scan_floor(network).unwrap().height;
            for birthday in [floor_height, floor_height + 1, floor_height + 4_300] {
                let cp = recovery_floor(network, birthday);
                assert_eq!(cp.height, floor_height, "{network:?} birthday {birthday}");
            }
        }
        let floor_height = BTC_KYOTO_SCAN_FLOOR.height;
        let newest = super::super::birthdays::anchor_for_height(BitcoinNetwork::Main, u32::MAX)
            .unwrap()
            .height;
        assert!(
            newest > floor_height,
            "the table postdates the shipped floor"
        );
        for birthday in [floor_height, floor_height + 1, floor_height + 4_300] {
            let cp = recovery_floor(BitcoinNetwork::Main, birthday);
            assert!(
                floor_height <= cp.height && cp.height <= birthday && birthday - cp.height < 300,
                "birthday {birthday}: start {}",
                cp.height
            );
        }
        for birthday in [newest, newest + 1, newest + 100_000, u32::MAX] {
            let cp = recovery_floor(BitcoinNetwork::Main, birthday);
            assert_eq!(cp.height, newest, "birthday {birthday}");
        }
    }

    #[test]
    fn an_older_birthday_falls_back_to_segwit_activation() {
        // A restore may hold history from before the floor, so the floor must not apply.
        // On mainnet the per-day table takes over from SegWit activation the day after it.
        let floor_height = BTC_KYOTO_SCAN_FLOOR.height;
        let segwit = HashCheckpoint::segwit_activation();
        for birthday in [0, 481_824, 481_914] {
            let cp = recovery_floor(BitcoinNetwork::Main, birthday);
            assert_eq!(cp.height, segwit.height, "birthday {birthday}");
        }
        for birthday in [481_915, 600_000, floor_height - 1] {
            let cp = recovery_floor(BitcoinNetwork::Main, birthday);
            assert!(
                segwit.height < cp.height && cp.height <= birthday && birthday - cp.height < 300,
                "birthday {birthday}: start {}",
                cp.height
            );
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

    fn birthday(height: u32) -> KyotoBirthday {
        KyotoBirthday {
            height,
            time: None,
            anchor: None,
            block_time: None,
        }
    }

    #[test]
    fn resolution_runs_only_when_it_can_improve_on_the_scan_start() {
        // A height above the scan start is worth resolving to an anchor...
        assert_eq!(
            resolution_target(146_000, &birthday(150_000)),
            Some(AnchorTarget::Height(150_000))
        );
        // ...one at (or below - the mainnet pre-floor restore clamped up to SegWit
        // activation) the start would change nothing, or drag the scan lower.
        assert_eq!(resolution_target(146_000, &birthday(146_000)), None);
        assert_eq!(resolution_target(481_824, &birthday(100)), None);
        // A date always resolves: its offline record was the floor itself, so only the
        // headers know the true height.
        let dated = KyotoBirthday {
            time: Some(1_787_000_000),
            ..birthday(146_000)
        };
        assert_eq!(
            resolution_target(146_000, &dated),
            Some(AnchorTarget::Date(1_787_000_000))
        );
    }

    #[test]
    fn the_anchor_cap_is_deeper_where_reorgs_are() {
        // Mainnet's hashrate makes >6 unheard of; the testnets' 20-minute rule invites
        // block storms tens of blocks deep, so their anchors sit a comfortable 100 below
        // tip. Regtest keeps the shallow cap - a deep one would leave nothing resolvable
        // on its tiny operator-mined chains.
        assert_eq!(
            anchor_reorg_margin(BitcoinNetwork::Main),
            crate::init::BTC_FRESH_WALLET_BIRTHDAY_MARGIN
        );
        for network in [BitcoinNetwork::Testnet3, BitcoinNetwork::Testnet4] {
            assert!(
                anchor_reorg_margin(network) >= 100,
                "{network:?} cap must clear a block-storm reorg"
            );
        }
        assert_eq!(
            anchor_reorg_margin(BitcoinNetwork::Regtest),
            crate::init::BTC_FRESH_WALLET_BIRTHDAY_MARGIN
        );
    }

    #[test]
    fn a_recorded_anchor_beats_the_floor_and_needs_no_resolution() {
        use crate::btc::keys::{tests::bip84_seed, AccountKeys};
        use bdk_wallet::KeychainKind;
        let keys = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Testnet4).unwrap();
        let wallet = Wallet::create(
            keys.descriptor(KeychainKind::External),
            keys.descriptor(KeychainKind::Internal),
        )
        .network(keys.network)
        .create_wallet_no_persist()
        .unwrap();
        let endpoint = endpoint(BitcoinNetwork::Testnet4, vec![]);

        // Anchor-less: the first scan starts at the shipped floor and wants a resolution
        // for the above-floor birthday.
        let (scan, resolution) = endpoint.scan_plan(&wallet, &birthday(150_000), None);
        match scan {
            ScanType::Recovery { checkpoint, .. } => {
                assert_eq!(checkpoint.height, BTC_KYOTO_SCAN_FLOOR_TESTNET4.height)
            }
            other => panic!("expected a recovery scan, got {other:?}"),
        }
        assert_eq!(
            resolution,
            Some((
                BTC_KYOTO_SCAN_FLOOR_TESTNET4.height,
                AnchorTarget::Height(150_000)
            ))
        );

        // With a recorded anchor the scan starts at the birthday itself, resolving nothing.
        let hash: BlockHash = BTC_KYOTO_SCAN_FLOOR_TESTNET4.hash.parse().unwrap();
        let anchored = KyotoBirthday {
            anchor: Some((150_000, hash)),
            ..birthday(150_000)
        };
        let (scan, resolution) = endpoint.scan_plan(&wallet, &anchored, None);
        match scan {
            ScanType::Recovery { checkpoint, .. } => assert_eq!(checkpoint.height, 150_000),
            other => panic!("expected a recovery scan, got {other:?}"),
        }
        assert_eq!(resolution, None);
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

    #[test]
    fn a_rejected_header_batch_is_the_only_fatal_warning() {
        let fatal = Warning::UnexpectedSyncError {
            warning: "Unexpected header syncing error: the target work does not adhere to \
                      basic transition requirements."
                .to_string(),
        };
        let why = fatal_sync_warning(&fatal).expect("a rejected batch parks the node");
        assert!(why.contains("transition requirements"), "{why}");
        for transient in [
            Warning::NeedConnections {
                connected: 0,
                required: 1,
            },
            Warning::PeerTimedOut,
            Warning::CouldNotConnect,
            Warning::PotentialStaleTip,
            Warning::EvaluatingFork,
            Warning::ChannelDropped,
        ] {
            assert_eq!(fatal_sync_warning(&transient), None, "{transient:?}");
        }
    }

    #[test]
    fn the_resync_depth_starts_on_the_second_failure_and_escalates_geometrically() {
        // A healthy dial and the first retry are plain `Sync` redials (7 blocks back).
        assert_eq!(resync_depth(0), None);
        assert_eq!(resync_depth(1), None);
        assert_eq!(resync_depth(2), Some(16));
        assert_eq!(resync_depth(3), Some(64));
        assert_eq!(resync_depth(4), Some(256));
        assert_eq!(resync_depth(5), Some(1024));
        // Saturates rather than wrapping; a saturated depth clamps to the first-scan start.
        assert_eq!(resync_depth(40), Some(u32::MAX));
        assert_eq!(resync_depth(u32::MAX), Some(u32::MAX));
    }

    fn hash(n: u8) -> BlockHash {
        use bdk_wallet::bitcoin::hashes::Hash as _;
        BlockHash::from_byte_array([n; 32])
    }

    #[test]
    fn the_resync_checkpoint_walks_the_wallets_own_chain_and_clamps_at_the_first_scan_start() {
        use bdk_wallet::chain::BlockId;
        // A sparse checkpoint chain, as a synced wallet's is away from the tip.
        let tip = [(0u32, 0u8), (100, 1), (110, 2), (120, 3), (130, 4)]
            .into_iter()
            .fold(None::<CheckPoint>, |cp, (height, n)| {
                let id = BlockId {
                    height,
                    hash: hash(n),
                };
                Some(match cp {
                    None => CheckPoint::new(id),
                    Some(cp) => cp.insert(id),
                })
            })
            .unwrap();
        let start = HashCheckpoint::new(100, hash(1));

        // Exactly on a checkpoint, and between two (floor to the one below the target).
        let at = resync_checkpoint(&tip, 10, start);
        assert_eq!((at.height, at.hash), (120, hash(3)));
        let between = resync_checkpoint(&tip, 15, start);
        assert_eq!((between.height, between.hash), (110, hash(2)));
        // Reaching the first-scan start, or below it (genesis is on the chain but is never
        // chosen), yields the start itself.
        let clamped = resync_checkpoint(&tip, 30, start);
        assert_eq!((clamped.height, clamped.hash), (100, hash(1)));
        let saturated = resync_checkpoint(&tip, u32::MAX, start);
        assert_eq!((saturated.height, saturated.hash), (100, hash(1)));
        // A start below the wallet's chain lets the wallet's own checkpoints win down to it.
        let lower = HashCheckpoint::new(90, hash(9));
        let own = resync_checkpoint(&tip, 30, lower);
        assert_eq!((own.height, own.hash), (100, hash(1)));
        let past = resync_checkpoint(&tip, 100, lower);
        assert_eq!((past.height, past.hash), (90, hash(9)));
    }

    /// A synced wallet redials with `Sync` unless a resync depth is given, in which case it
    /// restarts as a recovery scan from its own chain that far back - the birthday anchor
    /// bounding it below.
    #[test]
    fn a_synced_wallet_resyncs_from_its_own_chain_only_when_asked() {
        use crate::btc::keys::{tests::bip84_seed, AccountKeys};
        use bdk_wallet::chain::BlockId;
        use bdk_wallet::KeychainKind;
        let keys = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Testnet4).unwrap();
        let mut wallet = Wallet::create(
            keys.descriptor(KeychainKind::External),
            keys.descriptor(KeychainKind::Internal),
        )
        .network(keys.network)
        .create_wallet_no_persist()
        .unwrap();
        let chain = [(160_000u32, 1u8), (160_010, 2), (160_020, 3)]
            .into_iter()
            .fold(wallet.latest_checkpoint(), |cp, (height, n)| {
                cp.insert(BlockId {
                    height,
                    hash: hash(n),
                })
            });
        wallet
            .apply_update(Update {
                chain: Some(chain),
                ..Default::default()
            })
            .unwrap();
        let endpoint = endpoint(BitcoinNetwork::Testnet4, vec![]);
        let anchored = KyotoBirthday {
            anchor: Some((150_000, hash(7))),
            ..birthday(150_000)
        };

        let (scan, resolution) = endpoint.scan_plan(&wallet, &anchored, None);
        assert!(matches!(scan, ScanType::Sync), "{scan:?}");
        assert_eq!(resolution, None);

        let (scan, resolution) = endpoint.scan_plan(&wallet, &anchored, Some(15));
        match scan {
            ScanType::Recovery {
                used_script_index,
                checkpoint,
            } => {
                assert_eq!((checkpoint.height, checkpoint.hash), (160_000, hash(1)));
                assert_eq!(used_script_index, RECOVERY_SCRIPT_LOOKAHEAD);
            }
            other => panic!("expected a recovery scan, got {other:?}"),
        }
        assert_eq!(resolution, None);

        let (scan, _) = endpoint.scan_plan(&wallet, &anchored, Some(u32::MAX));
        match scan {
            ScanType::Recovery { checkpoint, .. } => {
                assert_eq!((checkpoint.height, checkpoint.hash), (150_000, hash(7)))
            }
            other => panic!("expected a recovery scan, got {other:?}"),
        }
    }
}
