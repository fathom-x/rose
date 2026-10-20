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
//! rose works around it at its seam rather than patching the crate: the warning drain
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

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context as _};
use bdk_kyoto::bip157::{AddrV2, ServiceFlags};
use bdk_kyoto::builder::{Builder, BuilderExt as _};
use bdk_kyoto::{HashCheckpoint, Requester, ScanType, TrustedPeer, Update, Warning};
use bdk_wallet::bitcoin::{BlockHash, FeeRate, Transaction, Txid};
use bdk_wallet::chain::CheckPoint;
use bdk_wallet::{KeychainKind, Wallet};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::btc::fee_samples::{BlockSample, FeeSamples};
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

/// The same deadline with `[backend] p2p_receive_window_bytes` set: a 2000-header answer
/// then arrives one half-segment per round trip (`btc::net`), which is a long way past
/// five seconds on anything but a LAN. bip157's own 20 s per filter batch is not ours to
/// move, so this only buys the header batches time.
const RESPONSE_TIMEOUT_BOUNDED_WINDOW: Duration = Duration::from_secs(120);

/// How long a TCP connect to a peer may take before kyoto counts the peer unreachable.
/// bip157's default is two seconds, sized for a LAN; the same as the P2P mempool feed's
/// handshake deadline, so the two clients agree on which peers are reachable. From an
/// enclave whose egress crosses a proxy and an ocean, the default lost every whitelisted
/// peer: bip157 then ends its node task (`NoReachablePeers`), the actor drops the
/// connection and redials, and the wallet sits at `down` while the feed on the same
/// host and port stays connected.
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

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

/// A shipped recovery checkpoint sitting below the birthday of **every generated rose
/// Bitcoin wallet that will ever exist** on its network - each block was mined before
/// rose's first release.
///
/// The reasoning that makes this sound: rose creates a Bitcoin wallet in exactly two ways.
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
/// Every floor predates rose's *first* release, so a wallet generated by any release -
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
/// over the floor block's own header time - maps to the block after the floor, the first
/// block an anchor-less first scan from the floor covers (a checkpoint's own block is
/// never scanned, so [`recovery_floor`] applies the floor only to a birthday strictly
/// above it). The date itself is recorded alongside (`WalletStore::birthday_time`), and
/// the first sync refines it to the true height via [`resolve_birthday_anchor`]. An
/// earlier date (or regtest, which ships no floor) has no offline reference; the caller
/// falls back to the BIP 84 history floor.
pub(crate) fn birthday_height_for_date(network: BitcoinNetwork, date: u64) -> Option<u32> {
    let floor = scan_floor(network)?;
    (date >= floor.time + 24 * 60 * 60).then_some(floor.height + 1)
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

/// The scripts one light client connection matches filters against, as the highest
/// derivation index watched per keychain, and where its scan started.
///
/// bdk_kyoto hands bip157 a fixed set when the client is built: from index 0 through
/// `last_revealed + lookahead - 1` of each keychain - the wallet's `[wallets.<name>]
/// lookahead` either way, since rose passes it as a [`ScanType::Recovery`]'s
/// `used_script_index` and a [`ScanType::Sync`] uses it by itself; there is no separate
/// light-client number, because the node fetching a block is worth nothing unless the
/// wallet's own index attributes the output, and it attributes only within its lookahead.
/// It extends the set after each delivered update, to its own index's
/// `last_revealed + lookahead - 1`, but never rescans the blocks already passed. So as a
/// scan reveals addresses the wallet's window walks past the watched set, and from then on
/// a payment to an index beyond it matches no filter and is never fetched: with the fixed
/// 100-script recovery set rose used to pass, a restore recovered about 120 used addresses
/// per keychain, then reported synced with the rest of the funds missing. The
/// block-by-block backend has no such ceiling, since every output of every block meets the
/// index.
///
/// [`ScriptWatch::rescan_from`] is the check the actor runs after every applied update:
/// when the set bdk_kyoto would build for the index as it now stands reaches past the set
/// this connection has, it answers the checkpoint to rebuild the client from with the set
/// that index now gives, and the actor keeps the wallet at `Syncing` and restarts until a
/// pass reveals nothing past what it watched - a restore that discovers until the gap, as
/// Core's does, in as many passes as the history is lookaheads long (a wider `lookahead`,
/// or an `initial_scan` floor, means fewer). Measured by bdk_kyoto's own formula, deliberately: its set ends one
/// index short of the window the wallet attributes within (`last_revealed + lookahead`),
/// so held to the wallet's window every fresh `Sync` connection would rebuild once for
/// nothing. That last index is upstream's to watch (`TODO(upstream)`); until it does, the
/// gap a kyoto wallet bridges is one address narrower than its lookahead.
///
/// What moved the window decides how soon. A discovery - a payment the pass found at an
/// index the wallet had not revealed before the update, the way a restore finds its
/// history - whose window reaches past the set means the blocks already passed may hold
/// more payments the set could not match: the rebuild follows at once, which is what
/// makes a restore discover until the gap. A reveal by `getnewaddress` (or a change
/// address a send takes), and a payment to an address so handed out, get half a lookahead
/// of slack (`slack`): the client is rebuilt only once the window has outrun its set by
/// more than `lookahead / 2`. Held exactly to the window, a wallet handing out an address
/// per deposit rebuilt the client, and its whole script set, on nearly every block (5 s
/// per block at a lookahead of 50,000 for the rebuild alone). The slack costs
/// nothing the wallet can see: an address it handed out is always within the set, which
/// reaches `lookahead - 1` past the index revealed when the connection was built while the
/// rebuild comes after `lookahead / 2` reveals at the latest (a handed-out address past the
/// set rebuilds at once regardless); what waits for the rebuild is a payment to an index
/// nobody has handed out yet (derived elsewhere from the xpub, the `initial_scan` case),
/// which the rebuild's recovery scan from the connection's start then finds.
#[derive(Debug, Clone)]
pub struct ScriptWatch {
    /// Where this connection's scan started: the lowest a rescan from it ever goes.
    start: HashCheckpoint,
    /// The highest index in the set, per keychain.
    watched: BTreeMap<KeychainKind, u32>,
    /// How far past the set the wallet's window may run on reveals alone before the
    /// client is rebuilt: `lookahead / 2`.
    slack: u32,
}

impl ScriptWatch {
    /// The set bdk_kyoto builds for `wallet` under `scan`, starting at `start`.
    fn new(wallet: &Wallet, scan: ScanType, start: HashCheckpoint) -> Self {
        let lookahead = wallet.spk_index().lookahead();
        let scripts = match scan {
            ScanType::Sync => lookahead,
            ScanType::Recovery {
                used_script_index, ..
            } => used_script_index,
        };
        let slack = lookahead / 2;
        let watched = [KeychainKind::External, KeychainKind::Internal]
            .into_iter()
            .map(|keychain| {
                let revealed = wallet.spk_index().last_revealed_index(keychain);
                (keychain, watched_through(revealed, scripts))
            })
            .collect();
        Self {
            start,
            watched,
            slack,
        }
    }

    /// Mirror the extension bdk_kyoto applies after delivering an update whose highest
    /// used indices were `last_active`: its own index revealed through each of them, and
    /// the next update's filters are matched through that plus the wallet's `lookahead`.
    /// Only ever widens: a keychain the update did not touch keeps its set.
    fn extend(&mut self, last_active: &BTreeMap<KeychainKind, u32>, lookahead: u32) {
        for (keychain, used) in last_active {
            let through = watched_through(Some(*used), lookahead);
            self.watched
                .entry(*keychain)
                .and_modify(|w| *w = (*w).max(through))
                .or_insert(through);
        }
    }

    /// After the actor applied this connection's update, whose highest used indexes were
    /// `last_active` and before which the wallet had revealed through `revealed_before`:
    /// `None` when the set bdk_kyoto would build for the index as it now stands is within
    /// this connection's, so the scan is complete; else the checkpoint to rebuild the
    /// client from. That is the wallet's own checkpoint just below the earliest block that
    /// may hold a payment the set missed - the first block that paid an index whose reveal
    /// put an unwatched one in the window ([`first_reveal_past`]) - or, when no block did
    /// (the addresses were revealed by `getnewaddress`), the scan's own start, since such
    /// a payment could sit anywhere in the band. Clamped at the start either way, like a
    /// resync. A keychain needs the rebuild when a discovery (a used index past
    /// `revealed_before`) put the window past the set, when an address the wallet handed
    /// out lies past the set, or when the window has been carried more than `slack` past
    /// it otherwise.
    pub fn rescan_from(
        &self,
        wallet: &Wallet,
        last_active: &BTreeMap<KeychainKind, u32>,
        revealed_before: &BTreeMap<KeychainKind, u32>,
    ) -> Option<HashCheckpoint> {
        let index = wallet.spk_index();
        let lookahead = index.lookahead();
        // Read once, and only if a keychain needs it: the canonical transaction list is a
        // pass over the whole graph.
        let mut heights: Option<HashMap<Txid, u32>> = None;
        let mut needed = false;
        let mut earliest: Option<u32> = None;
        for (keychain, watched) in &self.watched {
            let revealed = index.last_revealed_index(*keychain);
            let discovered_past = last_active.get(keychain).is_some_and(|used| {
                revealed_before.get(keychain).is_none_or(|r| *used > *r)
                    && watched_through(Some(*used), lookahead) > *watched
            });
            let handed_out_past = revealed.is_some_and(|r| r > *watched);
            let window_past_slack =
                watched_through(revealed, lookahead) > watched.saturating_add(self.slack);
            if !(discovered_past || handed_out_past || window_past_slack) {
                continue;
            }
            needed = true;
            let heights = heights.get_or_insert_with(|| confirmed_heights(wallet));
            let first = first_reveal_past(*watched, lookahead);
            let from = index
                .keychain_outpoints(*keychain)
                .rev()
                .take_while(|(i, _)| *i >= first)
                .filter_map(|(_, outpoint)| heights.get(&outpoint.txid).copied())
                .min();
            info!(
                keychain = ?keychain,
                watched,
                slack = self.slack,
                revealed,
                lookahead,
                from,
                "the scan revealed addresses past the scripts the light client watched"
            );
            earliest = match (earliest, from) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        if !needed {
            return None;
        }
        let tip = wallet.latest_checkpoint();
        let depth = match earliest {
            Some(height) => tip.height().saturating_sub(height.saturating_sub(1)),
            None => u32::MAX,
        };
        Some(resync_checkpoint(&tip, depth, self.start))
    }
}

/// The highest index among `scripts` scripts peeked from index 0 past `last_revealed`:
/// bdk_kyoto's `peek_scripts`, which takes `last_revealed.unwrap_or(0) + scripts` of the
/// keychain's unbounded iterator.
fn watched_through(last_revealed: Option<u32>, scripts: u32) -> u32 {
    last_revealed
        .unwrap_or(0)
        .saturating_add(scripts)
        .saturating_sub(1)
}

/// The lowest index whose reveal puts an index past `watched` in the window
/// ([`watched_through`] of it exceeds `watched`): the first payment at or above it is the
/// earliest block a set this wide could have missed anything after.
fn first_reveal_past(watched: u32, lookahead: u32) -> u32 {
    watched.saturating_add(2).saturating_sub(lookahead)
}

/// The confirmation height of every confirmed wallet transaction.
fn confirmed_heights(wallet: &Wallet) -> HashMap<Txid, u32> {
    use bdk_wallet::chain::ChainPosition;
    wallet
        .transactions()
        .filter_map(|wtx| match wtx.chain_position {
            ChainPosition::Confirmed { anchor, .. } => {
                Some((wtx.tx_node.txid, anchor.block_id.height))
            }
            ChainPosition::Unconfirmed { .. } => None,
        })
        .collect()
}

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
    /// advance until it is rebuilt from an older checkpoint. `tip` is the header tree's
    /// height at the failure (when the node could still say): the actor implicates the
    /// recorded birthday anchor only when the tree never grew past it.
    HeaderSync { why: String, tip: Option<u32> },
    /// The node stopped, or lost every peer: the bridge's own `update()` failed or the
    /// channel closed.
    Stream(String),
}

impl std::fmt::Display for KyotoFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderSync { why, tip } => write!(
                f,
                "kyoto rejected a header batch and is parked on its current tip{}: {why}",
                tip.map(|tip| format!(" ({tip})")).unwrap_or_default()
            ),
            Self::Stream(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for KyotoFailure {}

/// The text `bip157` prefixes a rejected header batch with (`node.rs`, the header-sync
/// arm). The same `UnexpectedSyncError` variant also carries a bad merkle root, a block
/// with an unknown hash, and filter / filter-header trouble - cases where the node bans
/// the peer and carries on with the next one.
const HEADER_SYNC_ERROR_PREFIX: &str = "Unexpected header syncing error";

/// The warnings after which the node makes no further progress on its own - a rejected
/// header batch parks it on its current tip (the module doc's fork case), so the only way
/// forward is a rebuilt tree. Every other warning is transient or informational (peer
/// churn, a fork under evaluation, a rejected broadcast, a peer serving a bad block or
/// filter - banned and replaced) and the node handles it itself. Matching the whole
/// `UnexpectedSyncError` variant used to tear the node down for those too, and on a
/// checkpoint-less wallet three of them cleared a perfectly good birthday anchor.
pub(crate) fn fatal_sync_warning(warning: &Warning) -> Option<String> {
    match warning {
        Warning::UnexpectedSyncError { warning }
            if warning.starts_with(HEADER_SYNC_ERROR_PREFIX) =>
        {
            Some(warning.clone())
        }
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

/// Whether the redial built after `failures_before` consecutive header-sync failures
/// already restarted from the recorded birthday anchor - the bottom of the escalation - so
/// that one more failure means the anchor itself is on a dead branch. A checkpoint-less
/// wallet restarts from the anchor every time, so it gets two tries before the anchor is
/// suspect; a synced wallet's redial bottoms out once [`resync_checkpoint`] clamps to it.
/// The actor then clears the anchor (`Persister::clear_birthday_anchor`) and the next
/// redial starts from [`recovery_floor`], whose headers a live network does serve.
pub(crate) fn resync_bottomed_at_anchor(
    tip: &CheckPoint,
    failures_before: u32,
    anchor: (u32, BlockHash),
) -> bool {
    let anchor = HashCheckpoint::new(anchor.0, anchor.1);
    if tip.height() == 0 {
        return failures_before >= 2;
    }
    resync_depth(failures_before)
        .is_some_and(|depth| resync_checkpoint(tip, depth, anchor) == anchor)
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
    /// Explicit trusted peers from `kyoto://host:port[,host:port...]` tokens. Empty means
    /// discovery through the network's DNS seeds, which is the bare `kyoto` token's meaning.
    peers: Vec<(IpAddr, Option<u16>)>,
    /// `[backend] p2p_receive_window_bytes`: dial every peer through a loopback relay whose
    /// outbound socket has this receive buffer, so the peer never has more than one window
    /// in flight (`btc::net`). `None` is an ordinary dial.
    receive_window: Option<u32>,
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

/// The one-line description of a kyoto peer selection, shared by the endpoint and by
/// `config check`/`config show` (which describe a token with no endpoint built). Every
/// named peer is listed, so what the report shows is exactly what will be dialed.
pub fn describe_peers(peers: &[(IpAddr, Option<u16>)]) -> String {
    let render = |(ip, port): &(IpAddr, Option<u16>)| match port {
        Some(p) => format!("{ip}:{p}"),
        None => ip.to_string(),
    };
    match peers {
        [] => "kyoto (p2p, dns-seeded peers)".to_string(),
        [one] => format!("kyoto (p2p, trusted peer {})", render(one)),
        many => format!(
            "kyoto (p2p, {} trusted peers as failover: {})",
            many.len(),
            many.iter().map(render).collect::<Vec<_>>().join(", ")
        ),
    }
}

impl KyotoEndpoint {
    /// Build an endpoint from a resolved peer list and the wallet's kyoto data directory.
    pub fn new(
        network: BitcoinNetwork,
        peers: Vec<(IpAddr, Option<u16>)>,
        data_dir: PathBuf,
    ) -> Self {
        // With an explicit peer list the node is whitelist-only (see `connect`), and the
        // requirement is ONE connection whatever the list's length. Two things decide that.
        // A requirement above the number of peers named can never be satisfied - kyoto keeps
        // waiting for connections and never advances past the header sync to request
        // filters - so it could never exceed the count. And an explicit list is the operator
        // naming nodes they run and trust: its second entry is there as failover for the
        // first, not as a witness against it, so requiring both would turn one replica's
        // outage into a stalled wallet - the opposite of why it was listed. The
        // disagreement-detection argument behind `DEFAULT_REQUIRED_PEERS` is about strangers
        // from the DNS seeds, and stays there.
        let required_peers = if peers.is_empty() {
            DEFAULT_REQUIRED_PEERS
        } else {
            1
        };
        Self {
            network,
            peers,
            data_dir,
            required_peers,
            receive_window: None,
        }
    }

    /// Bound the peers' receive window (`[backend] p2p_receive_window_bytes`); see
    /// [`crate::btc::net`] for what that buys and costs.
    pub fn with_receive_window(mut self, bytes: Option<u32>) -> Self {
        self.receive_window = bytes;
        self
    }

    /// The bounded receive window, if configured - the P2P mempool feed dials with it too.
    pub fn receive_window(&self) -> Option<u32> {
        self.receive_window
    }

    /// The explicit trusted peers (`kyoto://host:port`), empty for DNS discovery. The
    /// mempool feed's P2P source peers with the first of them by default.
    pub fn peers(&self) -> &[(IpAddr, Option<u16>)] {
        &self.peers
    }

    pub fn describe(&self) -> String {
        describe_peers(&self.peers)
    }

    /// The configuration-only checks a connect would fail on, so `rose config check` reports
    /// them offline - the kyoto counterpart of
    /// [`BitcoindEndpoint::preflight`](super::chain::BitcoindEndpoint::preflight).
    ///
    /// There is no credential gate here (nothing secret crosses a P2P link), so the only
    /// unreachable-by-construction case is a network with no peers to find: regtest has no
    /// DNS seeds, so the bare `kyoto` token can never discover anything there.
    pub fn preflight(&self) -> anyhow::Result<()> {
        if self.receive_window.is_some() && self.peers.is_empty() {
            bail!(
                "[backend] p2p_receive_window_bytes needs explicit kyoto peers \
                 ('kyoto://host:port[,host:port]'): the bounded window is applied by a \
                 loopback relay per named peer, and peers found through the DNS seeds \
                 cannot be relayed"
            );
        }
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
    /// (re)dial, `Some` after repeated header-sync failures (see the module doc). `rescan`
    /// is a pending rescan checkpoint from [`ScriptWatch::rescan_from`]: the previous
    /// connection's scan revealed addresses past the scripts it watched.
    pub fn connect(
        &self,
        wallet: &Wallet,
        birthday: &KyotoBirthday,
        resync: Option<u32>,
        rescan: Option<HashCheckpoint>,
    ) -> anyhow::Result<KyotoConn> {
        self.preflight()?;
        let network = crate::btc::keys::network(self.network);
        let (scan_type, start, target) = self.scan_plan(wallet, birthday, resync, rescan);
        let tree_start = start.height;
        let resolution = target.map(|target| (tree_start, target));
        let watch = ScriptWatch::new(wallet, scan_type, start);

        // Created so the path exists the moment the crate starts honoring it; today it stays
        // empty (see `data_dir`). Cheap, and it keeps the failure mode "empty directory"
        // rather than "kyoto silently declines a path it cannot write".
        std::fs::create_dir_all(&self.data_dir).with_context(|| {
            format!(
                "create the kyoto header/filter store at {}",
                self.data_dir.display()
            )
        })?;

        // With a bounded window the peers are dialed through loopback stand-ins
        // (`btc::net::WindowRelay`): bound here so their ports are known before the
        // builder sees them, served once the runtime below exists.
        let mut relay = match self.receive_window {
            Some(bytes) => {
                let targets: Vec<SocketAddr> = self
                    .peers
                    .iter()
                    .map(|(ip, port)| {
                        SocketAddr::new(
                            *ip,
                            port.unwrap_or(super::p2p_feed::default_port(self.network)),
                        )
                    })
                    .collect();
                Some(
                    crate::btc::net::WindowRelay::bind(&targets, bytes)
                        .context("bind the loopback relay for the bounded receive window")?,
                )
            }
            None => None,
        };
        let dial_peers: Vec<(IpAddr, Option<u16>)> = match &relay {
            Some(relay) => relay
                .loopback_peers()
                .map(|addr| (addr.ip(), Some(addr.port())))
                .collect(),
            None => self.peers.clone(),
        };
        let response_timeout = if self.receive_window.is_some() {
            RESPONSE_TIMEOUT_BOUNDED_WINDOW
        } else {
            RESPONSE_TIMEOUT
        };
        let mut builder = Builder::new(network)
            .data_dir(self.data_dir.clone())
            .required_peers(self.required_peers)
            .handshake_timeout(DIAL_TIMEOUT)
            .response_timeout(response_timeout)
            // bip157 requests blocks as `MSG_BLOCK` by default, which a peer serves
            // witness-stripped (BIP 144): every received transaction would then be stored
            // without its witness - `gettransaction.hex` incomplete, and a rebroadcast of it
            // after a reorg rejected by every node for a missing witness (found by
            // `regtest_btc_reorg_deep`, where the node answered the re-announce's `getdata`
            // with a 113-byte, witness-less transaction it then dropped). `MSG_WITNESS_BLOCK`
            // costs the witness bytes on the block download and nothing else.
            .fetch_witness_data();
        for (ip, port) in &dial_peers {
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
            .thread_name("rose-kyoto")
            .enable_all()
            .build()
            .context("start the kyoto light client's runtime")?;
        let entered = runtime.enter();
        if let Some(relay) = relay.as_mut() {
            relay
                .serve()
                .context("serve the loopback relay for the bounded receive window")?;
        }
        let (client, logging, mut updates) = client.subscribe();
        let client = client.start();
        let requester = client.requester();

        // Kyoto's info/warning streams are the only visibility into peer discovery and
        // filter progress; route them into rose's tracing rather than dropping them. The
        // two drains are joined, not `select!`ed with a shared break: one stream closing
        // must not discard the survivor - the warning stream carries the sole surfacing
        // of a P2P broadcast rejection (see `broadcast`).
        // The bridge channel: `update()` is not cancel-safe and resolves only at tip, so it
        // gets a task of its own (below) and hands the actor a channel it can poll without
        // blocking. The warning drain holds a sender too - a fatal warning is the one signal
        // that the node has parked itself, and it only ever surfaces on that stream.
        let (tx, rx) = mpsc::channel(UPDATE_CHANNEL_BOUND);
        let fail_tx = tx.clone();
        let probe = requester.clone();
        let describe = self.describe();
        // Raised by the warning drain the instant it sees a fatal warning, before the tip
        // probe below: a rejected header batch also ends the update stream (the node bans
        // its peer and, with no other, halts), and the bridge must not race a generic
        // stream error past the header-sync verdict - the actor acts on whichever lands
        // first, and only the verdict escalates the redial.
        let fatal_seen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fatal_flag = fatal_seen.clone();
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
                        fatal_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                        // Where the tree stands, for the actor's anchor verdict: the node
                        // is parked, not gone, so it can usually still answer - bounded,
                        // since a node that lost its last peer answers nothing.
                        let tip = tokio::time::timeout(RESPONSE_TIMEOUT, probe.chain_tip())
                            .await
                            .ok()
                            .and_then(|tip| tip.ok())
                            .map(|tip| tip.height);
                        // A closed channel means the actor already dropped this
                        // connection; nothing left to tell it.
                        let _ = fail_tx
                            .send(Err(KyotoFailure::HeaderSync { why, tip }))
                            .await;
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
                        // A fatal warning already in flight carries the verdict for this
                        // failure; the drain delivers it once its tip probe returns.
                        if !fatal_seen.load(std::sync::atomic::Ordering::SeqCst) {
                            let _ = tx
                                .send(Err(KyotoFailure::Stream(format!(
                                    "kyoto update stream failed: {e}"
                                ))))
                                .await;
                        }
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
            from = tree_start,
            watched = ?watch.watched,
            "kyoto light client started"
        );
        Ok(KyotoConn {
            updates: rx,
            requester,
            bridge,
            logs,
            anchor,
            _relay: relay,
            runtime: Some(runtime),
            birthday_time,
            tree_start,
            watch,
            fee_sampler: None,
            started: Some(Instant::now()),
        })
    }

    /// Where a fresh scan starts - the checkpoint the light client's header tree is
    /// anchored at for it (no header at or below that height is ever in the tree) - and
    /// whether a birthday-anchor resolution should run beside it.
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
    /// band cannot miss a script the wallet has revealed since. A pending `rescan` (the
    /// previous connection's scan revealed addresses past the scripts it watched,
    /// [`ScriptWatch::rescan_from`]) restarts the same way from its checkpoint; both
    /// pending, the lower wins, since each is a floor the other's band must not skip.
    fn scan_plan(
        &self,
        wallet: &Wallet,
        birthday: &KyotoBirthday,
        resync: Option<u32>,
        rescan: Option<HashCheckpoint>,
    ) -> (ScanType, HashCheckpoint, Option<AnchorTarget>) {
        let tip = wallet.latest_checkpoint();
        if tip.height() > 0 {
            let resync_at = resync.map(|depth| {
                let checkpoint = resync_checkpoint(&tip, depth, self.first_scan_start(birthday));
                info!(
                    depth,
                    from = checkpoint.height,
                    wallet_tip = tip.height(),
                    "kyoto resync after repeated header-sync failures: rebuilding the \
                     light client from an older checkpoint"
                );
                checkpoint
            });
            let restart = match (resync_at, rescan) {
                (Some(a), Some(b)) => Some(if b.height < a.height { b } else { a }),
                (a, b) => a.or(b),
            };
            let (scan, start) = match restart {
                None => {
                    let cp = sync_tree_start(&tip);
                    (ScanType::Sync, HashCheckpoint::new(cp.height(), cp.hash()))
                }
                Some(checkpoint) => {
                    let scan = ScanType::Recovery {
                        used_script_index: wallet.spk_index().lookahead(),
                        checkpoint,
                    };
                    (scan, checkpoint)
                }
            };
            // A synced wallet without an anchor - one from before the per-wallet anchor
            // existed, or one whose anchor reorged out and was cleared - resolves one
            // against the live headers; the actor records it without a restart, so the
            // next resync bottoms out at the birthday instead of the floor. Only when the
            // tree will hold the headers, though: a `Sync` tree starts a few checkpoints
            // below the tip, so a birthday further down is simply not resolvable on this
            // connection (the resolver used to poll for it every 5 s for the connection's
            // life), and a resync tree starts at its own checkpoint.
            let target = if birthday.anchor.is_none() {
                resolution_target(start.height, birthday)
            } else {
                None
            };
            return (scan, start, target);
        }
        if let Some((height, hash)) = birthday.anchor {
            debug!(
                birthday = birthday.height,
                anchor = height,
                "kyoto recovery scan start (recorded birthday anchor)"
            );
            let checkpoint = HashCheckpoint::new(height, hash);
            let scan = ScanType::Recovery {
                used_script_index: wallet.spk_index().lookahead(),
                checkpoint,
            };
            return (scan, checkpoint, None);
        }
        let floor = recovery_floor(self.network, birthday.height);
        let target = resolution_target(floor.height, birthday);
        debug!(
            birthday = birthday.height,
            floor = floor.height,
            resolving = target.is_some(),
            "kyoto recovery scan start"
        );
        let scan = ScanType::Recovery {
            used_script_index: wallet.spk_index().lookahead(),
            checkpoint: floor,
        };
        (scan, floor, target)
    }
}

/// How many checkpoints back from the wallet's tip bdk_kyoto anchors a [`ScanType::Sync`]
/// header tree (its `IMPOSSIBLE_REORG_DEPTH`; `walk_back_max_reorg` is not exported, so
/// [`sync_tree_start`] replicates it). Below that height the tree holds no header.
const SYNC_WALK_BACK_CHECKPOINTS: usize = 7;

/// The checkpoint a `Sync` scan's header tree is anchored at: the one
/// [`SYNC_WALK_BACK_CHECKPOINTS`] steps below the tip along the wallet's own (sparse)
/// checkpoint chain, or the lowest one when the chain is shorter.
fn sync_tree_start(tip: &CheckPoint) -> CheckPoint {
    tip.iter()
        .take(SYNC_WALK_BACK_CHECKPOINTS + 1)
        .last()
        .unwrap_or_else(|| tip.clone())
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
/// was the floor, so the true height is only known from headers). A height resolves to
/// the block **before** it: bip157 stores a recovery anchor as the tree's tip and fetches
/// filters from `anchor + 1`, so an anchor at the birthday itself skipped the one block
/// the operator was told to name - the height of the first transaction - and a restore
/// whose first receive sat in it missed the payment silently. And only when that block
/// sits above the scan start: anchoring *at* the start would change nothing, and a
/// birthday below it (the mainnet pre-floor restore, clamped up to SegWit activation)
/// must not drag the scan lower.
fn resolution_target(scan_start: u32, birthday: &KyotoBirthday) -> Option<AnchorTarget> {
    if let Some(time) = birthday.time {
        return Some(AnchorTarget::Date(time));
    }
    let anchor = birthday.height.checked_sub(1)?;
    (anchor > scan_start).then_some(AnchorTarget::Height(anchor))
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
            // An anchor recorded at the birthday itself (before anchors moved one block
            // below it). The block is not in the header tree, so a fetch the node cannot
            // serve fails the same way every time: give up on the first error rather than
            // poll it for the connection's life.
            Some((height, hash)) if height == birthday => {
                return requester
                    .get_block(hash)
                    .await
                    .ok()
                    .map(|indexed| u64::from(indexed.block.header.time))
            }
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
///  * [`AnchorTarget::Height`]: one header fetch at the target height (the block before
///    the birthday - see [`resolution_target`]), made only once the synced chain extends
///    `margin` blocks past it ([`anchor_reorg_margin`], per network) - so the anchor
///    cannot name a block that could still reorg out, and a partially-synced header chain
///    cannot cap it low.
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
                // Below the tree's own start there is no header to fetch, ever - the poll
                // would never end (`resolution_target` screens this, given the true start).
                if height <= scan_start {
                    return None;
                }
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
                // The first synced header already past the target date means nothing
                // here can improve on the scan start - a synced wallet's tree begins a
                // few checkpoints below its tip, and a historical date is simply not in
                // it. Give up now rather than poll until the chain outgrows the margin.
                match header_at(&requester, search_lo).await {
                    Some(first) if u64::from(first.time) >= target_time => return None,
                    Some(_) => {}
                    None => continue,
                }
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
    /// The loopback stand-ins for the peers under `[backend] p2p_receive_window_bytes`,
    /// held so their listeners live as long as the connection; the tasks are on `runtime`.
    _relay: Option<crate::btc::net::WindowRelay>,
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
    /// The height the header tree is anchored at (see [`KyotoEndpoint::scan_plan`]): what
    /// a later resolution on this connection can and cannot reach.
    tree_start: u32,
    /// The scripts this connection matches filters against (see [`ScriptWatch`]).
    watch: ScriptWatch,
    /// The background fee sampler, once an estimate armed it ([`Self::arm_fee_sampler`]).
    fee_sampler: Option<JoinHandle<()>>,
    /// When the node started, until the first update is delivered: what the "caught up"
    /// line reports, so a restart's cost is visible in the log.
    started: Option<Instant>,
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
            Ok(Ok(update)) => {
                if let Some(started) = self.started.take() {
                    info!(
                        from = self.tree_start,
                        tip = update.chain.as_ref().map(|cp| cp.height()),
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "the light client caught up: headers and filters synced from `from` \
                         (a restart of a synced wallet resumes a few blocks below its tip)"
                    );
                }
                Ok(Some(update))
            }
            Ok(Err(e)) => Err(e),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(KyotoFailure::Stream(
                "the kyoto node stopped running".to_string(),
            )),
        }
    }

    /// After the actor applied an update from this connection: the checkpoint to rebuild
    /// the client from with a wider script set, or `None` when the scan is complete - see
    /// [`ScriptWatch::rescan_from`]. Run before [`Self::extend_watch`] for the same update:
    /// the update's blocks were matched against the set as it stood.
    pub fn rescan_from(
        &self,
        wallet: &Wallet,
        last_active: &BTreeMap<KeychainKind, u32>,
        revealed_before: &BTreeMap<KeychainKind, u32>,
    ) -> Option<HashCheckpoint> {
        self.watch.rescan_from(wallet, last_active, revealed_before)
    }

    /// Widen the watched set the way bdk_kyoto does after delivering an update whose
    /// `last_active_indices` these were (see [`ScriptWatch::extend`]).
    pub fn extend_watch(&mut self, last_active: &BTreeMap<KeychainKind, u32>, lookahead: u32) {
        self.watch.extend(last_active, lookahead);
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

    /// Start the background fee sampler if it is not running: it keeps the last
    /// [`crate::btc::fee_samples::CAPACITY`] blocks' samples in `samples`, one download per
    /// new block, so an estimate reads the ring instead of fetching blocks on the send path.
    /// The actor arms it on every estimate; it stops by itself [`FEE_SAMPLER_IDLE`] after
    /// the last one, and with the connection.
    pub fn arm_fee_sampler(&mut self, samples: SharedFeeSamples, network: BitcoinNetwork) {
        // Arming is a use: the task's first idle check must not find the ring unread and
        // exit before the estimate that armed it gets to mark it.
        lock(&samples).mark_used(Instant::now());
        if self
            .fee_sampler
            .as_ref()
            .is_some_and(|task| !task.is_finished())
        {
            return;
        }
        let Some(runtime) = self.runtime.as_ref() else {
            return;
        };
        let requester = self.requester.clone();
        self.fee_sampler = Some(runtime.spawn(async move {
            debug!("fee sampler started");
            loop {
                let idle = lock(&samples)
                    .last_used()
                    .is_none_or(|used| used.elapsed() > FEE_SAMPLER_IDLE);
                if idle {
                    debug!("fee sampler stopped: no estimate for a day");
                    return;
                }
                let depth = crate::btc::fee_samples::CAPACITY as u32;
                if let Err(e) =
                    refresh_fee_samples(&requester, &samples, network, depth, false).await
                {
                    debug!("fee sampler pass failed ({e:#}); retrying");
                }
                tokio::time::sleep(FEE_SAMPLER_POLL).await;
            }
        }));
    }

    /// Resolve the birthday anchor again against the node's headers - the actor's move
    /// after an update that reorged the wallet's chain. A fork below the anchor leaves its
    /// block orphaned, and the wallet's own chain cannot say so: BDK keeps a checkpoint
    /// below the lowest conflict an update names, so a stale anchor checkpoint survives a
    /// sparse update untouched. The headers can say so, and [`resolve_birthday_anchor`]
    /// waits for them to cover the birthday plus the reorg margin before answering; the
    /// result arrives through [`KyotoConn::try_resolved_anchor`] like a first scan's, and
    /// the actor records it only if it differs from the anchor on record. Replaces any
    /// resolution still in flight.
    pub fn re_resolve_anchor(&mut self, network: BitcoinNetwork, birthday: &KyotoBirthday) {
        // Against this connection's tree, not the recovery floor: a synced wallet's tree
        // starts a few checkpoints below its tip, and a birthday below that cannot be
        // verified here at all (the escalating redials cover a reorg that deep).
        let tree_start = self.tree_start;
        let Some(target) = resolution_target(tree_start, birthday) else {
            return;
        };
        let Some(runtime) = self.runtime.as_ref() else {
            return;
        };
        let requester = self.requester.clone();
        let margin = anchor_reorg_margin(network);
        let (tx, rx) = oneshot::channel();
        let task = runtime.spawn(async move {
            if let Some(anchor) =
                resolve_birthday_anchor(requester, tree_start, target, margin).await
            {
                let _ = tx.send(anchor);
            }
        });
        if let Some((_, previous)) = self.anchor.replace((rx, task)) {
            previous.abort();
        }
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
/// The `birthday > height` comparison is the correctness gate, and it is per-wallet: a
/// floor is used only for wallets whose birthday proves they cannot have funds at or
/// below it. Strictly below, because a checkpoint is the block the scan starts *after*
/// (kyoto fetches filters from `anchor + 1`): a floor at the birthday itself would skip
/// the birthday block, which is the first one that may hold funds. The same holds for
/// the per-day entry, which is looked up below the birthday for that reason. Scanning
/// from too early is only slow; this function is what makes "too late" unreachable no
/// matter what value the constants (or the table) hold.
fn recovery_floor(network: BitcoinNetwork, birthday: u32) -> HashCheckpoint {
    let shipped = match scan_floor(network) {
        None => HashCheckpoint::from_genesis(crate::btc::keys::network(network)),
        Some(floor) if birthday > floor.height => {
            let hash = floor
                .hash
                .parse::<BlockHash>()
                .expect("scan floors are literal block hashes; covered by a unit test");
            HashCheckpoint::new(floor.height, hash)
        }
        Some(_) if network == BitcoinNetwork::Main => HashCheckpoint::segwit_activation(),
        Some(_) => HashCheckpoint::from_genesis(crate::btc::keys::network(network)),
    };
    let below = birthday.saturating_sub(1);
    match super::birthdays::anchor_for_height(network, below) {
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

/// How many recent blocks the estimate path makes sure the ring holds before it answers
/// (see [`estimate_fee_rate`]): with the background sampler running these are already
/// there, and on a cold start they are the only blocks a send waits for - five concurrent
/// downloads, bounded together by [`FEE_BLOCK_TIMEOUT`].
const FEE_FRESH_BLOCKS: u32 = 5;

/// How often the background fee sampler looks for new blocks. Reading the tip is local to
/// the light client; only a new block costs a download.
const FEE_SAMPLER_POLL: Duration = Duration::from_secs(30);

/// How long the background fee sampler keeps running after the last estimate. A wallet that
/// never prices a send (the view-only product) never starts it, and one that stops sending
/// stops paying a block download every ten minutes a day later.
const FEE_SAMPLER_IDLE: Duration = Duration::from_secs(24 * 60 * 60);

/// How far above the recent blocks an HTTP fee oracle may price a send before it is
/// disbelieved: a multiple of the highest block average in the ring (see
/// [`oracle_ceiling`]).
const ORACLE_PLAUSIBLE_MULTIPLE: u64 = 4;

/// The block-sample ring, shared between the actor (which keeps it across reconnects), the
/// estimate path and the background sampler. Locked only between awaits.
pub type SharedFeeSamples = Arc<Mutex<FeeSamples>>;

/// How far the peers' BIP-133 feefilter may lift the estimate above the block-derived
/// one: a multiple of it. An honest node's mempool minimum sits *below* what blocks
/// are paying - blocks take the top of the mempool, the filter reflects its bottom - so
/// twice the median leaves every honest filter room while bounding what one stranger's
/// claim can cost.
const FEEFILTER_MEDIAN_MULTIPLE: u64 = 2;

/// How far the feefilter is honored without corroboration, in sat/vB: always up to here,
/// whatever the blocks say, and alone when no block estimate arrived. Without corroboration
/// the filter is nothing but a peer's word; an honest one sits at the 1 sat/vB relay floor
/// except while mempools are full, and a full mempool is exactly when blocks are there to
/// be read. It is also what keeps a floor-priced estimate - an idle market, the norm on
/// regtest and a quiet testnet - from capping a busier peer's filter below what it relays.
const FEEFILTER_UNCORROBORATED_MAX_SAT_PER_VB: u32 = 10;

/// A fee rate for a send, from the only signals a filter-based light client has.
///
/// **This is not `estimatesmartfee`**, though it takes a confirmation target. It is the
/// greater of:
///
///  * the **block-derived estimate** ([`crate::btc::fee_samples`]): a recency-weighted
///    quantile of recent blocks' average fee rates, one quantile per target, blended toward
///    the relay floor unless recent blocks were full. The averages come from each block's
///    coinbase (`(output - subsidy) / weight`) and are anchored to header-committed data - a
///    coinbase rides the merkle root of a PoW-validated header - so unlike the feefilter a
///    peer cannot inflate one without mining; and
///  * the BIP-133 fee filter, the floor for the transaction to propagate - **capped**, see
///    [`combine_fee_signals`]. `bip157` reports only the *maximum* filter across connected
///    peers, so on a DNS-seeded wallet it is one stranger's free, unverifiable claim: left
///    uncapped, a single peer advertising a huge filter priced the next send at the 2000
///    sat/vB sanity ceiling. Capped, it can lift the estimate to at most the greater of
///    [`FEEFILTER_UNCORROBORATED_MAX_SAT_PER_VB`] and [`FEEFILTER_MEDIAN_MULTIPLE`] times the
///    estimate; a send that then undershoots that one peer's filter still propagates
///    through any honest peer, which is all relay needs.
///
/// The samples come from `samples`, which the background sampler keeps warm; this call
/// only fetches the last [`FEE_FRESH_BLOCKS`] blocks the ring lacks (all of them on a cold
/// start, none once warm) and checks the rest against the header chain.
///
/// `do_send` still passes the result through `fees::enforce_sanity_ceiling`; that ceiling
/// is the backstop rather than the bound.
pub async fn estimate_fee_rate(
    requester: Requester,
    samples: SharedFeeSamples,
    network: BitcoinNetwork,
    target: u16,
) -> anyhow::Result<Option<FeeRate>> {
    lock(&samples).mark_used(Instant::now());
    let floor = requester
        .broadcast_min_feerate()
        .await
        .map_err(|e| anyhow!("kyoto broadcast fee filter: {e}"))?;
    let tip = refresh_fee_samples(&requester, &samples, network, FEE_FRESH_BLOCKS, true).await?;
    let estimate = lock(&samples).estimate(tip, target);
    match &estimate {
        Some(e) => debug!(
            target_blocks = target,
            samples = e.samples,
            congestion_percent = e.congestion_percent,
            quantile_sat_per_kwu = e.quantile.to_sat_per_kwu(),
            estimate_sat_per_kwu = e.rate.to_sat_per_kwu(),
            "block-derived fee estimate"
        ),
        None => warn!(
            "no peer served any of the last {FEE_FRESH_BLOCKS} blocks for a fee estimate \
             within {}s; falling back to the peers' relay floor alone (capped at \
             {FEEFILTER_UNCORROBORATED_MAX_SAT_PER_VB} sat/vB)",
            FEE_BLOCK_TIMEOUT.as_secs()
        ),
    }
    let (rate, capped) = combine_fee_signals(estimate.map(|e| e.rate), floor);
    if capped {
        warn!(
            feefilter_sat_per_kwu = floor.to_sat_per_kwu(),
            estimate_sat_per_kwu = rate.to_sat_per_kwu(),
            "a peer's BIP-133 fee filter is far above what blocks are paying; not letting \
             it set the fee (any honest peer relays at the estimate)"
        );
    }
    Ok(Some(rate))
}

/// The most an HTTP fee oracle may answer before the wallet disbelieves it: the greater of
/// [`ORACLE_PLAUSIBLE_MULTIPLE`] times the highest average fee rate among the ring's recent
/// blocks and [`FEEFILTER_UNCORROBORATED_MAX_SAT_PER_VB`] (below which any answer passes,
/// as a quiet chain's near-zero averages would otherwise refuse a sane oracle). `None` when
/// no block could be read: then the sanity ceiling is the only bound, as before.
///
/// An oracle sees the mempool and the ring sees only blocks, so the check is deliberately
/// loose: it catches an oracle that is broken or hostile - one that would price a send at
/// many times what any recent block paid - not one that is a little ahead of the chain.
pub async fn oracle_ceiling(
    requester: Requester,
    samples: SharedFeeSamples,
    network: BitcoinNetwork,
) -> anyhow::Result<Option<FeeRate>> {
    lock(&samples).mark_used(Instant::now());
    let tip = refresh_fee_samples(&requester, &samples, network, FEE_FRESH_BLOCKS, true).await?;
    let highest = lock(&samples).highest_recent(tip);
    Ok(highest.map(|rate| {
        FeeRate::from_sat_per_kwu(
            rate.to_sat_per_kwu()
                .saturating_mul(ORACLE_PLAUSIBLE_MULTIPLE),
        )
        .max(FeeRate::from_sat_per_vb_u32(
            FEEFILTER_UNCORROBORATED_MAX_SAT_PER_VB,
        ))
    }))
}

/// Bring the ring up to date with the header chain, answering the tip height: drop samples
/// above the tip or whose block a reorg replaced (a header lookup is local), then fetch the
/// blocks it lacks among the last `depth` - concurrently for the estimate path, whose wall
/// clock is one [`FEE_BLOCK_TIMEOUT`], one at a time for the background sampler.
async fn refresh_fee_samples(
    requester: &Requester,
    samples: &SharedFeeSamples,
    network: BitcoinNetwork,
    depth: u32,
    concurrent: bool,
) -> anyhow::Result<u32> {
    let tip = requester
        .chain_tip()
        .await
        .map_err(|e| anyhow!("kyoto chain tip: {e}"))?
        .height;
    let held = {
        let mut ring = lock(samples);
        ring.truncate_above(tip);
        ring.heights()
    };
    for height in held {
        let current = requester.get_header(height).await.ok().flatten();
        let mut ring = lock(samples);
        let stale = match (current, ring.get(height)) {
            (Some(header), Some(sample)) => header.header.block_hash() != sample.hash,
            (None, Some(_)) => true,
            (_, None) => false,
        };
        if stale {
            debug!(
                height,
                "a reorg replaced a fee-sample block; dropping its sample"
            );
            ring.remove(height);
        }
    }
    let missing = lock(samples).missing(tip, depth);
    if concurrent {
        let mut fetches = tokio::task::JoinSet::new();
        for height in missing {
            let requester = requester.clone();
            fetches.spawn(async move { fetch_block_sample(&requester, network, height).await });
        }
        while let Some(joined) = fetches.join_next().await {
            if let Ok(Some((height, sample))) = joined {
                lock(samples).insert(height, sample);
            }
        }
    } else {
        for height in missing {
            if let Some((height, sample)) = fetch_block_sample(requester, network, height).await {
                lock(samples).insert(height, sample);
            }
        }
    }
    Ok(tip)
}

/// One block's fee sample, fetched under [`FEE_BLOCK_TIMEOUT`]; `None` when no peer served
/// it in time.
async fn fetch_block_sample(
    requester: &Requester,
    network: BitcoinNetwork,
    height: u32,
) -> Option<(u32, BlockSample)> {
    tokio::time::timeout(FEE_BLOCK_TIMEOUT, async {
        let header = requester.get_header(height).await.ok().flatten()?;
        let hash = header.header.block_hash();
        let indexed = requester.get_block(hash).await.ok()?;
        Some((height, block_sample(&indexed.block, hash, height, network)))
    })
    .await
    .ok()
    .flatten()
}

/// A block's average fee rate and weight. The fee is the coinbase's claim above the
/// subsidy - what `bip157`'s `average_fee_rate` computes, but on this network's halving
/// schedule (regtest halves every 150 blocks, and the mainnet schedule there reads every
/// block past 150 as fee-less at best).
fn block_sample(
    block: &bdk_wallet::bitcoin::Block,
    hash: BlockHash,
    height: u32,
    network: BitcoinNetwork,
) -> BlockSample {
    let weight_wu = block.weight().to_wu();
    let revenue: u64 = block
        .txdata
        .first()
        .map(|coinbase| coinbase.output.iter().map(|o| o.value.to_sat()).sum())
        .unwrap_or(0);
    let fees = revenue.saturating_sub(block_subsidy_sat(height, network));
    BlockSample {
        hash,
        fee_rate_sat_per_kwu: (fees.saturating_mul(1_000))
            .checked_div(weight_wu)
            .unwrap_or(0),
        weight_wu,
    }
}

/// The block subsidy at `height`: 50 BTC halved every 210,000 blocks (150 on regtest).
fn block_subsidy_sat(height: u32, network: BitcoinNetwork) -> u64 {
    let interval = match network {
        BitcoinNetwork::Regtest => 150,
        _ => 210_000,
    };
    let halvings = height / interval;
    if halvings >= 64 {
        0
    } else {
        (50 * 100_000_000u64) >> halvings
    }
}

/// The ring's lock. A poisoned lock means a panic mid-update of plain data; the samples are
/// still samples, so carry on with them.
fn lock(samples: &SharedFeeSamples) -> std::sync::MutexGuard<'_, FeeSamples> {
    samples
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Combine the block-derived estimate and the peers' maximum feefilter into the send's
/// rate: the greater of the two, with the filter's contribution capped at the greater of
/// [`FEEFILTER_UNCORROBORATED_MAX_SAT_PER_VB`] and [`FEEFILTER_MEDIAN_MULTIPLE`] times the
/// estimate (the former alone when no estimate arrived). The flag reports whether the cap bit,
/// for the caller's WARN.
fn combine_fee_signals(median: Option<FeeRate>, feefilter: FeeRate) -> (FeeRate, bool) {
    let uncorroborated = FeeRate::from_sat_per_vb_u32(FEEFILTER_UNCORROBORATED_MAX_SAT_PER_VB);
    let cap = match median {
        Some(median) => FeeRate::from_sat_per_kwu(
            median
                .to_sat_per_kwu()
                .saturating_mul(FEEFILTER_MEDIAN_MULTIPLE),
        )
        .max(uncorroborated),
        None => uncorroborated,
    };
    let floor = feefilter.min(cap);
    let rate = median.map_or(floor, |median| median.max(floor));
    (rate, feefilter > cap)
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
        if let Some(task) = &self.fee_sampler {
            task.abort();
        }
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
        KyotoEndpoint::new(network, peers, PathBuf::from("/tmp/rose-kyoto-test"))
    }

    #[test]
    fn bounded_window_needs_explicit_peers() {
        let one = vec![("192.0.2.7".parse().unwrap(), Some(8333))];
        assert!(endpoint(BitcoinNetwork::Main, vec![])
            .with_receive_window(Some(1448))
            .preflight()
            .is_err());
        assert!(endpoint(BitcoinNetwork::Main, one.clone())
            .with_receive_window(Some(1448))
            .preflight()
            .is_ok());
        assert_eq!(
            endpoint(BitcoinNetwork::Main, one)
                .with_receive_window(Some(1448))
                .receive_window(),
            Some(1448)
        );
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
            for birthday in [floor_height + 1, floor_height + 2, floor_height + 4_300] {
                let cp = recovery_floor(network, birthday);
                assert_eq!(cp.height, floor_height, "{network:?} birthday {birthday}");
            }
            // A birthday AT the floor may hold funds in the floor block, which a scan from
            // the floor skips; with no per-day table the testnets fall back to genesis -
            // slow, never wrong (a date birthday records floor + 1 for this reason).
            assert_eq!(
                recovery_floor(network, floor_height).height,
                0,
                "{network:?}"
            );
        }
        let floor_height = BTC_KYOTO_SCAN_FLOOR.height;
        let newest = super::super::birthdays::anchor_for_height(BitcoinNetwork::Main, u32::MAX)
            .unwrap()
            .height;
        assert!(
            newest > floor_height,
            "the table postdates the shipped floor"
        );
        // A birthday AT the floor may hold funds in the floor block itself, which a scan
        // from the floor would skip: it starts at the table entry a day earlier instead.
        let at_floor = recovery_floor(BitcoinNetwork::Main, floor_height);
        assert!(at_floor.height < floor_height, "{}", at_floor.height);
        for birthday in [floor_height + 1, floor_height + 2, floor_height + 4_300] {
            let cp = recovery_floor(BitcoinNetwork::Main, birthday);
            assert!(
                floor_height <= cp.height && cp.height < birthday && birthday - cp.height < 300,
                "birthday {birthday}: start {}",
                cp.height
            );
        }
        for birthday in [newest + 1, newest + 100_000, u32::MAX] {
            let cp = recovery_floor(BitcoinNetwork::Main, birthday);
            assert_eq!(cp.height, newest, "birthday {birthday}");
        }
        // A birthday AT the newest entry may hold funds in that block, which a scan from
        // it would skip: it starts a day earlier.
        let at_newest = recovery_floor(BitcoinNetwork::Main, newest);
        assert!(at_newest.height < newest, "{}", at_newest.height);
    }

    #[test]
    fn an_older_birthday_falls_back_to_segwit_activation() {
        // A restore may hold history from before the floor, so the floor must not apply.
        // On mainnet the per-day table takes over from SegWit activation the day after it.
        let floor_height = BTC_KYOTO_SCAN_FLOOR.height;
        let segwit = HashCheckpoint::segwit_activation();
        // 481_915 is the table's first entry; a birthday there starts at SegWit
        // activation too, since the entry's own block is the one a scan from it skips.
        for birthday in [0, 481_824, 481_914, 481_915] {
            let cp = recovery_floor(BitcoinNetwork::Main, birthday);
            assert_eq!(cp.height, segwit.height, "birthday {birthday}");
        }
        for birthday in [481_916, 600_000, floor_height - 1] {
            let cp = recovery_floor(BitcoinNetwork::Main, birthday);
            assert!(
                segwit.height < cp.height && cp.height < birthday && birthday - cp.height < 300,
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
                // The earliest block this wallet could hold funds in: the birthday, but on
                // mainnet no earlier than the first SegWit block (`segwit` is the last
                // pre-SegWit one), and nowhere earlier than block 1 (genesis pays no one).
                let earliest_possible = if network == BitcoinNetwork::Main {
                    birthday.max(segwit + 1)
                } else {
                    birthday.max(1)
                };
                let cp = recovery_floor(network, birthday);
                // Strictly below: the checkpoint's own block is never scanned.
                assert!(
                    cp.height < earliest_possible,
                    "{network:?} birthday {birthday}: floor {} is not below the earliest block \
                     this wallet could hold funds in ({earliest_possible})",
                    cp.height
                );
            }
        }
    }

    #[test]
    fn one_peers_feefilter_cannot_set_the_fee() {
        let vb = FeeRate::from_sat_per_vb_u32;
        // An honest filter under the median changes nothing; one between the median and
        // the cap lifts the rate to it (the relay floor is honored).
        assert_eq!(combine_fee_signals(Some(vb(10)), vb(1)), (vb(10), false));
        assert_eq!(combine_fee_signals(Some(vb(10)), vb(15)), (vb(15), false));
        assert_eq!(combine_fee_signals(Some(vb(10)), vb(20)), (vb(20), false));
        // A stranger's 1999 sat/vB filter - the attack - lifts it to twice the median, not
        // to the sanity ceiling.
        assert_eq!(combine_fee_signals(Some(vb(10)), vb(1_999)), (vb(20), true));
        // Fee-less blocks (regtest, a quiet testnet) average zero: the relay floor must
        // survive that, or the send goes out at zero fee and nobody relays it. A modest
        // filter is honored whatever the median; only past the uncorroborated bound does
        // the median's multiple take over.
        assert_eq!(combine_fee_signals(Some(vb(0)), vb(1)), (vb(1), false));
        assert_eq!(combine_fee_signals(Some(vb(2)), vb(8)), (vb(8), false));
        assert_eq!(
            combine_fee_signals(Some(vb(0)), vb(1_999)),
            (vb(FEEFILTER_UNCORROBORATED_MAX_SAT_PER_VB), true)
        );
        // No median to check against: the filter alone, bounded.
        assert_eq!(combine_fee_signals(None, vb(3)), (vb(3), false));
        assert_eq!(
            combine_fee_signals(None, vb(1_999)),
            (vb(FEEFILTER_UNCORROBORATED_MAX_SAT_PER_VB), true)
        );
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
            // A full day past the floor block's own header time: the block after the
            // floor serves (the floor's own block is the one the scan starts *after*).
            assert_eq!(
                birthday_height_for_date(network, floor.time + day),
                Some(floor.height + 1),
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
        // A height above the scan start is worth resolving to an anchor - at the block
        // BEFORE the birthday, since the scan resumes at anchor + 1 and the birthday
        // block is the first that may hold funds...
        assert_eq!(
            resolution_target(146_000, &birthday(150_000)),
            Some(AnchorTarget::Height(149_999))
        );
        assert_eq!(
            resolution_target(146_000, &birthday(146_002)),
            Some(AnchorTarget::Height(146_001))
        );
        // ...one whose anchor would sit at (or below - the mainnet pre-floor restore
        // clamped up to SegWit activation) the start would change nothing, or drag the
        // scan lower.
        assert_eq!(resolution_target(146_000, &birthday(146_001)), None);
        assert_eq!(resolution_target(146_000, &birthday(146_000)), None);
        assert_eq!(resolution_target(481_824, &birthday(100)), None);
        assert_eq!(resolution_target(0, &birthday(0)), None);
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

    /// The `Sync` tree starts where bdk_kyoto anchors it - seven checkpoints below the
    /// tip along the wallet's own sparse chain, or the lowest checkpoint of a shorter one -
    /// which is what bounds what a resolution on that connection can reach.
    #[test]
    fn the_sync_tree_starts_seven_checkpoints_below_the_tip() {
        use bdk_wallet::chain::local_chain::LocalChain;
        use bdk_wallet::chain::BlockId;
        let genesis = BlockId {
            height: 0,
            hash: hash(0),
        };
        let (mut chain, _) = LocalChain::from_genesis_hash(genesis.hash);
        for height in [10u32, 20, 30, 40, 50, 60, 70, 80, 90, 100] {
            chain
                .insert_block(BlockId {
                    height,
                    hash: hash(height as u8),
                })
                .unwrap();
        }
        // Tip 100, then 90, 80, ... : seven steps back lands on 30.
        assert_eq!(sync_tree_start(&chain.tip()).height(), 30);
        let (mut short, _) = LocalChain::from_genesis_hash(genesis.hash);
        short
            .insert_block(BlockId {
                height: 5,
                hash: hash(5),
            })
            .unwrap();
        assert_eq!(sync_tree_start(&short.tip()).height(), 0);
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
        let (scan, tree_start, target) =
            endpoint.scan_plan(&wallet, &birthday(150_000), None, None);
        match scan {
            ScanType::Recovery { checkpoint, .. } => {
                assert_eq!(checkpoint.height, BTC_KYOTO_SCAN_FLOOR_TESTNET4.height)
            }
            other => panic!("expected a recovery scan, got {other:?}"),
        }
        assert_eq!(tree_start.height, BTC_KYOTO_SCAN_FLOOR_TESTNET4.height);
        // The anchor names the block BEFORE the birthday: the scan resumes at anchor + 1,
        // which must be the birthday block itself.
        assert_eq!(target, Some(AnchorTarget::Height(149_999)));

        // With a recorded anchor the scan starts at the birthday itself, resolving nothing.
        let hash: BlockHash = BTC_KYOTO_SCAN_FLOOR_TESTNET4.hash.parse().unwrap();
        let anchored = KyotoBirthday {
            anchor: Some((150_000, hash)),
            ..birthday(150_000)
        };
        let (scan, tree_start, target) = endpoint.scan_plan(&wallet, &anchored, None, None);
        match scan {
            ScanType::Recovery { checkpoint, .. } => assert_eq!(checkpoint.height, 150_000),
            other => panic!("expected a recovery scan, got {other:?}"),
        }
        assert_eq!(tree_start.height, 150_000);
        assert_eq!(target, None);
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
    fn explicit_peers_require_one_connection_whatever_their_number() {
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
        // A list is a failover set: any one of the named replicas keeps the wallet syncing,
        // so naming more never raises the requirement (it used to climb to the default,
        // which made one replica's outage stall a wallet listing two).
        let three = vec![
            ("127.0.0.1".parse::<IpAddr>().unwrap(), None),
            ("10.0.0.1".parse::<IpAddr>().unwrap(), None),
            ("10.0.0.2".parse::<IpAddr>().unwrap(), None),
        ];
        assert_eq!(endpoint(BitcoinNetwork::Main, three).required_peers, 1);
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
        // The same variant carries the errors the node handles itself by banning the peer
        // and moving on; tearing the client down for those (and counting them toward the
        // anchor-clearing escalation) restarted a first scan from the floor for nothing.
        for handled in [
            "Compact filter header syncing encountered an error: x",
            "Found a conflict while peers are sending filter headers",
            "Compact filter syncing encountered an error: x",
            "A block received does not have a known hash",
            "A block received does not have a valid merkle root",
        ] {
            let warning = Warning::UnexpectedSyncError {
                warning: handled.to_string(),
            };
            assert_eq!(fatal_sync_warning(&warning), None, "{handled}");
        }
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

    /// The anchor becomes suspect exactly when the redial before the latest failure had
    /// already restarted from it: a synced wallet once the escalation clamps to the anchor,
    /// a checkpoint-less one after two failed tries (every redial of its starts there).
    #[test]
    fn the_anchor_is_suspect_once_a_redial_from_it_has_failed() {
        use bdk_wallet::chain::BlockId;
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
        let anchor = (100, hash(1));
        // Failures 0 and 1 precede a plain `Sync` redial; failure 2's redial is 16 deep
        // (checkpoint 110); failure 3's is 64 deep - clamped to the anchor. So the anchor
        // is suspect only from the failure after that one.
        assert!(!resync_bottomed_at_anchor(&tip, 0, anchor));
        assert!(!resync_bottomed_at_anchor(&tip, 1, anchor));
        assert!(!resync_bottomed_at_anchor(&tip, 2, anchor));
        assert!(resync_bottomed_at_anchor(&tip, 3, anchor));
        assert!(resync_bottomed_at_anchor(&tip, 9, anchor));
        // A checkpoint-less wallet: two tries from the anchor, then suspect.
        let genesis = CheckPoint::new(BlockId {
            height: 0,
            hash: hash(0),
        });
        assert!(!resync_bottomed_at_anchor(&genesis, 1, anchor));
        assert!(resync_bottomed_at_anchor(&genesis, 2, anchor));
    }

    /// A synced wallet redials with `Sync` unless a resync depth is given, in which case it
    /// restarts as a recovery scan from its own chain that far back - the birthday anchor
    /// bounding it below.
    #[test]
    fn a_synced_wallet_resyncs_from_its_own_chain_only_when_asked() {
        use crate::btc::keys::{tests::bip84_seed, AccountKeys};
        use bdk_wallet::chain::BlockId;
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

        let (scan, _, target) = endpoint.scan_plan(&wallet, &anchored, None, None);
        assert!(matches!(scan, ScanType::Sync), "{scan:?}");
        assert_eq!(target, None);

        let (scan, tree_start, target) = endpoint.scan_plan(&wallet, &anchored, Some(15), None);
        match scan {
            ScanType::Recovery {
                used_script_index,
                checkpoint,
            } => {
                assert_eq!((checkpoint.height, checkpoint.hash), (160_000, hash(1)));
                // The wallet's own lookahead, the one knob: BDK's default here.
                assert_eq!(used_script_index, wallet.spk_index().lookahead());
                assert_eq!(used_script_index, 25);
            }
            other => panic!("expected a recovery scan, got {other:?}"),
        }
        assert_eq!(tree_start.height, 160_000);
        assert_eq!(target, None);

        let (scan, _, _) = endpoint.scan_plan(&wallet, &anchored, Some(u32::MAX), None);
        match scan {
            ScanType::Recovery { checkpoint, .. } => {
                assert_eq!((checkpoint.height, checkpoint.hash), (150_000, hash(7)))
            }
            other => panic!("expected a recovery scan, got {other:?}"),
        }
    }

    /// bdk_kyoto's set is `last_revealed + N` scripts from index 0 (a fresh wallet and one
    /// with index 0 revealed watch the same N), `N` the `used_script_index` of a recovery
    /// scan or the lookahead of a `Sync` - and rose passes the lookahead as both. The same
    /// formula measures the window the wallet has walked to, so a fresh `Sync` connection
    /// over a quiet wallet is complete as is.
    #[test]
    fn the_watched_window_follows_bdk_kyoto() {
        assert_eq!(watched_through(None, 100), 99);
        assert_eq!(watched_through(Some(0), 100), 99);
        assert_eq!(watched_through(Some(119), 100), 218);
        assert_eq!(watched_through(None, 25), 24);
        assert_eq!(watched_through(Some(5), 25), 29);
        // The reveal that first puts an index past the set in the window: `watched + 2 -
        // lookahead` (its window ends at `index + lookahead - 1`), and index 0 when the
        // whole set is within one lookahead of it.
        assert_eq!(first_reveal_past(99, 25), 76);
        assert_eq!(watched_through(Some(76), 25), 100);
        assert_eq!(watched_through(Some(75), 25), 99);
        assert_eq!(first_reveal_past(24, 25), 1);
        assert_eq!(first_reveal_past(10, 25), 0);
    }

    /// The failing restore's shape, with the 100-script recovery set rose passed at the time (the
    /// arithmetic is bdk_kyoto's and holds for any N; today N is the lookahead): the scan
    /// watches indexes 0..=99 per keychain; once the blocks it fetched reveal through 119,
    /// the window runs to 143, so the scan is not complete, and the rescan starts below
    /// the first block that paid index 76 or above. A scan that reveals nothing past its
    /// set is.
    #[test]
    fn a_recovery_scan_that_reveals_past_its_set_rescans_from_the_first_unwatched_reveal() {
        use crate::btc::keys::{tests::bip84_seed, AccountKeys};
        use bdk_wallet::chain::BlockId;
        let keys = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Regtest).unwrap();
        let mut wallet = Wallet::create(
            keys.descriptor(KeychainKind::External),
            keys.descriptor(KeychainKind::Internal),
        )
        .network(keys.network)
        .lookahead(25)
        .create_wallet_no_persist()
        .unwrap();
        let start = HashCheckpoint::new(0, wallet.latest_checkpoint().hash());
        let recovery = ScanType::Recovery {
            used_script_index: 100,
            checkpoint: start,
        };
        let watch = ScriptWatch::new(&wallet, recovery, start);
        assert_eq!(
            watch.watched,
            BTreeMap::from([(KeychainKind::External, 99), (KeychainKind::Internal, 99)])
        );
        let sync = ScriptWatch::new(&wallet, ScanType::Sync, start);
        assert_eq!(
            sync.watched,
            BTreeMap::from([(KeychainKind::External, 24), (KeychainKind::Internal, 24)])
        );
        // Nothing revealed: complete.
        let none = BTreeMap::new();
        assert_eq!(watch.rescan_from(&wallet, &none, &none), None);

        // Three blocks pay the external keychain: 0..=59 at height 10, 60..=119 at 20 (the
        // set had 60..=99, so the block was fetched and the cascade revealed through 119),
        // and the one at 30 the scan never fetched.
        let mut chain = wallet.latest_checkpoint();
        let mut tx_update = bdk_wallet::chain::TxUpdate::default();
        for (height, indexes) in [(10u32, 0u32..60), (20, 60..120)] {
            let block = BlockId {
                height,
                hash: hash(height as u8),
            };
            chain = chain.insert(block);
            let tx = Transaction {
                version: bdk_wallet::bitcoin::transaction::Version::TWO,
                lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
                input: vec![],
                output: indexes
                    .map(|i| bdk_wallet::bitcoin::TxOut {
                        value: bdk_wallet::bitcoin::Amount::from_sat(1_000),
                        script_pubkey: wallet
                            .peek_address(KeychainKind::External, i)
                            .script_pubkey(),
                    })
                    .collect(),
            };
            let txid = tx.compute_txid();
            tx_update.txs.push(Arc::new(tx));
            tx_update.anchors.insert((
                bdk_wallet::chain::ConfirmationBlockTime {
                    block_id: block,
                    confirmation_time: 0,
                },
                txid,
            ));
        }
        chain = chain.insert(BlockId {
            height: 30,
            hash: hash(30),
        });
        wallet
            .apply_update(Update {
                chain: Some(chain),
                tx_update,
                last_active_indices: BTreeMap::from([(KeychainKind::External, 119)]),
            })
            .unwrap();
        assert_eq!(
            wallet
                .spk_index()
                .last_revealed_index(KeychainKind::External),
            Some(119)
        );
        // Nothing was revealed before the update: every payment it found is a discovery.
        let paid = BTreeMap::from([(KeychainKind::External, 119)]);
        let rescan = watch
            .rescan_from(&wallet, &paid, &none)
            .expect("a window to 143 reaches past 99");
        // Below height 20, on the wallet's own chain: its checkpoint at 10.
        assert_eq!((rescan.height, rescan.hash), (10, hash(10)));

        // The next connection watches through 119 + 100 - 1 and finds nothing more: done.
        let wider = ScriptWatch::new(&wallet, recovery, rescan);
        assert_eq!(wider.watched[&KeychainKind::External], 218);
        assert_eq!(wider.rescan_from(&wallet, &paid, &none), None);

        // A `Sync` connection built at 119 watches through 143 - complete as it stands -
        // and, extended by an update that used index 130, through 154. The slack is half
        // the lookahead, 12 here, on every connection.
        let mut live = ScriptWatch::new(&wallet, ScanType::Sync, rescan);
        assert_eq!((watch.slack, live.slack), (12, 12));
        assert_eq!(live.watched[&KeychainKind::External], 143);
        let before = BTreeMap::from([(KeychainKind::External, 119)]);
        assert_eq!(live.rescan_from(&wallet, &paid, &before), None);
        live.extend(&BTreeMap::from([(KeychainKind::External, 130)]), 25);
        assert_eq!(live.watched[&KeychainKind::External], 154);
        live.extend(&BTreeMap::from([(KeychainKind::External, 100)]), 25);
        assert_eq!(live.watched[&KeychainKind::External], 154, "never narrows");
        // A discovery gets no slack: a payment found at 140, past the 119 revealed before
        // the update, puts the window at 164, past 154, and the blocks already passed may
        // hold more like it.
        let at_140 = BTreeMap::from([(KeychainKind::External, 140)]);
        assert!(
            live.rescan_from(&wallet, &at_140, &before).is_some(),
            "a discovery past the set rebuilds at once"
        );
        assert_eq!(
            live.rescan_from(
                &wallet,
                &BTreeMap::from([(KeychainKind::External, 130)]),
                &before
            ),
            None,
            "130 + 24 is within 154"
        );
        // Reveals from `getnewaddress` alone walk the window past the set at 131 (131 +
        // 24 = 155), and up to the slack beyond it at 142 (166 = 154 + 12): no rebuild
        // yet, and every address handed out so far is still within the set.
        for _ in 120..=142 {
            wallet.reveal_next_address(KeychainKind::External);
        }
        assert_eq!(
            live.rescan_from(&wallet, &none, &none),
            None,
            "142 + 24 is within the set plus its slack"
        );
        assert!(142 <= live.watched[&KeychainKind::External]);
        // The same payment at 140 is no discovery once 140 was handed out before the
        // update: a deposit to an issued address moves nothing the slack does not cover.
        let handed_out = BTreeMap::from([(KeychainKind::External, 142)]);
        assert_eq!(
            live.rescan_from(&wallet, &at_140, &handed_out),
            None,
            "a payment to a handed-out address is not a discovery"
        );
        // The reveal past the slack: a rescan with no block to start below, so from the
        // connection's own start.
        wallet.reveal_next_address(KeychainKind::External);
        let from_start = live
            .rescan_from(&wallet, &none, &none)
            .expect("143 + 24 reaches past 154 + 12");
        assert_eq!((from_start.height, from_start.hash), (10, hash(10)));
        assert!(
            143 <= live.watched[&KeychainKind::External],
            "the address that triggers the rebuild is itself still watched"
        );
    }
}
