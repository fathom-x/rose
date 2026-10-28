//! The opt-in mempool feed: 0-conf visibility for the kyoto backend.
//!
//! BIP-158 filters cover blocks only, so a kyoto wallet sees an incoming payment when it
//! confirms and not before: `getbalances.untrusted_pending` stays empty, `listtransactions`
//! shows nothing at 0-conf, and a merchant cannot show a buyer a "detected" state until the
//! first block - ten minutes on average, sometimes much longer. Nothing in BIP-157 fixes it.
//! This module does, at a cost the operator opts into, from one of two sources named in
//! `[mempool] sources` (the first that can run for the wallet wins):
//!
//! - `"p2p"` ([`super::p2p_feed`]): rose's own relay connection to one node - by default
//!   the wallet's `kyoto://` trusted peer - announcing every transaction entering its
//!   mempool over the Bitcoin P2P protocol. No server, raw-size bandwidth, and with
//!   `p2p_snapshot` a BIP 35 mempool snapshot at connect and periodically (evictions).
//! - `"mempool_space"` (this module's socket): a long-lived websocket to a mempool.space
//!   instance, whose `track-mempool`
//!   subscription answers with a `mempool-transactions` **delta** every couple of seconds -
//!   `{sequence, added, removed, replaced, mined}` - where every `added` entry is a full
//!   Esplora-shape transaction: version, locktime, each input with its `prevout` script and
//!   value, witness and sequence, each output with script and value, plus fee, vsize and
//!   first-seen time. (Re-verified against the live mainnet instance on 2026-09-10: a
//!   `replaced` entry is `{"replaced": "<txid>", "by": {<full tx>}}` and its txid is listed
//!   under `removed` as well; `mined` was empty in every delta seen. The recorded delta in
//!   `testdata/mempool_delta.json` is the fixture.)
//!
//! ## What the wallet does with it
//!
//! Everything is matched **locally**, and both sources deliver the same [`FeedEvent`]s to
//! the actor. The bridge task ([`MempoolFeed::start`]) owns the socket - the same shape as
//! the kyoto update bridge, since a socket read is not cancel-safe and must not sit in the
//! actor's `select!` - and feeds a channel the actor drains. On the websocket, each `added`
//! transaction is rebuilt into a `bitcoin::Transaction` from the JSON and
//! its txid is **checked against the one the feed reported** ([`reconstruct`]): a mismatch
//! means the reconstruction is not faithful (a field this parser does not understand), and
//! such a transaction is dropped rather than recorded under a wrong id. The actor then runs
//! `is_mine` over the outputs and over the inputs' `prevout` scripts ([`wallet_relevant`])
//! and applies a match with `apply_unconfirmed_txs`, and a `removed` txid the wallet holds
//! unconfirmed with `apply_evicted_txs` - the same two calls the bitcoind backend's mempool
//! pass makes. Confirmation stays the filter scan's job: a transaction seen here first and in
//! a block later is anchored by the scan, not duplicated.
//!
//! ## What it does not do
//!
//! **Deltas only.** There is no snapshot on subscribe (the full set is megabytes of txids on
//! mainnet plus a fetch per transaction), so whatever is already in the mempool at connect is
//! invisible until it confirms - a blind spot the scan closes within a block or two, and the
//! reason a reconnect needs no catch-up.
//!
//! ## Trust and disclosure
//!
//! The feed is the existing 0-conf posture and nothing more: the oracle's mempool is not our
//! peers' and could lie, and a lie only ever moves `untrusted_pending` - never confirmed
//! state, which headers, proof of work and filters keep trustless. No address and no txid of
//! interest ever leaves the wallet; what the server learns is that a wallet is online at this
//! IP for as long as the socket lives, strictly less than any per-address backend, and
//! removable outright with a self-hosted instance (`[mempool] mempool_space_url`, `ws://`
//! allowed for the same reason the `[fees]` overrides allow plain `http://`). Like the fee
//! oracles, the feed dials directly rather than through `[backend] proxy`.
//!
//! ## Cost - why it stays off by default
//!
//! Two to twenty kilobytes of JSON per transaction (asm strings, ancestor data): several GB
//! a day at mainnet ingress, negligible on testnet4, plus an always-on connection. A
//! bitcoind-backed wallet never needs it - it has a real mempool - and `config check` says so
//! if the section is set on one.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context as _};
use bdk_wallet::bitcoin::hex::FromHex as _;
use bdk_wallet::bitcoin::{
    absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use bdk_wallet::Wallet;
use futures_util::{SinkExt as _, StreamExt as _};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn, Instrument as _};

use crate::backoff::Backoff;
use crate::coin::BitcoinNetwork;
use crate::config::{MempoolConfig, MempoolSource};

/// The subscription that turns a fresh mempool.space socket into a delta stream. Sent once,
/// right after the handshake.
pub const SUBSCRIBE: &str = r#"{"track-mempool":true}"#;

/// The key a delta rides under in the server's messages. A message may carry other keys
/// too (the instance pushes what it pushes); only this one is read.
const DELTA_KEY: &str = "mempool-transactions";

/// How long the handshake may take. The dial happens off the actor, so this bounds only how
/// soon a dead endpoint is noticed and retried.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// A keepalive ping, so an idle socket (a quiet test network can go minutes between deltas)
/// is not closed by an intermediary as dead, and so that silence is measurable: a healthy
/// server answers each with a pong.
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// Nothing at all - no delta, no pong - for this long means the socket is dead however open
/// it looks. Several ping intervals, so one lost pong does not reconnect.
const SILENCE_TIMEOUT: Duration = Duration::from_secs(180);

/// A connection that lasted this long counts as having worked: the next drop is a new
/// outage, warned about afresh and retried from the base delay.
const STABLE_CONNECTION: Duration = Duration::from_secs(60);

/// Depth of the channel between the socket task and the actor. A delta is small once
/// reconstructed, and the actor drains the channel on every pass; the bound only makes a
/// wedged actor apply backpressure to the reader instead of growing without limit.
const EVENT_CHANNEL_BOUND: usize = 64;

/// The mempool.space websocket for `network`, or `None` where the public instance has
/// nothing to say - regtest is a private chain with no public instance.
fn mempool_space_endpoint(network: BitcoinNetwork) -> Option<&'static str> {
    match network {
        BitcoinNetwork::Main => Some("wss://mempool.space/api/v1/ws"),
        BitcoinNetwork::Testnet3 => Some("wss://mempool.space/testnet/api/v1/ws"),
        BitcoinNetwork::Testnet4 => Some("wss://mempool.space/testnet4/api/v1/ws"),
        BitcoinNetwork::Regtest => None,
    }
}

/// The URL the websocket source would be subscribed at: the operator's override, else the
/// built-in public endpoint for this network, else nothing.
pub fn endpoint_for(config: &MempoolConfig, network: BitcoinNetwork) -> Option<String> {
    config
        .mempool_space_url
        .clone()
        .or_else(|| mempool_space_endpoint(network).map(str::to_string))
}

/// The node the P2P source would peer with: `[mempool] p2p_peer` when set, else the wallet's
/// first `kyoto://` trusted peer (at the network-standard port when the token named none),
/// else nothing - a DNS-seeded wallet has no node of its own to ask, and a stranger would
/// not be trusted with the snapshot request anyway.
pub fn p2p_peer_for(
    config: &MempoolConfig,
    network: BitcoinNetwork,
    kyoto_peers: &[(IpAddr, Option<u16>)],
) -> Option<SocketAddr> {
    config.p2p_peer.or_else(|| {
        kyoto_peers.first().map(|(ip, port)| {
            SocketAddr::new(*ip, port.unwrap_or(super::p2p_feed::default_port(network)))
        })
    })
}

/// Where one feed source connects, resolved for a wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedTarget {
    /// The mempool.space websocket at `url`.
    WebSocket { url: String },
    /// A relay connection to `peer` on `network`; `snapshot` adds the BIP 35 mempool
    /// requests at connect and at this interval (see `p2p_feed`).
    Peer {
        peer: SocketAddr,
        network: BitcoinNetwork,
        snapshot: Option<Duration>,
        /// `[backend] p2p_receive_window_bytes`, the same bound the kyoto peers dial with.
        receive_window: Option<u32>,
    },
}

impl FeedTarget {
    pub fn source(&self) -> MempoolSource {
        match self {
            FeedTarget::WebSocket { .. } => MempoolSource::MempoolSpace,
            FeedTarget::Peer { .. } => MempoolSource::P2p,
        }
    }

    /// What `getwalletinfo` and the log call the endpoint.
    pub fn describe(&self) -> String {
        match self {
            FeedTarget::WebSocket { url } => url.clone(),
            FeedTarget::Peer { peer, snapshot, .. } => match snapshot {
                Some(every) => {
                    format!(
                        "p2p://{peer} (relay + mempool snapshots every {}s)",
                        every.as_secs()
                    )
                }
                None => format!("p2p://{peer} (relay)"),
            },
        }
    }

    /// Whether this feed takes BIP 35 mempool snapshots: the only kind that can establish
    /// the wallet's view of its own unconfirmed history (`BtcActor::send_gate`), since a
    /// relay or websocket feed reports only what is announced after it connects. The
    /// actor and `rose config check` both read it, so the two cannot disagree on it.
    pub fn takes_snapshots(&self) -> bool {
        matches!(
            self,
            FeedTarget::Peer {
                snapshot: Some(_),
                ..
            }
        )
    }
}

/// Resolve one named source for a wallet, or `None` when it cannot run there.
pub fn target_for(
    config: &MempoolConfig,
    source: MempoolSource,
    network: BitcoinNetwork,
    kyoto_peers: &[(IpAddr, Option<u16>)],
    receive_window: Option<u32>,
) -> Option<FeedTarget> {
    match source {
        MempoolSource::MempoolSpace => {
            endpoint_for(config, network).map(|url| FeedTarget::WebSocket { url })
        }
        MempoolSource::P2p => {
            p2p_peer_for(config, network, kyoto_peers).map(|peer| FeedTarget::Peer {
                peer,
                network,
                snapshot: config
                    .p2p_snapshot
                    .then(|| Duration::from_secs(config.p2p_snapshot_interval_secs)),
                receive_window,
            })
        }
    }
}

/// The feed a kyoto wallet runs: the first named source that can run for it (`kyoto_peers`
/// being the wallet's own trusted peers), or `None` when the section is unset (the default)
/// or nothing named can. One feed at a time - the list is a preference order, not a set of
/// parallel subscriptions.
pub fn feed_target(
    config: &MempoolConfig,
    network: BitcoinNetwork,
    kyoto_peers: &[(IpAddr, Option<u16>)],
    receive_window: Option<u32>,
) -> Option<FeedTarget> {
    config
        .sources
        .iter()
        .find_map(|&source| target_for(config, source, network, kyoto_peers, receive_window))
}

/// Refuse a `[mempool]` URL override that could never be dialed, at config-resolution time.
/// `key` names the offending setting so the message points at the line to fix.
///
/// Plain `ws://` is permitted for the same reason `[fees]` allows `http://`: the override's
/// purpose is a self-hosted instance, which on a trusted LAN may legitimately not run TLS,
/// and the connection carries no credentials and no wallet data. The compiled-in Mozilla
/// roots are the only TLS trust anchor (the musl release images ship no CA bundle), so a
/// `wss://` instance with a privately-issued certificate will fail to connect - use `ws://`
/// on a trusted network, or a publicly-issued certificate.
pub fn validate_endpoint_override(key: &str, url: &str) -> anyhow::Result<()> {
    let uri: hyper::Uri = url
        .parse()
        .with_context(|| format!("[mempool] {key} is not a valid URL: {url:?}"))?;
    match uri.scheme_str() {
        Some("ws") | Some("wss") => {}
        _ => anyhow::bail!(
            "[mempool] {key} must be a ws:// or wss:// URL, got {url:?} (give the full \
             websocket path, e.g. \"wss://mempool.example/api/v1/ws\")"
        ),
    }
    if uri.host().is_none_or(str::is_empty) {
        anyhow::bail!("[mempool] {key} has no host: {url:?}");
    }
    Ok(())
}

/// One `mempool-transactions` delta as the server sends it. Every field this parser does not
/// read is ignored (serde's default), so an upstream addition cannot break the feed; the
/// fields it does read are the ones [`reconstruct`] needs to rebuild a transaction
/// byte-for-byte, and the txid check is what catches an upstream change to *those*.
#[derive(Debug, Default, serde::Deserialize)]
pub struct RawDelta {
    #[serde(default)]
    pub sequence: Option<u64>,
    #[serde(default)]
    pub added: Vec<RawTx>,
    #[serde(default)]
    pub removed: Vec<String>,
    /// RBF replacements. The shape has varied across server versions, so it is kept as
    /// raw JSON and mined for txids leniently ([`replaced_txids`]) rather than typed: a
    /// replaced transaction is evicted like a removed one, and its replacement, if it is a
    /// full transaction, is treated as added.
    #[serde(default)]
    pub replaced: Vec<serde_json::Value>,
    #[serde(default)]
    pub mined: Vec<String>,
}

/// An Esplora-shape transaction, reduced to what rebuilding it needs.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RawTx {
    pub txid: String,
    pub version: i32,
    pub locktime: u32,
    pub vin: Vec<RawVin>,
    pub vout: Vec<RawVout>,
    /// mempool.space's `firstSeen`; Esplora proper has no such field. Unix seconds.
    #[serde(default, alias = "firstSeen")]
    pub first_seen: Option<u64>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RawVin {
    pub txid: String,
    pub vout: u32,
    #[serde(default)]
    pub prevout: Option<RawPrevout>,
    #[serde(default)]
    pub scriptsig: String,
    #[serde(default)]
    pub witness: Vec<String>,
    pub sequence: u32,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RawPrevout {
    pub scriptpubkey: String,
    #[serde(default)]
    pub value: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RawVout {
    pub scriptpubkey: String,
    pub value: u64,
}

/// Read one websocket text message. `Ok(None)` is a message without a delta in it (the
/// server pushes other things too); `Err` is a message that claims to carry one but does
/// not parse, which is worth a log line but never a reconnect.
pub fn parse_message(text: &str) -> anyhow::Result<Option<RawDelta>> {
    let mut envelope: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(text).context("parse the feed message")?;
    let Some(delta) = envelope.remove(DELTA_KEY) else {
        return Ok(None);
    };
    serde_json::from_value(delta)
        .with_context(|| format!("parse the {DELTA_KEY} delta"))
        .map(Some)
}

/// A transaction rebuilt from the feed, with what matching needs beside it.
#[derive(Debug, Clone)]
pub struct FeedTx {
    pub tx: Arc<Transaction>,
    /// Each input's prevout script when the feed supplied it, in input order - what lets a
    /// spend of a wallet output be recognized even before the output itself is recorded.
    pub prevouts: Vec<Option<ScriptBuf>>,
    /// When the server first saw it (unix seconds), else when this wallet did.
    pub seen: u64,
}

/// Rebuild the transaction and verify it: the txid of the rebuilt bytes must equal the one
/// the feed reported. That is a check on the *reconstruction* (every field round-tripped),
/// not on validity - the feed's view is untrusted either way and only moves
/// `untrusted_pending`.
pub fn reconstruct(raw: &RawTx, now: u64) -> anyhow::Result<FeedTx> {
    let reported: Txid = raw
        .txid
        .parse()
        .with_context(|| format!("txid {:?}", raw.txid))?;
    let mut prevouts = Vec::with_capacity(raw.vin.len());
    let mut input = Vec::with_capacity(raw.vin.len());
    for vin in &raw.vin {
        let witness: Vec<Vec<u8>> = vin
            .witness
            .iter()
            .map(|item| Vec::<u8>::from_hex(item).with_context(|| format!("witness {item:?}")))
            .collect::<anyhow::Result<_>>()?;
        input.push(TxIn {
            previous_output: OutPoint::new(
                vin.txid
                    .parse()
                    .with_context(|| format!("input txid {:?}", vin.txid))?,
                vin.vout,
            ),
            script_sig: ScriptBuf::from_hex(&vin.scriptsig)
                .with_context(|| format!("scriptsig {:?}", vin.scriptsig))?,
            sequence: Sequence(vin.sequence),
            witness: Witness::from_slice(&witness),
        });
        prevouts.push(match &vin.prevout {
            Some(prevout) => Some(
                ScriptBuf::from_hex(&prevout.scriptpubkey)
                    .with_context(|| format!("prevout script {:?}", prevout.scriptpubkey))?,
            ),
            None => None,
        });
    }
    let output = raw
        .vout
        .iter()
        .map(|vout| {
            Ok(TxOut {
                value: Amount::from_sat(vout.value),
                script_pubkey: ScriptBuf::from_hex(&vout.scriptpubkey)
                    .with_context(|| format!("output script {:?}", vout.scriptpubkey))?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let tx = Transaction {
        version: transaction::Version(raw.version),
        lock_time: absolute::LockTime::from_consensus(raw.locktime),
        input,
        output,
    };
    let computed = tx.compute_txid();
    if computed != reported {
        return Err(anyhow!(
            "the rebuilt transaction hashes to {computed}, but the feed reported {reported}: \
             the reconstruction is not faithful; dropping it"
        ));
    }
    Ok(FeedTx {
        tx: Arc::new(tx),
        prevouts,
        seen: raw.first_seen.unwrap_or(now),
    })
}

/// Every txid a `replaced` entry names as *replaced*, whatever shape the entry takes: a bare
/// string, `{"replaced": "<txid>"}`, `{"replaced": ["<txid>", ...]}`, or an object carrying a
/// `txid` - and the same one level down under `replaced`. Unrecognized shapes contribute
/// nothing rather than failing the delta.
pub fn replaced_txids(entries: &[serde_json::Value]) -> Vec<Txid> {
    fn collect(value: &serde_json::Value, out: &mut Vec<Txid>) {
        match value {
            serde_json::Value::String(s) => {
                if let Ok(txid) = s.parse() {
                    out.push(txid);
                }
            }
            serde_json::Value::Array(items) => items.iter().for_each(|v| collect(v, out)),
            serde_json::Value::Object(map) => {
                if let Some(txid) = map.get("txid") {
                    collect(txid, out);
                } else if let Some(inner) = map.get("replaced") {
                    collect(inner, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for entry in entries {
        match entry {
            serde_json::Value::Object(map) => match map.get("replaced") {
                Some(inner) => collect(inner, &mut out),
                None => collect(entry, &mut out),
            },
            other => collect(other, &mut out),
        }
    }
    out
}

/// The replacement transactions a `replaced` delta carries in full (`{"by": {<tx>}}`), when
/// it does. A replacement that is only named by txid is nothing to apply - it will arrive
/// as an `added` entry of its own, or confirm.
fn replacement_txs(entries: &[serde_json::Value]) -> Vec<RawTx> {
    entries
        .iter()
        .filter_map(|entry| entry.get("by"))
        .filter_map(|by| serde_json::from_value::<RawTx>(by.clone()).ok())
        .collect()
}

/// A delta after reconstruction: what the actor applies.
#[derive(Debug, Default)]
pub struct FeedDelta {
    pub sequence: Option<u64>,
    pub added: Vec<FeedTx>,
    pub removed: Vec<Txid>,
    /// How many `added` entries failed to rebuild (logged individually at DEBUG; counted
    /// here so a systematically broken parser shows up in the feed's status rather than
    /// only in the log).
    pub dropped: usize,
}

/// Turn a raw delta into an applicable one: rebuild every added transaction (and every
/// full replacement), drop what does not rebuild, and merge the replaced txids into the
/// removed set.
pub fn build_delta(raw: RawDelta, now: u64) -> FeedDelta {
    let mut delta = FeedDelta {
        sequence: raw.sequence,
        ..FeedDelta::default()
    };
    let mut seen: HashSet<Txid> = HashSet::new();
    for tx in raw
        .added
        .iter()
        .chain(replacement_txs(&raw.replaced).iter())
    {
        match reconstruct(tx, now) {
            Ok(feed_tx) => {
                if seen.insert(feed_tx.tx.compute_txid()) {
                    delta.added.push(feed_tx);
                }
            }
            Err(e) => {
                delta.dropped += 1;
                debug!(txid = %tx.txid, "mempool feed: dropping an added transaction: {e:#}");
            }
        }
    }
    let mut removed: HashSet<Txid> = raw.removed.iter().filter_map(|s| s.parse().ok()).collect();
    removed.extend(replaced_txids(&raw.replaced));
    delta.removed = removed.into_iter().collect();
    delta
}

/// Whether a feed transaction touches this wallet: pays one of its scripts, or spends one of
/// its outputs (by the feed's prevout script, or by an outpoint the wallet already holds).
/// Purely local - the wallet's own descriptor index answers, and nothing is asked of anyone.
pub fn wallet_relevant(wallet: &Wallet, feed_tx: &FeedTx) -> bool {
    if feed_tx
        .tx
        .output
        .iter()
        .any(|txout| wallet.is_mine(txout.script_pubkey.clone()))
    {
        return true;
    }
    feed_tx
        .tx
        .input
        .iter()
        .zip(feed_tx.prevouts.iter())
        .any(|(txin, prevout)| {
            prevout
                .as_ref()
                .is_some_and(|script| wallet.is_mine(script.clone()))
                || wallet
                    .tx_graph()
                    .get_txout(txin.previous_output)
                    .is_some_and(|txout| wallet.is_mine(txout.script_pubkey.clone()))
        })
}

/// What the socket task tells the actor.
#[derive(Debug)]
pub enum FeedEvent {
    /// The handshake completed and the subscription was sent. `peer_bloom`: for the P2P
    /// source, whether the peer advertised `NODE_BLOOM` (the websocket source reports
    /// `None`).
    Connected { peer_bloom: Option<bool> },
    /// One delta, reconstructed.
    Delta(FeedDelta),
    /// The P2P source's answer to a BIP 35 `mempool` request: every txid the node holds.
    /// A wallet transaction the feed had reported held and that is missing here has left the
    /// node's mempool - the only eviction signal that source has, since Core never announces
    /// one. The websocket source never sends this (its `removed` deltas are explicit).
    Snapshot(FeedSnapshot),
    /// Where a snapshot being collected stands, at most once a second while one is: what
    /// the node has announced since the request and what is still being fetched, so the
    /// wait a send sits in (see `BtcActor::send_gate`) shows as progress rather than
    /// silence. The P2P source only; a [`Self::Snapshot`] ends the series.
    SnapshotProgress(SnapshotProgress),
    /// The socket is gone; the task is already backing off toward a redial.
    Disconnected(String),
}

/// One BIP 35 snapshot, delivered only once every transaction it had to fetch has arrived
/// (or was reported gone), so each of them reached the actor as a delta first.
#[derive(Debug)]
pub struct FeedSnapshot {
    /// Every txid the node listed.
    pub held: HashSet<Txid>,
    /// Whether every one of them was fetched in full on this request - a snapshot at
    /// connect, or one [`MempoolFeed::request_full_snapshot`] asked for - as opposed to a
    /// periodic one, which skips what the connection already delivered.
    pub full: bool,
    /// When it was requested. A full snapshot matched against the wallet only counts as a
    /// complete view of the mempool if the wallet was itself complete (at tip) by then.
    pub requested_at: std::time::Instant,
}

/// A BIP 35 snapshot in progress ([`FeedEvent::SnapshotProgress`]): the counts the P2P
/// session keeps while it collects one, as `getwalletinfo.mempool_feed.snapshot_progress`
/// reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotProgress {
    /// Transactions the node has announced since the request (every txid it listed, fetched
    /// or already known on the connection).
    pub announced: u64,
    /// Of those, requested and neither delivered nor reported gone yet.
    pub pending: u64,
    /// When the snapshot was requested, unix seconds.
    pub requested_at: u64,
    /// How long after the request the announcements still count as the snapshot's
    /// (`p2p_feed::SNAPSHOT_WINDOW`), in seconds: the snapshot is delivered once the window
    /// has passed and nothing is pending, so a client can show the window elapsing.
    pub window_secs: u64,
}

/// A running feed: the channel the socket task feeds, and the task itself, which dies with
/// this value.
pub struct MempoolFeed {
    pub source: MempoolSource,
    /// [`FeedTarget::describe`], for the log and `getwalletinfo`.
    pub endpoint: String,
    rx: mpsc::Receiver<FeedEvent>,
    task: JoinHandle<()>,
    /// Bumped to ask the P2P source for a full snapshot (see
    /// [`Self::request_full_snapshot`]); the websocket source ignores it.
    refetch: watch::Sender<u64>,
}

impl MempoolFeed {
    /// Start the socket task. It owns connect, subscribe, read, and reconnect-with-backoff
    /// for the life of the returned value; the actor only ever polls [`Self::try_next`]
    /// or awaits [`Self::next`].
    pub fn start(target: FeedTarget, reconnect_base: Duration, reconnect_max: Duration) -> Self {
        let (tx, rx) = mpsc::channel(EVENT_CHANNEL_BOUND);
        let (refetch, mut refetch_rx) = watch::channel(0u64);
        let source = target.source();
        let endpoint = target.describe();
        let dial = endpoint.clone();
        let span = tracing::Span::current();
        let task = tokio::spawn(
            async move {
                let mut backoff = Backoff::new(reconnect_base, reconnect_max);
                let mut warned = false;
                loop {
                    let started = std::time::Instant::now();
                    let outcome = match &target {
                        FeedTarget::WebSocket { url } => run_socket(url, &tx).await,
                        FeedTarget::Peer {
                            peer,
                            network,
                            snapshot,
                            receive_window,
                        } => {
                            super::p2p_feed::run_peer(
                                *peer,
                                *network,
                                *snapshot,
                                *receive_window,
                                &tx,
                                &mut refetch_rx,
                            )
                            .await
                        }
                    };
                    if tx.is_closed() {
                        break;
                    }
                    // A socket that lived a while was a real connection: the next failure
                    // is a fresh outage (WARN again, backoff from the base). One that died
                    // at once keeps backing off - a server that accepts and immediately
                    // drops must not be hammered.
                    if started.elapsed() >= STABLE_CONNECTION {
                        backoff.reset();
                        warned = false;
                    }
                    let why = match outcome {
                        Ok(()) => "the other side closed the connection".to_string(),
                        Err(e) => format!("{e:#}"),
                    };
                    let delay = backoff.next_delay();
                    if warned {
                        debug!(endpoint = %dial, "mempool feed down (retrying in {delay:?}): {why}");
                    } else {
                        warn!(endpoint = %dial, "mempool feed down (retrying in {delay:?}): {why}");
                        warned = true;
                    }
                    if tx.send(FeedEvent::Disconnected(why)).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(delay).await;
                }
            }
            .instrument(span),
        );
        Self {
            source,
            endpoint,
            rx,
            task,
            refetch,
        }
    }

    /// Ask the P2P source to refetch the node's whole mempool: forget which transactions
    /// this connection already delivered and request a BIP 35 snapshot, so every
    /// transaction the node holds arrives as a delta again. The actor asks once a wallet
    /// built from an empty datadir reaches tip, when matching them can finally see which
    /// ones spend its outputs. A no-op for the websocket source and for a P2P feed without
    /// `p2p_snapshot`.
    pub fn request_full_snapshot(&self) {
        self.refetch.send_modify(|n| *n += 1);
    }

    /// The next event without waiting; `None` when there is none queued.
    pub fn try_next(&mut self) -> Option<FeedEvent> {
        self.rx.try_recv().ok()
    }

    /// The next event, waiting for it. Cancel-safe (an `mpsc` receive), so it may sit in
    /// the actor's idle `select!`. `None` only once the task has ended, which it does not
    /// on its own.
    pub async fn next(&mut self) -> Option<FeedEvent> {
        self.rx.recv().await
    }
}

impl Drop for MempoolFeed {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One connection's life: dial, subscribe, read until it breaks. `Ok` is the server's
/// orderly close; `Err` everything else. Either way the caller redials with backoff.
async fn run_socket(url: &str, events: &mpsc::Sender<FeedEvent>) -> anyhow::Result<()> {
    let (mut ws, _response) =
        tokio::time::timeout(CONNECT_TIMEOUT, tokio_tungstenite::connect_async(url))
            .await
            .map_err(|_| anyhow!("no handshake within {CONNECT_TIMEOUT:?}"))?
            .context("connect")?;
    ws.send(Message::text(SUBSCRIBE))
        .await
        .context("send the subscription")?;
    info!(url = %url, "mempool feed connected and subscribed");
    if events
        .send(FeedEvent::Connected { peer_bloom: None })
        .await
        .is_err()
    {
        return Ok(());
    }
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.tick().await; // the first tick is immediate; the socket was just opened
    loop {
        tokio::select! {
            next = tokio::time::timeout(SILENCE_TIMEOUT, ws.next()) => {
                let message = match next {
                    Err(_) => return Err(anyhow!("nothing received for {SILENCE_TIMEOUT:?}")),
                    Ok(None) => return Ok(()),
                    Ok(Some(Err(e))) => return Err(anyhow!("read: {e}")),
                    Ok(Some(Ok(message))) => message,
                };
                match message {
                    Message::Text(text) => match parse_message(text.as_str()) {
                        Ok(Some(raw)) => {
                            let delta = build_delta(raw, unix_now());
                            if events.send(FeedEvent::Delta(delta)).await.is_err() {
                                return Ok(());
                            }
                        }
                        Ok(None) => {}
                        Err(e) => debug!("mempool feed: unreadable message: {e:#}"),
                    },
                    Message::Ping(payload) => {
                        ws.send(Message::Pong(payload)).await.context("pong")?;
                    }
                    Message::Close(frame) => {
                        debug!(?frame, "mempool feed: server closed the socket");
                        return Ok(());
                    }
                    // A pong is the answer to our keepalive - it counts as activity by
                    // virtue of having arrived; binary frames are not part of the protocol.
                    Message::Pong(_) | Message::Binary(_) | Message::Frame(_) => {}
                }
            }
            _ = ping.tick() => {
                ws.send(Message::Ping(Vec::new().into())).await.context("ping")?;
            }
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::hashes::Hash as _;
    use bdk_wallet::KeychainKind;

    /// Render a transaction into the feed's JSON shape, the way the server would, so a
    /// reconstruction test starts from real bytes rather than a hand-typed fixture.
    fn feed_json(tx: &Transaction, prevouts: &[Option<(ScriptBuf, u64)>]) -> serde_json::Value {
        use bdk_wallet::bitcoin::consensus::Encodable as _;
        let vin: Vec<_> = tx
            .input
            .iter()
            .zip(prevouts)
            .map(|(txin, prevout)| {
                let mut v = serde_json::json!({
                    "txid": txin.previous_output.txid.to_string(),
                    "vout": txin.previous_output.vout,
                    "scriptsig": txin.script_sig.to_hex_string(),
                    "scriptsig_asm": "",
                    "witness": txin.witness.iter().map(hex_string).collect::<Vec<_>>(),
                    "is_coinbase": false,
                    "sequence": txin.sequence.0,
                });
                if let Some((script, value)) = prevout {
                    v["prevout"] = serde_json::json!({
                        "scriptpubkey": script.to_hex_string(),
                        "scriptpubkey_asm": "",
                        "scriptpubkey_type": "v0_p2wpkh",
                        "scriptpubkey_address": "tb1qexample",
                        "value": value,
                    });
                }
                v
            })
            .collect();
        let vout: Vec<_> = tx
            .output
            .iter()
            .map(|txout| {
                serde_json::json!({
                    "scriptpubkey": txout.script_pubkey.to_hex_string(),
                    "scriptpubkey_asm": "",
                    "scriptpubkey_type": "v0_p2wpkh",
                    "scriptpubkey_address": "tb1qexample",
                    "value": txout.value.to_sat(),
                })
            })
            .collect();
        let mut bytes = Vec::new();
        tx.consensus_encode(&mut bytes).unwrap();
        serde_json::json!({
            "txid": tx.compute_txid().to_string(),
            "version": tx.version.0,
            "locktime": tx.lock_time.to_consensus_u32(),
            "vin": vin,
            "vout": vout,
            "size": bytes.len(),
            "weight": tx.weight().to_wu(),
            "sigops": 0,
            "fee": 339,
            "vsize": tx.vsize(),
            "adjustedVsize": tx.vsize(),
            "firstSeen": 1_725_000_000,
            "status": {"confirmed": false},
        })
    }

    fn hex_string(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn wallet() -> Wallet {
        let keys = crate::btc::keys::AccountKeys::from_seed(
            &crate::btc::keys::tests::bip84_seed(),
            BitcoinNetwork::Regtest,
        )
        .unwrap();
        Wallet::create(
            keys.descriptor(KeychainKind::External),
            keys.descriptor(KeychainKind::Internal),
        )
        .network(keys.network)
        .create_wallet_no_persist()
        .unwrap()
    }

    /// A segwit spend with a witness, paying `outputs`, from one made-up outpoint.
    fn spend(outputs: Vec<(ScriptBuf, u64)>, salt: u8) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::from_consensus(101),
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([salt; 32]), u32::from(salt)),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::from_slice(&[vec![0x30, 0x44, salt], vec![0x02; 33]]),
            }],
            output: outputs
                .into_iter()
                .map(|(spk, value)| TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: spk,
                })
                .collect(),
        }
    }

    fn foreign_script(salt: u8) -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&bdk_wallet::bitcoin::WPubkeyHash::from_byte_array(
            [salt; 20],
        ))
    }

    #[test]
    fn every_public_network_has_a_websocket_and_regtest_has_none() {
        assert_eq!(
            mempool_space_endpoint(BitcoinNetwork::Main),
            Some("wss://mempool.space/api/v1/ws")
        );
        assert!(mempool_space_endpoint(BitcoinNetwork::Testnet3)
            .unwrap()
            .contains("/testnet/"));
        assert!(mempool_space_endpoint(BitcoinNetwork::Testnet4)
            .unwrap()
            .contains("/testnet4/"));
        assert!(mempool_space_endpoint(BitcoinNetwork::Regtest).is_none());
    }

    fn ws_only() -> MempoolConfig {
        MempoolConfig {
            sources: vec![MempoolSource::MempoolSpace],
            ..MempoolConfig::default()
        }
    }

    #[test]
    fn the_feed_is_off_unless_a_source_is_named_and_can_run() {
        assert!(feed_target(&MempoolConfig::default(), BitcoinNetwork::Main, &[], None).is_none());
        assert_eq!(
            feed_target(&ws_only(), BitcoinNetwork::Testnet4, &[], None),
            Some(FeedTarget::WebSocket {
                url: "wss://mempool.space/testnet4/api/v1/ws".to_string()
            })
        );
        // Named but nothing public serves regtest: off, not an error.
        assert!(feed_target(&ws_only(), BitcoinNetwork::Regtest, &[], None).is_none());
        // An override supplies the endpoint the network lacks, and wins where it has one.
        let hosted = MempoolConfig {
            mempool_space_url: Some("ws://mempool.internal:8999/api/v1/ws".into()),
            ..ws_only()
        };
        for network in [BitcoinNetwork::Regtest, BitcoinNetwork::Main] {
            assert_eq!(
                feed_target(&hosted, network, &[], None).unwrap().describe(),
                "ws://mempool.internal:8999/api/v1/ws"
            );
        }
    }

    /// The P2P source peers with the wallet's own trusted node by default, at the standard
    /// port when the token named none; `p2p_peer` overrides it; a DNS-seeded wallet without an
    /// override has no feed. The list is a preference order: the first runnable source wins.
    #[test]
    fn the_p2p_source_resolves_to_the_kyoto_peer_or_the_override() {
        let p2p = MempoolConfig {
            sources: vec![MempoolSource::P2p],
            ..MempoolConfig::default()
        };
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        assert_eq!(
            feed_target(&p2p, BitcoinNetwork::Testnet4, &[(ip, Some(48333))], None),
            Some(FeedTarget::Peer {
                peer: "192.0.2.7:48333".parse().unwrap(),
                network: BitcoinNetwork::Testnet4,
                snapshot: None,
                receive_window: None,
            })
        );
        assert_eq!(
            feed_target(&p2p, BitcoinNetwork::Main, &[(ip, None)], None)
                .unwrap()
                .describe(),
            "p2p://192.0.2.7:8333 (relay)"
        );
        assert!(feed_target(&p2p, BitcoinNetwork::Main, &[], None).is_none());
        let pinned = MempoolConfig {
            p2p_peer: Some("10.0.0.9:18444".parse().unwrap()),
            p2p_snapshot: true,
            p2p_snapshot_interval_secs: 45,
            ..p2p.clone()
        };
        assert_eq!(
            feed_target(&pinned, BitcoinNetwork::Regtest, &[(ip, Some(1))], None)
                .unwrap()
                .describe(),
            "p2p://10.0.0.9:18444 (relay + mempool snapshots every 45s)"
        );
        // Preference order: p2p first falls back to the websocket where the wallet has no
        // peer, and the reverse order prefers the websocket where it has an endpoint.
        let both = MempoolConfig {
            sources: vec![MempoolSource::P2p, MempoolSource::MempoolSpace],
            ..MempoolConfig::default()
        };
        assert!(matches!(
            feed_target(&both, BitcoinNetwork::Main, &[], None),
            Some(FeedTarget::WebSocket { .. })
        ));
        assert!(matches!(
            feed_target(&both, BitcoinNetwork::Main, &[(ip, None)], None),
            Some(FeedTarget::Peer { .. })
        ));
        let reversed = MempoolConfig {
            sources: vec![MempoolSource::MempoolSpace, MempoolSource::P2p],
            ..MempoolConfig::default()
        };
        assert!(matches!(
            feed_target(&reversed, BitcoinNetwork::Main, &[(ip, None)], None),
            Some(FeedTarget::WebSocket { .. })
        ));
        assert!(matches!(
            feed_target(&reversed, BitcoinNetwork::Regtest, &[(ip, None)], None),
            Some(FeedTarget::Peer { .. })
        ));
    }

    #[test]
    fn overrides_must_be_websocket_urls() {
        assert!(
            validate_endpoint_override("mempool_space_url", "wss://m.example/api/v1/ws").is_ok()
        );
        // Plaintext is allowed on purpose: a self-hosted instance on a trusted LAN.
        assert!(
            validate_endpoint_override("mempool_space_url", "ws://10.0.0.2:8999/api/v1/ws").is_ok()
        );
        // The likely mistake is pasting the HTTP API URL; the message names the scheme.
        let err =
            validate_endpoint_override("mempool_space_url", "https://mempool.space/api/v1/ws")
                .unwrap_err()
                .to_string();
        assert!(err.contains("mempool_space_url"), "{err}");
        assert!(err.contains("wss://"), "{err}");
        assert!(validate_endpoint_override("mempool_space_url", "mempool.example").is_err());
        assert!(validate_endpoint_override("mempool_space_url", "wss:///no-host").is_err());
    }

    /// A real delta's envelope, trimmed: the delta key beside another key the server pushes,
    /// and the transaction in the Esplora shape (every field the server sends, only some of
    /// which are read).
    #[test]
    fn a_recorded_delta_parses_and_rebuilds_to_the_reported_txid() {
        let wallet = wallet();
        let mine = wallet
            .peek_address(KeychainKind::External, 0)
            .script_pubkey();
        let tx = spend(vec![(mine.clone(), 50_000), (foreign_script(9), 1_000)], 7);
        let prevouts = [Some((foreign_script(3), 60_000))];
        let message = serde_json::json!({
            "mempoolInfo": {"loaded": true, "size": 3, "bytes": 1024},
            DELTA_KEY: {
                "sequence": 4242,
                "added": [feed_json(&tx, &prevouts)],
                "removed": ["11".repeat(32)],
                "replaced": [],
                "mined": [],
            }
        })
        .to_string();
        let raw = parse_message(&message).unwrap().unwrap();
        assert_eq!(raw.sequence, Some(4242));
        assert_eq!(raw.added.len(), 1);
        let delta = build_delta(raw, 1_800_000_000);
        assert_eq!(delta.dropped, 0);
        assert_eq!(delta.added.len(), 1);
        let rebuilt = &delta.added[0];
        assert_eq!(*rebuilt.tx, tx);
        assert_eq!(
            rebuilt.seen, 1_725_000_000,
            "firstSeen wins over the local clock"
        );
        assert_eq!(rebuilt.prevouts, vec![Some(foreign_script(3))]);
        assert_eq!(delta.removed, vec![Txid::from_byte_array([0x11; 32])]);
        assert!(wallet_relevant(&wallet, rebuilt));

        // A message without the delta key is not a delta (and not an error).
        assert!(parse_message(r#"{"conversions":{"USD":1}}"#)
            .unwrap()
            .is_none());
        // One that claims one but cannot be read is an error the reader logs and moves past.
        assert!(parse_message(&format!(r#"{{"{DELTA_KEY}": 5}}"#)).is_err());
    }

    /// The txid check is the whole guard on the reconstruction: a transaction whose JSON
    /// does not round-trip to the id the server reported is dropped, counted, and never
    /// applied under either id.
    #[test]
    fn a_transaction_that_does_not_rebuild_to_its_txid_is_dropped() {
        let tx = spend(vec![(foreign_script(1), 1_000)], 5);
        let mut json = feed_json(&tx, &[None]);
        json["vout"][0]["value"] = serde_json::json!(999);
        let raw = RawDelta {
            added: vec![serde_json::from_value(json).unwrap()],
            ..RawDelta::default()
        };
        let delta = build_delta(raw, 0);
        assert!(delta.added.is_empty());
        assert_eq!(delta.dropped, 1);
        // And the direct API names both ids.
        let mut raw_tx: RawTx = serde_json::from_value(feed_json(&tx, &[None])).unwrap();
        raw_tx.txid = "22".repeat(32);
        let err = reconstruct(&raw_tx, 0).unwrap_err().to_string();
        assert!(err.contains(&tx.compute_txid().to_string()), "{err}");
        assert!(err.contains("not faithful"), "{err}");
        // A missing `firstSeen` (plain Esplora) falls back to the caller's clock.
        let raw_tx: RawTx = serde_json::from_value({
            let mut j = feed_json(&tx, &[None]);
            j.as_object_mut().unwrap().remove("firstSeen");
            j
        })
        .unwrap();
        assert_eq!(reconstruct(&raw_tx, 77).unwrap().seen, 77);
    }

    #[test]
    fn replacements_evict_the_replaced_and_add_a_full_replacement() {
        let tx = spend(vec![(foreign_script(1), 1_000)], 5);
        let old = Txid::from_byte_array([0xaa; 32]);
        let older = Txid::from_byte_array([0xbb; 32]);
        // Every shape the server has used: an object with a string, one with a list, and a
        // bare string; plus a full `by` transaction.
        let entries = vec![
            serde_json::json!({"replaced": old.to_string(), "by": feed_json(&tx, &[None])}),
            serde_json::json!({"replaced": [{"txid": older.to_string()}], "by": tx.compute_txid().to_string()}),
            serde_json::json!("cc".repeat(32)),
            serde_json::json!(42),
        ];
        let mut named = replaced_txids(&entries);
        named.sort();
        let mut expect = vec![old, older, Txid::from_byte_array([0xcc; 32])];
        expect.sort();
        assert_eq!(named, expect);

        let delta = build_delta(
            RawDelta {
                added: vec![serde_json::from_value(feed_json(&tx, &[None])).unwrap()],
                replaced: entries,
                ..RawDelta::default()
            },
            0,
        );
        // The replacement is the same transaction as the `added` entry: applied once.
        assert_eq!(delta.added.len(), 1);
        assert_eq!(delta.removed.len(), 3);
    }

    /// Relevance is local and covers both directions: a payment to one of the wallet's
    /// scripts, and a spend of one of its outputs - by the feed's prevout script, or by an
    /// outpoint the wallet already holds even when the feed omits prevouts.
    #[test]
    fn relevance_covers_receives_and_spends_by_prevout_or_by_held_outpoint() {
        let mut wallet = wallet();
        let mine = wallet
            .peek_address(KeychainKind::External, 0)
            .script_pubkey();
        let receive = spend(vec![(mine.clone(), 50_000)], 1);
        let feed_receive = FeedTx {
            tx: Arc::new(receive.clone()),
            prevouts: vec![None],
            seen: 0,
        };
        assert!(wallet_relevant(&wallet, &feed_receive));
        let unrelated = FeedTx {
            tx: Arc::new(spend(vec![(foreign_script(2), 1)], 2)),
            prevouts: vec![Some(foreign_script(3))],
            seen: 0,
        };
        assert!(!wallet_relevant(&wallet, &unrelated));

        // A spend of the wallet's output, recognized by the prevout script before the wallet
        // has recorded the output...
        let mut spend_of_mine = spend(vec![(foreign_script(4), 49_000)], 3);
        spend_of_mine.input[0].previous_output = OutPoint::new(receive.compute_txid(), 0);
        let by_prevout = FeedTx {
            tx: Arc::new(spend_of_mine.clone()),
            prevouts: vec![Some(mine.clone())],
            seen: 0,
        };
        assert!(wallet_relevant(&wallet, &by_prevout));
        // ...and, once the output is held, by the outpoint alone.
        let by_outpoint = FeedTx {
            tx: Arc::new(spend_of_mine),
            prevouts: vec![None],
            seen: 0,
        };
        assert!(!wallet_relevant(&wallet, &by_outpoint));
        wallet.apply_unconfirmed_txs([(Arc::new(receive), 1_700_000_000)]);
        assert!(wallet_relevant(&wallet, &by_outpoint));
    }

    /// One delta recorded from the live mainnet feed (2026-09-10, trimmed to two added
    /// transactions, the removed list and one replacement): real transactions must rebuild
    /// to their reported txids, and the replacement shape the server actually sends -
    /// `{"replaced": "<txid>", "by": {<full tx>}}` - must evict the old and add the new.
    /// The recorded shape is what `the_public_feed_still_answers_in_the_shape_we_parse`
    /// re-checks live.
    #[test]
    fn a_delta_recorded_from_the_live_feed_rebuilds_every_transaction() {
        let message = include_str!("testdata/mempool_delta.json");
        let raw = parse_message(message).unwrap().unwrap();
        assert_eq!(raw.added.len(), 2);
        assert_eq!(raw.replaced.len(), 1);
        let replaced = replaced_txids(&raw.replaced);
        assert_eq!(replaced.len(), 1);
        let replacement: Txid = raw.replaced[0]["by"]["txid"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let removed_count = raw.removed.len();
        let delta = build_delta(raw, 0);
        assert_eq!(
            delta.dropped, 0,
            "a real transaction did not rebuild to its txid"
        );
        // Two added plus the full replacement, each hashing to what the server reported.
        assert_eq!(delta.added.len(), 3);
        assert!(delta
            .added
            .iter()
            .any(|t| t.tx.compute_txid() == replacement));
        for added in &delta.added {
            assert!(added.seen > 1_600_000_000, "firstSeen was read");
            assert!(
                added.prevouts.iter().all(Option::is_some),
                "prevouts were read"
            );
        }
        // The server lists a replaced txid under `removed` as well; the union dedupes it.
        assert_eq!(delta.removed.len(), removed_count);
        assert!(delta.removed.contains(&replaced[0]));
    }

    /// The socket path end to end against an in-process fake feed: the handshake, the
    /// subscription the server must see, a delta delivered as an event, and the server
    /// closing the socket reported as a disconnect followed by a redial. This is what lets
    /// the reader be covered offline rather than only by the `#[ignore]`d live test.
    #[tokio::test]
    async fn the_socket_task_subscribes_delivers_deltas_and_redials() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tx = spend(vec![(foreign_script(1), 1_000)], 5);
        let delta = serde_json::json!({
            DELTA_KEY: {
                "sequence": 1,
                "added": [feed_json(&tx, &[None])],
                "removed": [],
                "replaced": [],
                "mined": [],
            }
        })
        .to_string();
        let (subscriptions_tx, mut subscriptions) = mpsc::channel::<String>(4);
        tokio::spawn(async move {
            // Two connections: the first is closed by the server after one delta, the
            // second stays open (and sees the subscription again).
            for connection in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                let first = ws.next().await.unwrap().unwrap();
                subscriptions_tx
                    .send(first.into_text().unwrap().as_str().to_string())
                    .await
                    .unwrap();
                ws.send(Message::text(delta.clone())).await.unwrap();
                if connection == 0 {
                    ws.close(None).await.unwrap();
                } else {
                    // Keep the second socket open until the test ends.
                    while ws.next().await.is_some() {}
                }
            }
        });

        let mut feed = MempoolFeed::start(
            FeedTarget::WebSocket {
                url: format!("ws://{addr}/api/v1/ws"),
            },
            Duration::from_millis(50),
            Duration::from_millis(50),
        );
        async fn next(feed: &mut MempoolFeed) -> FeedEvent {
            tokio::time::timeout(Duration::from_secs(10), feed.next())
                .await
                .expect("an event within the deadline")
                .expect("the feed task is alive")
        }
        assert!(matches!(next(&mut feed).await, FeedEvent::Connected { .. }));
        assert_eq!(subscriptions.recv().await.unwrap(), SUBSCRIBE);
        match next(&mut feed).await {
            FeedEvent::Delta(delta) => {
                assert_eq!(delta.sequence, Some(1));
                assert_eq!(delta.added.len(), 1);
                assert_eq!(*delta.added[0].tx, tx);
            }
            other => panic!("expected a delta, got {other:?}"),
        }
        assert!(matches!(next(&mut feed).await, FeedEvent::Disconnected(_)));
        // The redial subscribes afresh and the stream resumes.
        assert!(matches!(next(&mut feed).await, FeedEvent::Connected { .. }));
        assert_eq!(subscriptions.recv().await.unwrap(), SUBSCRIBE);
        assert!(matches!(next(&mut feed).await, FeedEvent::Delta(_)));
        // Dropping the feed ends the task.
        let task_alive = !feed.task.is_finished();
        assert!(task_alive);
        drop(feed);
    }

    /// The P2P source end to end against an in-process node: handshake, an announcement
    /// fetched and delivered as a delta, a ping answered, the BIP 35 snapshot request
    /// answered and delivered as a `Snapshot`, and a closed socket reported then redialed.
    #[tokio::test]
    async fn the_p2p_source_relays_snapshots_and_redials() {
        use crate::btc::p2p_feed::tests::{fake_node, sample_tx, Step};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = listener.local_addr().unwrap();
        let (a, b) = (sample_tx(1), sample_tx(2));
        let (a_id, b_id) = (a.compute_txid(), b.compute_txid());
        let stale = Txid::from_byte_array([9; 32]);
        let known = vec![a.clone(), b.clone()];
        let network = BitcoinNetwork::Regtest;
        let node = tokio::spawn({
            let known = known.clone();
            async move {
                fake_node(
                    listener,
                    network,
                    known.clone(),
                    vec![
                        // The snapshot request comes first (sent right after the handshake).
                        Step::AnswerMempool(vec![a.compute_txid(), stale]),
                        Step::Announce(vec![b.clone()]),
                        Step::Ping,
                        // Long enough for the (test-shortened) snapshot window to close.
                        Step::Wait(Duration::from_secs(6)),
                        Step::Close,
                    ],
                )
                .await;
                // The redial: handshake, then stay up.
                let listener = tokio::net::TcpListener::bind(peer).await.unwrap();
                fake_node(listener, network, known, vec![Step::Idle]).await;
            }
        });
        let mut feed = MempoolFeed::start(
            FeedTarget::Peer {
                peer,
                network,
                snapshot: Some(Duration::from_secs(300)),
                receive_window: None,
            },
            Duration::from_millis(200),
            Duration::from_millis(200),
        );
        async fn next(feed: &mut MempoolFeed) -> FeedEvent {
            tokio::time::timeout(Duration::from_secs(60), feed.next())
                .await
                .expect("an event within the deadline")
                .expect("the feed task is alive")
        }
        assert!(matches!(next(&mut feed).await, FeedEvent::Connected { .. }));
        // The snapshot's inv is fetched like any announcement: `a` arrives as a delta (the
        // stale txid draws a notfound, which is silent), then `b` from the plain announcement.
        let mut deltas = Vec::new();
        let mut snapshot = None;
        while deltas.len() < 2 || snapshot.is_none() {
            match next(&mut feed).await {
                FeedEvent::Delta(d) => deltas.push(d),
                FeedEvent::Snapshot(s) => snapshot = Some(s),
                // The collection's progress rides alongside; `p2p_feed`'s own test pins it.
                FeedEvent::SnapshotProgress(_) => {}
                other => panic!("unexpected {other:?}"),
            }
        }
        // The connect snapshot fetched everything (nothing was known on a new connection).
        assert!(snapshot.as_ref().unwrap().full);
        let mut got: Vec<Txid> = deltas
            .iter()
            .map(|d| d.added[0].tx.compute_txid())
            .collect();
        got.sort();
        let mut want = vec![a_id, b_id];
        want.sort();
        assert_eq!(got, want);
        assert!(deltas.iter().all(|d| d.added[0].prevouts == vec![None]));
        let snapshot = snapshot.unwrap().held;
        assert!(snapshot.contains(&a_id));
        assert!(snapshot.contains(&stale));
        // The node closed: a disconnect, then the redial connects again (a redial that
        // races the node's re-bind only costs another disconnect first).
        assert!(matches!(next(&mut feed).await, FeedEvent::Disconnected(_)));
        loop {
            match next(&mut feed).await {
                FeedEvent::Connected { .. } => break,
                FeedEvent::Disconnected(_) => continue,
                other => panic!("unexpected {other:?}"),
            }
        }
        drop(feed);
        node.abort();
    }

    /// The one thing the offline tests cannot check: that the live instance still speaks the
    /// shape this parser reads - the delta key, the Esplora transaction fields, and a
    /// reconstruction that hashes to the reported txid on real transactions. `#[ignore]`d
    /// (network, like `fees.rs`'s oracle test); run with
    /// `cargo test --features bitcoin -- --include-ignored`. Testnet4 rather than mainnet so a
    /// CI run does not pull mainnet volumes, but a delta may take a minute to arrive there.
    ///
    /// NB it needs *direct* egress: the trust anchors are the compiled-in Mozilla roots, so
    /// behind a TLS-intercepting proxy this fails the handshake however healthy the endpoint.
    #[tokio::test]
    #[ignore = "requires network access to mempool.space"]
    async fn the_public_feed_still_answers_in_the_shape_we_parse() {
        let target = feed_target(&ws_only(), BitcoinNetwork::Testnet4, &[], None).unwrap();
        let url = target.describe();
        let mut feed = MempoolFeed::start(target, Duration::from_secs(1), Duration::from_secs(1));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
        loop {
            let event = tokio::time::timeout_at(deadline, feed.next())
                .await
                .unwrap_or_else(|_| panic!("no delta from {url} within the deadline"))
                .unwrap();
            match event {
                FeedEvent::Connected { .. }
                | FeedEvent::Snapshot(_)
                | FeedEvent::SnapshotProgress(_) => {}
                FeedEvent::Disconnected(why) => panic!("{url}: {why}"),
                FeedEvent::Delta(delta) => {
                    // A quiet moment yields an empty delta; wait for one with content so the
                    // reconstruction is exercised on a real transaction.
                    if delta.added.is_empty() && delta.removed.is_empty() {
                        continue;
                    }
                    assert_eq!(
                        delta.dropped, 0,
                        "{url}: some added transactions did not rebuild to their txid"
                    );
                    return;
                }
            }
        }
    }
}
