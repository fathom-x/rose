//! The P2P mempool source: 0-conf for the kyoto backend with no server in the loop.
//!
//! The alternative to the mempool.space websocket ([`super::mempool_feed`] holds the shared
//! shape and the actor-facing events). Where that feed asks a third party for JSON, this one
//! is a minimal Bitcoin P2P client of zecd's own - version handshake, `inv`/`getdata`/`tx`,
//! `ping`/`pong`, and optionally BIP 35 `mempool` - peering with one node, by default the
//! wallet's own `kyoto://<ip>:<port>` trusted peer. Our `version` announces `relay = true`,
//! so the node announces every transaction entering its mempool with an `inv`; the client
//! requests **all of them** (`getdata`, by witness txid, in batches) and the actor matches
//! each received transaction against the wallet locally: an output paying one of its scripts
//! is a receive, an input spending an output it holds is a spend. The node learns nothing
//! but "a wallet at this IP wants relay", exactly what it learns from any full-node peer, and
//! since it relays everything to every such peer it cannot tell which transactions matter.
//!
//! Why a client of our own: the `bip157` crate kyoto rides on sends `relay: false`, drops
//! transaction inventory, and its maintainer has closed the request to expose relay
//! (2140-dev/kyoto#220: "a side-car application may still be possible"). This is that
//! side-car, built in zecd; kyoto keeps doing headers, filters and blocks untouched, over its
//! own connection.
//!
//! ## Bandwidth and the snapshot
//!
//! The stream costs raw transaction size - roughly 150-300 MB a day on mainnet, an order of
//! magnitude under the JSON feed, negligible on testnet4. With `[mempool] p2p_snapshot = true`
//! the client also sends BIP 35 `mempool` after the handshake and every
//! `p2p_snapshot_interval_secs` (five minutes by default: each answer costs the node an
//! `inv` of its whole mempool, and the interval only bounds how stale an eviction may be):
//! the node answers with an `inv` of its whole mempool, which the
//! client fetches like any other announcement (closing the pre-connect blind spot the
//! websocket design accepts) and reports to the actor as a [`FeedEvent::Snapshot`] - the one
//! source of **evictions** on this backend, since Core never announces them: a wallet
//! transaction the node held and no longer lists is queued for eviction, settled at the next
//! scan tip like a websocket `removed`. It is opt-in because Bitcoin Core answers `mempool`
//! only for peers with the `mempool` permission (`-whitelist=mempool@<wallet host>` or
//! `-whitebind`) or when `-peerbloomfilters` is on, and **disconnects** an unpermissioned
//! peer that asks; a DNS-seeded stranger will never answer. Without it the client is
//! deltas-only, like the websocket feed.
//!
//! ## Trust
//!
//! The same 0-conf posture as the websocket: the node's mempool view could lie, and a lie
//! only moves `untrusted_pending`. It cannot forge a confirmation (headers, proof of work and
//! filters keep confirmed state trustless) and it cannot attribute traffic to addresses. Note
//! the protocol version announced here is below the wtxid-relay threshold on purpose, so the
//! node announces by txid - the id `getdata` asks by and the wallet indexes by.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context as _};
use bdk_wallet::bitcoin::consensus::encode;
use bdk_wallet::bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bdk_wallet::bitcoin::p2p::message_blockdata::Inventory;
use bdk_wallet::bitcoin::p2p::message_network::VersionMessage;
use bdk_wallet::bitcoin::p2p::{Address, Magic, ServiceFlags};
use bdk_wallet::bitcoin::Txid;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, trace};

use super::mempool_feed::{FeedDelta, FeedEvent, FeedSnapshot, FeedTx};
use crate::coin::BitcoinNetwork;

/// What the node sees us as. Bitcoin Core logs it; nothing else reads it.
pub const USER_AGENT: &str = concat!("/zecd:", env!("CARGO_PKG_VERSION"), "/");

/// The protocol version announced: the last one before BIP 339 wtxid relay (70016). A node
/// negotiates wtxid relay only with a peer that announces 70016 *and* sends `wtxidrelay`;
/// staying below keeps every announcement a `MSG_TX` by txid without a negotiation to get
/// wrong, and Core accepts anything from 31800 up.
pub const PROTOCOL_VERSION: u32 = 70015;

/// How long the handshake (dial, `version`, `verack`) may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Our keepalive. Core pings its peers every two minutes on its own; ours is only so that a
/// silent link is noticed on our schedule rather than the node's.
const PING_INTERVAL: Duration = Duration::from_secs(60);

/// No message of any kind for this long means the link is dead: a healthy Core pings every
/// two minutes and answers ours within one, so this never fires on a live peer.
const SILENCE_TIMEOUT: Duration = Duration::from_secs(300);

/// How long after a `mempool` request the announcements that arrive count as the snapshot.
/// Core sends the reply at its next trickle (Poisson, mean 5s for an inbound peer) as one or
/// more `inv`s; this leaves generous room, and anything announced meanwhile is in the mempool
/// anyway, so over-collecting is harmless. (Shortened under test: the fake node answers at
/// once, and a 30s wait per test would only measure the clock.)
#[cfg(not(test))]
const SNAPSHOT_WINDOW: Duration = Duration::from_secs(30);
#[cfg(test)]
const SNAPSHOT_WINDOW: Duration = Duration::from_secs(2);

/// The longest a snapshot waits, past its window, for the transactions it requested. A
/// snapshot is delivered only once every transaction the request had to fetch arrived or
/// was reported gone (`notfound`), so the actor has matched each before it acts on the
/// snapshot; this bounds that wait against a node that never answers some request.
#[cfg(not(test))]
const SNAPSHOT_MAX_WAIT: Duration = Duration::from_secs(300);
#[cfg(test)]
const SNAPSHOT_MAX_WAIT: Duration = Duration::from_secs(10);

/// Announcements requested per `getdata`. Core caps a message at 50 000 entries; smaller
/// batches keep the node's reply interleaved with new announcements rather than a snapshot's
/// hundred thousand transactions arriving as one block of traffic.
const GETDATA_BATCH: usize = 1_000;

/// The frame size ceiling, Core's own `MAX_PROTOCOL_MESSAGE_LENGTH`. A peer claiming more is
/// not speaking the protocol.
const MAX_PAYLOAD: u32 = 4_000_000;

/// Txids already requested on this connection, so a snapshot does not re-fetch what the
/// stream already delivered. Cleared - not trimmed - past this size (a lost dedupe costs one
/// redundant fetch, never a missed transaction); a snapshot shrinks it to the live set anyway.
const KNOWN_CAP: usize = 500_000;

/// The network-standard P2P port, bitcoind's own default for each chain.
pub fn default_port(network: BitcoinNetwork) -> u16 {
    match network {
        BitcoinNetwork::Main => 8333,
        BitcoinNetwork::Testnet3 => 18333,
        BitcoinNetwork::Testnet4 => 48333,
        BitcoinNetwork::Regtest => 18444,
    }
}

/// The network's message-start bytes.
pub fn magic(network: BitcoinNetwork) -> Magic {
    match network {
        BitcoinNetwork::Main => Magic::BITCOIN,
        BitcoinNetwork::Testnet3 => Magic::TESTNET3,
        BitcoinNetwork::Testnet4 => Magic::TESTNET4,
        BitcoinNetwork::Regtest => Magic::REGTEST,
    }
}

/// Encode and write one message.
pub async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    magic: Magic,
    message: NetworkMessage,
) -> anyhow::Result<()> {
    let raw = RawNetworkMessage::new(magic, message);
    writer
        .write_all(&encode::serialize(&raw))
        .await
        .context("write a p2p message")?;
    Ok(())
}

/// Read one message: the 24-byte header (magic, command, length, checksum), then the payload
/// the header announces, then the crate's decoder over both - which checks the checksum and
/// turns any command it does not know into [`NetworkMessage::Unknown`] rather than an error,
/// so a newer node's chatter is skipped, not fatal. A wrong magic is fatal: the peer is on
/// another network.
pub async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    magic: Magic,
) -> anyhow::Result<NetworkMessage> {
    let mut header = [0u8; 24];
    reader
        .read_exact(&mut header)
        .await
        .context("read a p2p message header")?;
    if header[..4] != magic.to_bytes() {
        return Err(anyhow!(
            "the peer is on another network (message start {:02x?}, expected {:02x?})",
            &header[..4],
            magic.to_bytes()
        ));
    }
    let length = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
    if length > MAX_PAYLOAD {
        return Err(anyhow!(
            "the peer announced a {length}-byte message; refusing it"
        ));
    }
    let mut frame = Vec::with_capacity(24 + length as usize);
    frame.extend_from_slice(&header);
    frame.resize(24 + length as usize, 0);
    reader
        .read_exact(&mut frame[24..])
        .await
        .context("read a p2p message payload")?;
    let raw: RawNetworkMessage = encode::deserialize(&frame).context("decode a p2p message")?;
    Ok(raw.into_payload())
}

/// Our `version`: no services (we serve nothing), `relay = true` (the whole point), no
/// listening address, height 0. The node compares `nonce` against its own to detect a
/// self-connection; a random value is what the protocol asks for.
fn version_message(peer: SocketAddr) -> VersionMessage {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let nobody: SocketAddr = "0.0.0.0:0".parse().expect("a literal socket address");
    let mut version = VersionMessage::new(
        ServiceFlags::NONE,
        now,
        Address::new(&peer, ServiceFlags::NONE),
        Address::new(&nobody, ServiceFlags::NONE),
        rand_nonce(),
        USER_AGENT.to_string(),
        0,
    );
    version.version = PROTOCOL_VERSION;
    version.relay = true;
    version
}

/// A nonce without a dependency on a random-number crate: the clock's nanoseconds mixed with
/// this process's id. It only needs to differ from the node's own nonce.
fn rand_nonce() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    nanos ^ (u64::from(std::process::id()).rotate_left(32))
}

/// Only transaction announcements are of interest, and only by txid: a `MSG_WTX` (wtxid)
/// announcement would need wtxid relay, which [`PROTOCOL_VERSION`] does not negotiate, so
/// the node never sends one.
fn announced_txids(inventory: &[Inventory]) -> Vec<Txid> {
    inventory
        .iter()
        .filter_map(|item| match item {
            Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => Some(*txid),
            _ => None,
        })
        .collect()
}

/// A snapshot being collected.
struct Collecting {
    requested_at: Instant,
    /// Every txid announced since the request.
    collected: HashSet<Txid>,
    /// Requested with `getdata` since, and neither delivered nor reported gone yet.
    pending: HashSet<Txid>,
    /// Whether nothing was known on the connection when it was requested, so every txid it
    /// lists is fetched in full (see [`FeedSnapshot::full`]).
    full: bool,
}

/// The connection's mutable state across messages.
struct Session {
    magic: Magic,
    /// Txids requested on this connection (see [`KNOWN_CAP`]).
    known: HashSet<Txid>,
    /// While a snapshot is being collected.
    snapshot: Option<Collecting>,
    last_ping: Option<u64>,
}

impl Session {
    /// Request every newly announced transaction, in batches, and fold the announcement into
    /// an in-progress snapshot.
    async fn on_inv<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        inventory: &[Inventory],
    ) -> anyhow::Result<()> {
        let txids = announced_txids(inventory);
        if self.known.len() >= KNOWN_CAP {
            self.known.clear();
        }
        let wanted: Vec<Txid> = txids
            .iter()
            .copied()
            .filter(|txid| self.known.insert(*txid))
            .collect();
        if let Some(snapshot) = &mut self.snapshot {
            snapshot.collected.extend(txids.iter().copied());
            snapshot.pending.extend(wanted.iter().copied());
        }
        let wanted: Vec<Inventory> = wanted
            .into_iter()
            .map(Inventory::WitnessTransaction)
            .collect();
        trace!(
            announced = inventory.len(),
            requested = wanted.len(),
            "p2p feed: inv"
        );
        for batch in wanted.chunks(GETDATA_BATCH) {
            write_message(writer, self.magic, NetworkMessage::GetData(batch.to_vec())).await?;
        }
        Ok(())
    }

    /// Ask the node for its whole mempool (BIP 35) and start collecting the answer. `full`
    /// first forgets what this connection already fetched, so the answer is fetched in its
    /// entirety (see [`super::mempool_feed::MempoolFeed::request_full_snapshot`]); a request
    /// on a connection that has fetched nothing yet is full by construction.
    async fn request_snapshot<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        full: bool,
    ) -> anyhow::Result<()> {
        if full {
            self.known.clear();
        }
        let full = self.known.is_empty();
        write_message(writer, self.magic, NetworkMessage::MemPool).await?;
        self.snapshot = Some(Collecting {
            requested_at: Instant::now(),
            collected: HashSet::new(),
            pending: HashSet::new(),
            full,
        });
        debug!(full, "p2p feed: requested the node's mempool");
        Ok(())
    }

    /// A requested transaction arrived, or the node reported it gone.
    fn settled(&mut self, txid: &Txid) {
        if let Some(snapshot) = &mut self.snapshot {
            snapshot.pending.remove(txid);
        }
    }

    /// The finished snapshot, once its collection window has passed and every transaction
    /// it requested has been delivered (or [`SNAPSHOT_MAX_WAIT`] ran out). Also trims `known`
    /// to what the node still holds, so a later re-announcement of a returned transaction is
    /// fetched again rather than skipped as already seen.
    fn take_snapshot(&mut self) -> Option<FeedSnapshot> {
        let done = matches!(&self.snapshot, Some(s) if {
            let age = s.requested_at.elapsed();
            age >= SNAPSHOT_WINDOW && (s.pending.is_empty() || age >= SNAPSHOT_MAX_WAIT)
        });
        if !done {
            return None;
        }
        let snapshot = self.snapshot.take()?;
        if !snapshot.pending.is_empty() {
            debug!(
                outstanding = snapshot.pending.len(),
                "p2p feed: snapshot delivered with requests still unanswered"
            );
        }
        self.known.retain(|txid| snapshot.collected.contains(txid));
        Some(FeedSnapshot {
            held: snapshot.collected,
            full: snapshot.full,
            requested_at: snapshot.requested_at,
        })
    }
}

/// One connection's life: dial, handshake, then relay until the link breaks. `Ok` is the
/// node closing the socket; `Err` everything else. Either way the caller redials with
/// backoff. Every event goes to `events`; a closed channel ends the connection quietly.
pub async fn run_peer(
    peer: SocketAddr,
    network: BitcoinNetwork,
    snapshot: Option<Duration>,
    receive_window: Option<u32>,
    events: &mpsc::Sender<FeedEvent>,
    refetch: &mut watch::Receiver<u64>,
) -> anyhow::Result<()> {
    let magic = magic(network);
    // A refetch asked for before this connection existed is already served by it: the
    // snapshot at connect fetches everything.
    refetch.borrow_and_update();
    let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, super::net::connect(peer, receive_window))
        .await
        .map_err(|_| anyhow!("no connection to {peer} within {HANDSHAKE_TIMEOUT:?}"))?
        .with_context(|| format!("connect to {peer}"))?;
    let (mut reader, mut writer) = stream.into_split();
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        write_message(
            &mut writer,
            magic,
            NetworkMessage::Version(version_message(peer)),
        )
        .await?;
        let mut acked = false;
        let mut versioned = false;
        while !(acked && versioned) {
            match read_message(&mut reader, magic).await? {
                NetworkMessage::Version(theirs) => {
                    debug!(
                        peer = %peer,
                        agent = %theirs.user_agent,
                        version = theirs.version,
                        height = theirs.start_height,
                        "p2p feed: peer version"
                    );
                    versioned = true;
                    write_message(&mut writer, magic, NetworkMessage::Verack).await?;
                }
                NetworkMessage::Verack => acked = true,
                // Anything else before the handshake completes (`wtxidrelay`, `sendaddrv2`,
                // a newer node's extensions) is ignored, as the protocol says.
                _ => {}
            }
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow!("no handshake with {peer} within {HANDSHAKE_TIMEOUT:?}"))??;
    info!(peer = %peer, snapshot = ?snapshot, "p2p feed connected (relaying)");
    if events.send(FeedEvent::Connected).await.is_err() {
        return Ok(());
    }

    // Reads move to a task of their own: `read_exact` is not cancel-safe, so a frame read
    // that sat in the `select!` below would lose its partial bytes whenever another branch
    // fired first (a ping tick mid-header desyncs the stream). A channel receive is
    // cancel-safe, so the loop waits on that instead. The task dies with this function.
    let (frames_tx, mut frames) = mpsc::channel::<anyhow::Result<NetworkMessage>>(256);
    let reader_task = AbortOnDrop(tokio::spawn(async move {
        loop {
            match read_message(&mut reader, magic).await {
                Ok(message) => {
                    if frames_tx.send(Ok(message)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = frames_tx.send(Err(e)).await;
                    break;
                }
            }
        }
    }));
    let _keep = &reader_task;

    let mut session = Session {
        magic,
        known: HashSet::new(),
        snapshot: None,
        last_ping: None,
    };
    if snapshot.is_some() {
        session.request_snapshot(&mut writer, true).await?;
    }
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.tick().await; // the first tick is immediate; the handshake just proved the link
                       // With snapshots off the interval never fires (the branch is guarded), so any period
                       // will do for it.
    let mut resnapshot = tokio::time::interval(snapshot.unwrap_or(Duration::from_secs(3600)));
    resnapshot.tick().await;
    // The snapshot window closes on a timer of its own so a quiet link (no message to
    // prompt the check) still delivers it.
    let mut settle = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            next = tokio::time::timeout(SILENCE_TIMEOUT, frames.recv()) => {
                let message = match next {
                    Err(_) => return Err(anyhow!("nothing received from {peer} for {SILENCE_TIMEOUT:?}")),
                    // The reader task ended without an error: only after a send failed,
                    // which cannot happen while this loop holds the receiver.
                    Ok(None) => return Ok(()),
                    Ok(Some(Err(e))) => {
                        // A clean close reads as an EOF inside the header read.
                        let closed = e
                            .root_cause()
                            .downcast_ref::<std::io::Error>()
                            .is_some_and(|io| io.kind() == std::io::ErrorKind::UnexpectedEof);
                        return if closed { Ok(()) } else { Err(e) };
                    }
                    Ok(Some(Ok(message))) => message,
                };
                match message {
                    NetworkMessage::Inv(inventory) => {
                        session.on_inv(&mut writer, &inventory).await?;
                    }
                    NetworkMessage::Tx(tx) => {
                        session.settled(&tx.compute_txid());
                        let prevouts = vec![None; tx.input.len()];
                        let delta = FeedDelta {
                            sequence: None,
                            added: vec![FeedTx {
                                tx: Arc::new(tx),
                                prevouts,
                                seen: unix_now(),
                            }],
                            removed: Vec::new(),
                            dropped: 0,
                        };
                        if events.send(FeedEvent::Delta(delta)).await.is_err() {
                            return Ok(());
                        }
                    }
                    NetworkMessage::Ping(nonce) => {
                        write_message(&mut writer, magic, NetworkMessage::Pong(nonce)).await?;
                    }
                    NetworkMessage::Pong(nonce) => {
                        if session.last_ping == Some(nonce) {
                            session.last_ping = None;
                        }
                    }
                    // `notfound`: the transaction left the mempool between the announcement
                    // and our request. Never applied; only a snapshot waiting on it cares.
                    NetworkMessage::NotFound(gone) => {
                        for txid in announced_txids(&gone) {
                            session.settled(&txid);
                        }
                    }
                    // Headers, addresses, fee filters, compact-block negotiation, and
                    // whatever a newer node adds: not this client's business.
                    _ => {}
                }
            }
            _ = ping.tick() => {
                let nonce = rand_nonce();
                session.last_ping = Some(nonce);
                write_message(&mut writer, magic, NetworkMessage::Ping(nonce)).await?;
            }
            _ = resnapshot.tick(), if snapshot.is_some() => {
                if session.snapshot.is_none() {
                    session.request_snapshot(&mut writer, false).await?;
                }
            }
            // The actor asked for the whole mempool again (see
            // `MempoolFeed::request_full_snapshot`). Replaces a periodic snapshot in flight.
            changed = refetch.changed(), if snapshot.is_some() => {
                if changed.is_err() {
                    return Ok(());
                }
                session.request_snapshot(&mut writer, true).await?;
            }
            _ = settle.tick() => {
                if let Some(held) = session.take_snapshot() {
                    debug!(
                        held = held.held.len(),
                        full = held.full,
                        "p2p feed: mempool snapshot collected"
                    );
                    if events.send(FeedEvent::Snapshot(held)).await.is_err() {
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// A task that must not outlive the connection it reads for.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use bdk_wallet::bitcoin::hashes::Hash as _;
    use bdk_wallet::bitcoin::{
        absolute, transaction, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };
    use tokio::net::TcpListener;

    /// A transaction with a witness, so the fetch is by `MSG_WITNESS_TX` and the bytes on the
    /// wire carry it.
    pub(crate) fn sample_tx(salt: u8) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([salt; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::from_slice(&[vec![salt; 71], vec![0x02; 33]]),
            }],
            output: vec![TxOut {
                value: bdk_wallet::bitcoin::Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_p2wpkh(
                    &bdk_wallet::bitcoin::WPubkeyHash::from_byte_array([salt; 20]),
                ),
            }],
        }
    }

    /// What a fake node does after the handshake, in order.
    pub(crate) enum Step {
        /// Announce these transactions, serve the `getdata` that follows.
        Announce(Vec<Transaction>),
        /// Wait for a `mempool` request and answer it with an `inv` of these txids.
        AnswerMempool(Vec<Txid>),
        /// Ping the client and wait for the pong.
        Ping,
        /// Stay up (serving requests) for this long.
        Wait(Duration),
        /// Close the socket.
        Close,
        /// Keep the socket open, answering pings, until the client goes away.
        Idle,
    }

    /// An in-process node speaking just enough of the protocol: handshake, then `steps`.
    /// Every `getdata` it sees is answered from `known` (a `notfound` for the rest), and
    /// pings are answered throughout.
    pub(crate) async fn fake_node(
        listener: TcpListener,
        network: BitcoinNetwork,
        known: Vec<Transaction>,
        steps: Vec<Step>,
    ) {
        let magic = magic(network);
        let (stream, _) = listener.accept().await.unwrap();
        let (mut reader, mut writer) = stream.into_split();
        // Handshake: their version, our version + verack, their verack.
        let theirs = match read_message(&mut reader, magic).await.unwrap() {
            NetworkMessage::Version(v) => v,
            other => panic!("expected version, got {other:?}"),
        };
        assert!(theirs.relay, "the client must ask for relay");
        assert_eq!(theirs.version, PROTOCOL_VERSION);
        assert_eq!(theirs.user_agent, USER_AGENT);
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut ours = version_message(peer);
        ours.user_agent = "/FakeCore:0.1/".into();
        write_message(&mut writer, magic, NetworkMessage::Version(ours))
            .await
            .unwrap();
        write_message(&mut writer, magic, NetworkMessage::Verack)
            .await
            .unwrap();
        while read_message(&mut reader, magic).await.unwrap() != NetworkMessage::Verack {}
        // Serve a getdata / answer a ping, until `until` matches a message.
        async fn serve_until<F: Fn(&NetworkMessage) -> bool>(
            reader: &mut tokio::net::tcp::OwnedReadHalf,
            writer: &mut tokio::net::tcp::OwnedWriteHalf,
            magic: Magic,
            known: &[Transaction],
            until: F,
        ) -> Option<NetworkMessage> {
            loop {
                let message = match read_message(reader, magic).await {
                    Ok(m) => m,
                    Err(_) => return None,
                };
                if until(&message) {
                    return Some(message);
                }
                match message {
                    NetworkMessage::GetData(items) => {
                        for item in items {
                            let txid = match item {
                                Inventory::WitnessTransaction(t) | Inventory::Transaction(t) => t,
                                _ => continue,
                            };
                            match known.iter().find(|tx| tx.compute_txid() == txid) {
                                Some(tx) => {
                                    write_message(writer, magic, NetworkMessage::Tx(tx.clone()))
                                        .await
                                        .unwrap()
                                }
                                None => write_message(
                                    writer,
                                    magic,
                                    NetworkMessage::NotFound(vec![Inventory::WitnessTransaction(
                                        txid,
                                    )]),
                                )
                                .await
                                .unwrap(),
                            }
                        }
                    }
                    NetworkMessage::Ping(nonce) => {
                        write_message(writer, magic, NetworkMessage::Pong(nonce))
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
        for step in steps {
            match step {
                Step::Announce(txs) => {
                    let inv = txs
                        .iter()
                        .map(|tx| Inventory::Transaction(tx.compute_txid()))
                        .collect();
                    write_message(&mut writer, magic, NetworkMessage::Inv(inv))
                        .await
                        .unwrap();
                    // Serve the getdata that follows before moving on.
                    let got = serve_until(&mut reader, &mut writer, magic, &known, |m| {
                        matches!(m, NetworkMessage::GetData(_))
                    })
                    .await;
                    if let Some(NetworkMessage::GetData(items)) = got {
                        for item in items {
                            if let Inventory::WitnessTransaction(txid)
                            | Inventory::Transaction(txid) = item
                            {
                                // As Core answers: the transaction, or a `notfound` (a
                                // snapshot waits on every txid it requested).
                                let reply = match known.iter().find(|tx| tx.compute_txid() == txid)
                                {
                                    Some(tx) => NetworkMessage::Tx(tx.clone()),
                                    None => NetworkMessage::NotFound(vec![
                                        Inventory::WitnessTransaction(txid),
                                    ]),
                                };
                                write_message(&mut writer, magic, reply).await.unwrap();
                            }
                        }
                    }
                }
                Step::AnswerMempool(txids) => {
                    let got = serve_until(&mut reader, &mut writer, magic, &known, |m| {
                        matches!(m, NetworkMessage::MemPool)
                    })
                    .await;
                    assert!(got.is_some(), "the client never asked for the mempool");
                    let inv = txids.into_iter().map(Inventory::Transaction).collect();
                    write_message(&mut writer, magic, NetworkMessage::Inv(inv))
                        .await
                        .unwrap();
                }
                Step::Ping => {
                    write_message(&mut writer, magic, NetworkMessage::Ping(42))
                        .await
                        .unwrap();
                    let got = serve_until(&mut reader, &mut writer, magic, &known, |m| {
                        matches!(m, NetworkMessage::Pong(42))
                    })
                    .await;
                    assert!(got.is_some(), "the client did not answer the ping");
                }
                Step::Wait(how_long) => {
                    let _ = tokio::time::timeout(
                        how_long,
                        serve_until(&mut reader, &mut writer, magic, &known, |_| false),
                    )
                    .await;
                }
                Step::Close => {
                    drop(writer);
                    return;
                }
                Step::Idle => {
                    serve_until(&mut reader, &mut writer, magic, &known, |_| false).await;
                    return;
                }
            }
        }
    }

    #[test]
    fn ports_and_magic_follow_bitcoind() {
        assert_eq!(default_port(BitcoinNetwork::Main), 8333);
        assert_eq!(default_port(BitcoinNetwork::Testnet4), 48333);
        assert_eq!(default_port(BitcoinNetwork::Regtest), 18444);
        assert_eq!(magic(BitcoinNetwork::Main), Magic::BITCOIN);
        assert_eq!(magic(BitcoinNetwork::Testnet4), Magic::TESTNET4);
        assert_eq!(magic(BitcoinNetwork::Regtest), Magic::REGTEST);
    }

    #[test]
    fn only_transaction_announcements_are_requested() {
        let txid = Txid::from_byte_array([7; 32]);
        let inv = vec![
            Inventory::Transaction(txid),
            Inventory::Block(bdk_wallet::bitcoin::BlockHash::from_byte_array([1; 32])),
            Inventory::WTx(bdk_wallet::bitcoin::Wtxid::from_byte_array([2; 32])),
            Inventory::WitnessTransaction(txid),
        ];
        assert_eq!(announced_txids(&inv), vec![txid, txid]);
    }

    /// The codec round-trips through the crate's decoder, a wrong network is refused at the
    /// header, and an unknown command is skipped rather than fatal.
    #[tokio::test]
    async fn the_frame_codec_round_trips_and_refuses_another_network() {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        write_message(&mut a, Magic::TESTNET4, NetworkMessage::Ping(9))
            .await
            .unwrap();
        assert!(matches!(
            read_message(&mut b, Magic::TESTNET4).await.unwrap(),
            NetworkMessage::Ping(9)
        ));
        write_message(&mut a, Magic::BITCOIN, NetworkMessage::Ping(9))
            .await
            .unwrap();
        let err = read_message(&mut b, Magic::TESTNET4)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("another network"), "{err}");
        // An unknown command decodes as `Unknown`, so a newer node's messages are ignorable.
        // (A fresh pipe: the refused frame's payload is still in the old one - a refused
        // magic ends the connection, it does not resynchronize it.)
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let raw = RawNetworkMessage::new(
            Magic::REGTEST,
            NetworkMessage::Unknown {
                command: "zecdfuture".parse().unwrap(),
                payload: Vec::new(),
            },
        );
        a.write_all(&encode::serialize(&raw)).await.unwrap();
        assert!(matches!(
            read_message(&mut b, Magic::REGTEST).await.unwrap(),
            NetworkMessage::Unknown { .. }
        ));
    }

    #[test]
    fn the_version_asks_for_relay_below_wtxid_negotiation() {
        let v = version_message("127.0.0.1:18444".parse().unwrap());
        assert!(v.relay);
        assert_eq!(v.version, 70015);
        assert_eq!(v.services, ServiceFlags::NONE);
        assert!(v.user_agent.starts_with("/zecd:"));
    }
}
