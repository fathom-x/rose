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
//! A **rebroadcast pass** ([`BtcActor::rebroadcast_pass`]) follows every sync pass that
//! reaches a tip the wallet has not rebroadcast at yet - so once per new block, and once
//! after every reconnect, never on a timer. It resubmits every unconfirmed wallet transaction,
//! sends and receives alike, as Bitcoin Core's wallet does (a transaction the network dropped
//! stays unconfirmed in the wallet - a send with its inputs still spent - and nothing else
//! would bring the network back in line: a reorg makes an anti-fee-sniping locktime non-final
//! and Core drops the transaction rather than hold it), skipping the ones bitcoind's mempool
//! already holds and classifying its verdicts
//! ([`classify_rejection`]); over kyoto it re-announces detached, since a peer that already
//! has the transaction never asks for it and the wait must not hold the actor.
//!
//! A send is **committed before it is relayed** ([`BtcActor::commit_before_relay`], then
//! [`BtcActor::relay_committed`]): the signed transaction is applied at 0-conf and persisted
//! before a byte of it goes to the upstream, so a crash between the two leaves a wallet that
//! knows its inputs are spent rather than one that double-spends them on the next send -
//! Bitcoin Core's `CommitTransaction` order. The record then follows the relay's verdict:
//! rejected by the node, a transaction the wallet funded is withdrawn (the same bytes can
//! never be accepted, the inputs are released, the node's error passes through - except a
//! `-27` already-in-chain, which only says the scan is behind); no verdict at all (a transport failure)
//! or a kyoto announcement no peer requests within the light client's timeout
//! ([`Relay::Queued`]), and it **stands** with the txid returned and a WARN, because the
//! bytes may well still relay (the light client holds a queued transaction for the next
//! peer; the rebroadcast pass resubmits at each new tip and reconnect), and dropping the
//! record would leave the wallet's view behind the world's - a retry could then double-spend
//! the same inputs, which is unrecoverable, where a recorded send that never relays merely
//! holds its inputs until `abandontransaction` releases them (recoverable).
//!
//! The spend path derives its signers from the seed **per send** (a throwaway in-memory
//! signing wallet over the private BIP 84 descriptors - `keys::signing_wallet`), so no
//! spending material ever lands on disk; the persisted wallet holds public descriptors only.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bdk_bitcoind_rpc::Emitter;
use bdk_wallet::bitcoin::{Address, Amount, BlockHash, FeeRate, OutPoint, Psbt, Transaction, Txid};
use bdk_wallet::{KeychainKind, PersistedWallet, SignOptions, Wallet};
use secrecy::SecretVec;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, error, info, info_span, warn, Instrument as _};

use crate::backoff::Backoff;
use crate::btc::ancestors::{AncestorAware, Ancestry, Unconfirmed};
use crate::btc::chain::{BitcoindRpc, BroadcastError, BtcEndpoint};
use crate::btc::keys::{self, AccountKeys};
use crate::btc::kyoto::{KyotoConn, KyotoFailure};
use crate::btc::mempool_feed::{feed_target, FeedDelta, FeedEvent, MempoolFeed};
use crate::btc::store::Persister;
use crate::coin::BitcoinNetwork;
use crate::error::{codes, RpcError};
use bdk_wallet::bitcoin::constants::COINBASE_MATURITY;

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

/// The wallet's balance in satoshis, bucketed on Core's rules (the actor's `Balance`
/// command computes it from the unspent set rather than taking BDK's own `balance()`,
/// whose maturity and trust rules both differ from Core's by a little).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BtcBalance {
    /// Confirmed and spendable.
    pub confirmed: u64,
    /// Unconfirmed outputs of transactions the wallet funded (change and self-payments).
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
    /// Whether the output is a coinbase reward (the wallet's address was a block's payout).
    pub coinbase: bool,
    /// Whether it is a coinbase reward Core still calls immature (under
    /// `COINBASE_MATURITY + 1` confirmations). Every reader withholds these unless asked -
    /// `listunspent` and depth-filtered `getbalance` exactly as Core does (BDK's own
    /// `list_unspent` has no maturity filter, and counting an unspendable reward as a
    /// spendable balance is a reporting bug); `listunspent`'s
    /// `include_immature_coinbase` query option is the one way to see them there.
    /// `getbalances.mine.immature` is where their value shows.
    pub immature: bool,
    /// The output's script, hex (`listunspent.scriptPubKey`).
    pub script_pubkey: String,
    /// Core's inferred output descriptor for the wallet key that owns it, with its
    /// checksum: `wpkh([fingerprint/84'/coin'/0'/keychain/index]pubkey)#checksum`.
    pub desc: Option<String>,
}

/// What the engine knows about an address, for `getaddressinfo`-shaped reads.
#[derive(Clone, Debug)]
pub struct BtcAddressInfo {
    pub is_mine: bool,
    /// `Some((change, index))` when the address is one of the wallet's own derived
    /// addresses: which keychain (change or external) and the derivation index.
    pub derivation: Option<(bool, u32)>,
    /// The owning key, for an own address (`getaddressinfo`'s `pubkey`/`desc`/
    /// `hdmasterfingerprint`).
    pub key: Option<BtcKeyOrigin>,
}

/// One revealed external address with every output that ever paid it - the raw material of
/// `listreceivedbyaddress`, whose `minconf`/`include_empty`/filter rules the RPC layer
/// applies. Internal (change) addresses are never listed: Core's `listreceivedbyaddress`
/// counts receiving addresses only, and so does the Zcash handler.
#[derive(Clone, Debug)]
pub struct BtcAddressReceipts {
    pub address: String,
    /// The external-keychain derivation index (`m/84'/c'/0'/0/<index>`).
    pub index: u32,
    pub receipts: Vec<BtcReceipt>,
}

/// One output paying a wallet address.
#[derive(Clone, Debug)]
pub struct BtcReceipt {
    pub txid: String,
    pub amount_sat: u64,
    /// 0 while the paying transaction is unconfirmed.
    pub confirmations: u64,
    /// A coinbase reward Core still calls immature (the same rule as `BtcUtxo::immature`):
    /// withheld by `getreceivedbyaddress`/`listreceivedbyaddress` unless their
    /// `include_immature_coinbase` argument asks for it, as in Core.
    pub immature: bool,
}

/// One of the wallet's two public descriptors, Core's `listdescriptors` vocabulary.
#[derive(Clone, Debug)]
pub struct BtcDescriptor {
    /// The descriptor string with its checksum: `wpkh([fp/84'/c'/0']xpub/0/*)#....`.
    pub desc: String,
    /// The change (internal) keychain, as opposed to the receiving one.
    pub internal: bool,
    /// The next index to be revealed on this keychain.
    pub next_index: u32,
    /// The end of the range the wallet currently watches: `next_index` plus the keychain's
    /// lookahead - Core's `range[1]`, the keypool analogue.
    pub range_end: u32,
    /// Core's `timestamp` (the descriptor's birth time, the point a rescan starts from): the
    /// birthday block's own time once the chain source has answered, else the operator's
    /// recorded birthday date when `init` kept one, else the UTC midnight of the day the
    /// shipped per-day table places the birthday height in (mainnet; at or before the
    /// block's own time, so a rescan from it cannot miss the birthday block), else 0.
    pub timestamp: u64,
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
    /// Raw transaction hex (`gettransaction`'s `hex` field) - serialized for a single
    /// lookup only; a history listing, which never shows it, leaves it `None`.
    pub hex: Option<String>,
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

impl BtcConnState {
    /// The `/status` spelling, shared with the Zcash `ConnState` so one dashboard reads both.
    pub fn as_str(self) -> &'static str {
        match self {
            BtcConnState::Down => "down",
            BtcConnState::Syncing => "syncing",
            BtcConnState::Ready => "ready",
        }
    }
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
    /// The resolved birthday anchor - the `(height, hash)` checkpoint a kyoto first scan
    /// starts from - once one exists: recorded by `init`, or by the first sync's own
    /// resolution against the light client's headers (which is why it rides the status
    /// channel rather than the static handle: it can appear at runtime). `None` until then,
    /// and always `None` for a bitcoind-backed wallet, whose emitter starts from the
    /// birthday by height. Reported by `getwalletinfo` as `birthday.anchor`.
    pub birthday_anchor: Option<(u32, String)>,
    /// The birthday block's header time, once the chain source has answered: one
    /// `getblockheader` at connect over bitcoind, the header (or the anchor block) off the
    /// light client once its headers cover the birthday over kyoto. `None` until then.
    /// `getwalletinfo` prefers it for `birthday.time` over the offline record.
    pub birthday_block_time: Option<u64>,
    /// The opt-in mempool feed's state (`[mempool]`, kyoto only): `None` when no feed is
    /// configured for this wallet - the default, and always the case over bitcoind, which
    /// has a mempool of its own. Reported by `getwalletinfo` as `mempool_feed`.
    pub mempool_feed: Option<MempoolFeedStatus>,
}

/// What the wallet knows about its mempool feed (`crate::btc::mempool_feed`), for
/// `getwalletinfo`. Counters are per actor life, not persisted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MempoolFeedStatus {
    /// The `[mempool] sources` name the feed runs on.
    pub source: &'static str,
    /// Where it connects (`FeedTarget::describe`).
    pub endpoint: String,
    /// Whether the socket is up and subscribed right now.
    pub connected: bool,
    /// When the last delta arrived (unix seconds); `None` before the first.
    pub last_delta: Option<u64>,
    /// Deltas received.
    pub deltas: u64,
    /// Transactions the feed delivered that touched this wallet and were applied.
    pub matched: u64,
    /// Added transactions the feed delivered that did not rebuild to their reported txid
    /// and were dropped - a count that grows steadily means the parser has drifted from
    /// the server's shape.
    pub dropped: u64,
    /// For a feed that takes BIP 35 snapshots (`p2p` with `p2p_snapshot`): whether one has
    /// been applied since the feed last (re)connected - for a wallet started from an empty
    /// datadir, one fetched in full after the wallet reached tip. Sends wait for it (see
    /// `BtcActor::send_gate`). `None` for a feed that takes none.
    pub snapshot_applied: Option<bool>,
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
        reply: oneshot::Sender<Result<BtcSent, RpcError>>,
    },
    Broadcast {
        hex: String,
        reply: oneshot::Sender<Result<String, RpcError>>,
    },
    AbandonTransaction {
        txid: Txid,
        reply: oneshot::Sender<Result<(), RpcError>>,
    },
    /// `bumpfee`: replace an unconfirmed own send with a higher-fee one (BIP 125).
    BumpFee {
        txid: Txid,
        options: BtcBumpOptions,
        reply: oneshot::Sender<Result<BtcBumped, RpcError>>,
    },
    /// A window of the history in Core's `listtransactions` terms: skip `skip` entries from
    /// the newest end, then up to `count` entries, oldest first. Only that window is built.
    ListTransactions {
        count: usize,
        skip: usize,
        reply: oneshot::Sender<Result<Vec<BtcTxRecord>, RpcError>>,
    },
    /// How many transactions the wallet holds (`getwalletinfo.txcount`), without building any.
    TxCount {
        reply: oneshot::Sender<Result<usize, RpcError>>,
    },
    GetTransaction {
        txid: String,
        reply: oneshot::Sender<Result<Option<BtcTxRecord>, RpcError>>,
    },
    ReceivedByAddress {
        reply: oneshot::Sender<Result<Vec<BtcAddressReceipts>, RpcError>>,
    },
    Descriptors {
        reply: oneshot::Sender<Result<Vec<BtcDescriptor>, RpcError>>,
    },
    /// `listsinceblock`: every transaction mined above `since` (or unconfirmed), and the
    /// cursor block `target_confirmations` deep.
    SinceBlock {
        since: Option<BlockHash>,
        target_confirmations: u32,
        reply: oneshot::Sender<Result<BtcSinceBlock, RpcError>>,
    },
    /// `estimatesmartfee`: the connected backend's fee rate for `target` blocks, with the
    /// source that answered.
    EstimateFee {
        target: u16,
        conservative: Option<bool>,
        reply: oneshot::Sender<Result<Option<(u64, String)>, RpcError>>,
    },
}

/// What `listsinceblock` reports: the transactions, oldest first, and the cursor to pass
/// back next time.
#[derive(Clone, Debug)]
pub struct BtcSinceBlock {
    pub records: Vec<BtcTxRecord>,
    /// The hash of the block `target_confirmations` deep - or the wallet's earliest
    /// checkpoint when the chain it holds is shallower (a lower cursor only re-reports,
    /// never misses), the Zcash handler's rule.
    pub lastblock: String,
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
    /// How the recipients in `subtract_fee_from` share the fee (zecd's `fee_split`).
    pub fee_split: BtcFeeSplit,
    /// Core's `replaceable = false`: build every input with `nSequence = 0xFFFFFFFE`
    /// (locktime still enforced for anti-fee-sniping, no BIP 125 signal) instead of BDK's
    /// RBF-signalling default. `false` - the `Default` - keeps that default, which is also
    /// Core's own `-walletrbf` default.
    pub non_replaceable: bool,
}

/// How the recipients that pay a send's fee share it (zecd's `fee_split` extension).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BtcFeeSplit {
    /// Core's `subtractfeefrom`: the whole fee, divided equally among the paying recipients.
    #[default]
    Equal,
    /// Each paying recipient pays for its own output's block space at the send's rate
    /// (`output_fee_share`); the sender's change pays everything else - the header, the
    /// inputs, the change output, and any unconfirmed parents the send pays for. A
    /// recipient's charge is then independent of which coins the sender happened to spend.
    Output,
}

/// What a completed send reports: the txid, and Core's `fee_reason` - where the fee rate
/// came from, the second half of `sendtoaddress`/`sendmany`'s `verbose` answer. Core's own
/// strings where zecd prices the same way ("PayTxFee set" for an explicit `fee_rate`,
/// "Fallback fee" for the test-network floor); otherwise the source that answered
/// (`estimatesmartfee`, or a `[fees]` tier name on kyoto), since Core's estimator-horizon
/// strings describe a computation zecd does not do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcSent {
    pub txid: String,
    pub fee_reason: String,
}

/// Caller-supplied `bumpfee` options the engine honors - wire-friendly primitives, as
/// [`BtcSendOptions`]. `Default` is Core's default bump: the old fee rate plus the wallet's
/// incremental relay fee, or the upstream's estimate when that is higher.
#[derive(Clone, Debug, Default)]
pub struct BtcBumpOptions {
    /// An explicit fee rate for the replacement, in sat/kvB (Core's `fee_rate`, sat/vB at
    /// 3-decimal precision). Must still clear BIP 125's replacement rules against the
    /// original - a higher rate *and* a higher total fee by the incremental relay fee.
    pub fee_rate_sat_per_kvb: Option<u64>,
    /// Core's `replaceable = false`: the replacement stops signalling BIP 125, so it cannot
    /// itself be bumped again.
    pub non_replaceable: bool,
}

/// What a completed `bumpfee` reports - Core's `{txid, origfee, fee}`, the fees in satoshis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcBumped {
    pub txid: String,
    pub orig_fee_sat: u64,
    pub fee_sat: u64,
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
    /// Whether the seed is passphrase-encrypted - and therefore locked, since nothing can
    /// unlock a Bitcoin wallet (see [`BtcActorConfig::encrypted`]).
    pub encrypted: bool,
    /// The recorded birthday height (`keys.toml`): where a rebuild scans from, and on kyoto
    /// what the recovery floor and anchor resolution are derived from.
    pub birthday: u32,
    /// The birthday as a date (unix seconds of a UTC midnight), when one is known: the
    /// operator's `--birthday` date when `init` kept one for the first sync to refine (see
    /// `WalletStore::birthday_time`), else the day the shipped per-day table places the
    /// birthday height in (mainnet; at or before the block's own time). `None` off-table.
    /// Display only - the actor's own resolution target stays the operator's date alone.
    pub birthday_time: Option<u64>,
    /// The configured chain source, as the log lines name it (`bitcoind host:port`, or the
    /// kyoto peer set); `None` for an offline wallet with no upstream. `/status` reports it
    /// as `server`, beside the Zcash wallets' zebra endpoint.
    pub upstream: Option<String>,
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

    /// Build, sign, broadcast, and record a send paying `recipients`. Returns the txid and
    /// where the fee rate came from.
    pub async fn send(
        &self,
        recipients: Vec<(String, u64)>,
        options: BtcSendOptions,
    ) -> Result<BtcSent, RpcError> {
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

    /// Mark an unconfirmed wallet transaction (and its unconfirmed descendants) abandoned
    /// (`abandontransaction`): its inputs are released for the next send. See
    /// `BtcActor::do_abandon` for the eligibility rules.
    pub async fn abandon_transaction(&self, txid: Txid) -> Result<(), RpcError> {
        self.dispatch(|reply| BtcCommand::AbandonTransaction { txid, reply })
            .await
    }

    /// Replace an unconfirmed own send with a higher-fee version of itself (`bumpfee`). See
    /// `BtcActor::do_bump_fee` for the eligibility rules and the fee arithmetic.
    pub async fn bump_fee(
        &self,
        txid: Txid,
        options: BtcBumpOptions,
    ) -> Result<BtcBumped, RpcError> {
        self.dispatch(|reply| BtcCommand::BumpFee {
            txid,
            options,
            reply,
        })
        .await
    }

    /// Core's `listtransactions` window: the newest `count` visible entries after skipping
    /// `skip` newer ones, oldest first. Each returned record carries only the entries
    /// (`details`) inside the window, so a boundary that falls inside one transaction's
    /// fan-out is honoured exactly as Core does.
    pub async fn list_transactions(
        &self,
        count: usize,
        skip: usize,
    ) -> Result<Vec<BtcTxRecord>, RpcError> {
        self.dispatch(|reply| BtcCommand::ListTransactions { count, skip, reply })
            .await
    }

    /// Every wallet transaction, counted without being built.
    pub async fn tx_count(&self) -> Result<usize, RpcError> {
        self.dispatch(|reply| BtcCommand::TxCount { reply }).await
    }

    pub async fn get_transaction(&self, txid: String) -> Result<Option<BtcTxRecord>, RpcError> {
        self.dispatch(|reply| BtcCommand::GetTransaction { txid, reply })
            .await
    }

    /// `listsinceblock`'s data: the transactions above `since` and the next cursor.
    pub async fn since_block(
        &self,
        since: Option<BlockHash>,
        target_confirmations: u32,
    ) -> Result<BtcSinceBlock, RpcError> {
        self.dispatch(|reply| BtcCommand::SinceBlock {
            since,
            target_confirmations,
            reply,
        })
        .await
    }

    /// `estimatesmartfee`'s data: a fee rate in sat/kvB for `target` blocks and the source
    /// that answered, or `None` when the backend has no estimate. `conservative` is Core's
    /// `estimate_mode` (bitcoind honors it; the kyoto fee chain has no modes).
    pub async fn estimate_fee(
        &self,
        target: u16,
        conservative: Option<bool>,
    ) -> Result<Option<(u64, String)>, RpcError> {
        self.dispatch(|reply| BtcCommand::EstimateFee {
            target,
            conservative,
            reply,
        })
        .await
    }

    /// Every revealed receiving address with the outputs that paid it, ascending by index.
    pub async fn received_by_address(&self) -> Result<Vec<BtcAddressReceipts>, RpcError> {
        self.dispatch(|reply| BtcCommand::ReceivedByAddress { reply })
            .await
    }

    /// The wallet's public descriptors (receiving, then change).
    pub async fn descriptors(&self) -> Result<Vec<BtcDescriptor>, RpcError> {
        self.dispatch(|reply| BtcCommand::Descriptors { reply })
            .await
    }

    /// The actor's latest published sync status.
    pub fn status(&self) -> BtcSyncStatus {
        self.status_rx.borrow().clone()
    }

    /// Whether the wallet's actor task is still servicing commands. False once the task has
    /// ended (a panic, or shutdown): every command then fails with "wallet actor is not
    /// running", and `/readyz` reports the wallet `actor_down` rather than ready on a
    /// status snapshot the dead task can no longer refresh.
    pub fn actor_alive(&self) -> bool {
        !self.cmd_tx.is_closed()
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

/// BDK's default lookahead (25): what a wallet runs on when `[wallets.<name>] lookahead` is
/// unset. Re-exported so the config layer and tests name one number.
pub const DEFAULT_LOOKAHEAD: u32 = bdk_wallet::chain::keychain_txout::DEFAULT_LOOKAHEAD;

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
    /// Whether that seed is passphrase-encrypted (`keys.toml`'s `encryption` marker). The
    /// engine has no `walletpassphrase`, so such a wallet is locked for its whole life -
    /// reported as encrypted and locked rather than as an ordinary spender that happens to
    /// fail every send. `init --encrypt` refuses to create one now; this covers wallets
    /// encrypted before that refusal existed.
    pub encrypted: bool,
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
    /// The opt-in mempool feed (`[mempool]`), run only on the kyoto backend - bitcoind has
    /// a mempool of its own, and `config check` warns when the section is set on one.
    pub mempool: crate::config::MempoolConfig,
    /// The height the block scan starts from on an empty chain state (recorded by init).
    pub birthday: u32,
    /// The operator's `--birthday` date when init could only record it approximately (the
    /// kyoto date path - see `WalletStore::birthday_time`); the kyoto first sync resolves
    /// it to a real `(height, hash)` anchor. `None` everywhere else.
    pub birthday_time: Option<u64>,
    /// How far past the last revealed index of each keychain the wallet derives and
    /// watches (`[wallets.<name>] lookahead`): BDK's lookahead, which on a restore or an
    /// xpub import is the BIP-44 gap limit - the longest run of never-paid addresses the
    /// scan can bridge, since a payment found at an unrevealed index reveals up to it and
    /// pushes the window on. Not persisted; applied at every load.
    pub lookahead: u32,
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
        encrypted,
        imported_keys,
        endpoint,
        fees,
        mempool,
        birthday,
        birthday_time,
        lookahead,
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
    let mut load = Wallet::load()
        .check_network(keys::network(network))
        .lookahead(lookahead);
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
                .network(keys.network)
                .lookahead(lookahead),
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
    let (status_tx, status_rx) = watch::channel(status_of(
        &wallet,
        BtcConnState::Down,
        birthday_anchor.as_ref(),
        None,
        None,
    ));
    let span = info_span!("wallet", name = %name);
    let upstream = endpoint.as_ref().map(BtcEndpoint::describe);
    let wallet_never_synced = wallet.latest_checkpoint().height() == 0;
    let actor = BtcActor {
        wallet,
        persister,
        seed,
        watch_only: !has_seed,
        network,
        endpoint,
        fees,
        mempool,
        feed: None,
        feed_status: None,
        feed_held: HashSet::new(),
        feed_pending_evictions: HashMap::new(),
        feed_ready: false,
        // A wallet that has never applied a block (its chain is the genesis checkpoint
        // alone) knows none of its own history: an empty datadir, or one started over.
        mempool_rebuild: if wallet_never_synced {
            MempoolRebuild::AwaitingTip
        } else {
            MempoolRebuild::NotNeeded
        },
        birthday,
        birthday_time,
        birthday_anchor,
        birthday_block_time: None,
        conn: None,
        at_tip: false,
        backoff: Backoff::new(reconnect_base, reconnect_max),
        reconnect_base,
        reconnect_max,
        next_attempt: Instant::now(),
        reconnect_warned: false,
        header_sync_failures: 0,
        rebroadcast_tip: None,
        node_mempool: None,
        rebroadcast_rejections: HashMap::new(),
        lookahead,
        unconfirmed_since: HashMap::new(),
        fee_samples: Default::default(),
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
            encrypted,
            birthday,
            birthday_time: birthday_time
                .or_else(|| crate::btc::birthdays::day_start_for_height(network, birthday)),
            upstream,
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
        /// The block emitter - `None` while it is out on a thread running its mempool pass
        /// (`mempool` then holds the channel it comes back on).
        emitter: Option<BitcoindEmitter>,
        mempool: Option<std::sync::mpsc::Receiver<MempoolPass>>,
    },
    Kyoto(KyotoConn),
}

type BitcoindEmitter = Emitter<Arc<bdk_bitcoind_rpc::bitcoincore_rpc::Client>>;

/// What the mempool-pass thread hands back: the emitter it borrowed and the pass's result.
type MempoolPass = (
    BitcoindEmitter,
    Result<bdk_bitcoind_rpc::MempoolEvent, bdk_bitcoind_rpc::bitcoincore_rpc::Error>,
);

/// How a bounded block pull ended.
enum BlockPull {
    /// Blocks applied; the node has more.
    More(usize),
    /// Blocks applied and the emitter ran dry: the tip is reached.
    AtTip(usize),
    Failed(anyhow::Error),
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
    /// See [`BtcActorConfig::mempool`].
    mempool: crate::config::MempoolConfig,
    /// The running mempool feed, started once at actor start when the wallet is kyoto-backed
    /// and `[mempool]` names a source with an endpoint for this network; lives for the
    /// actor's life (its own task redials with backoff), independent of `conn`.
    feed: Option<MempoolFeed>,
    /// The feed's reported state, `Some` exactly when [`Self::feed`] is.
    feed_status: Option<MempoolFeedStatus>,
    /// Wallet transactions the feed has reported as held by the server's mempool and not
    /// since removed: the rebroadcast pass skips them, the way the bitcoind pass skips what
    /// that node holds. Pruned to the unconfirmed set on every delta.
    feed_held: HashSet<Txid>,
    /// `removed` txids the wallet held unconfirmed when the feed reported them gone, with
    /// when. **Deferred** to the next sync pass that reaches tip: the server also drops a
    /// transaction from its mempool when a block mines it, and the filter scan can trail
    /// that by a minute, so evicting on arrival would briefly un-count a payment that has in
    /// fact just confirmed. Settled by [`Self::settle_feed_evictions`]: still unconfirmed
    /// once the scan has caught up means genuinely evicted.
    feed_pending_evictions: HashMap<Txid, u64>,
    /// Whether the mempool view is established: a snapshot-taking feed has applied a
    /// snapshot that counts (see [`MempoolRebuild`]) since it last connected. Kyoto sends
    /// wait on it ([`Self::send_gate`]); cleared whenever the feed (re)connects or drops.
    feed_ready: bool,
    /// Where a wallet that started with no history stands in rebuilding its view of its own
    /// unconfirmed transactions.
    mempool_rebuild: MempoolRebuild,
    birthday: u32,
    /// See [`BtcActorConfig::birthday_time`].
    birthday_time: Option<u64>,
    /// The recorded (or just-resolved) birthday anchor a kyoto first scan starts from -
    /// loaded from the engine database at spawn, updated in place when the resolution task
    /// delivers one mid-sync.
    birthday_anchor: Option<(u32, bdk_wallet::bitcoin::BlockHash)>,
    /// See [`BtcSyncStatus::birthday_block_time`]; resolved once per actor life, on the
    /// first connection that can answer, and kept across reconnects.
    birthday_block_time: Option<u64>,
    conn: Option<Conn>,
    /// Whether the last sync pass reached the upstream's tip (drives Ready vs Syncing).
    at_tip: bool,
    backoff: Backoff,
    /// The backoff bounds, kept for the feed's own task (it redials independently).
    reconnect_base: Duration,
    reconnect_max: Duration,
    next_attempt: Instant,
    /// WARN once per outage, then DEBUG (the logging convention for reconnect streams).
    reconnect_warned: bool,
    /// Kyoto only: header-sync failures since the last delivered update. Each one deepens
    /// the next redial's restart checkpoint (`kyoto::resync_depth`), so a fork the light
    /// client cannot reorg onto from 7 blocks back is retried from further down the
    /// wallet's own chain rather than from the same stale tip forever.
    header_sync_failures: u32,
    /// The wallet tip the last rebroadcast pass ran at; `None` until the first pass after a
    /// (re)connect. A pass runs when a sync pass reaches a tip that differs, which makes
    /// the cadence one attempt per new block plus one per reconnect.
    rebroadcast_tip: Option<BlockHash>,
    /// What the upstream's mempool held at the last pass that reached tip: `Some` over
    /// bitcoind (the emitter's mempool pass fetches the whole set), `None` over kyoto, which
    /// has no mempool view. The three-way answer the rebroadcast pass filters on - a
    /// transaction known to be held is skipped, an unknown one is resubmitted.
    node_mempool: Option<HashSet<Txid>>,
    /// The last rejection each unconfirmed send drew from bitcoind, for WARN-once logging
    /// (a repeat of the same verdict drops to DEBUG). Pruned to the current candidate set.
    rebroadcast_rejections: HashMap<Txid, String>,
    /// See [`BtcActorConfig::lookahead`]; needed again by [`BtcActor::reload_wallet`].
    lookahead: u32,
    /// Kyoto only: the wallet tip at which each once-confirmed received transaction was
    /// first seen unconfirmed again - a reorg unwound it - for [`BtcActor::expire_reorged_receives`].
    unconfirmed_since: HashMap<Txid, u32>,
    /// Kyoto only: the peer fee tier's block samples (`crate::btc::fee_samples`), kept
    /// across reconnects; each connection's sampler and estimate refresh them against its
    /// own header chain.
    fee_samples: crate::btc::kyoto::SharedFeeSamples,
    sync_interval: Duration,
    status_tx: watch::Sender<BtcSyncStatus>,
    cmd_rx: mpsc::Receiver<BtcCommand>,
    shutdown: watch::Receiver<bool>,
}

fn status_of(
    wallet: &Wallet,
    conn_state: BtcConnState,
    birthday_anchor: Option<&(u32, bdk_wallet::bitcoin::BlockHash)>,
    birthday_block_time: Option<u64>,
    mempool_feed: Option<&MempoolFeedStatus>,
) -> BtcSyncStatus {
    let cp = wallet.latest_checkpoint();
    BtcSyncStatus {
        conn_state,
        synced_height: cp.height(),
        synced_hash: cp.hash().to_string(),
        birthday_anchor: birthday_anchor.map(|(height, hash)| (*height, hash.to_string())),
        birthday_block_time,
        mempool_feed: mempool_feed.cloned(),
    }
}

/// The feed's next event, or never when there is no feed - so the actor's idle `select!`
/// can name the branch unconditionally (its guard skips it when `feed` is `None`).
async fn feed_next(feed: &mut Option<MempoolFeed>) -> Option<FeedEvent> {
    match feed {
        Some(feed) => feed.next().await,
        None => std::future::pending().await,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Confirmations of a transaction anchored at `height` against the wallet's own tip
/// (0 for an unconfirmed one), Core's counting: the anchoring block is the first.
fn confirmations_at(wallet: &Wallet, height: Option<u32>) -> u64 {
    match height {
        Some(h) => u64::from(wallet.latest_checkpoint().height().saturating_sub(h)) + 1,
        None => 0,
    }
}

/// Where a transaction sorts in the history and how many visible entries it fans out
/// to - the cheap half of [`Self::tx_entry`], computed for every transaction so the
/// window can be chosen before anything is serialized.
fn tx_position(wallet: &Wallet, wtx: &bdk_wallet::WalletTx<'_>) -> (u64, u64, usize) {
    let (sort_key, time, height) = match &wtx.chain_position {
        bdk_wallet::chain::ChainPosition::Confirmed { anchor, .. } => (
            u64::from(anchor.block_id.height),
            anchor.confirmation_time,
            Some(anchor.block_id.height),
        ),
        bdk_wallet::chain::ChainPosition::Unconfirmed {
            first_seen,
            last_seen,
        } => {
            // Unconfirmed sorts after every mined transaction.
            (u64::MAX, first_seen.or(*last_seen).unwrap_or(0), None)
        }
    };
    let tx = &wtx.tx_node.tx;
    let funded = wallet.sent_and_received(tx).0 > Amount::ZERO;
    let coinbase = tx.is_coinbase().then(|| confirmations_at(wallet, height));
    let entries = tx
        .output
        .iter()
        .map(|txout| {
            let keychain = wallet
                .derivation_of_spk(txout.script_pubkey.clone())
                .map(|(keychain, _)| keychain);
            categories(funded, keychain, coinbase).len()
        })
        .sum();
    (sort_key, time, entries)
}

/// Core's accounting (and the Zcash side's `tx_entries`) for one output: on a funded
/// transaction, a foreign output is a `send`, an own external-keychain output is a
/// self-payment (send+receive pair), and change (internal keychain) is hidden. On a
/// transaction the wallet did not fund, only the wallet's own outputs appear, as
/// `receive`. A coinbase reward (`coinbase` = its confirmations) is Core's
/// `orphan`/`immature`/`generate` by depth instead, on every own output - so an immature
/// reward no longer reads as a `receive` the balance does not count.
fn categories(
    funded: bool,
    keychain: Option<KeychainKind>,
    coinbase: Option<u64>,
) -> &'static [&'static str] {
    match (funded, keychain, coinbase) {
        (_, Some(_), Some(confirmations)) => coinbase_category(confirmations),
        (_, None, Some(_)) => &[],
        (true, None, None) => &["send"],
        (true, Some(KeychainKind::External), None) => &["send", "receive"],
        (true, Some(KeychainKind::Internal), None) => &[],
        (false, Some(_), None) => &["receive"],
        (false, None, None) => &[],
    }
}

/// Core's category for a coinbase output at `confirmations`: `orphan` while it is not in
/// the chain, `immature` until maturity (`GetBlocksToMaturity` > 0, i.e. through
/// `COINBASE_MATURITY` confirmations - the same bound `coinbase_immature` applies), then
/// `generate`.
fn coinbase_category(confirmations: u64) -> &'static [&'static str] {
    if confirmations == 0 {
        &["orphan"]
    } else if confirmations <= u64::from(COINBASE_MATURITY) {
        &["immature"]
    } else {
        &["generate"]
    }
}

/// One wallet transaction as a wire-shaped record with its per-output fan-out. The
/// fee needs every input resolved and the hex a full serialization, so this is built
/// only for the transactions a caller will actually see: the `listtransactions` window,
/// or the one `gettransaction` names (`with_hex`, the only reader of the hex).
fn tx_entry(wallet: &Wallet, wtx: &bdk_wallet::WalletTx<'_>, with_hex: bool) -> BtcTxRecord {
    let network = wallet.network();
    let tx = &wtx.tx_node.tx;
    let (sent, _received) = wallet.sent_and_received(tx);
    let funded = sent > Amount::ZERO;
    let fee = if funded {
        wallet.calculate_fee(tx).ok().map(|a| a.to_sat())
    } else {
        None
    };
    let (height, blockhash, time) = match &wtx.chain_position {
        bdk_wallet::chain::ChainPosition::Confirmed { anchor, .. } => (
            Some(anchor.block_id.height),
            Some(anchor.block_id.hash.to_string()),
            anchor.confirmation_time,
        ),
        bdk_wallet::chain::ChainPosition::Unconfirmed {
            first_seen,
            last_seen,
        } => (None, None, first_seen.or(*last_seen).unwrap_or(0)),
    };
    let coinbase = tx.is_coinbase().then(|| confirmations_at(wallet, height));
    let mut details = Vec::new();
    for (vout, txout) in tx.output.iter().enumerate() {
        let vout = u32::try_from(vout).unwrap_or(u32::MAX);
        let keychain = wallet
            .derivation_of_spk(txout.script_pubkey.clone())
            .map(|(keychain, _)| keychain);
        let address = Address::from_script(&txout.script_pubkey, network)
            .ok()
            .map(|a| a.to_string());
        let value = i64::try_from(txout.value.to_sat()).unwrap_or(i64::MAX);
        for category in categories(funded, keychain, coinbase) {
            details.push(BtcTxDetail {
                category,
                amount_sat: if *category == "send" { -value } else { value },
                address: address.clone(),
                vout,
            });
        }
    }
    BtcTxRecord {
        txid: wtx.tx_node.txid.to_string(),
        fee_sat: fee,
        confirmations: confirmations_at(wallet, height),
        height,
        blockhash,
        time,
        explicit_rbf: tx.is_explicitly_rbf(),
        hex: with_hex.then(|| bdk_wallet::bitcoin::consensus::encode::serialize_hex(tx.as_ref())),
        details,
    }
}

/// Core's `listtransactions` window over the visible entries, oldest first (confirmed
/// by height, then unconfirmed by first-seen): skip `skip` entries from the newest end,
/// then up to `count`. Every transaction is positioned (cheap), only those inside the
/// window are built, and a record at either boundary carries just the entries within
/// it - so the cost of a page is the page, not the history.
fn tx_history(wallet: &Wallet, count: usize, skip: usize) -> Vec<BtcTxRecord> {
    let mut positioned: Vec<(u64, u64, usize, Txid)> = wallet
        .transactions()
        .map(|wtx| {
            let (sort_key, time, entries) = tx_position(wallet, &wtx);
            (sort_key, time, entries, wtx.tx_node.txid)
        })
        .collect();
    positioned.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let total: usize = positioned.iter().map(|p| p.2).sum();
    let upper = total.saturating_sub(skip);
    let lower = upper.saturating_sub(count);
    if lower == upper {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut offset = 0usize;
    for (_, _, entries, txid) in positioned {
        let start = offset;
        offset += entries;
        if entries == 0 || offset <= lower {
            continue;
        }
        if start >= upper {
            break;
        }
        let Some(wtx) = wallet.get_tx(txid) else {
            continue;
        };
        let mut record = tx_entry(wallet, &wtx, false);
        // Trim to the window where a boundary falls inside this transaction's fan-out.
        let keep_from = lower.saturating_sub(start);
        let keep_to = (upper - start).min(record.details.len());
        record.details = record.details.drain(keep_from..keep_to).collect();
        out.push(record);
    }
    out
}

/// Where a wallet that started with no history stands in rebuilding its view of its own
/// unconfirmed transactions (see `BtcActor::maybe_request_mempool_rebuild`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MempoolRebuild {
    /// The wallet had history at start (its own sends are on disk), or the rebuild is done.
    NotNeeded,
    /// Started with none; waiting to reach tip before asking.
    AwaitingTip,
    /// Asked the feed for a full snapshot at this instant.
    Requested(Instant),
}

/// Warn, once at start, that a kyoto wallet has no feed that can rebuild its view of its own
/// unconfirmed transactions - louder when it started with no history, which is exactly when
/// that view is missing. Sends are not blocked: the operator chose to run without one.
fn warn_no_mempool_view(rebuild: MempoolRebuild) {
    if rebuild == MempoolRebuild::AwaitingTip {
        warn!(
            "this kyoto wallet started with no history and has no snapshot-taking mempool \
             feed ([mempool] sources = [\"p2p\"] with p2p_snapshot = true): its own \
             unconfirmed transactions from before are unknown until they confirm, and a send \
             before then may double-spend them"
        );
    } else {
        info!(
            "no snapshot-taking mempool feed for this kyoto wallet; after a restart from an \
             empty datadir, sends could not see its own earlier unconfirmed transactions"
        );
    }
}

/// `listsinceblock` over the wallet's own chain: every transaction mined strictly above
/// `since` - or everything, when `since` is absent or names a block the wallet's chain does
/// not hold (reorged away, or below its checkpoints: the Zcash handler's rule, so a poller
/// feeding back a stale cursor re-reads rather than wedging) - plus every unconfirmed one,
/// oldest first; and the cursor block `target_confirmations` deep.
fn since_block(
    wallet: &Wallet,
    since: Option<BlockHash>,
    target_confirmations: u32,
) -> BtcSinceBlock {
    let tip = wallet.local_chain().tip();
    let since_height = since.and_then(|hash| {
        tip.iter()
            .find(|cp| cp.hash() == hash)
            .map(|cp| cp.height())
    });
    let mut positioned: Vec<(u64, u64, Txid)> = wallet
        .transactions()
        .filter(|wtx| match &wtx.chain_position {
            bdk_wallet::chain::ChainPosition::Confirmed { anchor, .. } => {
                since_height.is_none_or(|since| anchor.block_id.height > since)
            }
            bdk_wallet::chain::ChainPosition::Unconfirmed { .. } => true,
        })
        .map(|wtx| {
            let (sort_key, time, _) = tx_position(wallet, &wtx);
            (sort_key, time, wtx.tx_node.txid)
        })
        .collect();
    positioned.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let records = positioned
        .into_iter()
        .filter_map(|(_, _, txid)| wallet.get_tx(txid))
        .map(|wtx| tx_entry(wallet, &wtx, false))
        .filter(|record| !record.details.is_empty())
        .collect();
    let depth = target_confirmations.saturating_sub(1);
    let lastblock = tip
        .floor_at(tip.height().saturating_sub(depth))
        .or_else(|| tip.iter().last())
        .map(|cp| cp.hash().to_string())
        .unwrap_or_else(|| "0".repeat(64));
    BtcSinceBlock { records, lastblock }
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
        self.start_feed();
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
            // The feed's deltas first: cheap, and a 0-conf sighting should not wait behind
            // a sync pass.
            let fed = self.feed_step();
            let worked = if self.endpoint.is_some() {
                self.sync_step()
            } else {
                false
            } || fed;
            self.maybe_request_mempool_rebuild();
            // At a tip the wallet has not rebroadcast at: resubmit what the network may
            // have dropped. `at_tip` only survives a successful pass (an error drops the
            // connection and clears it), and the hash comparison makes a quiet tip free.
            if self.at_tip
                && self.conn.is_some()
                && self.rebroadcast_tip != Some(self.wallet.latest_checkpoint().hash())
            {
                self.rebroadcast_pass().await;
            }
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
                // A feed event wakes the loop like a command does, so a 0-conf sighting is
                // applied when it arrives rather than at the next scheduled pass.
                event = feed_next(&mut self.feed), if self.feed.is_some() => match event {
                    Some(event) => {
                        self.on_feed_event(event);
                    }
                    None => {
                        warn!("the mempool feed task ended; the feed is off until restart");
                        self.feed = None;
                        if let Some(status) = &mut self.feed_status {
                            status.connected = false;
                        }
                    }
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
        // The birthday block's time, for display, when a kyoto connect resolved it this pass.
        let mut resolved_time: Option<u64> = None;
        // What the emitter's mempool pass reported evicted this pass, retired below once the
        // connection is no longer borrowed (retirement may rebuild it).
        let mut evicted_now: Vec<(Txid, u64)> = Vec::new();
        // Kyoto: the redial that just failed header sync had already restarted from the
        // recorded birthday anchor, so the anchor is on a dead branch.
        let mut anchor_suspect = false;
        let result = match conn {
            // Bitcoind, with its mempool pass in flight on a thread: collect the result if
            // it has landed, otherwise there is nothing to pull this pass (the emitter is
            // out with the thread). The pass is one `getrawtransaction` per node-mempool
            // txid the emitter has not seen - the whole mempool after every (re)connect and
            // `reload_wallet`, minutes on mainnet - and running it here under
            // `block_in_place` held every command the actor serves for that long.
            Conn::Bitcoind {
                emitter,
                mempool: mempool @ Some(_),
                ..
            } => match mempool.as_ref().map(|rx| rx.try_recv()) {
                Some(Ok((returned, event))) => {
                    *emitter = Some(returned);
                    *mempool = None;
                    match event {
                        Ok(event) => {
                            reached_tip = true;
                            // The pass fetched the node's whole mempool: keep its txid set,
                            // so the rebroadcast pass skips what the node already holds.
                            self.node_mempool = Some(
                                event
                                    .update
                                    .iter()
                                    .map(|(tx, _)| tx.compute_txid())
                                    .collect(),
                            );
                            let sightings = self.drop_superseded_sightings(event.update);
                            self.wallet.apply_unconfirmed_txs(sightings);
                            // The emitter diffs the node's whole mempool, so nearly every
                            // departure it reports is a foreign transaction the wallet never
                            // held. Retiring those wrote one tombstone row apiece (244
                            // against 38 wallet transactions on a testnet4 wallet, unbounded
                            // on mainnet, all read back on every load) and counted as work,
                            // skipping the sync interval for as long as the mempool churned.
                            // Only a transaction in the wallet's own graph can be retired.
                            //
                            // And never one the wallet funded. The emitter is seeded with
                            // the wallet's unconfirmed set at connect, so a send whose
                            // broadcast got no verdict - committed, never in the node's
                            // mempool - reads as "evicted" on the first pass after the
                            // redial, and retiring it released its inputs to the next send:
                            // a double-spend of a transaction that may be on the network.
                            // Core's wallet keeps an own transaction that left the mempool
                            // (unconfirmed, inputs spent) until a conflict confirms or the
                            // operator abandons it; here the rebroadcast pass resubmits it,
                            // its verdicts retire a confirmed conflict, and
                            // `abandontransaction` is the operator's release.
                            evicted_now = event
                                .evicted
                                .into_iter()
                                .filter(|(txid, _)| {
                                    self.wallet.tx_graph().get_tx(*txid).is_some_and(|tx| {
                                        self.wallet.sent_and_received(&tx).0 == Amount::ZERO
                                    })
                                })
                                .collect();
                            Ok(0)
                        }
                        Err(e) => Err(anyhow::anyhow!("mempool: {e}")),
                    }
                }
                Some(Err(std::sync::mpsc::TryRecvError::Empty)) => Ok(0),
                Some(Err(std::sync::mpsc::TryRecvError::Disconnected)) | None => Err(
                    anyhow::anyhow!("the mempool pass ended without handing the emitter back"),
                ),
            },
            // Bitcoind: a bounded blocking pull. The emitter's RPC calls block, so relocate
            // the worker's other tasks for the duration, exactly as the Zcash scan does.
            Conn::Bitcoind {
                emitter, mempool, ..
            } => {
                let Some(mut pull) = emitter.take() else {
                    return false;
                };
                let outcome = tokio::task::block_in_place(|| {
                    let mut applied = 0usize;
                    while applied < SYNC_BLOCKS_PER_PASS {
                        match pull.next_block() {
                            Ok(Some(event)) => {
                                let height = event.block_height();
                                if let Err(e) = self.wallet.apply_block_connected_to(
                                    &event.block,
                                    height,
                                    event.connected_to(),
                                ) {
                                    return BlockPull::Failed(anyhow::anyhow!(
                                        "apply block {height}: {e}"
                                    ));
                                }
                                applied += 1;
                            }
                            Ok(None) => return BlockPull::AtTip(applied),
                            Err(e) => return BlockPull::Failed(anyhow::anyhow!("next_block: {e}")),
                        }
                    }
                    BlockPull::More(applied)
                });
                match outcome {
                    BlockPull::More(applied) => {
                        *emitter = Some(pull);
                        Ok(applied)
                    }
                    BlockPull::Failed(e) => {
                        *emitter = Some(pull);
                        Err(e)
                    }
                    // Caught up: one mempool pass gives 0-conf visibility and eviction
                    // handling (evictions are only reported once the emitter is at tip).
                    // It goes out to a thread with the emitter (see the arm above); the
                    // tip counts as reached when its result lands, so `at_tip`, the
                    // rebroadcast pass and readiness keep their old ordering behind it.
                    BlockPull::AtTip(applied) => {
                        let (tx, rx) = std::sync::mpsc::sync_channel(1);
                        let spawned = std::thread::Builder::new()
                            .name("zecd-btc-mempool".into())
                            .spawn(move || {
                                let event = pull.mempool();
                                // A closed receiver means the connection was dropped
                                // meanwhile; the emitter dies with this thread.
                                let _ = tx.send((pull, event));
                            });
                        match spawned {
                            Ok(_) => {
                                *mempool = Some(rx);
                                Ok(applied)
                            }
                            Err(e) => Err(anyhow::anyhow!("spawn the mempool pass: {e}")),
                        }
                    }
                }
            }
            // Kyoto: a non-blocking poll of the bridge channel. An `Update` is a whole
            // sync-to-tip rather than one block, so its arrival *is* the tip signal - and
            // there is no mempool pass to follow it, the divergence `kyoto`'s module doc
            // records. `applied` counts updates, only to decide whether the pass did work.
            Conn::Kyoto(kyoto) => match kyoto.try_next_update() {
                Ok(Some(update)) => {
                    reached_tip = true;
                    self.header_sync_failures = 0;
                    // A delivered update is the light client's first proof of life - the
                    // point its reconnect backoff resets (see `connect`).
                    self.backoff.reset();
                    // No mempool view on this backend: the rebroadcast pass cannot filter.
                    self.node_mempool = None;
                    resolved_time = kyoto.try_resolved_birthday_time();
                    let tip_before = {
                        let cp = self.wallet.latest_checkpoint();
                        (cp.height(), cp.hash())
                    };
                    let applied = self
                        .wallet
                        .apply_update(update)
                        .map_err(|e| anyhow::anyhow!("apply kyoto update: {e}"))
                        .map(|()| 1usize);
                    // A reorg: the block the wallet had at its old tip height is not the
                    // one it has there now. The light client may have followed a fork below
                    // the recorded birthday anchor by itself, with no redial ever failing
                    // from it, so the anchor is verified against the node's headers rather
                    // than the wallet's chain (see `KyotoConn::re_resolve_anchor`); the
                    // answer lands on a later idle poll and is recorded only if it moved.
                    let reorged = tip_before.0 > 0
                        && self
                            .wallet
                            .latest_checkpoint()
                            .get(tip_before.0)
                            .is_none_or(|cp| cp.hash() != tip_before.1);
                    if reorged && self.birthday_anchor.is_some() {
                        let birthday = crate::btc::kyoto::KyotoBirthday {
                            height: self.birthday,
                            time: self.birthday_time,
                            anchor: self.birthday_anchor,
                            block_time: self.birthday_block_time,
                        };
                        kyoto.re_resolve_anchor(self.network, &birthday);
                        info!(
                            old_tip = tip_before.0,
                            "reorg applied over kyoto; verifying the birthday anchor against \
                             the new headers"
                        );
                    }
                    applied
                }
                // No update yet: the client is still finding peers or downloading filters.
                // The idle poll is also where a resolved birthday anchor arrives (it can
                // only exist before the first update - `scan_plan` launches the resolution
                // only for a checkpoint-less wallet, and an applied update writes the
                // checkpoint that retires the whole mechanism).
                Ok(None) => {
                    resolved_anchor = kyoto.try_resolved_anchor();
                    resolved_time = kyoto.try_resolved_birthday_time();
                    Ok(0)
                }
                // The node parked itself on a rejected header batch: count it, so the
                // redial below (via `drop_conn`) restarts from an older checkpoint.
                Err(e @ KyotoFailure::HeaderSync { .. }) => {
                    let before = self.header_sync_failures;
                    self.header_sync_failures = before.saturating_add(1);
                    if let (Some(anchor), KyotoFailure::HeaderSync { tip, .. }) =
                        (self.birthday_anchor, &e)
                    {
                        // The anchor is implicated only when the header tree never grew
                        // past it. A batch rejected at a tip well above the anchor - a
                        // testnet4 fork at the tip, during a first scan that has been
                        // running from the anchor for hours - says nothing about the
                        // anchor's block, which the tree already built on; clearing it
                        // there restarted the whole scan from the floor.
                        let tree_past_anchor = tip.is_some_and(|tip| tip > anchor.0);
                        anchor_suspect = !tree_past_anchor
                            && crate::btc::kyoto::resync_bottomed_at_anchor(
                                &self.wallet.latest_checkpoint(),
                                before,
                                anchor,
                            );
                    }
                    Err(anyhow::anyhow!(e))
                }
                Err(e) => Err(anyhow::anyhow!(e)),
            },
        };
        if let Some(time) = resolved_time {
            self.birthday_block_time = Some(time);
        }
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
            self.status_tx.send_replace(status_of(
                &self.wallet,
                BtcConnState::Syncing,
                self.birthday_anchor.as_ref(),
                self.birthday_block_time,
                self.feed_status.as_ref(),
            ));
            return true;
        }
        // A synced wallet's resolution - no anchor on record (a wallet from before the
        // per-wallet anchor, or one whose anchor was cleared), or a verification after a
        // reorg - is recorded and nothing restarts: the scan is past the birthday, and the
        // anchor only steers where a future resync bottoms out. A verification that comes
        // back with the anchor already on record changes nothing.
        if let Some((height, hash)) = resolved_anchor {
            if self.birthday_anchor == Some((height, hash)) {
                debug!(
                    anchor = height,
                    "birthday anchor verified against the headers"
                );
            } else {
                let moved = self.birthday_anchor.is_some();
                if let Err(e) = self
                    .persister
                    .save_birthday_anchor(height, &hash.to_string())
                {
                    warn!("failed to record the resolved birthday anchor: {e:#}");
                }
                self.birthday_anchor = Some((height, hash));
                if moved {
                    warn!(
                        anchor = height,
                        "the recorded birthday anchor's block left the chain in a reorg; \
                         re-recorded against the new chain"
                    );
                } else {
                    info!(
                        anchor = height,
                        "birthday anchor recorded against the synced headers (the wallet is \
                         past it; no restart)"
                    );
                }
            }
        }
        let worked = match result {
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
                let status = status_of(
                    &self.wallet,
                    state,
                    self.birthday_anchor.as_ref(),
                    self.birthday_block_time,
                    self.feed_status.as_ref(),
                );
                if applied > 0 {
                    debug!(
                        blocks = applied,
                        height = status.synced_height,
                        unconfirmed = self
                            .wallet
                            .transactions()
                            .filter(|t| !t.chain_position.is_confirmed())
                            .count(),
                        graph_txs = self.wallet.tx_graph().full_txs().count(),
                        anchored = self.wallet.tx_graph().all_anchors().len(),
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
                if anchor_suspect {
                    if let Some((height, _)) = self.birthday_anchor.take() {
                        // A reorg deeper than the anchor: every redial from it fails, and
                        // the escalation has nowhere lower to go. Forget it - the next
                        // redial starts from the network's recovery floor, and the
                        // resolution task records a fresh anchor against the new chain.
                        warn!(
                            anchor = height,
                            "header sync keeps failing from the recorded birthday anchor: \
                             its block has left the chain; clearing it and restarting from \
                             the recovery floor"
                        );
                        if let Err(e) = self.persister.clear_birthday_anchor() {
                            warn!("failed to clear the birthday anchor: {e:#}");
                        }
                    }
                }
                self.drop_conn();
                return true;
            }
        };
        if !evicted_now.is_empty() {
            // The node dropped them from its mempool: BDK records the eviction, and the
            // tombstone plus reload retires any that had reorged out of a block (which the
            // eviction alone never does - `Persister::retire_tx`).
            self.retire(evicted_now, "mempool eviction");
            return true;
        }
        if reached_tip
            && matches!(self.conn, Some(Conn::Kyoto(_)))
            && self.expire_reorged_receives()
        {
            return true;
        }
        if reached_tip && self.settle_feed_evictions() {
            return true;
        }
        worked
    }

    /// Start the mempool feed, if this wallet is to run one: kyoto-backed, and `[mempool]`
    /// names a source with an endpoint for this network. Once per actor life.
    fn start_feed(&mut self) {
        let Some(BtcEndpoint::Kyoto(kyoto)) = &self.endpoint else {
            if !self.mempool.sources.is_empty() {
                info!(
                    "[mempool] sources is set but this wallet is not kyoto-backed (a bitcoind \
                     upstream has a mempool of its own); the feed is not started here"
                );
            }
            return;
        };
        let Some(target) = feed_target(
            &self.mempool,
            self.network,
            kyoto.peers(),
            kyoto.receive_window(),
        ) else {
            if !self.mempool.sources.is_empty() {
                warn!(
                    network = self.network.name(),
                    "[mempool] names no source that can run for this wallet (p2p needs a \
                     kyoto:// trusted peer or p2p_peer; mempool_space needs a public instance \
                     for the network or mempool_space_url); running without the 0-conf feed"
                );
            }
            warn_no_mempool_view(self.mempool_rebuild);
            return;
        };
        let source = target.source();
        let endpoint = target.describe();
        info!(
            source = source.as_str(),
            %endpoint,
            "starting the mempool feed (0-conf receives)"
        );
        let snapshots = matches!(
            target,
            crate::btc::mempool_feed::FeedTarget::Peer {
                snapshot: Some(_),
                ..
            }
        );
        if !snapshots {
            warn_no_mempool_view(self.mempool_rebuild);
        }
        self.feed_status = Some(MempoolFeedStatus {
            source: source.as_str(),
            endpoint,
            connected: false,
            last_delta: None,
            deltas: 0,
            matched: 0,
            dropped: 0,
            snapshot_applied: snapshots.then_some(false),
        });
        self.feed = Some(MempoolFeed::start(
            target,
            self.reconnect_base,
            self.reconnect_max,
        ));
        self.publish_status();
    }

    /// Drain every queued feed event. Returns whether a delta changed the wallet.
    fn feed_step(&mut self) -> bool {
        let mut worked = false;
        while let Some(event) = self.feed.as_mut().and_then(MempoolFeed::try_next) {
            worked |= self.on_feed_event(event);
        }
        worked
    }

    /// One feed event. Returns whether it changed the wallet.
    fn on_feed_event(&mut self, event: FeedEvent) -> bool {
        match event {
            FeedEvent::Connected => {
                // A new connection's view starts over: sends wait for its first snapshot
                // (requested at connect) rather than trusting the last link's.
                self.set_feed_ready(false);
                if let Some(status) = &mut self.feed_status {
                    status.connected = true;
                }
                self.publish_status();
                false
            }
            FeedEvent::Disconnected(_) => {
                self.set_feed_ready(false);
                if let Some(status) = &mut self.feed_status {
                    status.connected = false;
                }
                self.publish_status();
                false
            }
            FeedEvent::Delta(delta) => self.apply_feed_delta(delta),
            FeedEvent::Snapshot(snapshot) => self.apply_feed_snapshot(&snapshot),
        }
    }

    /// The P2P source's view of the node's whole mempool. Two things follow from it. A
    /// wallet transaction the feed had reported held and that the node no longer lists is
    /// queued for eviction (deferred like a websocket `removed`, for the same reason: a
    /// mined transaction leaves the mempool too). And every unconfirmed wallet transaction
    /// the node does list is known held - the wallet's own sends included, which the
    /// rebroadcast pass then stops re-announcing. Never changes the wallet directly.
    fn apply_feed_snapshot(&mut self, snapshot: &crate::btc::mempool_feed::FeedSnapshot) -> bool {
        let held = &snapshot.held;
        // Whether this snapshot establishes the mempool view. For a wallet that started
        // with no history only a full one requested once it had reached tip does: the
        // transactions of an earlier snapshot were matched against a wallet that did not
        // yet hold the outputs they spend, so its own earlier sends went unrecognized.
        let counts = match self.mempool_rebuild {
            MempoolRebuild::NotNeeded => true,
            MempoolRebuild::AwaitingTip => false,
            MempoolRebuild::Requested(at) => snapshot.full && snapshot.requested_at >= at,
        };
        if counts {
            if self.mempool_rebuild != MempoolRebuild::NotNeeded {
                info!(
                    held = held.len(),
                    "mempool view rebuilt: every transaction the node holds was matched \
                     against the synced wallet; sends are open"
                );
                self.mempool_rebuild = MempoolRebuild::NotNeeded;
            }
            self.set_feed_ready(true);
        }
        let now = unix_now();
        if let Some(status) = &mut self.feed_status {
            status.last_delta = Some(now);
            status.deltas += 1;
        }
        let gone: Vec<Txid> = self
            .feed_held
            .iter()
            .filter(|txid| !held.contains(*txid))
            .copied()
            .collect();
        for txid in gone {
            self.feed_held.remove(&txid);
            if self
                .wallet
                .get_tx(txid)
                .is_some_and(|wtx| !wtx.chain_position.is_confirmed())
            {
                debug!(%txid, "mempool feed: the node no longer holds a wallet transaction");
                self.feed_pending_evictions.entry(txid).or_insert(now);
            }
        }
        let unconfirmed: Vec<Txid> = self
            .wallet
            .transactions()
            .filter(|wtx| !wtx.chain_position.is_confirmed())
            .map(|wtx| wtx.tx_node.txid)
            .filter(|txid| held.contains(txid))
            .collect();
        for txid in unconfirmed {
            self.feed_held.insert(txid);
            self.feed_pending_evictions.remove(&txid);
        }
        self.publish_status();
        false
    }

    /// Apply one delta: every added transaction that touches the wallet is recorded
    /// unconfirmed (the 0-conf sighting), and every removed txid the wallet holds
    /// unconfirmed is queued for eviction at the next scan tip (see
    /// [`Self::feed_pending_evictions`] for why not now). Returns whether the wallet changed.
    fn apply_feed_delta(&mut self, delta: FeedDelta) -> bool {
        let now = unix_now();
        if let Some(status) = &mut self.feed_status {
            status.last_delta = Some(now);
            status.deltas += 1;
            status.dropped += delta.dropped as u64;
        }
        let matched: Vec<(Arc<Transaction>, u64)> = delta
            .added
            .iter()
            .filter(|feed_tx| crate::btc::mempool_feed::wallet_relevant(&self.wallet, feed_tx))
            .map(|feed_tx| (feed_tx.tx.clone(), feed_tx.seen))
            .collect();
        let matched = self.drop_superseded_sightings(matched);
        for txid in &delta.removed {
            // Gone from the server's mempool: no longer known held (so the rebroadcast
            // pass may resubmit it if it turns out to still be valid), and a candidate for
            // eviction if the scan does not confirm it.
            self.feed_held.remove(txid);
            if self
                .wallet
                .get_tx(*txid)
                .is_some_and(|wtx| !wtx.chain_position.is_confirmed())
            {
                self.feed_pending_evictions.entry(*txid).or_insert(now);
            }
        }
        if matched.is_empty() {
            // Nothing for the wallet, but the delta itself is news: `last_delta` is what an
            // operator reads to tell a live feed from a silently dead one.
            self.publish_status();
            return false;
        }
        for (tx, _) in &matched {
            let txid = tx.compute_txid();
            info!(%txid, "mempool feed: a wallet transaction is in the mempool");
            self.feed_held.insert(txid);
            // Seen again means not evicted after all - the feed re-added it.
            self.feed_pending_evictions.remove(&txid);
        }
        if let Some(status) = &mut self.feed_status {
            status.matched += matched.len() as u64;
        }
        self.wallet.apply_unconfirmed_txs(matched);
        self.persist("mempool feed");
        self.feed_held.retain(|txid| {
            self.wallet
                .get_tx(*txid)
                .is_some_and(|wtx| !wtx.chain_position.is_confirmed())
        });
        self.publish_status();
        true
    }

    /// Settle the deferred feed evictions against a wallet that has just reached tip: a
    /// transaction the scan anchored meanwhile was mined, not evicted, and is forgotten
    /// here; one still unconfirmed is evicted for real. Returns whether anything was.
    fn settle_feed_evictions(&mut self) -> bool {
        if self.feed_pending_evictions.is_empty() {
            return false;
        }
        let pending = std::mem::take(&mut self.feed_pending_evictions);
        let evicted: Vec<(Txid, u64)> = pending
            .into_iter()
            .filter(|(txid, _)| {
                self.wallet
                    .get_tx(*txid)
                    .is_some_and(|wtx| !wtx.chain_position.is_confirmed())
            })
            .collect();
        if evicted.is_empty() {
            return false;
        }
        self.retire(evicted, "mempool feed eviction");
        true
    }

    /// Record whether the mempool view is established, mirrored into the feed status.
    fn set_feed_ready(&mut self, ready: bool) {
        self.feed_ready = ready;
        if let Some(status) = &mut self.feed_status {
            if status.snapshot_applied.is_some() {
                status.snapshot_applied = Some(ready);
            }
        }
    }

    /// Once a wallet that started with no history reaches tip, ask the feed for a full
    /// snapshot: every transaction the node holds, fetched again and matched against a
    /// wallet that now holds its outputs - which is what makes its own unconfirmed sends
    /// from before the restart visible. Once per actor life.
    fn maybe_request_mempool_rebuild(&mut self) {
        if self.mempool_rebuild != MempoolRebuild::AwaitingTip || !self.at_tip {
            return;
        }
        let Some(feed) = &self.feed else {
            return;
        };
        // Only a snapshot-taking feed can refetch.
        if self
            .feed_status
            .as_ref()
            .and_then(|s| s.snapshot_applied)
            .is_none()
        {
            return;
        }
        info!(
            "the wallet reached tip from an empty history; refetching the node's whole \
             mempool to find its own unconfirmed transactions (sends wait for it)"
        );
        self.mempool_rebuild = MempoolRebuild::Requested(Instant::now());
        feed.request_full_snapshot();
    }

    /// Whether a send may proceed. Over kyoto with a snapshot-taking feed, not until the
    /// mempool view is established: a wallet rebuilt from an empty datadir does not know
    /// its own unconfirmed sends from before (a light client sees them only once mined),
    /// so their inputs look unspent and the next send could double-spend them.
    fn send_gate(&self) -> Result<(), RpcError> {
        if !matches!(self.conn, Some(Conn::Kyoto(_))) {
            return Ok(());
        }
        let snapshots = self
            .feed_status
            .as_ref()
            .is_some_and(|s| s.snapshot_applied.is_some());
        if snapshots && !self.feed_ready {
            return Err(RpcError::new(
                codes::RPC_WALLET_ERROR,
                "mempool view not yet established (waiting for the P2P feed's mempool \
                 snapshot, so this wallet's own unconfirmed transactions are known before it \
                 spends); retry shortly",
            ));
        }
        Ok(())
    }

    fn publish_status(&self) {
        let state = if self.conn.is_none() {
            BtcConnState::Down
        } else if self.at_tip {
            BtcConnState::Ready
        } else {
            BtcConnState::Syncing
        };
        self.status_tx.send_replace(status_of(
            &self.wallet,
            state,
            self.birthday_anchor.as_ref(),
            self.birthday_block_time,
            self.feed_status.as_ref(),
        ));
    }

    /// Retire evicted transactions for good where BDK will not: write the tombstone beside
    /// the eviction, and when any of them holds an anchor - a once-confirmed transaction the
    /// eviction cannot demote - reload the wallet so the load-time strip takes effect now
    /// rather than at the next daemon start. See `Persister::retire_tx`.
    fn retire(&mut self, evicted: Vec<(Txid, u64)>, why: &str) {
        let mut anchored = false;
        for (txid, _) in &evicted {
            if self.wallet.tx_graph().all_anchors().contains_key(txid) {
                anchored = true;
            }
            self.unconfirmed_since.remove(txid);
            self.rebroadcast_rejections.remove(txid);
            self.feed_held.remove(txid);
            self.feed_pending_evictions.remove(txid);
        }
        self.wallet.apply_evicted_txs(evicted.iter().copied());
        // The tombstones and the eviction they accompany land in ONE SQLite transaction. Written
        // separately, a tombstone that outlived a failed eviction write reloaded the transaction
        // with its anchors stripped but no `last_evicted` - canonical and unconfirmed, wrong on
        // both sides. A failed write keeps the eviction staged in memory for the next persist,
        // writes no tombstone, and skips the reload (which would only read the old log back).
        let wallet = &mut self.wallet;
        let written = self.persister.transactionally(|persister| {
            for (txid, at) in &evicted {
                persister.retire_tx(txid, *at)?;
            }
            wallet
                .persist(persister)
                .map(|_| ())
                .map_err(|e| anyhow::anyhow!("persist the eviction: {e:#}"))
        });
        match &written {
            Ok(()) => info!(
                retired = evicted.len(),
                anchored,
                "retired evicted transactions ({why}){}",
                if anchored {
                    "; reloading the wallet to drop their stale anchors"
                } else {
                    ""
                }
            ),
            Err(e) => error!(
                retired = evicted.len(),
                "failed to record the retirement ({why}); the eviction stays staged for the next \
                 persist and no tombstone was written: {e:#}"
            ),
        }
        if anchored && written.is_ok() {
            self.reload_wallet(why);
        }
        let state = if self.at_tip {
            BtcConnState::Ready
        } else {
            BtcConnState::Syncing
        };
        self.status_tx.send_replace(status_of(
            &self.wallet,
            state,
            self.birthday_anchor.as_ref(),
            self.birthday_block_time,
            self.feed_status.as_ref(),
        ));
    }

    /// Reload the wallet from the persister - the only way an edit the changeset log makes
    /// on the way in (`Persister::initialize`) reaches the live wallet - and rebuild the
    /// connection, whose emitter or light client is positioned on the old one. A deliberate
    /// restart, not an outage: no backoff, the next pass redials at once from the wallet's
    /// own checkpoint, which the reload does not move.
    fn reload_wallet(&mut self, why: &str) {
        let keys = match AccountKeys::from_wallet(&self.wallet) {
            Ok(keys) => keys,
            Err(e) => {
                warn!("cannot reload the wallet ({why}): {e:#}");
                return;
            }
        };
        let load = Wallet::load()
            .check_network(keys::network(self.network))
            .lookahead(self.lookahead)
            .descriptor(
                KeychainKind::External,
                Some(keys.descriptor(KeychainKind::External)),
            )
            .descriptor(
                KeychainKind::Internal,
                Some(keys.descriptor(KeychainKind::Internal)),
            );
        match PersistedWallet::load(&mut self.persister, load) {
            Ok(Some(wallet)) => {
                self.wallet = wallet;
                info!(
                    height = self.wallet.latest_checkpoint().height(),
                    "reloaded the wallet ({why}); the retired transactions are gone"
                );
            }
            Ok(None) => warn!("cannot reload the wallet ({why}): the database is empty"),
            Err(e) => {
                warn!("cannot reload the wallet ({why}): {e:#}");
                return;
            }
        }
        self.conn = None;
        self.at_tip = false;
        self.rebroadcast_tip = None;
        self.node_mempool = None;
    }

    /// The kyoto backend's only evidence that a reorged-out receive was double-spent is
    /// time. There is no mempool and no verdict there, and the conflict - spending the
    /// sender's outputs, paying someone else - touches no wallet script, so the light
    /// client never fetches its block. But a receive is only ever unconfirmed on this
    /// backend because a reorg unwound it (nothing else puts an unconfirmed foreign
    /// transaction in the wallet), a valid one is re-mined within a block or two, and a
    /// conflicted one never is. So a once-confirmed received transaction still unconfirmed
    /// after the network's reorg depth of tips (`kyoto::anchor_reorg_margin`) is retired.
    /// The wallet's own sends are exempt: their inputs are wallet scripts, so a conflict
    /// spending them is filter-visible and BDK retires them directly; and a transaction the
    /// wallet only ever saw unconfirmed (one it broadcast itself) has no anchor and is left
    /// to BDK's own seen-versus-evicted accounting. Returns whether anything was retired.
    fn expire_reorged_receives(&mut self) -> bool {
        let tip = self.tip_height();
        let margin = crate::btc::kyoto::anchor_reorg_margin(self.network);
        let anchors = self.wallet.tx_graph().all_anchors();
        let mut current = HashSet::new();
        let mut expired = Vec::new();
        for wtx in self.wallet.transactions() {
            if wtx.chain_position.is_confirmed() {
                continue;
            }
            let txid = wtx.tx_node.txid;
            if !anchors.contains_key(&txid)
                || self.wallet.sent_and_received(&wtx.tx_node.tx).0 > Amount::ZERO
            {
                continue;
            }
            current.insert(txid);
            let since = *self.unconfirmed_since.entry(txid).or_insert(tip);
            if tip.saturating_sub(since) >= margin {
                expired.push((txid, unix_now()));
            }
        }
        self.unconfirmed_since
            .retain(|txid, _| current.contains(txid));
        if expired.is_empty() {
            return false;
        }
        for (txid, _) in &expired {
            warn!(
                %txid,
                margin,
                "a received transaction reorged out of its block and stayed unconfirmed for \
                 the reorg depth: retiring it as double-spent (it returns if it confirms)"
            );
        }
        self.retire(expired, "reorg-expired receive");
        true
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
                    Conn::Bitcoind {
                        rpc,
                        emitter: Some(emitter),
                        mempool: None,
                    }
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
                    block_time: self.birthday_block_time,
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
                // The birthday block's time, for display, from a node that can answer it
                // directly - once, on the first connect that succeeds (a birthday above the
                // node's tip, or a failed call, simply leaves it for the next connect).
                if self.birthday_block_time.is_none() {
                    if let Conn::Bitcoind { rpc, .. } = &conn {
                        let birthday = self.birthday;
                        self.birthday_block_time =
                            tokio::task::block_in_place(|| rpc.block_time_blocking(birthday)).ok();
                    }
                }
                self.conn = Some(conn);
                self.at_tip = false;
                // A fresh connection rebroadcasts once at its first tip, whatever the hash.
                self.rebroadcast_tip = None;
                self.node_mempool = None;
                // A bitcoind dial that succeeded is proof the node is back, so the backoff
                // resets here. A kyoto "dial" cannot fail - it only starts the node task -
                // so resetting it here made every redial take the attempt-0 delay: a node
                // that kept failing was rebuilt, headers re-synced, once a second. Its
                // backoff resets on the first update the client delivers instead.
                if matches!(self.conn, Some(Conn::Bitcoind { .. })) {
                    self.backoff.reset();
                }
                self.reconnect_warned = false;
                self.status_tx.send_replace(status_of(
                    &self.wallet,
                    BtcConnState::Syncing,
                    self.birthday_anchor.as_ref(),
                    self.birthday_block_time,
                    self.feed_status.as_ref(),
                ));
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
                self.status_tx.send_replace(status_of(
                    &self.wallet,
                    BtcConnState::Down,
                    self.birthday_anchor.as_ref(),
                    self.birthday_block_time,
                    self.feed_status.as_ref(),
                ));
                false
            }
        }
    }

    fn drop_conn(&mut self) {
        self.conn = None;
        self.at_tip = false;
        self.rebroadcast_tip = None;
        self.node_mempool = None;
        self.next_attempt = Instant::now() + self.backoff.next_delay();
        self.status_tx.send_replace(status_of(
            &self.wallet,
            BtcConnState::Down,
            self.birthday_anchor.as_ref(),
            self.birthday_block_time,
            self.feed_status.as_ref(),
        ));
    }

    /// Resubmit the wallet's unconfirmed transactions to the upstream. See the module doc for
    /// when it runs; this is what it does.
    ///
    /// The candidate set is every canonical unconfirmed wallet transaction (the wallet's
    /// own sends and payments it received, exactly Bitcoin Core's
    /// `ResubmitWalletTransactions`) minus what the upstream's mempool is known to hold
    /// ([`Self::node_mempool`]).
    /// Received payments are included on purpose: a signed transaction that was broadcast is
    /// public data anyone may relay, the sender has no veto short of double-spending it (in
    /// which case the resubmission is rejected), and a recipient whose sender's wallet never
    /// rebroadcasts would otherwise wait on them forever. Parents go before children, so an
    /// own chain of unconfirmed sends is accepted in order rather than the child failing on
    /// a missing input the next line would have supplied.
    ///
    /// Over bitcoind each verdict is classified ([`classify_rejection`]): an accepted
    /// resubmission and an already-mined one need nothing more; a confirmed conflict (the
    /// inputs are gone from the UTXO set, and no input waits on an unconfirmed wallet
    /// parent) is terminal, so the transaction is marked **evicted** - a send's inputs free
    /// up, a receive stops counting toward the unconfirmed balance, and neither lingers as
    /// a transaction that can never confirm (an eviction is not final in BDK's model: a
    /// later block or mempool sighting re-canonicalizes it); everything else, `non-final`
    /// (the reorg case: the locktime height arrives on its own) and fee policy (mempool
    /// minimums move) included, simply retries at the next tip. A transport failure drops
    /// the connection like any other. Over kyoto there are no verdicts at all, so each
    /// transaction is re-announced on a detached task: a peer that already holds it never
    /// asks, the wait is bounded by the light client's broadcast timeout, and neither may
    /// hold the actor.
    async fn rebroadcast_pass(&mut self) {
        let tip = self.wallet.latest_checkpoint();
        self.rebroadcast_tip = Some(tip.hash());
        let candidates = self.rebroadcast_candidates();
        let live: HashSet<Txid> = candidates.iter().map(|c| c.txid).collect();
        self.rebroadcast_rejections
            .retain(|txid, _| live.contains(txid));
        if candidates.is_empty() {
            return;
        }
        debug!(
            candidates = candidates.len(),
            height = tip.height(),
            "rebroadcasting unconfirmed transactions"
        );
        let mut evicted = Vec::new();
        for candidate in candidates {
            let RebroadcastCandidate { tx, txid, parents } = candidate;
            match self.conn.as_ref() {
                Some(Conn::Bitcoind { rpc, .. }) => {
                    let outcome = tokio::task::block_in_place(|| rpc.broadcast_blocking(&tx));
                    match outcome {
                        Ok(_) => {
                            self.rebroadcast_rejections.remove(&txid);
                            info!(%txid, height = tip.height(), "re-broadcast an unconfirmed transaction");
                        }
                        Err(BroadcastError::Rejected { code, message }) => {
                            match classify_rejection(code, &message, parents) {
                                RebroadcastVerdict::AlreadyInChain => {
                                    debug!(%txid, "rebroadcast: already in the chain (the block is on its way)");
                                }
                                RebroadcastVerdict::ConfirmedConflict => {
                                    warn!(
                                        %txid,
                                        "rebroadcast: the inputs were spent by a confirmed \
                                         conflict ({code}: {message}); marking the transaction \
                                         evicted"
                                    );
                                    evicted.push((txid, unix_now()));
                                }
                                RebroadcastVerdict::Retry => {
                                    let verdict = format!("{code}: {message}");
                                    // `non-final` is the expected reorg shape and clears by
                                    // itself; anything else WARNs once, then repeats at DEBUG.
                                    let repeat =
                                        self.rebroadcast_rejections.get(&txid) == Some(&verdict);
                                    if repeat || message.contains("non-final") {
                                        debug!(%txid, "rebroadcast rejected, retrying at the next tip ({verdict})");
                                    } else {
                                        warn!(%txid, "rebroadcast rejected, retrying at the next tip ({verdict})");
                                    }
                                    self.rebroadcast_rejections.insert(txid, verdict);
                                }
                            }
                        }
                        Err(BroadcastError::Transport(e)) => {
                            warn!("rebroadcast transport error (reconnecting with backoff): {e:#}");
                            self.drop_conn();
                            return;
                        }
                    }
                }
                Some(Conn::Kyoto(kyoto)) => {
                    let requester = kyoto.requester();
                    let span = tracing::Span::current();
                    tokio::spawn(
                        async move {
                            match crate::btc::kyoto::announce(requester, &tx).await {
                                Ok(true) => info!(%txid, "re-broadcast an unconfirmed transaction (a peer requested it)"),
                                Ok(false) => debug!(%txid, "re-announced an unconfirmed transaction; no peer asked for it"),
                                Err(e) => warn!(%txid, "re-announcing an unconfirmed transaction failed: {e:#}"),
                            }
                        }
                        .instrument(span),
                    );
                }
                None => return,
            }
        }
        if !evicted.is_empty() {
            self.retire(evicted, "rebroadcast eviction");
        }
    }

    /// The rebroadcast pass's input, parents first. See [`Self::rebroadcast_pass`].
    fn rebroadcast_candidates(&self) -> Vec<RebroadcastCandidate> {
        let unconfirmed: HashMap<Txid, Arc<Transaction>> = self
            .wallet
            .transactions()
            .filter(|wtx| !wtx.chain_position.is_confirmed())
            .map(|wtx| (wtx.tx_node.txid, wtx.tx_node.tx.clone()))
            .collect();
        let candidates = unconfirmed
            .iter()
            .filter(|(txid, _)| {
                !self
                    .node_mempool
                    .as_ref()
                    .is_some_and(|mempool| mempool.contains(*txid))
                    // Over kyoto the feed is the one mempool view there is: a transaction
                    // it reports held has propagated, so re-announcing it is noise.
                    && !self.feed_held.contains(*txid)
            })
            .map(|(txid, tx)| {
                let parents = classify_parents(
                    tx,
                    |parent| unconfirmed.contains_key(&parent),
                    |parent| self.wallet.get_tx(parent).is_some(),
                );
                RebroadcastCandidate {
                    tx: tx.clone(),
                    txid: *txid,
                    parents,
                }
            })
            .collect();
        order_parents_first(candidates)
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

    fn is_coinbase(&self, txid: Txid) -> bool {
        self.wallet
            .get_tx(txid)
            .is_some_and(|wtx| wtx.tx_node.tx.is_coinbase())
    }

    /// The transactions the wallet funded - Core's trust rule for an unconfirmed output
    /// (trusted iff created by the wallet's own transaction: change, a self-payment),
    /// never by a foreign sender's unconfirmed payment. Behind both `getbalance`'s
    /// `trusted_pending` and `listunspent`'s `safe`, so the two cannot disagree.
    fn funded_txids(&self) -> HashSet<Txid> {
        self.wallet
            .transactions()
            .filter(|wtx| self.wallet.sent_and_received(&wtx.tx_node.tx).0 > Amount::ZERO)
            .map(|wtx| wtx.tx_node.txid)
            .collect()
    }

    /// Drop mempool sightings of transactions the wallet holds as *replaced by one of its own
    /// unconfirmed sends* - an original that `bumpfee` superseded. A sighting sets
    /// `last_seen`, and BDK keeps whichever of two conflicting unconfirmed transactions was
    /// seen later (a tie broken by txid), so a sighting that reached the wallet after the
    /// bump - the P2P feed relaying the original's announcement, a bitcoind mempool pass
    /// captured before the bump - would make the original canonical again, in the same
    /// second as often as not. The wallet's own replacement is authoritative until a block
    /// says otherwise: if the network kept the original instead, its confirmation settles it.
    fn drop_superseded_sightings(
        &self,
        sightings: Vec<(Arc<Transaction>, u64)>,
    ) -> Vec<(Arc<Transaction>, u64)> {
        sightings
            .into_iter()
            .filter(|(tx, _)| {
                let drop = replaced_by_own_send(&self.wallet, tx);
                if drop {
                    debug!(
                        txid = %tx.compute_txid(),
                        "ignoring a mempool sighting of a transaction the wallet replaced"
                    );
                }
                !drop
            })
            .collect()
    }

    /// The coinbase outputs Core still calls immature (`coinbase_immature`), withheld from
    /// coin selection: BDK's own rule would admit a reward one block before Core does, and
    /// `listunspent` already hides it for that block.
    fn immature_coinbase_outpoints(&self) -> Vec<OutPoint> {
        self.wallet
            .list_unspent()
            .filter(|output| self.coinbase_immature(output))
            .map(|output| output.outpoint)
            .collect()
    }

    /// The wallet's unconfirmed transactions for ancestor-aware funding: fees, sizes,
    /// parents and Core's trust rule (see `crate::btc::ancestors`).
    fn ancestry(&self) -> Ancestry {
        wallet_ancestry(&self.wallet, &self.funded_txids())
    }

    /// Unconfirmed outputs a send may not select: those whose ancestry the wallet cannot
    /// price - a foreign sender's unconfirmed payment, first of all (Core's untrusted).
    fn unpriceable_unconfirmed(&self, ancestry: &Ancestry) -> Vec<OutPoint> {
        self.wallet
            .list_unspent()
            .filter(|output| !output.chain_position.is_confirmed())
            .filter(|output| !ancestry.is_spendable(&output.outpoint.txid))
            .map(|output| output.outpoint)
            .collect()
    }

    /// Core's coinbase maturity rule, for the read path: a reward is immature until its
    /// block has `COINBASE_MATURITY` blocks on top of it - `GetBlocksToMaturity` is
    /// `COINBASE_MATURITY + 1 - depth`, so mature at 101 confirmations, immature at 100.
    /// BDK's `balance()` (`bdk_chain::ChainPosition::is_confirmed_and_spendable`) calls it
    /// mature one block earlier (a spend could enter the *next* block), so the actor
    /// applies this rule itself on `listunspent` and the balance split rather than
    /// inheriting a `getbalances` that disagrees with Core by a block. An unconfirmed
    /// coinbase cannot exist.
    fn coinbase_immature(&self, output: &bdk_wallet::LocalOutput) -> bool {
        let bdk_wallet::chain::ChainPosition::Confirmed { anchor, .. } = &output.chain_position
        else {
            return false;
        };
        let depth = self.tip_height().saturating_sub(anchor.block_id.height) + 1;
        depth <= COINBASE_MATURITY && self.is_coinbase(output.outpoint.txid)
    }

    fn confirmations(&self, anchor_height: Option<u32>) -> u64 {
        confirmations_at(&self.wallet, anchor_height)
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
                // Every bucket on Core's rules, from the same unspent set `listunspent`
                // reports: confirmed/immature split on Core's maturity (`coinbase_immature`
                // - BDK calls a coinbase mature one block earlier), and trusted/untrusted
                // on Core's trust rule (`funded_txids`: an unconfirmed output is trusted
                // iff the wallet funded its transaction), which is also what
                // `listunspent.safe` says. BDK's own `balance()` trusts the internal
                // keychain instead, so an unconfirmed self-payment to an external address
                // read `safe: true` in one and `untrusted_pending` in the other.
                let own = self.funded_txids();
                let mut balance = BtcBalance::default();
                for output in self.wallet.list_unspent() {
                    let value = output.txout.value.to_sat();
                    let bucket = match &output.chain_position {
                        bdk_wallet::chain::ChainPosition::Confirmed { .. } => {
                            if self.coinbase_immature(&output) {
                                &mut balance.immature
                            } else {
                                &mut balance.confirmed
                            }
                        }
                        bdk_wallet::chain::ChainPosition::Unconfirmed { .. } => {
                            if own.contains(&output.outpoint.txid) {
                                &mut balance.trusted_pending
                            } else {
                                &mut balance.untrusted_pending
                            }
                        }
                    };
                    *bucket += value;
                }
                let _ = reply.send(Ok(balance));
            }
            BtcCommand::ListUnspent { reply } => {
                let network = self.wallet.network();
                let tip = self.tip_height();
                let own_txids = self.funded_txids();
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
                        let immature = self.coinbase_immature(&output);
                        let coinbase = self.is_coinbase(output.outpoint.txid);
                        let desc = inferred_descriptor(
                            &self.wallet,
                            output.keychain,
                            output.derivation_index,
                        );
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
                            coinbase,
                            immature,
                            script_pubkey: output.txout.script_pubkey.to_hex_string(),
                            desc,
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
                        let derivation = self.wallet.derivation_of_spk(spk.clone());
                        Ok(BtcAddressInfo {
                            is_mine: self.wallet.is_mine(spk),
                            derivation: derivation.map(|(keychain, index)| {
                                (keychain == KeychainKind::Internal, index)
                            }),
                            key: derivation.and_then(|(keychain, index)| {
                                key_origin(&self.wallet, keychain, index)
                            }),
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
            BtcCommand::AbandonTransaction { txid, reply } => {
                let _ = reply.send(self.do_abandon(txid));
            }
            BtcCommand::BumpFee {
                txid,
                options,
                reply,
            } => {
                let result = self.do_bump_fee(txid, options).await;
                let _ = reply.send(result);
            }
            BtcCommand::ListTransactions { count, skip, reply } => {
                let _ = reply.send(Ok(tx_history(&self.wallet, count, skip)));
            }
            BtcCommand::SinceBlock {
                since,
                target_confirmations,
                reply,
            } => {
                let _ = reply.send(Ok(since_block(&self.wallet, since, target_confirmations)));
            }
            BtcCommand::EstimateFee {
                target,
                conservative,
                reply,
            } => {
                let result = self
                    .estimate_fee_at(target, conservative)
                    .await
                    .map(|answer| {
                        answer.map(|(rate, source)| {
                            (rate.to_sat_per_kwu().saturating_mul(4), source.to_string())
                        })
                    })
                    .map_err(|e| RpcError::new(codes::RPC_WALLET_ERROR, format!("{e:#}")));
                let _ = reply.send(result);
            }
            BtcCommand::TxCount { reply } => {
                let _ = reply.send(Ok(self.wallet.transactions().count()));
            }
            BtcCommand::GetTransaction { txid, reply } => {
                let result = match Txid::from_str(&txid) {
                    Ok(txid) => Ok(self
                        .wallet
                        .get_tx(txid)
                        .map(|wtx| tx_entry(&self.wallet, &wtx, true))),
                    Err(_) => Err(RpcError::invalid_address_or_key(format!(
                        "Invalid txid: {txid}"
                    ))),
                };
                let _ = reply.send(result);
            }
            BtcCommand::ReceivedByAddress { reply } => {
                let _ = reply.send(Ok(self.received_by_address()));
            }
            BtcCommand::Descriptors { reply } => {
                let _ = reply.send(Ok(self.descriptors()));
            }
        }
    }

    /// Every revealed external address, with every output in the wallet's transaction graph
    /// that pays it. Revealed-but-never-paid addresses come back with no receipts, which is
    /// what lets `listreceivedbyaddress include_empty` enumerate the issued set; nothing
    /// beyond the last revealed index is listed, since the wallet never handed those out.
    fn received_by_address(&self) -> Vec<BtcAddressReceipts> {
        let network = self.wallet.network();
        let mut by_index: std::collections::BTreeMap<u32, BtcAddressReceipts> = self
            .wallet
            .spk_index()
            .revealed_keychain_spks(KeychainKind::External)
            .filter_map(|(index, spk)| {
                let address = Address::from_script(&spk, network).ok()?.to_string();
                Some((
                    index,
                    BtcAddressReceipts {
                        address,
                        index,
                        receipts: Vec::new(),
                    },
                ))
            })
            .collect();
        for wtx in self.wallet.transactions() {
            let txid = wtx.tx_node.txid.to_string();
            let confirmations = match &wtx.chain_position {
                bdk_wallet::chain::ChainPosition::Confirmed { anchor, .. } => {
                    self.confirmations(Some(anchor.block_id.height))
                }
                bdk_wallet::chain::ChainPosition::Unconfirmed { .. } => 0,
            };
            // Core's maturity rule (`coinbase_immature`): under COINBASE_MATURITY + 1 deep.
            let immature =
                wtx.tx_node.tx.is_coinbase() && confirmations <= u64::from(COINBASE_MATURITY);
            for txout in &wtx.tx_node.tx.output {
                let Some((KeychainKind::External, index)) =
                    self.wallet.derivation_of_spk(txout.script_pubkey.clone())
                else {
                    continue;
                };
                if let Some(entry) = by_index.get_mut(&index) {
                    entry.receipts.push(BtcReceipt {
                        txid: txid.clone(),
                        amount_sat: txout.value.to_sat(),
                        confirmations,
                        immature,
                    });
                }
            }
        }
        by_index.into_values().collect()
    }

    /// The two public descriptors the wallet scans with - receiving first, change second -
    /// each with where its keychain stands. Public material only: the database holds no
    /// private descriptor, and the seed-derived signer exists only for the duration of a
    /// send.
    fn descriptors(&self) -> Vec<BtcDescriptor> {
        let lookahead = self.wallet.spk_index().lookahead();
        [KeychainKind::External, KeychainKind::Internal]
            .into_iter()
            .map(|keychain| {
                let next_index = self.wallet.next_derivation_index(keychain);
                BtcDescriptor {
                    desc: self.wallet.public_descriptor(keychain).to_string(),
                    internal: keychain == KeychainKind::Internal,
                    next_index,
                    range_end: next_index.saturating_add(lookahead),
                    timestamp: self
                        .birthday_block_time
                        .or(self.birthday_time)
                        .unwrap_or_else(|| {
                            crate::btc::birthdays::day_start_for_height(self.network, self.birthday)
                                .unwrap_or(0)
                        }),
                }
            })
            .collect()
    }

    /// The upstream's fee rate for a send, in whichever dialect is connected.
    ///
    /// Bitcoind answers with `estimatesmartfee`. Kyoto has no such call and answers with a
    /// far coarser signal - see [`crate::btc::kyoto::estimate_fee_rate`] - so the mainnet fallback
    /// rule below is doing more work on that backend than on this one.
    /// The answer carries the name of the source that gave it, for `fee_reason`.
    async fn upstream_fee_rate(
        &mut self,
    ) -> anyhow::Result<Option<(bdk_wallet::bitcoin::FeeRate, &'static str)>> {
        self.estimate_fee_at(FEE_TARGET_BLOCKS, None).await
    }

    /// [`Self::upstream_fee_rate`] at a caller-chosen target - `estimatesmartfee`'s path.
    /// Bitcoind estimates at `target` in the requested mode. Over kyoto the HTTP oracles
    /// answer one horizon, so they ignore both; the peer tier honors the target (one
    /// quantile per target, `crate::btc::fee_samples`) and has no notion of a mode.
    async fn estimate_fee_at(
        &mut self,
        target: u16,
        conservative: Option<bool>,
    ) -> anyhow::Result<Option<(bdk_wallet::bitcoin::FeeRate, &'static str)>> {
        let requester = match self.conn.as_mut() {
            // Blocking and synchronous: answer here, before any await exists.
            Some(Conn::Bitcoind { rpc, .. }) => {
                let network = self.network;
                return tokio::task::block_in_place(|| {
                    let rate = rpc.estimate_fee_rate_blocking(target, conservative)?;
                    // A test network's estimator can be broken while staying under the
                    // sanity ceiling (testnet4: 361 sat/vB at every target). A
                    // flat curve there is "no estimate", which the send's test-network
                    // fallback prices at 1 sat/vB. Mainnet keeps its answer: a missing
                    // estimate there refuses the send, and its estimator is sane.
                    if rate.is_none() || network == BitcoinNetwork::Main {
                        return Ok(rate);
                    }
                    use crate::btc::chain::{
                        fee_curve_is_flat, FEE_CURVE_LONG_TARGET, FEE_CURVE_SHORT_TARGET,
                    };
                    let short =
                        rpc.estimate_fee_rate_blocking(FEE_CURVE_SHORT_TARGET, conservative)?;
                    let long =
                        rpc.estimate_fee_rate_blocking(FEE_CURVE_LONG_TARGET, conservative)?;
                    if let (Some(short), Some(long)) = (short, long) {
                        if fee_curve_is_flat(short, long) {
                            warn!(
                                short_sat_per_kwu = short.to_sat_per_kwu(),
                                long_sat_per_kwu = long.to_sat_per_kwu(),
                                "the node's fee estimate is flat across targets, which a \
                                 working estimator never is above the floor; treating it as \
                                 no estimate on this test network"
                            );
                            return Ok(None);
                        }
                    }
                    Ok(rate)
                })
                .map(|rate| rate.map(|rate| (rate, "estimatesmartfee")));
            }
            Some(Conn::Kyoto(kyoto)) => {
                kyoto.arm_fee_sampler(Arc::clone(&self.fee_samples), self.network);
                kyoto.requester()
            }
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
                        Ok(rate) => {
                            // The oracle's answer against what recent blocks paid: one far
                            // above them is broken or hostile, and falls through like a
                            // failure. No readable block leaves the sanity ceiling as the
                            // only bound, as it always was.
                            let ceiling = crate::btc::kyoto::oracle_ceiling(
                                requester.clone(),
                                Arc::clone(&self.fee_samples),
                                self.network,
                            )
                            .await
                            .unwrap_or_else(|e| {
                                debug!("no block data to check the fee oracle against ({e:#})");
                                None
                            });
                            match ceiling {
                                Some(ceiling) if rate > ceiling => warn!(
                                    source = source.as_str(),
                                    %url,
                                    oracle_sat_per_kwu = rate.to_sat_per_kwu(),
                                    ceiling_sat_per_kwu = ceiling.to_sat_per_kwu(),
                                    "the fee oracle's rate is implausibly far above what \
                                     recent blocks paid; falling through to the next fee \
                                     source"
                                ),
                                _ => return Ok(Some((rate, source.as_str()))),
                            }
                        }
                        Err(e) => warn!(
                            source = source.as_str(),
                            %url,
                            "fee lookup failed ({e:#}); falling through to the next fee source"
                        ),
                    }
                }
                crate::btc::fees::FeeTier::PeerMedian => {
                    let attempt = crate::btc::kyoto::estimate_fee_rate(
                        requester.clone(),
                        Arc::clone(&self.fee_samples),
                        self.network,
                        target,
                    )
                    .await
                    .map(|rate| {
                        rate.map(|rate| (rate, crate::config::FeeSource::PeerMedian.as_str()))
                    });
                    if i == last {
                        return attempt;
                    }
                    match attempt {
                        Ok(Some(answer)) => return Ok(Some(answer)),
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
    /// kyoto announcement to the P2P peers. Failures come back as [`BroadcastError`]:
    /// bitcoind classifies rejection vs transport itself, and every kyoto failure is
    /// transport-shaped - a rejection there surfaces asynchronously in the log stream, so
    /// this call failing only ever means "no verdict" (see [`crate::btc::kyoto::announce`]).
    /// A kyoto announcement no peer answers within the timeout is not a failure but
    /// [`Relay::Queued`]: the light client holds the transaction and relays it later.
    async fn upstream_broadcast(&mut self, tx: &Transaction) -> Result<Relay, BroadcastError> {
        let requester = match self.conn.as_ref() {
            Some(Conn::Bitcoind { rpc, .. }) => {
                return tokio::task::block_in_place(|| rpc.broadcast_blocking(tx))
                    .map(|_| Relay::Relayed);
            }
            Some(Conn::Kyoto(kyoto)) => kyoto.requester(),
            None => {
                return Err(BroadcastError::Transport(anyhow::anyhow!(
                    "no upstream connection"
                )))
            }
        };
        match crate::btc::kyoto::announce(requester, tx).await {
            Ok(true) => Ok(Relay::Relayed),
            Ok(false) => Ok(Relay::Queued),
            Err(e) => Err(BroadcastError::Transport(e)),
        }
    }

    /// Record a transaction the upstream only *queued* (a kyoto announcement no peer
    /// answered) exactly as a relayed one, and say so: the inputs lock now, the rebroadcast
    /// pass re-announces it at every new tip, and `abandontransaction` is the way out if it
    /// never relays.
    fn note_queued(&self, txid: Txid) {
        warn!(
            %txid,
            "no peer requested the transaction within the broadcast timeout; recorded at \
             0-conf anyway (its inputs are locked and it is re-announced at each new tip, \
             the light client also holding it for the next peer) - check peer connectivity, \
             and `abandontransaction` releases the inputs if it never relays"
        );
    }

    /// Map a broadcast failure of a transaction the wallet holds **no record of** onto the
    /// RPC vocabulary - the `sendrawtransaction` of a foreign transaction, the one relay
    /// that has nothing to commit first. A rejection passes the node's own verify-family
    /// code and message through (the node answered; retrying the same bytes cannot
    /// succeed). A transport failure is `-4` - retry semantics, the opposite instruction -
    /// and drops a bitcoind connection so the next operation redials with backoff (the
    /// `Conn` convention); a kyoto connection is deliberately kept, since the light client
    /// itself holds the still-queued transaction and tearing it down would discard the
    /// pending relay. A wallet transaction takes [`Self::relay_committed`] instead, whose
    /// transport arm keeps the record rather than erroring.
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
                        "broadcast failed before the upstream gave a verdict: {err:#}; retry \
                         once the upstream is reachable"
                    ),
                )
            }
        }
    }

    /// Commit a transaction to the wallet **before** it is relayed - Bitcoin Core's
    /// `CommitTransaction` order, and the order the crash window demands: the record is on
    /// disk (inputs locked, the transaction a rebroadcast candidate) before any byte of it
    /// can reach the network, so a crash between the two leaves a wallet that knows about
    /// its own send rather than one that will double-spend it. Relaying first, as this
    /// used to, left exactly that window open, and over kyoto - no mempool pass at
    /// reconnect to rediscover the send - nothing ever closed it.
    ///
    /// The apply is BDK's relevance-filtered one, so a foreign transaction stages nothing
    /// and [`Commit::NotOurs`] comes back: there is nothing to commit, and the caller relays
    /// it on the uncommitted path. A persist failure means the record is *not* on disk, so
    /// nothing is relayed: the sighting is withdrawn in memory with an eviction stamped at
    /// its own timestamp (BDK keeps a transaction canonical only while
    /// `last_evicted < last_seen`, so the tie excludes it and the inputs are free again)
    /// and the caller gets an actionable `-4`. The sighting's timestamp rides out on
    /// [`Commit::Recorded`] so a later withdrawal can stamp its eviction no earlier than
    /// the sighting - `SystemTime` is not monotonic, and an eviction one clock step
    /// *before* the sighting would leave the record canonical.
    ///
    /// `not_before` floors the sighting's timestamp: a fee bump passes one past the
    /// original's `last_seen`, since BDK resolves two conflicting unconfirmed transactions
    /// by the later sighting and breaks a tie by txid - a replacement committed in the same
    /// second as its original would otherwise lose half the time. `0` for no floor.
    fn commit_before_relay(
        &mut self,
        tx: &Arc<Transaction>,
        what: &str,
        not_before: u64,
    ) -> Result<Commit, RpcError> {
        let txid = tx.compute_txid();
        // A resubmission of a transaction the wallet once evicted (abandoned, retired) must
        // outrun that eviction, strictly - BDK keeps `last_evicted < last_seen` - or the
        // sighting changes nothing and the relay would go out over a record the wallet
        // still counts as withdrawn. The clock's second granularity makes "later" a floor,
        // not a given.
        let seen_at = match self.wallet.tx_graph().get_last_evicted(txid) {
            Some(evicted_at) => unix_now().max(evicted_at + 1),
            None => unix_now(),
        }
        .max(not_before);
        self.wallet
            .apply_unconfirmed_txs(vec![(Arc::clone(tx), seen_at)]);
        if self.wallet.get_tx(txid).is_none() {
            return Ok(Commit::NotOurs);
        }
        if let Err(e) = self.wallet.persist(&mut self.persister) {
            self.wallet.apply_evicted_txs([(txid, seen_at)]);
            error!(
                %txid,
                "failed to persist the wallet before relaying the {what}; nothing was \
                 broadcast and the record was withdrawn: {e:#}"
            );
            return Err(RpcError::new(
                codes::RPC_WALLET_ERROR,
                format!(
                    "could not persist the wallet before relaying the transaction ({e:#}); \
                     nothing was broadcast and its inputs stay unlocked - retry once the \
                     wallet database is writable"
                ),
            ));
        }
        Ok(Commit::Recorded { seen_at })
    }

    /// Relay a transaction [`Self::commit_before_relay`] has recorded, and settle the record
    /// on the outcome; the caller gets the txid and how the relay ended, since the record
    /// stands in every `Ok` and only the log line differs. Relayed or queued (a kyoto
    /// announcement no peer answered in time - [`Relay::Queued`]): the record stands.
    /// **Transport** (no verdict): the bytes may or may not have reached the network, and
    /// only the record can tell the wallet's next send that the inputs are spoken for, so
    /// it **stands** - Core's posture, which logs the failed relay and keeps the
    /// transaction for its resubmission loop - reported as [`RelayOutcome::Unrelayed`]
    /// with a WARN; the rebroadcast pass resubmits it at the next tip or reconnect, and
    /// `abandontransaction` releases the inputs if it never relays. A bitcoind connection
    /// is dropped for redial, exactly as on the uncommitted path.
    ///
    /// **Rejected** (bitcoind only - kyoto has no verdicts): the node's own code and
    /// message pass through, and the verdict is read the way the rebroadcast pass reads
    /// it ([`classify_rejection`] over the transaction's [`Parents`]) before the record is
    /// touched. A transaction the wallet funded - every own send, and a caller-built spend
    /// of wallet outputs - is withdrawn through [`Self::retire`]: the same bytes can never
    /// be accepted, so its inputs are freed for a differently built one. Two verdicts
    /// leave the record standing: `-27` already-in-chain, which says the block is on its
    /// way (a payment to this wallet mined ahead of its scan), and any verdict on a
    /// transaction with **foreign** parents (a received payment relayed on the sender's
    /// behalf), which proves nothing about it - it propagates on its own and is re-sighted
    /// or retired by the scan, not by a relay it was never ours to make.
    async fn relay_committed(
        &mut self,
        tx: &Transaction,
        seen_at: u64,
        what: &str,
    ) -> Result<(Txid, RelayOutcome), RpcError> {
        let txid = tx.compute_txid();
        match self.upstream_broadcast(tx).await {
            Ok(Relay::Relayed) => Ok((txid, RelayOutcome::Relayed)),
            Ok(Relay::Queued) => {
                self.note_queued(txid);
                Ok((txid, RelayOutcome::Queued))
            }
            Err(BroadcastError::Rejected { code, message }) => {
                let parents = classify_parents(
                    tx,
                    |parent| {
                        self.wallet
                            .get_tx(parent)
                            .is_some_and(|wtx| !wtx.chain_position.is_confirmed())
                    },
                    |parent| self.wallet.get_tx(parent).is_some(),
                );
                let verdict = classify_rejection(code, &message, parents);
                let withdraw =
                    verdict != RebroadcastVerdict::AlreadyInChain && parents != Parents::Foreign;
                if withdraw {
                    warn!(
                        %txid,
                        code,
                        ?verdict,
                        "the upstream rejected the {what}: {message}; withdrawing the \
                         record (its inputs are released)"
                    );
                    // No earlier than the sighting: BDK keeps a transaction canonical
                    // while `last_evicted < last_seen`, and the clock may have stepped
                    // back during the round trip.
                    self.retire(
                        vec![(txid, seen_at.max(unix_now()))],
                        &format!("{what} rejected by the upstream"),
                    );
                } else {
                    warn!(
                        %txid,
                        code,
                        ?verdict,
                        ?parents,
                        "the upstream rejected the {what}: {message}; the record stands \
                         (the verdict does not settle it - the scan will)"
                    );
                }
                Err(RpcError::new(code, message))
            }
            Err(BroadcastError::Transport(err)) => {
                if matches!(self.conn, Some(Conn::Bitcoind { .. })) {
                    self.drop_conn();
                }
                warn!(
                    %txid,
                    "broadcast of the {what} failed before the upstream gave a verdict: \
                     {err:#}; recorded at 0-conf anyway (its inputs are locked and it is \
                     resubmitted at the next tip or reconnect) - `abandontransaction` \
                     releases the inputs if it never relays"
                );
                Ok((txid, RelayOutcome::Unrelayed))
            }
        }
    }

    /// Relay a transaction the wallet holds **no fresh record of**: a caller-built foreign
    /// transaction, or one already in the wallet (a resubmission), where the record is not
    /// this relay's to settle. The outcome is reported as is - a queued kyoto announcement
    /// comes back as [`Relay::Queued`] for the caller to answer - and a failure goes
    /// through [`Self::broadcast_failure`].
    async fn relay_uncommitted(&mut self, tx: &Transaction) -> Result<Relay, RpcError> {
        match self.upstream_broadcast(tx).await {
            Ok(relay) => Ok(relay),
            Err(e) => Err(self.broadcast_failure(e)),
        }
    }

    async fn do_send(
        &mut self,
        recipients: Vec<(String, u64)>,
        options: BtcSendOptions,
    ) -> Result<BtcSent, RpcError> {
        // Checked here but borrowed only at the signing step below: the fee and broadcast
        // calls take `&mut self`, so holding a `&self.seed` across them would not borrow-check.
        self.require_signer()?;
        // Recipients first: pure checks, so a typo'd address or a bad amount is refused
        // before the send costs a fee-oracle round trip on the single-writer actor, and
        // answers the same `-5`/`-3` offline as online.
        let parsed = parse_recipients(&recipients, self.wallet.network())?;
        if self.conn.is_none() {
            return Err(RpcError::new(
                codes::RPC_WALLET_ERROR,
                "no connection to the upstream (fee estimation and broadcast need it); retry \
                 once it is reachable",
            ));
        }
        self.send_gate()?;
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
            Some(kvb) => Some((FeeRate::from_sat_per_kwu(kvb.div_ceil(4)), "PayTxFee set")),
            None => self
                .upstream_fee_rate()
                .await
                .map_err(|e| RpcError::new(codes::RPC_WALLET_ERROR, format!("{e:#}")))?,
        };
        let (fee_rate, fee_reason) = match fee_rate {
            Some((rate, reason)) => (
                crate::btc::fees::enforce_sanity_ceiling(rate)
                    .map_err(|e| RpcError::new(codes::RPC_WALLET_ERROR, format!("{e:#}")))?,
                reason,
            ),
            None if self.network == BitcoinNetwork::Main => {
                return Err(RpcError::new(
                    codes::RPC_WALLET_ERROR,
                    "Fee estimation failed and no fallback applies on mainnet; retry once \
                     the node has fee data (or pass an explicit fee_rate)",
                ))
            }
            None => (FeeRate::from_sat_per_vb_u32(1), "Fallback fee"),
        };
        let started = Instant::now();
        // Ancestor-aware funding (`crate::btc::ancestors`): an unconfirmed output is priced
        // net of what its unconfirmed ancestry lacks at this rate, and one the wallet cannot
        // price is not spent at all.
        let ancestry = Arc::new(self.ancestry());
        let mut unspendable = self.immature_coinbase_outpoints();
        unspendable.extend(self.unpriceable_unconfirmed(&ancestry));
        let sequence = options
            .non_replaceable
            .then_some(bdk_wallet::bitcoin::Sequence::ENABLE_LOCKTIME_NO_RBF);
        // `fee_split = "output"`: each paying recipient's amount is cut by its own output's
        // share up front, and the send is then an ordinary one - the sender's change pays the
        // rest of the fee, so there is no fixed point to walk.
        let by_output = options.fee_split == BtcFeeSplit::Output;
        let parsed = if by_output {
            subtract_output_shares(&parsed, &options.subtract_fee_from, fee_rate)?
        } else {
            parsed
        };
        let (psbt, ancestor_fee) = if options.subtract_fee_from.is_empty() || by_output {
            let selection = AncestorAware::new(Arc::clone(&ancestry), fee_rate);
            let paid = selection.paid();
            let mut builder = self.wallet.build_tx().coin_selection(selection);
            builder.unspendable(unspendable);
            for (address, amount) in &parsed {
                builder.add_recipient(address.script_pubkey(), *amount);
            }
            builder.fee_rate(fee_rate);
            if let Some(sequence) = sequence {
                builder.set_exact_sequence(sequence);
            }
            let psbt = builder.finish().map_err(map_create_tx_error)?;
            (psbt, paid.load(std::sync::atomic::Ordering::Relaxed))
        } else {
            self.build_subtract_fee_psbt(
                &parsed,
                &options.subtract_fee_from,
                fee_rate,
                &ancestry,
                unspendable,
                sequence,
            )?
        };
        // The absolute-fee cap (Core's `-maxtxfee`), checked on the built PSBT before a
        // signer exists. The sanity ceiling bounds the *rate*; a large consolidation at a
        // sane rate can still carry a surprising total, and this is the one number the
        // operator actually pays.
        let fee = psbt
            .fee()
            .map_err(|e| RpcError::misc(format!("compute the psbt fee: {e}")))?;
        check_max_tx_fee(fee.to_sat(), self.fees.max_tx_fee_sat)?;

        let tx = self.sign_and_extract(psbt)?;
        // Commit, then relay (module doc): the send is on disk at 0-conf - its inputs
        // locked against the next send's coin selection - before a byte of it can reach
        // the network. An own send always spends wallet outputs, so `NotOurs` cannot
        // happen here; treating it as recorded would relay without a record, which is the
        // window this order exists to close.
        let seen_at = match self.commit_before_relay(&tx, "send", 0)? {
            Commit::Recorded { seen_at } => seen_at,
            Commit::NotOurs => {
                return Err(RpcError::misc(
                    "the built transaction is not recognized as a wallet transaction; \
                     nothing was broadcast",
                ))
            }
        };
        let (txid, outcome) = self.relay_committed(&tx, seen_at, "send").await?;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        if ancestor_fee > 0 {
            info!(
                %txid,
                ancestor_fee,
                "the send pays toward its unconfirmed parents so they confirm at its rate \
                 (ancestor-aware funding)"
            );
        }
        match outcome {
            RelayOutcome::Relayed => info!(
                %txid,
                recipients = recipients.len(),
                elapsed_ms,
                "sent transaction"
            ),
            // Committed, not yet relayed: the WARN above says why. Not "sent" - an
            // operator counting that line must not count these.
            RelayOutcome::Queued | RelayOutcome::Unrelayed => info!(
                %txid,
                recipients = recipients.len(),
                elapsed_ms,
                relay = ?outcome,
                "committed transaction; relay pending"
            ),
        }
        Ok(BtcSent {
            txid: txid.to_string(),
            fee_reason: fee_reason.to_string(),
        })
    }

    /// Refuse a spend on a wallet with no seed in hand - Bitcoin Core's `-4` for a wallet
    /// that cannot sign, worded for which of the two shapes this is: a watch-only wallet has
    /// nothing to unlock, ever; a locked spending wallet has a seed the custody model did
    /// not hand over.
    fn require_signer(&self) -> Result<(), RpcError> {
        if self.seed.is_some() {
            return Ok(());
        }
        Err(RpcError::new(
            codes::RPC_WALLET_ERROR,
            if self.watch_only {
                "Error: Private keys are disabled for this wallet (watch-only, built from \
                 an imported xpub); spend from the paired spending wallet"
            } else {
                "Error: Private keys are disabled for this wallet, or the wallet is locked \
                 (bitcoin wallets have no walletpassphrase yet - use an identity-file \
                 wallet with auto_unlock for unattended sending)"
            },
        ))
    }

    /// Sign a built PSBT and extract the finished transaction. Signers are derived from the
    /// seed per call and dropped with this scope - the custody model's spend half (the
    /// persisted wallet holds public descriptors only). The caller has passed
    /// [`Self::require_signer`].
    fn sign_and_extract(&self, mut psbt: Psbt) -> Result<Arc<Transaction>, RpcError> {
        let seed = self
            .seed
            .as_ref()
            .ok_or_else(|| RpcError::misc("no seed to sign with"))?;
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
        Ok(Arc::new(psbt.extract_tx().map_err(|e| {
            RpcError::misc(format!("extract transaction: {e:?}"))
        })?))
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
        ancestry: &Arc<Ancestry>,
        unspendable: Vec<OutPoint>,
        sequence: Option<bdk_wallet::bitcoin::Sequence>,
    ) -> Result<(Psbt, u64), RpcError> {
        let inputs: Vec<OutPoint> = {
            let mut builder = self
                .wallet
                .build_tx()
                .coin_selection(AncestorAware::new(Arc::clone(ancestry), fee_rate));
            builder.unspendable(unspendable);
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
            let selection = AncestorAware::new(Arc::clone(ancestry), fee_rate);
            let paid = selection.paid();
            let mut builder = self.wallet.build_tx().coin_selection(selection);
            builder
                .add_utxos(&inputs)
                .map_err(|e| RpcError::misc(format!("re-select inputs: {e:?}")))?;
            builder.manually_selected_only();
            for (address, amount) in &reduced {
                builder.add_recipient(address.script_pubkey(), *amount);
            }
            builder.fee_rate(fee_rate);
            if let Some(sequence) = sequence {
                builder.set_exact_sequence(sequence);
            }
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
                        return Ok((psbt, paid.load(std::sync::atomic::Ordering::Relaxed)));
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
        let txid = tx.compute_txid();
        let tx = Arc::new(tx);
        // A transaction the wallet holds **canonical** - a resubmission of an own send, or
        // of a payment it received - has nothing to commit: relay it and report the
        // verdict as is, leaving the record to the rebroadcast pass and the block scan (a
        // `-27` on a confirmed transaction must not evict it). The canonical view, not the
        // raw graph: an abandoned or retired transaction is in the graph too, and
        // resubmitting one must re-canonicalize it first (below), or the node would hold a
        // transaction whose inputs the wallet still counts as free.
        //
        // Unlike a send, `sendrawtransaction` answers a txid only once the transaction was
        // actually relayed - Core never returns one without mempool acceptance, and a
        // script reading success here would believe the network has it. A kyoto
        // announcement no peer requested, or a bitcoind broadcast with no verdict, is `-25`
        // naming what the wallet did with it. (A send returns its txid in those cases,
        // because there the record is the product; here the relay is.)
        if self.wallet.get_tx(txid).is_some() {
            return match self.relay_uncommitted(&tx).await? {
                Relay::Relayed => Ok(txid.to_string()),
                Relay::Queued => Err(not_relayed(
                    txid,
                    "the wallet already holds it and re-announces it at each new tip",
                )),
            };
        }
        // Otherwise commit first when it touches this wallet (the apply filters relevance
        // itself; a fresh sighting outruns any earlier eviction), then relay - the same
        // order as a send, for the same crash window. A foreign transaction has nothing to
        // record and is relayed on the uncommitted path, whose failures are reported
        // verbatim.
        match self.commit_before_relay(&tx, "broadcast", 0)? {
            Commit::Recorded { seen_at } => {
                match self.relay_committed(&tx, seen_at, "broadcast").await? {
                    (txid, RelayOutcome::Relayed) => Ok(txid.to_string()),
                    (txid, RelayOutcome::Queued | RelayOutcome::Unrelayed) => Err(not_relayed(
                        txid,
                        "it is recorded at 0-conf and resubmitted at each new tip; \
                         `abandontransaction` releases its inputs if it never relays",
                    )),
                }
            }
            Commit::NotOurs => match self.relay_uncommitted(&tx).await? {
                Relay::Relayed => Ok(txid.to_string()),
                Relay::Queued => {
                    // Nothing records a foreign transaction, so nothing would ever retry it
                    // - but the light client's queue would announce it to the next peer
                    // regardless, turning this error into a late, unannounced success.
                    // Restarting the node discards the queue, which makes the answer true:
                    // it was not relayed, and will not be.
                    self.restart_light_client(txid, "a foreign transaction no peer requested");
                    Err(not_relayed(
                        txid,
                        "the wallet does not record it, and the light client was restarted \
                         so it is not announced later either; retry once peers are reachable",
                    ))
                }
            },
        }
    }

    /// `abandontransaction`: mark an unconfirmed wallet transaction and its unconfirmed
    /// descendants abandoned, releasing their inputs for the next send. Core's eligibility
    /// rules: the transaction must be the wallet's (`-5` "Invalid or non-wallet transaction
    /// id"), unconfirmed, and not in the mempool (`-5` "Transaction not eligible for
    /// abandonment"). The mempool half is only checkable where the upstream has a mempool
    /// view - over bitcoind, [`Self::node_mempool`] from the last pass at tip; over kyoto
    /// there is none, so the caller is trusted. Over kyoto the abandonment also **restarts
    /// the light client**: `bip157`'s in-memory broadcast queue holds the signed bytes and
    /// re-announces them to every peer that completes a handshake, with no API to forget
    /// one, so leaving the node up would have the operator's own client keep pushing a
    /// transaction the operator just abandoned - worse than Core, whose node at least stops
    /// relaying. Dropping the node discards the queue; the redial is a deliberate restart
    /// (no backoff, from the wallet's own checkpoint), not an outage. What remains is
    /// Core's own caveat: a peer that already received the bytes may still relay them. BDK
    /// represents "abandoned" as an eviction (`apply_evicted_txs`), which is not final: if
    /// the transaction confirms after all, the block re-canonicalizes it.
    fn do_abandon(&mut self, txid: Txid) -> Result<(), RpcError> {
        let Some(wtx) = self.wallet.get_tx(txid) else {
            return Err(RpcError::invalid_address_or_key(
                "Invalid or non-wallet transaction id",
            ));
        };
        if wtx.chain_position.is_confirmed() {
            return Err(RpcError::invalid_address_or_key(
                "Transaction not eligible for abandonment",
            ));
        }
        if self
            .node_mempool
            .as_ref()
            .is_some_and(|mempool| mempool.contains(&txid))
        {
            return Err(RpcError::invalid_address_or_key(
                "Transaction not eligible for abandonment",
            ));
        }
        // The transaction plus every unconfirmed wallet transaction that spends from the
        // set, to a fixed point: a child cannot stand once its parent is abandoned.
        let unconfirmed: Vec<(Txid, Arc<Transaction>)> = self
            .wallet
            .transactions()
            .filter(|wtx| !wtx.chain_position.is_confirmed())
            .map(|wtx| (wtx.tx_node.txid, wtx.tx_node.tx.clone()))
            .collect();
        let mut abandoned: HashSet<Txid> = HashSet::from([txid]);
        loop {
            let before = abandoned.len();
            for (child, tx) in &unconfirmed {
                if !abandoned.contains(child)
                    && tx
                        .input
                        .iter()
                        .any(|input| abandoned.contains(&input.previous_output.txid))
                {
                    abandoned.insert(*child);
                }
            }
            if abandoned.len() == before {
                break;
            }
        }
        let now = unix_now();
        self.retire(
            abandoned.iter().map(|id| (*id, now)).collect(),
            "abandontransaction",
        );
        info!(
            target: "zecd::audit",
            %txid,
            descendants = abandoned.len() - 1,
            "abandoned an unconfirmed transaction; its inputs are released"
        );
        self.restart_light_client(txid, "an abandoned transaction");
        Ok(())
    }

    /// `bumpfee`: replace an unconfirmed own send with a higher-fee version of itself
    /// (BIP 125). Bitcoin Core's contract, precondition by precondition and with its codes:
    /// the transaction must be the wallet's (`-5` "Invalid or non-wallet transaction id"),
    /// not yet mined (`-4`), not already replaced (`-4` naming the replacement), have no
    /// unconfirmed wallet descendants (`-8` - replacing it would silently evict them),
    /// signal replaceability (`-4`), and spend only wallet inputs (`-4` - there is no
    /// signer for a foreign one).
    ///
    /// The replacement keeps every recipient output and every original input; BDK's
    /// `build_fee_bump` drops the change output and re-runs coin selection, taking more
    /// (confirmed) inputs only if the change cannot absorb the higher fee. Its rate is the
    /// caller's `fee_rate`, else Core's default: the original's rate plus the wallet's
    /// incremental relay fee ([`default_bump_rate_sat_per_kvb`]), or the upstream's
    /// estimate when that is higher - an unavailable estimate is not an error here, since
    /// the incremental floor alone is a well-defined bump. BDK enforces BIP 125's rate rule
    /// (at least 1 sat/vB above the original); the total-fee rule (the original's fee plus
    /// 1 sat/vB of the replacement's size, [`bump_total_fee_floor`]) is checked here, since
    /// a replacement that sheds its change output can clear the first and fail the second.
    /// A default bump is then rebuilt once at the rate that clears it; an explicit rate is
    /// refused with Core's `-8`. Then the send path: sanity ceiling, `max_tx_fee_sat`,
    /// per-call signers, commit (stamped past the original's sighting, so the replacement
    /// is the canonical one - see [`Self::commit_before_relay`]), relay.
    ///
    /// The original is not deleted: BDK keeps it in the graph, non-canonical while the
    /// replacement stands. If the relay is rejected the replacement is retired and the
    /// original is canonical again; if the original confirms after all (kyoto: a peer never
    /// took the replacement), its block re-canonicalizes it and the replacement drops out.
    async fn do_bump_fee(
        &mut self,
        txid: Txid,
        options: BtcBumpOptions,
    ) -> Result<BtcBumped, RpcError> {
        self.require_signer()?;
        let original = self.bump_candidate(txid)?;
        if self.conn.is_none() {
            return Err(RpcError::new(
                codes::RPC_WALLET_ERROR,
                "no connection to the upstream (fee estimation and broadcast need it); retry \
                 once it is reachable",
            ));
        }
        self.send_gate()?;
        let orig_fee = self
            .wallet
            .calculate_fee(&original)
            .map_err(|e| RpcError::misc(format!("compute the original fee: {e}")))?
            .to_sat();
        let orig_vsize = original.weight().to_vbytes_ceil();
        let explicit = options.fee_rate_sat_per_kvb;
        let rate_kvb = match explicit {
            Some(kvb) => kvb,
            None => {
                let estimate_kvb = match self.upstream_fee_rate().await {
                    Ok(Some((rate, _))) => Some(rate.to_sat_per_kwu() * 4),
                    Ok(None) => None,
                    Err(e) => {
                        debug!(%txid, "bumpfee: no fee estimate ({e:#}); bumping by the incremental fee alone");
                        None
                    }
                };
                default_bump_rate_sat_per_kvb(orig_fee, orig_vsize, estimate_kvb)
            }
        };
        // Signed before the total-fee rule is checked: the rule is priced on the
        // replacement's final size, witnesses included.
        let (mut tx, mut fee) = self.build_signed_bump(txid, rate_kvb, options.non_replaceable)?;
        let floor = bump_total_fee_floor(orig_fee, tx.vsize() as u64);
        if fee < floor {
            if explicit.is_some() {
                return Err(insufficient_bump_fee(fee, floor, orig_fee));
            }
            // A default bump that shed its change output: rebuild once at the rate that
            // clears the total-fee rule for the size just built.
            let vsize = tx.vsize() as u64;
            let retry_kvb = (floor * 1_000).div_ceil(vsize).max(rate_kvb + 1);
            (tx, fee) = self.build_signed_bump(txid, retry_kvb, options.non_replaceable)?;
            let floor = bump_total_fee_floor(orig_fee, tx.vsize() as u64);
            if fee < floor {
                return Err(insufficient_bump_fee(fee, floor, orig_fee));
            }
        }
        let not_before = self
            .wallet
            .tx_graph()
            .get_tx_node(txid)
            .and_then(|node| node.last_seen)
            .map_or(0, |seen| seen + 1);
        let seen_at = match self.commit_before_relay(&tx, "fee bump", not_before)? {
            Commit::Recorded { seen_at } => seen_at,
            Commit::NotOurs => {
                return Err(RpcError::misc(
                    "the replacement is not recognized as a wallet transaction; nothing was \
                     broadcast",
                ))
            }
        };
        let (new_txid, outcome) = self.relay_committed(&tx, seen_at, "fee bump").await?;
        info!(
            target: "zecd::audit",
            original = %txid,
            replacement = %new_txid,
            orig_fee,
            fee,
            relay = ?outcome,
            "replaced an unconfirmed send with a higher-fee version (bumpfee)"
        );
        Ok(BtcBumped {
            txid: new_txid.to_string(),
            orig_fee_sat: orig_fee,
            fee_sat: fee,
        })
    }

    /// `bumpfee`'s preconditions - see [`Self::do_bump_fee`] - answering the original
    /// transaction when every one holds.
    fn bump_candidate(&self, txid: Txid) -> Result<Arc<Transaction>, RpcError> {
        let Some(original) = self.wallet.tx_graph().get_tx(txid) else {
            return Err(RpcError::invalid_address_or_key(
                "Invalid or non-wallet transaction id",
            ));
        };
        match self.wallet.get_tx(txid) {
            Some(wtx) if wtx.chain_position.is_confirmed() => {
                return Err(RpcError::new(
                    codes::RPC_WALLET_ERROR,
                    "Transaction has been mined, or is conflicted with a mined transaction",
                ))
            }
            Some(_) => {}
            // In the graph but not canonical: replaced (a canonical transaction spends one
            // of its inputs), or abandoned/evicted.
            None => {
                let inputs: HashSet<OutPoint> =
                    original.input.iter().map(|i| i.previous_output).collect();
                let conflict = self.wallet.transactions().find(|wtx| {
                    wtx.tx_node
                        .tx
                        .input
                        .iter()
                        .any(|i| inputs.contains(&i.previous_output))
                });
                return Err(RpcError::new(
                    codes::RPC_WALLET_ERROR,
                    match conflict {
                        Some(wtx) if wtx.chain_position.is_confirmed() => {
                            "Transaction has been mined, or is conflicted with a mined \
                             transaction"
                                .to_string()
                        }
                        Some(wtx) => format!(
                            "Cannot bump transaction {txid} since it has already been bumped \
                             by {}",
                            wtx.tx_node.txid
                        ),
                        None => format!(
                            "Transaction {txid} was abandoned or evicted, so there is nothing \
                             in flight to bump; send the payment again"
                        ),
                    },
                ));
            }
        }
        if self.wallet.transactions().any(|wtx| {
            wtx.tx_node
                .tx
                .input
                .iter()
                .any(|i| i.previous_output.txid == txid)
        }) {
            return Err(RpcError::invalid_parameter(
                "Transaction has descendants in the wallet",
            ));
        }
        if !original.is_explicitly_rbf() {
            return Err(RpcError::new(
                codes::RPC_WALLET_ERROR,
                "Transaction is not BIP 125 replaceable",
            ));
        }
        let foreign = original.input.iter().any(|input| {
            self.wallet
                .tx_graph()
                .get_txout(input.previous_output)
                .is_none_or(|txout| !self.wallet.is_mine(txout.script_pubkey.clone()))
        });
        if foreign {
            return Err(RpcError::new(
                codes::RPC_WALLET_ERROR,
                "Transaction contains inputs that don't belong to this wallet",
            ));
        }
        Ok(original)
    }

    /// [`Self::build_bump`], then the send path's checks on the built PSBT - the absolute
    /// fee cap (answered as Core's `bumpfee` does, `-4`, not the send path's `-6`) - and the
    /// per-call signers. Answers the signed replacement and its fee in satoshis.
    fn build_signed_bump(
        &mut self,
        txid: Txid,
        rate_kvb: u64,
        non_replaceable: bool,
    ) -> Result<(Arc<Transaction>, u64), RpcError> {
        let psbt = self.build_bump(txid, rate_kvb, non_replaceable)?;
        let fee = psbt
            .fee()
            .map_err(|e| RpcError::misc(format!("compute the psbt fee: {e}")))?
            .to_sat();
        check_max_tx_fee(fee, self.fees.max_tx_fee_sat)
            .map_err(|e| RpcError::new(codes::RPC_WALLET_ERROR, e.message))?;
        Ok((self.sign_and_extract(psbt)?, fee))
    }

    /// One `build_fee_bump` attempt at `rate_kvb` (sat/kvB). The rate passes the sanity
    /// ceiling first, like every send's; BDK's own replacement-rate refusal becomes Core's
    /// `-8`.
    fn build_bump(
        &mut self,
        txid: Txid,
        rate_kvb: u64,
        non_replaceable: bool,
    ) -> Result<Psbt, RpcError> {
        use bdk_wallet::error::{BuildFeeBumpError, CreateTxError};
        let rate = crate::btc::fees::enforce_sanity_ceiling(FeeRate::from_sat_per_kwu(
            rate_kvb.div_ceil(4),
        ))
        .map_err(|e| RpcError::new(codes::RPC_WALLET_ERROR, format!("{e:#}")))?;
        let immature = self.immature_coinbase_outpoints();
        // The original's own unconfirmed parents are paid for at the new rate too (Core's
        // `feebumper` adds the combined bump fee of the reused inputs); BDK adds only
        // confirmed coins to a bump, so those inputs are the only ones that can carry any.
        let ancestry = Arc::new(self.ancestry());
        let mut builder = self
            .wallet
            .build_fee_bump(txid)
            .map_err(|e| match e {
                BuildFeeBumpError::TransactionNotFound(_) => {
                    RpcError::invalid_address_or_key("Invalid or non-wallet transaction id")
                }
                other => RpcError::new(codes::RPC_WALLET_ERROR, format!("{other}")),
            })?
            .coin_selection(AncestorAware::new(ancestry, rate));
        builder.unspendable(immature);
        builder.fee_rate(rate);
        if non_replaceable {
            builder.set_exact_sequence(bdk_wallet::bitcoin::Sequence::ENABLE_LOCKTIME_NO_RBF);
        }
        builder.finish().map_err(|e| match e {
            CreateTxError::FeeRateTooLow { required } => RpcError::invalid_parameter(format!(
                "Insufficient fee rate: the replacement must pay at least {} sat/vB (the \
                 original's rate plus the 1 sat/vB incremental relay fee)",
                required.to_sat_per_kwu().saturating_mul(4).div_ceil(1_000)
            )),
            other => map_create_tx_error(other),
        })
    }

    /// Over kyoto, drop the light client so its broadcast queue forgets `txid`: `bip157`
    /// re-announces a queued transaction to every peer that completes a handshake and has
    /// no API to forget one, so a new node is the only way. A deliberate restart, like the
    /// birthday anchor's: no backoff, the next pass redials at once from the wallet's own
    /// checkpoint. A no-op over bitcoind, which queues nothing.
    fn restart_light_client(&mut self, txid: Txid, what: &str) {
        if !matches!(self.conn, Some(Conn::Kyoto(_))) {
            return;
        }
        self.conn = None;
        self.at_tip = false;
        self.rebroadcast_tip = None;
        self.node_mempool = None;
        self.status_tx.send_replace(status_of(
            &self.wallet,
            BtcConnState::Syncing,
            self.birthday_anchor.as_ref(),
            self.birthday_block_time,
            self.feed_status.as_ref(),
        ));
        info!(
            %txid,
            "restarting the light client so its broadcast queue forgets {what}; a peer that \
             already received it may still relay it"
        );
    }
}

/// Whether the wallet holds `tx` as replaced by one of its own unconfirmed sends: in the
/// graph, not canonical, and conflicting with a canonical unconfirmed transaction the wallet
/// funded. See [`BtcActor::drop_superseded_sightings`].
fn replaced_by_own_send(wallet: &Wallet, tx: &Transaction) -> bool {
    let txid = tx.compute_txid();
    if wallet.tx_graph().get_tx(txid).is_none() || wallet.get_tx(txid).is_some() {
        return false;
    }
    let inputs: HashSet<OutPoint> = tx.input.iter().map(|i| i.previous_output).collect();
    wallet.transactions().any(|wtx| {
        !wtx.chain_position.is_confirmed()
            && wallet.sent_and_received(&wtx.tx_node.tx).0 > Amount::ZERO
            && wtx
                .tx_node
                .tx
                .input
                .iter()
                .any(|i| inputs.contains(&i.previous_output))
    })
}

/// [`BtcActor::ancestry`] over a bare wallet, given the funded set.
fn wallet_ancestry(wallet: &Wallet, funded: &HashSet<Txid>) -> Ancestry {
    let txs: Vec<Unconfirmed> = wallet
        .transactions()
        .filter(|wtx| !wtx.chain_position.is_confirmed())
        .map(|wtx| {
            let tx = &wtx.tx_node.tx;
            let parents: Vec<Txid> = tx.input.iter().map(|i| i.previous_output.txid).collect();
            Unconfirmed {
                txid: wtx.tx_node.txid,
                fee: wallet.calculate_fee(tx).ok().map(Amount::to_sat),
                vsize: tx.vsize() as u64,
                funded: funded.contains(&wtx.tx_node.txid),
                unknown_parents: parents.iter().any(|p| wallet.get_tx(*p).is_none()),
                parents,
            }
        })
        .collect();
    Ancestry::new(txs)
}

/// `sendrawtransaction`'s answer for a transaction that was not relayed: Core's `-25`
/// (`RPC_VERIFY_ERROR`, what it answers for a broadcast that did not reach the mempool),
/// saying what became of it.
fn not_relayed(txid: Txid, fate: &str) -> RpcError {
    RpcError::new(
        RPC_VERIFY_ERROR,
        format!(
            "transaction {txid} was not relayed: no peer requested it within the broadcast \
             timeout, or the node gave no verdict; {fate}"
        ),
    )
}

/// What [`BtcActor::commit_before_relay`] found: the transaction is the wallet's and is now
/// on disk at 0-conf (sighted at `seen_at`, the floor for any later eviction stamp), or it
/// touches nothing of the wallet's and there was nothing to record.
enum Commit {
    Recorded { seen_at: u64 },
    NotOurs,
}

/// How [`BtcActor::relay_committed`] left a committed transaction. The record stands in
/// every case; this is what the caller's log line says about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayOutcome {
    /// The upstream accepted it (bitcoind), or a peer fetched the announcement (kyoto).
    Relayed,
    /// Kyoto: no peer asked within the broadcast timeout; the light client holds it queued.
    Queued,
    /// No verdict at all (transport failure): the rebroadcast pass carries it from here.
    Unrelayed,
}

/// What an upstream broadcast achieved, when it did not fail outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relay {
    /// The node accepted it (bitcoind), or a peer requested the bytes (kyoto).
    Relayed,
    /// Kyoto only: no peer asked within the timeout; the light client holds the
    /// transaction queued and announces it to every peer that connects from now on. The
    /// send records it and returns the txid all the same - see the module doc.
    Queued,
}

/// One unconfirmed wallet transaction the rebroadcast pass will resubmit.
struct RebroadcastCandidate {
    tx: Arc<Transaction>,
    txid: Txid,
    /// What the wallet knows about the transactions its inputs spend - the context a
    /// missing-inputs verdict is read in.
    parents: Parents,
}

/// What the wallet knows about a candidate's funding transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Parents {
    /// Every input spends a wallet transaction the wallet holds confirmed: the outputs are
    /// in the node's UTXO set unless something else spent them, so a missing-inputs
    /// verdict is a confirmed conflict.
    Confirmed,
    /// Some input spends a wallet transaction that is itself unconfirmed (an own chain of
    /// sends): missing inputs means "parent first".
    WaitsOnOwn,
    /// Some input spends a transaction the wallet does not hold - every received payment.
    /// Core answers `Missing inputs` for an unconfirmed parent it no longer holds (a
    /// restart without mempool persistence, say) exactly as for a confirmed parent that
    /// was double-spent, and the wallet cannot tell the two apart; a verdict here proves
    /// nothing. A dead receive is retired by other means: over bitcoind BDK inserts the
    /// conflict when its block is applied (`is_tx_or_conflict_relevant`), over kyoto
    /// [`BtcActor::expire_reorged_receives`] times it out.
    Foreign,
}

/// What a bitcoind rejection of a resubmitted send means for the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RebroadcastVerdict {
    /// Core's `-27`: mined already; the block reaches the wallet on its own.
    AlreadyInChain,
    /// The inputs are gone from the UTXO set and every one of them was a confirmed wallet
    /// output, so something else spent them and confirmed. Terminal: the transaction can
    /// never confirm as things stand.
    ConfirmedConflict,
    /// Anything else - `non-final` after a reorg, a fee-policy floor, a missing input whose
    /// parent is an own unconfirmed send or a foreign transaction - clears with time or a
    /// parent, so try again next tip.
    Retry,
}

/// Bitcoin Core's `sendrawtransaction` error codes (`rpc/protocol.h`).
const RPC_VERIFY_ERROR: i32 = -25;
const RPC_VERIFY_ALREADY_IN_CHAIN: i32 = -27;

/// Classify a bitcoind rejection of a resubmitted transaction. Pure, so the rules are
/// testable without a node: `-27` is [`RebroadcastVerdict::AlreadyInChain`]; `-25` with
/// Core's missing-inputs text (`Missing inputs` from `sendrawtransaction`,
/// `bad-txns-inputs-missingorspent` from mempool acceptance) is a
/// [`RebroadcastVerdict::ConfirmedConflict`] **only** when every input spends a confirmed
/// wallet transaction ([`Parents::Confirmed`]) - the same text means "parent first" on an
/// own unconfirmed parent and proves nothing on a foreign one; everything else, the `-26`
/// policy family included, is [`RebroadcastVerdict::Retry`].
fn classify_rejection(code: i32, message: &str, parents: Parents) -> RebroadcastVerdict {
    let lower = message.to_ascii_lowercase();
    let missing_inputs = lower.contains("missing inputs") || lower.contains("missingorspent");
    match code {
        RPC_VERIFY_ALREADY_IN_CHAIN => RebroadcastVerdict::AlreadyInChain,
        RPC_VERIFY_ERROR if missing_inputs && parents == Parents::Confirmed => {
            RebroadcastVerdict::ConfirmedConflict
        }
        _ => RebroadcastVerdict::Retry,
    }
}

/// What the wallet knows about the transactions `tx` spends: an input funded by a wallet
/// transaction the wallet holds unconfirmed (an own chain of sends) is a dependency; one
/// funded by a transaction the wallet does not hold at all - every input of a received
/// payment - makes the node's missing-inputs verdict unreadable (see [`Parents::Foreign`]).
/// `own_unconfirmed` answers the first question for a parent txid, `held` the second; the
/// rebroadcast pass answers from the candidate set it already built, a single relay from
/// the wallet's canonical view.
fn classify_parents(
    tx: &Transaction,
    own_unconfirmed: impl Fn(Txid) -> bool,
    held: impl Fn(Txid) -> bool,
) -> Parents {
    let mut parents = Parents::Confirmed;
    for input in &tx.input {
        let parent = input.previous_output.txid;
        if own_unconfirmed(parent) {
            return Parents::WaitsOnOwn;
        }
        if !held(parent) {
            parents = Parents::Foreign;
        }
    }
    parents
}

/// Order candidates so that no transaction precedes one it spends from (a stable
/// topological sort over the candidate set; transactions outside the set are not
/// constraints). A cycle is impossible for valid transactions, but the loop still
/// terminates on one by appending whatever is left.
fn order_parents_first(mut pending: Vec<RebroadcastCandidate>) -> Vec<RebroadcastCandidate> {
    let mut ordered = Vec::with_capacity(pending.len());
    while !pending.is_empty() {
        let unresolved: HashSet<Txid> = pending.iter().map(|c| c.txid).collect();
        let (ready, blocked): (Vec<_>, Vec<_>) = pending.into_iter().partition(|c| {
            !c.tx
                .input
                .iter()
                .any(|input| unresolved.contains(&input.previous_output.txid))
        });
        if ready.is_empty() {
            ordered.extend(blocked);
            break;
        }
        ordered.extend(ready);
        pending = blocked;
    }
    ordered
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

/// What one output costs at `rate`: its serialized size (8-byte value, the script's length
/// prefix, the script - all non-witness, so weight is 4x the bytes) priced by weight and
/// rounded up, the same way BDK prices the transaction. `fee_split = "output"` charges
/// each paying recipient exactly this.
fn output_fee_share(rate: FeeRate, script: &bdk_wallet::bitcoin::Script) -> u64 {
    let weight = bdk_wallet::bitcoin::TxOut {
        value: Amount::ZERO,
        script_pubkey: script.to_owned(),
    }
    .weight()
    .to_wu();
    (rate.to_sat_per_kwu() * weight).div_ceil(1_000)
}

/// Cut each paying recipient's amount by its own output's share ([`output_fee_share`]):
/// `fee_split = "output"`. A cut that would leave nothing is Core's `-4` for a fee the
/// amount cannot cover; one that leaves dust is refused by the builder as usual.
fn subtract_output_shares(
    parsed: &[(Address, Amount)],
    payers: &[usize],
    rate: FeeRate,
) -> Result<Vec<(Address, Amount)>, RpcError> {
    let mut out = parsed.to_vec();
    for idx in payers {
        let entry = out
            .get_mut(*idx)
            .ok_or_else(|| RpcError::invalid_parameter("subtractfeefrom index out of range"))?;
        let cut = output_fee_share(rate, &entry.0.script_pubkey());
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

/// The wallet key at one derivation, in the forms Core reports it: the inferred
/// single-key descriptor (`listunspent.desc`, `getaddressinfo.desc`) with its checksum, the
/// compressed public key, and the master fingerprint.
#[derive(Clone, Debug)]
pub struct BtcKeyOrigin {
    pub desc: String,
    pub pubkey: String,
    pub fingerprint: String,
}

/// Core's inferred descriptor for the wallet key at `keychain/index` - the single-key form
/// Core's `listunspent.desc` carries: `wpkh([fingerprint/full/path]pubkey)` with its
/// checksum. `None` only if the wallet's descriptor cannot be derived there (it always can
/// for a BIP 84 wallet at a non-hardened index).
fn inferred_descriptor(
    wallet: &bdk_wallet::Wallet,
    keychain: KeychainKind,
    index: u32,
) -> Option<String> {
    key_origin(wallet, keychain, index).map(|origin| origin.desc)
}

/// [`inferred_descriptor`] plus the key parts it is built from.
fn key_origin(
    wallet: &bdk_wallet::Wallet,
    keychain: KeychainKind,
    index: u32,
) -> Option<BtcKeyOrigin> {
    use bdk_wallet::miniscript::descriptor::{Descriptor, DescriptorPublicKey};
    use bdk_wallet::miniscript::ForEachKey as _;
    let definite = wallet
        .public_descriptor(keychain)
        .at_derivation_index(index)
        .ok()?;
    let secp = bdk_wallet::bitcoin::secp256k1::Secp256k1::verification_only();
    let mut key = None;
    definite.for_each_key(|k| {
        key = Some((
            k.master_fingerprint(),
            k.full_derivation_path(),
            k.derive_public_key(&secp).ok(),
        ));
        true
    });
    let (fingerprint, Some(path), Some(pubkey)) = key? else {
        return None;
    };
    let path = path.to_string();
    let path = path.trim_start_matches('m').trim_start_matches('/');
    // Parsed back so miniscript appends the checksum (and so a malformed string is `None`
    // rather than a bad descriptor on the wire).
    let desc = Descriptor::<DescriptorPublicKey>::from_str(&format!(
        "wpkh([{fingerprint}/{path}]{pubkey})"
    ))
    .ok()?
    .to_string();
    Some(BtcKeyOrigin {
        desc,
        pubkey: pubkey.to_string(),
        fingerprint: fingerprint.to_string(),
    })
}

/// Parse a send's recipients against the wallet's network: `-5` for an address that does
/// not parse or belongs to another network, `-3` for a zero amount (Core's "Invalid
/// amount", as the Zcash send answers) and for a total above the supply cap.
///
/// The total check is what keeps the builder from panicking: each amount is already
/// range-checked at the RPC boundary, but nothing bounded their *sum*, and BDK sums the
/// recipients with `Amount`'s panicking `+` - so a `sendmany` of a few thousand
/// max-value recipients (well under the request-body limit) killed the actor task, and
/// with it every later command and the shutdown persist.
fn parse_recipients(
    recipients: &[(String, u64)],
    network: bdk_wallet::bitcoin::Network,
) -> Result<Vec<(Address, Amount)>, RpcError> {
    let mut parsed = Vec::with_capacity(recipients.len());
    let mut total: u64 = 0;
    for (addr, sats) in recipients {
        let address = Address::from_str(addr)
            .and_then(|a| a.require_network(network))
            .map_err(|_| {
                RpcError::invalid_address_or_key(format!("Invalid Bitcoin address: {addr}"))
            })?;
        if *sats == 0 {
            return Err(RpcError::type_error("Invalid amount"));
        }
        total = total
            .checked_add(*sats)
            .filter(|t| *t <= crate::amount::MAX_MONEY)
            .ok_or_else(|| {
                RpcError::type_error("Invalid amount: the recipients total more than 21000000 BTC")
            })?;
        parsed.push((address, Amount::from_sat(*sats)));
    }
    Ok(parsed)
}

/// The wallet's incremental relay fee for a default `bumpfee`, in sat/kvB: Bitcoin Core's
/// `WALLET_INCREMENTAL_RELAY_FEE` (5 sat/vB), deliberately above the node's 1 sat/vB so one
/// bump clears the replacement rules with room to spare rather than inching up.
const WALLET_INCREMENTAL_RELAY_FEE_SAT_PER_KVB: u64 = 5_000;

/// BIP 125's incremental relay fee, in sat/vB: what a replacement must add to the
/// original's total fee per virtual byte of its own size (Core's `-incrementalrelayfee`
/// default, and what BDK's rate rule adds too).
const INCREMENTAL_RELAY_FEE_SAT_PER_VB: u64 = 1;

/// Core's default `bumpfee` rate (`feebumper.cpp`'s `EstimateFeeRate`), in sat/kvB: the
/// original's rate rounded up, plus 1 sat/kvB, plus the wallet incremental relay fee -
/// or the upstream's estimate when that is higher.
fn default_bump_rate_sat_per_kvb(
    orig_fee_sat: u64,
    orig_vsize: u64,
    estimate_sat_per_kvb: Option<u64>,
) -> u64 {
    let orig_kvb = (orig_fee_sat * 1_000).div_ceil(orig_vsize.max(1));
    let floor = orig_kvb + 1 + WALLET_INCREMENTAL_RELAY_FEE_SAT_PER_KVB;
    estimate_sat_per_kvb.map_or(floor, |estimate| estimate.max(floor))
}

/// BIP 125 rule 4: the least total fee a replacement of `new_vsize` vbytes may pay - the
/// original's fee plus the incremental relay fee over the replacement's own size.
fn bump_total_fee_floor(orig_fee_sat: u64, new_vsize: u64) -> u64 {
    orig_fee_sat + INCREMENTAL_RELAY_FEE_SAT_PER_VB * new_vsize
}

/// Core's refusal for a replacement under [`bump_total_fee_floor`], `-8` with its message.
fn insufficient_bump_fee(fee_sat: u64, floor_sat: u64, orig_fee_sat: u64) -> RpcError {
    use crate::amount::zats_to_value;
    RpcError::invalid_parameter(format!(
        "Insufficient total fee {}, must be at least {} (oldFee {} + incrementalFee {})",
        zats_to_value(fee_sat),
        zats_to_value(floor_sat),
        zats_to_value(orig_fee_sat),
        zats_to_value(floor_sat - orig_fee_sat),
    ))
}

/// Refuse a send whose absolute fee exceeds `[fees] max_tx_fee_sat` - Core's `-maxtxfee`,
/// with Core's message and code (`-6`: Core's `SendMoney` surfaces every
/// `CreateTransaction` failure, this one included, as `RPC_WALLET_INSUFFICIENT_FUNDS`).
fn check_max_tx_fee(fee_sat: u64, max_sat: u64) -> Result<(), RpcError> {
    if fee_sat > max_sat {
        return Err(RpcError::new(
            codes::RPC_WALLET_INSUFFICIENT_FUNDS,
            format!(
                "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate): the \
                 transaction would pay {} BTC, above [fees] max_tx_fee_sat = {} BTC; nothing \
                 was broadcast",
                crate::amount::zats_to_value(fee_sat),
                crate::amount::zats_to_value(max_sat),
            ),
        ));
    }
    Ok(())
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
            encrypted: false,
            seed,
            imported_keys: None,
            endpoint: None,
            fees: crate::config::FeesConfig::default(),
            mempool: crate::config::MempoolConfig::default(),
            birthday: 0,
            birthday_time: None,
            lookahead: DEFAULT_LOOKAHEAD,
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
        assert!(handle.list_transactions(10, 0).await.unwrap().is_empty());
        assert_eq!(handle.tx_count().await.unwrap(), 0);

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
    fn an_output_pays_for_its_own_block_space() {
        let addr = |s: &str| Address::from_str(s).unwrap().assume_checked();
        // P2WPKH: 8 + 1 + 22 = 31 bytes; P2TR: 8 + 1 + 34 = 43 bytes.
        let wpkh = addr("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let tr = addr("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0");
        let rate = FeeRate::from_sat_per_vb_u32(10);
        assert_eq!(output_fee_share(rate, &wpkh.script_pubkey()), 310);
        assert_eq!(output_fee_share(rate, &tr.script_pubkey()), 430);
        // A fractional rate rounds up: 1.001 sat/vB is 251 sat/kwu (ceil), 31 vB -> 32 sat.
        assert_eq!(
            output_fee_share(FeeRate::from_sat_per_kwu(251), &wpkh.script_pubkey()),
            32
        );

        let parsed = vec![
            (wpkh.clone(), Amount::from_sat(10_000)),
            (tr.clone(), Amount::from_sat(20_000)),
            (wpkh.clone(), Amount::from_sat(30_000)),
        ];
        let out = subtract_output_shares(&parsed, &[0, 1], rate).unwrap();
        assert_eq!(out[0].1.to_sat(), 10_000 - 310);
        assert_eq!(out[1].1.to_sat(), 20_000 - 430);
        assert_eq!(
            out[2].1.to_sat(),
            30_000,
            "a non-paying recipient is untouched"
        );
        // An amount its own share would consume is refused, as Core refuses one the fee would.
        let tiny = vec![(wpkh.clone(), Amount::from_sat(310))];
        assert!(subtract_output_shares(&tiny, &[0], rate).is_err());
    }

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

    /// `listunspent.desc`/`getaddressinfo.desc` against the BIP 84 specification's own test
    /// vector: the `abandon ... about` mnemonic's first receiving key, with its origin.
    #[test]
    fn inferred_descriptor_matches_the_bip84_test_vector() {
        let keys = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Main).unwrap();
        let wallet = Wallet::create(
            keys.descriptor(KeychainKind::External),
            keys.descriptor(KeychainKind::Internal),
        )
        .network(keys.network)
        .create_wallet_no_persist()
        .unwrap();
        let origin = key_origin(&wallet, KeychainKind::External, 0).unwrap();
        assert_eq!(
            origin.pubkey,
            "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
        );
        assert_eq!(origin.fingerprint, "73c5da0a");
        let (body, checksum) = origin.desc.split_once('#').unwrap();
        assert_eq!(
            body,
            "wpkh([73c5da0a/84'/0'/0'/0/0]\
             0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c)"
        );
        assert_eq!(checksum.len(), 8);
    }

    /// The recipients' sum is bounded by the supply cap, including the exact-cap boundary
    /// and a sum that would wrap `u64` - the case BDK's panicking `Amount` add would hit.
    #[test]
    fn recipients_total_is_bounded_by_the_supply_cap() {
        let network = bdk_wallet::bitcoin::Network::Bitcoin;
        let a = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string();
        let max = crate::amount::MAX_MONEY;
        assert_eq!(
            parse_recipients(&[(a.clone(), max - 1), (a.clone(), 1)], network)
                .unwrap()
                .len(),
            2
        );
        for recipients in [
            vec![(a.clone(), max), (a.clone(), 1)],
            vec![(a.clone(), u64::MAX), (a.clone(), u64::MAX)],
        ] {
            let err = parse_recipients(&recipients, network).unwrap_err();
            assert_eq!(err.code, crate::error::codes::RPC_TYPE_ERROR);
        }
        // A testnet address on a mainnet wallet is -5, as Core answers.
        let err = parse_recipients(
            &[("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(), 1)],
            network,
        )
        .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_ADDRESS_OR_KEY);
    }

    /// The absolute-fee cap is inclusive (a fee exactly at the cap passes, as in Core) and
    /// answers Core's `-maxtxfee` message and code.
    #[test]
    fn the_absolute_fee_cap_refuses_only_above_the_cap() {
        assert!(check_max_tx_fee(10_000_000, 10_000_000).is_ok());
        let err = check_max_tx_fee(10_000_001, 10_000_000).unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_WALLET_INSUFFICIENT_FUNDS);
        assert!(err.message.contains("-maxtxfee"), "{}", err.message);
        assert!(err.message.contains("0.10000001"), "{}", err.message);
    }

    /// Core's default bump rate: the original's rate rounded up, plus 1 sat/kvB, plus the
    /// 5 sat/vB wallet increment - an estimate only ever raises it. And BIP 125 rule 4's
    /// floor is the old fee plus 1 sat/vB of the replacement's size, refused as Core's `-8`
    /// naming all four numbers.
    #[test]
    fn bump_fee_arithmetic_follows_core() {
        // 141 sat over 141 vB is exactly 1 sat/vB: 1000 + 1 + 5000 sat/kvB.
        assert_eq!(default_bump_rate_sat_per_kvb(141, 141, None), 6_001);
        // A fractional rate rounds up before the increments: 150/141 vB = 1063.8 -> 1064.
        assert_eq!(default_bump_rate_sat_per_kvb(150, 141, None), 6_065);
        // A higher estimate wins; a lower one does not undercut the increment.
        assert_eq!(
            default_bump_rate_sat_per_kvb(141, 141, Some(20_000)),
            20_000
        );
        assert_eq!(default_bump_rate_sat_per_kvb(141, 141, Some(2_000)), 6_001);
        assert_eq!(bump_total_fee_floor(141, 110), 251);
        let err = insufficient_bump_fee(200, 251, 141);
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_PARAMETER);
        assert_eq!(
            err.message,
            "Insufficient total fee 0.00000200, must be at least 0.00000251 \
             (oldFee 0.00000141 + incrementalFee 0.00000110)"
        );
    }

    /// What `do_bump_fee` relies on in BDK: `build_fee_bump` keeps the recipient, spends the
    /// original's input and pays at least the requested rate; the replacement, committed one
    /// second after the original's sighting (`commit_before_relay`'s `not_before`), is the
    /// canonical one - the original leaves `transactions()` and the balance counts the
    /// replacement's change - while a replacement stamped at the *same* second would be
    /// decided by txid order, which is why the floor exists.
    #[test]
    fn a_fee_bump_replaces_the_original_in_the_canonical_view() {
        use bdk_wallet::bitcoin::block::{Header, Version};
        use bdk_wallet::bitcoin::hashes::Hash as _;
        use bdk_wallet::bitcoin::{
            absolute, Block, CompactTarget, OutPoint, ScriptBuf, Sequence, TxIn, TxMerkleNode,
            TxOut, Txid, Witness,
        };
        use std::str::FromStr as _;
        let keys = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Regtest).unwrap();
        let mut wallet = Wallet::create(
            keys.descriptor(KeychainKind::External),
            keys.descriptor(KeychainKind::Internal),
        )
        .network(keys.network)
        .create_wallet_no_persist()
        .unwrap();
        let addr = wallet.reveal_next_address(KeychainKind::External).address;
        let funding = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_str(&"33".repeat(32)).unwrap(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: addr.script_pubkey(),
            }],
        };
        let block = Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: wallet.latest_checkpoint().hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 1,
            },
            txdata: vec![funding],
        };
        wallet.apply_block(&block, 1).unwrap();
        let signer = keys::signing_wallet(&bip84_seed(), BitcoinNetwork::Regtest).unwrap();
        let recipient = ScriptBuf::new_p2wpkh(&bdk_wallet::bitcoin::WPubkeyHash::all_zeros());
        let sign = |mut psbt: Psbt| {
            assert!(signer.sign(&mut psbt, SignOptions::default()).unwrap());
            Arc::new(psbt.extract_tx().unwrap())
        };

        let mut builder = wallet.build_tx();
        builder.add_recipient(recipient.clone(), Amount::from_sat(100_000));
        builder.fee_rate(FeeRate::from_sat_per_vb_u32(1));
        let original = sign(builder.finish().unwrap());
        let orig_txid = original.compute_txid();
        wallet.apply_unconfirmed_txs([(Arc::clone(&original), 1_800_000_000)]);
        let orig_fee = wallet.calculate_fee(&original).unwrap().to_sat();

        // Below BIP 125's rate rule BDK refuses, which `build_bump` maps to Core's -8.
        let mut builder = wallet.build_fee_bump(orig_txid).unwrap();
        builder.fee_rate(FeeRate::from_sat_per_vb_u32(1));
        assert!(matches!(
            builder.finish(),
            Err(bdk_wallet::error::CreateTxError::FeeRateTooLow { .. })
        ));

        let rate = default_bump_rate_sat_per_kvb(orig_fee, original.vsize() as u64, None);
        let mut builder = wallet.build_fee_bump(orig_txid).unwrap();
        builder.fee_rate(FeeRate::from_sat_per_kwu(rate.div_ceil(4)));
        let replacement = sign(builder.finish().unwrap());
        let new_txid = replacement.compute_txid();
        assert_eq!(
            replacement.input[0].previous_output,
            original.input[0].previous_output
        );
        assert!(replacement
            .output
            .iter()
            .any(|o| o.script_pubkey == recipient && o.value == Amount::from_sat(100_000)));
        let fee = wallet.calculate_fee(&replacement).unwrap().to_sat();
        assert!(fee >= bump_total_fee_floor(orig_fee, replacement.vsize() as u64));
        // BDK prices by weight (a rounded-up vsize reads fractionally under the rate).
        assert!(fee * 4_000 >= rate * replacement.weight().to_wu());

        wallet.apply_unconfirmed_txs([(Arc::clone(&replacement), 1_800_000_001)]);
        let canonical: Vec<Txid> = wallet.transactions().map(|t| t.tx_node.txid).collect();
        assert!(canonical.contains(&new_txid), "{canonical:?}");
        assert!(!canonical.contains(&orig_txid), "{canonical:?}");
        // A late mempool sighting of the original is dropped rather than applied: at a
        // later `last_seen` it would win back (drop_superseded_sightings).
        assert!(replaced_by_own_send(&wallet, &original));
        assert!(!replaced_by_own_send(&wallet, &replacement));
        let mut probe = wallet.tx_graph().clone();
        let _ = probe.insert_seen_at(orig_txid, 1_800_000_002);
        assert!(
            probe
                .list_canonical_txs(
                    wallet.local_chain(),
                    wallet.local_chain().tip().block_id(),
                    Default::default()
                )
                .any(|t| t.tx_node.txid == orig_txid),
            "the hazard the drop exists for"
        );
        assert_eq!(
            wallet.balance().trusted_pending,
            Amount::from_sat(1_000_000 - 100_000 - fee)
        );
        // The original stays in the graph, non-canonical: a retired replacement brings it
        // back.
        assert!(wallet.tx_graph().get_tx(orig_txid).is_some());
        wallet.apply_evicted_txs([(new_txid, 1_800_000_002)]);
        assert!(wallet.get_tx(orig_txid).is_some());
        assert!(wallet.get_tx(new_txid).is_none());
    }

    /// Ancestor-aware funding over a real wallet: a send that can only spend the change of
    /// a 1 sat/vB send pays for that parent, so the pair confirms at the child's rate; a
    /// foreign unconfirmed payment is not a candidate at all.
    #[test]
    fn a_send_from_unconfirmed_change_pays_for_its_parent() {
        use crate::btc::ancestors::AncestorAware;
        use bdk_wallet::bitcoin::block::{Header, Version};
        use bdk_wallet::bitcoin::hashes::Hash as _;
        use bdk_wallet::bitcoin::{
            absolute, Block, CompactTarget, OutPoint, ScriptBuf, Sequence, TxIn, TxMerkleNode,
            TxOut, Txid, Witness,
        };
        use std::str::FromStr as _;
        let keys = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Regtest).unwrap();
        let mut wallet = Wallet::create(
            keys.descriptor(KeychainKind::External),
            keys.descriptor(KeychainKind::Internal),
        )
        .network(keys.network)
        .create_wallet_no_persist()
        .unwrap();
        let addr = wallet.reveal_next_address(KeychainKind::External).address;
        let pay = |prev: &str, value: u64| Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_str(&prev.repeat(32)).unwrap(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: addr.script_pubkey(),
            }],
        };
        let block = Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: wallet.latest_checkpoint().hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 1,
            },
            txdata: vec![pay("33", 1_000_000)],
        };
        wallet.apply_block(&block, 1).unwrap();
        let signer = keys::signing_wallet(&bip84_seed(), BitcoinNetwork::Regtest).unwrap();
        let recipient = ScriptBuf::new_p2wpkh(&bdk_wallet::bitcoin::WPubkeyHash::all_zeros());
        let sign = |mut psbt: Psbt| {
            assert!(signer.sign(&mut psbt, SignOptions::default()).unwrap());
            Arc::new(psbt.extract_tx().unwrap())
        };
        let funded = |wallet: &Wallet| -> HashSet<Txid> {
            wallet
                .transactions()
                .filter(|wtx| wallet.sent_and_received(&wtx.tx_node.tx).0 > Amount::ZERO)
                .map(|wtx| wtx.tx_node.txid)
                .collect()
        };

        // The parent: 1 sat/vB, leaving its change as the wallet's only coin.
        let mut builder = wallet.build_tx();
        builder.add_recipient(recipient.clone(), Amount::from_sat(100_000));
        builder.fee_rate(FeeRate::from_sat_per_vb_u32(1));
        let parent = sign(builder.finish().unwrap());
        wallet.apply_unconfirmed_txs([(Arc::clone(&parent), 1_800_000_000)]);
        let parent_fee = wallet.calculate_fee(&parent).unwrap().to_sat();
        // And a foreign sender's unconfirmed payment, which the wallet cannot price.
        let foreign = Arc::new(pay("44", 5_000_000));
        wallet.apply_unconfirmed_txs([(Arc::clone(&foreign), 1_800_000_000)]);

        let ancestry = Arc::new(wallet_ancestry(&wallet, &funded(&wallet)));
        assert!(ancestry.is_spendable(&parent.compute_txid()));
        assert!(!ancestry.is_spendable(&foreign.compute_txid()));

        // The child at 10 sat/vB, the foreign coin withheld as `do_send` withholds it.
        let rate = FeeRate::from_sat_per_vb_u32(10);
        let selection = AncestorAware::new(Arc::clone(&ancestry), rate);
        let paid = selection.paid();
        let mut builder = wallet.build_tx().coin_selection(selection);
        builder.unspendable(vec![OutPoint::new(foreign.compute_txid(), 0)]);
        builder.add_recipient(recipient.clone(), Amount::from_sat(100_000));
        builder.fee_rate(rate);
        let child = sign(builder.finish().unwrap());
        assert!(child
            .input
            .iter()
            .all(|i| i.previous_output.txid == parent.compute_txid()));
        let child_fee = wallet.calculate_fee(&child).unwrap().to_sat();
        let paid = paid.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(paid, 10 * parent.vsize() as u64 - parent_fee);
        // The package clears the child's rate - by weight, as BDK prices (a rounded-up
        // vsize reads fractionally under the rate).
        let package_wu = parent.weight().to_wu() + child.weight().to_wu();
        assert!(
            (parent_fee + child_fee) * 4 >= 10 * package_wu,
            "package {} sat over {package_wu} WU",
            parent_fee + child_fee
        );
        // And the child alone pays its own rate plus exactly the parent's shortfall.
        assert!(child_fee >= paid + 10 * child.vsize() as u64 - 10);
    }

    /// `replaceable = false` rides on BDK's `set_exact_sequence`: the default build signals
    /// BIP 125 on every input, the exact sequence `do_send` passes signals it on none (and
    /// keeps the locktime enforced, so anti-fee-sniping still applies). Pins the BDK
    /// behavior the RPC flag depends on.
    #[test]
    fn a_non_replaceable_send_signals_no_rbf() {
        use bdk_wallet::bitcoin::{absolute, ScriptBuf, Sequence, TxIn, TxOut, Witness};
        let keys = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Regtest).unwrap();
        let mut wallet = Wallet::create(
            keys.descriptor(KeychainKind::External),
            keys.descriptor(KeychainKind::Internal),
        )
        .network(keys.network)
        .create_wallet_no_persist()
        .unwrap();
        let own = wallet.reveal_next_address(KeychainKind::External).address;
        let receive = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_str(&"22".repeat(32)).unwrap(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: own.script_pubkey(),
            }],
        };
        wallet.apply_unconfirmed_txs([(receive, 1_700_000_000)]);
        let build = |wallet: &mut Wallet, sequence: Option<Sequence>| {
            let mut builder = wallet.build_tx();
            builder.add_recipient(own.script_pubkey(), Amount::from_sat(10_000));
            builder.fee_rate(FeeRate::from_sat_per_vb_u32(1));
            if let Some(sequence) = sequence {
                builder.set_exact_sequence(sequence);
            }
            builder.finish().unwrap().unsigned_tx
        };
        let default = build(&mut wallet, None);
        assert!(default.is_explicitly_rbf());
        let non_rbf = build(&mut wallet, Some(Sequence::ENABLE_LOCKTIME_NO_RBF));
        assert!(!non_rbf.is_explicitly_rbf());
        assert!(non_rbf
            .input
            .iter()
            .all(|i| i.sequence.enables_absolute_lock_time()));
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

        // Recipients are validated before the upstream is needed, so a bad one answers the
        // same offline as online: -5 for an address, -3 for a zero amount or a total past
        // the supply cap. The last used to panic inside BDK's `Amount` sum and kill the
        // actor, so the follow-up call proves it is still serving.
        let good = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string();
        let err = handle
            .send(
                vec![("bc1qnotanaddress".to_string(), 10_000)],
                BtcSendOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_ADDRESS_OR_KEY);
        let err = handle
            .send(vec![(good.clone(), 0)], BtcSendOptions::default())
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_TYPE_ERROR);
        let max = crate::amount::MAX_MONEY;
        let err = handle
            .send(
                vec![(good.clone(), max), (good.clone(), max)],
                BtcSendOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_TYPE_ERROR);
        assert!(err.message.contains("total"), "{}", err.message);
        let err = handle
            .send(vec![(good, 10_000)], BtcSendOptions::default())
            .await
            .unwrap_err();
        assert!(err.message.contains("upstream"), "{}", err.message);

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

    /// The commit-then-relay order withdraws a record with an eviction stamped at the
    /// **same second** as the sighting - a persist failure before the relay, a node
    /// rejection right after it - and that only works because BDK keeps an unconfirmed
    /// transaction canonical strictly while `last_evicted < last_seen`: a tie excludes it.
    /// If this starts failing, BDK changed the rule and `commit_before_relay` /
    /// `relay_committed` must stamp the eviction one second past `seen_at` instead.
    #[test]
    fn an_eviction_at_the_sighting_timestamp_withdraws_the_record() {
        use bdk_wallet::bitcoin::{absolute, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};
        let keys = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Regtest).unwrap();
        let mut wallet = Wallet::create(
            keys.descriptor(KeychainKind::External),
            keys.descriptor(KeychainKind::Internal),
        )
        .network(keys.network)
        .create_wallet_no_persist()
        .unwrap();
        let own = wallet.reveal_next_address(KeychainKind::External).address;
        let receive = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_str(&"11".repeat(32)).unwrap(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(5_000),
                script_pubkey: own.script_pubkey(),
            }],
        };
        let txid = receive.compute_txid();
        let seen_at = 1_700_000_100;
        wallet.apply_unconfirmed_txs([(receive, seen_at)]);
        assert_eq!(
            wallet.transactions().count(),
            1,
            "the sighting is canonical"
        );
        assert_eq!(wallet.balance().untrusted_pending.to_sat(), 5_000);

        wallet.apply_evicted_txs([(txid, seen_at)]);
        assert_eq!(
            wallet.transactions().count(),
            0,
            "an eviction at the sighting's own timestamp withdraws it"
        );
        assert_eq!(wallet.balance().total().to_sat(), 0);
        assert!(
            wallet.list_unspent().next().is_none(),
            "the withdrawn output is no longer spendable"
        );

        // And the other direction, which a resubmission of an abandoned transaction rides:
        // a sighting at the eviction's own second changes nothing, one second past it
        // re-canonicalizes - so `commit_before_relay` stamps at least `last_evicted + 1`.
        let (tx, _) = wallet
            .tx_graph()
            .full_txs()
            .next()
            .map(|n| (n.tx.clone(), n.txid))
            .unwrap();
        wallet.apply_unconfirmed_txs([(tx.clone(), seen_at)]);
        assert_eq!(wallet.transactions().count(), 0, "a tie stays evicted");
        wallet.apply_unconfirmed_txs([(tx, seen_at + 1)]);
        assert_eq!(
            wallet.transactions().count(),
            1,
            "a sighting past the eviction re-canonicalizes"
        );
        assert_eq!(wallet.balance().untrusted_pending.to_sat(), 5_000);
    }

    /// A coinbase reward reports Core's `orphan`/`immature`/`generate` by depth, on every
    /// own output, instead of a `receive` the balance does not count; a foreign output of
    /// a coinbase (another miner's) appears nowhere.
    #[test]
    fn coinbase_outputs_carry_cores_reward_categories() {
        for keychain in [KeychainKind::External, KeychainKind::Internal] {
            assert_eq!(categories(false, Some(keychain), Some(0)), &["orphan"]);
            assert_eq!(categories(false, Some(keychain), Some(1)), &["immature"]);
            assert_eq!(
                categories(false, Some(keychain), Some(u64::from(COINBASE_MATURITY))),
                &["immature"]
            );
            assert_eq!(
                categories(
                    false,
                    Some(keychain),
                    Some(u64::from(COINBASE_MATURITY) + 1)
                ),
                &["generate"]
            );
        }
        assert!(categories(false, None, Some(5)).is_empty());
        // The ordinary shapes are unchanged.
        assert_eq!(categories(true, None, None), &["send"]);
        assert_eq!(
            categories(true, Some(KeychainKind::External), None),
            &["send", "receive"]
        );
        assert!(categories(true, Some(KeychainKind::Internal), None).is_empty());
        assert_eq!(
            categories(false, Some(KeychainKind::External), None),
            &["receive"]
        );
    }

    #[test]
    fn classify_rejection_reads_core_verdicts() {
        use Parents::*;
        use RebroadcastVerdict::*;
        assert_eq!(
            classify_rejection(-27, "Transaction already in block chain", Confirmed),
            AlreadyInChain
        );
        // Missing inputs over confirmed wallet parents: a conflict confirmed.
        assert_eq!(
            classify_rejection(-25, "Missing inputs", Confirmed),
            ConfirmedConflict
        );
        assert_eq!(
            classify_rejection(-25, "bad-txns-inputs-missingorspent", Confirmed),
            ConfirmedConflict
        );
        // The same text while waiting on an own unconfirmed parent is a dependency.
        assert_eq!(classify_rejection(-25, "Missing inputs", WaitsOnOwn), Retry);
        // And over a foreign parent (every received payment) it proves nothing: Core says
        // it for an unconfirmed parent it no longer holds too, so tombstoning here retired
        // valid 0-conf receives after a node restart without mempool persistence.
        assert_eq!(classify_rejection(-25, "Missing inputs", Foreign), Retry);
        // The reorg shape and the policy family both retry.
        assert_eq!(classify_rejection(-26, "non-final", Confirmed), Retry);
        assert_eq!(
            classify_rejection(-26, "min relay fee not met", Confirmed),
            Retry
        );
        assert_eq!(
            classify_rejection(-26, "txn-mempool-conflict", Confirmed),
            Retry
        );
        // An unfamiliar -25 is not read as a conflict.
        assert_eq!(
            classify_rejection(-25, "mandatory-script-verify-flag-failed", Confirmed),
            Retry
        );
    }

    #[test]
    fn order_parents_first_puts_a_spent_from_transaction_ahead_of_its_spender() {
        use bdk_wallet::bitcoin::{
            absolute, transaction, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness,
        };
        fn tx(inputs: &[OutPoint]) -> Arc<Transaction> {
            Arc::new(Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: inputs
                    .iter()
                    .map(|&previous_output| TxIn {
                        previous_output,
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                        witness: Witness::new(),
                    })
                    .collect(),
                output: vec![TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: ScriptBuf::new(),
                }],
            })
        }
        fn candidate(tx: Arc<Transaction>) -> RebroadcastCandidate {
            RebroadcastCandidate {
                txid: tx.compute_txid(),
                tx,
                parents: Parents::Confirmed,
            }
        }
        let external = OutPoint::new(Txid::from_str(&"11".repeat(32)).unwrap(), 0);
        let parent = tx(&[external]);
        let child = tx(&[OutPoint::new(parent.compute_txid(), 0)]);
        let grandchild = tx(&[OutPoint::new(child.compute_txid(), 0)]);
        let unrelated = tx(&[OutPoint::new(Txid::from_str(&"22".repeat(32)).unwrap(), 1)]);
        // Fed children-first, they come out parents-first; the unrelated one keeps its
        // relative position among the ready set.
        let ordered = order_parents_first(vec![
            candidate(grandchild.clone()),
            candidate(child.clone()),
            candidate(unrelated.clone()),
            candidate(parent.clone()),
        ]);
        let ids: Vec<Txid> = ordered.iter().map(|c| c.txid).collect();
        assert_eq!(
            ids,
            vec![
                unrelated.compute_txid(),
                parent.compute_txid(),
                child.compute_txid(),
                grandchild.compute_txid(),
            ]
        );
        assert!(order_parents_first(Vec::new()).is_empty());
    }

    /// Pins a BDK behaviour: a transaction whose anchor reorged out of
    /// the best chain stays canonical as "unconfirmed" no matter what evictions are applied:
    /// with no `last_seen`, seen-then-evicted after the reorg, or seen-then-evicted
    /// before it. `bdk_chain`'s canonicalization routes such a transaction through its
    /// leftover path, which never consults `last_evicted`. So neither the rebroadcast
    /// pass's `-25` verdict nor a kyoto-side rule can retire a reorged-out receive whose
    /// conflict the wallet has not seen; the fix is the persistence-level retirement the
    /// issue describes. If this test starts failing, BDK changed - re-check the issue.
    #[test]
    fn bdk_keeps_a_reorged_out_transaction_canonical_despite_evictions() {
        use bdk_wallet::bitcoin::block::{Header, Version};
        use bdk_wallet::bitcoin::hashes::Hash as _;
        use bdk_wallet::bitcoin::{
            absolute, Block, CompactTarget, OutPoint, ScriptBuf, Sequence, TxIn, TxMerkleNode,
            TxOut, Txid, Witness,
        };
        use std::str::FromStr as _;
        let keys = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Regtest).unwrap();
        let build = || {
            Wallet::create(
                keys.descriptor(KeychainKind::External),
                keys.descriptor(KeychainKind::Internal),
            )
            .network(keys.network)
            .create_wallet_no_persist()
            .unwrap()
        };
        let block =
            |prev: bdk_wallet::bitcoin::BlockHash, nonce: u32, txs: Vec<Transaction>| Block {
                header: Header {
                    version: Version::TWO,
                    prev_blockhash: prev,
                    merkle_root: TxMerkleNode::all_zeros(),
                    time: 1_700_000_000 + nonce,
                    bits: CompactTarget::from_consensus(0x207f_ffff),
                    nonce,
                },
                txdata: txs,
            };
        // A receive confirmed at 3, then a reorg replacing 3 (and adding 4). `before`
        // runs between confirmation and reorg, `after` once the reorg is applied.
        let run = |before: &dyn Fn(&mut Wallet, &Transaction, Txid),
                   after: &dyn Fn(&mut Wallet, &Transaction, Txid)| {
            let mut wallet = build();
            let addr = wallet.reveal_next_address(KeychainKind::External).address;
            let receive = Transaction {
                version: bdk_wallet::bitcoin::transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::new(Txid::from_str(&"22".repeat(32)).unwrap(), 0),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(50_000_000),
                    script_pubkey: addr.script_pubkey(),
                }],
            };
            let txid = receive.compute_txid();
            let b1 = block(wallet.latest_checkpoint().hash(), 1, vec![]);
            wallet.apply_block(&b1, 1).unwrap();
            let b2 = block(b1.block_hash(), 2, vec![]);
            wallet.apply_block(&b2, 2).unwrap();
            let b3 = block(b2.block_hash(), 3, vec![receive.clone()]);
            wallet.apply_block(&b3, 3).unwrap();
            assert_eq!(wallet.balance().confirmed, Amount::from_sat(50_000_000));
            before(&mut wallet, &receive, txid);
            let b3b = block(b2.block_hash(), 33, vec![]);
            wallet.apply_block(&b3b, 3).unwrap();
            let b4 = block(b3b.block_hash(), 4, vec![]);
            wallet.apply_block(&b4, 4).unwrap();
            after(&mut wallet, &receive, txid);
            let balance = wallet.balance();
            assert_eq!(balance.confirmed, Amount::ZERO);
            let listed = wallet.transactions().any(|t| t.tx_node.txid == txid);
            (balance.untrusted_pending, listed)
        };
        let pending = Amount::from_sat(50_000_000);
        // Evicted with no last_seen at all.
        assert_eq!(
            run(&|_, _, _| {}, &|w, _, id| w
                .apply_evicted_txs([(id, 1_800_000_000)])),
            (pending, true)
        );
        // Seen, then evicted, both after the reorg.
        assert_eq!(
            run(&|_, _, _| {}, &|w, tx, id| {
                w.apply_unconfirmed_txs([(tx.clone(), 1_800_000_001)]);
                w.apply_evicted_txs([(id, 1_800_000_002)]);
            }),
            (pending, true)
        );
        // Seen while still anchored (bitcoind's ordering), evicted after the reorg.
        assert_eq!(
            run(
                &|w, tx, _| w.apply_unconfirmed_txs([(tx.clone(), 1_700_000_100)]),
                &|w, _, id| w.apply_evicted_txs([(id, 1_700_000_200)])
            ),
            (pending, true)
        );
    }

    /// The `listtransactions` window is Core's: entries oldest first, `skip` from the newest
    /// end, then `count`; a boundary inside one transaction's fan-out trims that record to
    /// the entries within the window; and only the window is built. The count is the
    /// transaction total, visible entries or not.
    #[test]
    fn history_window_pages_entries_like_core() {
        use bdk_wallet::bitcoin::block::{Header, Version};
        use bdk_wallet::bitcoin::hashes::Hash as _;
        use bdk_wallet::bitcoin::{
            absolute, Block, CompactTarget, OutPoint, ScriptBuf, Sequence, TxIn, TxMerkleNode,
            TxOut, Txid, Witness,
        };
        use std::str::FromStr as _;
        let keys = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Regtest).unwrap();
        let mut wallet = Wallet::create(
            keys.descriptor(KeychainKind::External),
            keys.descriptor(KeychainKind::Internal),
        )
        .network(keys.network)
        .create_wallet_no_persist()
        .unwrap();
        let block =
            |prev: bdk_wallet::bitcoin::BlockHash, nonce: u32, txs: Vec<Transaction>| Block {
                header: Header {
                    version: Version::TWO,
                    prev_blockhash: prev,
                    merkle_root: TxMerkleNode::all_zeros(),
                    time: 1_700_000_000 + nonce,
                    bits: CompactTarget::from_consensus(0x207f_ffff),
                    nonce,
                },
                txdata: txs,
            };
        let pay = |outputs: Vec<(ScriptBuf, u64)>, salt: u8| Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(
                    Txid::from_str(&format!("{salt:02x}").repeat(32)).unwrap(),
                    0,
                ),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: outputs
                .into_iter()
                .map(|(spk, value)| TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: spk,
                })
                .collect(),
        };
        let a0 = wallet.reveal_next_address(KeychainKind::External).address;
        let a1 = wallet.reveal_next_address(KeychainKind::External).address;
        let a2 = wallet.reveal_next_address(KeychainKind::External).address;
        // Block 1: one transaction paying two wallet outputs (two entries). Block 2: one
        // output (one entry). Then an unconfirmed receive (one entry, sorts last).
        let two = pay(
            vec![(a0.script_pubkey(), 1_000), (a1.script_pubkey(), 2_000)],
            0x11,
        );
        let one = pay(vec![(a2.script_pubkey(), 3_000)], 0x22);
        let mempool = pay(vec![(a0.script_pubkey(), 4_000)], 0x33);
        let b1 = block(wallet.latest_checkpoint().hash(), 1, vec![two.clone()]);
        wallet.apply_block(&b1, 1).unwrap();
        let b2 = block(b1.block_hash(), 2, vec![one.clone()]);
        wallet.apply_block(&b2, 2).unwrap();
        wallet.apply_unconfirmed_txs([(mempool.clone(), 1_700_000_100)]);
        assert_eq!(wallet.transactions().count(), 3);

        let flat = |records: Vec<BtcTxRecord>| -> Vec<(String, i64)> {
            records
                .iter()
                .flat_map(|r| {
                    r.details
                        .iter()
                        .map(move |d| (r.txid.clone(), d.amount_sat))
                })
                .collect()
        };
        let (t2, t1, tm) = (
            two.compute_txid().to_string(),
            one.compute_txid().to_string(),
            mempool.compute_txid().to_string(),
        );
        // Everything, oldest first: the block-1 pair, block 2, then the mempool receive.
        let all = tx_history(&wallet, 10, 0);
        assert!(
            all.iter().all(|r| r.hex.is_none()),
            "a listing carries no hex"
        );
        assert_eq!(
            flat(all),
            vec![
                (t2.clone(), 1_000),
                (t2.clone(), 2_000),
                (t1.clone(), 3_000),
                (tm.clone(), 4_000)
            ]
        );
        // The newest one.
        assert_eq!(flat(tx_history(&wallet, 1, 0)), vec![(tm.clone(), 4_000)]);
        // Skip the newest, take two: the boundary falls inside the block-1 pair, which is
        // trimmed to its second entry.
        assert_eq!(
            flat(tx_history(&wallet, 2, 1)),
            vec![(t2.clone(), 2_000), (t1.clone(), 3_000)]
        );
        // The oldest entry alone, through the other boundary.
        assert_eq!(flat(tx_history(&wallet, 1, 3)), vec![(t2.clone(), 1_000)]);
        // Past either end: nothing.
        assert!(tx_history(&wallet, 0, 0).is_empty());
        assert!(tx_history(&wallet, 5, 4).is_empty());
        assert!(tx_history(&wallet, 5, 40).is_empty());
        // A single lookup carries the hex and the whole fan-out.
        let wtx = wallet.get_tx(two.compute_txid()).unwrap();
        let entry = tx_entry(&wallet, &wtx, true);
        assert_eq!(entry.details.len(), 2);
        assert_eq!(entry.confirmations, 2);
        assert_eq!(
            entry.hex.as_deref(),
            Some(bdk_wallet::bitcoin::consensus::encode::serialize_hex(&two).as_str())
        );
    }
}
