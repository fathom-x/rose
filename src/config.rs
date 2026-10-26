//! Daemon configuration: a TOML file plus CLI overrides, resolved into [`AppConfig`].
//!
//! CLI flags use Bitcoin-Core-style names (`-rpcuser`, `-rpcport`, `-datadir`, `-testnet`)
//! where it helps operators, but the canonical source is the TOML config.

use std::collections::BTreeMap;
use std::net::IpAddr;
#[cfg(feature = "zcash")]
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
#[cfg(feature = "zcash")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "zcash")]
use std::sync::Arc;

use anyhow::Context;
#[cfg(feature = "cli")]
use clap::Parser;
use serde::Deserialize;
#[cfg(feature = "zcash")]
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;

use crate::coin::{Coin, CoinNetwork};
use crate::network::ZNetwork;
#[cfg(feature = "zcash")]
use crate::pools::{Receiver, ReceiverSet};
use crate::secret::Password;

/// Default chain upstream: a local zebrad's JSON-RPC ("full mode"). Public keeps the bare
/// `zebra` shorthand as the default rather than spelling the authority out; `backend::resolve`
/// expands it to `127.0.0.1:8234` on mainnet / `:18234` on testnet and regtest (see
/// `backend::ZEBRA_RPC_PORT_*`). A zebrad on another host/port is
/// `[backend] server = "zebra://host:port"`, and `backend::resolve` documents the full token
/// grammar including the light-mode forms.
pub const DEFAULT_SERVER: &str = "zebra";

/// The built-in `server` token for `network`, used when neither `--server` nor `[backend]
/// server` is set. Network-independent here, since the shorthand resolves per network.
/// (`backend::tests::default_server_resolves_to_local_zebrad_per_network` pins that.)
pub fn default_server(_network: ZNetwork) -> &'static str {
    DEFAULT_SERVER
}

/// The default directory for wallet `name`: `<datadir>/<name>`.
///
/// A wallet directory holds `keys.toml` - the one file in it that is rose's own, and the only
/// one a from-seed restore cannot rebuild - plus one subdirectory per coin ([`coin_dir`]).
/// The data directory itself holds only daemon-level files (`rose.toml`, `.lock`, `.cookie`,
/// `identity.txt`).
///
/// A `[wallets.<name>] dir` override replaces this outright; everything below is still laid
/// out inside whatever path the operator names.
pub fn wallet_dir(datadir: &Path, name: &str) -> PathBuf {
    datadir.join(name)
}

/// Where `coin`'s state lives inside `parent`: `<parent>/zec` for Zcash ([`Coin::data_dir`]).
///
/// `parent` is a wallet directory for a configured wallet, and the fleet root ([`fleet_root`])
/// for the fleet. Either way the coin sits one level inside the unit that owns it, never above
/// it: a wallet's `keys.toml` wraps a BIP-39 seed that serves every coin and so must sit above
/// the per-coin directories, and the fleet keeps the same shape for a different reason - see
/// [`fleet_root`].
pub fn coin_dir(parent: &Path, coin: Coin) -> PathBuf {
    parent.join(coin.data_dir())
}

/// The fleet's root: `<datadir>/fleet`, holding one coin directory
/// ([`fleet_coin_dir`]) and nothing else.
///
/// The fleet is the outer unit and the coin sits inside it, mirroring
/// `<datadir>/<wallet>/<coin>/` - so a datadir's top level is a list of *units* (wallets, plus
/// the fleet) rather than a mix of units and currencies. That ordering also keeps the reserved
/// names down to one: `wallet_dir` is `datadir.join(name)`, so anything rose puts at the datadir
/// root is a name a `[wallets.<name>]` entry could claim. One reserved `fleet` is checkable
/// ([`fleet_path_conflict`]); a reserved name per coin token would mean a wallet called `zec`
/// silently sharing a directory with the fleet.
///
/// Everything below is coin-scoped for the fleet's own reasons - see [`fleet_manifest_dir`] and
/// [`fleet_dir`].
pub fn fleet_root(datadir: &Path) -> PathBuf {
    datadir.join(DEFAULT_FLEET_ROOT)
}

/// Where `coin`'s fleet state lives: `<datadir>/fleet/zec` for Zcash.
pub fn fleet_coin_dir(datadir: &Path, coin: Coin) -> PathBuf {
    coin_dir(&fleet_root(datadir), coin)
}

/// Where the fleet's wallet manifests live by default: `<datadir>/fleet/zec/wallets.d`.
///
/// Coin-scoped, unlike `keys.toml`, because a manifest holds a **UFVK** and a UFVK is not the
/// cross-coin secret a mnemonic is: "unified" there means unified across Zcash's shielded pools,
/// not across currencies, and no other coin's viewing key can be derived from one. A second coin
/// therefore gets a sibling manifest directory with its own wallets, not a share of this one.
///
/// It is named under the fleet rather than beside it because `<datadir>/<wallet>/` directories
/// are wallets too: at the datadir root, `wallets.d` would read as rose's wallets in general
/// rather than the fleet's.
///
/// A `[fleet] manifest_dir` override replaces this outright, exactly as `[wallets.<name>] dir`
/// does for a wallet.
pub fn fleet_manifest_dir(datadir: &Path, coin: Coin) -> PathBuf {
    fleet_coin_dir(datadir, coin).join(DEFAULT_FLEET_MANIFEST_DIR)
}

/// Where the fleet's shard databases live by default: `<datadir>/fleet/zec/shards`, holding one
/// `shard-NNNN/` directory per shard.
///
/// The coin sits **above** the shard index rather than below it. A shard is a scan domain, and
/// which shard a wallet lands in is decided by its birthday - a block height on one chain - so
/// `shard-0000` is a per-coin membership decision. Nesting the coin inside the shard would claim
/// that shard numbering means the same thing on every chain, which it cannot.
///
/// The `shards` level of its own keeps that numbered namespace clean:
/// [`crate::fleet::existing_shard_dirs`] enumerates `shard-NNNN` by pattern from index 0, so the
/// series must not share a parent with a named directory like `wallets.d`.
pub fn fleet_dir(datadir: &Path, coin: Coin) -> PathBuf {
    fleet_coin_dir(datadir, coin).join(DEFAULT_FLEET_SHARD_DIR)
}

/// Where a shard's engine files live: `<shard dir>/lrz` for Zcash ([`Coin::engine_dir`]).
///
/// The coin level is already above the shards directory ([`fleet_dir`]), so a shard directory
/// takes only the engine level - which it takes for the same reason a wallet does: what
/// librustzcash owns stays separable from rose's own shard-index namespace, so replacing the
/// storage library is a sibling directory and a rescan.
pub fn shard_engine_dir(shard_dir: &Path, coin: Coin) -> PathBuf {
    shard_dir.join(coin.engine_dir())
}

/// The first wallet whose directory overlaps one of the fleet's, with the two paths.
///
/// `wallet_dir` is `datadir.join(name)`, so a wallet named after anything rose puts at the
/// datadir root claims that path - a wallet called `fleet` resolves to [`fleet_root`] itself.
/// Nothing would be *overwritten* (the fleet's files sit deeper), but one directory would hold
/// two owners' state, `rose rescan` on that wallet would delete through it, and a backup scoped
/// to the wallet would silently carry viewing keys. An explicit `[wallets.<name>] dir` or a
/// `[fleet]` override can produce the same overlap from either side, so the test is containment
/// in both directions rather than a reserved-name list.
#[cfg(feature = "zcash")]
pub fn fleet_path_conflict(
    wallets: &BTreeMap<String, WalletEntry>,
    fleet: &FleetConfig,
) -> Option<(String, PathBuf, PathBuf)> {
    for (name, entry) in wallets {
        for fleet_path in [&fleet.manifest_dir, &fleet.dir] {
            if fleet_path.starts_with(&entry.dir) || entry.dir.starts_with(fleet_path) {
                return Some((name.clone(), entry.dir.clone(), fleet_path.clone()));
            }
        }
    }
    None
}

/// Where the wallet-storage engine's own files live: `<wallet dir>/zec/lrz` for Zcash, holding
/// everything librustzcash owns - `data.sqlite`, plus the `blockmeta.sqlite` and `blocks/` an
/// older rose's on-disk block cache left behind ([`Coin::engine_dir`]).
///
/// Nothing outside these functions and [`crate::migrate`] should join a coin or engine
/// directory name onto a path: callers take a wallet directory from [`WalletEntry::dir`] and an
/// engine directory from [`WalletEntry::engine_dir`].
pub fn engine_dir(wallet_dir: &Path, coin: Coin) -> PathBuf {
    coin_dir(wallet_dir, coin).join(coin.engine_dir())
}

/// Where the Bitcoin engine's kyoto light client keeps its own store: `<wallet dir>/btc/kyoto`.
///
/// A fourth path helper rather than a literal join at the call site, for the reason the three
/// above give. It sits beside the BDK database ([`engine_dir`]) rather than inside it because
/// it belongs to the *chain source*, not the wallet: block headers, filter headers and a peer
/// book, all public chain data that any node could refetch. Deleting it costs a re-sync of
/// headers and nothing else - no wallet state lives here.
#[cfg(feature = "bitcoin")]
pub fn btc_kyoto_dir(wallet_dir: &Path) -> PathBuf {
    coin_dir(wallet_dir, Coin::Bitcoin).join("kyoto")
}

/// Binary configuration defaults (config file, datadir, ports).
pub struct BinaryDefaults {
    /// Config file name looked up inside the datadir (`rose.toml`).
    pub conf_file: &'static str,
    /// Default datadir when neither CLI nor env supplies one.
    pub datadir: &'static str,
    /// Environment variable consulted for the datadir.
    pub datadir_env: &'static str,
    /// Default RPC port on mainnet / test+regtest.
    pub rpc_port_main: u16,
    pub rpc_port_test: u16,
    /// Default health-probe port.
    pub health_port: u16,
}

/// The config file name from before the `zecd` -> `rose` rename. A datadir that holds one and
/// no [`BinaryDefaults::conf_file`] is refused rather than silently started on defaults: the
/// operator renames the file (nothing inside it changed).
pub const LEGACY_CONF_FILE: &str = "zecd.toml";

pub const ROSE_DEFAULTS: BinaryDefaults = BinaryDefaults {
    conf_file: "rose.toml",
    datadir: "./rose-data",
    datadir_env: "ROSE_DATADIR",
    rpc_port_main: 8232,
    rpc_port_test: 18232,
    health_port: 9233,
};

/// Resolve the upstream `server` token by precedence: CLI `--server` > file `server` >
/// built-in default (a local zebrad).
fn select_server_token(cli_server: Option<String>, file_server: Option<String>) -> String {
    cli_server
        .or(file_server)
        .unwrap_or_else(|| DEFAULT_SERVER.to_string())
}

/// Read a single secret (e.g. the RPC password) from a file, trimming a trailing newline/CR
/// (the common `echo "secret" > file` gotcha) but preserving any other surrounding whitespace.
/// Used for `[rpc] password_file` so the secret can live in a mounted Secret, not the TOML.
fn read_secret_file(path: &std::path::Path) -> anyhow::Result<Password> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading secret file {}", path.display()))?;
    Ok(Password::new(raw.trim_end_matches(['\n', '\r'])))
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub network: ZNetwork,
    /// Which public Bitcoin test network this (testnet) daemon's Bitcoin wallets use - the
    /// top-level `btc_testnet` key, already applied to every Bitcoin [`WalletEntry::chain`].
    /// Carried here so `config show` can render the effective value even when no Bitcoin
    /// wallet is configured yet.
    #[cfg(feature = "bitcoin")]
    pub btc_testnet: crate::coin::BitcoinTestnet,
    pub datadir: PathBuf,
    /// Where an un-prefixed request (`/` rather than `/wallet/<name>`) routes: the file's
    /// `default_wallet`; else the one declared wallet when exactly one is; else the literal
    /// `default` (an implicit wallet of the build's default coin, filled in at resolve).
    pub default_wallet: String,
    /// The wallet a subcommand acts on when its `--wallet` is omitted
    /// ([`wallet_or_default`](Self::wallet_or_default)): [`default_wallet`](Self::default_wallet)
    /// whenever the file names one or declares at most one wallet, and `None` when it
    /// declares several and names none - nothing singles a wallet out then, so the flag is
    /// required rather than quietly meaning the literal `default`.
    pub implied_wallet: Option<String>,
    pub wallets: BTreeMap<String, WalletEntry>,
    pub backend: BackendConfig,
    #[cfg(feature = "zcash")]
    pub zebra: ZebraConfig,
    /// `[bitcoind]` credentials for bitcoin wallets' upstream (the BDK engine's full mode).
    #[cfg(feature = "bitcoin")]
    pub bitcoind: BitcoindConfig,
    /// `[fees]` - the fee-oracle chain the BDK engine's kyoto (light) mode prices sends from.
    #[cfg(feature = "bitcoin")]
    pub fees: FeesConfig,
    /// `[mempool]` - the opt-in 0-conf feed for the BDK engine's kyoto (light) mode.
    #[cfg(feature = "bitcoin")]
    pub mempool: MempoolConfig,
    pub rpc: RpcConfig,
    pub keys: KeysConfig,
    pub sync: SyncConfig,
    #[cfg(feature = "zcash")]
    pub spend: SpendConfig,
    /// Global default enabled pools / UA receivers, applied to wallets that don't override them
    /// (including the implicit default wallet that has no `[wallets.<name>]` entry).
    #[cfg(feature = "zcash")]
    pub pools: PoolsConfig,
    pub health: HealthConfig,
    pub log: LogConfig,
    /// `[fleet]` - monitoring many watch-only wallets in this one daemon.
    #[cfg(feature = "zcash")]
    pub fleet: FleetConfig,
}

/// The fleet's root directory, relative to the datadir ([`fleet_root`]).
pub const DEFAULT_FLEET_ROOT: &str = "fleet";
/// The fleet's manifest directory, relative to its coin directory ([`fleet_manifest_dir`]).
pub const DEFAULT_FLEET_MANIFEST_DIR: &str = "wallets.d";
/// The fleet's shard-database directory, relative to its coin directory ([`fleet_dir`]).
pub const DEFAULT_FLEET_SHARD_DIR: &str = "shards";
/// Accounts per shard database.
///
/// Sharding buys nothing in trial-decryption cost - that is the sum over viewing keys however
/// they are grouped - so this is not a throughput knob. It bounds *blast radius*: onboarding a
/// wallet rewinds its shard's database to the new account's birthday, one SQLite writer
/// serializes per shard, `get_wallet_summary` is O(accounts in the database), and a halted shard
/// stops one group of wallets rather than the fleet.
pub const DEFAULT_FLEET_SHARD_SIZE: usize = 128;
/// How far below a shard's earliest birthday an arriving wallet may be and still join it, rather
/// than starting a shard of its own.
///
/// Importing an account rewinds its database to that account's birthday, so a wallet arriving far
/// below a caught-up shard's floor would drag every wallet in it back through a rescan. Alone in a
/// fresh shard it re-scans only against its own key, over blocks the daemon is fetching anyway.
pub const DEFAULT_FLEET_COHORT_DEPTH: u32 = 10_000;

/// `[fleet]` - monitoring many watch-only wallets in one daemon.
///
/// **Experimental, and off unless [`FleetConfig::enabled`] says otherwise.** The manifest
/// format, the `[fleet]` keys and the four wallet-management RPCs carry no compatibility
/// guarantee while the feature is experimental: they may change in a patch release. Two known
/// limitations are the reason: shard placement groups wallets by arrival rather than by
/// birthday, so a wide spread of birthdays makes a recent wallet wait behind the oldest member
/// of its shard; and there is no path to remove a wallet from a shard once it is imported.
///
/// The fleet is **additive**: disabled (the default) none of this runs, and `[wallets.<name>]`
/// entries keep behaving exactly as they always have.
#[cfg(feature = "zcash")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetConfig {
    /// Run the fleet at all (`[fleet] enabled`, default `false`).
    ///
    /// Off means the manifest directory is never read, no shard is opened, and the wallet
    /// management RPCs (`createwallet`, `loadwallet`, `unloadwallet`) refuse with a message
    /// naming this key. It is a deliberate opt-in rather than "on when manifests exist": the
    /// feature is experimental, so an operator should have said so, and a stray file in the
    /// datadir should not enrol a daemon into it.
    pub enabled: bool,
    /// Directory of per-wallet manifests, one small TOML each (absolute after resolution).
    ///
    /// Defaults to [`fleet_manifest_dir`] - under the fleet's own *coin* directory, since a
    /// manifest holds a coin-specific viewing key.
    pub manifest_dir: PathBuf,
    /// Directory holding the `shard-NNNN/` databases (absolute after resolution).
    ///
    /// Defaults to [`fleet_dir`], the sibling of the manifest directory under the same coin.
    pub dir: PathBuf,
    /// The coin this fleet's wallets are watched on.
    ///
    /// Not a config key (nothing in `rose.toml` selects it and `config show` renders nothing for
    /// it), exactly like [`WalletEntry::coin`]: it is carried so the shard directories can be
    /// laid out without the fleet code naming a currency itself.
    pub coin: Coin,
    /// Accounts per shard - see [`DEFAULT_FLEET_SHARD_SIZE`].
    pub shard_size: usize,
    /// Cohort depth for placement - see [`DEFAULT_FLEET_COHORT_DEPTH`].
    pub cohort_depth: u32,
}

#[cfg(feature = "zcash")]
impl Default for FleetConfig {
    fn default() -> Self {
        FleetConfig {
            enabled: false,
            manifest_dir: fleet_manifest_dir(Path::new(""), Coin::Zcash),
            dir: fleet_dir(Path::new(""), Coin::Zcash),
            coin: Coin::Zcash,
            shard_size: DEFAULT_FLEET_SHARD_SIZE,
            cohort_depth: DEFAULT_FLEET_COHORT_DEPTH,
        }
    }
}

/// `[pools]` - the wallet's shielded **receiver** configuration: which receivers its addresses
/// may carry, and which of those the Unified Addresses it hands out include by default. A default
/// receiver may never name one that isn't enabled (validated at startup). Per-wallet
/// `[wallets.<name>]` entries can override either field; this is the global default.
///
/// Both fields name receivers rather than value pools, so this list is shorter than the set of
/// pools rose reports funds in: ironwood has no receiver of its own (see `crate::pools`).
#[cfg(feature = "zcash")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolsConfig {
    /// The shielded receivers the wallet may hand out, and so the pools it receives into. Also
    /// picks the pool change is sent to (the strongest of them). It does **not** restrict
    /// spending: a send draws on every pool the wallet holds notes in, ironwood and any
    /// pool whose receiver is absent here included.
    pub enabled: ReceiverSet,
    /// Receivers included in the UAs handed out by `getnewaddress` when no per-call override is
    /// given. Always a subset of `enabled`.
    #[cfg(feature = "zcash")]
    pub default_receivers: ReceiverSet,
    /// Whether the wallet may hand out bare transparent (`t1...`/`tm...`) receiving addresses - via
    /// `getnewaddress "" "transparent"`, and (when `transparent_default`) as the no-argument
    /// default. Off preserves rose's shielded-only behaviour: `address_type = "transparent"` is
    /// rejected `-8`. Received transparent UTXOs are spendable only by auto-shielding them into a
    /// shielded send.
    #[cfg(feature = "zcash")]
    pub transparent_enabled: bool,
    /// Whether a no-argument `getnewaddress` returns a bare transparent address instead of a
    /// Unified Address. Requires `transparent_enabled` (validated at parse time).
    #[cfg(feature = "zcash")]
    pub transparent_default: bool,
    /// The **external** transparent gap limit: how far past the last *funded* receiving address a
    /// stateless restore keeps scanning the address index before giving up. Sized to the maximum
    /// number of addresses the operator may hand out ahead of funding - a higher value lets a
    /// rebuilt (stateless) wallet rediscover transparent funds across sparsely-funded
    /// pre-generated addresses, at the cost of more address-index queries per restore/scan. Only
    /// meaningful when `transparent_enabled`.
    #[cfg(feature = "zcash")]
    pub transparent_gap_limit: u32,
    /// **Initial scan depth.** On startup/restore, pre-expose external transparent indices
    /// `0..transparent_initial_scan` so the wallet scans *all* of them for receives - independent
    /// of (and typically far larger than) `transparent_gap_limit`. This is the initial-scan lever: an
    /// exchange that hands out, say, 10 000 addresses sets this to 10 000 so a stateless restore
    /// rediscovers a payment to any of them, while keeping a small steady-state `gap_limit` (it
    /// does *not* want a 10 000-deep sliding window past every funded address). `0` (the default)
    /// means no pre-exposure - discovery is bounded by `gap_limit` alone. Only meaningful when
    /// `transparent_enabled`.
    #[cfg(feature = "zcash")]
    pub transparent_initial_scan: u32,
    /// Whether `getnewaddress "" "transparent"` may keep issuing receiving addresses **past** the
    /// recovery window (`transparent_gap_limit` consecutive unfunded addresses, plus the
    /// `transparent_initial_scan` floor). librustzcash fails closed at the gap limit; with this set
    /// (the default) rose issues beyond it anyway, logging a loud warning that funds received at
    /// such an address may be unrecoverable from seed. Set `false` to instead fail the call with an
    /// actionable error. Only meaningful when `transparent_enabled`.
    #[cfg(feature = "zcash")]
    pub transparent_allow_beyond_recovery_window: bool,
    /// Warn (once per `getnewaddress`) when fewer than this many transparent address slots remain
    /// inside the recovery window before generation would hit the gap limit. Lets an operator widen
    /// `transparent_gap_limit`/`transparent_initial_scan` (or fund a lower index) before addresses
    /// start landing outside the window. `0` warns only on actual exhaustion. Only meaningful when
    /// `transparent_enabled`.
    #[cfg(feature = "zcash")]
    pub transparent_gap_warn_threshold: u32,
}

/// The Bitcoin engine's default address lookahead: BDK's own 25. Spelled here rather than
/// through `btc::actor` so a build without the `bitcoin` feature resolves the same config
/// (the key is refused on Zcash wallets, so the number is inert there).
pub const DEFAULT_LOOKAHEAD: u32 = 25;

/// Default external transparent gap limit. Above librustzcash's built-in 10 to give a safer margin
/// for typical sparse issuance, while keeping restore scans cheap.
pub const DEFAULT_TRANSPARENT_GAP_LIMIT: u32 = 20;

/// Hard upper bound on `transparent_gap_limit`, enforced at config validation. The gap window is
/// not just a scan bound: librustzcash's gap maintenance re-derives the ENTIRE window - a full
/// unified-address derivation per index - every time a transparent receive is recorded
/// (`put_received_transparent_utxo` -> `update_gap_limits`), and repeats that regeneration once
/// per already-recorded output of the same transaction. At the measured ~1.2k derivations/s a
/// 71000-wide window costs about a minute per received UTXO (quadratically more for multi-output
/// transactions), all on the single-writer actor inside the sync batch - in the field this
/// presented as a restore "stalled" >100x, one core pegged, with the block scan frozen for hours
/// (rose 0.5.1-rc2 report, 2026-07-30). Deep restore coverage belongs to
/// `transparent_initial_scan` (a one-time pre-exposure, not a per-receive cost); the gap limit
/// only needs to cover outstanding unfunded handed-out addresses. Above 10 000 the worst-case
/// per-receive cost passes ~10s, far beyond any sane outstanding-handout count - but the value
/// stays the operator's choice: the daemon starts anyway and logs at error level (an
/// operator-facing knob is never a hard failure when the misconfiguration only costs
/// performance).
pub const TRANSPARENT_GAP_LIMIT_SEVERE: u32 = 10_000;

/// Soft bound on `transparent_gap_limit` above which the daemon logs a startup warning (see
/// [`TRANSPARENT_GAP_LIMIT_SEVERE`] for the cost mechanism): ~1s of address derivation per
/// recorded transparent receive, more for multi-output transactions.
pub const TRANSPARENT_GAP_LIMIT_COSTLY: u32 = 1_000;

/// Default for `transparent_allow_beyond_recovery_window`: permissive (warn, don't block), matching
/// the Bitcoin-RPC promise that `getnewaddress` keeps handing out addresses.
pub const DEFAULT_TRANSPARENT_ALLOW_BEYOND: bool = true;

/// Default for `transparent_gap_warn_threshold`: warn once the last few in-window slots remain.
pub const DEFAULT_TRANSPARENT_GAP_WARN_THRESHOLD: u32 = 5;

#[cfg(feature = "zcash")]
impl Default for PoolsConfig {
    fn default() -> Self {
        // Preserves rose's historical behaviour: Orchard-only receiving, no transparent.
        Self {
            enabled: ReceiverSet::single(Receiver::Orchard),
            default_receivers: ReceiverSet::single(Receiver::Orchard),
            transparent_enabled: false,
            transparent_default: false,
            transparent_gap_limit: DEFAULT_TRANSPARENT_GAP_LIMIT,
            transparent_initial_scan: 0,
            transparent_allow_beyond_recovery_window: DEFAULT_TRANSPARENT_ALLOW_BEYOND,
            transparent_gap_warn_threshold: DEFAULT_TRANSPARENT_GAP_WARN_THRESHOLD,
        }
    }
}

/// What `/readyz` means - chosen to fit a deployment's priorities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessMode {
    /// Ready only once the wallet has actually scanned to (near) the chain tip: connected and
    /// within `max_scan_lag` blocks of the tip, AND the transaction-enhancement backlog has
    /// drained. Strict - a from-birthday restore stays "not
    /// ready" until it catches up. **This is the default**: a client must not see an empty or
    /// stale balance/history as authoritative while the wallet is still scanning.
    Synced,
    /// Like [`ReadinessMode::Synced`] minus the enhancement-backlog term: connected and within
    /// `max_scan_lag` blocks of the tip, whether or not transaction-data requests are still
    /// pending. This is the "scanned to tip, memos still landing" state: balances and note
    /// spendability are current (they come from the block scan), but history RPCs may still be
    /// missing memos/full transaction data, which `getwalletinfo.enhanced_through` bounds
    /// precisely. Exists because the backlog is not restore-only: on a wallet holding many
    /// transparent UTXOs, every send (and tip advance) re-emits the recurring spend-search
    /// requests, so gating on an empty backlog makes `/readyz` flap after routine sends -
    /// pulling a healthy node out of rotation while every balance RPC was answering correctly.
    /// Opt in (`readiness = "scanned"`) for deployments that route balance/send traffic and
    /// clamp history consumption to `enhanced_through`.
    Scanned,
    /// Ready as soon as the backend is connected and its chain tip is past the wallet's birthday
    /// (a cheap sanity check that we're talking to the right, live network). Does NOT wait for
    /// the wallet to finish scanning, so RPC clients can reach rose while it catches up - at the
    /// cost of reads possibly lagging the tip. Avoids readiness flapping during long scans. Opt in
    /// (`readiness = "connected"`) only when reachability matters more than balance freshness.
    Connected,
}

impl ReadinessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ReadinessMode::Synced => "synced",
            ReadinessMode::Scanned => "scanned",
            ReadinessMode::Connected => "connected",
        }
    }

    fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "synced" => Ok(ReadinessMode::Synced),
            "scanned" => Ok(ReadinessMode::Scanned),
            "connected" => Ok(ReadinessMode::Connected),
            other => Err(anyhow::anyhow!(
                "invalid [health] readiness {other:?}: expected \"synced\", \"scanned\" or \
                 \"connected\""
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// Serve liveness/readiness probes on a separate, unauthenticated HTTP port.
    pub enabled: bool,
    pub bind: IpAddr,
    pub port: u16,
    /// What `/readyz` gates on (see [`ReadinessMode`]).
    pub readiness: ReadinessMode,
    /// Maximum `chain_tip - fully_scanned` block gap at which `/readyz` reports ready, in
    /// [`ReadinessMode::Synced`]. This height gap is the meaningful "caught up" signal:
    /// librustzcash's note-weighted progress ratio is over the *tip-priority* range and reaches
    /// 1.0 while lower-priority historical ranges are still being scanned, so a wallet can look
    /// "100% scanned" with `fully_scanned` far below the tip (e.g. a from-birthday restore).
    /// Gating on the height gap instead means `/readyz` only goes ready once the wallet has
    /// actually scanned to (near) the tip.
    pub max_scan_lag: u32,
}

#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Default tracing filter (overridden by `RUST_LOG`).
    pub level: String,
    /// "text" (human) or "json" (structured, for log aggregation).
    pub format: String,
}

#[derive(Debug, Clone)]
pub struct WalletEntry {
    pub dir: PathBuf,
    /// Where this wallet's `keys.toml` lives. `None` means the default location,
    /// `<dir>/keys.toml`; an explicit path (per-wallet `keys_file`, or the global
    /// `[keys] keys_file` / `ROSE_KEYS_FILE` for the default wallet) lets the encrypted seed
    /// be mounted as a Kubernetes Secret separately from the (disposable) data directory.
    pub keys_file: Option<PathBuf>,
    /// The coin this wallet serves.
    pub coin: Coin,
    /// This wallet's chain, derived from (its coin, the daemon's network environment). Not a
    /// config key: `--testnet`/`--regtest` set the environment for the whole daemon and every
    /// wallet's chain follows from it, so a wallet on the wrong network is unrepresentable.
    pub chain: CoinNetwork,
    /// This wallet's overrides of the global `[backend]` endpoint settings.
    pub backend: WalletBackendOverride,
    /// Shielded pools this wallet receives into and spends from (resolved per wallet).
    #[cfg(feature = "zcash")]
    pub pools: ReceiverSet,
    /// Receivers included by default in this wallet's Unified Addresses (a subset of `pools`).
    #[cfg(feature = "zcash")]
    pub default_receivers: ReceiverSet,
    /// Whether this wallet may hand out bare transparent receiving addresses (resolved per wallet).
    #[cfg(feature = "zcash")]
    pub transparent_enabled: bool,
    /// Whether a no-argument `getnewaddress` on this wallet returns a bare transparent address.
    #[cfg(feature = "zcash")]
    pub transparent_default: bool,
    /// This wallet's external transparent gap limit (see [`PoolsConfig::transparent_gap_limit`]).
    #[cfg(feature = "zcash")]
    pub transparent_gap_limit: u32,
    /// This wallet's initial transparent scan depth (see [`PoolsConfig::transparent_initial_scan`]).
    #[cfg(feature = "zcash")]
    pub transparent_initial_scan: u32,
    /// Whether this wallet may issue transparent addresses past the recovery window
    /// (see [`PoolsConfig::transparent_allow_beyond_recovery_window`]).
    #[cfg(feature = "zcash")]
    pub transparent_allow_beyond_recovery_window: bool,
    /// This wallet's remaining-slot warning threshold
    /// (see [`PoolsConfig::transparent_gap_warn_threshold`]).
    #[cfg(feature = "zcash")]
    pub transparent_gap_warn_threshold: u32,
    /// How far below the chain tip `init` anchors this wallet's birthday when freshly
    /// generated (resolved per wallet: the wallet's own key, else the global
    /// `[keys] fresh_wallet_birthday_margin`, else the coin's built-in margin -
    /// [`crate::init::default_fresh_wallet_birthday_margin`]). Legal on every coin, like
    /// `server`; the per-coin default exists because the same block count spans ~10x more
    /// wall-clock time on Bitcoin than on Zcash.
    pub fresh_wallet_birthday_margin: u32,
    /// The Bitcoin engine's address lookahead (`[wallets.<name>] lookahead`, Bitcoin wallets
    /// only): how far past the last revealed index of each keychain BDK derives and watches -
    /// on a restore or an xpub import, the BIP-44 gap limit the scan can bridge. Defaults to
    /// BDK's own 25 ([`crate::btc::actor::DEFAULT_LOOKAHEAD`]); carried at that default on
    /// a Zcash wallet, whose gap limit is `transparent_gap_limit`.
    pub lookahead: u32,
    /// The Bitcoin engine's initial scan depth (`[wallets.<name>] initial_scan`, Bitcoin
    /// wallets only): external indexes `0..N` are revealed once, at spawn, so a restore
    /// watches all of them from its first pass while `lookahead` stays small - the
    /// Bitcoin counterpart of `transparent_initial_scan`. `0` (the default) reveals
    /// nothing; carried at `0` on a Zcash wallet.
    pub initial_scan: u32,
    /// Let a kyoto wallet spend with no mempool view of its own unconfirmed history
    /// (`[wallets.<name>] allow_sends_without_mempool_view`, Bitcoin wallets only; default
    /// `false`). A wallet whose database may be missing an earlier instance's unconfirmed
    /// sends - restored, rescanned, or rebuilt on an empty datadir - refuses to spend over
    /// kyoto until a snapshot-taking `[mempool]` feed establishes that view, since the
    /// inputs of those sends look unspent and a new send could double-spend one
    /// (`BtcActor::send_gate`). `true` accepts that risk and spends at once. Inert over
    /// bitcoind, whose mempool pass is the view; carried at `false` on a Zcash wallet.
    pub allow_sends_without_mempool_view: bool,
}

impl WalletEntry {
    /// This wallet's Zcash network.
    ///
    /// Unwrapped at the call site rather than stored bare, so the daemon-global
    /// `config.network` and a wallet's own chain stay distinguishable: the reads that mean
    /// "this deployment" keep using the former, and the per-wallet ones go through here.
    #[cfg(feature = "zcash")]
    pub fn zcash_network(&self) -> ZNetwork {
        match self.chain {
            CoinNetwork::Zcash(network) => network,
            // Every caller branches on `WalletEntry::coin` (or a registry tag derived from
            // it) before unwrapping a chain; reaching this arm is that invariant broken, not
            // an input error, so it fails loudly rather than inventing a network.
            #[cfg(feature = "bitcoin")]
            CoinNetwork::Bitcoin(_) => {
                panic!("zcash_network() on a Bitcoin wallet entry (caller must branch on coin)")
            }
        }
    }

    /// This wallet's Bitcoin network. The same contract as [`WalletEntry::zcash_network`],
    /// from the other side of the coin branch.
    #[cfg(feature = "bitcoin")]
    pub fn bitcoin_network(&self) -> crate::coin::BitcoinNetwork {
        match self.chain {
            CoinNetwork::Bitcoin(network) => network,
            #[cfg(feature = "zcash")]
            CoinNetwork::Zcash(_) => {
                panic!("bitcoin_network() on a Zcash wallet entry (caller must branch on coin)")
            }
        }
    }

    /// This wallet's engine directory: everything librustzcash owns, at
    /// `<dir>/<coin>/<engine>` (see [`engine_dir`]). This - not [`WalletEntry::dir`] - is what
    /// the wallet database, the block cache, and every read path are opened against.
    pub fn engine_dir(&self) -> PathBuf {
        engine_dir(&self.dir, self.coin)
    }

    /// The effective path to this wallet's `keys.toml` (the explicit `keys_file` override, or
    /// `<dir>/keys.toml` by default).
    ///
    /// It sits at the wallet root, above the per-coin directories: the BIP-39 seed it wraps
    /// serves every coin, and it is the one file here that no engine swap or rescan may touch.
    pub fn keys_path(&self) -> PathBuf {
        self.keys_file
            .clone()
            .unwrap_or_else(|| self.dir.join("keys.toml"))
    }
}

/// A wallet's per-endpoint overrides of the global `[backend]` section.
///
/// Only the settings that describe *which upstream this wallet dials* are overridable:
/// the server token and the TLS trust that authenticates it. Daemon policy - timeouts,
/// reconnect backoff, the cleartext-locality rules - and the `[zebra]` credentials stay
/// global, because they are properties of the deployment rather than of one endpoint.
///
/// Every field is `None` when the wallet does not override it, which is also what
/// `config show` renders by: a wallet with no overrides emits no backend keys at all, and
/// falls back to `[backend]`.
#[derive(Debug, Clone, Default)]
pub struct WalletBackendOverride {
    /// See [`BackendConfig::server`].
    pub server: Option<String>,
    /// See [`BackendConfig::tls`]. The outer `Option` is "did the wallet override it"; the
    /// inner one is the tri-state TLS mode (`None` = auto).
    pub tls: Option<Option<bool>>,
    /// See [`BackendConfig::tls_roots`].
    pub tls_roots: Option<crate::backend::TlsRoots>,
    /// See [`BackendConfig::tls_insecure_skip_verify`].
    pub tls_insecure_skip_verify: Option<bool>,
    /// See [`BackendConfig::tls_ca_pem`]. Read at config load, like the global key.
    pub tls_ca_pem: Option<Vec<u8>>,
    /// See [`BackendConfig::tls_ca_file`] - kept so the setting can be reported by its key.
    pub tls_ca_file: Option<PathBuf>,
    /// See [`BackendConfig::tls_pins`].
    pub tls_pins: Option<Vec<crate::backend::CertFingerprint>>,
    /// See [`BackendConfig::assume_transparent_in_compact_blocks`].
    pub assume_transparent_in_compact_blocks: Option<bool>,
}

impl WalletBackendOverride {
    /// Whether this wallet overrides anything at all (used to skip duplicate reporting of an
    /// endpoint that is just the global one).
    pub fn is_empty(&self) -> bool {
        self.server.is_none()
            && self.tls.is_none()
            && self.tls_roots.is_none()
            && self.tls_insecure_skip_verify.is_none()
            && self.tls_ca_pem.is_none()
            && self.tls_pins.is_none()
            && self.assume_transparent_in_compact_blocks.is_none()
    }

    /// The effective backend settings for this wallet: the global `[backend]` with this
    /// wallet's overrides applied. Field-by-field, so a wallet that overrides only `server`
    /// keeps every global TLS setting.
    pub fn effective(&self, global: &BackendConfig) -> BackendConfig {
        BackendConfig {
            server: self.server.clone().unwrap_or_else(|| global.server.clone()),
            tls: self.tls.unwrap_or(global.tls),
            tls_roots: self.tls_roots.unwrap_or(global.tls_roots),
            tls_insecure_skip_verify: self
                .tls_insecure_skip_verify
                .unwrap_or(global.tls_insecure_skip_verify),
            tls_ca_pem: self
                .tls_ca_pem
                .clone()
                .or_else(|| global.tls_ca_pem.clone()),
            tls_ca_file: self
                .tls_ca_file
                .clone()
                .or_else(|| global.tls_ca_file.clone()),
            tls_pins: self
                .tls_pins
                .clone()
                .unwrap_or_else(|| global.tls_pins.clone()),
            assume_transparent_in_compact_blocks: self
                .assume_transparent_in_compact_blocks
                .unwrap_or(global.assume_transparent_in_compact_blocks),
            // Daemon policy, never per-wallet.
            connect_timeout_secs: global.connect_timeout_secs,
            reconnect_base_secs: global.reconnect_base_secs,
            reconnect_max_secs: global.reconnect_max_secs,
            p2p_receive_window_bytes: global.p2p_receive_window_bytes,
            rfc1918_is_local: global.rfc1918_is_local,
            allow_remote_cleartext: global.allow_remote_cleartext,
            proxy: global.proxy.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackendConfig {
    /// The upstream server token: `zebra` (a local zebrad, the default),
    /// `zebra://host:port`, the `zecrocks` public-lightwalletd preset, or a lightwalletd
    /// endpoint (`https://host[:port]` / `http://host:port` / bare `host:port`).
    pub server: String,
    /// Per-attempt dial timeout (seconds) for connecting to the backend endpoint.
    pub connect_timeout_secs: u64,
    /// Reconnect backoff base delay (seconds).
    pub reconnect_base_secs: u64,
    /// Reconnect backoff maximum delay (seconds).
    pub reconnect_max_secs: u64,
    /// `[backend] p2p_receive_window_bytes`: the socket receive buffer of every outbound
    /// Bitcoin P2P connection (kyoto peers, the P2P mempool feed), which bounds the window
    /// a peer may have in flight. `None` leaves the kernel's autotuned default. At 1448 a
    /// peer sends one half-size segment per round trip and never two back-to-back, for
    /// paths that lose back-to-back packets (`btc::net`). Kyoto needs explicit peers for it.
    pub p2p_receive_window_bytes: Option<u32>,
    /// Treat private / non-globally-routable ranges (RFC1918, link-local, CGNAT, IPv6 unique-local
    /// and link-local) as "local" for the cleartext-credential gate, so a credentialed connect to
    /// a container/LAN zebra is allowed without an override. Default `true` (the self-hosted
    /// `zebra -> rose` Docker/LAN norm); set `false` for a strict loopback-only posture.
    pub rfc1918_is_local: bool,
    /// Escape hatch for the cleartext-credential gate: allow the (plaintext) zebra connection to
    /// carry RPC credentials to *any* host, including globally-routable ones. Off by default; the
    /// gate otherwise refuses a globally-routable host, since the credentials travel in cleartext.
    /// Set this only when the hop to a remote zebra is secured out-of-band (SSH/WireGuard tunnel,
    /// private overlay).
    pub allow_remote_cleartext: bool,
    /// lightwalletd TLS mode: `None` ("auto", the default) uses the locality heuristic
    /// (loopback/private plaintext, public TLS); `Some(true/false)` forces it. Ignored by
    /// `zebra://` endpoints (always plaintext) and overridden per-endpoint by an explicit
    /// `https://`/`http://` scheme.
    pub tls: Option<bool>,
    /// Which root certificates lightwalletd TLS trusts (`native` = OS store, the default;
    /// `webpki` = the embedded Mozilla bundle).
    pub tls_roots: crate::backend::TlsRoots,
    /// Accept *any* lightwalletd TLS certificate - no chain-of-trust or hostname check. Off by
    /// default. The connection stays encrypted but is no longer authenticated, so an on-path
    /// attacker can impersonate the server and observe every address and txid this wallet asks
    /// about. `tls_pinned_sha256` is the better answer for a self-signed certificate: it
    /// authenticates the server rather than giving up on doing so.
    pub tls_insecure_skip_verify: bool,
    /// PEM contents of a private CA to trust for lightwalletd TLS (`tls_ca_file`), read at
    /// config load. Added to the public roots, so a private-CA-issued certificate validates
    /// normally - hostname and expiry included.
    pub tls_ca_pem: Option<Vec<u8>>,
    /// Where [`tls_ca_pem`](Self::tls_ca_pem) was read from. Kept alongside the bytes purely so
    /// the setting can be *reported* by its key (`rose config show` renders the effective
    /// configuration in its own TOML syntax, and a PEM blob is not a value that can be written
    /// back as `tls_ca_file`). Nothing on the connect path reads it.
    pub tls_ca_file: Option<PathBuf>,
    /// Acceptable lightwalletd leaf-certificate SHA-256 fingerprints (`tls_pinned_sha256`).
    /// Non-empty pins the connection to those certificates; combined with `tls_ca_file` the
    /// chain is validated against that CA as well.
    pub tls_pins: Vec<crate::backend::CertFingerprint>,
    /// Operator assertion that the upstream lightwalletd serves transparent (and ironwood) data
    /// inside compact blocks, overriding the `GetLightdInfo.lightwalletProtocolVersion` probe.
    ///
    /// The probe exists because a server that cannot serve that data would silently never
    /// discover transparent receives. But no released lightwalletd populates the field yet - it
    /// is specified in the lightwallet protocol and left empty by the reference implementation -
    /// so the probe reports "incapable" even for a 0.5.x server that does serve the data. This
    /// knob is the operator's way to say "I know what my server does". Off by default: guessing
    /// wrong reintroduces exactly the silent-loss failure the probe is there to prevent.
    ///
    /// Ignored by `zebra://` endpoints, which always cover transparent data.
    pub assume_transparent_in_compact_blocks: bool,
    /// Route every outbound connection through this SOCKS5 proxy (`socks5://host:port`), e.g.
    /// `socks5://127.0.0.1:9050` for Tor. `None` (the default) dials directly.
    ///
    /// Daemon policy, not a per-endpoint setting: it covers both upstream kinds - the zebrad
    /// JSON-RPC client and the lightwalletd gRPC channel - so a configured proxy carries *all*
    /// of rose's network traffic. The destination is resolved by the proxy rather than locally
    /// (so `.onion` upstreams work and no DNS leaks), and lightwalletd TLS is layered over the
    /// proxied stream unchanged, keeping certificate verification pinned to the destination
    /// hostname. SOCKS username/password authentication is not supported.
    pub proxy: Option<crate::socks::SocksProxy>,
}

impl BackendConfig {
    /// The resolved TLS settings for the lightwalletd dial.
    pub fn tls_options(&self) -> crate::backend::TlsOptions {
        crate::backend::TlsOptions {
            force_tls: self.tls,
            roots: self.tls_roots,
            insecure_skip_verify: self.tls_insecure_skip_verify,
            ca_pem: self.tls_ca_pem.clone(),
            pins: self.tls_pins.clone(),
        }
    }
}

/// `[bitcoind]` - credentials for a bitcoin wallet's `bitcoind`/`bitcoind://host:port`
/// endpoint, mirroring `[zebra]`: a cookie file wins over user/password. Unlike zebrad,
/// bitcoind's RPC always requires auth, so "nothing set" only works against a node the
/// operator has explicitly opened (the dial then fails with the node's own refusal).
/// The value type lives here (shared layer); the engine converts it at its edge
/// (`crate::btc::chain`).
#[cfg(feature = "bitcoin")]
#[derive(Debug, Clone, Default)]
pub struct BitcoindConfig {
    /// The default upstream token for bitcoin wallets that don't set their own
    /// `[wallets.<name>] server` (same grammar: `bitcoind` or `bitcoind://host:port`).
    /// Unset means `bitcoind` - a local node on the network-standard port. This is the
    /// bitcoin analog of `[backend] server`, so both coins share the same shape: a global
    /// default with per-wallet overrides.
    pub server: Option<String>,
    pub rpc_user: Option<String>,
    pub rpc_password: Option<String>,
    pub rpc_cookie: Option<PathBuf>,
}

/// One tier of the kyoto backend's fee-oracle chain, named in `[fees] sources`.
///
/// A BIP-157 light client has no `estimatesmartfee`, so the kyoto spend path walks these in
/// the configured order and takes the first answer. Each tier is independently skippable,
/// which is what makes the list worth having: naming fewer sources is how an operator trades
/// a forward estimate for zero third-party contact (`sources = ["peer_median"]`), or the
/// reverse. The bitcoind backend never consults any of them - it has a local estimator.
#[cfg(feature = "bitcoin")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeSource {
    /// mempool.space's `/api/v1/fees/recommended`, read as `hourFee` - its own projected-block
    /// heuristic for a ~6 block target.
    MempoolSpace,
    /// A Blockstream-style Esplora `/fee-estimates`, read at the `"6"` key - a node's
    /// `estimatesmartfee`, so a different estimator than the tier above rather than a mirror.
    Esplora,
    /// Kyoto's own peers: the BIP-133 relay floor and an estimate from recent blocks' fee
    /// averages (`btc/fee_samples.rs`).
    /// No server and no URL - see [`crate::btc::kyoto::estimate_fee_rate`].
    PeerMedian,
}

/// The fallback chain when `[fees] sources` is unset: the forward estimate first, a second
/// independent HTTP oracle when it is down, and the no-third-party signals last.
#[cfg(feature = "bitcoin")]
pub const DEFAULT_FEE_SOURCES: [FeeSource; 3] = [
    FeeSource::MempoolSpace,
    FeeSource::Esplora,
    FeeSource::PeerMedian,
];

#[cfg(feature = "bitcoin")]
impl FeeSource {
    pub fn as_str(self) -> &'static str {
        match self {
            FeeSource::MempoolSpace => "mempool_space",
            FeeSource::Esplora => "esplora",
            FeeSource::PeerMedian => "peer_median",
        }
    }

    fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "mempool_space" => Ok(FeeSource::MempoolSpace),
            "esplora" => Ok(FeeSource::Esplora),
            "peer_median" => Ok(FeeSource::PeerMedian),
            other => Err(anyhow::anyhow!(
                "invalid [fees] source {other:?}: expected \"mempool_space\", \"esplora\" or \
                 \"peer_median\""
            )),
        }
    }
}

/// Default for `[fees] max_tx_fee_sat`: 0.1 BTC, Bitcoin Core's `DEFAULT_TRANSACTION_MAXFEE`.
#[cfg(feature = "bitcoin")]
pub const DEFAULT_MAX_TX_FEE_SAT: u64 = 10_000_000;

/// `[fees]` - the kyoto backend's fee-oracle chain: which sources to ask, in what order, and
/// (optionally) at which endpoints instead of the built-in public ones. Also the absolute
/// fee cap every Bitcoin send honors, on both backends.
///
/// The overrides are the answer to the privacy cost the chain otherwise carries: pointed at a
/// self-hosted mempool.space or Esplora instance, the fee lookup goes to infrastructure the
/// operator controls, the same posture `kyoto://<peer>` gives block data. They are also the
/// only way to reach a tier on a network the public instances do not serve (Blockstream runs
/// no testnet4 Esplora) or from a restricted network.
///
/// The value type lives here (shared layer); the engine resolves it into an ordered endpoint
/// chain at its edge (`crate::btc::fees`).
#[cfg(feature = "bitcoin")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeesConfig {
    /// The tiers to consult, in order. Defaults to [`DEFAULT_FEE_SOURCES`]. An empty list is
    /// legal and means "no estimation at all" - every send must then carry an explicit
    /// `fee_rate`, since mainnet refuses to guess and the test networks fall to 1 sat/vB.
    pub sources: Vec<FeeSource>,
    /// Full URL for the [`FeeSource::MempoolSpace`] tier, replacing the built-in per-network
    /// endpoint. Unset uses the public instance (and skips the tier where there is none).
    pub mempool_space_url: Option<String>,
    /// Full URL for the [`FeeSource::Esplora`] tier, same rule.
    pub esplora_url: Option<String>,
    /// The largest absolute fee, in satoshis, any send may pay - Bitcoin Core's `-maxtxfee`,
    /// with its default ([`DEFAULT_MAX_TX_FEE_SAT`]). Applies on both backends and to an
    /// explicit `fee_rate` as much as an estimated one: the rate ceiling bounds sat/vB, and
    /// a large consolidation at a sane rate can still carry a surprising total.
    pub max_tx_fee_sat: u64,
}

#[cfg(feature = "bitcoin")]
impl Default for FeesConfig {
    fn default() -> Self {
        Self {
            sources: DEFAULT_FEE_SOURCES.to_vec(),
            mempool_space_url: None,
            esplora_url: None,
            max_tx_fee_sat: DEFAULT_MAX_TX_FEE_SAT,
        }
    }
}

/// One source of the kyoto backend's mempool feed, named in `[mempool] sources`.
///
/// A BIP-157 light client sees a transaction when it confirms and not before. The feed is
/// what gives a kyoto wallet 0-conf receives: either a relay connection to one node or a
/// long-lived websocket to a mempool.space instance, whose announcements the wallet matches
/// locally (`crate::btc::mempool_feed`). The list shape mirrors `[fees] sources`, so a tier
/// can be dropped or reordered rather than only switched off. The bitcoind backend never
/// consults it - it has a real mempool.
#[cfg(feature = "bitcoin")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolSource {
    /// mempool.space's `/api/v1/ws` websocket, subscribed with `track-mempool`.
    MempoolSpace,
    /// rose's own relay connection to one node over the Bitcoin P2P protocol - by default
    /// the wallet's `kyoto://` trusted peer, else `p2p_peer` (`crate::btc::p2p_feed`).
    P2p,
}

#[cfg(feature = "bitcoin")]
impl MempoolSource {
    pub fn as_str(self) -> &'static str {
        match self {
            MempoolSource::MempoolSpace => "mempool_space",
            MempoolSource::P2p => "p2p",
        }
    }

    fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "mempool_space" => Ok(MempoolSource::MempoolSpace),
            "p2p" => Ok(MempoolSource::P2p),
            other => Err(anyhow::anyhow!(
                "invalid [mempool] source {other:?}: expected \"p2p\" or \"mempool_space\""
            )),
        }
    }
}

/// The chain when `[mempool] sources` is unset: the relay peer only.
///
/// [`MempoolSource::P2p`] is the default because it is the source that contacts nobody new -
/// it peers with the node the kyoto wallet already syncs from, and a wallet with no trusted
/// peer to name simply runs no feed. [`MempoolSource::MempoolSpace`] stays opt-in: it adds a
/// third party and, on mainnet, gigabytes a day of JSON.
#[cfg(feature = "bitcoin")]
pub const DEFAULT_MEMPOOL_SOURCES: [MempoolSource; 1] = [MempoolSource::P2p];

/// `[mempool]` - the kyoto backend's 0-conf feed: which sources to try, in order, and where
/// each connects instead of its default.
///
/// **`p2p` runs by default** ([`DEFAULT_MEMPOOL_SOURCES`]): without a feed a kyoto wallet
/// first sees a payment in its block, which reads as a stall rather than a setting, and the
/// relay connection that fixes it is to the node the wallet already peers with - no new
/// counterparty, raw-size bandwidth, no server. What it costs is legibility: a peer that
/// requests every announced transaction looks like a wallet chasing 0-conf rather than a
/// plain filter client. `sources = []` turns the feed off outright.
///
/// The `mempool_space` source is opt-in and stays that way: it adds a third party and, on
/// mainnet, gigabytes a day of JSON. Its override is the answer to the third party (a
/// self-hosted instance), and `ws://` is allowed for it on the same terms `[fees]` allows
/// plain `http://` (no credentials, no wallet data on the wire).
///
/// The value type lives here (shared layer); the engine resolves it into an endpoint and
/// runs the socket at its edge (`crate::btc::mempool_feed`).
#[cfg(feature = "bitcoin")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MempoolConfig {
    /// The sources to subscribe to, in preference order; the first with an endpoint for
    /// the wallet's network runs. Defaults to [`DEFAULT_MEMPOOL_SOURCES`]; an explicit empty
    /// list is legal and means "no feed at all", so a kyoto wallet sees a payment only once
    /// it confirms.
    pub sources: Vec<MempoolSource>,
    /// Whether `[mempool] sources` was named in the config file rather than defaulted. Only
    /// `config check` reads it: a section that cannot do what it says is worth a warning,
    /// while the same situation reached by default is not the operator's doing.
    pub sources_explicit: bool,
    /// Full websocket URL for the [`MempoolSource::MempoolSpace`] source, replacing the
    /// built-in per-network endpoint. Unset uses the public instance (and leaves the feed
    /// off where there is none - regtest).
    pub mempool_space_url: Option<String>,
    /// The node the [`MempoolSource::P2p`] source peers with (`ip:port`), replacing the
    /// wallet's own `kyoto://` trusted peer. Unset uses that peer; a DNS-seeded wallet with
    /// no override runs no P2P feed.
    pub p2p_peer: Option<std::net::SocketAddr>,
    /// Whether the P2P source also requests the node's mempool (BIP 35) at connect and
    /// periodically - the pre-connect blind spot and evictions, at the cost of a full
    /// mempool fetch per connect. Needs the `mempool` permission on the node
    /// (`-whitelist=mempool@<wallet host>`): Bitcoin Core disconnects a peer that asks
    /// without it. Default false.
    pub p2p_snapshot: bool,
    /// How often the P2P source re-requests the snapshot, in seconds (default
    /// [`DEFAULT_P2P_SNAPSHOT_INTERVAL_SECS`], minimum [`MIN_P2P_SNAPSHOT_INTERVAL_SECS`]).
    /// Bounds how stale an eviction can be; each request costs the node an `inv` of its
    /// whole mempool, which is why the default is minutes rather than seconds.
    pub p2p_snapshot_interval_secs: u64,
}

/// `[mempool] p2p_snapshot_interval_secs` when unset: five minutes.
#[cfg(feature = "bitcoin")]
pub const DEFAULT_P2P_SNAPSHOT_INTERVAL_SECS: u64 = 300;

/// The floor on `[mempool] p2p_snapshot_interval_secs`: below this the requests would
/// overlap their own collection window (the source collects a snapshot's announcements
/// for thirty seconds), and the node would be answering with its whole mempool
/// continuously. Low enough that a regtest suite can exercise the periodic path.
#[cfg(feature = "bitcoin")]
pub const MIN_P2P_SNAPSHOT_INTERVAL_SECS: u64 = 5;

#[cfg(feature = "bitcoin")]
impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            sources: DEFAULT_MEMPOOL_SOURCES.to_vec(),
            sources_explicit: false,
            mempool_space_url: None,
            p2p_peer: None,
            p2p_snapshot: false,
            p2p_snapshot_interval_secs: DEFAULT_P2P_SNAPSHOT_INTERVAL_SECS,
        }
    }
}

/// `[zebra]` - credentials for the `zebra://host:port` endpoint (direct-to-zebrad mode).
/// A cookie file wins over user/password, and nothing set means no auth (zebrad with
/// `enable_cookie_auth = false`).
#[cfg(feature = "zcash")]
#[derive(Debug, Clone, Default)]
pub struct ZebraConfig {
    pub rpc_user: Option<String>,
    pub rpc_password: Option<Password>,
    pub rpc_cookie: Option<PathBuf>,
}

#[cfg(feature = "zcash")]
impl ZebraConfig {
    pub fn auth(&self) -> crate::chain::zebra::ZebraAuth {
        crate::chain::zebra::ZebraAuth {
            user: self.rpc_user.clone(),
            password: self.rpc_password.clone(),
            cookie: self.rpc_cookie.clone(),
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RpcConfig {
    pub bind: IpAddr,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<Password>,
    /// Bitcoin-Core-style `rpcauth` entries (`<user>:<salt>$<hmac-sha256 hex>`), each an
    /// additional accepted credential; generate them with `rose rpcauth <user> [password]`.
    pub auth: Vec<String>,
    /// Path to a bitcoind-style cookie file; generated at startup when no user/password set.
    pub cookiefile: Option<PathBuf>,
    /// Max concurrent in-flight requests before returning HTTP 503 (Bitcoin Core's
    /// `-rpcworkqueue`, default 100).
    pub work_queue: usize,
    /// RPC method safelist. Empty (the default) serves every method; non-empty serves *only*
    /// these methods, with anything else rejected as method-not-found (`-32601`). Names are
    /// validated at startup against [`crate::rpc::ALL_METHODS`], so a typo fails fast.
    pub allowed_methods: Vec<String>,
    /// Accept a repeated *shielded* recipient in one `z_sendmany` call (default false).
    ///
    /// zcashd rejects any duplicate recipient address, and rose matches that by default: this
    /// is a zcashd-dialect method, and quietly accepting input a client was written against a
    /// refusal for is how bugs get baked in. But nothing in consensus or the wallet forbids two
    /// shielded outputs paying one address - it is how a batch of memo-carrying payments to a
    /// single address rides in one transaction, for one ZIP-317 fee - so an operator running
    /// such a protocol can opt in here. Transparent duplicates stay refused whatever this is
    /// set to: Bitcoin Core dedupes them for reasons of its own in history accounting, and
    /// nothing asked for that to change.
    ///
    /// Embedded callers need no knob: [`crate::node::Node::send`] takes a
    /// `zip321::TransactionRequest`, which expresses repeated recipients natively.
    pub allow_duplicate_shielded_recipients: bool,
}

#[derive(Debug, Clone)]
pub struct KeysConfig {
    /// age identity file used to decrypt the wallet seed for unattended sending.
    pub age_identity: Option<PathBuf>,
    /// When true, decrypt the seed at startup so sends need no `walletpassphrase`.
    pub auto_unlock: bool,
    /// When true (the default), a wallet whose `keys.toml` is present but whose `data.sqlite`
    /// has no account is rebuilt from `keys.toml` on boot: the account is recreated from the
    /// seed (once available - immediately for identity/auto-unlock wallets, at first
    /// `walletpassphrase` for encrypted ones) and the wallet rescans from its birthday. Lets the
    /// data directory be a disposable cache while the seed lives in a mounted Secret. Set false
    /// to instead fail fast on an empty datadir.
    pub bootstrap_from_keys: bool,
    /// The global `[keys] fresh_wallet_birthday_margin`: how far below the chain tip `init`
    /// anchors a *freshly generated* wallet's birthday, for every wallet that doesn't set its
    /// own. `None` (the default) means each wallet uses its coin's built-in margin
    /// ([`crate::init::default_fresh_wallet_birthday_margin`]) - the same block count spans
    /// ~10x more wall-clock time on Bitcoin than on Zcash, so "unset" deliberately does not
    /// mean one shared number. The knob exists for operators with their own reorg model, not
    /// for tuning. Restores and an explicit `--birthday` are unaffected.
    pub fresh_wallet_birthday_margin: Option<u32>,
    /// Permit more than one loaded wallet to hold spending keys - **honored only by an embedded
    /// node, and refused outright by the `rose` daemon** (see
    /// [`reject_multiple_spenders_in_daemon`]).
    ///
    /// The single-spender rule is a custody line, not a technical limit: over RPC, a credential
    /// is spend authority for whichever wallet a request routes to, so with two spenders loaded
    /// "which key can this credential spend?" stops having a one-word answer, and one leaked
    /// credential reaches every seed in the datadir. An embedded node has no RPC credentials -
    /// its host application is the authorization boundary and names the wallet explicitly on
    /// every [`crate::node::Node::call`] / [`crate::node::Node::send`] - so the ambiguity the
    /// rule prevents does not arise, and an application managing several writable stores in one
    /// process can opt in here rather than running a node per store.
    ///
    /// Caveat worth stating plainly: `server::run` is public, so an embedder *can* put the HTTP
    /// server in front of its own node. Doing that with this flag set re-creates exactly the
    /// situation the daemon refuses, and is the embedder's decision to own.
    pub allow_multiple_spending_wallets: bool,
}

#[derive(Debug, Clone)]
pub struct SyncConfig {
    pub interval_secs: u64,
    /// How often (at most) to re-broadcast wallet txs that are unmined and unexpired.
    pub rebroadcast_secs: u64,
    /// Whether this wallet recovers **memos**. Default `true`.
    ///
    /// Compact blocks carry the whole note plaintext except its memo, so recovering memos means
    /// fetching each received transaction's full data and trial-decrypting it - one upstream
    /// round trip per transaction, which on a from-seed restore is the multi-hour backlog that
    /// keeps `/readyz` at 503 long after the block scan has reached the tip. An operator who
    /// never reads memos (an exchange crediting deposits by address, or by transparent
    /// receives) sets `fetch_memos = false` and the wallet is ready at scan-tip instead.
    ///
    /// **Memos are the only thing it costs.** The fetch is skipped only for transactions the
    /// wallet did not spend in, where the memo is genuinely all it would have added
    /// (`actor::request_in_scope`); a transaction the wallet spent in is still fetched, because
    /// its outgoing records and its fee exist nowhere else. So balances, receives, the wallet's
    /// own sends with their recipients and amounts, fees, transaction-status tracking, the
    /// transparent address checks and `gettransaction.hex` are all exactly as they would be
    /// with the setting on - and identical whether the wallet caught a transaction live or
    /// recovered it in a restore.
    ///
    /// Memos are then withheld **uniformly**, not just where the fetch was skipped: the history
    /// RPCs omit `memo`/`memoStr` outright (`read::load_outputs`), and `enhanced_through` - the
    /// watermark that promises "memos at or below here are readable" - reports `None`. Without
    /// that, a memo's presence would depend on whether the mempool path happened to store a
    /// transaction before the block scan reached it, so the same wallet would answer
    /// differently before and after a restore. `getwalletinfo` reports `fetch_memos: false`, so
    /// a consumer asserts the wallet's kind rather than inferring it from absent memo fields.
    ///
    /// Reversible: the skipped requests stay queued in the wallet database, so flipping this
    /// back on drains the backlog and backfills the memos with no rescan. NB a deployment whose
    /// shielded deposit flow identifies depositors *by memo* must keep it on.
    pub fetch_memos: bool,
    /// How many blocks one download-and-scan batch covers. Default
    /// [`DEFAULT_BATCH_SIZE`](DEFAULT_BATCH_SIZE) (10,000).
    ///
    /// Each batch pays a fixed cost - one tree-state round trip, one scan-range query, one
    /// `put_blocks` database transaction - so a bigger batch amortizes it over more blocks.
    /// Measured on a 238k-block testnet restore: 2,000-block batches scanned in 294 s, 10,000 in
    /// 226 s, 25,000 in 198 s, 50,000 in 207 s - the curve flattens past 25,000 and the memory
    /// held per batch keeps growing. The batch lives in memory (`sync::memcache`), and one more
    /// is fetched ahead while it scans, so two batches of compact blocks are resident at once;
    /// on mainnet's densest ranges that is hundreds of megabytes at 25,000. The default stays
    /// at 10,000 for that reason; a server with memory to spare sets 25,000. Also bounds how far
    /// a reorg rewind will grow ([`REORG_MAX_MARGIN`](crate::sync::engine::REORG_MAX_MARGIN)).
    pub batch_size: u32,
    /// The SQLite page-cache ceiling of each wallet's writer connection, in MiB. Default
    /// [`DEFAULT_WRITER_CACHE_MIB`](DEFAULT_WRITER_CACHE_MIB) (256).
    ///
    /// The writer is the connection the sync loop scans through, and SQLite's own default of
    /// 2 MiB made it re-read the note-commitment tree pages from the operating system on
    /// nearly every block; 256 MiB took a deep testnet restore's scan from 178 s to 152 s. It
    /// is a ceiling, not an allocation - a small wallet never reaches it - but a cache that has
    /// grown is kept for the connection's lifetime, and every writer has its own: one per
    /// configured wallet and one per fleet shard. So the daemon-wide figure to size against is
    /// this value times the number of wallets and shards, which `config check` warns about
    /// past 2 GiB. Lower it on a small host or a large fleet; raising it past the wallet's
    /// database size buys nothing. Durability does not depend on it.
    pub writer_cache_mib: u32,
    /// How many transaction fetches the enhancement drain keeps in flight at once, which is
    /// also how many requests one drain pass services. Default [`DEFAULT_ENHANCE_CONCURRENCY`]
    /// (16).
    ///
    /// The drain that follows the block scan is one upstream round trip per transaction, and
    /// serviced one at a time its throughput is `1 / latency` however fast the host or the
    /// link - about 5 requests a second against a remote lightwalletd, against a backlog that
    /// on a busy wallet is tens of thousands. The requests are independent, so they go
    /// upstream together, this many at a time, and the pass's results are applied under one
    /// database transaction. Measured on a 7,546-request drain against a rack-local
    /// lightwalletd: 1 in flight took 1303 s, 16 took 194 s, 64 took 136 s, 256 took 105 s.
    /// Against a full node each fetch is its own JSON-RPC call, and the zebra client caps those
    /// at its own in-flight limit whatever this is set to. `config check` warns above 64: a
    /// public lightwalletd may throttle a client that opens that many streams at once.
    ///
    /// Only the fetches are concurrent. The results are applied on the wallet's single writer,
    /// one after another, so this is also how many stores the actor performs before it next
    /// services a queued command - the pass-sized window in which a send or `getnewaddress`
    /// waits. At the default it is the same 16-store window the sequential drain had; at 256
    /// on a wallet whose stores have grown to hundreds of milliseconds each it is a minute.
    pub enhance_concurrency: usize,
}

/// The default blocks per download-and-scan batch, and the value `[sync] batch_size`
/// overrides. Kept as a named constant because `sync::engine::REORG_MAX_MARGIN` is defined in
/// terms of it: a rewind never usefully goes further back than one batch would re-scan.
pub const DEFAULT_BATCH_SIZE: u32 = 10_000;

/// The default `[sync] writer_cache_mib`: the writer connection's SQLite page-cache ceiling.
/// See `wallet::open` for how it was measured and what it does (and does not) trade.
pub const DEFAULT_WRITER_CACHE_MIB: u32 = 256;

/// The default `[sync] enhance_concurrency`.
pub const DEFAULT_ENHANCE_CONCURRENCY: usize = 16;

/// `[spend]` - the wallet-wide confirmations policy (ZIP 315 defaults, like Zallet's
/// `trusted_confirmations`/`untrusted_confirmations`): how deep an output must be before
/// the wallet treats it as spendable, which also anchors `getbalance`/`getbalances`/
/// `getwalletinfo` and the sync engine's spend proposals.
#[cfg(feature = "zcash")]
#[derive(Debug, Clone)]
pub struct SpendConfig {
    /// Confirmations before the wallet's *own* outputs (change) are spendable. Default 3.
    pub trusted_confirmations: u32,
    /// Confirmations before third-party outputs are spendable. Must be at least
    /// `trusted_confirmations`. Default 10.
    pub untrusted_confirmations: u32,
    /// Mark transactions this wallet authors as **trusted** at store time
    /// (`actor::mark_own_tx_trusted`), so their outputs - including the payment half of a
    /// self-send - are spendable at `trusted_confirmations` instead of
    /// `untrusted_confirmations` (Bitcoin Core's own-transaction trust model). **On by
    /// default.** Set `trust_own_transactions = false` to keep rose from persisting the marker
    /// at all: every output is then classified purely from data a from-seed restore re-derives
    /// (key scope + chain), so an authoring instance and a restore of the same seed report
    /// byte-identical classifications at every confirmation depth - the strictest reading of
    /// the statelessness invariant, at the cost of self-send payments waiting the untrusted
    /// depth. Governs new sends only; markers already written remain until a rescan.
    pub trust_own_transactions: bool,
    /// What sends are allowed to reveal on-chain. Default `AllowRevealedRecipients`.
    pub privacy: SendPrivacy,
    /// Cap on the number of Orchard-family actions a single send may build, mirroring Zallet's
    /// `[builder.limits] orchard_actions` (default 50).
    ///
    /// Counted **per bundle and summed** - what the prover will run. Within one bundle that is
    /// `max(spends, outputs)`, but post-NU6.3 a send that spends legacy Orchard V2 notes into
    /// Ironwood outputs builds two bundles whose actions add up, and a single family-wide
    /// `max` would report the larger of the two rather than their total. It
    /// bounds memory/proving cost and gives a clean `-8` instead of a deep librustzcash error
    /// when a `z_sendmany` has too many recipients. `0` disables the cap. Default 50.
    pub orchard_action_limit: usize,
    /// Ceiling on the serialized size, in bytes, of a transaction a send may build. `0`
    /// disables it. Default [`DEFAULT_MAX_TX_BYTES`].
    ///
    /// This is a *relay* bound, not a consensus one, and it is the binding one: consensus only
    /// requires a transaction to fit in a block (2 MB), while a node forwards a much smaller
    /// one. A transaction over what nodes relay is not rejected so much as never mined - after
    /// the wallet has paid for its proof - so the ceiling is applied when the proposal is
    /// built, before proving.
    ///
    /// It bounds bytes where `orchard_action_limit` bounds actions, and neither implies the
    /// other: an Orchard-family action costs ~3.2 KB, so the shipped action cap of 50 sits
    /// comfortably inside a 250 KB ceiling, while a post-NU6.3 send carrying both an Orchard
    /// and an Ironwood bundle pays two proofs and reaches the ceiling sooner than its action
    /// count suggests. Raise it only if every node between this wallet and a miner raises its
    /// own policy to match - relay is hop by hop, so a locally raised limit gets a transaction
    /// into one mempool and no further.
    pub max_tx_bytes: usize,
    /// Prove sends through the PCZT roles with the Orchard proving keys warmed in the background
    /// at startup (and their prepared commitment tables armed), instead of the fused
    /// `create_proposed_transactions` path. On the Zakura stack both paths share one
    /// process-wide key set, so the fused path no longer rebuilds a key per transaction; what
    /// `false` gives up is the startup warm-up (the first fused send builds the key inline),
    /// the cached verifying key at the extract step, and `pipeline_proving`. On by default; set
    /// `cache_proving_key = false` to fall back to the fused path (e.g. for benchmarking or if
    /// a PCZT issue is suspected). Both paths produce identical transactions.
    pub cache_proving_key: bool,
    /// Run a send's proving step *off* the single-writer actor so it no longer freezes the
    /// background sync (and reads/status/mempool) for the whole proof - which, on a large,
    /// note-fragmented wallet, can be many minutes. The actor still serializes sends (only one
    /// proof is uncommitted at a time, so there is no double-spend surface and no reservation
    /// overlay); the win is that sync stays live while the proof runs on a blocking thread.
    /// Only engages on the cached-Orchard PCZT path (an Orchard-only wallet with
    /// `cache_proving_key` on); a Sapling-spending wallet keeps the inline fused path. **Off by
    /// default** - flip it on once validated by the funded/stress regtest tiers.
    pub pipeline_proving: bool,
    /// How many notes a send tries to leave the wallet holding, by splitting its change
    /// (librustzcash's `MultiOutputChangeStrategy` target). More notes means more sends can be
    /// in flight before the wallet runs out of confirmed inputs. Default 4.
    pub target_note_count: usize,
    /// Floor, in zatoshis, on each split change note: change is only divided while every
    /// resulting note would be at least this large, so a send never shatters a small balance
    /// into dust. Default 10_000_000 (0.1 ZEC).
    ///
    /// The default is sized for mainnet-scale value, and it is the *balance* it applies to, not
    /// the network - a wallet whose whole balance is below `target_note_count` times this floor
    /// gets a single change note, so consecutive sends must wait `trusted_confirmations` apart
    /// rather than spending several notes in turn. A deployment built on small balances (a
    /// faucet-funded testnet wallet, high-frequency low-value sends) should lower this to
    /// roughly its own typical payment size.
    pub min_split_output_value: u64,
    /// How long, in seconds, the wallet actor spends finishing sends it has already accepted
    /// when shutdown is signalled, before dropping whatever is left (see
    /// `actor::WalletActor::finish_accepted_sends`). Default 60.
    ///
    /// This has to fit **inside** whatever grace period the supervisor allows between its
    /// stop signal and `SIGKILL`, and the common ones are shorter than this default: `docker
    /// stop` kills after 10s and Kubernetes' `terminationGracePeriodSeconds` after 30s, where
    /// systemd's `DefaultTimeoutStopSec` is 90s. Killed mid-drain nothing is corrupted - a send
    /// that had not been stored is simply lost, exactly as before this drain existed - but the
    /// guarantee it buys is silently gone, so raise the supervisor's timeout or lower this.
    /// `0` disables the drain and restores the old drop-on-shutdown behaviour.
    pub shutdown_drain_secs: u64,
    /// How many blocks a send may scan to catch the wallet up to the chain tip before it is
    /// built. `0` removes the bound. Default [`DEFAULT_MAX_SEND_CATCHUP_BLOCKS`].
    ///
    /// A send first scans up to the upstream's tip, because the spend anchor and expiry both
    /// derive from the wallet's chain tip (see `actor::WalletActor::sync_to_tip_for_send`).
    /// That is a few blocks normally, but on a wallet still restoring it is the whole remaining
    /// scan, run on the single-writer actor while the caller waits - minutes to hours, with
    /// every other send queued behind it. Past this many blocks the send fails at once with
    /// Bitcoin Core's `-10` ("still syncing") instead, naming the lag, and the caller retries
    /// once `waitforsync` says the wallet has caught up. Balance and history reads are never
    /// gated: they already report what the wallet has scanned.
    pub max_send_catchup_blocks: u32,
}

#[cfg(feature = "zcash")]
impl Default for SpendConfig {
    fn default() -> Self {
        Self {
            trusted_confirmations: 3,
            untrusted_confirmations: 10,
            trust_own_transactions: true,
            privacy: SendPrivacy::AllowRevealedRecipients,
            orchard_action_limit: DEFAULT_ORCHARD_ACTION_LIMIT,
            max_tx_bytes: DEFAULT_MAX_TX_BYTES,
            cache_proving_key: true,
            pipeline_proving: false,
            target_note_count: DEFAULT_TARGET_NOTE_COUNT,
            min_split_output_value: DEFAULT_MIN_SPLIT_OUTPUT_VALUE,
            shutdown_drain_secs: DEFAULT_SHUTDOWN_DRAIN_SECS,
            max_send_catchup_blocks: DEFAULT_MAX_SEND_CATCHUP_BLOCKS,
        }
    }
}

#[cfg(feature = "zcash")]
impl SpendConfig {
    /// Reject change-splitting settings the send path could not use.
    ///
    /// Both values reach librustzcash through constructors that reject out-of-range input, so
    /// without this a typo in `rose.toml` would surface as a panic on the first send rather than
    /// as a refusal to start.
    pub fn validate_change_splitting(&self) -> anyhow::Result<()> {
        if self.target_note_count == 0 {
            anyhow::bail!(
                "[spend] target_note_count must be at least 1 (it is the number of notes a send \
                 aims to leave the wallet holding)"
            );
        }
        if zcash_protocol::value::Zatoshis::from_u64(self.min_split_output_value).is_err() {
            anyhow::bail!(
                "[spend] min_split_output_value = {} is not a valid amount of zatoshis",
                self.min_split_output_value
            );
        }
        Ok(())
    }
}

/// The `[spend]` values a running daemon can change without a restart.
///
/// Everything else in the resolved config is copied into per-actor fields at startup and is
/// immutable for the process's life. These are not, because an operator needs to change them
/// *while* a wallet is stuck: the Orchard-action cap is the one a fragmented wallet hits, where
/// every payout fails until the cap moves and the backlog grows while it does not. A mining
/// pool ran into exactly that and had to restart a live payment wallet to get out.
///
/// The cap is a shared cell rather than a per-call RPC argument on purpose. It bounds what a
/// single call can make the daemon prove - CPU linear in actions across every core, memory in
/// witness data, and the wait every queued send inherits - and the changelog leans on it as a
/// security property, citing it as bounding how long one proof can run while a decrypted seed
/// is resident. A knob an RPC caller could raise would not be that bound. So the only channel
/// that changes it is one requiring process-level authority: SIGHUP, which re-reads the config
/// file. See `Node::reload_config`.
#[cfg(feature = "zcash")]
#[derive(Debug, Clone)]
pub struct SpendLimits {
    orchard_action_limit: Arc<AtomicUsize>,
    max_tx_bytes: Arc<AtomicUsize>,
}

#[cfg(feature = "zcash")]
impl SpendLimits {
    pub fn new(spend: &SpendConfig) -> Self {
        Self {
            orchard_action_limit: Arc::new(AtomicUsize::new(spend.orchard_action_limit)),
            max_tx_bytes: Arc::new(AtomicUsize::new(spend.max_tx_bytes)),
        }
    }

    /// The cap in force right now. Read per send rather than cached, so a reload takes effect on
    /// the next send instead of the next restart.
    pub fn orchard_action_limit(&self) -> usize {
        self.orchard_action_limit.load(Ordering::Relaxed)
    }

    /// Apply a new cap. Returns the previous value, so a caller can report what changed.
    pub fn set_orchard_action_limit(&self, limit: usize) -> usize {
        self.orchard_action_limit.swap(limit, Ordering::Relaxed)
    }

    /// The transaction-size ceiling in force right now, in bytes (`0` = disabled). Reloadable
    /// for the same reason the action cap is: it is the other setting that can leave a wallet
    /// unable to pay out until it moves, and the operator needs it while that is happening.
    pub fn max_tx_bytes(&self) -> usize {
        self.max_tx_bytes.load(Ordering::Relaxed)
    }

    /// Apply a new size ceiling. Returns the previous value.
    pub fn set_max_tx_bytes(&self, bytes: usize) -> usize {
        self.max_tx_bytes.swap(bytes, Ordering::Relaxed)
    }
}

/// What a configuration reload changed, and what it could not.
///
/// A reload is deliberately narrow: only the keys on [`RELOADABLE_KEYS`] are applied, and
/// everything else in a re-read config is reported as needing a restart rather than being
/// silently ignored or half-applied. An operator who edits the wrong key should be told so by
/// the daemon, not discover it when the behaviour does not change.
#[cfg(feature = "zcash")]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReloadReport {
    /// `(key, old, new)` for each setting this reload applied.
    pub applied: Vec<(&'static str, String, String)>,
    /// Keys whose value differs from the running config but that only a restart can change.
    pub requires_restart: Vec<String>,
}

#[cfg(feature = "zcash")]
impl ReloadReport {
    /// Whether the reload found nothing to do - the file matches what is running.
    pub fn is_empty(&self) -> bool {
        self.applied.is_empty() && self.requires_restart.is_empty()
    }
}

/// The configuration keys a running daemon applies on reload. Everything else needs a restart.
///
/// Deliberately a short list. Reloading a setting means it is safe to change under a running
/// wallet actor, and most are not: an endpoint, a network, a wallet's pools or gap limits are
/// all baked into state that exists by the time the daemon is serving. These two are here
/// because an operator needs them *while* a wallet is stuck rather than at the next restart -
/// a wallet that fails every payout on one of these bounds keeps failing, and its backlog
/// grows, until the bound moves. Add to this list only when the same is true.
#[cfg(feature = "zcash")]
pub const RELOADABLE_KEYS: &[&str] = &["spend.orchard_action_limit", "spend.max_tx_bytes"];

/// Compare a freshly resolved config against the one the daemon is running, apply what can be
/// applied, and report the rest.
#[cfg(feature = "zcash")]
pub fn apply_reload(running: &AppConfig, fresh: &AppConfig, limits: &SpendLimits) -> ReloadReport {
    let mut report = ReloadReport::default();

    // The live keys. Compared against the cells rather than against `running`, so a second
    // reload that changes nothing reports nothing even after the first one moved them.
    let current = limits.orchard_action_limit();
    if fresh.spend.orchard_action_limit != current {
        limits.set_orchard_action_limit(fresh.spend.orchard_action_limit);
        report.applied.push((
            "spend.orchard_action_limit",
            current.to_string(),
            fresh.spend.orchard_action_limit.to_string(),
        ));
    }
    let current = limits.max_tx_bytes();
    if fresh.spend.max_tx_bytes != current {
        limits.set_max_tx_bytes(fresh.spend.max_tx_bytes);
        report.applied.push((
            "spend.max_tx_bytes",
            current.to_string(),
            fresh.spend.max_tx_bytes.to_string(),
        ));
    }

    // Everything else: report a difference rather than pretending it took effect.
    //
    // The comparison runs over `config_show::render`'s output rather than over the structs,
    // which buys two things. It names the *key* that differs, using the same spelling an
    // operator writes in the file (that renderer is already pinned to emit keys a config parse
    // accepts). And it covers the whole config by construction, so adding a setting cannot
    // create a change nobody is told about - which is the failure mode a hand-written field
    // comparison has, and the one that matters here, since silently ignoring an edit is worse
    // than refusing it.
    for key in changed_keys(running, fresh) {
        if !RELOADABLE_KEYS.contains(&key.as_str()) {
            report.requires_restart.push(key);
        }
    }

    report
}

/// The dotted config keys whose rendered values differ between two configs.
///
/// Works off `config_show::render`, whose output is the effective config as TOML using the real
/// key names - so a differing line names the setting an operator would edit. Comment and blank
/// lines are skipped; a `[table]` header sets the prefix for the keys under it. A secret is
/// rendered as a commented-out key name, so a changed password reads as no change here: that is
/// a deliberate limit of comparing the redacted rendering, and credentials need a restart
/// anyway.
#[cfg(feature = "zcash")]
fn changed_keys(running: &AppConfig, fresh: &AppConfig) -> Vec<String> {
    fn keyed(config: &AppConfig) -> Vec<(String, String)> {
        let mut section = String::new();
        let mut out = Vec::new();
        for line in crate::config_show::render(config).lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = format!("{name}.");
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                out.push((format!("{section}{}", key.trim()), value.trim().to_string()));
            }
        }
        out
    }
    let (a, b) = (keyed(running), keyed(fresh));
    let bm: std::collections::BTreeMap<_, _> = b.iter().cloned().collect();
    let mut changed: Vec<String> = a
        .iter()
        .filter(|(k, v)| bm.get(k).is_some_and(|other| other != v))
        .map(|(k, _)| k.clone())
        .collect();
    // A key present in one rendering and not the other (an optional setting gained or dropped)
    // is a change too.
    let am: std::collections::BTreeMap<_, _> = a.iter().cloned().collect();
    changed.extend(
        b.iter()
            .filter(|(k, _)| !am.contains_key(k))
            .map(|(k, _)| k.clone()),
    );
    changed.extend(
        a.iter()
            .filter(|(k, _)| !bm.contains_key(k))
            .map(|(k, _)| k.clone()),
    );
    changed.sort();
    changed.dedup();
    changed
}

/// Default Orchard-action cap, matching Zallet's `orchard_actions` default.
pub const DEFAULT_ORCHARD_ACTION_LIMIT: usize = 50;

/// Default `[spend] max_tx_bytes`: the largest transaction a send may build, in bytes.
///
/// 250 000, which is zakura's `[mempool] max_transaction_bytes` default
/// (`DEFAULT_MAX_TRANSACTION_BYTES`, in its `crates/zakurad/src/components/mempool/config.rs`):
/// the per-transaction ceiling a stock node applies before it will relay one. Matching it is
/// the point, since a wallet that builds past what nodes forward has spent its proving time on
/// a transaction that never reaches a miner.
///
/// It is a *policy* number rather than a consensus one, so it can move; but it cannot be
/// treated as a local setting. Relay is hop by hop, so what bounds a transaction in practice is
/// the default every unconfigured peer applies, not whatever the operator's own node is set to.
/// Zebra and zcashd have no equivalent per-transaction cap - zcashd dropped its standard-size
/// limit for shielded transactions - so on a network of those this ceiling costs a wallet only
/// the consolidation rounds it would have taken anyway.
pub const DEFAULT_MAX_TX_BYTES: usize = 250_000;

/// Default change-splitting target, matching zcash-devtool's send defaults.
pub const DEFAULT_TARGET_NOTE_COUNT: usize = 4;

/// Default floor on a split change note (0.1 ZEC), matching zcash-devtool's send defaults.
pub const DEFAULT_MIN_SPLIT_OUTPUT_VALUE: u64 = 10_000_000;

/// Default `[spend] shutdown_drain_secs`: how long the actor finishes accepted sends on
/// shutdown. Comfortably above a single send's proof (a 50-note merge measured 29-35 s in the
/// field) and below systemd's 90 s default stop timeout - but above `docker stop`'s 10 s and
/// Kubernetes' 30 s, which is why it is configurable at all.
pub const DEFAULT_SHUTDOWN_DRAIN_SECS: u64 = 60;

/// Default `[spend] max_send_catchup_blocks`: the most blocks a send scans before building.
/// Matches Zallet's `sync.lock_threshold`. A live wallet lags its upstream by a block or two,
/// so this only binds on a wallet that is genuinely still syncing.
pub const DEFAULT_MAX_SEND_CATCHUP_BLOCKS: u32 = 100;

/// `[spend] privacy_policy` - Zallet/zcashd's privacy-policy idea (zcash/zcash#6240) reduced to
/// the leaks a rose send can actually cause: whether a send may cross between shielded pools
/// (Sapling↔Orchard, revealing the transferred amount on-chain via `valueBalance`), whether it
/// may include a transparent recipient (additionally revealing the recipient), whether it may be
/// *funded* from the wallet's transparent UTXOs (revealing the sender's addresses and input
/// amounts - `z_sendmany`'s transparent `fromaddress`/`ANY_TADDR` coin control), and whether the
/// change of such a send may stay transparent (a fully transparent spend). zcashd/Zallet require
/// an explicit `AllowRevealed*` opt-in for each, and this knob is rose's equivalent: a five-rung
/// ladder - `FullPrivacy` < `AllowRevealedAmounts` < `AllowRevealedRecipients` <
/// `AllowRevealedSenders` < `AllowFullyTransparent`. Unlike zcashd's policy lattice the ladder is
/// linear, so each rung implies everything below it (`AllowRevealedSenders` here permits
/// transparent recipients too, where zcashd keeps senders and recipients orthogonal).
#[cfg(feature = "zcash")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendPrivacy {
    /// Only fully-shielded transactions confined to a **single** shielded value pool: no
    /// transparent recipients, and no Sapling↔Orchard crossing. Such a send reveals neither the
    /// amount nor the recipient. (Enforced on the built proposal - see the actor's `do_send`.)
    FullPrivacy,
    /// Permits crossing the Sapling↔Orchard turnstile (which reveals the transferred *amount*
    /// on-chain via `valueBalance`) but **not** a transparent recipient (which would additionally
    /// reveal the *recipient*). This is zcashd's `AllowRevealedAmounts`, the policy one notch
    /// weaker than `FullPrivacy`: a caller who opts into revealing amounts has not thereby opted
    /// into revealing recipients.
    AllowRevealedAmounts,
    /// Permits transparent recipients and cross-pool sends (which reveal the transferred amount,
    /// and the recipient if transparent). This is the default: the Bitcoin-RPC dialect promises
    /// "send to any valid address". A transparent recipient is paid from shielded notes, so the
    /// *sender* side stays shielded; the wallet's leftover change also stays shielded.
    AllowRevealedRecipients,
    /// Additionally permits funding a send from the wallet's received transparent (t-address)
    /// UTXOs - `z_sendmany` with a transparent `fromaddress` or `ANY_TADDR` - which reveals the
    /// sender's addresses and input amounts on-chain. The change of such a send is **shielded**
    /// (it goes to the wallet's shielded change pool), so a send from a t-address to a shielded
    /// recipient under this rung is the t->z *shielding* send. Kept-transparent change (a fully
    /// transparent spend) still requires `AllowFullyTransparent`. Mirrors zcashd's
    /// `AllowRevealedSenders`, except rose's linear ladder means this rung also permits
    /// transparent recipients (paid from shielded notes when the source is shielded).
    AllowRevealedSenders,
    /// Additionally permits a **fully transparent** spend: funding a send directly from the
    /// wallet's received transparent (t-address) UTXOs, with the change kept transparent - the
    /// most revealing send possible (amount, sender UTXOs, recipient, and change are all public,
    /// and never touch a shielded pool). Strictly opt-in; this is the only policy under which
    /// transparent change is possible. Mirrors zcashd/Zallet
    /// `AllowFullyTransparent`/`NoPrivacy`.
    AllowFullyTransparent,
}

#[cfg(feature = "zcash")]
impl SendPrivacy {
    fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "FullPrivacy" => Ok(Self::FullPrivacy),
            "AllowRevealedAmounts" => Ok(Self::AllowRevealedAmounts),
            "AllowRevealedRecipients" => Ok(Self::AllowRevealedRecipients),
            "AllowRevealedSenders" => Ok(Self::AllowRevealedSenders),
            "AllowFullyTransparent" => Ok(Self::AllowFullyTransparent),
            other => anyhow::bail!(
                "[spend] privacy_policy must be \"FullPrivacy\", \"AllowRevealedAmounts\", \
                 \"AllowRevealedRecipients\", \"AllowRevealedSenders\", or \
                 \"AllowFullyTransparent\" (got \"{other}\")"
            ),
        }
    }

    /// recipient and the amount on-chain. `AllowRevealedRecipients` and every rung above it
    /// (`AllowRevealedSenders`, `AllowFullyTransparent` - the ladder is linear, each rung implies
    /// the ones below) permit a transparent recipient; `FullPrivacy` and `AllowRevealedAmounts`
    /// reject one (the latter opts into revealed *amounts* only). Omitting `AllowFullyTransparent`
    /// here would make the fully-transparent send path unreachable - the `build_payment` pre-check
    /// would `-8`-reject the recipient before the t->t spend could run.
    pub fn allows_transparent_recipient(self) -> bool {
        matches!(
            self,
            Self::AllowRevealedRecipients
                | Self::AllowRevealedSenders
                | Self::AllowFullyTransparent
        )
    }

    /// Whether a send under this policy may be *funded* from the wallet's transparent UTXOs
    /// (`z_sendmany` with a transparent `fromaddress`/`ANY_TADDR`), revealing the sender's
    /// addresses and input amounts on-chain. This is the gate for spending transparent inputs at
    /// all; the kept-transparent-change t->t path additionally requires `AllowFullyTransparent`
    /// (under `AllowRevealedSenders` the change of a transparent-funded send is shielded).
    pub fn allows_transparent_inputs(self) -> bool {
        matches!(
            self,
            Self::AllowRevealedSenders | Self::AllowFullyTransparent
        )
    }

    /// The zcashd `privacyPolicy` name for this policy, used in the self-diagnosing send errors.
    pub fn policy_name(self) -> &'static str {
        match self {
            Self::FullPrivacy => "FullPrivacy",
            Self::AllowRevealedAmounts => "AllowRevealedAmounts",
            Self::AllowRevealedRecipients => "AllowRevealedRecipients",
            Self::AllowRevealedSenders => "AllowRevealedSenders",
            Self::AllowFullyTransparent => "AllowFullyTransparent",
        }
    }
}

#[cfg(feature = "zcash")]
impl SpendConfig {
    /// Build the [`ConfirmationsPolicy`] this configuration describes. Values are clamped
    /// to at least 1 (a shielded note is never spendable unmined); trusted exceeding
    /// untrusted is a configuration error, as in librustzcash.
    pub fn confirmations_policy(&self) -> anyhow::Result<ConfirmationsPolicy> {
        let trusted = NonZeroU32::new(self.trusted_confirmations.max(1)).expect("clamped");
        let untrusted = NonZeroU32::new(self.untrusted_confirmations.max(1)).expect("clamped");
        // The third argument exists because this crate enables `transparent-inputs` (so
        // transparent receivers surface in getrawtransaction/getaddressinfo): it allows
        // 0-conf spends of transparent UTXOs, matching the ZIP-315 default policy. It is
        // inert for rose, whose wallets never expose transparent receivers.
        ConfirmationsPolicy::new(trusted, untrusted, true).map_err(|_| {
            anyhow::anyhow!(
                "[spend] trusted_confirmations ({}) must not exceed untrusted_confirmations ({})",
                self.trusted_confirmations,
                self.untrusted_confirmations
            )
        })
    }
}

// ---------------------------------------------------------------------------
// On-disk TOML representation
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    network: Option<String>,
    /// Which public Bitcoin test network a testnet daemon's Bitcoin wallets use:
    /// `"testnet3"` (the default) or `"testnet4"`. Parsed in every build so the error a
    /// default build gives is "this build has no bitcoin engine", not an unknown-key
    /// message; validated in [`AppConfig::resolve`] and nowhere else, like `coin`. Refused
    /// outside `network = "test"`, where it would be silently inert.
    btc_testnet: Option<String>,
    datadir: Option<PathBuf>,
    default_wallet: Option<String>,
    #[serde(default)]
    wallets: BTreeMap<String, WalletFile>,
    backend: Option<BackendFile>,
    #[cfg(feature = "zcash")]
    zebra: Option<ZebraFile>,
    /// `[bitcoind]` exists only in a build carrying the BDK engine; a default build refuses
    /// the section as an unknown field, consistent with `coin = "bitcoin"` being refused.
    #[cfg(feature = "bitcoin")]
    bitcoind: Option<BitcoindFile>,
    /// `[fees]`, same rule as `[bitcoind]`: a section only the BDK engine has any use for.
    #[cfg(feature = "bitcoin")]
    fees: Option<FeesFile>,
    /// `[mempool]`, same rule again.
    #[cfg(feature = "bitcoin")]
    mempool: Option<MempoolFile>,
    rpc: Option<RpcFile>,
    keys: Option<KeysFile>,
    sync: Option<SyncFile>,
    #[cfg(feature = "zcash")]
    spend: Option<SpendFile>,
    #[cfg(feature = "zcash")]
    pools: Option<PoolsFile>,
    health: Option<HealthFile>,
    log: Option<LogFile>,
    #[cfg(feature = "zcash")]
    fleet: Option<FleetFile>,
}

#[cfg(feature = "zcash")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FleetFile {
    enabled: Option<bool>,
    manifest_dir: Option<PathBuf>,
    dir: Option<PathBuf>,
    shard_size: Option<usize>,
    cohort_depth: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthFile {
    enabled: Option<bool>,
    bind: Option<String>,
    port: Option<u16>,
    readiness: Option<String>,
    max_scan_lag: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogFile {
    level: Option<String>,
    format: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletFile {
    /// The coin this wallet serves (`"zcash"`, the default; `"bitcoin"` in a build carrying
    /// the BDK engine). Validated in [`AppConfig::resolve`] and nowhere else, so the daemon,
    /// `config check`, and the embedded facade refuse an unsupported value identically.
    coin: Option<String>,
    dir: Option<PathBuf>,
    /// Path to this wallet's `keys.toml`, independent of `dir` (mount it as a Secret).
    keys_file: Option<PathBuf>,
    /// Override the global `[backend] server` for this wallet.
    server: Option<String>,
    /// Override the global `[backend] tls` for this wallet.
    tls: Option<String>,
    /// Override the global `[backend] tls_roots` for this wallet.
    tls_roots: Option<String>,
    /// Override the global `[backend] tls_insecure_skip_verify` for this wallet.
    tls_insecure_skip_verify: Option<bool>,
    /// Override the global `[backend] tls_ca_file` for this wallet.
    tls_ca_file: Option<PathBuf>,
    /// Override the global `[backend] tls_pinned_sha256` for this wallet.
    tls_pinned_sha256: Option<Vec<String>>,
    /// Override the global `[backend] assume_transparent_in_compact_blocks` for this wallet.
    assume_transparent_in_compact_blocks: Option<bool>,
    /// Override the global `[pools] enabled` for this wallet.
    pools: Option<Vec<String>>,
    /// Override the global `[pools] default_receivers` for this wallet.
    default_receivers: Option<Vec<String>>,
    /// Override the global `[pools] transparent` for this wallet.
    transparent: Option<bool>,
    /// Override the global `[pools] transparent_default` for this wallet.
    transparent_default: Option<bool>,
    /// Override the global `[pools] transparent_gap_limit` for this wallet.
    transparent_gap_limit: Option<u32>,
    /// Override the global `[pools] transparent_initial_scan` for this wallet.
    transparent_initial_scan: Option<u32>,
    /// Override the global `[pools] transparent_allow_beyond_recovery_window` for this wallet.
    transparent_allow_beyond_recovery_window: Option<bool>,
    /// Override the global `[pools] transparent_gap_warn_threshold` for this wallet.
    transparent_gap_warn_threshold: Option<u32>,
    /// Override the global `[keys] fresh_wallet_birthday_margin` for this wallet. Legal on
    /// every coin, like `server`.
    fresh_wallet_birthday_margin: Option<u32>,
    /// The Bitcoin engine's address lookahead (BDK's; the restore gap limit). Bitcoin
    /// wallets only - a Zcash wallet's gap limit is `transparent_gap_limit`.
    lookahead: Option<u32>,
    /// The Bitcoin engine's initial scan depth (external indexes revealed at spawn).
    /// Bitcoin wallets only - a Zcash wallet's is `transparent_initial_scan`.
    initial_scan: Option<u32>,
    /// Let a kyoto wallet spend before it has a mempool view of its own unconfirmed
    /// history. Bitcoin wallets only.
    allow_sends_without_mempool_view: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendFile {
    server: Option<String>,
    connect_timeout_secs: Option<u64>,
    reconnect_base_secs: Option<u64>,
    reconnect_max_secs: Option<u64>,
    p2p_receive_window_bytes: Option<u32>,
    rfc1918_is_local: Option<bool>,
    allow_remote_cleartext: Option<bool>,
    /// lightwalletd TLS mode: `auto` (default) / `yes` / `no`.
    tls: Option<String>,
    /// lightwalletd TLS root store: `native` (default) / `webpki`.
    tls_roots: Option<String>,
    /// Accept any lightwalletd TLS certificate (default `false`). Unsafe - see
    /// [`BackendConfig::tls_insecure_skip_verify`].
    tls_insecure_skip_verify: Option<bool>,
    /// Path to a PEM bundle holding a private CA to trust for lightwalletd TLS.
    tls_ca_file: Option<PathBuf>,
    /// SHA-256 leaf-certificate fingerprints to pin lightwalletd TLS to (`openssl x509 -noout
    /// -fingerprint -sha256` form; colons optional, case-insensitive).
    tls_pinned_sha256: Option<Vec<String>>,
    /// Assert that the upstream lightwalletd serves transparent data in compact blocks - see
    /// [`BackendConfig::assume_transparent_in_compact_blocks`].
    assume_transparent_in_compact_blocks: Option<bool>,
    /// Route all upstream traffic through a SOCKS5 proxy (`socks5://host:port`) - see
    /// [`BackendConfig::proxy`].
    proxy: Option<String>,
}

#[cfg(feature = "zcash")]
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ZebraFile {
    rpc_user: Option<String>,
    rpc_password: Option<Password>,
    rpc_cookie: Option<PathBuf>,
}

#[cfg(feature = "bitcoin")]
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct BitcoindFile {
    /// Default upstream token for bitcoin wallets (`bitcoind` when unset).
    server: Option<String>,
    rpc_user: Option<String>,
    rpc_password: Option<String>,
    rpc_cookie: Option<PathBuf>,
}

#[cfg(feature = "bitcoin")]
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FeesFile {
    /// Ordered tier names (`mempool_space` / `esplora` / `peer_median`); unset is
    /// [`DEFAULT_FEE_SOURCES`].
    sources: Option<Vec<String>>,
    mempool_space_url: Option<String>,
    esplora_url: Option<String>,
    max_tx_fee_sat: Option<u64>,
}

#[cfg(feature = "bitcoin")]
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct MempoolFile {
    /// Source names (`p2p` / `mempool_space`), in preference order; unset is
    /// [`DEFAULT_MEMPOOL_SOURCES`] and an explicit empty list is no feed.
    sources: Option<Vec<String>>,
    mempool_space_url: Option<String>,
    p2p_peer: Option<String>,
    p2p_snapshot: Option<bool>,
    p2p_snapshot_interval_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcFile {
    bind: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    password: Option<Password>,
    /// Read the RPC password from this file (trailing newline trimmed) instead of inlining it.
    /// Lets the password - which is spend-equivalent for clients - live in a Kubernetes Secret
    /// rather than the ConfigMap the rest of the config lands in. Overrides `password`; the
    /// `--rpcpassword` flag / `ROSE_RPC_PASSWORD` env still win over both.
    password_file: Option<PathBuf>,
    auth: Option<Vec<String>>,
    cookiefile: Option<PathBuf>,
    work_queue: Option<usize>,
    allowed_methods: Option<Vec<String>>,
    allow_duplicate_shielded_recipients: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysFile {
    age_identity: Option<PathBuf>,
    auto_unlock: Option<bool>,
    /// Path to the default wallet's `keys.toml`, independent of the datadir (mount as a Secret).
    /// Equivalent to `[wallets.<default>] keys_file`; the `ROSE_KEYS_FILE` env / `--keys-file`
    /// flag override it.
    keys_file: Option<PathBuf>,
    /// Rebuild `data.sqlite` from `keys.toml` on an empty datadir (default true).
    bootstrap_from_keys: Option<bool>,
    allow_multiple_spending_wallets: Option<bool>,
    /// Blocks below the tip a freshly generated wallet's birthday is anchored.
    fresh_wallet_birthday_margin: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncFile {
    interval_secs: Option<u64>,
    rebroadcast_secs: Option<u64>,
    /// See [`SyncConfig::fetch_memos`].
    fetch_memos: Option<bool>,
    /// See [`SyncConfig::batch_size`].
    batch_size: Option<u32>,
    /// See [`SyncConfig::writer_cache_mib`].
    writer_cache_mib: Option<u32>,
    /// See [`SyncConfig::enhance_concurrency`].
    enhance_concurrency: Option<usize>,
}

#[cfg(feature = "zcash")]
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpendFile {
    trusted_confirmations: Option<u32>,
    untrusted_confirmations: Option<u32>,
    trust_own_transactions: Option<bool>,
    privacy_policy: Option<String>,
    orchard_action_limit: Option<usize>,
    max_tx_bytes: Option<usize>,
    cache_proving_key: Option<bool>,
    pipeline_proving: Option<bool>,
    target_note_count: Option<usize>,
    min_split_output_value: Option<u64>,
    shutdown_drain_secs: Option<u64>,
    max_send_catchup_blocks: Option<u32>,
}

#[cfg(feature = "zcash")]
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolsFile {
    enabled: Option<Vec<String>>,
    default_receivers: Option<Vec<String>>,
    /// Enable bare transparent (`t1...`/`tm...`) receiving addresses.
    transparent: Option<bool>,
    /// Make a bare transparent address the no-argument `getnewaddress` default (implies
    /// `transparent`).
    transparent_default: Option<bool>,
    /// External transparent gap limit (restore scan depth past the last funded address).
    transparent_gap_limit: Option<u32>,
    /// Initial transparent scan depth (pre-expose + scan indices `0..N` on startup/restore).
    transparent_initial_scan: Option<u32>,
    /// Allow `getnewaddress` to issue transparent addresses beyond the recovery window (warn-only).
    transparent_allow_beyond_recovery_window: Option<bool>,
    /// Warn when fewer than this many in-window transparent address slots remain.
    transparent_gap_warn_threshold: Option<u32>,
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// CLI-shaped overrides to configuration resolution, decoupled from clap so a library consumer
/// can resolve an [`AppConfig`] without the CLI surface. The fields mirror [`Cli`]'s global
/// flags one for one, and [`Cli`] converts into this, so the daemon and an embedder resolve
/// configuration identically.
///
/// NB the `ROSE_RPC_PASSWORD` / `ROSE_AGE_IDENTITY` / `ROSE_KEYS_FILE` env fallbacks are clap
/// behavior on the corresponding [`Cli`] flags and do NOT apply here - a library caller sets
/// the fields explicitly. `ROSE_DATADIR` still applies (it is resolved during resolution, not
/// by clap).
///
/// Deliberately **not** `#[non_exhaustive]`, unlike the option structs elsewhere on the
/// supported surface: that attribute forbids a struct literal outside this crate entirely, even
/// with `..Default::default()`, so it would break every embedder rather than protect them. The
/// contract is upheld by construction instead - fields only ever arrive, and always with a
/// `Default` - so `ConfigOverrides { .., ..Default::default() }` stays source-compatible across
/// versions. This mirrors the CLI's global flags one for one; a setting with no flag (the
/// `[fleet]` section, `[sync] fetch_memos`, the `[pools]` knobs) is set on the resolved
/// [`AppConfig`], whose fields are public for that reason.
#[derive(Debug, Default, Clone)]
pub struct ConfigOverrides {
    /// Path to the TOML config file (default: `<datadir>/rose.toml`).
    pub conf: Option<PathBuf>,
    /// Data directory holding per-wallet subdirectories and the cookie file.
    pub datadir: Option<PathBuf>,
    /// Use testnet (overrides config `network`).
    pub testnet: bool,
    /// Use regtest (overrides config `network`).
    pub regtest: bool,
    /// Network: "main", "test", or "regtest".
    pub network: Option<String>,
    /// RPC bind address.
    pub rpc_bind: Option<String>,
    /// RPC port.
    pub rpc_port: Option<u16>,
    /// RPC username (HTTP Basic auth).
    pub rpc_user: Option<String>,
    /// RPC password (HTTP Basic auth).
    pub rpc_password: Option<Password>,
    /// rpcauth credentials (`<user>:<salt>$<hmac-sha256 hex>`).
    pub rpc_auth: Vec<String>,
    /// Chain upstream token (`zebra`, `zebra://host:port`, `zecrocks`, `https://...`, ...).
    pub server: Option<String>,
    /// SOCKS5 proxy carrying every outbound connection (`socks5://host:port`).
    pub proxy: Option<String>,
    /// age identity file used to decrypt the wallet seed for sending.
    pub age_identity: Option<PathBuf>,
    /// Path to the default wallet's `keys.toml`, independent of the datadir.
    pub keys_file: Option<PathBuf>,
}

#[cfg(feature = "cli")]
impl From<&Cli> for ConfigOverrides {
    fn from(cli: &Cli) -> ConfigOverrides {
        ConfigOverrides {
            conf: cli.conf.clone(),
            datadir: cli.datadir.clone(),
            testnet: cli.testnet,
            regtest: cli.regtest,
            network: cli.network.clone(),
            rpc_bind: cli.rpc_bind.clone(),
            rpc_port: cli.rpc_port,
            rpc_user: cli.rpc_user.clone(),
            rpc_password: cli.rpc_password.clone(),
            rpc_auth: cli.rpc_auth.clone(),
            server: cli.server.clone(),
            proxy: cli.proxy.clone(),
            age_identity: cli.age_identity.clone(),
            keys_file: cli.keys_file.clone(),
        }
    }
}

/// `rose` - a Bitcoin-Core-style JSON-RPC server for shielded-first Zcash.
// The global flags both binaries share: `rosed` (the daemon) flattens this next to
// [`RunArgs`], and `rose` (rose-cli) flattens it above its subcommands. Every flag here is
// `global`, so under `rose` it is accepted before *or* after a subcommand (`rose --conf f
// config check` and `rose config check --conf f` are the same command). That matters most for
// `config check`, whose whole job is resolving a named config the way the daemon would - having
// to remember that `--conf` only works in one position would be a trap on the one command an
// operator reaches for when something is already wrong. (A normal comment, not a doc comment:
// clap would render a doc comment as help text, and this is a note for readers of the source.)
// No `#[command(name, version)]` here: those belong to the binary that flattens this in. The
// `Parser` derive stays so tests can `Cli::parse_from` the flags on their own.
// `Clone` so the daemon can keep the parsed CLI for a SIGHUP reload: a reload must re-resolve
// through exactly the path startup took (the same file, the same overrides, the same defaults),
// which means holding on to the arguments rather than reconstructing them.
#[cfg(feature = "cli")]
#[derive(Debug, Clone, Parser)]
pub struct Cli {
    /// Path to the TOML config file (default: <datadir>/rose.toml, else ./rose.toml).
    #[arg(long, global = true, value_name = "FILE")]
    pub conf: Option<PathBuf>,

    /// Data directory holding per-wallet subdirectories and the cookie file.
    #[arg(long, global = true, value_name = "DIR")]
    pub datadir: Option<PathBuf>,

    /// Use testnet (overrides config `network`).
    #[arg(long, global = true)]
    pub testnet: bool,

    /// Use regtest - a local zebra regtest chain (overrides config `network`).
    #[arg(long, global = true)]
    pub regtest: bool,

    /// Network: "main", "test", or "regtest".
    #[arg(long, global = true, value_name = "NET")]
    pub network: Option<String>,

    /// RPC bind address.
    #[arg(long = "rpcbind", global = true, value_name = "ADDR")]
    pub rpc_bind: Option<String>,

    /// RPC port.
    #[arg(long = "rpcport", global = true, value_name = "PORT")]
    pub rpc_port: Option<u16>,

    /// RPC username (HTTP Basic auth).
    #[arg(long = "rpcuser", global = true, value_name = "USER")]
    pub rpc_user: Option<String>,

    /// RPC password (HTTP Basic auth). May also be supplied via `ROSE_RPC_PASSWORD` or
    /// `[rpc] password_file` so it need not live in the (ConfigMap-bound) TOML.
    #[arg(
        long = "rpcpassword",
        global = true,
        value_name = "PASS",
        env = "ROSE_RPC_PASSWORD"
    )]
    pub rpc_password: Option<Password>,

    /// rpcauth credential (`<user>:<salt>$<hmac-sha256 hex>`); may be repeated.
    #[arg(long = "rpcauth", global = true, value_name = "USER:SALT$HASH")]
    pub rpc_auth: Vec<String>,

    /// Chain upstream: `zebra` (local zebrad, the default) or `zebra://host:port`.
    #[arg(long, global = true, value_name = "SERVER")]
    pub server: Option<String>,

    /// Route every outbound connection through a SOCKS5 proxy, e.g. `socks5://127.0.0.1:9050`
    /// for Tor. Covers both upstream kinds; the proxy resolves the destination.
    #[arg(long, global = true, value_name = "SOCKS5_URL")]
    pub proxy: Option<String>,

    /// age identity file used to decrypt the wallet seed for sending.
    #[arg(long, global = true, value_name = "FILE", env = "ROSE_AGE_IDENTITY")]
    pub age_identity: Option<PathBuf>,

    /// Path to the default wallet's `keys.toml`, independent of the datadir (so the encrypted
    /// seed can be a mounted Secret while the datadir stays a disposable cache).
    #[arg(long, global = true, value_name = "FILE", env = "ROSE_KEYS_FILE")]
    pub keys_file: Option<PathBuf>,
}

/// `rose`'s subcommands (rose-cli): everything an operator does beside running the daemon.
/// The daemon itself is the `rosed` binary and has no subcommand; the RPC client half of
/// `rose` is rose-cli's own, built over any word that is not one of these.
#[cfg(feature = "cli")]
#[derive(Debug, Clone, clap::Subcommand)]
pub enum Command {
    /// Create and initialize a new wallet (mnemonic + accounts), then exit.
    Init(InitArgs),
    /// Print a wallet's Unified Full Viewing Key (for pairing a watch-only instance via
    /// `init --ufvk`), then exit.
    ExportUfvk(ExportUfvkArgs),
    /// Print a Bitcoin wallet's account xpub with its key origin (for pairing a watch-only
    /// instance via `init --xpub`), then exit.
    ExportXpub(ExportXpubArgs),
    /// Derive receiving addresses offline - no chain, no wallet database, no daemon - from an
    /// initialized wallet's `keys.toml`, a BIP-39 mnemonic, or a Unified Full Viewing Key, then
    /// exit.
    DeriveAddress(DeriveAddressArgs),
    /// Generate a salted bitcoind-style `[rpc] auth` credential line (no external
    /// `rpcauth.py` needed), then exit.
    Rpcauth(RpcauthArgs),
    /// Print the annotated example configuration file to stdout (or `--output-file`), then
    /// exit. Redirect it to `<datadir>/rose.toml` and edit to taste.
    ExampleConfig(ExampleConfigArgs),
    /// Print the license texts of the third-party crates compiled into this binary to
    /// stdout, then exit. The same text the packaging ships as `THIRD-PARTY-LICENSES.txt`.
    Licenses,
    /// Inspect the configuration (`rose config check`), then exit.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Rebuild a wallet whose database is broken: delete the wallet database (keys.toml and
    /// the seed are kept) so the next daemon start recreates the account from the seed and
    /// rescans the chain from the wallet birthday, re-deriving all funds and history. Refuses
    /// to run while the daemon holds the data directory.
    Rescan(RescanArgs),
    /// Dial the configured upstream and report its chain tip, then exit. Needs no wallet, so
    /// it answers "can this deployment reach its backend?" and "what birthday should a wallet
    /// created now get?" before `rose init` has run.
    ChainInfo(ChainInfoArgs),
}

#[cfg(feature = "cli")]
#[derive(Debug, Clone, clap::Args)]
pub struct ChainInfoArgs {
    /// Probe this endpoint instead of `[backend] server`, using the same token grammar, to
    /// test a candidate before committing it to a configuration file.
    #[arg(long, value_name = "TOKEN")]
    pub server: Option<String>,

    /// Emit a JSON object instead of the human-readable summary.
    #[arg(long)]
    pub json: bool,
}

#[cfg(feature = "cli")]
#[derive(Debug, Clone, clap::Args)]
pub struct InitArgs {
    /// Wallet name (selects/creates <datadir>/<name>). Defaults to the config's
    /// `default_wallet`, so a config whose only wallet is `[wallets.btc]` with
    /// `default_wallet = "btc"` needs no flag.
    #[arg(long, value_name = "NAME")]
    pub wallet: Option<String>,

    /// Restore from an existing mnemonic instead of generating a new one. The phrase is read
    /// from `--mnemonic-file`, else the `ROSE_MNEMONIC` env var, else stdin.
    #[arg(long)]
    pub restore: bool,

    /// For `--restore`: read the mnemonic phrase from this file (trailing newline trimmed)
    /// instead of stdin, for non-interactive init. `ROSE_MNEMONIC` takes precedence.
    #[arg(long, value_name = "FILE")]
    pub mnemonic_file: Option<PathBuf>,

    /// Passphrase-encrypt the wallet (Bitcoin-Core style): the mnemonic is wrapped with a
    /// passphrase instead of the age identity, and the wallet starts locked - sending requires
    /// `walletpassphrase`. The passphrase is read from `ROSE_WALLET_PASSPHRASE` or stdin.
    #[arg(long)]
    pub encrypt: bool,

    /// Create a watch-only wallet from this Unified Full Viewing Key instead of a mnemonic
    /// (export it from the spending wallet with `export-ufvk`). The wallet sees balances,
    /// history, and addresses, but holds no spending material - spend and encryption RPCs
    /// are disabled.
    #[arg(long, value_name = "UFVK", conflicts_with_all = ["restore", "encrypt"])]
    pub ufvk: Option<String>,

    /// Create a watch-only **Bitcoin** wallet from this account xpub instead of a mnemonic:
    /// either the `[fingerprint/84'/coin'/0']xpub...` form `export-xpub` prints, or a bare
    /// `xpub...` (taken to be the BIP 84 first account, `m/84'/coin'/0'`, which is the only
    /// derivation the engine supports; its export then carries fingerprint `00000000`). The
    /// wallet sees balances, history, and addresses, but holds no spending material - spend
    /// RPCs are disabled. Only a `coin = "bitcoin"` wallet accepts it; a Zcash wallet takes
    /// `--ufvk`.
    #[arg(long, value_name = "XPUB", conflicts_with_all = ["restore", "encrypt", "ufvk"])]
    pub xpub: Option<String>,

    /// Optional birthday: a block height, or a UTC date as YYYY-MM-DD - the date is
    /// resolved to a height with a ~1-day safety margin, so it need not be exact (an early
    /// birthday only scans more; funds can never predate the wallet). Defaults to near the
    /// current chain tip for new wallets. Dates are refused on regtest, whose block
    /// timestamps mean nothing.
    #[arg(long, value_name = "HEIGHT|YYYY-MM-DD", value_parser = crate::init::Birthday::parse)]
    pub birthday: Option<crate::init::Birthday>,
}

/// `rosed`'s own flags: what the daemon does before it serves. Every one of them exists
/// for a deployment with no shell to script `init` first - an enclave, or the `FROM scratch`
/// container images - where the whole "restore into an empty data directory, then serve"
/// sequence has to be one command.
#[cfg(feature = "cli")]
#[derive(Debug, Clone, Default, clap::Args)]
pub struct RunArgs {
    /// Before serving, create `--wallet` if it is not yet initialized (its `keys.toml` is
    /// absent): `init --restore` from the phrase in `ROSE_MNEMONIC` or `--mnemonic-file`
    /// (a spending wallet), or `init --xpub` from the account xpub in `ROSE_XPUB` (a
    /// watch-only Bitcoin wallet) - non-interactively, never stdin, and both set is refused.
    /// An initialized wallet is left exactly as it is and no secret is read at all. A
    /// restore that fails is fatal for the daemon - it exists to serve that wallet.
    #[arg(long)]
    pub restore_if_empty: bool,

    /// The wallet `--restore-if-empty` restores (a `[wallets.<name>]` entry, or the default
    /// layout for a name the config does not mention - exactly `init --wallet`). Defaults to
    /// the config's implied wallet: `default_wallet`, else its one declared wallet.
    #[arg(long, value_name = "NAME", requires = "restore_if_empty")]
    pub wallet: Option<String>,

    /// For `--restore-if-empty`: read the mnemonic phrase from this file (trailing newline
    /// trimmed) when `ROSE_MNEMONIC` is unset. `ROSE_MNEMONIC` takes precedence, as for
    /// `init --restore`.
    #[arg(long, value_name = "FILE", requires = "restore_if_empty")]
    pub mnemonic_file: Option<PathBuf>,

    /// For `--restore-if-empty`: the restored wallet's birthday, exactly as `init --birthday`
    /// (a height, or a UTC date as YYYY-MM-DD; erring early is safe). Without it a restore
    /// scans from the earliest block the wallet could hold funds in - slow, and on Bitcoin
    /// mainnet refused, as `init --restore` documents.
    #[arg(
        long,
        value_name = "HEIGHT|YYYY-MM-DD",
        value_parser = crate::init::Birthday::parse,
        requires = "restore_if_empty"
    )]
    pub birthday: Option<crate::init::Birthday>,
}

#[cfg(feature = "cli")]
#[derive(Debug, Clone, clap::Args)]
pub struct RpcauthArgs {
    /// RPC username the credential is for.
    pub username: String,

    /// Password to hash. If omitted, a strong random password is generated and printed once.
    pub password: Option<Password>,
}

#[cfg(feature = "cli")]
#[derive(Debug, Clone, clap::Args)]
pub struct ExampleConfigArgs {
    /// Write the config here instead of stdout. `-` also means stdout. Refuses to overwrite an
    /// existing file unless `--force`.
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output_file: Option<PathBuf>,

    /// Overwrite `--output-file` if it already exists.
    #[arg(long)]
    pub force: bool,
}

#[cfg(feature = "cli")]
#[derive(Debug, Clone, clap::Subcommand)]
pub enum ConfigCommand {
    /// Validate a configuration file against this rose build without starting the daemon, and
    /// print the settings it resolves to. Exits non-zero if the daemon would refuse to start.
    Check(ConfigCheckArgs),
    /// Print the effective configuration - the file, CLI flags and environment resolved
    /// together, with every unset key filled in by this build's default - as TOML, then exit.
    Show(ConfigShowArgs),
}

#[cfg(feature = "cli")]
#[derive(Debug, Clone, clap::Args)]
pub struct ConfigCheckArgs {
    /// Treat warnings as errors, so a config that merely looks risky also exits non-zero
    /// (for CI gates on a deployment repository).
    #[arg(long)]
    pub strict: bool,

    /// Suppress the effective-configuration summary (stdout) and the success line; problems
    /// and the exit code are still reported on stderr.
    #[arg(short = 'q', long)]
    pub quiet: bool,
}

/// `rose config show` takes no options of its own - the configuration it renders is selected by
/// the global flags (`--conf`, `--datadir`, `--network`, ...), exactly as the daemon selects it.
#[cfg(feature = "cli")]
#[derive(Debug, Clone, clap::Args)]
pub struct ConfigShowArgs {}

#[cfg(feature = "cli")]
#[derive(Debug, Clone, clap::Args)]
pub struct ExportUfvkArgs {
    /// Wallet name (selects <datadir>/<name>); defaults to the config's `default_wallet`.
    #[arg(long, value_name = "NAME")]
    pub wallet: Option<String>,
}

#[cfg(feature = "cli")]
#[derive(Debug, Clone, clap::Args)]
pub struct ExportXpubArgs {
    /// Wallet name (selects <datadir>/<name>); must be a `coin = "bitcoin"` wallet. Defaults
    /// to the config's `default_wallet`.
    #[arg(long, value_name = "NAME")]
    pub wallet: Option<String>,
}

#[cfg(feature = "cli")]
#[derive(Debug, Clone, clap::Args)]
pub struct DeriveAddressArgs {
    /// Wallet name (selects <datadir>/<name>). The default key source is this wallet's
    /// `keys.toml`; with `--mnemonic`/`--ufvk` the wallet is only consulted for its receiver
    /// configuration and to check the supplied key against its pinned viewing key. Omitted, the
    /// `default` wallet's configuration is used.
    #[arg(long)]
    pub wallet: Option<String>,

    /// Derive from a BIP-39 mnemonic instead of the wallet's `keys.toml`. The phrase is read
    /// from `ROSE_MNEMONIC`, else `--mnemonic-file`, else stdin.
    #[arg(long)]
    pub mnemonic: bool,

    /// Read the mnemonic phrase from this file (trailing newline trimmed) instead of stdin,
    /// for non-interactive derivation. Implies `--mnemonic`; `ROSE_MNEMONIC` takes precedence.
    #[arg(long, value_name = "FILE")]
    pub mnemonic_file: Option<PathBuf>,

    /// Derive from this Unified Full Viewing Key (see `export-ufvk`) instead of a mnemonic or
    /// the wallet's `keys.toml`. Addresses are the same either way - only spending needs a seed.
    #[arg(long, value_name = "UFVK", conflicts_with_all = ["mnemonic", "mnemonic_file"])]
    pub ufvk: Option<String>,

    /// Bitcoin wallets: derive from this account xpub (the `[fingerprint/84'/coin'/0']xpub...`
    /// form `export-xpub` prints, or a bare xpub) instead of a mnemonic or the wallet itself.
    #[arg(
        long,
        value_name = "XPUB",
        conflicts_with_all = ["mnemonic", "mnemonic_file", "ufvk"]
    )]
    pub xpub: Option<String>,

    /// Which receivers to derive, in `getnewaddress`'s `address_type` syntax: `unified`
    /// (alias `default`) for the wallet's configured receivers, `transparent` for a bare
    /// t-address, or a shielded pool list such as `orchard` / `sapling,orchard`. Defaults to
    /// what `getnewaddress` would hand out for this wallet.
    #[arg(long, value_name = "TYPE")]
    pub address_type: Option<String>,

    /// The first index to derive: a diversifier index for a Unified Address, or the BIP-44
    /// external child index for a bare transparent address (the same index the daemon exposes).
    #[arg(long, default_value_t = 0)]
    pub index: u64,

    /// How many consecutive indices to derive (one address per line), for pre-provisioning a
    /// batch of deposit addresses.
    #[arg(long, default_value_t = 1)]
    pub count: u32,

    /// Emit a JSON object instead of one address per line.
    #[arg(long)]
    pub json: bool,
}

#[cfg(feature = "cli")]
#[derive(Debug, Clone, clap::Args)]
pub struct RescanArgs {
    /// Wallet name (selects <datadir>/<name>); defaults to the config's `default_wallet`.
    #[arg(long, value_name = "NAME")]
    pub wallet: Option<String>,

    /// Skip the interactive confirmation prompt (for non-interactive/automated recovery).
    #[arg(long)]
    pub yes: bool,

    /// Change the recorded wallet birthday before the rebuild, so the rescan starts there
    /// instead of at the birthday `init` recorded: a block height, or a UTC date as
    /// YYYY-MM-DD, resolved exactly as `init --birthday` resolves it (against the upstream's
    /// block times, or offline on a kyoto wallet). Earlier only scans more; later than the
    /// wallet's first transaction silently drops that history from the rebuilt wallet.
    #[arg(long, value_name = "HEIGHT|YYYY-MM-DD", value_parser = crate::init::Birthday::parse)]
    pub birthday: Option<crate::init::Birthday>,
}

impl AppConfig {
    /// Resolve the effective configuration from CLI flags and the TOML file, using rose's
    /// file/port defaults.
    #[cfg(feature = "cli")]
    pub fn resolve(cli: &Cli) -> anyhow::Result<AppConfig> {
        Self::resolve_with(cli, &ROSE_DEFAULTS)
    }

    /// Resolve the effective configuration from clap-free overrides and the TOML file, using
    /// rose's file/port defaults - the library consumer's entry point ([`Cli`] converts into
    /// The wallet a `--wallet` flag names, or the config's [`implied_wallet`](Self::implied_wallet)
    /// when it was omitted - the one rule for every subcommand's `--wallet` (init,
    /// export-ufvk, export-xpub, rescan, `rosed --restore-if-empty`). A config that declares
    /// one wallet (`[wallets.btc]`, say) makes every subcommand address it with no flag; one
    /// that declares several and names no `default_wallet` makes the flag required, with an
    /// error listing the candidates. Before this the flags defaulted to the literal
    /// `"default"`, which on a Bitcoin-only config silently meant a phantom Zcash wallet.
    pub fn wallet_or_default(&self, wallet: Option<&str>) -> anyhow::Result<String> {
        if let Some(wallet) = wallet {
            return Ok(wallet.to_owned());
        }
        self.implied_wallet.clone().ok_or_else(|| {
            let names: Vec<&str> = self.wallets.keys().map(String::as_str).collect();
            anyhow::anyhow!(
                "--wallet is required: this configuration declares several wallets ({}) and \
                 sets no `default_wallet`, so none is implied",
                names.join(", ")
            )
        })
    }

    /// [`ConfigOverrides`], so this and [`resolve`](Self::resolve) cannot disagree).
    pub fn resolve_overrides(overrides: &ConfigOverrides) -> anyhow::Result<AppConfig> {
        Self::resolve_overrides_with(overrides, &ROSE_DEFAULTS)
    }

    /// The datadir named in the overrides (the command line) or in the environment, before the
    /// config file is read. The file is located *before* its own `datadir` can apply (like
    /// bitcoind: `-conf` resolution never depends on a datadir set inside the file), so the
    /// lookup uses only overrides/env. Datadir precedence overall: CLI > env (`ROSE_DATADIR`) >
    /// config file > default.
    fn cli_datadir(overrides: &ConfigOverrides, defaults: &BinaryDefaults) -> Option<PathBuf> {
        overrides
            .datadir
            .clone()
            .or_else(|| std::env::var_os(defaults.datadir_env).map(PathBuf::from))
    }

    /// The config file [`resolve`](Self::resolve) would read for this invocation, whether or not
    /// it exists. Exposed so `rose config check` can name the file it is checking - and can only
    /// ever check the same one the daemon would load.
    #[cfg(feature = "cli")]
    pub fn conf_path(cli: &Cli) -> PathBuf {
        Self::conf_path_with(cli, &ROSE_DEFAULTS)
    }

    /// [`conf_path`](Self::conf_path) with the binary's defaults.
    #[cfg(feature = "cli")]
    pub fn conf_path_with(cli: &Cli, defaults: &BinaryDefaults) -> PathBuf {
        Self::conf_path_overrides_with(&ConfigOverrides::from(cli), defaults)
    }

    /// [`conf_path`](Self::conf_path) from clap-free overrides.
    pub fn conf_path_overrides_with(
        overrides: &ConfigOverrides,
        defaults: &BinaryDefaults,
    ) -> PathBuf {
        overrides.conf.clone().unwrap_or_else(|| {
            Self::cli_datadir(overrides, defaults)
                .unwrap_or_else(|| PathBuf::from(defaults.datadir))
                .join(defaults.conf_file)
        })
    }

    /// Resolve the effective configuration with the binary's defaults (`rose`).
    #[cfg(feature = "cli")]
    pub fn resolve_with(cli: &Cli, defaults: &BinaryDefaults) -> anyhow::Result<AppConfig> {
        Self::resolve_overrides_with(&ConfigOverrides::from(cli), defaults)
    }

    /// [`resolve_overrides`](Self::resolve_overrides) with caller-supplied binary defaults.
    pub fn resolve_overrides_with(
        overrides: &ConfigOverrides,
        defaults: &BinaryDefaults,
    ) -> anyhow::Result<AppConfig> {
        // The overrides mirror the CLI flags one for one, so the body keeps its `cli` naming
        // (and its diff against the pre-overrides version stays a two-line header change).
        let cli = overrides;
        let cli_datadir = Self::cli_datadir(cli, defaults);
        let conf_path = Self::conf_path_overrides_with(cli, defaults);

        // Only the implied location is checked: an explicit `--conf` names exactly one file,
        // and a daemon with its own defaults (an embedder's) has no history to trip over.
        if cli.conf.is_none() && defaults.conf_file != LEGACY_CONF_FILE && !conf_path.exists() {
            let legacy = conf_path.with_file_name(LEGACY_CONF_FILE);
            if legacy.exists() {
                anyhow::bail!(
                    "found {} but no {}: the config file was renamed with the daemon. Rename it \
                     (its contents are unchanged), or pass --conf {}",
                    legacy.display(),
                    conf_path.display(),
                    legacy.display()
                );
            }
        }

        let file: ConfigFile = if conf_path.exists() {
            let text = std::fs::read_to_string(&conf_path)
                .with_context(|| format!("reading config {}", conf_path.display()))?;
            toml::from_str(&text)
                .with_context(|| format!("parsing config {}", conf_path.display()))?
        } else {
            ConfigFile::default()
        };

        let datadir = cli_datadir
            .or_else(|| file.datadir.clone())
            .unwrap_or_else(|| PathBuf::from(defaults.datadir));

        // Network: CLI --regtest/--testnet/--network override the file.
        let network = if cli.regtest {
            crate::network::regtest()
        } else if cli.testnet {
            ZNetwork::Test
        } else if let Some(n) = &cli.network {
            ZNetwork::parse(n)?
        } else if let Some(n) = &file.network {
            ZNetwork::parse(n)?
        } else {
            ZNetwork::Test
        };

        // `btc_testnet`: which public Bitcoin test network a testnet daemon's Bitcoin wallets
        // use. Validated here in every build (like `coin`): a build without the bitcoin
        // engine refuses a set key rather than silently ignoring it, and so does any daemon
        // whose environment is not the test one - main and regtest each name exactly one
        // Bitcoin chain, so the key would be inert there.
        #[cfg(not(feature = "bitcoin"))]
        if let Some(token) = &file.btc_testnet {
            anyhow::bail!(
                "btc_testnet = {token:?} requires a rose build with the `bitcoin` feature \
                 (this build supports: {})",
                Coin::supported_names()
            );
        }
        #[cfg(feature = "bitcoin")]
        let btc_testnet = match &file.btc_testnet {
            None => crate::coin::BitcoinTestnet::default(),
            Some(token) => {
                let testnet = crate::coin::BitcoinTestnet::parse(token).ok_or_else(|| {
                    anyhow::anyhow!(
                        "unsupported btc_testnet {token:?} (expected one of: {})",
                        crate::coin::BitcoinTestnet::supported_names()
                    )
                })?;
                if !matches!(network, ZNetwork::Test) {
                    anyhow::bail!(
                        "btc_testnet = {token:?} applies only to a testnet daemon \
                         (network = \"test\"); this daemon's network is {:?}",
                        network.name()
                    );
                }
                testnet
            }
        };

        // The wallet meant when none is named. An explicit `default_wallet` wins; a file
        // that declares exactly one wallet means that one (so a Bitcoin-only config with just
        // `[wallets.btc]` gets no phantom Zcash "default" beside it); and with several
        // declared and none named, routing keeps the literal `default` while the
        // subcommands' `--wallet` becomes required (`implied_wallet` is `None`).
        let sole_declared = match file.wallets.keys().collect::<Vec<_>>().as_slice() {
            [only] => Some((*only).clone()),
            _ => None,
        };
        let default_wallet = file
            .default_wallet
            .clone()
            .or(sole_declared)
            .unwrap_or_else(|| "default".to_string());
        let implied_wallet = (file.default_wallet.is_some() || file.wallets.len() <= 1)
            .then(|| default_wallet.clone());

        // keys.toml location override (so the encrypted seed can be a mounted Secret, separate
        // from the disposable datadir). The global `[keys] keys_file` / `ROSE_KEYS_FILE` /
        // `--keys-file` applies to the default wallet; a per-wallet `[wallets.<name>] keys_file`
        // overrides it for that wallet.
        let keys_file_global = cli
            .keys_file
            .clone()
            .or_else(|| file.keys.as_ref().and_then(|k| k.keys_file.clone()));

        // Global pool defaults (`[pools]`), validated before any per-wallet override.
        #[cfg(feature = "zcash")]
        let pools = resolve_global_pools(file.pools.as_ref())?;

        // The global `[keys] fresh_wallet_birthday_margin`, hoisted ahead of the wallet loop
        // (each wallet's own key overrides it, and a wallet with neither falls back to its
        // coin's built-in margin; `[keys]` itself resolves further down).
        let global_birthday_margin = file
            .keys
            .as_ref()
            .and_then(|k| k.fresh_wallet_birthday_margin);

        // Wallets: from file, plus an implicit default if none declared. Each wallet's pools and
        // default receivers are resolved against the global `[pools]` defaults, with the same
        // subset validation applied per wallet.
        let mut wallets = BTreeMap::new();
        for (name, w) in &file.wallets {
            let keys_file = w.keys_file.clone().or_else(|| {
                if name == &default_wallet {
                    keys_file_global.clone()
                } else {
                    None
                }
            });
            let coin = match &w.coin {
                None => Coin::DEFAULT,
                Some(token) => Coin::parse(token).ok_or_else(|| {
                    anyhow::anyhow!(
                        "unsupported coin {token:?} for wallet {name:?} (this build supports: {})",
                        Coin::supported_names()
                    )
                })?,
            };
            // Whether this wallet is the Zcash engine's. Spelled as a bool rather than a
            // comparison because `Coin::Zcash` does not exist in a bitcoin-only build, where
            // every configured wallet is a Bitcoin one and the refusals below cover them all.
            #[cfg(feature = "zcash")]
            let is_zcash = coin == Coin::Zcash;
            #[cfg(not(feature = "zcash"))]
            let is_zcash = false;
            // Every other per-wallet key is the Zcash engine's (pool selection, the
            // zebra/lightwalletd backend overrides). On a non-Zcash wallet a set key would be
            // silently ignored, which reads as configuration and isn't - refuse it instead.
            if !is_zcash {
                // `server` is legal on any coin - each engine resolves the token with its own
                // grammar (`backend::resolve_for_wallet` for Zcash, `btc::chain` for Bitcoin),
                // so a Zcash token on a bitcoin wallet is refused there, naming the grammar.
                let zcash_only: &[(&str, bool)] = &[
                    ("tls", w.tls.is_some()),
                    ("tls_roots", w.tls_roots.is_some()),
                    (
                        "tls_insecure_skip_verify",
                        w.tls_insecure_skip_verify.is_some(),
                    ),
                    ("tls_ca_file", w.tls_ca_file.is_some()),
                    ("tls_pinned_sha256", w.tls_pinned_sha256.is_some()),
                    (
                        "assume_transparent_in_compact_blocks",
                        w.assume_transparent_in_compact_blocks.is_some(),
                    ),
                    ("pools", w.pools.is_some()),
                    ("default_receivers", w.default_receivers.is_some()),
                    ("transparent", w.transparent.is_some()),
                    ("transparent_default", w.transparent_default.is_some()),
                    ("transparent_gap_limit", w.transparent_gap_limit.is_some()),
                    (
                        "transparent_initial_scan",
                        w.transparent_initial_scan.is_some(),
                    ),
                    (
                        "transparent_allow_beyond_recovery_window",
                        w.transparent_allow_beyond_recovery_window.is_some(),
                    ),
                    (
                        "transparent_gap_warn_threshold",
                        w.transparent_gap_warn_threshold.is_some(),
                    ),
                ];
                if let Some((key, _)) = zcash_only.iter().find(|(_, set)| *set) {
                    anyhow::bail!(
                        "[wallets.{name}] {key} does not apply to a {} wallet (it configures \
                         the Zcash engine)",
                        coin.name()
                    );
                }
            }
            // The mirror image: the Bitcoin engine's own knob is refused on a Zcash wallet,
            // naming the key that plays its role there.
            if is_zcash && w.lookahead.is_some() {
                anyhow::bail!(
                    "[wallets.{name}] lookahead does not apply to a zcash wallet (it configures \
                     the Bitcoin engine's address lookahead; a Zcash wallet's gap limit is \
                     transparent_gap_limit)"
                );
            }
            if w.lookahead == Some(0) {
                anyhow::bail!(
                    "[wallets.{name}] lookahead must be at least 1 (0 would watch no address \
                     past the last revealed one and recover nothing on a restore)"
                );
            }
            if is_zcash && w.initial_scan.is_some() {
                anyhow::bail!(
                    "[wallets.{name}] initial_scan does not apply to a zcash wallet (it \
                     configures the Bitcoin engine's initial scan depth; a Zcash wallet's is \
                     transparent_initial_scan)"
                );
            }
            if is_zcash && w.allow_sends_without_mempool_view.is_some() {
                anyhow::bail!(
                    "[wallets.{name}] allow_sends_without_mempool_view does not apply to a \
                     zcash wallet (it lets a kyoto Bitcoin wallet spend before it has a \
                     mempool view of its own unconfirmed history)"
                );
            }
            let dir = w.dir.clone().unwrap_or_else(|| wallet_dir(&datadir, name));
            let backend_override = resolve_wallet_backend(name, w)?;
            #[cfg(feature = "zcash")]
            let (
                enabled,
                default_receivers,
                transparent_enabled,
                transparent_default,
                transparent_gap_limit,
                transparent_initial_scan,
                transparent_allow_beyond_recovery_window,
                transparent_gap_warn_threshold,
            ) = resolve_wallet_pools(
                name,
                w.pools.as_deref(),
                w.default_receivers.as_deref(),
                w.transparent,
                w.transparent_default,
                w.transparent_gap_limit,
                w.transparent_initial_scan,
                w.transparent_allow_beyond_recovery_window,
                w.transparent_gap_warn_threshold,
                &pools,
            )?;
            #[cfg(feature = "bitcoin")]
            let chain = coin.chain_with(network, btc_testnet);
            #[cfg(not(feature = "bitcoin"))]
            let chain = coin.chain(network);
            wallets.insert(
                name.clone(),
                WalletEntry {
                    dir,
                    keys_file,
                    coin,
                    chain,
                    backend: backend_override,
                    #[cfg(feature = "zcash")]
                    pools: enabled,
                    #[cfg(feature = "zcash")]
                    default_receivers,
                    #[cfg(feature = "zcash")]
                    transparent_enabled,
                    #[cfg(feature = "zcash")]
                    transparent_default,
                    #[cfg(feature = "zcash")]
                    transparent_gap_limit,
                    #[cfg(feature = "zcash")]
                    transparent_initial_scan,
                    #[cfg(feature = "zcash")]
                    transparent_allow_beyond_recovery_window,
                    #[cfg(feature = "zcash")]
                    transparent_gap_warn_threshold,
                    fresh_wallet_birthday_margin: w
                        .fresh_wallet_birthday_margin
                        .or(global_birthday_margin)
                        .unwrap_or_else(|| crate::init::default_fresh_wallet_birthday_margin(coin)),
                    lookahead: w.lookahead.unwrap_or(DEFAULT_LOOKAHEAD),
                    initial_scan: w.initial_scan.unwrap_or(0),
                    allow_sends_without_mempool_view: w
                        .allow_sends_without_mempool_view
                        .unwrap_or(false),
                },
            );
        }
        wallets
            .entry(default_wallet.clone())
            .or_insert_with(|| WalletEntry {
                dir: wallet_dir(&datadir, &default_wallet),
                keys_file: keys_file_global.clone(),
                coin: Coin::DEFAULT,
                chain: Coin::DEFAULT.chain(network),
                backend: WalletBackendOverride::default(),
                #[cfg(feature = "zcash")]
                pools: pools.enabled.clone(),
                #[cfg(feature = "zcash")]
                default_receivers: pools.default_receivers.clone(),
                #[cfg(feature = "zcash")]
                transparent_enabled: pools.transparent_enabled,
                #[cfg(feature = "zcash")]
                transparent_default: pools.transparent_default,
                #[cfg(feature = "zcash")]
                transparent_gap_limit: pools.transparent_gap_limit,
                #[cfg(feature = "zcash")]
                transparent_initial_scan: pools.transparent_initial_scan,
                #[cfg(feature = "zcash")]
                transparent_allow_beyond_recovery_window: pools
                    .transparent_allow_beyond_recovery_window,
                #[cfg(feature = "zcash")]
                transparent_gap_warn_threshold: pools.transparent_gap_warn_threshold,
                fresh_wallet_birthday_margin: global_birthday_margin
                    .unwrap_or(crate::init::FRESH_WALLET_BIRTHDAY_MARGIN),
                lookahead: DEFAULT_LOOKAHEAD,
                initial_scan: 0,
                allow_sends_without_mempool_view: false,
            });

        let backend_file = file.backend.unwrap_or(BackendFile {
            server: None,
            connect_timeout_secs: None,
            reconnect_base_secs: None,
            reconnect_max_secs: None,
            p2p_receive_window_bytes: None,
            rfc1918_is_local: None,
            allow_remote_cleartext: None,
            tls: None,
            tls_roots: None,
            tls_insecure_skip_verify: None,
            tls_ca_file: None,
            tls_pinned_sha256: None,
            assume_transparent_in_compact_blocks: None,
            proxy: None,
        });
        // `[backend]`'s endpoint half configures the Zcash upstream (a zebrad JSON-RPC or a
        // lightwalletd), so a build without that engine refuses a set key naming it rather than
        // carrying a value nothing will ever dial. The section itself stays legal on every
        // build: its timing and locality keys are what both engines' reconnect and
        // cleartext-credential policies read.
        #[cfg(not(feature = "zcash"))]
        {
            let zcash_only: &[(&str, bool)] = &[
                (
                    "server (or --server)",
                    cli.server.is_some() || backend_file.server.is_some(),
                ),
                ("tls", backend_file.tls.is_some()),
                ("tls_roots", backend_file.tls_roots.is_some()),
                (
                    "tls_insecure_skip_verify",
                    backend_file.tls_insecure_skip_verify.is_some(),
                ),
                ("tls_ca_file", backend_file.tls_ca_file.is_some()),
                (
                    "tls_pinned_sha256",
                    backend_file.tls_pinned_sha256.is_some(),
                ),
                (
                    "assume_transparent_in_compact_blocks",
                    backend_file.assume_transparent_in_compact_blocks.is_some(),
                ),
                ("proxy", backend_file.proxy.is_some()),
            ];
            if let Some((key, _)) = zcash_only.iter().find(|(_, set)| *set) {
                anyhow::bail!(
                    "[backend] {key} configures the Zcash engine, which this build does not \
                     carry (this build supports: {})",
                    Coin::supported_names()
                );
            }
        }
        let server = select_server_token(cli.server.clone(), backend_file.server);
        let reconnect_base_secs = backend_file.reconnect_base_secs.unwrap_or(1).max(1);
        if let Some(bytes) = backend_file.p2p_receive_window_bytes {
            if !(512..=65535).contains(&bytes) {
                anyhow::bail!(
                    "[backend] p2p_receive_window_bytes must be between 512 and 65535 (one \
                     segment is 1448; leave it unset for the kernel's default), got {bytes}"
                );
            }
        }
        let backend = BackendConfig {
            server,
            connect_timeout_secs: backend_file.connect_timeout_secs.unwrap_or(10).max(1),
            reconnect_base_secs,
            reconnect_max_secs: backend_file
                .reconnect_max_secs
                .unwrap_or(60)
                .max(reconnect_base_secs),
            p2p_receive_window_bytes: backend_file.p2p_receive_window_bytes,
            rfc1918_is_local: backend_file.rfc1918_is_local.unwrap_or(true),
            allow_remote_cleartext: backend_file.allow_remote_cleartext.unwrap_or(false),
            tls: match backend_file.tls.as_deref() {
                Some(mode) => crate::backend::parse_tls_mode(mode).context("[backend] tls")?,
                None => None,
            },
            tls_roots: match backend_file.tls_roots.as_deref() {
                Some(roots) => {
                    crate::backend::TlsRoots::parse(roots).context("[backend] tls_roots")?
                }
                None => crate::backend::TlsRoots::default(),
            },
            tls_insecure_skip_verify: backend_file.tls_insecure_skip_verify.unwrap_or(false),
            // Read now, not at connect time: an unreadable or malformed CA file must fail
            // startup rather than leave the daemon quietly falling back to the public roots
            // (the same fail-fast rule `[rpc] password_file` follows).
            tls_ca_pem: match backend_file.tls_ca_file.as_deref() {
                Some(path) => Some(std::fs::read(path).with_context(|| {
                    format!("reading [backend] tls_ca_file {}", path.display())
                })?),
                None => None,
            },
            tls_ca_file: backend_file.tls_ca_file.clone(),
            tls_pins: backend_file
                .tls_pinned_sha256
                .unwrap_or_default()
                .iter()
                .map(|s| crate::backend::CertFingerprint::parse(s))
                .collect::<anyhow::Result<Vec<_>>>()
                .context("[backend] tls_pinned_sha256")?,
            assume_transparent_in_compact_blocks: backend_file
                .assume_transparent_in_compact_blocks
                .unwrap_or(false),
            // Parsed now, like the CA file above: a malformed proxy token must fail startup
            // rather than let the daemon dial directly under a config that says otherwise -
            // the whole point of the knob is that nothing bypasses it.
            proxy: match cli.proxy.clone().or(backend_file.proxy) {
                Some(token) => {
                    Some(crate::socks::SocksProxy::parse(&token).context("[backend] proxy")?)
                }
                None => None,
            },
        };
        validate_backend_tls(&backend)?;
        // Same contradiction checks for every wallet that overrides the endpoint, against its
        // effective settings - a never-consulted pin is exactly as silent per wallet as it is
        // globally.
        for (name, entry) in &wallets {
            if !entry.backend.is_empty() {
                validate_backend_tls(&entry.backend.effective(&backend))
                    .with_context(|| format!("[wallets.{name}]"))?;
            }
        }

        #[cfg(feature = "zcash")]
        let zebra_file = file.zebra.unwrap_or_default();
        #[cfg(feature = "zcash")]
        let zebra = ZebraConfig {
            rpc_user: zebra_file.rpc_user,
            rpc_password: zebra_file.rpc_password,
            rpc_cookie: zebra_file.rpc_cookie,
        };

        #[cfg(feature = "bitcoin")]
        let bitcoind = {
            let bitcoind_file = file.bitcoind.unwrap_or_default();
            BitcoindConfig {
                server: bitcoind_file.server,
                rpc_user: bitcoind_file.rpc_user,
                rpc_password: bitcoind_file.rpc_password,
                rpc_cookie: bitcoind_file.rpc_cookie,
            }
        };

        #[cfg(feature = "bitcoin")]
        let fees = {
            let fees_file = file.fees.unwrap_or_default();
            // An unset list is the built-in chain; an explicit one is taken verbatim, so an
            // operator can drop a tier (or all of them) rather than only reorder. A repeated
            // name is refused rather than deduplicated: asking one oracle twice is never what
            // was meant, and silently collapsing it hides the typo.
            let sources = match fees_file.sources {
                None => DEFAULT_FEE_SOURCES.to_vec(),
                Some(names) => {
                    let mut sources: Vec<FeeSource> = Vec::with_capacity(names.len());
                    for name in &names {
                        let source = FeeSource::parse(name)?;
                        if sources.contains(&source) {
                            anyhow::bail!("[fees] sources names {name:?} more than once");
                        }
                        sources.push(source);
                    }
                    sources
                }
            };
            // An empty string is "unset", so a template that ships the key blank falls back to
            // the built-in endpoint instead of failing.
            let mempool_space_url = fees_file.mempool_space_url.filter(|u| !u.trim().is_empty());
            let esplora_url = fees_file.esplora_url.filter(|u| !u.trim().is_empty());
            // Validate the overrides here, where every entry point shares the rule: the daemon
            // and `config check` refuse an unusable fee endpoint identically, at startup,
            // rather than at the first send.
            for (key, url) in [
                ("mempool_space_url", mempool_space_url.as_deref()),
                ("esplora_url", esplora_url.as_deref()),
            ] {
                if let Some(url) = url {
                    crate::btc::fees::validate_endpoint_override(key, url)?;
                }
            }
            // Zero would refuse every send; Core refuses a zero -maxtxfee too. Beyond that the
            // cap is the operator's to set - there is no upper bound, since "no cap" is just a
            // large number.
            let max_tx_fee_sat = fees_file.max_tx_fee_sat.unwrap_or(DEFAULT_MAX_TX_FEE_SAT);
            if max_tx_fee_sat == 0 {
                anyhow::bail!(
                    "[fees] max_tx_fee_sat must be greater than 0 (it caps every send's \
                     absolute fee; the default is {DEFAULT_MAX_TX_FEE_SAT} sat, 0.1 BTC)"
                );
            }
            FeesConfig {
                sources,
                mempool_space_url,
                esplora_url,
                max_tx_fee_sat,
            }
        };

        #[cfg(feature = "bitcoin")]
        let mempool = {
            let mempool_file = file.mempool.unwrap_or_default();
            // Unset is the built-in chain; an explicit list is taken verbatim, so `sources =
            // []` is how the feed is turned off rather than a second knob. A repeated name is
            // refused like a repeated fee source: subscribing twice is never what was meant.
            let sources_explicit = mempool_file.sources.is_some();
            let sources = match mempool_file.sources {
                None => DEFAULT_MEMPOOL_SOURCES.to_vec(),
                Some(names) => {
                    let mut sources: Vec<MempoolSource> = Vec::with_capacity(names.len());
                    for name in &names {
                        let source = MempoolSource::parse(name)?;
                        if sources.contains(&source) {
                            anyhow::bail!("[mempool] sources names {name:?} more than once");
                        }
                        sources.push(source);
                    }
                    sources
                }
            };
            let mempool_space_url = mempool_file
                .mempool_space_url
                .filter(|u| !u.trim().is_empty());
            if let Some(url) = &mempool_space_url {
                crate::btc::mempool_feed::validate_endpoint_override("mempool_space_url", url)?;
            }
            // An IP and a port, like `kyoto://` - never a DNS name, so nothing resolves
            // outside the wallet's control at dial time.
            let p2p_peer = match mempool_file.p2p_peer.filter(|p| !p.trim().is_empty()) {
                None => None,
                Some(peer) => Some(peer.parse::<std::net::SocketAddr>().map_err(|e| {
                    anyhow::anyhow!(
                        "[mempool] p2p_peer must be \"<ip>:<port>\" (an IP address, not a DNS \
                         name; IPv6 in brackets), got {peer:?}: {e}"
                    )
                })?),
            };
            let p2p_snapshot_interval_secs = mempool_file
                .p2p_snapshot_interval_secs
                .unwrap_or(DEFAULT_P2P_SNAPSHOT_INTERVAL_SECS);
            if p2p_snapshot_interval_secs < MIN_P2P_SNAPSHOT_INTERVAL_SECS {
                anyhow::bail!(
                    "[mempool] p2p_snapshot_interval_secs must be at least \
                     {MIN_P2P_SNAPSHOT_INTERVAL_SECS}, got {p2p_snapshot_interval_secs}"
                );
            }
            MempoolConfig {
                sources,
                sources_explicit,
                mempool_space_url,
                p2p_peer,
                p2p_snapshot: mempool_file.p2p_snapshot.unwrap_or(false),
                p2p_snapshot_interval_secs,
            }
        };

        let rpc_file = file.rpc.unwrap_or(RpcFile {
            bind: None,
            port: None,
            user: None,
            password: None,
            password_file: None,
            auth: None,
            cookiefile: None,
            work_queue: None,
            allowed_methods: None,
            allow_duplicate_shielded_recipients: None,
        });
        // RPC password precedence: `--rpcpassword` / `ROSE_RPC_PASSWORD` (clap) > `[rpc]
        // password_file` > inline `[rpc] password`. A configured `password_file` that can't be
        // read is fatal (fail fast rather than silently fall through to a weaker source).
        let password_from_file = rpc_file
            .password_file
            .as_deref()
            .map(read_secret_file)
            .transpose()?;
        // RPC method safelist: validate every entry against the known method set so a typo
        // fails at startup rather than silently disabling a method the operator meant to keep
        // (or, worse, appearing to allow one it doesn't). An absent or empty list means "no
        // restriction" - never "deny everything", which would be a useless footgun.
        let allowed_methods = rpc_file.allowed_methods.unwrap_or_default();
        for m in &allowed_methods {
            if !crate::rpc::is_known_method(m) {
                anyhow::bail!(
                    "[rpc] allowed_methods contains unknown method {m:?}; \
                     it is not an RPC method this build implements (see the example config \
                     for the full list)"
                );
            }
        }
        let bind: IpAddr = cli
            .rpc_bind
            .clone()
            .or(rpc_file.bind)
            .unwrap_or_else(|| "127.0.0.1".to_string())
            .parse()
            .context("parsing rpc bind address")?;
        let rpc = RpcConfig {
            bind,
            port: cli.rpc_port.or(rpc_file.port).unwrap_or(match network {
                ZNetwork::Main => defaults.rpc_port_main,
                ZNetwork::Test | ZNetwork::Regtest => defaults.rpc_port_test,
            }),
            user: cli.rpc_user.clone().or(rpc_file.user),
            password: cli
                .rpc_password
                .clone()
                .or(password_from_file)
                .or(rpc_file.password),
            // rpcauth entries accumulate across CLI and file, matching bitcoind where
            // every -rpcauth/conf line is an accepted credential.
            auth: cli
                .rpc_auth
                .iter()
                .cloned()
                .chain(rpc_file.auth.unwrap_or_default())
                .collect(),
            cookiefile: rpc_file
                .cookiefile
                .or_else(|| Some(datadir.join(".cookie"))),
            work_queue: rpc_file.work_queue.unwrap_or(100).max(1),
            allowed_methods,
            allow_duplicate_shielded_recipients: rpc_file
                .allow_duplicate_shielded_recipients
                .unwrap_or(false),
        };

        let keys_file = file.keys.unwrap_or(KeysFile {
            age_identity: None,
            auto_unlock: None,
            keys_file: None,
            bootstrap_from_keys: None,
            allow_multiple_spending_wallets: None,
            fresh_wallet_birthday_margin: None,
        });
        let keys = KeysConfig {
            // Default to <datadir>/identity.txt, matching where `rose init` writes the
            // identity, so auto-unlock works out of the box.
            age_identity: cli
                .age_identity
                .clone()
                .or(keys_file.age_identity)
                .or_else(|| Some(datadir.join("identity.txt"))),
            auto_unlock: keys_file.auto_unlock.unwrap_or(true),
            bootstrap_from_keys: keys_file.bootstrap_from_keys.unwrap_or(true),
            allow_multiple_spending_wallets: keys_file
                .allow_multiple_spending_wallets
                .unwrap_or(false),
            fresh_wallet_birthday_margin: global_birthday_margin,
        };

        let sync_file = file.sync.unwrap_or(SyncFile {
            interval_secs: None,
            rebroadcast_secs: None,
            fetch_memos: None,
            batch_size: None,
            writer_cache_mib: None,
            enhance_concurrency: None,
        });
        let sync = SyncConfig {
            // Clamp to >= 1s so a misconfigured `interval_secs = 0` can't make the actor busy-poll
            // the backend with no idle delay between passes (same guard as `rebroadcast_secs`).
            interval_secs: sync_file.interval_secs.unwrap_or(20).max(1),
            rebroadcast_secs: sync_file.rebroadcast_secs.unwrap_or(60).max(1),
            fetch_memos: sync_file.fetch_memos.unwrap_or(true),
            // A zero-block batch would make the scan loop spin without advancing.
            batch_size: sync_file.batch_size.unwrap_or(DEFAULT_BATCH_SIZE).max(1),
            // SQLite treats a zero cache as "no cache"; clamp so a typo cannot make every
            // page read a syscall.
            writer_cache_mib: sync_file
                .writer_cache_mib
                .unwrap_or(DEFAULT_WRITER_CACHE_MIB)
                .max(1),
            // Zero would stall the drain outright.
            enhance_concurrency: sync_file
                .enhance_concurrency
                .unwrap_or(DEFAULT_ENHANCE_CONCURRENCY)
                .max(1),
        };

        #[cfg(feature = "zcash")]
        let spend_file = file.spend.unwrap_or_default();
        #[cfg(feature = "zcash")]
        let spend = SpendConfig {
            trusted_confirmations: spend_file.trusted_confirmations.unwrap_or(3),
            untrusted_confirmations: spend_file.untrusted_confirmations.unwrap_or(10),
            trust_own_transactions: spend_file.trust_own_transactions.unwrap_or(true),
            privacy: spend_file
                .privacy_policy
                .as_deref()
                .map(SendPrivacy::parse)
                .transpose()?
                .unwrap_or(SendPrivacy::AllowRevealedRecipients),
            orchard_action_limit: spend_file
                .orchard_action_limit
                .unwrap_or(DEFAULT_ORCHARD_ACTION_LIMIT),
            max_tx_bytes: spend_file.max_tx_bytes.unwrap_or(DEFAULT_MAX_TX_BYTES),
            cache_proving_key: spend_file.cache_proving_key.unwrap_or(true),
            pipeline_proving: spend_file.pipeline_proving.unwrap_or(false),
            target_note_count: spend_file
                .target_note_count
                .unwrap_or(DEFAULT_TARGET_NOTE_COUNT),
            min_split_output_value: spend_file
                .min_split_output_value
                .unwrap_or(DEFAULT_MIN_SPLIT_OUTPUT_VALUE),
            shutdown_drain_secs: spend_file
                .shutdown_drain_secs
                .unwrap_or(DEFAULT_SHUTDOWN_DRAIN_SECS),
            max_send_catchup_blocks: spend_file
                .max_send_catchup_blocks
                .unwrap_or(DEFAULT_MAX_SEND_CATCHUP_BLOCKS),
        };
        // Fail at startup, not on the first balance/send call.
        #[cfg(feature = "zcash")]
        {
            spend.confirmations_policy()?;
            spend.validate_change_splitting()?;
        }

        let health_file = file.health.unwrap_or(HealthFile {
            enabled: None,
            bind: None,
            port: None,
            readiness: None,
            max_scan_lag: None,
        });
        let health = HealthConfig {
            enabled: health_file.enabled.unwrap_or(true),
            bind: health_file
                .bind
                .unwrap_or_else(|| "127.0.0.1".to_string())
                .parse()
                .context("parsing health bind address")?,
            port: health_file.port.unwrap_or(defaults.health_port),
            // Default to "synced": `/readyz` reports ready only once the wallet has actually
            // scanned to (near) the tip, so a client routed by readiness never sees an empty or
            // stale balance/history as authoritative during initial sync or a `--restore` (audit
            // 3.15). Deployments that prefer reachability-over-freshness - reaching rose while it
            // catches up, at the cost of possibly-lagging reads - can set `readiness = "connected"`.
            readiness: health_file
                .readiness
                .as_deref()
                .map(ReadinessMode::parse)
                .transpose()?
                .unwrap_or(ReadinessMode::Synced),
            max_scan_lag: health_file.max_scan_lag.unwrap_or(4),
        };

        #[cfg(feature = "zcash")]
        let fleet_file = file.fleet.unwrap_or(FleetFile {
            enabled: None,
            manifest_dir: None,
            dir: None,
            shard_size: None,
            cohort_depth: None,
        });
        #[cfg(feature = "zcash")]
        // The fleet is Zcash's, like every wallet this build serves. Both defaults sit under the
        // datadir's coin directory; an override is taken verbatim, so an operator's path keeps
        // its meaning exactly as a `[wallets.<name>] dir` does.
        let fleet_coin = Coin::Zcash;
        #[cfg(feature = "zcash")]
        let fleet = FleetConfig {
            enabled: fleet_file.enabled.unwrap_or(false),
            manifest_dir: fleet_file
                .manifest_dir
                .map(|p| datadir.join(p))
                .unwrap_or_else(|| fleet_manifest_dir(&datadir, fleet_coin)),
            dir: fleet_file
                .dir
                .map(|p| datadir.join(p))
                .unwrap_or_else(|| fleet_dir(&datadir, fleet_coin)),
            coin: fleet_coin,
            shard_size: fleet_file.shard_size.unwrap_or(DEFAULT_FLEET_SHARD_SIZE),
            cohort_depth: fleet_file
                .cohort_depth
                .unwrap_or(DEFAULT_FLEET_COHORT_DEPTH),
        };
        // A shard is a scan domain: zero accounts per shard would mean no wallet is ever placed.
        #[cfg(feature = "zcash")]
        if fleet.shard_size == 0 {
            anyhow::bail!("[fleet] shard_size must be at least 1");
        }
        // A wallet directory that overlaps one of the fleet's would put two owners' state in one
        // tree - see `fleet_path_conflict`. Refused only when the fleet actually runs: with
        // `[fleet] enabled` false nothing reads or writes those paths, so a deployment that has
        // long had a wallet called `fleet` keeps starting, and `rose config check` reports the
        // latent overlap as a warning instead.
        #[cfg(feature = "zcash")]
        if fleet.enabled {
            if let Some((name, wallet_path, fleet_path)) = fleet_path_conflict(&wallets, &fleet) {
                anyhow::bail!(
                    "wallet '{name}' has its data directory at {}, which overlaps the fleet's \
                     {}. Rename the wallet, or point [wallets.{name}] dir (or the [fleet] \
                     manifest_dir/dir) somewhere else",
                    wallet_path.display(),
                    fleet_path.display(),
                );
            }
        }

        let log_file = file.log.unwrap_or(LogFile {
            level: None,
            format: None,
        });
        let log = LogConfig {
            level: log_file.level.unwrap_or_else(|| "info".to_string()),
            format: log_file.format.unwrap_or_else(|| "text".to_string()),
        };
        // `init_tracing` treats anything that is not "json" as text, so a typo like "jsonl"
        // would silently produce text logs; refuse it here instead (and `config check`
        // reports the same refusal without starting anything).
        if !["text", "json"]
            .iter()
            .any(|v| log.format.eq_ignore_ascii_case(v))
        {
            anyhow::bail!(
                "[log] format must be \"text\" or \"json\", got {:?}",
                log.format
            );
        }

        Ok(AppConfig {
            network,
            #[cfg(feature = "bitcoin")]
            btc_testnet,
            datadir,
            default_wallet,
            implied_wallet,
            wallets,
            backend,
            #[cfg(feature = "zcash")]
            zebra,
            #[cfg(feature = "bitcoin")]
            bitcoind,
            #[cfg(feature = "bitcoin")]
            fees,
            #[cfg(feature = "bitcoin")]
            mempool,
            rpc,
            keys,
            sync,
            #[cfg(feature = "zcash")]
            spend,
            #[cfg(feature = "zcash")]
            pools,
            health,
            log,
            #[cfg(feature = "zcash")]
            fleet,
        })
    }
}

/// Refuse a configuration that opts into multiple spending wallets **when it is the `rose`
/// daemon that would run it**.
///
/// [`KeysConfig::allow_multiple_spending_wallets`] is honored only by an embedded node, whose
/// host application is the authorization boundary and names the wallet on every call. The
/// daemon serves JSON-RPC, where a credential is spend authority for whichever wallet the
/// request routes to - so with two spenders loaded, one leaked credential reaches both seeds
/// and "which key can this credential spend?" has no single answer. Rather than let that be
/// configured by accident, the binary refuses to start.
///
/// Called by `daemon::run` and by `rose config check` (which reports what the daemon would do),
/// and deliberately *not* by [`crate::node::NodeBuilder`] - that asymmetry is the whole
/// mechanism by which the option stays library-only.
pub fn reject_multiple_spenders_in_daemon(config: &AppConfig) -> anyhow::Result<()> {
    if config.keys.allow_multiple_spending_wallets {
        anyhow::bail!(
            "[keys] allow_multiple_spending_wallets is set, which the rose daemon does not \
             support: over RPC a credential is spend authority for whichever wallet a request \
             routes to, so more than one loaded spending wallet leaves no single answer to \
             \"which key can this credential spend?\". The option exists for applications \
             embedding rose as a library, where the host application is the authorization \
             boundary and names the wallet on every call. To run several writable wallets under \
             the daemon, run one rose per wallet (separate datadirs and ports); otherwise unset \
             the option and keep one spending wallet plus any number of watch-only replicas."
        );
    }
    Ok(())
}

/// Refuse the shipped placeholder RPC password, on every network. The example config and the
/// deploy templates ship `change-me`/`CHANGE-ME`, so a config that still carries it was never
/// edited - and the RPC credential is spend authority, so a daemon must not come up behind a
/// password printed in a public repository. The rule used to apply to mainnet only, which let
/// every testnet sample start on the literal placeholder; a testnet stack that just works on
/// the committed value is one nobody is prompted to change, so now nothing does.
///
/// Deliberately *not* part of [`AppConfig::resolve`]: it is a startup policy, not a parse rule,
/// and `resolve` is used by tooling (`config check`, `config show`) that must be able to
/// describe such a config rather than fail to build it. Both the daemon and `rose config check`
/// call this, so the two always agree on the verdict.
pub fn reject_placeholder_password(config: &AppConfig) -> anyhow::Result<()> {
    if config
        .rpc
        .password
        .as_ref()
        .is_some_and(|p| p.expose().trim().eq_ignore_ascii_case("change-me"))
    {
        anyhow::bail!(
            "[rpc] password is still the example placeholder \"CHANGE-ME\"; set a real password \
             (in the file, via [rpc] password_file, or as ROSE_RPC_PASSWORD in the environment) \
             before starting - on any network"
        );
    }
    Ok(())
}

/// Resolve and validate the global `[pools]` section. `enabled` defaults to Orchard-only;
/// `default_receivers` defaults to the enabled set. The receivers must be a subset of the
/// enabled pools.
/// Reject `[backend]` TLS settings that contradict each other, at load rather than at connect.
///
/// The failure being prevented is a *silent* one: a pin or a private CA that is never consulted
/// looks in the config exactly like one that is, so an operator who believes the connection is
/// authenticated would have no signal that it isn't. Two shapes are caught here (the third, a
/// bare `host:port` that the locality heuristic resolves to plaintext, is caught at connect,
/// where the heuristic has run).
fn validate_backend_tls(backend: &BackendConfig) -> anyhow::Result<()> {
    let authenticating = backend.tls_ca_pem.is_some() || !backend.tls_pins.is_empty();
    if authenticating && backend.tls_insecure_skip_verify {
        anyhow::bail!(
            "[backend] tls_insecure_skip_verify = true cannot be combined with \
             tls_pinned_sha256/tls_ca_file: it disables the very check they configure. Remove \
             tls_insecure_skip_verify - a pin authenticates a self-signed certificate without \
             giving up verification"
        );
    }
    if authenticating && backend.tls == Some(false) {
        anyhow::bail!(
            "[backend] tls_pinned_sha256/tls_ca_file require TLS, but tls = \"no\" forces a \
             plaintext connection where neither can be checked"
        );
    }
    if authenticating && backend.server.starts_with("http://") {
        anyhow::bail!(
            "[backend] tls_pinned_sha256/tls_ca_file require TLS, but the http:// server token \
             forces a plaintext connection where neither can be checked; use https://"
        );
    }
    Ok(())
}

/// Parse a wallet's `[wallets.<name>]` backend override keys. Each key is parsed by the same
/// helper the global `[backend]` section uses, so the two cannot drift; errors name the exact
/// TOML key that is wrong.
fn resolve_wallet_backend(name: &str, w: &WalletFile) -> anyhow::Result<WalletBackendOverride> {
    Ok(WalletBackendOverride {
        server: w.server.clone(),
        tls: match w.tls.as_deref() {
            Some(mode) => Some(
                crate::backend::parse_tls_mode(mode)
                    .with_context(|| format!("[wallets.{name}] tls"))?,
            ),
            None => None,
        },
        tls_roots: match w.tls_roots.as_deref() {
            Some(roots) => Some(
                crate::backend::TlsRoots::parse(roots)
                    .with_context(|| format!("[wallets.{name}] tls_roots"))?,
            ),
            None => None,
        },
        tls_insecure_skip_verify: w.tls_insecure_skip_verify,
        // Read now, not at connect time, exactly as the global key is: an unreadable CA file
        // must fail startup rather than leave this wallet silently on the public roots.
        tls_ca_pem: match w.tls_ca_file.as_deref() {
            Some(path) => Some(std::fs::read(path).with_context(|| {
                format!("reading [wallets.{name}] tls_ca_file {}", path.display())
            })?),
            None => None,
        },
        tls_ca_file: w.tls_ca_file.clone(),
        tls_pins: match &w.tls_pinned_sha256 {
            Some(pins) => Some(
                pins.iter()
                    .map(|s| crate::backend::CertFingerprint::parse(s))
                    .collect::<anyhow::Result<Vec<_>>>()
                    .with_context(|| format!("[wallets.{name}] tls_pinned_sha256"))?,
            ),
            None => None,
        },
        assume_transparent_in_compact_blocks: w.assume_transparent_in_compact_blocks,
    })
}

#[cfg(feature = "zcash")]
fn resolve_global_pools(file: Option<&PoolsFile>) -> anyhow::Result<PoolsConfig> {
    let enabled = match file.and_then(|f| f.enabled.as_deref()) {
        Some(tokens) => ReceiverSet::parse(tokens).context("[pools] enabled")?,
        None => ReceiverSet::single(Receiver::Orchard),
    };
    let default_receivers = match file.and_then(|f| f.default_receivers.as_deref()) {
        Some(tokens) => ReceiverSet::parse(tokens).context("[pools] default_receivers")?,
        None => enabled.clone(),
    };
    if !default_receivers.is_subset_of(&enabled) {
        anyhow::bail!(
            "[pools] default_receivers ({}) must be a subset of enabled pools ({})",
            default_receivers.display_names(),
            enabled.display_names()
        );
    }
    let transparent_enabled = file.and_then(|f| f.transparent).unwrap_or(false);
    let transparent_default = file.and_then(|f| f.transparent_default).unwrap_or(false);
    let transparent_gap_limit = file
        .and_then(|f| f.transparent_gap_limit)
        .unwrap_or(DEFAULT_TRANSPARENT_GAP_LIMIT);
    let transparent_initial_scan = file.and_then(|f| f.transparent_initial_scan).unwrap_or(0);
    let transparent_allow_beyond_recovery_window = file
        .and_then(|f| f.transparent_allow_beyond_recovery_window)
        .unwrap_or(DEFAULT_TRANSPARENT_ALLOW_BEYOND);
    let transparent_gap_warn_threshold = file
        .and_then(|f| f.transparent_gap_warn_threshold)
        .unwrap_or(DEFAULT_TRANSPARENT_GAP_WARN_THRESHOLD);
    validate_transparent_flags(
        "[pools]",
        transparent_enabled,
        transparent_default,
        transparent_gap_limit,
    )?;
    Ok(PoolsConfig {
        enabled,
        default_receivers,
        transparent_enabled,
        transparent_default,
        transparent_gap_limit,
        transparent_initial_scan,
        transparent_allow_beyond_recovery_window,
        transparent_gap_warn_threshold,
    })
}

/// `transparent_default` makes a bare t-address the no-argument `getnewaddress` default, so it
/// only makes sense when transparent receiving is enabled at all. The gap limit must be at least 1
/// (0 would scan no addresses and recover nothing on restore). There is deliberately no upper
/// bound here: a very wide window is an operator's (costly) choice, warned about loudly at actor
/// spawn ([`TRANSPARENT_GAP_LIMIT_COSTLY`] / [`TRANSPARENT_GAP_LIMIT_SEVERE`]) rather than
/// rejected.
#[cfg(feature = "zcash")]
fn validate_transparent_flags(
    ctx: &str,
    transparent_enabled: bool,
    transparent_default: bool,
    transparent_gap_limit: u32,
) -> anyhow::Result<()> {
    if transparent_default && !transparent_enabled {
        anyhow::bail!(
            "{ctx} transparent_default = true requires transparent = true \
             (transparent receiving must be enabled to default to it)"
        );
    }
    if transparent_gap_limit == 0 {
        anyhow::bail!("{ctx} transparent_gap_limit must be at least 1");
    }
    Ok(())
}

/// Resolve and validate one wallet's pools/receivers against the global defaults. A wallet that
/// overrides `pools` but not `default_receivers` receives into all of its enabled pools by
/// default; a wallet that overrides neither inherits the global defaults.
#[cfg(feature = "zcash")]
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn resolve_wallet_pools(
    name: &str,
    pools: Option<&[String]>,
    default_receivers: Option<&[String]>,
    transparent: Option<bool>,
    transparent_default: Option<bool>,
    transparent_gap_limit: Option<u32>,
    transparent_initial_scan: Option<u32>,
    transparent_allow_beyond_recovery_window: Option<bool>,
    transparent_gap_warn_threshold: Option<u32>,
    global: &PoolsConfig,
) -> anyhow::Result<(ReceiverSet, ReceiverSet, bool, bool, u32, u32, bool, u32)> {
    let enabled = match pools {
        Some(tokens) => {
            ReceiverSet::parse(tokens).with_context(|| format!("[wallets.{name}] pools"))?
        }
        None => global.enabled.clone(),
    };
    let receivers = match (default_receivers, pools) {
        (Some(tokens), _) => ReceiverSet::parse(tokens)
            .with_context(|| format!("[wallets.{name}] default_receivers"))?,
        // Wallet customized its pools but not its receivers: receive into everything it enabled.
        (None, Some(_)) => enabled.clone(),
        // Wallet customized neither: inherit the global default receivers.
        (None, None) => global.default_receivers.clone(),
    };
    if !receivers.is_subset_of(&enabled) {
        anyhow::bail!(
            "[wallets.{name}] default_receivers ({}) must be a subset of enabled pools ({})",
            receivers.display_names(),
            enabled.display_names()
        );
    }
    // Per-wallet transparent flags fall back to the global values when not overridden.
    let transparent_enabled = transparent.unwrap_or(global.transparent_enabled);
    let transparent_default = transparent_default.unwrap_or(global.transparent_default);
    let transparent_gap_limit = transparent_gap_limit.unwrap_or(global.transparent_gap_limit);
    let transparent_initial_scan =
        transparent_initial_scan.unwrap_or(global.transparent_initial_scan);
    let transparent_allow_beyond_recovery_window = transparent_allow_beyond_recovery_window
        .unwrap_or(global.transparent_allow_beyond_recovery_window);
    let transparent_gap_warn_threshold =
        transparent_gap_warn_threshold.unwrap_or(global.transparent_gap_warn_threshold);
    validate_transparent_flags(
        &format!("[wallets.{name}]"),
        transparent_enabled,
        transparent_default,
        transparent_gap_limit,
    )?;
    Ok((
        enabled,
        receivers,
        transparent_enabled,
        transparent_default,
        transparent_gap_limit,
        transparent_initial_scan,
        transparent_allow_beyond_recovery_window,
        transparent_gap_warn_threshold,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "zcash")]
    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[cfg(feature = "zcash")]
    #[test]
    fn global_pools_default_to_orchard_only() {
        let p = resolve_global_pools(None).unwrap();
        assert_eq!(p, PoolsConfig::default());
        assert!(p.enabled.contains(Receiver::Orchard));
        assert!(!p.enabled.contains(Receiver::Sapling));
        assert_eq!(p.default_receivers, p.enabled);
    }

    #[cfg(feature = "zcash")]
    #[test]
    fn global_default_receivers_default_to_enabled() {
        let f = PoolsFile {
            enabled: Some(s(&["sapling", "orchard"])),
            default_receivers: None,
            ..Default::default()
        };
        let p = resolve_global_pools(Some(&f)).unwrap();
        assert!(p.enabled.contains(Receiver::Sapling) && p.enabled.contains(Receiver::Orchard));
        // Receivers fall back to the full enabled set.
        assert_eq!(p.default_receivers, p.enabled);
    }

    #[cfg(feature = "zcash")]
    #[test]
    fn global_receivers_must_be_subset_of_enabled() {
        let f = PoolsFile {
            enabled: Some(s(&["orchard"])),
            default_receivers: Some(s(&["sapling"])),
            ..Default::default()
        };
        let err = resolve_global_pools(Some(&f)).unwrap_err().to_string();
        assert!(err.contains("subset"), "{err}");
        assert!(err.contains("sapling"), "{err}");
    }

    #[cfg(feature = "zcash")]
    #[test]
    fn global_unknown_pool_is_rejected() {
        let f = PoolsFile {
            enabled: Some(s(&["ironwood"])),
            default_receivers: None,
            ..Default::default()
        };
        let err = format!("{:#}", resolve_global_pools(Some(&f)).unwrap_err());
        assert!(
            err.contains("ironwood") || err.contains("unknown pool"),
            "{err}"
        );
    }

    #[cfg(feature = "zcash")]
    #[test]
    fn global_empty_enabled_is_rejected() {
        let f = PoolsFile {
            enabled: Some(vec![]),
            default_receivers: None,
            ..Default::default()
        };
        assert!(resolve_global_pools(Some(&f)).is_err());
    }

    #[cfg(feature = "zcash")]
    #[test]
    fn wallet_inherits_global_when_unset() {
        let global = PoolsConfig {
            enabled: ReceiverSet::parse(&s(&["sapling", "orchard"])).unwrap(),
            default_receivers: ReceiverSet::single(Receiver::Orchard),
            transparent_enabled: false,
            transparent_default: false,
            transparent_gap_limit: DEFAULT_TRANSPARENT_GAP_LIMIT,
            transparent_initial_scan: 0,
            transparent_allow_beyond_recovery_window: DEFAULT_TRANSPARENT_ALLOW_BEYOND,
            transparent_gap_warn_threshold: DEFAULT_TRANSPARENT_GAP_WARN_THRESHOLD,
        };
        let (enabled, receivers, _, _, _, _, _, _) =
            resolve_wallet_pools("w", None, None, None, None, None, None, None, None, &global)
                .unwrap();
        assert_eq!(enabled, global.enabled);
        assert_eq!(receivers, global.default_receivers);
    }

    #[cfg(feature = "zcash")]
    #[test]
    fn wallet_overriding_pools_defaults_receivers_to_its_enabled() {
        // A wallet that narrows its pools but doesn't set receivers must not inherit the global
        // receivers (which could name a now-disabled pool) - it receives into all it enabled.
        let global = PoolsConfig::default(); // orchard-only
        let (enabled, receivers, _, _, _, _, _, _) = resolve_wallet_pools(
            "w",
            Some(&s(&["sapling"])),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            &global,
        )
        .unwrap();
        assert!(enabled.contains(Receiver::Sapling) && !enabled.contains(Receiver::Orchard));
        assert_eq!(receivers, enabled);
    }

    #[cfg(feature = "zcash")]
    #[test]
    fn wallet_receivers_not_subset_of_enabled_is_rejected() {
        let global = PoolsConfig::default();
        let err = resolve_wallet_pools(
            "hot",
            Some(&s(&["orchard"])),
            Some(&s(&["sapling"])),
            None,
            None,
            None,
            None,
            None,
            None,
            &global,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("wallets.hot"), "{err}");
        assert!(err.contains("subset"), "{err}");
    }

    #[cfg(feature = "zcash")]
    #[test]
    fn transparent_flags_and_gap_limit() {
        // Default: transparent off, gap limit at the rose default.
        let p = resolve_global_pools(None).unwrap();
        assert!(!p.transparent_enabled);
        assert!(!p.transparent_default);
        assert_eq!(p.transparent_gap_limit, DEFAULT_TRANSPARENT_GAP_LIMIT);

        // Explicit enable + custom gap limit are honored.
        let f = PoolsFile {
            transparent: Some(true),
            transparent_gap_limit: Some(50),
            ..Default::default()
        };
        let p = resolve_global_pools(Some(&f)).unwrap();
        assert!(p.transparent_enabled);
        assert_eq!(p.transparent_gap_limit, 50);
        assert_eq!(p.transparent_initial_scan, 0, "initial scan defaults off");

        // Initial scan depth is independent of the gap limit.
        let f = PoolsFile {
            transparent: Some(true),
            transparent_gap_limit: Some(20),
            transparent_initial_scan: Some(10_000),
            ..Default::default()
        };
        let p = resolve_global_pools(Some(&f)).unwrap();
        assert_eq!(p.transparent_gap_limit, 20);
        assert_eq!(p.transparent_initial_scan, 10_000);

        // A zero gap limit is rejected (would recover nothing on restore).
        let f = PoolsFile {
            transparent: Some(true),
            transparent_gap_limit: Some(0),
            ..Default::default()
        };
        assert!(resolve_global_pools(Some(&f)).is_err());

        // A pathologically wide gap limit is rejected with guidance toward the A18 knob:
        // recording each transparent receive re-derives the whole window, so a huge window
        // stalls restores (the 0.5.1-rc2 field report ran transparent_gap_limit = 71000), but
        // the width is the operator's choice: it parses fine and is warned about at actor spawn
        // (error-level above TRANSPARENT_GAP_LIMIT_SEVERE), never rejected.
        let f = PoolsFile {
            transparent: Some(true),
            transparent_gap_limit: Some(71_000),
            ..Default::default()
        };
        assert_eq!(
            resolve_global_pools(Some(&f))
                .unwrap()
                .transparent_gap_limit,
            71_000
        );

        // transparent_default without transparent is rejected.
        let f = PoolsFile {
            transparent_default: Some(true),
            ..Default::default()
        };
        let err = resolve_global_pools(Some(&f)).unwrap_err().to_string();
        assert!(err.contains("transparent"), "{err}");

        // Recovery-window knobs default to permissive + the standard warn threshold.
        let p = resolve_global_pools(None).unwrap();
        assert!(p.transparent_allow_beyond_recovery_window);
        assert_eq!(
            p.transparent_gap_warn_threshold,
            DEFAULT_TRANSPARENT_GAP_WARN_THRESHOLD
        );
        // ...and parse from `[pools]`.
        let f = PoolsFile {
            transparent: Some(true),
            transparent_allow_beyond_recovery_window: Some(false),
            transparent_gap_warn_threshold: Some(3),
            ..Default::default()
        };
        let p = resolve_global_pools(Some(&f)).unwrap();
        assert!(!p.transparent_allow_beyond_recovery_window);
        assert_eq!(p.transparent_gap_warn_threshold, 3);

        // Per-wallet override of the flags + gap limit + initial scan depth + recovery-window knobs.
        let global = PoolsConfig::default();
        let (_, _, te, td, gap, init, allow_beyond, warn_thresh) = resolve_wallet_pools(
            "w",
            None,
            None,
            Some(true),
            None,
            Some(7),
            Some(500),
            Some(false),
            Some(2),
            &global,
        )
        .unwrap();
        assert!(te && !td);
        assert_eq!(gap, 7);
        assert_eq!(init, 500, "per-wallet transparent_initial_scan override");
        assert!(
            !allow_beyond,
            "per-wallet transparent_allow_beyond_recovery_window override"
        );
        assert_eq!(
            warn_thresh, 2,
            "per-wallet transparent_gap_warn_threshold override"
        );

        // Per-wallet knobs inherit the global values when unset.
        let global = PoolsConfig {
            transparent_allow_beyond_recovery_window: false,
            transparent_gap_warn_threshold: 9,
            ..PoolsConfig::default()
        };
        let (_, _, _, _, _, _, allow_beyond, warn_thresh) =
            resolve_wallet_pools("w", None, None, None, None, None, None, None, None, &global)
                .unwrap();
        assert!(!allow_beyond, "inherits global allow_beyond");
        assert_eq!(warn_thresh, 9, "inherits global warn threshold");

        // A very wide per-wallet gap-limit override is likewise accepted (warned about at spawn,
        // not rejected); only 0 is invalid.
        let global = PoolsConfig::default();
        let (_, _, _, _, gap, _, _, _) = resolve_wallet_pools(
            "w",
            None,
            None,
            Some(true),
            None,
            Some(TRANSPARENT_GAP_LIMIT_SEVERE + 1),
            None,
            None,
            None,
            &global,
        )
        .unwrap();
        assert_eq!(gap, TRANSPARENT_GAP_LIMIT_SEVERE + 1);
        let err = resolve_wallet_pools(
            "w",
            None,
            None,
            Some(true),
            None,
            Some(0),
            None,
            None,
            None,
            &global,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("at least 1"), "{err}");
    }

    #[cfg(feature = "zcash")]
    #[test]
    fn spend_section_builds_policy_and_validates() {
        // Parses from TOML; explicit values land in the policy.
        let f: SpendFile =
            toml::from_str("trusted_confirmations = 1\nuntrusted_confirmations = 2").unwrap();
        let s = SpendConfig {
            trusted_confirmations: f.trusted_confirmations.unwrap_or(3),
            untrusted_confirmations: f.untrusted_confirmations.unwrap_or(10),
            ..Default::default()
        };
        let p = s.confirmations_policy().unwrap();
        assert_eq!((p.trusted().get(), p.untrusted().get()), (1, 2));
        // The defaults are ZIP 315's 3/10.
        let p = SpendConfig {
            trusted_confirmations: 3,
            untrusted_confirmations: 10,
            ..Default::default()
        }
        .confirmations_policy()
        .unwrap();
        assert_eq!((p.trusted().get(), p.untrusted().get()), (3, 10));
        // 0 clamps to 1 (a shielded note is never spendable unmined).
        let p = SpendConfig {
            trusted_confirmations: 0,
            untrusted_confirmations: 1,
            ..Default::default()
        }
        .confirmations_policy()
        .unwrap();
        assert_eq!((p.trusted().get(), p.untrusted().get()), (1, 1));
        // trusted > untrusted is rejected (surfaces as a startup error).
        assert!(SpendConfig {
            trusted_confirmations: 11,
            untrusted_confirmations: 10,
            ..Default::default()
        }
        .confirmations_policy()
        .is_err());
        // Unknown keys in the section are rejected like everywhere else.
        assert!(toml::from_str::<SpendFile>("min_conf = 1").is_err());
    }

    /// The floor is the reason this is configurable at all: a deployment built on small
    /// balances needs a lower one, and the default is sized for mainnet-scale value. Both keys
    /// must also be *rejected* when unusable rather than reaching the send path, where they are
    /// unwrapped - a `target_note_count = 0` used to be a panic waiting for the first send.
    #[cfg(feature = "zcash")]
    #[test]
    fn change_splitting_defaults_parses_and_rejects_unusable_values() {
        assert_eq!(SpendConfig::default().target_note_count, 4);
        assert_eq!(SpendConfig::default().min_split_output_value, 10_000_000);
        SpendConfig::default()
            .validate_change_splitting()
            .expect("the defaults are usable");

        let f: SpendFile =
            toml::from_str("target_note_count = 8\nmin_split_output_value = 50000").unwrap();
        assert_eq!(f.target_note_count, Some(8));
        assert_eq!(f.min_split_output_value, Some(50_000));

        let zero_target = SpendConfig {
            target_note_count: 0,
            ..SpendConfig::default()
        };
        assert!(
            zero_target.validate_change_splitting().is_err(),
            "a zero note target would panic the send path"
        );

        let absurd_floor = SpendConfig {
            min_split_output_value: u64::MAX,
            ..SpendConfig::default()
        };
        assert!(
            absurd_floor.validate_change_splitting().is_err(),
            "a floor above MAX_MONEY is not a valid amount"
        );

        // A floor of zero is legal: it means "split without a minimum".
        let no_floor = SpendConfig {
            min_split_output_value: 0,
            ..SpendConfig::default()
        };
        assert!(no_floor.validate_change_splitting().is_ok());
    }

    /// A reload applies the reloadable key and reports everything else as needing a restart,
    /// rather than silently dropping it - an operator who edits a key that cannot be reloaded
    /// has to be told, not left to infer it from behaviour that did not change.
    #[cfg(feature = "zcash")]
    #[test]
    fn reload_applies_the_live_key_and_names_the_rest() {
        let running = AppConfig::resolve_overrides(&ConfigOverrides {
            regtest: true,
            ..Default::default()
        })
        .expect("resolve running config");
        let limits = SpendLimits::new(&running.spend);

        // Nothing changed: nothing applied, nothing to report.
        let report = apply_reload(&running, &running, &limits);
        assert!(
            report.is_empty(),
            "an identical config is a no-op: {report:?}"
        );
        assert_eq!(
            limits.orchard_action_limit(),
            running.spend.orchard_action_limit
        );

        // The live key.
        let mut fresh = AppConfig::resolve_overrides(&ConfigOverrides {
            regtest: true,
            ..Default::default()
        })
        .expect("resolve fresh config");
        fresh.spend.orchard_action_limit = 0;
        let report = apply_reload(&running, &fresh, &limits);
        assert_eq!(
            report.applied,
            vec![(
                "spend.orchard_action_limit",
                DEFAULT_ORCHARD_ACTION_LIMIT.to_string(),
                "0".to_string()
            )]
        );
        assert!(report.requires_restart.is_empty(), "{report:?}");
        assert_eq!(
            limits.orchard_action_limit(),
            0,
            "the cell took the new value"
        );

        // Applying the same value twice reports nothing the second time: the comparison is
        // against the cell, not against the config the daemon started with.
        let report = apply_reload(&running, &fresh, &limits);
        assert!(
            report.is_empty(),
            "a repeated reload is a no-op: {report:?}"
        );

        // A key that cannot be reloaded is named, and does not take effect.
        let mut fresh = fresh.clone();
        fresh.rpc.work_queue = running.rpc.work_queue + 7;
        let report = apply_reload(&running, &fresh, &limits);
        assert!(
            report
                .requires_restart
                .iter()
                .any(|k| k == "rpc.work_queue"),
            "the changed key must be named: {report:?}"
        );

        // Including another key in the same section as the reloadable one, which a
        // section-level comparison would have hidden behind it.
        let mut fresh = fresh.clone();
        fresh.spend.target_note_count = running.spend.target_note_count + 1;
        let report = apply_reload(&running, &fresh, &limits);
        assert!(
            report
                .requires_restart
                .iter()
                .any(|k| k == "spend.target_note_count"),
            "a non-reloadable key in the reloadable key's own section must still be named: \
             {report:?}"
        );
    }

    /// `[spend] max_send_catchup_blocks` defaults to Zallet's lock threshold, parses, and
    /// accepts the unbounding `0`.
    #[cfg(feature = "zcash")]
    #[test]
    fn max_send_catchup_blocks_parses_and_defaults() {
        assert_eq!(
            SpendConfig::default().max_send_catchup_blocks,
            DEFAULT_MAX_SEND_CATCHUP_BLOCKS
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rose.toml");
        for (value, expected) in [("0", 0), ("2500", 2500)] {
            std::fs::write(
                &path,
                format!("[spend]\nmax_send_catchup_blocks = {value}\n"),
            )
            .expect("write config");
            let config = AppConfig::resolve_overrides(&ConfigOverrides {
                regtest: true,
                conf: Some(path.clone()),
                ..Default::default()
            })
            .expect("resolve");
            assert_eq!(config.spend.max_send_catchup_blocks, expected);
        }
    }

    /// A datadir whose only config is the pre-rename `zecd.toml` is refused with the rename
    /// spelled out, instead of being started on defaults. Only the implied location counts:
    /// `--conf` names a file, and a renamed file (or both present) resolves as usual.
    #[test]
    fn a_legacy_config_file_is_refused_until_renamed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let legacy = dir.path().join(LEGACY_CONF_FILE);
        std::fs::write(&legacy, "network = \"regtest\"\n").expect("write legacy config");
        let overrides = ConfigOverrides {
            datadir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };

        let err = AppConfig::resolve_overrides(&overrides).expect_err("legacy file refused");
        let msg = err.to_string();
        assert!(
            msg.contains("zecd.toml") && msg.contains("rose.toml"),
            "{msg}"
        );

        let explicit = AppConfig::resolve_overrides(&ConfigOverrides {
            conf: Some(legacy.clone()),
            ..overrides.clone()
        })
        .expect("--conf names the file explicitly");
        assert!(explicit.network.is_regtest());

        std::fs::rename(&legacy, dir.path().join(ROSE_DEFAULTS.conf_file)).expect("rename");
        let renamed = AppConfig::resolve_overrides(&overrides).expect("renamed file resolves");
        assert!(renamed.network.is_regtest());
    }

    /// `[spend] shutdown_drain_secs` bounds how long a stopping wallet finishes sends it already
    /// accepted. It is configuration rather than a constant because the value that binds is the
    /// supervisor's own grace period, not any property of rose - so the parse, the default, and
    /// the disabling `0` all have to hold.
    #[cfg(feature = "zcash")]
    #[test]
    fn shutdown_drain_parses_and_defaults_to_the_documented_value() {
        let dir = tempfile::tempdir().expect("tempdir");

        let default = AppConfig::resolve_overrides(&ConfigOverrides {
            regtest: true,
            ..Default::default()
        })
        .expect("resolve with no file");
        assert_eq!(
            default.spend.shutdown_drain_secs, DEFAULT_SHUTDOWN_DRAIN_SECS,
            "the default is the documented 60s"
        );

        let path = dir.path().join("rose.toml");
        std::fs::write(&path, "[spend]\nshutdown_drain_secs = 0\n").expect("write config");
        let disabled = AppConfig::resolve_overrides(&ConfigOverrides {
            regtest: true,
            conf: Some(path.clone()),
            ..Default::default()
        })
        .expect("resolve with the drain disabled");
        assert_eq!(
            disabled.spend.shutdown_drain_secs, 0,
            "0 is a legal value - it restores the drop-on-shutdown behaviour"
        );

        std::fs::write(&path, "[spend]\nshutdown_drain_secs = 25\n").expect("write config");
        let short = AppConfig::resolve_overrides(&ConfigOverrides {
            regtest: true,
            conf: Some(path),
            ..Default::default()
        })
        .expect("resolve with a shortened drain");
        assert_eq!(short.spend.shutdown_drain_secs, 25);

        // It is not reloadable: the drain is read once, when the actor is already stopping.
        let limits = SpendLimits::new(&default.spend);
        let report = apply_reload(&default, &short, &limits);
        assert!(
            report
                .requires_restart
                .iter()
                .any(|k| k == "spend.shutdown_drain_secs"),
            "a changed drain must be named as needing a restart: {report:?}"
        );
    }

    /// Every key on the reloadable list must be one `apply_reload` actually applies, or the
    /// list is a promise the code does not keep.
    #[cfg(feature = "zcash")]
    #[test]
    fn reloadable_keys_are_all_applied() {
        let running = AppConfig::resolve_overrides(&ConfigOverrides {
            regtest: true,
            ..Default::default()
        })
        .expect("resolve");
        let limits = SpendLimits::new(&running.spend);
        let mut fresh = running.clone();
        // Move every reloadable key, so the report names all of them and the assertion below
        // fails if the list grows without `apply_reload` growing with it.
        fresh.spend.orchard_action_limit = running.spend.orchard_action_limit + 1;
        fresh.spend.max_tx_bytes = running.spend.max_tx_bytes + 1;
        let report = apply_reload(&running, &fresh, &limits);
        let applied: Vec<&str> = report.applied.iter().map(|(k, _, _)| *k).collect();
        assert_eq!(applied, RELOADABLE_KEYS, "the list and the code must agree");
    }

    #[cfg(feature = "zcash")]
    #[test]
    fn orchard_action_limit_defaults_and_parses() {
        // Absent -> the Zallet-matching default of 50.
        assert_eq!(SpendConfig::default().orchard_action_limit, 50);
        assert_eq!(DEFAULT_ORCHARD_ACTION_LIMIT, 50);
        // Explicit value (including 0, which disables the cap) round-trips.
        let f: SpendFile = toml::from_str("orchard_action_limit = 200").unwrap();
        assert_eq!(f.orchard_action_limit, Some(200));
        let f: SpendFile = toml::from_str("orchard_action_limit = 0").unwrap();
        assert_eq!(f.orchard_action_limit, Some(0));
    }

    #[cfg(feature = "zcash")]
    #[test]
    fn pipeline_proving_defaults_off_and_parses() {
        // Absent -> off (the inline send path, byte-identical to today's behaviour).
        assert!(!SpendConfig::default().pipeline_proving);
        // Explicit value round-trips both ways.
        let f: SpendFile = toml::from_str("pipeline_proving = true").unwrap();
        assert_eq!(f.pipeline_proving, Some(true));
        let f: SpendFile = toml::from_str("pipeline_proving = false").unwrap();
        assert_eq!(f.pipeline_proving, Some(false));
    }

    #[cfg(feature = "zcash")]
    #[test]
    fn trust_own_transactions_defaults_on_and_parses() {
        // Absent -> on: wallet-authored transactions are marked trusted at store time.
        assert!(SpendConfig::default().trust_own_transactions);
        // The full-statelessness opt-out round-trips: with it off, rose persists no trust
        // marker, so an authoring instance and a from-seed restore classify identically.
        let f: SpendFile = toml::from_str("trust_own_transactions = false").unwrap();
        assert_eq!(f.trust_own_transactions, Some(false));
        let f: SpendFile = toml::from_str("trust_own_transactions = true").unwrap();
        assert_eq!(f.trust_own_transactions, Some(true));
    }

    #[cfg(feature = "zcash")]
    #[test]
    fn fleet_defaults_off_and_parses() {
        // Absent -> off. The fleet is experimental and opt-in: a daemon that never mentions
        // [fleet] must not read the manifest directory or accept a runtime `createwallet`,
        // and a stray file in the datadir must not enrol it.
        assert!(!FleetConfig::default().enabled);
        // An omitted [fleet] table resolves to the same thing as an empty one.
        let f: FleetFile = toml::from_str("").unwrap();
        assert_eq!(f.enabled, None);
        let f: FleetFile = toml::from_str("enabled = true").unwrap();
        assert_eq!(f.enabled, Some(true));
        let f: FleetFile = toml::from_str("enabled = false").unwrap();
        assert_eq!(f.enabled, Some(false));
        // The other keys are inert but still parse, so a config can be written before the
        // feature is switched on.
        let f: FleetFile = toml::from_str("shard_size = 64\ncohort_depth = 500").unwrap();
        assert_eq!(f.enabled, None);
        assert_eq!(f.shard_size, Some(64));
        assert_eq!(f.cohort_depth, Some(500));
    }

    #[cfg(feature = "zcash")]
    #[test]
    fn privacy_policy_parses_known_values_only() {
        assert_eq!(
            SendPrivacy::parse("FullPrivacy").unwrap(),
            SendPrivacy::FullPrivacy
        );
        assert_eq!(
            SendPrivacy::parse("AllowRevealedAmounts").unwrap(),
            SendPrivacy::AllowRevealedAmounts
        );
        assert_eq!(
            SendPrivacy::parse("AllowRevealedRecipients").unwrap(),
            SendPrivacy::AllowRevealedRecipients
        );
        assert_eq!(
            SendPrivacy::parse("AllowRevealedSenders").unwrap(),
            SendPrivacy::AllowRevealedSenders
        );
        assert_eq!(
            SendPrivacy::parse("AllowFullyTransparent").unwrap(),
            SendPrivacy::AllowFullyTransparent
        );
        // Unknown values, and the `z_sendmany`-only `NoPrivacy` alias (which maps to
        // AllowFullyTransparent at the RPC layer but is not a canonical config token), are a
        // startup error, never a silent default.
        assert!(SendPrivacy::parse("NoPrivacy").is_err());
        assert!(SendPrivacy::parse("AllowLinkingAccountAddresses").is_err());
        assert!(SendPrivacy::parse("fullprivacy").is_err());
    }

    #[cfg(feature = "zcash")]
    #[test]
    fn allows_transparent_recipient_ladder() {
        // The three upper rungs permit a transparent recipient; the two private rungs reject it.
        // Regression guard: `AllowFullyTransparent` (top rung) must be included, or `build_payment`
        // rejects the very t->t sends the policy exists to allow.
        assert!(!SendPrivacy::FullPrivacy.allows_transparent_recipient());
        assert!(!SendPrivacy::AllowRevealedAmounts.allows_transparent_recipient());
        assert!(SendPrivacy::AllowRevealedRecipients.allows_transparent_recipient());
        assert!(SendPrivacy::AllowRevealedSenders.allows_transparent_recipient());
        assert!(SendPrivacy::AllowFullyTransparent.allows_transparent_recipient());
    }

    #[cfg(feature = "zcash")]
    #[test]
    fn allows_transparent_inputs_ladder() {
        // Only the two top rungs permit funding a send from transparent UTXOs (revealing the
        // sender). The default (`AllowRevealedRecipients`) must stay false: spending transparent
        // inputs is strictly opt-in via config or a per-call `privacyPolicy`.
        assert!(!SendPrivacy::FullPrivacy.allows_transparent_inputs());
        assert!(!SendPrivacy::AllowRevealedAmounts.allows_transparent_inputs());
        assert!(!SendPrivacy::AllowRevealedRecipients.allows_transparent_inputs());
        assert!(SendPrivacy::AllowRevealedSenders.allows_transparent_inputs());
        assert!(SendPrivacy::AllowFullyTransparent.allows_transparent_inputs());
    }

    #[test]
    fn server_token_precedence() {
        // CLI wins over the file `server`.
        assert_eq!(
            select_server_token(Some("cli:1".into()), Some("str:1".into())),
            "cli:1".to_string()
        );
        // The file `server` is used when there's no CLI flag.
        assert_eq!(
            select_server_token(None, Some("str:1".into())),
            "str:1".to_string()
        );
        // Nothing configured -> built-in default (a local zebrad).
        assert_eq!(select_server_token(None, None), DEFAULT_SERVER.to_string());
    }

    #[test]
    fn backend_file_parses_server_and_backoff() {
        let f: BackendFile = toml::from_str(
            r#"
            server = "zebra://127.0.0.1:18234"
            connect_timeout_secs = 5
            reconnect_base_secs = 2
            reconnect_max_secs = 30
            "#,
        )
        .unwrap();
        assert_eq!(f.server.as_deref(), Some("zebra://127.0.0.1:18234"));
        assert_eq!(f.connect_timeout_secs, Some(5));
        assert_eq!(f.reconnect_base_secs, Some(2));
        assert_eq!(f.reconnect_max_secs, Some(30));
        assert_eq!(f.p2p_receive_window_bytes, None);
        let f: BackendFile = toml::from_str("p2p_receive_window_bytes = 1448").unwrap();
        assert_eq!(f.p2p_receive_window_bytes, Some(1448));
        // The cleartext-gate knobs default to unset (-> rfc1918_is_local true, remote override
        // false) and parse when present.
        assert_eq!(f.rfc1918_is_local, None);
        assert_eq!(f.allow_remote_cleartext, None);
        let f: BackendFile =
            toml::from_str("rfc1918_is_local = false\nallow_remote_cleartext = true").unwrap();
        assert_eq!(f.rfc1918_is_local, Some(false));
        assert_eq!(f.allow_remote_cleartext, Some(true));
    }

    #[test]
    fn backend_file_parses_the_proxy_key() {
        let f: BackendFile = toml::from_str("server = \"zecrocks\"").unwrap();
        assert_eq!(f.proxy, None);
        let f: BackendFile = toml::from_str("proxy = \"socks5://127.0.0.1:9050\"").unwrap();
        assert_eq!(f.proxy.as_deref(), Some("socks5://127.0.0.1:9050"));
    }

    /// What a subcommand acts on when `--wallet` is omitted, and where un-prefixed RPCs
    /// route: an explicit `default_wallet`; else the one declared wallet; else - several
    /// declared, none named - the literal `default` for routing while the flag becomes
    /// required, since nothing singles a wallet out. The middle case is what stops a
    /// Bitcoin-only config from growing a phantom Zcash wallet.
    #[test]
    fn the_implied_wallet_follows_default_wallet_then_the_sole_declared_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        let resolve = |body: &str| {
            std::fs::write(
                &conf,
                format!(
                    "network = \"test\"\ndatadir = {:?}\n{body}[rpc]\nuser = \"u\"\npassword = \"p\"\n",
                    dir.path()
                ),
            )
            .unwrap();
            AppConfig::resolve_overrides(&ConfigOverrides {
                conf: Some(conf.clone()),
                ..Default::default()
            })
            .expect("resolves")
        };
        // Nothing declared: the implicit wallet, by its literal name.
        let c = resolve("");
        assert_eq!(c.default_wallet, "default");
        assert_eq!(c.wallet_or_default(None).unwrap(), "default");
        // One declared wallet is the implied one, for routing and for the flag - and no
        // phantom "default" is filled in beside it.
        let c = resolve("[wallets.w1]\n");
        assert_eq!(c.default_wallet, "w1");
        assert_eq!(c.wallet_or_default(None).unwrap(), "w1");
        assert_eq!(c.wallets.keys().collect::<Vec<_>>(), ["w1"]);
        // Several, none named: routing keeps the literal, the flag is required and the
        // error lists the candidates; an explicit flag is honored as given.
        let c = resolve("[wallets.w1]\n[wallets.w2]\n");
        assert_eq!(c.default_wallet, "default");
        let err = c.wallet_or_default(None).unwrap_err().to_string();
        assert!(
            err.contains("--wallet is required") && err.contains("w1") && err.contains("w2"),
            "{err}"
        );
        assert_eq!(c.wallet_or_default(Some("w2")).unwrap(), "w2");
        // An explicit default_wallet settles both, however many are declared.
        let c = resolve("default_wallet = \"w2\"\n[wallets.w1]\n[wallets.w2]\n");
        assert_eq!(c.default_wallet, "w2");
        assert_eq!(c.wallet_or_default(None).unwrap(), "w2");
    }

    /// The library entry point carries the proxy the same way the binary's flag does, and it
    /// reaches the `Server` a `NodeBuilder` would dial - so an embedded node is proxied on the
    /// same terms as the daemon.
    #[cfg(feature = "zcash")]
    #[test]
    fn a_library_consumers_override_reaches_the_resolved_server() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        std::fs::write(
            &conf,
            format!(
                "network = \"test\"\ndatadir = {:?}\n[rpc]\nuser = \"u\"\npassword = \"p\"\n",
                dir.path()
            ),
        )
        .unwrap();

        let config = AppConfig::resolve_overrides(&ConfigOverrides {
            conf: Some(conf),
            proxy: Some("socks5://127.0.0.1:9050".into()),
            ..Default::default()
        })
        .expect("resolve with a proxy override");
        assert_eq!(
            config.backend.proxy,
            Some(crate::socks::SocksProxy::parse("socks5://127.0.0.1:9050").unwrap())
        );
        // `resolve_configured` is what the daemon dials through; `resolve_for_wallet` is what
        // `node.rs` calls per wallet. Both must carry it.
        assert!(crate::backend::resolve_configured(&config)
            .unwrap()
            .describe()
            .contains("via socks5://127.0.0.1:9050"));
        for entry in config.wallets.values() {
            assert!(crate::backend::resolve_for_wallet(&config, entry)
                .unwrap()
                .describe()
                .contains("via socks5://127.0.0.1:9050"));
        }
    }

    #[test]
    fn the_proxy_is_daemon_policy_and_never_per_wallet() {
        // A wallet may override its endpoint and TLS, but not how the daemon reaches the
        // network: one proxy decision for the whole process.
        let mut global = backend_cfg();
        global.proxy = Some(crate::socks::SocksProxy::parse("socks5://127.0.0.1:9050").unwrap());
        let override_with_own_server = WalletBackendOverride {
            server: Some("zecrocks".into()),
            ..Default::default()
        };
        assert_eq!(
            override_with_own_server.effective(&global).proxy,
            global.proxy,
            "a wallet override must inherit the daemon's proxy"
        );
        // And there is no per-wallet key to set one with.
        assert!(toml::from_str::<WalletFile>("proxy = \"socks5://127.0.0.1:9050\"").is_err());
    }

    #[test]
    fn backend_file_parses_transparent_capability_override() {
        // Absent by default - asserting a capability the server does not advertise has to be a
        // deliberate act, since guessing wrong loses transparent receives silently.
        let f: BackendFile = toml::from_str("server = \"zecrocks\"").unwrap();
        assert_eq!(f.assume_transparent_in_compact_blocks, None);
        let f: BackendFile = toml::from_str("assume_transparent_in_compact_blocks = true").unwrap();
        assert_eq!(f.assume_transparent_in_compact_blocks, Some(true));
    }

    #[test]
    fn backend_file_parses_tls_options() {
        // Unset is the safe default: verification stays on, with no private CA and no pins.
        let f: BackendFile = toml::from_str("tls = \"yes\"\ntls_roots = \"webpki\"").unwrap();
        assert_eq!(f.tls.as_deref(), Some("yes"));
        assert_eq!(f.tls_roots.as_deref(), Some("webpki"));
        assert_eq!(f.tls_insecure_skip_verify, None);
        assert_eq!(f.tls_ca_file, None);
        assert_eq!(f.tls_pinned_sha256, None);
        // ...and each of the three trust knobs has to be asked for explicitly.
        let f: BackendFile = toml::from_str("tls_insecure_skip_verify = true").unwrap();
        assert_eq!(f.tls_insecure_skip_verify, Some(true));
        let f: BackendFile = toml::from_str(
            "tls_ca_file = \"/etc/rose/ca.pem\"\ntls_pinned_sha256 = [\"AB:CD\", \"ef01\"]",
        )
        .unwrap();
        assert_eq!(f.tls_ca_file, Some(PathBuf::from("/etc/rose/ca.pem")));
        assert_eq!(
            f.tls_pinned_sha256,
            Some(vec!["AB:CD".to_string(), "ef01".to_string()])
        );
    }

    /// A `BackendConfig` with everything at its default, for the TLS-combination checks.
    fn backend_cfg() -> BackendConfig {
        BackendConfig {
            server: "zecrocks".into(),
            connect_timeout_secs: 10,
            reconnect_base_secs: 1,
            reconnect_max_secs: 60,
            p2p_receive_window_bytes: None,
            rfc1918_is_local: true,
            allow_remote_cleartext: false,
            tls: None,
            tls_roots: Default::default(),
            tls_insecure_skip_verify: false,
            tls_ca_pem: None,
            tls_ca_file: None,
            tls_pins: Vec::new(),
            assume_transparent_in_compact_blocks: false,
            proxy: None,
        }
    }

    #[test]
    fn tls_trust_settings_compose_and_contradictions_are_rejected() {
        let pin = crate::backend::CertFingerprint::parse(&"ab".repeat(32)).unwrap();

        // Each knob alone is fine, and so is the pin + private-CA combination (pin the leaf,
        // validate the chain) - "optional everywhere" is the point of these settings.
        for cfg in [
            backend_cfg(),
            BackendConfig {
                tls_insecure_skip_verify: true,
                ..backend_cfg()
            },
            BackendConfig {
                tls_ca_pem: Some(b"pem".to_vec()),
                ..backend_cfg()
            },
            BackendConfig {
                tls_pins: vec![pin],
                ..backend_cfg()
            },
            BackendConfig {
                tls_ca_pem: Some(b"pem".to_vec()),
                tls_pins: vec![pin],
                ..backend_cfg()
            },
        ] {
            assert!(validate_backend_tls(&cfg).is_ok());
        }

        // Skipping verification cannot be combined with settings whose whole purpose is to
        // verify - that config would look authenticated while being anything but.
        let err = validate_backend_tls(&BackendConfig {
            tls_insecure_skip_verify: true,
            tls_pins: vec![pin],
            ..backend_cfg()
        })
        .unwrap_err();
        assert!(err.to_string().contains("tls_insecure_skip_verify"));

        // Nor can they ride a connection that will not be TLS at all, whether that is forced by
        // `tls = "no"`...
        assert!(validate_backend_tls(&BackendConfig {
            tls: Some(false),
            tls_pins: vec![pin],
            ..backend_cfg()
        })
        .is_err());
        // ...or by an http:// endpoint.
        assert!(validate_backend_tls(&BackendConfig {
            server: "http://lwd.example.com:9067".into(),
            tls_ca_pem: Some(b"pem".to_vec()),
            ..backend_cfg()
        })
        .is_err());
        // A plaintext endpoint with no trust settings stays valid - that is the regtest harness.
        assert!(validate_backend_tls(&BackendConfig {
            server: "http://127.0.0.1:9067".into(),
            ..backend_cfg()
        })
        .is_ok());
    }

    #[test]
    fn backend_file_rejects_unknown_field() {
        // `deny_unknown_fields` must still reject typos/unsupported keys.
        assert!(toml::from_str::<BackendFile>("bogus_key = 1").is_err());
    }

    #[cfg(feature = "zcash")]
    #[test]
    fn zebra_section_parses_and_validates() {
        let f: ConfigFile = toml::from_str(
            "[zebra]\nrpc_user = \"u\"\nrpc_password = \"p\"\nrpc_cookie = \"/tmp/.cookie\"\n",
        )
        .unwrap();
        let z = f.zebra.unwrap();
        assert_eq!(z.rpc_user.as_deref(), Some("u"));
        assert_eq!(z.rpc_password.as_ref().map(Password::expose), Some("p"));
        assert_eq!(z.rpc_cookie, Some(PathBuf::from("/tmp/.cookie")));
        // The section maps onto the zebra backend's auth type.
        let auth = ZebraConfig {
            rpc_user: z.rpc_user,
            rpc_password: z.rpc_password,
            rpc_cookie: z.rpc_cookie,
        }
        .auth();
        assert_eq!(auth.user.as_deref(), Some("u"));
        assert!(auth.cookie.is_some());
        // Typos are rejected like every other section.
        assert!(toml::from_str::<ZebraFile>("user = \"u\"").is_err());
        // An absent section resolves to no credentials.
        assert!(ZebraConfig::default().auth().header().unwrap().is_none());
    }

    #[cfg(feature = "cli")]
    #[test]
    fn file_datadir_is_honored_and_cli_wins() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        std::fs::write(&conf, "datadir = \"/tmp/rose-from-file\"\n").unwrap();

        // A `datadir` set in the config file governs data placement...
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.datadir, PathBuf::from("/tmp/rose-from-file"));

        // ...but --datadir on the CLI still wins over the file.
        let cli = Cli::parse_from([
            "rose",
            "--conf",
            conf.to_str().unwrap(),
            "--datadir",
            "/tmp/rose-from-cli",
        ]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.datadir, PathBuf::from("/tmp/rose-from-cli"));
    }

    #[cfg(feature = "cli")]
    #[test]
    fn cleartext_gate_defaults_and_overrides_resolve() {
        use clap::Parser as _;
        // Security-critical defaults: an absent [backend] resolves to rfc1918_is_local = true
        // (private/LAN self-hosting works) and allow_remote_cleartext = false (no public leak).
        let cli = Cli::parse_from(["rose"]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert!(cfg.backend.rfc1918_is_local);
        assert!(!cfg.backend.allow_remote_cleartext);

        // Both knobs are honored from the file.
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        std::fs::write(
            &conf,
            "[backend]\nrfc1918_is_local = false\nallow_remote_cleartext = true\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert!(!cfg.backend.rfc1918_is_local);
        assert!(cfg.backend.allow_remote_cleartext);
    }

    #[cfg(feature = "cli")]
    #[test]
    fn readiness_defaults_to_synced_and_is_overridable() {
        use clap::Parser as _;
        // Absent [health] readiness resolves to Synced: `/readyz` waits for the scan so a client
        // routed by readiness never trusts an empty/stale balance mid-sync.
        let cli = Cli::parse_from(["rose"]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.health.readiness, ReadinessMode::Synced);

        // A [health] block that omits `readiness` still defaults to Synced...
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        std::fs::write(&conf, "[health]\nport = 9999\n").unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.health.readiness, ReadinessMode::Synced);

        // ...and the lenient modes are still opt-in from the file.
        std::fs::write(&conf, "[health]\nreadiness = \"connected\"\n").unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.health.readiness, ReadinessMode::Connected);

        // The middle mode: scanned to tip without waiting on the enhancement backlog.
        std::fs::write(&conf, "[health]\nreadiness = \"scanned\"\n").unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.health.readiness, ReadinessMode::Scanned);

        // An unknown mode is a config error naming the accepted values.
        std::fs::write(&conf, "[health]\nreadiness = \"caught-up\"\n").unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let err = AppConfig::resolve(&cli).unwrap_err().to_string();
        assert!(
            err.contains("scanned"),
            "error should list the modes: {err}"
        );
    }

    #[cfg(feature = "cli")]
    #[test]
    fn sync_interval_secs_is_clamped_to_at_least_one() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");

        // A misconfigured `interval_secs = 0` must not make the actor busy-poll with no idle
        // delay; it clamps up to 1s (mirroring `rebroadcast_secs`).
        std::fs::write(&conf, "[sync]\ninterval_secs = 0\nrebroadcast_secs = 0\n").unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.sync.interval_secs, 1);
        assert_eq!(cfg.sync.rebroadcast_secs, 1);

        // An explicit larger value is preserved unchanged.
        std::fs::write(&conf, "[sync]\ninterval_secs = 45\n").unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.sync.interval_secs, 45);

        // Absent section -> the 20s default.
        std::fs::write(&conf, "datadir = \"/tmp/rose-x\"\n").unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.sync.interval_secs, 20);
    }

    /// `[sync] writer_cache_mib` defaults to the measured 256 MiB, parses an override, and
    /// clamps zero to one - SQLite would take a zero cache literally.
    #[cfg(feature = "cli")]
    #[test]
    fn writer_cache_mib_defaults_parses_and_clamps() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        for (body, expected) in [
            ("[sync]\ninterval_secs = 20\n", DEFAULT_WRITER_CACHE_MIB),
            ("[sync]\nwriter_cache_mib = 64\n", 64),
            ("[sync]\nwriter_cache_mib = 0\n", 1),
        ] {
            std::fs::write(&conf, body).unwrap();
            let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
            let cfg = AppConfig::resolve(&cli).unwrap();
            assert_eq!(cfg.sync.writer_cache_mib, expected, "config body: {body:?}");
        }
    }

    /// `[sync] fetch_memos` defaults on (memos are part of the standard history surface) and
    /// parses both ways - `false` is the exchange-style opt-out that skips the memo-backfill
    /// half of the enhancement drain.
    #[cfg(feature = "cli")]
    #[test]
    fn fetch_memos_defaults_on_and_parses_off() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");

        for (body, want) in [
            ("datadir = \"/tmp/rose-x\"\n", true),
            ("[sync]\ninterval_secs = 20\n", true),
            ("[sync]\nfetch_memos = true\n", true),
            ("[sync]\nfetch_memos = false\n", false),
        ] {
            std::fs::write(&conf, body).unwrap();
            let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
            let cfg = AppConfig::resolve(&cli).unwrap();
            assert_eq!(cfg.sync.fetch_memos, want, "config body: {body:?}");
        }
    }

    /// The **embedded** resolution path defaults `fetch_memos` on, exactly as the daemon's does.
    ///
    /// The test above goes through `resolve`, which is clap's path; an embedder calls
    /// `resolve_overrides`, and `ConfigOverrides` carries no `fetch_memos` field at all (it
    /// mirrors the CLI's global flags, and there is no such flag). So a library consumer that
    /// ships no `rose.toml` - which is the common case, and what `examples/embedded.rs` does -
    /// reaches the default through a seam the clap test never exercises. Pinning it here is what
    /// makes "memos are on unless you asked otherwise" true of the library and not just the
    /// binary: the two share one `unwrap_or(true)`, and this is the assertion that fails if a
    /// future refactor gives the embedded path a resolver of its own.
    #[test]
    fn embedded_resolution_defaults_fetch_memos_on() {
        // A datadir of our own, so a `rose.toml` sitting in the default location cannot answer
        // for the default we are trying to observe.
        let dir = tempfile::tempdir().unwrap();
        let cfg = AppConfig::resolve_overrides(&ConfigOverrides {
            regtest: true,
            datadir: Some(dir.path().to_path_buf()),
            ..Default::default()
        })
        .expect("resolve with no config file");
        assert!(
            cfg.sync.fetch_memos,
            "an embedded node with no config file must recover memos"
        );
    }

    /// The multi-spender opt-in defaults off, parses both ways, and - the load-bearing half -
    /// is refused by the daemon while an embedded node accepts it. That asymmetry is the
    /// mechanism keeping the option library-only, so it is asserted here rather than left to
    /// the call sites.
    #[cfg(feature = "cli")]
    #[test]
    fn allow_multiple_spending_wallets_is_off_by_default_and_daemon_only_refused() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");

        for (body, want) in [
            ("network = \"test\"\n", false),
            ("[keys]\nallow_multiple_spending_wallets = false\n", false),
            ("[keys]\nallow_multiple_spending_wallets = true\n", true),
        ] {
            std::fs::write(&conf, body).unwrap();
            let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
            let cfg = AppConfig::resolve(&cli).unwrap();
            assert_eq!(
                cfg.keys.allow_multiple_spending_wallets, want,
                "for config: {body}"
            );
            // The daemon refuses exactly when the option is on; resolution itself never does,
            // because an embedded node resolves through the same path and must accept it.
            assert_eq!(
                reject_multiple_spenders_in_daemon(&cfg).is_err(),
                want,
                "daemon refusal must track the option: {body}"
            );
        }
    }

    /// The duplicate-shielded-recipient opt-in defaults off (zcashd parity is the default
    /// behaviour, not something an operator has to ask for) and parses both ways.
    #[cfg(feature = "cli")]
    #[test]
    fn allow_duplicate_shielded_recipients_defaults_off_and_parses() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");

        for (body, want) in [
            ("network = \"test\"\n", false),
            (
                "[rpc]\nallow_duplicate_shielded_recipients = false\n",
                false,
            ),
            ("[rpc]\nallow_duplicate_shielded_recipients = true\n", true),
        ] {
            std::fs::write(&conf, body).unwrap();
            let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
            let cfg = AppConfig::resolve(&cli).unwrap();
            assert_eq!(
                cfg.rpc.allow_duplicate_shielded_recipients, want,
                "for config: {body}"
            );
        }
    }

    #[cfg(feature = "cli")]
    #[test]
    fn rpc_allowed_methods_parses_and_validates() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");

        // Absent -> empty list (no restriction; every method served).
        std::fs::write(&conf, "network = \"test\"\n").unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert!(cfg.rpc.allowed_methods.is_empty());

        // A valid list is preserved verbatim.
        std::fs::write(
            &conf,
            "[rpc]\nallowed_methods = [\"getbalance\", \"getnewaddress\", \"sendtoaddress\"]\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(
            cfg.rpc.allowed_methods,
            vec![
                "getbalance".to_string(),
                "getnewaddress".to_string(),
                "sendtoaddress".to_string()
            ]
        );

        // An explicit empty array is "no restriction", never "deny everything".
        std::fs::write(&conf, "[rpc]\nallowed_methods = []\n").unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert!(cfg.rpc.allowed_methods.is_empty());

        // An unknown method name is a startup error (typo protection), naming the offender.
        std::fs::write(
            &conf,
            "[rpc]\nallowed_methods = [\"getbalance\", \"getblance\"]\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let err = AppConfig::resolve(&cli).unwrap_err().to_string();
        assert!(err.contains("getblance"), "got: {err}");
    }

    #[test]
    fn read_secret_file_trims_trailing_newline_only() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pw");
        // The classic `echo "secret" > file` leaves a trailing newline; it must be stripped,
        // but interior/leading whitespace is preserved (a password may legitimately contain it).
        std::fs::write(&p, "  hunter2 spaces \n").unwrap();
        assert_eq!(read_secret_file(&p).unwrap().expose(), "  hunter2 spaces ");
        // A missing file is an error (fail fast), not an empty password.
        assert!(read_secret_file(&dir.path().join("nope")).is_err());
    }

    #[cfg(feature = "cli")]
    #[test]
    fn rpc_password_file_is_read_and_overridden_by_cli() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let pw = dir.path().join("rpc.pw");
        std::fs::write(&pw, "from-file\n").unwrap();
        let conf = dir.path().join("rose.toml");
        std::fs::write(
            &conf,
            format!(
                "network = \"test\"\n[rpc]\nuser = \"u\"\npassword = \"inline\"\npassword_file = \"{}\"\n",
                pw.display()
            ),
        )
        .unwrap();

        // password_file overrides the inline [rpc] password...
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(
            cfg.rpc.password.as_ref().map(Password::expose),
            Some("from-file")
        );

        // ...but an explicit --rpcpassword still wins over the file.
        let cli = Cli::parse_from([
            "rose",
            "--conf",
            conf.to_str().unwrap(),
            "--rpcpassword",
            "from-cli",
        ]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(
            cfg.rpc.password.as_ref().map(Password::expose),
            Some("from-cli")
        );

        // A configured-but-missing password_file is a startup error.
        std::fs::write(
            &conf,
            "network = \"test\"\n[rpc]\npassword_file = \"/no/such/rpc.pw\"\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        assert!(AppConfig::resolve(&cli).is_err());
    }

    #[cfg(feature = "cli")]
    #[test]
    fn keys_file_override_resolves_per_wallet() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");

        // Default: keys.toml lives at the root of the wallet's dir, above the per-coin
        // subdirectories (see `Coin::data_dir`) - the seed it wraps serves every coin.
        std::fs::write(&conf, "network = \"test\"\ndatadir = \"/d\"\n").unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(
            cfg.wallets["default"].keys_path(),
            PathBuf::from("/d/default/keys.toml")
        );

        // Global [keys] keys_file applies to the default wallet; a per-wallet override wins for
        // the named wallet and the global doesn't leak onto non-default wallets.
        std::fs::write(
            &conf,
            "network = \"test\"\ndatadir = \"/d\"\n\
             [keys]\nkeys_file = \"/secrets/keys.toml\"\n\
             [wallets.default]\n\
             [wallets.other]\nkeys_file = \"/secrets/other.toml\"\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(
            cfg.wallets["default"].keys_path(),
            PathBuf::from("/secrets/keys.toml")
        );
        assert_eq!(
            cfg.wallets["other"].keys_path(),
            PathBuf::from("/secrets/other.toml")
        );

        // --keys-file overrides the file's global keys_file for the default wallet.
        let cli = Cli::parse_from([
            "rose",
            "--conf",
            conf.to_str().unwrap(),
            "--keys-file",
            "/cli/keys.toml",
        ]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(
            cfg.wallets["default"].keys_path(),
            PathBuf::from("/cli/keys.toml")
        );
    }

    #[cfg(feature = "zcash")]
    #[test]
    #[cfg(feature = "cli")]
    fn every_resolved_wallet_is_a_zcash_wallet() {
        // The implicit default wallet and any named wallet alike. Nothing in the config file
        // selects this - it is a property of the build, resolved once so the rest of the tree
        // reads it from the entry rather than assuming it.
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        std::fs::write(
            &conf,
            "network = \"test\"\ndatadir = \"/d\"\n[wallets.default]\n[wallets.other]\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.wallets["default"].coin, Coin::Zcash);
        assert_eq!(cfg.wallets["other"].coin, Coin::Zcash);
    }

    /// The `coin` key: an explicit `"zcash"` is the default spelled out, and an unsupported
    /// token is one error raised in `resolve` (so the daemon, `config check`, and the
    /// embedded facade refuse it identically), naming the wallet and this build's supported
    /// set. Whether `"bitcoin"` is in that set is a property of the build.
    #[cfg(feature = "zcash")]
    #[test]
    #[cfg(feature = "cli")]
    fn the_coin_key_is_validated_in_resolve() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        std::fs::write(
            &conf,
            "network = \"test\"\ndatadir = \"/d\"\n[wallets.w]\ncoin = \"zcash\"\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.wallets["w"].coin, Coin::Zcash);

        std::fs::write(
            &conf,
            "network = \"test\"\ndatadir = \"/d\"\n[wallets.w]\ncoin = \"dogecoin\"\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let err = AppConfig::resolve(&cli).unwrap_err().to_string();
        assert!(err.contains("unsupported coin \"dogecoin\""), "{err}");
        assert!(err.contains("\"w\""), "{err}");
        assert!(
            err.contains(&format!("this build supports: {}", Coin::supported_names())),
            "{err}"
        );

        std::fs::write(
            &conf,
            "network = \"test\"\ndatadir = \"/d\"\n[wallets.btc]\ncoin = \"bitcoin\"\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        #[cfg(not(feature = "bitcoin"))]
        {
            let err = AppConfig::resolve(&cli).unwrap_err().to_string();
            assert!(err.contains("unsupported coin \"bitcoin\""), "{err}");
        }
        #[cfg(feature = "bitcoin")]
        {
            let cfg = AppConfig::resolve(&cli).unwrap();
            let entry = &cfg.wallets["btc"];
            assert_eq!(entry.coin, Coin::Bitcoin);
            assert_eq!(
                entry.chain,
                CoinNetwork::Bitcoin(crate::coin::BitcoinNetwork::Testnet3)
            );
            assert_eq!(
                entry.bitcoin_network(),
                crate::coin::BitcoinNetwork::Testnet3
            );
            // The engine directory follows the coin's frozen path components.
            assert!(entry.engine_dir().ends_with("btc/bdk"));
        }
    }

    /// The `btc_testnet` key: it selects which public Bitcoin testnet a testnet daemon's
    /// Bitcoin wallets ride (default testnet3), an unsupported token is refused naming the
    /// accepted set, and outside the test environment - where it would be silently inert -
    /// it is refused too. A build without the bitcoin engine refuses any set value.
    #[cfg(feature = "zcash")]
    #[test]
    #[cfg(feature = "cli")]
    fn the_btc_testnet_key_is_validated_in_resolve() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        let resolve = |text: &str| {
            std::fs::write(&conf, text).unwrap();
            let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
            AppConfig::resolve(&cli)
        };

        #[cfg(not(feature = "bitcoin"))]
        {
            let err = resolve("network = \"test\"\ndatadir = \"/d\"\nbtc_testnet = \"testnet4\"\n")
                .unwrap_err()
                .to_string();
            assert!(err.contains("requires a rose build"), "{err}");
        }
        #[cfg(feature = "bitcoin")]
        {
            use crate::coin::{BitcoinNetwork, BitcoinTestnet};
            // Default: testnet3, the engine's previous behaviour.
            let cfg = resolve(
                "network = \"test\"\ndatadir = \"/d\"\n[wallets.btc]\ncoin = \"bitcoin\"\n",
            )
            .unwrap();
            assert_eq!(cfg.btc_testnet, BitcoinTestnet::Testnet3);
            assert_eq!(
                cfg.wallets["btc"].bitcoin_network(),
                BitcoinNetwork::Testnet3
            );

            // testnet4 selects the other public testnet for every Bitcoin wallet.
            let cfg = resolve(
                "network = \"test\"\ndatadir = \"/d\"\nbtc_testnet = \"testnet4\"\n\
                 [wallets.default]\n[wallets.btc]\ncoin = \"bitcoin\"\n",
            )
            .unwrap();
            assert_eq!(cfg.btc_testnet, BitcoinTestnet::Testnet4);
            assert_eq!(
                cfg.wallets["btc"].bitcoin_network(),
                BitcoinNetwork::Testnet4
            );
            // ...and never touches a Zcash wallet's chain.
            assert_eq!(
                cfg.wallets["default"].chain,
                CoinNetwork::Zcash(ZNetwork::Test)
            );

            // An unsupported token names the accepted set.
            let err = resolve("network = \"test\"\ndatadir = \"/d\"\nbtc_testnet = \"signet\"\n")
                .unwrap_err()
                .to_string();
            assert!(err.contains("testnet3, testnet4"), "{err}");

            // Outside the test environment the key is inert, so it is refused instead.
            for network in ["main", "regtest"] {
                let err = resolve(&format!(
                    "network = \"{network}\"\ndatadir = \"/d\"\nbtc_testnet = \"testnet4\"\n"
                ))
                .unwrap_err()
                .to_string();
                assert!(err.contains("applies only to a testnet daemon"), "{err}");
                assert!(err.contains(network), "{err}");
            }
        }
    }

    /// A Zcash-engine key on a non-Zcash wallet is refused, not silently ignored: a set key
    /// that configures nothing would read as configuration.
    #[test]
    #[cfg(all(feature = "cli", feature = "bitcoin"))]
    fn zcash_engine_keys_are_refused_on_a_bitcoin_wallet() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        for (key, line) in [
            ("transparent", "transparent = true"),
            ("pools", "pools = [\"orchard\"]"),
            ("tls", "tls = \"yes\""),
        ] {
            std::fs::write(
                &conf,
                format!(
                    "network = \"test\"\ndatadir = \"/d\"\n[wallets.btc]\ncoin = \"bitcoin\"\n{line}\n"
                ),
            )
            .unwrap();
            let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
            let err = AppConfig::resolve(&cli).unwrap_err().to_string();
            assert!(
                err.contains(&format!("[wallets.btc] {key}")),
                "{key}: {err}"
            );
            assert!(err.contains("Zcash engine"), "{key}: {err}");
        }
    }

    /// The Bitcoin engine's `lookahead`: resolved per wallet with BDK's default, at least 1,
    /// and refused on a Zcash wallet naming the key that plays its role there.
    #[cfg(feature = "zcash")]
    #[test]
    #[cfg(all(feature = "cli", feature = "bitcoin"))]
    fn lookahead_is_a_bitcoin_wallet_knob() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        let resolve = |body: &str| {
            std::fs::write(&conf, body).unwrap();
            let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
            AppConfig::resolve(&cli)
        };
        let cfg =
            resolve("network = \"test\"\ndatadir = \"/d\"\n[wallets.btc]\ncoin = \"bitcoin\"\n")
                .unwrap();
        assert_eq!(cfg.wallets["btc"].lookahead, DEFAULT_LOOKAHEAD);
        assert_eq!(DEFAULT_LOOKAHEAD, 25, "BDK's default");
        let cfg = resolve(
            "network = \"test\"\ndatadir = \"/d\"\n[wallets.btc]\ncoin = \"bitcoin\"\nlookahead = 40\n",
        )
        .unwrap();
        assert_eq!(cfg.wallets["btc"].lookahead, 40);
        let err = resolve(
            "network = \"test\"\ndatadir = \"/d\"\n[wallets.btc]\ncoin = \"bitcoin\"\nlookahead = 0\n",
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("[wallets.btc] lookahead must be at least 1"),
            "{err}"
        );
        let err = resolve("network = \"test\"\ndatadir = \"/d\"\n[wallets.zec]\nlookahead = 40\n")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("[wallets.zec] lookahead does not apply to a zcash wallet"),
            "{err}"
        );
        assert!(err.contains("transparent_gap_limit"), "{err}");
    }

    /// The Bitcoin engine's `initial_scan`: off by default, taken as given on a Bitcoin
    /// wallet, and refused on a Zcash wallet naming `transparent_initial_scan`.
    #[cfg(feature = "zcash")]
    #[test]
    #[cfg(all(feature = "cli", feature = "bitcoin"))]
    fn initial_scan_is_a_bitcoin_wallet_knob() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        let resolve = |body: &str| {
            std::fs::write(&conf, body).unwrap();
            let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
            AppConfig::resolve(&cli)
        };
        let cfg =
            resolve("network = \"test\"\ndatadir = \"/d\"\n[wallets.btc]\ncoin = \"bitcoin\"\n")
                .unwrap();
        assert_eq!(cfg.wallets["btc"].initial_scan, 0);
        let cfg = resolve(
            "network = \"test\"\ndatadir = \"/d\"\n[wallets.btc]\ncoin = \"bitcoin\"\n\
             initial_scan = 10000\n",
        )
        .unwrap();
        assert_eq!(cfg.wallets["btc"].initial_scan, 10000);
        let err =
            resolve("network = \"test\"\ndatadir = \"/d\"\n[wallets.zec]\ninitial_scan = 100\n")
                .unwrap_err()
                .to_string();
        assert!(
            err.contains("[wallets.zec] initial_scan does not apply to a zcash wallet"),
            "{err}"
        );
        assert!(err.contains("transparent_initial_scan"), "{err}");
    }

    /// `allow_sends_without_mempool_view`: off by default, taken as given on a
    /// Bitcoin wallet, and refused on a Zcash wallet, which has no kyoto send gate.
    #[cfg(feature = "zcash")]
    #[test]
    #[cfg(all(feature = "cli", feature = "bitcoin"))]
    fn allow_sends_without_mempool_view_is_a_bitcoin_wallet_knob() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        let resolve = |body: &str| {
            std::fs::write(&conf, body).unwrap();
            let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
            AppConfig::resolve(&cli)
        };
        let cfg =
            resolve("network = \"test\"\ndatadir = \"/d\"\n[wallets.btc]\ncoin = \"bitcoin\"\n")
                .unwrap();
        assert!(!cfg.wallets["btc"].allow_sends_without_mempool_view);
        let cfg = resolve(
            "network = \"test\"\ndatadir = \"/d\"\n[wallets.btc]\ncoin = \"bitcoin\"\n\
             allow_sends_without_mempool_view = true\n",
        )
        .unwrap();
        assert!(cfg.wallets["btc"].allow_sends_without_mempool_view);
        let err = resolve(
            "network = \"test\"\ndatadir = \"/d\"\n[wallets.zec]\n\
             allow_sends_without_mempool_view = true\n",
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains(
                "[wallets.zec] allow_sends_without_mempool_view does not apply to a zcash wallet"
            ),
            "{err}"
        );
    }

    #[cfg(feature = "zcash")]
    #[test]
    #[cfg(feature = "cli")]
    fn wallet_chain_is_derived_from_the_daemon_environment() {
        // One environment per daemon: a wallet's chain follows from it rather than being
        // configured on its own, so there is no way to express a mainnet wallet in a testnet
        // daemon.
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        std::fs::write(
            &conf,
            "datadir = \"/d\"\n[wallets.default]\n[wallets.other]\n",
        )
        .unwrap();

        for (flag, env) in [("test", ZNetwork::Test), ("main", ZNetwork::Main)] {
            let cli = Cli::parse_from([
                "rose",
                "--conf",
                conf.to_str().unwrap(),
                "--network",
                flag,
                "--rpcpassword",
                "not-the-placeholder",
            ]);
            let cfg = AppConfig::resolve(&cli).unwrap();
            for name in ["default", "other"] {
                let entry = &cfg.wallets[name];
                assert_eq!(entry.chain, CoinNetwork::Zcash(env));
                assert_eq!(entry.zcash_network(), env);
                assert_eq!(entry.zcash_network(), cfg.network);
            }
        }
    }

    #[cfg(feature = "zcash")]
    #[test]
    #[cfg(feature = "cli")]
    fn per_wallet_backend_overrides_fall_back_to_the_global_section() {
        // One daemon, two upstreams: a zebra-backed wallet alongside a lightwalletd-backed one.
        // A wallet that overrides nothing must resolve exactly as it did before the keys existed.
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        std::fs::write(
            &conf,
            "network = \"test\"\ndatadir = \"/d\"\n\
             [backend]\nserver = \"zebra://127.0.0.1:18234\"\ntls_roots = \"webpki\"\n\
             [wallets.default]\n\
             [wallets.replica]\nserver = \"https://lwd.example:9067\"\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();

        // No overrides: the global endpoint, unchanged.
        let default = &cfg.wallets["default"];
        assert!(default.backend.is_empty());
        let resolved = crate::backend::resolve_for_wallet(&cfg, default).unwrap();
        assert_eq!(
            resolved.describe(),
            crate::backend::resolve_configured(&cfg).unwrap().describe()
        );

        // Overridden server, but the global TLS settings still apply field by field.
        let replica = &cfg.wallets["replica"];
        assert!(!replica.backend.is_empty());
        let resolved = crate::backend::resolve_for_wallet(&cfg, replica).unwrap();
        assert_eq!(resolved.kind(), crate::backend::ServerKind::Lightwalletd);
        assert_eq!(
            replica.backend.effective(&cfg.backend).tls_roots,
            crate::backend::TlsRoots::Webpki
        );
    }

    #[test]
    #[cfg(feature = "cli")]
    fn per_wallet_backend_keys_are_parsed_and_validated_by_their_own_key() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");

        // A bad value names the wallet's own key, not `[backend]`.
        std::fs::write(
            &conf,
            "network = \"test\"\ndatadir = \"/d\"\n[wallets.a]\ntls_roots = \"bogus\"\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let err = format!("{:#}", AppConfig::resolve(&cli).unwrap_err());
        assert!(err.contains("[wallets.a] tls_roots"), "{err}");

        // The TLS contradiction checks apply per wallet, against its effective settings.
        std::fs::write(
            &conf,
            "network = \"test\"\ndatadir = \"/d\"\n\
             [wallets.a]\nserver = \"https://lwd.example\"\ntls = \"no\"\n\
             tls_pinned_sha256 = [\"AA:BB\"]\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        assert!(AppConfig::resolve(&cli).is_err());
    }

    #[cfg(all(feature = "cli", feature = "bitcoin"))]
    #[test]
    fn the_fee_source_chain_defaults_and_is_overridable() {
        use clap::Parser as _;
        // No `[fees]` at all is the built-in chain: a forward estimate first, a second
        // independent oracle behind it, the no-third-party signals last.
        let cli = Cli::parse_from(["rose"]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.fees.sources, DEFAULT_FEE_SOURCES.to_vec());
        assert!(cfg.fees.mempool_space_url.is_none());
        assert!(cfg.fees.esplora_url.is_none());

        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        // Reordered, shortened, and both endpoints redirected at instances the operator runs -
        // the shape that turns the fee lookup from a third-party disclosure into a private one.
        std::fs::write(
            &conf,
            "[fees]\nsources = [\"esplora\", \"peer_median\"]\n\
             mempool_space_url = \"https://mempool.internal/api/v1/fees/recommended\"\n\
             esplora_url = \"http://esplora.internal:3002/api/fee-estimates\"\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(
            cfg.fees.sources,
            vec![FeeSource::Esplora, FeeSource::PeerMedian]
        );
        assert_eq!(
            cfg.fees.esplora_url.as_deref(),
            Some("http://esplora.internal:3002/api/fee-estimates")
        );
        // Set but unnamed in `sources`: kept as configured (resolve records, it does not
        // second-guess), and simply never asked.
        assert!(cfg.fees.mempool_space_url.is_some());
    }

    #[cfg(all(feature = "cli", feature = "bitcoin"))]
    #[test]
    fn the_absolute_fee_cap_defaults_to_cores_and_refuses_zero() {
        use clap::Parser as _;
        let cli = Cli::parse_from(["rose"]);
        assert_eq!(
            AppConfig::resolve(&cli).unwrap().fees.max_tx_fee_sat,
            DEFAULT_MAX_TX_FEE_SAT
        );

        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        let resolve = |body: &str| {
            std::fs::write(&conf, body).unwrap();
            let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
            AppConfig::resolve(&cli)
        };
        assert_eq!(
            resolve("[fees]\nmax_tx_fee_sat = 250000\n")
                .unwrap()
                .fees
                .max_tx_fee_sat,
            250_000
        );
        let err = resolve("[fees]\nmax_tx_fee_sat = 0\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("max_tx_fee_sat"), "{err}");
    }

    #[cfg(all(feature = "cli", feature = "bitcoin"))]
    #[test]
    fn the_mempool_feed_is_off_by_default_and_opt_in() {
        use clap::Parser as _;
        // No `[mempool]` at all: the relay peer, which contacts nobody the wallet is not
        // already peered with. The websocket tier is never reached by default.
        let cli = Cli::parse_from(["rose"]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.mempool, MempoolConfig::default());
        assert_eq!(cfg.mempool.sources, DEFAULT_MEMPOOL_SOURCES.to_vec());
        assert!(!cfg.mempool.sources_explicit);

        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        let resolve = |body: &str| {
            std::fs::write(&conf, body).unwrap();
            let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
            AppConfig::resolve(&cli)
        };
        // Named, at a self-hosted instance - plaintext allowed, like the fee overrides.
        let cfg = resolve(
            "[mempool]\nsources = [\"mempool_space\"]\n\
             mempool_space_url = \"ws://mempool.internal:8999/api/v1/ws\"\n",
        )
        .unwrap();
        assert_eq!(cfg.mempool.sources, vec![MempoolSource::MempoolSpace]);
        assert_eq!(
            cfg.mempool.mempool_space_url.as_deref(),
            Some("ws://mempool.internal:8999/api/v1/ws")
        );
        assert!(cfg.mempool.p2p_peer.is_none());
        assert!(!cfg.mempool.p2p_snapshot);
        // The P2P source, in preference order ahead of the websocket, pinned to a node with
        // the snapshot requests on.
        let cfg = resolve(
            "[mempool]\nsources = [\"p2p\", \"mempool_space\"]\n\
             p2p_peer = \"[2001:db8::7]:48333\"\np2p_snapshot = true\n",
        )
        .unwrap();
        assert_eq!(
            cfg.mempool.sources,
            vec![MempoolSource::P2p, MempoolSource::MempoolSpace]
        );
        assert_eq!(
            cfg.mempool.p2p_peer.map(|p| p.to_string()).as_deref(),
            Some("[2001:db8::7]:48333")
        );
        assert!(cfg.mempool.p2p_snapshot);
        assert_eq!(
            cfg.mempool.p2p_snapshot_interval_secs,
            DEFAULT_P2P_SNAPSHOT_INTERVAL_SECS
        );
        // The interval has a floor: below it the requests overlap their own window.
        let cfg =
            resolve("[mempool]\nsources = [\"p2p\"]\np2p_snapshot_interval_secs = 5\n").unwrap();
        assert_eq!(cfg.mempool.p2p_snapshot_interval_secs, 5);
        let err = resolve("[mempool]\np2p_snapshot_interval_secs = 4\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("p2p_snapshot_interval_secs"), "{err}");
        // A DNS name is refused, naming the grammar - the peer is dialed by address only.
        let err = resolve("[mempool]\np2p_peer = \"node.example:8333\"\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("[mempool] p2p_peer"), "{err}");
        assert!(err.contains("<ip>:<port>"), "{err}");
        assert!(resolve("[mempool]\np2p_peer = \"10.0.0.1\"\n").is_err());
        // A blank override is unset (a template shipping the key empty must not fail).
        let cfg = resolve("[mempool]\nsources = [\"mempool_space\"]\nmempool_space_url = \"\"\n")
            .unwrap();
        assert!(cfg.mempool.mempool_space_url.is_none());
        // An explicit empty list is the off switch, and is NOT the same as unset: a named
        // list is taken verbatim, so the default chain never comes back through the side door.
        let cfg = resolve("[mempool]\nsources = []\n").unwrap();
        assert!(cfg.mempool.sources.is_empty());
        assert!(cfg.mempool.sources_explicit);

        // Refusals, each naming the line to fix: an unknown source, a repeated one, and an
        // override that is the HTTP API rather than the websocket.
        let err = resolve("[mempool]\nsources = [\"mempool\"]\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid [mempool] source"), "{err}");
        assert!(err.contains("mempool_space"), "{err}");
        assert!(err.contains("p2p"), "{err}");
        let err = resolve("[mempool]\nsources = [\"mempool_space\", \"mempool_space\"]\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("more than once"), "{err}");
        let err = resolve("[mempool]\nmempool_space_url = \"https://mempool.space/api/v1/ws\"\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("[mempool] mempool_space_url"), "{err}");
        assert!(err.contains("wss://"), "{err}");
        // And an unknown key in the section is refused like everywhere else.
        assert!(resolve("[mempool]\nsource = \"mempool_space\"\n").is_err());
    }

    #[cfg(all(feature = "cli", feature = "bitcoin"))]
    #[test]
    fn a_fee_chain_that_could_not_work_is_refused_at_resolve() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        let resolve = |body: &str| {
            std::fs::write(&conf, body).unwrap();
            let cli = Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
            AppConfig::resolve(&cli)
        };

        // A misspelled tier names the accepted values rather than silently dropping one - a
        // dropped oracle is invisible until the one above it is down.
        let err = resolve("[fees]\nsources = [\"mempool\"]\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("mempool_space"), "{err}");
        // A repeat is a typo, not a request to ask one oracle twice.
        assert!(resolve("[fees]\nsources = [\"esplora\", \"esplora\"]\n").is_err());
        // An override that could never be fetched fails at startup, not at the first send.
        assert!(resolve("[fees]\nesplora_url = \"esplora.example/api\"\n").is_err());
        assert!(resolve("[fees]\nmempool_space_url = \"ftp://mempool.example/x\"\n").is_err());
        // An empty override is "unset": a template shipping the key blank still starts, on the
        // built-in endpoint.
        let cfg = resolve("[fees]\nesplora_url = \"\"\n").unwrap();
        assert!(cfg.fees.esplora_url.is_none());
        // An empty list is legal and means no estimation at all - every send must then carry
        // an explicit fee rate.
        assert!(resolve("[fees]\nsources = []\n")
            .unwrap()
            .fees
            .sources
            .is_empty());
    }

    /// The example and docker configs must deserialize (`deny_unknown_fields` catches typos and
    /// drift as the schema evolves).
    ///
    /// These three select the Zcash engine - `rose.example.toml` documents `[pools]` and
    /// `[spend]`, the deploy pair set `[zebra]` - so they parse in a build that carries it and
    /// are refused as unknown sections in one that does not, which is the doctrine and is
    /// asserted from the other side in `tests/cli.rs`.
    #[cfg(feature = "zcash")]
    #[test]
    fn shipped_configs_parse() {
        toml::from_str::<ConfigFile>(include_str!("../rose.example.toml"))
            .expect("rose.example.toml");
        // What `rose example-config` emits must be loadable by the same binary that emitted it.
        toml::from_str::<ConfigFile>(crate::example_config::EXAMPLE_CONFIG)
            .expect("example-config output");
        toml::from_str::<ConfigFile>(include_str!("../deploy/rose.toml"))
            .expect("deploy/rose.toml");
        toml::from_str::<ConfigFile>(include_str!("../deploy/rose.mainnet.toml"))
            .expect("deploy/rose.mainnet.toml");
    }

    /// The Bitcoin deploy samples are the mirror image: they parse wherever the BDK engine is
    /// compiled in, including a build with no Zcash engine at all.
    #[cfg(feature = "bitcoin")]
    #[test]
    fn shipped_bitcoin_configs_parse() {
        for (name, body) in [
            (
                "deploy/rose.btc-mainnet.toml",
                include_str!("../deploy/rose.btc-mainnet.toml"),
            ),
            (
                "deploy/rose.btc-mainnet-view.toml",
                include_str!("../deploy/rose.btc-mainnet-view.toml"),
            ),
            (
                "deploy/rose.btc-testnet3.toml",
                include_str!("../deploy/rose.btc-testnet3.toml"),
            ),
            (
                "deploy/rose.btc-testnet4.toml",
                include_str!("../deploy/rose.btc-testnet4.toml"),
            ),
            (
                "deploy/rose.btc-testnet4-kyoto.toml",
                include_str!("../deploy/rose.btc-testnet4-kyoto.toml"),
            ),
            (
                "deploy/rose.btc-testnet4-view.toml",
                include_str!("../deploy/rose.btc-testnet4-view.toml"),
            ),
        ] {
            toml::from_str::<ConfigFile>(body).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    /// `wallet_dir` is `datadir.join(name)`, so a wallet named after the fleet root claims it.
    /// Nothing is overwritten - the fleet's own files sit deeper - which is exactly why this
    /// needs catching: two owners would share a tree, `rose rescan` on the wallet would delete
    /// through it, and a backup scoped to the wallet would quietly carry viewing keys.
    #[cfg(feature = "zcash")]
    #[test]
    fn a_wallet_named_after_the_fleet_root_is_refused_when_the_fleet_runs() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        std::fs::write(
            &conf,
            format!(
                "network = \"test\"\ndatadir = {:?}\n[wallets.fleet]\n[fleet]\nenabled = true\n",
                dir.path()
            ),
        )
        .unwrap();

        let err = AppConfig::resolve_overrides(&ConfigOverrides {
            conf: Some(conf),
            ..Default::default()
        })
        .expect_err("a wallet directory holding the fleet's own tree is refused");
        let msg = format!("{err:#}");
        assert!(msg.contains("wallet 'fleet'"), "names the wallet: {msg}");
        assert!(msg.contains("overlaps the fleet"), "names the clash: {msg}");
    }

    /// The same config starts fine with the fleet off, because nothing then reads or writes
    /// those paths - a deployment that has long had a wallet called `fleet` keeps working, and
    /// `config check` reports the latent overlap instead.
    #[cfg(feature = "zcash")]
    #[test]
    fn a_wallet_named_after_the_fleet_root_is_allowed_while_the_fleet_is_off() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        std::fs::write(
            &conf,
            format!(
                "network = \"test\"\ndatadir = {:?}\n[wallets.fleet]\n",
                dir.path()
            ),
        )
        .unwrap();

        let config = AppConfig::resolve_overrides(&ConfigOverrides {
            conf: Some(conf),
            ..Default::default()
        })
        .expect("resolves with the fleet disabled");
        assert!(!config.fleet.enabled);
        assert!(fleet_path_conflict(&config.wallets, &config.fleet).is_some());
    }

    /// The ordinary shape: a wallet beside the fleet, sharing only the data directory itself.
    #[cfg(feature = "zcash")]
    #[test]
    fn an_ordinary_wallet_does_not_overlap_the_fleet() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("rose.toml");
        std::fs::write(
            &conf,
            format!(
                "network = \"test\"\ndatadir = {:?}\n[wallets.default]\n[fleet]\nenabled = true\n",
                dir.path()
            ),
        )
        .unwrap();

        let config = AppConfig::resolve_overrides(&ConfigOverrides {
            conf: Some(conf),
            ..Default::default()
        })
        .expect("resolves");
        assert_eq!(
            config.fleet.manifest_dir,
            dir.path().join("fleet/zec/wallets.d")
        );
        assert_eq!(config.fleet.dir, dir.path().join("fleet/zec/shards"));
        assert_eq!(fleet_path_conflict(&config.wallets, &config.fleet), None);
    }
}
