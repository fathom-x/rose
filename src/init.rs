//! `zecd init`: create a new wallet (age identity + mnemonic + account), ported from
//! `zcash-devtool/src/commands/wallet/init.rs`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use age::secrecy::ExposeSecret as _;
use anyhow::{anyhow, bail, Context};
use bip0039::{Count, English, Mnemonic};
use secrecy::{SecretVec, Zeroize};
use tokio::io::AsyncWriteExt as _;

use tracing::warn;
use zcash_client_backend::data_api::{
    Account as _, AccountPurpose, AccountSource, WalletRead, WalletWrite,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

use crate::backend;
use crate::chain::ChainSource as _;
use crate::config::{AppConfig, WalletEntry};
#[cfg(feature = "cli")]
use crate::config::{ExportUfvkArgs, InitArgs, RescanArgs};
use crate::network::ZNetwork;
use crate::pools::{Receiver, ReceiverSet};
use crate::wallet::keys;
use crate::wallet::open;
use crate::wallet::store::{Passphrase, WalletStore};

/// How far below the chain tip a *freshly generated* **Zcash** wallet's birthday is placed.
///
/// A new wallet has no history, so the tip itself would do - the margin absorbs a short reorg
/// between reading the tip and recording the birthday, which would otherwise strand the wallet
/// anchored to a block that no longer exists. 100 blocks is ~2 hours at Zcash's 75-second
/// spacing, far beyond observed reorg depths, and costs nothing meaningful to scan. The
/// margin defaults per coin ([`default_fresh_wallet_birthday_margin`]) precisely because a
/// block count spans ~10x more wall-clock time on Bitcoin; the config overrides
/// (`[keys]`/`[wallets.<name>] fresh_wallet_birthday_margin`) exist for operators with their
/// own reorg model.
pub const FRESH_WALLET_BIRTHDAY_MARGIN: u32 = 100;

/// The [`FRESH_WALLET_BIRTHDAY_MARGIN`] analog for a **Bitcoin** wallet: ~1 hour at 10-minute
/// spacing, still generous against observed depths (Bitcoin's deepest reorg in 2026 was
/// 2 blocks).
#[cfg(feature = "bitcoin")]
pub const BTC_FRESH_WALLET_BIRTHDAY_MARGIN: u32 = 6;

/// The built-in birthday margin for a coin, when neither the wallet's
/// `fresh_wallet_birthday_margin` nor the global `[keys]` one is set.
pub fn default_fresh_wallet_birthday_margin(coin: crate::coin::Coin) -> u32 {
    match coin {
        crate::coin::Coin::Zcash => FRESH_WALLET_BIRTHDAY_MARGIN,
        #[cfg(feature = "bitcoin")]
        crate::coin::Coin::Bitcoin => BTC_FRESH_WALLET_BIRTHDAY_MARGIN,
    }
}

/// The birthday `init` records for a freshly generated wallet at a given chain tip, `margin`
/// blocks below it (`margin` is the wallet's resolved `fresh_wallet_birthday_margin`).
///
/// Exposed so a caller that needs the height *before* creating the wallet - pinning a birthday
/// alongside a seed it generated itself, say - gets the number `init` would actually use rather
/// than re-deriving the policy. [`crate::chain_probe`] reports it for exactly that reason.
pub fn fresh_wallet_birthday(chain_tip: u32, margin: u32) -> u32 {
    chain_tip.saturating_sub(margin)
}

/// A wallet birthday as the operator states it: an exact block height, or a calendar date
/// (UTC) that `init` resolves to a height with a comfortable safety margin.
///
/// Dates exist because a height is the wrong unit to ask a human for: nobody remembers the
/// height their wallet was created at, everyone can say "sometime in July" - and a height is
/// per-network where a date means the right thing on every chain. Approximate is fine by
/// construction: a birthday resolved *early* merely scans more, while funds can never
/// predate the wallet, so every resolution path here errs low (see
/// [`BIRTHDAY_DATE_MARGIN_SECS`]). The resolved height is what gets persisted; nothing
/// downstream sees a date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Birthday {
    Height(u32),
    /// Unix seconds at the date's UTC midnight.
    Date(u64),
}

impl From<u32> for Birthday {
    fn from(height: u32) -> Self {
        Birthday::Height(height)
    }
}

impl Birthday {
    /// Parse a CLI birthday: all-digits is a height, `YYYY-MM-DD` a UTC date. The `String`
    /// error type is what clap's `value_parser` wants.
    pub fn parse(s: &str) -> Result<Self, String> {
        if s.chars().all(|c| c.is_ascii_digit()) {
            return s
                .parse::<u32>()
                .map(Birthday::Height)
                .map_err(|_| format!("'{s}' is not a valid block height"));
        }
        let mut parts = s.splitn(3, '-');
        let (y, m, d) = match (parts.next(), parts.next(), parts.next()) {
            (Some(y), Some(m), Some(d)) => (y, m, d),
            _ => {
                return Err(format!(
                    "'{s}' is neither a block height nor a YYYY-MM-DD date"
                ))
            }
        };
        let bad = || format!("'{s}' is not a valid YYYY-MM-DD date");
        let year: i64 = y.parse().map_err(|_| bad())?;
        let month: u32 = m.parse().map_err(|_| bad())?;
        let day: u32 = d.parse().map_err(|_| bad())?;
        if !(2009..=9999).contains(&year) || !(1..=12).contains(&month) {
            return Err(bad());
        }
        if day == 0 || day > days_in_month(year, month) {
            return Err(bad());
        }
        let days = days_from_civil(year, i64::from(month), i64::from(day));
        let midnight = u64::try_from(days).map_err(|_| bad())? * 86_400;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(u64::MAX);
        if midnight > now {
            return Err(format!("birthday date '{s}' is in the future"));
        }
        Ok(Birthday::Date(midnight))
    }
}

fn days_in_month(year: i64, month: u32) -> u32 {
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        _ => 28,
    }
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's `days_from_civil` algorithm),
/// so date parsing needs no calendar dependency.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The comfortable margin a date-given birthday is backed off by before it becomes a
/// height: one full day. The date's UTC midnight already precedes the wallet's actual
/// creation moment by up to a day, header timestamps skew by at most ~2 hours, and a day
/// of extra scan is cheap on every chain - so the resolved height provably cannot postdate
/// the wallet's first possible transaction.
const BIRTHDAY_DATE_MARGIN_SECS: u64 = 24 * 60 * 60;

/// The pure state of the date->height search over block times, driven by
/// [`height_for_time`] and [`zcash_height_for_date`] so the algorithm exists once (an
/// `async` probe cannot ride the sync driver's closure).
///
/// Probes are *interpolated*, not bisected: the bracket's two endpoints imply the chain's
/// own average block time over that span, and the target's offset into the bracket divided
/// by that spacing lands within a few blocks on a steadily-mined chain - single-digit
/// probes where bisection alone takes ~log2(tip) (~22 on Bitcoin mainnet, more on
/// testnet3). The average is derived per bracket from the observed times, so it self-tunes
/// to any network and to hashrate drift within one, with no hardcoded spacing constants.
/// Every other probe falls back to plain bisection, bounding pathological timestamp
/// distributions at ~2 log2(tip) instead of O(tip).
///
/// Invariant between observations: `time(lo) <= target < time(hi)`, so [`answer`] is `lo`
/// once the bracket closes. Block header times jitter by ~2 hours rather than being
/// strictly monotonic; callers pass a target already backed off by
/// [`BIRTHDAY_DATE_MARGIN_SECS`], which dwarfs it. A target before the chain's first block
/// resolves to height 1 (scan everything; never height 0 - genesis is unrequestable on the
/// Zcash side).
///
/// [`answer`]: HeightSearch::answer
struct HeightSearch {
    lo: u32,
    hi: u32,
    t_lo: Option<u64>,
    t_hi: Option<u64>,
    target: u64,
    bisect: bool,
    done: bool,
}

impl HeightSearch {
    fn new(tip: u32, target: u64) -> Self {
        Self {
            lo: 1,
            hi: tip.max(1),
            t_lo: None,
            t_hi: None,
            target,
            bisect: false,
            done: false,
        }
    }

    /// The next height to fetch a block time for, or `None` once [`Self::answer`] is
    /// ready: the bracket's two endpoints first, then interpolated probes.
    fn next_probe(&self) -> Option<u32> {
        if self.done {
            return None;
        }
        let (t_lo, t_hi) = match (self.t_lo, self.t_hi) {
            (None, _) => return Some(self.lo),
            (_, None) => return Some(self.hi),
            (Some(t_lo), Some(t_hi)) => (t_lo, t_hi),
        };
        if self.hi - self.lo <= 1 {
            return None;
        }
        let span = self.hi - self.lo;
        // `t_hi > t_lo` holds by the bracket invariant; the guard is belt-and-braces
        // against a division by zero ever costing correctness.
        let guess = if self.bisect || t_hi <= t_lo {
            self.lo + span / 2
        } else {
            // (t_hi - t_lo) / span is the bracket's average seconds-per-block; the
            // target's offset from t_lo divided by it is the interpolated distance.
            let num = u128::from(self.target - t_lo) * u128::from(span);
            let den = u128::from(t_hi - t_lo);
            self.lo + u32::try_from(num / den).unwrap_or(span)
        };
        // Strictly inside the bracket, so every probe shrinks it.
        Some(guess.clamp(self.lo + 1, self.hi - 1))
    }

    /// Feed back the block time at the height [`Self::next_probe`] named.
    fn observe(&mut self, height: u32, time: u64) {
        if self.t_lo.is_none() {
            self.t_lo = Some(time);
            // A target before the chain's first block: height 1 is the answer (scan
            // everything). A one-block chain is likewise already answered.
            if time > self.target || self.hi == self.lo {
                self.done = true;
            }
            return;
        }
        if self.t_hi.is_none() {
            self.t_hi = Some(time);
            // The whole chain sits at or before the target: the tip is the answer.
            if time <= self.target {
                self.lo = self.hi;
                self.done = true;
            }
            return;
        }
        self.bisect = !self.bisect;
        if time <= self.target {
            self.lo = height;
            self.t_lo = Some(time);
        } else {
            self.hi = height;
            self.t_hi = Some(time);
        }
    }

    /// The highest height whose observed time is at or below the target.
    fn answer(&self) -> u32 {
        self.lo
    }
}

/// [`HeightSearch`] driven by a blocking probe (the bitcoind path); one upstream call per
/// probe.
fn height_for_time(
    mut time_at: impl FnMut(u32) -> anyhow::Result<u64>,
    tip: u32,
    target: u64,
) -> anyhow::Result<u32> {
    let mut search = HeightSearch::new(tip, target);
    while let Some(height) = search.next_probe() {
        let time = time_at(height)?;
        search.observe(height, time);
    }
    Ok(search.answer())
}

/// [`HeightSearch`] driven against the Zcash upstream: the block time at each probed
/// height comes from the tree state, one unary call both backends serve.
async fn zcash_height_for_date(
    client: &mut crate::chain::AnySource,
    chain_tip: u32,
    date: u64,
) -> anyhow::Result<u32> {
    let target = date.saturating_sub(BIRTHDAY_DATE_MARGIN_SECS);
    let mut search = HeightSearch::new(chain_tip, target);
    while let Some(height) = search.next_probe() {
        let state = client.tree_state(BlockHeight::from(height)).await?;
        search.observe(height, u64::from(state.time));
    }
    Ok(search.answer())
}

/// The default account birthday when `--birthday` is omitted for a restore/import: the
/// activation height of the earliest *enabled* shielded pool, with a human label. An
/// Orchard-only wallet (the default) can hold no notes before NU5 (Orchard activation), so it
/// starts there - much faster than the old Sapling-activation default while never missing an
/// Orchard note. A Sapling-enabled wallet must start at Sapling activation, where it could
/// first hold notes.
fn restore_birthday_default(network: ZNetwork, pools: &ReceiverSet) -> (u32, &'static str) {
    let (upgrade, label) = if pools.contains(Receiver::Sapling) {
        (NetworkUpgrade::Sapling, "Sapling")
    } else {
        (NetworkUpgrade::Nu5, "Orchard (NU5)")
    };
    let height = u32::from(
        network
            .activation_height(upgrade)
            .expect("pool activation height is known"),
    );
    (height, label)
}

/// Minimum length (in characters) for a wallet-encryption passphrase.
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// Reject a too-short passphrase before it wraps the mnemonic.
#[cfg(any(feature = "cli", test))]
fn validate_passphrase(p: &str) -> anyhow::Result<()> {
    let n = p.chars().count();
    if n < MIN_PASSPHRASE_CHARS {
        bail!("passphrase must be at least {MIN_PASSPHRASE_CHARS} characters (got {n})");
    }
    Ok(())
}

/// Read the encryption passphrase for `init --encrypt`. Prefers the `ZECD_WALLET_PASSPHRASE`
/// environment variable (for non-interactive/automated init); otherwise prompts on stderr and
/// reads it twice from stdin to confirm. Only the trailing newline is stripped, so a passphrase
/// may contain surrounding spaces.
#[cfg(feature = "cli")]
fn read_encryption_passphrase() -> anyhow::Result<Passphrase> {
    if let Some(p) = std::env::var_os("ZECD_WALLET_PASSPHRASE") {
        let s = p.to_string_lossy().into_owned();
        validate_passphrase(&s)?;
        return Ok(Passphrase::from(s));
    }
    let read_line = |prompt: &str| -> anyhow::Result<String> {
        eprintln!("{prompt}");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(line.trim_end_matches(['\n', '\r']).to_string())
    };
    let p1 = read_line("Enter a passphrase to encrypt the wallet:")?;
    let p2 = read_line("Confirm passphrase:")?;
    if p1 != p2 {
        bail!("passphrases do not match");
    }
    validate_passphrase(&p1)?;
    Ok(Passphrase::from(p1))
}

/// Read a mnemonic phrase from the non-interactive sources first - the `ZECD_MNEMONIC`
/// environment variable, then `file` - and otherwise print `prompt` on stderr and read one line
/// from stdin. Surrounding whitespace is trimmed. Shared by `init --restore` and
/// `derive-address --mnemonic` so both accept the same inputs in the same precedence.
#[cfg(feature = "cli")]
pub(crate) fn read_mnemonic_phrase(
    file: Option<&Path>,
    prompt: &str,
) -> anyhow::Result<Mnemonic<English>> {
    let phrase = if let Some(p) = std::env::var_os("ZECD_MNEMONIC") {
        p.to_string_lossy().trim().to_string()
    } else if let Some(path) = file {
        std::fs::read_to_string(path)
            .with_context(|| format!("reading mnemonic file {}", path.display()))?
            .trim()
            .to_string()
    } else {
        eprintln!("{prompt}");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        line.trim().to_string()
    };
    Ok(<Mnemonic<English>>::from_phrase(&phrase)?)
}

/// Resolve the [`WalletEntry`] for `wallet`: the configured `[wallets.<name>]` entry, or the
/// default layout (`<datadir>/zec/<name>`, global pool settings) for a wallet the config doesn't
/// name - exactly the entry the daemon would build for it.
pub(crate) fn resolve_wallet_entry(config: &AppConfig, wallet: &str) -> WalletEntry {
    config
        .wallets
        .get(wallet)
        .cloned()
        .unwrap_or_else(|| WalletEntry {
            dir: crate::config::wallet_dir(&config.datadir, wallet),
            keys_file: None,
            coin: crate::coin::Coin::Zcash,
            chain: crate::coin::Coin::Zcash.chain(config.network),
            backend: Default::default(),
            pools: config.pools.enabled.clone(),
            default_receivers: config.pools.default_receivers.clone(),
            transparent_enabled: config.pools.transparent_enabled,
            transparent_default: config.pools.transparent_default,
            transparent_gap_limit: config.pools.transparent_gap_limit,
            transparent_initial_scan: config.pools.transparent_initial_scan,
            transparent_allow_beyond_recovery_window: config
                .pools
                .transparent_allow_beyond_recovery_window,
            transparent_gap_warn_threshold: config.pools.transparent_gap_warn_threshold,
            fresh_wallet_birthday_margin: config
                .keys
                .fresh_wallet_birthday_margin
                .unwrap_or(FRESH_WALLET_BIRTHDAY_MARGIN),
        })
}

/// The restore phrase for [`init_wallet`], with any interactive input deferred behind a
/// callback: the CLI reads the phrase from stdin only *after* the upstream connect and tip
/// fetch (that ordering is observable - a dead upstream fails before the prompt), so a caller
/// that wants the same behavior supplies `Deferred` and one with the phrase in hand supplies
/// `Phrase`. The same pattern as [`rescan_wallet`]'s `confirm` callback.
pub enum MnemonicInput {
    Phrase(Mnemonic<English>),
    Deferred(Box<dyn FnOnce() -> anyhow::Result<Mnemonic<English>> + Send>),
}

impl MnemonicInput {
    fn resolve(self) -> anyhow::Result<Mnemonic<English>> {
        match self {
            MnemonicInput::Phrase(m) => Ok(m),
            MnemonicInput::Deferred(f) => f(),
        }
    }
}

/// How a seed wallet's mnemonic is protected at rest (ignored for a watch-only init, which has
/// no at-rest secret). The passphrase variants mirror [`MnemonicInput`]: the CLI prompts for
/// the passphrase after the wallet database checks and before any network I/O, so `Deferred`
/// preserves that ordering; a programmatic `Passphrase` is used as given (the caller owns its
/// strength - the CLI's prompt path enforces [`MIN_PASSPHRASE_CHARS`]).
pub enum EncryptionInput {
    /// Wrap to the age identity file for unattended unlock (created if missing).
    AgeIdentity,
    Passphrase(Passphrase),
    DeferredPassphrase(Box<dyn FnOnce() -> anyhow::Result<Passphrase> + Send>),
}

/// How the new wallet gets its key material.
pub enum InitKey {
    /// A fresh 24-word mnemonic; the [`InitOutcome`] carries it for the operator to record.
    Generate,
    /// Recover an existing seed wallet; the recovery window extends to the current tip.
    Restore(MnemonicInput),
    /// A watch-only wallet from this encoded Unified Full Viewing Key.
    WatchOnly(String),
}

/// What to create - the library-facing form of the `zecd init` flags.
pub struct InitOptions {
    pub wallet: String,
    pub key: InitKey,
    pub encryption: EncryptionInput,
    /// Birthday, as a height or a UTC date ([`Birthday`]); defaults to near-tip for a fresh
    /// wallet and to the earliest enabled pool's activation for a restore/import (safe but
    /// slow - see the CLI's warning). A date is resolved to a height here and never
    /// persisted as a date; refused on regtest, whose block timestamps mean nothing.
    pub birthday: Option<Birthday>,
}

/// What [`init_wallet`] created - everything the CLI prints, as data.
pub struct InitOutcome {
    pub wallet: String,
    pub wallet_dir: PathBuf,
    pub keys_path: PathBuf,
    pub network: ZNetwork,
    /// The account birthday actually recorded (derived from the anchoring tree state).
    pub birthday: u32,
    pub watch_only: bool,
    /// True when the wallet is passphrase-encrypted (starts locked).
    pub encrypted: bool,
    /// The age identity file protecting the seed, when [`EncryptionInput::AgeIdentity`] was
    /// used (created if it did not exist).
    pub identity_path: Option<PathBuf>,
    /// The freshly generated mnemonic, present only for [`InitKey::Generate`] - the phrase the
    /// operator must record. NB `bip0039::Mnemonic` does not zeroize on drop (the CLI prints
    /// this to stdout, the same exposure); drop it promptly. The derived seed inside
    /// [`init_wallet`] is a zeroize-on-drop `SecretVec` throughout.
    pub generated_mnemonic: Option<Mnemonic<English>>,
}

#[cfg(feature = "cli")]
pub async fn run(config: &AppConfig, args: &InitArgs) -> anyhow::Result<()> {
    // Map the flags onto the library options. The interactive inputs stay shell-side, behind
    // the deferred callbacks, so their prompts fire at the same points they always have.
    let key = if let Some(encoded) = &args.ufvk {
        InitKey::WatchOnly(encoded.clone())
    } else if args.restore {
        let file = args.mnemonic_file.clone();
        InitKey::Restore(MnemonicInput::Deferred(Box::new(move || {
            read_mnemonic_phrase(
                file.as_deref(),
                "Enter the mnemonic phrase to restore, then press Enter:",
            )
        })))
    } else {
        InitKey::Generate
    };
    let encryption = if args.encrypt {
        EncryptionInput::DeferredPassphrase(Box::new(read_encryption_passphrase))
    } else {
        EncryptionInput::AgeIdentity
    };

    let outcome = init_wallet(
        config,
        InitOptions {
            wallet: args.wallet.clone(),
            key,
            encryption,
            birthday: args.birthday,
        },
    )
    .await?;

    eprintln!(
        "Wallet '{}' initialized at {}",
        outcome.wallet,
        outcome.wallet_dir.display()
    );
    // A date input resolved to a height the operator never typed; show them the number
    // that was actually recorded.
    if matches!(args.birthday, Some(Birthday::Date(_))) {
        eprintln!("birthday height: {}", outcome.birthday);
    }
    if outcome.watch_only {
        eprintln!(
            "Watch-only wallet (imported UFVK): balances, history, and addresses are \
             available; spending and wallet-encryption RPCs are disabled."
        );
    } else if outcome.encrypted {
        eprintln!(
            "Wallet is passphrase-encrypted; it starts locked. Call walletpassphrase \"<pass>\" <timeout> to unlock for sending."
        );
    } else if let Some(identity_path) = &outcome.identity_path {
        eprintln!("age identity: {}", identity_path.display());
    }
    if let Some(mnemonic) = &outcome.generated_mnemonic {
        eprintln!("\nIMPORTANT - record this mnemonic seed phrase and keep it safe:\n");
        println!("{}", mnemonic.phrase());
        eprintln!();
    }
    Ok(())
}

/// The library core of `zecd init`: create (or restore/import) a wallet and its account,
/// returning what was created instead of printing it. No stdout/stderr; the only interactive
/// I/O possible is whatever the caller put behind the `Deferred` inputs. Everything else is
/// unchanged from the CLI: the datadir lock is taken for the duration, a live upstream is
/// dialed once (the account anchors on the tree state at `birthday - 1`), and every refusal
/// fires before anything is written.
pub async fn init_wallet(config: &AppConfig, opts: InitOptions) -> anyhow::Result<InitOutcome> {
    let InitOptions {
        wallet,
        key,
        encryption,
        birthday: birthday_opt,
    } = opts;
    // Single-instance guard: take the exclusive datadir lock before creating any wallet, held
    // until `init` returns. This refuses an `init` against a datadir a running daemon (or another
    // `init`) already owns, rather than racing it. See `crate::lock`.
    let _datadir_lock = crate::lock::lock_datadir(&config.datadir)?;
    // Under the same lock, move any wallet still in the pre-`zec/` layout into the per-coin
    // subdirectory - so an `init` run against an un-migrated data directory sees the wallets
    // that are already there (and refuses to create one over the top of an existing wallet)
    // rather than starting a second one beside them. See `crate::migrate`.
    crate::migrate::migrate(config)?;

    let entry = resolve_wallet_entry(config, &wallet);
    // A Bitcoin wallet takes the BDK engine's init path. Branch before any read that assumes
    // a Zcash entry; the datadir lock and migration above cover both engines. Like the Zcash
    // path, it dials its upstream (bitcoind) once - but only to anchor a freshly generated
    // wallet's birthday just below the tip; a restore (SegWit-activation floor) or an
    // explicit --birthday initializes fully offline.
    #[cfg(feature = "bitcoin")]
    if entry.coin == crate::coin::Coin::Bitcoin {
        return init_bitcoin_wallet(config, entry, wallet, key, encryption, birthday_opt).await;
    }
    let keys_path = entry.keys_path();
    let enabled_pools = entry.pools.clone();
    let birthday_margin = entry.fresh_wallet_birthday_margin;
    // Create the account under the wallet's external transparent gap limit (only when transparent
    // is enabled), so init pre-generates the same receiving-address window the daemon scans.
    let init_gap_limit = entry
        .transparent_enabled
        .then_some(entry.transparent_gap_limit);
    let network = entry.zcash_network();
    // `keys.toml` lives at the wallet root; everything librustzcash owns lives one coin and one
    // engine deeper (see `crate::migrate`).
    let engine_dir = entry.engine_dir();
    let wallet_dir = entry.dir;

    if WalletStore::exists(&keys_path) {
        return Err(anyhow!(
            "wallet '{}' is already initialized ({} exists)",
            wallet,
            keys_path.display()
        ));
    }

    // Watch-only init: parse the UFVK up front (before any directory or network I/O) so a
    // malformed key fails fast (`--ufvk` conflicts with `--restore`/`--encrypt` at the clap
    // level; the enum makes the same shapes unrepresentable here). A `Some` UFVK means this is
    // a watch-only wallet; `None` means it will hold spending keys.
    let (ufvk, restore_input) = match key {
        InitKey::WatchOnly(encoded) => (
            Some(
                UnifiedFullViewingKey::decode(&network, encoded.trim())
                    .map_err(|e| anyhow!("invalid unified full viewing key: {e}"))?,
            ),
            None,
        ),
        InitKey::Restore(input) => (None, Some(input)),
        InitKey::Generate => (None, None),
    };
    let restore = restore_input.is_some();

    // zecd permits at most one spending wallet (any number of watch-only UFVK wallets may be
    // added alongside it). When creating a spending wallet, refuse up front if another
    // configured wallet already holds spending keys - the same invariant the daemon enforces at
    // startup, surfaced here so the operator finds out at `init` time rather than at the next
    // boot. Watch-only inits (`--ufvk`) are exempt: any number are allowed. Done before any
    // directory or network I/O so it fails fast and leaves nothing behind.
    // The opt-in ([keys] allow_multiple_spending_wallets, honored only by an embedded node)
    // skips the guard: refusing to *create* the second wallet would make the option
    // unreachable, since there would be no way to get into the shape it permits.
    if ufvk.is_none() && !config.keys.allow_multiple_spending_wallets {
        if let Some(existing) = existing_spending_wallet(network, &config.wallets, &wallet) {
            return Err(anyhow!(
                "cannot create spending wallet '{}': wallet '{}' already holds spending keys, \
                 and zecd allows at most one spending wallet (any number of watch-only \
                 UFVK wallets may be added alongside it). Create this wallet watch-only with \
                 `--ufvk` (see `zecd export-ufvk`), or remove/convert the existing spending \
                 wallet.",
                wallet,
                existing
            ));
        }
    }

    std::fs::create_dir_all(&wallet_dir)?;

    // Open (and migrate) the wallet database up front and refuse to initialize into one that
    // already holds an account. Without this, a pre-existing (planted or leftover) database
    // would gain the operator's account *alongside* its own, and the daemon selects the first
    // account, so receive addresses could derive from a key that is not the operator's. Done
    // before any interactive or network I/O so a refusal is fast and leaves no keys.toml
    // behind.
    let mut db = open::init_dbs_with_gap_limit(network, &engine_dir, init_gap_limit)?;
    ensure_no_preexisting_account(&db, &wallet, &engine_dir)?;

    let identity_path = config
        .keys
        .age_identity
        .clone()
        .unwrap_or_else(|| config.datadir.join("identity.txt"));
    // How the mnemonic is protected at rest. All settled *before* any network I/O so a bad
    // passphrase / missing identity fails fast:
    // - view-only (imported UFVK): no mnemonic at all, so there is no at-rest secret;
    // - encrypt: wrap with a passphrase (age scrypt) - starts locked, `walletpassphrase`;
    // - default: wrap to the age identity file for unattended unlock.
    enum AtRest {
        ViewOnly,
        Passphrase(Passphrase),
        Identity(Vec<Box<dyn age::Recipient + Send>>),
    }
    let at_rest = if ufvk.is_some() {
        AtRest::ViewOnly
    } else {
        match encryption {
            EncryptionInput::Passphrase(passphrase) => AtRest::Passphrase(passphrase),
            EncryptionInput::DeferredPassphrase(read) => AtRest::Passphrase(read()?),
            EncryptionInput::AgeIdentity => {
                AtRest::Identity(ensure_identity(&identity_path).await?)
            }
        }
    };

    // init is a one-shot interactive command that dials the configured upstream once.
    let mut server = backend::resolve(&config.backend.server, network)?;
    backend::apply_zebra_auth(&mut server, &config.zebra.auth());
    backend::apply_cleartext_policy(
        &mut server,
        crate::chain::zebra::CleartextPolicy {
            rfc1918_is_local: config.backend.rfc1918_is_local,
            allow_remote_cleartext: config.backend.allow_remote_cleartext,
        },
    );
    backend::apply_tls(&mut server, config.backend.tls_options());
    backend::apply_transparent_capability_override(
        &mut server,
        config.backend.assume_transparent_in_compact_blocks,
    );
    let mut client = server
        .connect_timeout(Duration::from_secs(config.backend.connect_timeout_secs))
        .await
        .with_context(|| format!("connecting to {}", server.describe()))?;

    let chain_tip: u32 = client
        .latest_block()
        .await?
        .height
        .try_into()
        .map_err(|_| anyhow!("chain tip height does not fit into u32"))?;

    let (mnemonic, recover_until) = if ufvk.is_some() {
        // A watch-only wallet has no mnemonic; the imported key may have history, so treat
        // it like a restore (recovery window up to the current tip).
        (None, Some(BlockHeight::from(chain_tip)))
    } else if let Some(input) = restore_input {
        (Some(input.resolve()?), Some(BlockHeight::from(chain_tip)))
    } else {
        (Some(Mnemonic::generate(Count::Words24)), None)
    };

    // A freshly-generated wallet can have no history, so its birthday defaults to just below
    // the tip. A *restored* wallet (or an imported viewing key) may hold notes from any point
    // in its past; defaulting anywhere near the tip would silently skip them (the funds exist
    // on chain but are never scanned), so without --birthday we scan from the earliest enabled
    // pool's activation (Orchard/NU5 for the Orchard-only default) - never missing a note, at
    // the cost of a long initial sync we warn about.
    let key_may_have_history = restore || ufvk.is_some();
    let birthday_height = BlockHeight::from(match birthday_opt {
        Some(Birthday::Height(height)) => height,
        Some(Birthday::Date(date)) => {
            if network.is_regtest() {
                bail!(
                    "--birthday takes a date only on public networks: regtest block \
                     timestamps are not meaningful. Pass --birthday <height> instead."
                );
            }
            let height = zcash_height_for_date(&mut client, chain_tip, date).await?;
            tracing::info!(
                "resolved the --birthday date to height {height} (~1 day before the \
                 date's midnight UTC, so the wallet cannot miss funds)"
            );
            height
        }
        None if key_may_have_history => {
            let (height, label) = restore_birthday_default(network, &enabled_pools);
            warn!(
                "no --birthday given; scanning from {label} activation (height {height}) - a \
                 full rescan that is slow on mainnet. Pass --birthday <height> at or before the \
                 wallet's first transaction to speed up the initial sync."
            );
            height
        }
        None => fresh_wallet_birthday(chain_tip, birthday_margin),
    });
    // Anchors on the tree state of the block before the birthday (which leaks the birthday to
    // the server). Shared with `chain_probe::account_birthday`, which is how an embedder pins a
    // birthday before the wallet exists - one code path, so the two cannot diverge.
    let birthday =
        crate::chain_probe::account_birthday(&mut client, birthday_height, recover_until).await?;

    // Non-view-only models always have a mnemonic (the `AtRest` variant and `ufvk.is_none()`
    // agree by construction); `expect` documents that invariant.
    let require_mnemonic = || {
        mnemonic
            .as_ref()
            .expect("non-view-only init always has a mnemonic")
    };

    // The BIP-39 seed for a seed wallet (zeroized on drop). Derived once, used both to pin the
    // account's UFVK into keys.toml and to create the account itself.
    let seed = mnemonic.as_ref().map(|m| {
        let mut s = m.to_seed("");
        let secret = SecretVec::new(s.to_vec());
        s.zeroize();
        secret
    });

    // The account UFVK to pin into keys.toml: the imported key for a watch-only wallet, the
    // seed's ZIP-32 index-0 derivation otherwise (the account `create_account` builds on the
    // account-less database guaranteed above). Every startup verifies the database's account
    // against this pin, so a later database swap fails closed (see `wallet::binding`).
    let pinned_ufvk = match (&ufvk, &seed) {
        (Some(ufvk), _) => ufvk.encode(&network),
        (None, Some(seed)) => crate::wallet::binding::seed_ufvk_encoded(
            network,
            seed,
            zip32::AccountId::try_from(0u32).expect("0 is a valid account index"),
        )?,
        (None, None) => unreachable!("init either imports a UFVK or has a mnemonic"),
    };

    match &at_rest {
        AtRest::ViewOnly => {
            WalletStore::init_view_only(&keys_path, birthday.height(), network, &pinned_ufvk)?
        }
        AtRest::Passphrase(passphrase) => WalletStore::init_with_passphrase(
            &keys_path,
            passphrase.clone(),
            require_mnemonic(),
            birthday.height(),
            network,
            &pinned_ufvk,
        )?,
        AtRest::Identity(recipients) => WalletStore::init_with_mnemonic(
            &keys_path,
            recipients.iter().map(|r| r.as_ref() as _),
            require_mnemonic(),
            birthday.height(),
            network,
            &pinned_ufvk,
        )?,
    }

    // zecd surfaces a single account per wallet, so the account label is a fixed constant
    // (the name is stored by librustzcash but zecd never reads it back).
    let account_name = "primary";
    let account_id = match (&ufvk, &seed) {
        (Some(ufvk), _) => db
            .import_account_ufvk(
                account_name,
                ufvk,
                &birthday,
                AccountPurpose::ViewOnly,
                None,
            )?
            .id(),
        (None, Some(seed)) => db.create_account(account_name, seed, &birthday, None)?.0,
        (None, None) => unreachable!("init either imports a UFVK or has a mnemonic"),
    };

    // Cross-check the pin against the account actually created. These agree by construction
    // (same key material, same derivation); if they ever diverge, e.g. a librustzcash bump
    // changes what `create_account` derives, failing here at init is loud and immediate,
    // where a divergence first hitting the startup verifier would brick every fresh wallet
    // one boot later.
    let created_ufvk = crate::wallet::binding::account_ufvk_encoded(network, &db, account_id)?;
    if created_ufvk != pinned_ufvk {
        bail!(
            "internal error: the created account's viewing key does not match the key derived \
             for the keys.toml pin; refusing to leave an inconsistent wallet. Please report \
             this bug."
        );
    }

    Ok(InitOutcome {
        wallet,
        wallet_dir,
        keys_path,
        network,
        birthday: u32::from(birthday.height()),
        watch_only: matches!(at_rest, AtRest::ViewOnly),
        encrypted: matches!(at_rest, AtRest::Passphrase(_)),
        identity_path: matches!(at_rest, AtRest::Identity(_)).then_some(identity_path),
        generated_mnemonic: mnemonic.filter(|_| !restore),
    })
}

/// Resolve a date birthday for a Bitcoin wallet, erring low in both shapes:
///  * a bitcoind upstream answers exactly - binary-search the node's headers for the last
///    block at or before the date minus the one-day margin ([`height_for_time`]); an
///    unreachable node is a clean refusal naming `--birthday <height>` as the offline
///    escape hatch, like the fresh-wallet dial.
///  * kyoto stays offline, as everywhere in `init`: a date at or after the shipped scan
///    floor's own date maps to the floor height, which serves *exactly* as well as the
///    true height (the first scan starts at the floor for any birthday at or above it -
///    see `btc::kyoto`); an earlier date has no offline reference and falls back to the
///    BIP 84 history floor, slow but never wrong.
///
/// Regtest is refused like the Zcash side: its block timestamps mean nothing.
#[cfg(feature = "bitcoin")]
async fn bitcoin_height_for_date(
    config: &AppConfig,
    entry: &crate::config::WalletEntry,
    btc_network: crate::coin::BitcoinNetwork,
    date: u64,
) -> anyhow::Result<u32> {
    if btc_network == crate::coin::BitcoinNetwork::Regtest {
        bail!(
            "--birthday takes a date only on public networks: regtest block timestamps \
             are not meaningful. Pass --birthday <height> instead."
        );
    }
    let endpoint = crate::btc::chain::resolve_for_wallet(config, entry)?;
    let described = endpoint.describe();
    match endpoint {
        crate::btc::chain::BtcEndpoint::Bitcoind(endpoint) => {
            let target = date.saturating_sub(BIRTHDAY_DATE_MARGIN_SECS);
            let height = tokio::task::spawn_blocking(move || -> anyhow::Result<u32> {
                let rpc = endpoint.connect_blocking()?;
                let tip = u32::try_from(rpc.tip_at_connect).unwrap_or(u32::MAX);
                height_for_time(|h| rpc.block_time_blocking(h), tip, target)
            })
            .await
            .context("bitcoind dial task")?
            .with_context(|| {
                format!(
                    "dialing {described} to resolve the --birthday date failed. Start the \
                     node (or point `server`/[bitcoind] at it), or pass --birthday <height> \
                     to initialize offline"
                )
            })?;
            tracing::info!(
                "resolved the --birthday date to height {height} (~1 day before the date's \
                 midnight UTC, so the wallet cannot miss funds)"
            );
            Ok(height)
        }
        crate::btc::chain::BtcEndpoint::Kyoto(_) => {
            match crate::btc::kyoto::birthday_height_for_date(btc_network, date) {
                Some(height) => {
                    tracing::info!(
                        "resolved the --birthday date to height {height}, this build's \
                         shipped scan floor - the height a kyoto first scan starts at for \
                         any birthday above it, so no precision is lost and the resolution \
                         stays offline"
                    );
                    Ok(height)
                }
                None => {
                    let height = bip84_history_floor(btc_network);
                    warn!(
                        "the --birthday date predates this build's shipped scan floor, and \
                         kyoto resolves dates offline against that floor alone; recording \
                         the BIP 84 history floor (height {height}) instead - a full \
                         history scan. Pass --birthday <height> for a faster first sync."
                    );
                    Ok(height)
                }
            }
        }
    }
}

/// The Bitcoin half of [`init_wallet`]: same refusals (already-initialized, one spending
/// wallet per coin), same custody models, no upstream. The engine has no chain source yet,
/// so the recorded birthday is `--birthday` or 0 (scan from genesis when sync lands) rather
/// than a near-tip default, and the wallet database is created here - from the seed, holding
/// only public descriptors - so an encrypted wallet can start without its passphrase.
#[cfg(feature = "bitcoin")]
async fn init_bitcoin_wallet(
    config: &AppConfig,
    entry: crate::config::WalletEntry,
    wallet: String,
    key: InitKey,
    encryption: EncryptionInput,
    birthday_opt: Option<Birthday>,
) -> anyhow::Result<InitOutcome> {
    let keys_path = entry.keys_path();
    let engine_dir = entry.engine_dir();
    let btc_network = entry.bitcoin_network();
    let birthday_margin = entry.fresh_wallet_birthday_margin;
    // `entry` stays whole: the generated-wallet path below resolves the wallet's bitcoind
    // endpoint from it to anchor the birthday.
    let wallet_dir = entry.dir.clone();
    // `keys.toml` speaks the environment vocabulary (`main`/`test`/`regtest`), shared by both
    // coins' networks; the daemon checks it against its own environment at spawn.
    let network = config.network;

    if WalletStore::exists(&keys_path) {
        return Err(anyhow!(
            "wallet '{}' is already initialized ({} exists)",
            wallet,
            keys_path.display()
        ));
    }

    let restore_input = match key {
        InitKey::WatchOnly(_) => {
            return Err(anyhow!(
                "cannot create wallet '{}' with --ufvk: a Unified Full Viewing Key is a Zcash \
                 key, and watch-only Bitcoin wallets (descriptor import) are not supported yet",
                wallet
            ))
        }
        InitKey::Restore(input) => Some(input),
        InitKey::Generate => None,
    };
    let restore = restore_input.is_some();

    // One spending wallet per coin (the same invariant the daemon enforces at startup),
    // surfaced at init time. The library opt-in skips it, as on the Zcash path.
    if !config.keys.allow_multiple_spending_wallets {
        if let Some(existing) = existing_bitcoin_spending_wallet(config, &wallet) {
            return Err(anyhow!(
                "cannot create spending wallet '{}': wallet '{}' already holds spending keys \
                 for bitcoin, and zecd allows at most one spending wallet per coin. Remove or \
                 reconfigure the existing wallet.",
                wallet,
                existing
            ));
        }
    }

    // Resolve the birthday before anything is written, so a failed dial is a clean refusal
    // (the same before-any-write doctrine as the Zcash path, which likewise dials its
    // upstream once at init). Four cases:
    //  * --birthday height: honored verbatim; the init stays fully offline.
    //  * --birthday date: resolved to a height erring low (`bitcoin_height_for_date`) -
    //    exactly via a bitcoind upstream's headers, offline via the shipped scan floor on
    //    kyoto.
    //  * restore: the seed may hold history from any point in its past, so scan everything
    //    it could possibly own - from SegWit activation, the first block a BIP 84 (bech32)
    //    output can exist in. Warned, like the Zcash restore default.
    //  * freshly generated: no history is possible, so anchor just below the node's tip
    //    (`fresh_wallet_birthday`, shared with the Zcash path). The one case that needs the
    //    upstream - and the dial also verifies the node serves the wallet's chain.
    let birthday = match birthday_opt {
        Some(Birthday::Height(height)) => BlockHeight::from(height),
        Some(Birthday::Date(date)) => {
            BlockHeight::from(bitcoin_height_for_date(config, &entry, btc_network, date).await?)
        }
        None if restore => {
            let height = bip84_history_floor(btc_network);
            warn!(
                "no --birthday given; scanning from SegWit activation (height {height}) - a \
                 full history rescan that is slow on mainnet. Pass --birthday <height> at or \
                 before the wallet's first transaction to speed up the initial sync."
            );
            BlockHeight::from(height)
        }
        None => {
            let endpoint = crate::btc::chain::resolve_for_wallet(config, &entry)?;
            let described = endpoint.describe();
            match endpoint {
                crate::btc::chain::BtcEndpoint::Bitcoind(endpoint) => {
                    // The client is blocking (`bitcoincore-rpc`); `spawn_blocking` rather than
                    // the actor's `block_in_place` so a current-thread embedder can call
                    // `init_wallet`.
                    let rpc = tokio::task::spawn_blocking(move || endpoint.connect_blocking())
                        .await
                        .context("bitcoind dial task")?
                        .with_context(|| {
                            format!(
                                "dialing {described} to anchor the new wallet's birthday \
                                 failed. Start the node (or point `server`/[bitcoind] at it), \
                                 or pass --birthday <height> to initialize offline"
                            )
                        })?;
                    let tip = u32::try_from(rpc.tip_at_connect).unwrap_or(u32::MAX);
                    BlockHeight::from(fresh_wallet_birthday(tip, birthday_margin))
                }
                // Kyoto has a `chain_tip()`, but reaching it means starting a P2P node,
                // discovering peers and syncing headers - seconds to minutes on a cold data
                // directory, inside a command that is otherwise instant and fully offline.
                // Rather than hide that behind `init`, refuse and name the flag, the same
                // shape as the unreachable-bitcoind refusal above.
                crate::btc::chain::BtcEndpoint::Kyoto(_) => {
                    anyhow::bail!(
                        "a kyoto wallet cannot anchor its own birthday at init: reading the \
                         chain tip over BIP-157 means starting a P2P node and syncing block \
                         headers first, which `init` will not do behind your back. Pass \
                         --birthday <YYYY-MM-DD> (today's date is the right answer for a \
                         new wallet; resolved offline) or --birthday <height>, or \
                         initialize against a bitcoind `server` and switch this wallet to \
                         kyoto afterwards."
                    );
                }
            }
        }
    };

    std::fs::create_dir_all(&wallet_dir)?;

    let identity_path = config
        .keys
        .age_identity
        .clone()
        .unwrap_or_else(|| config.datadir.join("identity.txt"));
    enum AtRest {
        Passphrase(Passphrase),
        Identity(Vec<Box<dyn age::Recipient + Send>>),
    }
    let at_rest = match encryption {
        EncryptionInput::Passphrase(passphrase) => AtRest::Passphrase(passphrase),
        EncryptionInput::DeferredPassphrase(read) => AtRest::Passphrase(read()?),
        EncryptionInput::AgeIdentity => AtRest::Identity(ensure_identity(&identity_path).await?),
    };

    let mnemonic = match restore_input {
        Some(input) => input.resolve()?,
        None => Mnemonic::generate(Count::Words24),
    };
    let seed = {
        let mut s = mnemonic.to_seed("");
        let secret = SecretVec::new(s.to_vec());
        s.zeroize();
        secret
    };

    // keys.toml first, then the wallet database: a failure between the two is self-healing
    // (the daemon's spawn recreates a missing database from the seed), where the reverse
    // order would leave a database the already-initialized refusal then trips over.
    match &at_rest {
        AtRest::Passphrase(passphrase) => WalletStore::init_with_passphrase_unpinned(
            &keys_path,
            passphrase.clone(),
            &mnemonic,
            birthday,
            network,
        )?,
        AtRest::Identity(recipients) => WalletStore::init_with_mnemonic_unpinned(
            &keys_path,
            recipients.iter().map(|r| r.as_ref() as _),
            &mnemonic,
            birthday,
            network,
        )?,
    }
    crate::btc::store::create_wallet_db(&engine_dir, btc_network, &seed)?;

    Ok(InitOutcome {
        wallet,
        wallet_dir,
        keys_path,
        network,
        birthday: u32::from(birthday),
        watch_only: false,
        encrypted: matches!(at_rest, AtRest::Passphrase(_)),
        identity_path: matches!(at_rest, AtRest::Identity(_)).then_some(identity_path),
        generated_mnemonic: (!restore).then_some(mnemonic),
    })
}

/// The first block a restored Bitcoin wallet's history can exist in: SegWit activation. The
/// engine is bech32-only (BIP 84 is its sole derivation), and a P2WPKH output cannot appear
/// in a block before SegWit activated, so a restore that scans from here provably misses
/// nothing - the Bitcoin analog of [`restore_birthday_default`]'s earliest-enabled-pool
/// floor. Testnet4 and regtest deploy SegWit from the start.
#[cfg(feature = "bitcoin")]
fn bip84_history_floor(network: crate::coin::BitcoinNetwork) -> u32 {
    use crate::coin::BitcoinNetwork;
    match network {
        BitcoinNetwork::Main => 481_824,
        BitcoinNetwork::Testnet3 => 834_624,
        BitcoinNetwork::Testnet4 | BitcoinNetwork::Regtest => 0,
    }
}

/// The Bitcoin counterpart of [`existing_spending_wallet`]: another *configured* Bitcoin
/// wallet already holding a seed. Read from `keys.toml` rather than a wallet database - the
/// BDK database holds only public descriptors, so the seed's presence in the store is the
/// spending signal.
#[cfg(feature = "bitcoin")]
fn existing_bitcoin_spending_wallet(config: &AppConfig, exclude: &str) -> Option<String> {
    config
        .wallets
        .iter()
        .filter(|(name, entry)| {
            name.as_str() != exclude && entry.coin == crate::coin::Coin::Bitcoin
        })
        .find(|(_, entry)| {
            let keys_path = entry.keys_path();
            WalletStore::exists(&keys_path)
                && WalletStore::read(&keys_path).is_ok_and(|store| store.has_seed())
        })
        .map(|(name, _)| name.clone())
}

/// `zecd export-ufvk`: print the wallet's Unified Full Viewing Key to stdout, for setting up
/// a watch-only zecd elsewhere (`init --ufvk`). The UFVK is read from the wallet DB (where it
/// is stored for scanning anyway), so this works for locked and passphrase-encrypted wallets
/// alike and never touches spending material. Offline: no upstream connection is made.
#[cfg(feature = "cli")]
pub fn export_ufvk(config: &AppConfig, args: &ExportUfvkArgs) -> anyhow::Result<()> {
    let encoded = export_ufvk_string(config, &args.wallet)?;
    eprintln!(
        "Unified Full Viewing Key for wallet '{}' (grants full VIEW access - balances and \
         all transaction history - but cannot spend):",
        args.wallet
    );
    println!("{encoded}");
    Ok(())
}

/// The encoded UFVK behind [`export_ufvk`] - the library core, which reads the wallet DB and
/// prints nothing. Works for locked and passphrase-encrypted wallets alike (the UFVK is stored
/// for scanning anyway) and never touches spending material.
pub fn export_ufvk_string(config: &AppConfig, wallet: &str) -> anyhow::Result<String> {
    let entry = resolve_wallet_entry(config, wallet);
    #[cfg(feature = "bitcoin")]
    if entry.coin == crate::coin::Coin::Bitcoin {
        return Err(anyhow!(
            "wallet '{}' is a Bitcoin wallet; a Unified Full Viewing Key is a Zcash key and \
             descriptor export is not supported yet",
            wallet
        ));
    }
    let keys_path = entry.keys_path();
    let network = entry.zcash_network();
    // Read-only and lock-free (it must run beside a live daemon), so it cannot migrate the
    // layout - but it still reads a wallet database the daemon has not migrated yet.
    let engine_dir = crate::migrate::engine_dir_for_reading(&entry);

    if !WalletStore::exists(&keys_path) {
        return Err(anyhow!(
            "wallet '{}' is not initialized ({} missing)",
            wallet,
            keys_path.display()
        ));
    }
    // The UFVK encoding is network-scoped; refuse a network flag that contradicts the wallet
    // on disk rather than emit a key the watch-only side would reject.
    let st = WalletStore::read(&keys_path)?;
    ensure_store_matches(&st, wallet, network)?;

    let db = open::open_read(network, &engine_dir)?;
    let account_id = *db
        .get_account_ids()?
        .first()
        .ok_or_else(|| anyhow!("wallet has no accounts; run `init` first"))?;
    let account = db
        .get_account(account_id)?
        .ok_or_else(|| anyhow!("selected account not found"))?;
    let ufvk = account
        .ufvk()
        .ok_or_else(|| anyhow!("account has no unified full viewing key"))?;
    Ok(ufvk.encode(&network))
}

/// `zecd rescan`: the recovery path for a broken wallet database - e.g. a persistent
/// `PutBlocksCommitmentTree`/shardtree-conflict sync error that repeats at the same block range
/// across restarts and version upgrades (the daemon's sync-error log points here when it
/// detects that pattern). Deletes the wallet's *database* files while **keeping** `keys.toml`
/// (seed, network, birthday, UFVK pin), so the next daemon start takes the existing
/// empty-data-directory bootstrap path: it recreates the account from the seed and rescans the
/// chain from the wallet birthday, re-deriving all funds and history. This is safe by zecd's
/// statelessness invariant - everything in the database is rebuildable from seed + chain.
#[cfg(feature = "cli")]
pub fn rescan(config: &AppConfig, args: &RescanArgs) -> anyhow::Result<()> {
    // Same single-instance guard as `init`: refuses while the daemon (or another writer) owns
    // the datadir, so the database can't be deleted out from under a live wallet. Taken here
    // rather than inside `rescan_wallet` (which is why it is passed `None` below) because the
    // layout migration must run under this same lock, before the rescan decides what to delete.
    let _datadir_lock = crate::lock::lock_datadir(&config.datadir)?;
    // As in `init`: migrate the layout under the lock, so a rescan run before the first daemon
    // start of this build deletes the database that is actually in use. See `crate::migrate`.
    crate::migrate::migrate(config)?;

    let entry = resolve_wallet_entry(config, &args.wallet);
    #[cfg(feature = "bitcoin")]
    if entry.coin == crate::coin::Coin::Bitcoin {
        anyhow::bail!(
            "wallet '{}' is a Bitcoin wallet; `zecd rescan` is not supported for the BDK \
             engine yet (delete {} to rebuild from seed on next start)",
            args.wallet,
            crate::btc::store::wallet_db_path(&entry.engine_dir()).display()
        );
    }
    let removed = rescan_wallet(
        entry.zcash_network(),
        &args.wallet,
        // The lock (and the migration under it) are this wrapper's, taken above.
        None,
        &entry.keys_path(),
        &entry.engine_dir(),
        |st| {
            if args.yes {
                return Ok(true);
            }
            eprintln!(
                "This deletes the wallet database for '{}' at {} (keys.toml and the seed are \
                 kept).\nOn the next start zecd rebuilds the account from the seed and rescans \
                 from the wallet birthday ({}), which re-derives all funds and history but can \
                 take a while.\nType 'yes' to continue:",
                args.wallet,
                entry.dir.display(),
                u32::from(st.birthday)
            );
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            Ok(line.trim() == "yes")
        },
    )?;

    if removed.is_empty() {
        eprintln!(
            "Wallet '{}' has no database files at {}; nothing to delete. The next daemon start \
             will build it fresh from keys.toml.",
            args.wallet,
            entry.dir.display()
        );
    } else {
        eprintln!(
            "Wallet '{}' database removed ({}).",
            args.wallet,
            removed.join(", ")
        );
    }
    let st = WalletStore::read(&entry.keys_path())?;
    eprintln!(
        "Start zecd and it will rebuild the account from keys.toml and rescan from birthday {} \
         (requires [keys] bootstrap_from_keys, which is on by default).{}",
        u32::from(st.birthday),
        if st.is_encrypted() {
            "\nThis wallet is passphrase-encrypted: the rebuild starts at the first \
             `walletpassphrase` after the daemon is up."
        } else {
            ""
        }
    );
    Ok(())
}

/// The checks + deletion behind [`rescan`] - the library core, also unit-testable without an
/// [`AppConfig`] or stdin. `confirm` is consulted (with the parsed `keys.toml`) after
/// validation and before anything is deleted; returning `false` aborts cleanly.
///
/// `datadir` decides who owns the exclusive datadir lock. `Some(path)` takes it here for the
/// duration of the call, which is what a caller invoking this core directly wants: this
/// deletes a live wallet's database, and doing that under a running daemon would pull it out
/// from under that daemon's actor mid-write. `None` says the caller already holds the lock and
/// this must not try again (a second acquisition from the same process would block on the
/// caller's own guard); [`rescan`] passes `None` because it has to run the data-directory
/// layout migration under that same lock before this decides what to delete.
///
/// Refusals, in order: an uninitialized wallet (no `keys.toml` - deleting the database would
/// destroy the only record of the wallet), a network mismatch (the rebuilt scan would run on
/// the wrong chain), and a wallet with no key material to rebuild from at all. Returns the
/// database files/directories actually removed. Idempotent: an already-wiped wallet succeeds
/// with an empty list.
///
/// A **watch-only wallet is rescannable**: `keys.toml` pins the account's UFVK beside the
/// birthday - exactly what `init --ufvk` was given - so the next start re-runs
/// `import_account_ufvk` with them, just as a seed wallet's start re-runs `create_account`.
/// The only wallet that cannot be rebuilt is a watch-only `keys.toml` written before the pin
/// existed and never opened by a daemon since (a start backfills it trust-on-first-use); there
/// the recovery is still a fresh `init --ufvk`.
pub fn rescan_wallet(
    network: ZNetwork,
    wallet: &str,
    datadir: Option<&Path>,
    keys_path: &Path,
    engine_dir: &Path,
    confirm: impl FnOnce(&WalletStore) -> anyhow::Result<bool>,
) -> anyhow::Result<Vec<String>> {
    // This deletes a live wallet's database, so it must not run while a daemon owns the data
    // directory. `Some(datadir)` takes the exclusive lock here and holds it for the call - the
    // right choice for an embedder calling this core directly, which otherwise gets no
    // protection at all. `None` says the caller already holds the lock and this must not try
    // again (a second acquisition from the same process would block on the caller's own guard);
    // the CLI passes `None` because it has to run the data-directory layout migration under
    // that same lock *before* this decides what to delete.
    let _datadir_lock = datadir.map(crate::lock::lock_datadir).transpose()?;
    if !WalletStore::exists(keys_path) {
        return Err(anyhow!(
            "wallet '{}' is not initialized ({} missing); there is no database to rebuild - \
             run `zecd init` to create a wallet",
            wallet,
            keys_path.display()
        ));
    }
    let st = WalletStore::read(keys_path)?;
    ensure_store_matches(&st, wallet, network)?;
    // A rescan is only safe if the next daemon start can rebuild the account from `keys.toml`
    // alone. A spending wallet has its seed there; a watch-only wallet has the pinned UFVK and
    // the birthday, which is exactly what `init --ufvk` was given, so the bootstrap re-runs
    // `import_account_ufvk` with them. The one case that genuinely cannot be rebuilt is a
    // watch-only `keys.toml` written before the pin existed and never opened by a daemon since
    // (a start backfills the pin trust-on-first-use), which has no key material at all.
    if !st.has_seed() && st.pinned_ufvk().is_none() {
        return Err(anyhow!(
            "wallet '{}' is watch-only and its keys.toml holds no pinned viewing key (it \
             predates the pin), so nothing on disk can rebuild its account. Delete the wallet \
             directory and recreate it with `zecd init --wallet {} --ufvk <key> --birthday \
             <height>` (export the key from the spending wallet with `zecd export-ufvk`) \
             instead.",
            wallet,
            wallet
        ));
    }
    if !confirm(&st)? {
        return Err(anyhow!("rescan aborted (expected 'yes')"));
    }

    // Everything in the engine directory - the wallet database and the compact-block cache,
    // which `open::init_dbs` recreates on the next start. The list is
    // [`crate::migrate::ENGINE_ARTIFACTS`] rather than a second copy of it, so "what
    // librustzcash owns" cannot mean one thing to the migration and another to a rescan.
    // `keys.toml` sits at the wallet root, above this directory (and may be outside it
    // entirely via `keys_file`), so neither it nor the datadir-level `identity.txt` is touched.
    let mut removed = Vec::new();
    for artifact in crate::migrate::ENGINE_ARTIFACTS {
        let path = engine_dir.join(artifact);
        let result = if path.is_dir() {
            std::fs::remove_dir_all(&path).map(|()| format!("{artifact}/"))
        } else {
            std::fs::remove_file(&path).map(|()| artifact.to_string())
        };
        match result {
            Ok(name) => removed.push(name),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(anyhow!("removing {}: {e}", path.display())),
        }
    }
    Ok(removed)
}

/// Refuse to initialize into a wallet database that already contains an account. `init` only
/// ever creates the account of a *fresh* database; a database that has one already was planted,
/// left over from a different wallet, or otherwise unexpected, and silently adding the
/// operator's account beside it would let the daemon later serve the pre-existing (first)
/// account's addresses. Fail loud and let the operator decide.
fn ensure_no_preexisting_account(
    db: &open::WriteDb,
    wallet: &str,
    engine_dir: &Path,
) -> anyhow::Result<()> {
    let accounts = db.get_account_ids()?.len();
    if accounts == 0 {
        return Ok(());
    }
    Err(anyhow!(
        "wallet '{}' has no keys.toml, but its database at {} already contains {} account(s). \
         Refusing to initialize into an unexpected pre-existing database: it may belong to a \
         different wallet, and the daemon would serve its first account's addresses. Move the \
         existing data directory aside (or delete it, if it is not yours) and re-run `zecd \
         init`.",
        wallet,
        open::data_db_path(engine_dir).display(),
        accounts
    ))
}

/// Refuse a `keys.toml` that belongs to a different network than the configuration selects,
/// rather than acting on it.
fn ensure_store_matches(
    store: &WalletStore,
    wallet: &str,
    network: ZNetwork,
) -> anyhow::Result<()> {
    if store.network != network {
        return Err(anyhow!(
            "wallet '{}' is a {} wallet, but the configuration selects {}",
            wallet,
            store.network.name(),
            network.name()
        ));
    }
    Ok(())
}

/// Scan the configured `wallets` (other than `exclude`) for one that is already initialized and
/// holds spending keys, returning its name. Used by the `init` guard so a second spending
/// wallet is refused before any work is done. The scope is `config.wallets` - exactly the set
/// the daemon would load - so the two guards agree.
fn existing_spending_wallet(
    network: crate::network::ZNetwork,
    wallets: &std::collections::BTreeMap<String, WalletEntry>,
    exclude: &str,
) -> Option<String> {
    wallets
        .iter()
        .filter(|(name, _)| name.as_str() != exclude)
        .filter(|(_, entry)| WalletStore::exists(&entry.keys_path()))
        .find(|(_, entry)| wallet_has_spending_keys(network, &entry.engine_dir()))
        .map(|(name, _)| name.clone())
}

/// Whether an initialized wallet at `engine_dir` holds spending keys (i.e. its account is not a
/// watch-only UFVK import - the same `AccountSource::Imported { ViewOnly }` test the actor uses
/// for `watch_only`). Best-effort: a wallet whose DB can't be read or has no account is treated
/// as non-spending, so a single unreadable sibling never blocks `init` - the daemon's startup
/// guard is the backstop.
fn wallet_has_spending_keys(network: crate::network::ZNetwork, engine_dir: &Path) -> bool {
    let Ok(db) = open::open_read(network, engine_dir) else {
        return false;
    };
    let Ok(ids) = db.get_account_ids() else {
        return false;
    };
    let Some(id) = ids.first().copied() else {
        return false;
    };
    match db.get_account(id) {
        Ok(Some(account)) => !matches!(
            account.source(),
            AccountSource::Imported {
                purpose: AccountPurpose::ViewOnly,
                ..
            }
        ),
        _ => false,
    }
}

async fn ensure_identity(path: &Path) -> anyhow::Result<Vec<Box<dyn age::Recipient + Send>>> {
    if tokio::fs::try_exists(path).await.unwrap_or(false) {
        // Re-use of an existing identity: refuse it if its permissions have since been widened
        // (the file is created 0600, but nothing prevents a later chmod) - mirrors the load-time
        // check on the daemon's auto-unlock path so init can't silently bless an exposed key.
        keys::check_identity_file_permissions(path)?;
        let recipients =
            age::IdentityFile::from_file(path.to_string_lossy().into_owned())?.to_recipients()?;
        return Ok(recipients);
    }

    eprintln!(
        "Generating a new age identity to encrypt the mnemonic at {}",
        path.display()
    );
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    // Create the identity file with mode 0600 set atomically at open time, rather than
    // creating under the umask and chmod-ing afterwards: the age secret key must never be
    // briefly world-readable between create and set_permissions. `create_new` preserves the
    // refusal to clobber an existing identity. Mirrors the cookie writer in `server::auth`.
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        // tokio's OpenOptions exposes `mode` as an inherent method (no trait import needed).
        opts.mode(0o600);
    }
    let mut f = opts.open(path).await?;
    f.write_all(b"# zecd age identity (KEEP SECRET)\n").await?;
    f.write_all(format!("# public key: {recipient}\n").as_bytes())
        .await?;
    f.write_all(format!("{}\n", identity.to_string().expose_secret()).as_bytes())
        .await?;
    f.flush().await?;

    Ok(vec![Box::new(recipient)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_client_backend::data_api::AccountBirthday;

    /// The whole offline Bitcoin init: no upstream is dialed, `keys.toml` and the wallet
    /// database land on disk, the database holds exactly what the seed derives (checked by
    /// re-loading it against seed-derived descriptors), re-init is refused, and the
    /// one-spender-per-coin guard fires for a second configured Bitcoin wallet.
    #[cfg(all(feature = "bitcoin", feature = "cli"))]
    #[tokio::test(flavor = "multi_thread")]
    async fn init_creates_a_bitcoin_wallet_offline() {
        use crate::btc::keys::tests::BIP84_MNEMONIC;
        use clap::Parser as _;

        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("zecd.toml");
        std::fs::write(
            &conf,
            format!(
                "network = \"test\"\ndatadir = {:?}\n\
                 [wallets.btc]\ncoin = \"bitcoin\"\n\
                 [wallets.btc2]\ncoin = \"bitcoin\"\n",
                dir.path()
            ),
        )
        .unwrap();
        let cli = crate::config::Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let config = AppConfig::resolve(&cli).unwrap();

        let phrase = <Mnemonic<English>>::from_phrase(BIP84_MNEMONIC).unwrap();
        let outcome = init_wallet(
            &config,
            InitOptions {
                wallet: "btc".to_string(),
                key: InitKey::Restore(MnemonicInput::Phrase(phrase)),
                encryption: EncryptionInput::AgeIdentity,
                birthday: None,
            },
        )
        .await
        .unwrap();
        assert!(!outcome.watch_only);
        assert!(!outcome.encrypted);
        // The restore default: the SegWit-activation floor for testnet3 (`network = "test"`)
        // - the first block a BIP 84 output can exist in, so nothing is missed.
        assert_eq!(outcome.birthday, 834_624);
        assert!(
            outcome.generated_mnemonic.is_none(),
            "restore, not generate"
        );
        assert!(WalletStore::exists(&outcome.keys_path));
        let entry = &config.wallets["btc"];
        assert!(crate::btc::store::wallet_db_path(&entry.engine_dir()).exists());

        // The database binds to the seed: spawning with the same seed succeeds (descriptor
        // verification against what keys.toml decrypts to), which is the daemon's load path.
        let store = WalletStore::read(&outcome.keys_path).unwrap();
        assert!(store.has_seed());
        assert!(!store.is_encrypted());
        let identity = outcome.identity_path.as_ref().expect("identity custody");
        let seed = crate::wallet::keys::decrypt_seed_with_identity(&store, identity)
            .unwrap()
            .expect("seed decrypts");
        let (handle, _task) = crate::btc::actor::spawn(crate::btc::actor::BtcActorConfig {
            name: "btc".to_string(),
            engine_dir: entry.engine_dir(),
            network: entry.bitcoin_network(),
            seed: Some(seed),
            wallet_holds_seed: true,
            endpoint: None,
            birthday: 0,
            sync_interval: std::time::Duration::from_secs(20),
            reconnect_base: std::time::Duration::from_secs(1),
            reconnect_max: std::time::Duration::from_secs(60),
            shutdown: tokio::sync::watch::channel(false).1,
        })
        .unwrap();
        let address = handle.new_address().await.unwrap();
        assert!(address.starts_with("tb1"), "testnet bech32, got {address}");

        // Re-init refused.
        let again = init_wallet(
            &config,
            InitOptions {
                wallet: "btc".to_string(),
                key: InitKey::Generate,
                encryption: EncryptionInput::AgeIdentity,
                birthday: None,
            },
        )
        .await
        .err()
        .expect("re-init must be refused");
        assert!(again.to_string().contains("already initialized"), "{again}");

        // A second Bitcoin spending wallet trips the per-coin guard.
        let second = init_wallet(
            &config,
            InitOptions {
                wallet: "btc2".to_string(),
                key: InitKey::Generate,
                encryption: EncryptionInput::AgeIdentity,
                birthday: None,
            },
        )
        .await
        .err()
        .expect("second bitcoin spender must be refused");
        assert!(
            second
                .to_string()
                .contains("at most one spending wallet per coin"),
            "{second}"
        );

        // And --ufvk names a Zcash key, so it cannot create a Bitcoin wallet.
        let ufvk = init_wallet(
            &config,
            InitOptions {
                wallet: "btc2".to_string(),
                key: InitKey::WatchOnly("uview1invalid".to_string()),
                encryption: EncryptionInput::AgeIdentity,
                birthday: None,
            },
        )
        .await
        .err()
        .expect("--ufvk on a bitcoin wallet must be refused");
        assert!(ufvk.to_string().contains("--ufvk"), "{ufvk}");
    }

    /// Bitcoin-wallet config whose `[bitcoind]` points at `server`; wallet `btc` on testnet.
    /// `extra` is appended verbatim (e.g. a `[keys]` section).
    #[cfg(all(feature = "bitcoin", feature = "cli"))]
    fn bitcoin_test_config(dir: &std::path::Path, server: &str, extra: &str) -> AppConfig {
        use clap::Parser as _;
        let conf = dir.join("zecd.toml");
        std::fs::write(
            &conf,
            format!(
                "network = \"test\"\ndatadir = {:?}\n\
                 [bitcoind]\nserver = \"{server}\"\n\
                 [wallets.btc]\ncoin = \"bitcoin\"\n{extra}",
                dir
            ),
        )
        .unwrap();
        let cli = crate::config::Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        AppConfig::resolve(&cli).unwrap()
    }

    /// A generated wallet with an explicit `--birthday` initializes fully offline: the server
    /// below is unreachable on purpose, so a dial would fail the test.
    #[cfg(all(feature = "bitcoin", feature = "cli"))]
    #[tokio::test(flavor = "multi_thread")]
    async fn bitcoin_init_generate_with_explicit_birthday_is_offline() {
        let dir = tempfile::tempdir().unwrap();
        let config = bitcoin_test_config(dir.path(), "bitcoind://127.0.0.1:1", "");
        let outcome = init_wallet(
            &config,
            InitOptions {
                wallet: "btc".to_string(),
                key: InitKey::Generate,
                encryption: EncryptionInput::AgeIdentity,
                birthday: Some(Birthday::Height(12_345)),
            },
        )
        .await
        .unwrap();
        assert_eq!(outcome.birthday, 12_345);
        assert!(outcome.generated_mnemonic.is_some());
    }

    #[test]
    fn birthday_parses_heights_and_dates() {
        assert_eq!(Birthday::parse("12345"), Ok(Birthday::Height(12_345)));
        assert_eq!(Birthday::parse("0"), Ok(Birthday::Height(0)));
        // 2026-07-28T00:00:00Z - the mainnet scan floor's own date, cross-checked with
        // `date -ud 2026-07-28 +%s`.
        assert_eq!(
            Birthday::parse("2026-07-28"),
            Ok(Birthday::Date(1_785_196_800))
        );
        // A leap day parses (and 2023's non-leap February rejects it below).
        assert_eq!(
            Birthday::parse("2024-02-29"),
            Ok(Birthday::Date(1_709_164_800))
        );
        for bad in [
            "2026-02-30",
            "2023-02-29",
            "2026-13-01",
            "2026-00-10",
            "2026-7",
            "yesterday",
            "99999999999",
            "2008-12-31",
            "9999-01-01",
            "",
        ] {
            assert!(Birthday::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn height_for_time_finds_the_last_block_at_or_before_target() {
        // A synthetic chain: block h mined at 600h.
        let time_at = |h: u32| Ok(u64::from(h) * 600);
        assert_eq!(height_for_time(time_at, 1_000, 600 * 500).unwrap(), 500);
        // Between blocks: rounds down.
        assert_eq!(
            height_for_time(time_at, 1_000, 600 * 500 + 599).unwrap(),
            500
        );
        // A target before the chain resolves to height 1, never 0 (genesis is
        // unrequestable on the Zcash side); one after the tip resolves to the tip.
        assert_eq!(height_for_time(time_at, 1_000, 0).unwrap(), 1);
        assert_eq!(height_for_time(time_at, 1_000, u64::MAX).unwrap(), 1_000);
        // Header-time jitter (~2h, here on every 7th block) cannot push the result past
        // the true boundary, and the full-day margin callers back the target off by
        // dwarfs the undershoot it can cause.
        let jitter = |h: u32| {
            let base = u64::from(h) * 600;
            Ok(if h.is_multiple_of(7) {
                base + 7_200
            } else {
                base
            })
        };
        let resolved = height_for_time(jitter, 1_000, 600 * 656).unwrap();
        assert!((600..=656).contains(&resolved), "{resolved}");
    }

    #[test]
    fn height_probes_stay_few_on_a_steadily_mined_chain() {
        use std::cell::Cell;
        let probes = Cell::new(0u32);
        let time_at = |h: u32| {
            probes.set(probes.get() + 1);
            Ok(u64::from(h) * 600)
        };
        assert_eq!(
            height_for_time(time_at, 1_000_000, 600 * 777_777 + 42).unwrap(),
            777_777
        );
        // The point of interpolating: the endpoints imply the chain's average block time,
        // so the search lands in single-digit probes where bisection alone takes ~20.
        assert!(probes.get() <= 8, "{} probes", probes.get());
    }

    #[test]
    fn height_probe_count_stays_logarithmic_on_pathological_timestamps() {
        use std::cell::Cell;
        // Quadratic times (early blocks nearly simultaneous, late ones sparse) drag every
        // interpolated guess toward one end; the alternated bisection keeps the probe
        // count ~2 log2(tip) rather than O(tip).
        let probes = Cell::new(0u32);
        let time_at = |h: u32| {
            probes.set(probes.get() + 1);
            Ok(u64::from(h) * u64::from(h))
        };
        let target = 250_000u64 * 250_000;
        assert_eq!(
            height_for_time(time_at, 1_000_000, target).unwrap(),
            250_000
        );
        assert!(probes.get() <= 50, "{} probes", probes.get());
    }

    /// A kyoto wallet with a *date* birthday initializes fully offline: the date resolves
    /// against the shipped scan floor (or the BIP 84 history floor when it predates it),
    /// starting no P2P node and dialing nothing.
    #[cfg(all(feature = "bitcoin", feature = "cli"))]
    #[tokio::test(flavor = "multi_thread")]
    async fn bitcoin_kyoto_init_with_a_date_birthday_is_offline() {
        use crate::coin::BitcoinNetwork;
        // Well after the testnet3 floor's own date (2026-08-16), so the floor height serves.
        let recent = 1_787_000_000;
        let dir = tempfile::tempdir().unwrap();
        let config = bitcoin_test_config(dir.path(), "kyoto", "");
        let outcome = init_wallet(
            &config,
            InitOptions {
                wallet: "btc".to_string(),
                key: InitKey::Generate,
                encryption: EncryptionInput::AgeIdentity,
                birthday: Some(Birthday::Date(recent)),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            Some(outcome.birthday),
            crate::btc::kyoto::birthday_height_for_date(BitcoinNetwork::Testnet3, recent)
        );

        // A date from 2020 predates the floor: no offline reference, so the BIP 84
        // history floor is recorded - slow, never wrong.
        let dir = tempfile::tempdir().unwrap();
        let config = bitcoin_test_config(dir.path(), "kyoto", "");
        let outcome = init_wallet(
            &config,
            InitOptions {
                wallet: "btc".to_string(),
                key: InitKey::Generate,
                encryption: EncryptionInput::AgeIdentity,
                birthday: Some(Birthday::Date(1_600_000_000)),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            outcome.birthday,
            bip84_history_floor(BitcoinNetwork::Testnet3)
        );
    }

    /// A generated wallet with no `--birthday` needs the node: the failed dial is an
    /// actionable refusal naming the offline escape hatch, and fires before anything is
    /// written.
    #[cfg(all(feature = "bitcoin", feature = "cli"))]
    #[tokio::test(flavor = "multi_thread")]
    async fn bitcoin_init_generate_without_birthday_needs_the_node() {
        let dir = tempfile::tempdir().unwrap();
        let config = bitcoin_test_config(dir.path(), "bitcoind://127.0.0.1:1", "");
        let err = init_wallet(
            &config,
            InitOptions {
                wallet: "btc".to_string(),
                key: InitKey::Generate,
                encryption: EncryptionInput::AgeIdentity,
                birthday: None,
            },
        )
        .await
        .err()
        .expect("the dial must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("--birthday"),
            "must name the escape hatch: {msg}"
        );
        let entry = &config.wallets["btc"];
        assert!(
            !WalletStore::exists(&entry.keys_path()),
            "refusal must precede writes"
        );
        assert!(!entry.dir.exists(), "refusal must precede writes");
    }

    /// Minimal fake bitcoind: an HTTP/1.1 JSON-RPC loop answering every request with the
    /// same `getblockchaininfo` result (testnet chain at a fixed tip), echoing the request
    /// id (the client checks it). Detached; it dies with the test process.
    #[cfg(all(feature = "bitcoin", feature = "cli"))]
    fn fake_bitcoind(tip: u64) -> std::net::SocketAddr {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = stream.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&buf[..pos]);
                    let len = headers
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse::<usize>().ok())?
                        })
                        .unwrap_or(0);
                    if buf.len() >= pos + 4 + len {
                        break;
                    }
                }
                let body = String::from_utf8_lossy(&buf);
                let id: String = body
                    .split("\"id\":")
                    .nth(1)
                    .map(|rest| rest.chars().take_while(|c| c.is_ascii_digit()).collect())
                    .filter(|s: &String| !s.is_empty())
                    .unwrap_or_else(|| "0".to_string());
                // `get_blockchain_info` first probes the node version via `getnetworkinfo`
                // (and branches on it for softfork-shape compatibility), so both methods
                // must answer.
                let result = if body.contains("getnetworkinfo") {
                    "{\"version\":300200,\"subversion\":\"/Satoshi:30.2.0/\",\
                     \"protocolversion\":70016,\"localservices\":\"0000000000000409\",\
                     \"localrelay\":true,\"timeoffset\":0,\"connections\":0,\
                     \"networkactive\":true,\"networks\":[],\"relayfee\":0.00001,\
                     \"incrementalfee\":0.00001,\"localaddresses\":[],\"warnings\":\"\"}"
                        .to_string()
                } else {
                    format!(
                        "{{\"chain\":\"test\",\"blocks\":{tip},\"headers\":{tip},\
                         \"bestblockhash\":\"{:064}\",\"difficulty\":1.0,\"mediantime\":0,\
                         \"verificationprogress\":1.0,\"initialblockdownload\":false,\
                         \"chainwork\":\"00\",\"size_on_disk\":0,\"pruned\":false,\
                         \"warnings\":\"\"}}",
                        0
                    )
                };
                let resp_body = format!("{{\"result\":{result},\"error\":null,\"id\":{id}}}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        addr
    }

    /// The generated-wallet default: `init` dials the node once and anchors the birthday
    /// just below its tip, exactly as the Zcash path does against zebra.
    #[cfg(all(feature = "bitcoin", feature = "cli"))]
    #[tokio::test(flavor = "multi_thread")]
    async fn bitcoin_init_generate_anchors_birthday_on_the_node_tip() {
        let addr = fake_bitcoind(50_000);
        let dir = tempfile::tempdir().unwrap();
        let config = bitcoin_test_config(dir.path(), &format!("bitcoind://{addr}"), "");
        let outcome = init_wallet(
            &config,
            InitOptions {
                wallet: "btc".to_string(),
                key: InitKey::Generate,
                encryption: EncryptionInput::AgeIdentity,
                birthday: None,
            },
        )
        .await
        .unwrap();
        // The wallet's coin default: BTC_FRESH_WALLET_BIRTHDAY_MARGIN, not the Zcash 100.
        assert_eq!(
            config.wallets["btc"].fresh_wallet_birthday_margin,
            BTC_FRESH_WALLET_BIRTHDAY_MARGIN
        );
        assert_eq!(outcome.birthday, 50_000 - BTC_FRESH_WALLET_BIRTHDAY_MARGIN);
        assert!(outcome.generated_mnemonic.is_some());
    }

    /// `[keys] fresh_wallet_birthday_margin` overrides the anchor's default margin.
    #[cfg(all(feature = "bitcoin", feature = "cli"))]
    #[tokio::test(flavor = "multi_thread")]
    async fn bitcoin_init_birthday_margin_is_configurable() {
        let addr = fake_bitcoind(50_000);
        let dir = tempfile::tempdir().unwrap();
        let config = bitcoin_test_config(
            dir.path(),
            &format!("bitcoind://{addr}"),
            "[keys]\nfresh_wallet_birthday_margin = 0\n",
        );
        let outcome = init_wallet(
            &config,
            InitOptions {
                wallet: "btc".to_string(),
                key: InitKey::Generate,
                encryption: EncryptionInput::AgeIdentity,
                birthday: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            outcome.birthday, 50_000,
            "margin 0 anchors on the tip itself"
        );
    }

    /// The per-wallet `fresh_wallet_birthday_margin` beats the global `[keys]` one (the
    /// `extra` continues the `[wallets.btc]` table, then opens `[keys]`).
    #[cfg(all(feature = "bitcoin", feature = "cli"))]
    #[tokio::test(flavor = "multi_thread")]
    async fn bitcoin_init_birthday_margin_per_wallet_beats_global() {
        let addr = fake_bitcoind(50_000);
        let dir = tempfile::tempdir().unwrap();
        let config = bitcoin_test_config(
            dir.path(),
            &format!("bitcoind://{addr}"),
            "fresh_wallet_birthday_margin = 2\n[keys]\nfresh_wallet_birthday_margin = 4\n",
        );
        assert_eq!(config.keys.fresh_wallet_birthday_margin, Some(4));
        let outcome = init_wallet(
            &config,
            InitOptions {
                wallet: "btc".to_string(),
                key: InitKey::Generate,
                encryption: EncryptionInput::AgeIdentity,
                birthday: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(outcome.birthday, 50_000 - 2);
    }

    #[test]
    fn restore_birthday_default_is_pool_aware() {
        use crate::pools::{Receiver, ReceiverSet};
        // Orchard-only (the default): scan from NU5/Orchard activation - no Orchard note can
        // predate it.
        let (h, label) =
            restore_birthday_default(ZNetwork::Main, &ReceiverSet::single(Receiver::Orchard));
        assert!(label.contains("Orchard"), "{label}");
        assert_eq!(
            h,
            u32::from(
                ZNetwork::Main
                    .activation_height(NetworkUpgrade::Nu5)
                    .unwrap()
            )
        );
        // Sapling enabled: scan from the earlier Sapling activation, where a Sapling note could
        // first exist (defaulting to NU5 would silently skip pre-NU5 Sapling funds).
        let sap = ReceiverSet::parse(&["sapling".to_string(), "orchard".to_string()]).unwrap();
        let (hs, label_s) = restore_birthday_default(ZNetwork::Main, &sap);
        assert_eq!(label_s, "Sapling");
        assert_eq!(
            hs,
            u32::from(
                ZNetwork::Main
                    .activation_height(NetworkUpgrade::Sapling)
                    .unwrap()
            )
        );
        assert!(hs < h, "Sapling activation precedes NU5");
    }

    #[test]
    fn passphrase_min_length_is_enforced() {
        // Too short (and empty) are rejected; exactly the minimum and longer pass.
        assert!(validate_passphrase("").is_err());
        assert!(validate_passphrase("short").is_err());
        assert!(validate_passphrase("eleven chrs").is_err()); // 11 chars
        assert!(validate_passphrase("twelve chars").is_ok()); // 12 chars
        assert!(validate_passphrase("a much longer passphrase").is_ok());
    }

    use std::collections::BTreeMap;

    use bip0039::{English, Mnemonic};
    use zcash_client_backend::data_api::chain::ChainState;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::consensus::BlockHeight;

    use crate::network;

    /// The Orchard-only pool set these tests use (pool config is irrelevant to them).
    fn orchard_pools() -> crate::pools::ReceiverSet {
        crate::pools::ReceiverSet::single(crate::pools::Receiver::Orchard)
    }

    /// The committed testnet test mnemonic (valueless), reused here purely as a deterministic
    /// seed source for throwaway regtest wallets.
    const TEST_PHRASE: &str = "mechanic vehicle helmet decide plug gorilla frost dial october \
        midnight culture idea mountain fame park social drip bid doctor scatter glance defy \
        moment stage";

    fn test_seed() -> SecretVec<u8> {
        let mut seed = <Mnemonic<English>>::from_phrase(TEST_PHRASE)
            .unwrap()
            .to_seed("");
        let secret = SecretVec::new(seed.to_vec());
        seed.zeroize();
        secret
    }

    fn genesis_birthday() -> AccountBirthday {
        AccountBirthday::from_parts(
            ChainState::empty(BlockHeight::from_u32(0), BlockHash([0u8; 32])),
            None,
        )
    }

    /// The test seed's index-0 UFVK in its network-scoped encoding (what `init` pins).
    fn test_ufvk_encoded(net: crate::network::ZNetwork) -> String {
        crate::wallet::binding::seed_ufvk_encoded(
            net,
            &test_seed(),
            zip32::AccountId::try_from(0u32).unwrap(),
        )
        .expect("derive the test seed's UFVK")
    }

    /// Build a fully-initialized spending wallet (keys.toml with a seed + a seed-derived
    /// account) at `dir`, so both the `WalletStore::exists` gate and the DB account match a
    /// real `zecd init`.
    fn make_spending_wallet(dir: &Path) {
        let net = network::regtest();
        let mnemonic = <Mnemonic<English>>::from_phrase(TEST_PHRASE).unwrap();
        WalletStore::init_with_passphrase(
            &crate::wallet::store::keys_path(dir),
            Passphrase::from("test-pass".to_string()),
            &mnemonic,
            BlockHeight::from_u32(1),
            net,
            &test_ufvk_encoded(net),
        )
        .expect("write spending keys.toml");
        let mut db = open::init_dbs(net, &engine_of(dir)).expect("init spending dbs");
        db.create_account("primary", &test_seed(), &genesis_birthday(), None)
            .expect("create spending account");
    }

    /// The engine directory inside a wallet directory - where the databases the helpers below
    /// build actually live (`keys.toml` stays at `dir` itself).
    fn engine_of(dir: &Path) -> PathBuf {
        crate::config::engine_dir(dir, crate::coin::Coin::Zcash)
    }

    /// Build a fully-initialized watch-only wallet (seedless keys.toml + a ViewOnly UFVK
    /// import) at `dir`.
    fn make_watch_only_wallet(dir: &Path) {
        let net = network::regtest();
        WalletStore::init_view_only(
            &crate::wallet::store::keys_path(dir),
            BlockHeight::from_u32(1),
            net,
            &test_ufvk_encoded(net),
        )
        .expect("write watch-only keys.toml");
        let ufvk = {
            use secrecy::ExposeSecret as _;
            let seed = test_seed();
            UnifiedSpendingKey::from_seed(
                &net,
                seed.expose_secret(),
                zip32::AccountId::try_from(0u32).unwrap(),
            )
            .expect("derive USK")
            .to_unified_full_viewing_key()
        };
        let mut db = open::init_dbs(net, &engine_of(dir)).expect("init watch-only dbs");
        db.import_account_ufvk(
            "watch",
            &ufvk,
            &genesis_birthday(),
            AccountPurpose::ViewOnly,
            None,
        )
        .expect("import the UFVK view-only");
    }

    /// The init-time data-directory guard: an account-bearing database refuses `init`, an
    /// empty (fresh) one passes. This is the check that keeps `zecd init` from absorbing a
    /// planted or leftover database's account as the wallet's own.
    #[test]
    fn init_refuses_a_database_that_already_has_an_account() {
        let net = network::regtest();
        let dir = tempfile::tempdir().unwrap();

        // A fresh (migrated, account-less) database passes.
        let mut db = open::init_dbs(net, dir.path()).expect("init dbs");
        ensure_no_preexisting_account(&db, "default", dir.path())
            .expect("an empty database must not block init");

        // The same database with an account (planted, leftover, whatever) refuses.
        db.create_account("primary", &test_seed(), &genesis_birthday(), None)
            .expect("create account");
        let err = ensure_no_preexisting_account(&db, "default", dir.path())
            .expect_err("an account-bearing database must refuse init");
        assert!(
            err.to_string().contains("already contains 1 account"),
            "{err}"
        );
    }

    #[test]
    fn spending_keys_detected_for_seed_wallet_not_watch_only() {
        let net = network::regtest();
        let spend = tempfile::tempdir().unwrap();
        let watch = tempfile::tempdir().unwrap();
        let empty = tempfile::tempdir().unwrap();
        make_spending_wallet(spend.path());
        make_watch_only_wallet(watch.path());

        assert!(
            wallet_has_spending_keys(net, &engine_of(spend.path())),
            "a seed-derived wallet holds spending keys"
        );
        assert!(
            !wallet_has_spending_keys(net, &engine_of(watch.path())),
            "a view-only UFVK import does not hold spending keys"
        );
        // An uninitialized directory has no account, so it is treated as non-spending (the guard
        // is best-effort and never blocks on an unreadable sibling).
        assert!(
            !wallet_has_spending_keys(net, &engine_of(empty.path())),
            "an empty wallet dir is not a spending wallet"
        );
    }

    #[test]
    fn existing_spending_wallet_finds_the_other_spender() {
        let net = network::regtest();
        let default_dir = tempfile::tempdir().unwrap();
        let w2_dir = tempfile::tempdir().unwrap();
        make_spending_wallet(default_dir.path());

        let mut wallets = BTreeMap::new();
        wallets.insert(
            "default".to_string(),
            WalletEntry {
                dir: default_dir.path().to_path_buf(),
                keys_file: None,
                coin: crate::coin::Coin::Zcash,
                chain: crate::coin::Coin::Zcash.chain(net),
                backend: Default::default(),
                pools: orchard_pools(),
                default_receivers: orchard_pools(),
                transparent_enabled: false,
                transparent_default: false,
                transparent_gap_limit: 20,
                transparent_initial_scan: 0,
                transparent_allow_beyond_recovery_window: true,
                transparent_gap_warn_threshold: 5,
                fresh_wallet_birthday_margin: crate::init::FRESH_WALLET_BIRTHDAY_MARGIN,
            },
        );
        wallets.insert(
            "w2".to_string(),
            WalletEntry {
                dir: w2_dir.path().to_path_buf(),
                keys_file: None,
                coin: crate::coin::Coin::Zcash,
                chain: crate::coin::Coin::Zcash.chain(net),
                backend: Default::default(),
                pools: orchard_pools(),
                default_receivers: orchard_pools(),
                transparent_enabled: false,
                transparent_default: false,
                transparent_gap_limit: 20,
                transparent_initial_scan: 0,
                transparent_allow_beyond_recovery_window: true,
                transparent_gap_warn_threshold: 5,
                fresh_wallet_birthday_margin: crate::init::FRESH_WALLET_BIRTHDAY_MARGIN,
            },
        );

        // Creating spending wallet 'w2' must see the existing spending 'default'.
        assert_eq!(
            existing_spending_wallet(net, &wallets, "w2").as_deref(),
            Some("default"),
            "the existing spending wallet is detected"
        );
        // Re-initializing 'default' itself excludes it, so no conflict is reported.
        assert_eq!(
            existing_spending_wallet(net, &wallets, "default"),
            None,
            "the wallet being created is excluded from the scan"
        );
    }

    #[test]
    fn watch_only_siblings_do_not_count_as_spenders() {
        let net = network::regtest();
        let view_a = tempfile::tempdir().unwrap();
        let view_b = tempfile::tempdir().unwrap();
        let default_dir = tempfile::tempdir().unwrap();
        make_watch_only_wallet(view_a.path());
        make_watch_only_wallet(view_b.path());

        let mut wallets = BTreeMap::new();
        for (name, dir) in [
            ("default", &default_dir),
            ("view-a", &view_a),
            ("view-b", &view_b),
        ] {
            wallets.insert(
                name.to_string(),
                WalletEntry {
                    dir: dir.path().to_path_buf(),
                    keys_file: None,
                    coin: crate::coin::Coin::Zcash,
                    chain: crate::coin::Coin::Zcash.chain(net),
                    backend: Default::default(),
                    pools: orchard_pools(),
                    default_receivers: orchard_pools(),
                    transparent_enabled: false,
                    transparent_default: false,
                    transparent_gap_limit: 20,
                    transparent_initial_scan: 0,
                    transparent_allow_beyond_recovery_window: true,
                    transparent_gap_warn_threshold: 5,
                    fresh_wallet_birthday_margin: crate::init::FRESH_WALLET_BIRTHDAY_MARGIN,
                },
            );
        }

        // Creating the (first) spending 'default' alongside any number of watch-only wallets is
        // allowed: none of the existing siblings hold spending keys.
        assert_eq!(
            existing_spending_wallet(net, &wallets, "default"),
            None,
            "watch-only siblings never trip the single-spending-wallet guard"
        );
    }

    /// The `zecd rescan` core: on an initialized spending wallet it deletes exactly the
    /// database files (data.sqlite + the compact-block cache) and keeps `keys.toml` - the
    /// state the daemon's empty-datadir bootstrap path then rebuilds from - and it is
    /// idempotent (a second run finds nothing to delete and still succeeds).
    #[test]
    fn rescan_wipes_the_database_but_keeps_keys_toml() {
        let net = network::regtest();
        let dir = tempfile::tempdir().unwrap();
        make_spending_wallet(dir.path());
        let engine = engine_of(dir.path());
        // The compact-block cache dir, as a running daemon would have left it.
        std::fs::create_dir_all(engine.join("blocks")).unwrap();
        std::fs::write(engine.join("blocks").join("100-aa-bb.compact"), b"x").unwrap();
        let keys_path = crate::wallet::store::keys_path(dir.path());
        assert!(open::data_db_path(&engine).exists());

        let removed = rescan_wallet(
            net,
            "default",
            Some(dir.path()),
            &keys_path,
            &engine,
            |st| {
                // The confirmation sees the parsed store (the prompt shows its birthday).
                assert_eq!(u32::from(st.birthday), 1);
                Ok(true)
            },
        )
        .expect("rescan an initialized spending wallet");
        assert!(removed.contains(&"data.sqlite".to_string()), "{removed:?}");
        assert!(removed.contains(&"blocks/".to_string()), "{removed:?}");
        assert!(!open::data_db_path(&engine).exists(), "database deleted");
        assert!(!engine.join("blocks").exists(), "block cache deleted");
        assert!(
            WalletStore::exists(&keys_path),
            "keys.toml (the rebuild source) sits above the engine directory and must survive"
        );
        // Idempotent: nothing left to delete, still succeeds (recovery can be retried).
        let removed = rescan_wallet(
            net,
            "default",
            Some(dir.path()),
            &keys_path,
            &engine,
            |_| Ok(true),
        )
        .expect("re-running rescan is not an error");
        assert!(removed.is_empty(), "{removed:?}");

        // The daemon's bootstrap gate: an account-less database with keys.toml present is the
        // exact state `wallet::actor::spawn` rebuilds from.
        let db = open::init_dbs(net, &engine).expect("fresh dbs re-initialize");
        assert!(
            db.get_account_ids().expect("account ids").is_empty(),
            "the rebuilt database starts account-less (bootstrap recreates it from the seed)"
        );
    }

    /// A watch-only wallet rescans from its pinned UFVK. `keys.toml` carries the viewing key
    /// and the birthday - exactly what `init --ufvk` was given - so the daemon's bootstrap can
    /// re-run `import_account_ufvk` with them, and the pin it rebuilds from is the same one
    /// every startup verifies the account against. Before this, the documented recovery for a
    /// broken view-only database was deleting the directory and re-running `init --ufvk` by
    /// hand, which needed the key re-supplied out of band despite it already being on disk.
    #[test]
    fn rescan_rebuilds_a_watch_only_wallet_from_its_pinned_ufvk() {
        let net = network::regtest();
        let dir = tempfile::tempdir().unwrap();
        make_watch_only_wallet(dir.path());
        let keys_path = crate::wallet::store::keys_path(dir.path());
        let engine = engine_of(dir.path());
        let pin_before = WalletStore::read(&keys_path)
            .expect("read keys.toml")
            .pinned_ufvk()
            .expect("the watch-only wallet pins its UFVK")
            .to_string();
        assert!(open::data_db_path(&engine).exists());

        let removed = rescan_wallet(net, "w", Some(dir.path()), &keys_path, &engine, |_| {
            Ok(true)
        })
        .expect("a pinned watch-only wallet rescans");
        assert!(removed.contains(&"data.sqlite".to_string()), "{removed:?}");
        assert!(!open::data_db_path(&engine).exists(), "database deleted");

        // The rebuild source must survive intact - a rescan that dropped the pin would leave a
        // wallet that cannot be rebuilt at all, which is the state this path exists to avoid.
        let st = WalletStore::read(&keys_path).expect("keys.toml survives");
        assert_eq!(st.pinned_ufvk(), Some(pin_before.as_str()));
        assert_eq!(u32::from(st.birthday), 1, "the birthday survives too");
        assert!(!st.has_seed(), "still watch-only");
    }

    /// `rescan`'s refusals: an uninitialized wallet (no keys.toml means no rebuild source), a
    /// watch-only wallet (no seed - the bootstrap path can't recreate a view-only account), a
    /// network mismatch, and a declined confirmation - each before anything is deleted.
    #[test]
    fn rescan_refuses_unrebuildable_wallets_and_declined_confirmation() {
        let net = network::regtest();

        // Uninitialized: no keys.toml.
        let empty = tempfile::tempdir().unwrap();
        let err = rescan_wallet(
            net,
            "default",
            Some(empty.path()),
            &crate::wallet::store::keys_path(empty.path()),
            &engine_of(empty.path()),
            |_| Ok(true),
        )
        .expect_err("no keys.toml, nothing to rebuild from");
        assert!(err.to_string().contains("not initialized"), "{err}");

        // Watch-only *without* a pin: a keys.toml written before the pin existed holds no key
        // material at all, so nothing on disk can rebuild the account.
        let watch = tempfile::tempdir().unwrap();
        make_watch_only_wallet(watch.path());
        let watch_keys = crate::wallet::store::keys_path(watch.path());
        WalletStore::strip_pin_for_tests(&watch_keys);
        let err = rescan_wallet(
            net,
            "w",
            Some(watch.path()),
            &watch_keys,
            &engine_of(watch.path()),
            |_| Ok(true),
        )
        .expect_err("a pin-less watch-only wallet cannot be rebuilt from keys.toml");
        assert!(err.to_string().contains("no pinned viewing key"), "{err}");
        assert!(err.to_string().contains("--ufvk"), "{err}");
        assert!(
            open::data_db_path(&engine_of(watch.path())).exists(),
            "refusal must not delete anything"
        );

        // Network mismatch: the regtest wallet under a mainnet config would rescan the wrong
        // chain.
        let spend = tempfile::tempdir().unwrap();
        make_spending_wallet(spend.path());
        let spend_keys = crate::wallet::store::keys_path(spend.path());
        let err = rescan_wallet(
            ZNetwork::Main,
            "default",
            Some(spend.path()),
            &spend_keys,
            &engine_of(spend.path()),
            |_| Ok(true),
        )
        .expect_err("network mismatch is refused");
        assert!(err.to_string().contains("configuration selects"), "{err}");

        // Declined confirmation aborts before deletion.
        let err = rescan_wallet(
            net,
            "default",
            Some(spend.path()),
            &spend_keys,
            &engine_of(spend.path()),
            |_| Ok(false),
        )
        .expect_err("a declined confirmation aborts");
        assert!(err.to_string().contains("aborted"), "{err}");
        assert!(
            open::data_db_path(&engine_of(spend.path())).exists(),
            "nothing deleted on abort"
        );
    }

    /// The age identity holds the secret key that decrypts the mnemonic, so it must be created
    /// private. Asserts the end-state mode; atomicity (never world-readable mid-write) comes from
    /// creating with the mode set at open time rather than chmod-ing afterwards.
    #[cfg(unix)]
    #[tokio::test]
    async fn identity_file_is_created_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.txt");
        ensure_identity(&path).await.expect("create identity");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "age identity must be private (0600)");
    }
}
