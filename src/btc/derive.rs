//! `zecd derive-address` for a Bitcoin wallet: BIP 84 receiving addresses, offline.
//!
//! The Bitcoin counterpart of [`crate::derive_address`] (the Zcash command, which rides the
//! `zcash` feature): no network, no daemon, no datadir lock, so it runs beside a live daemon
//! and before a wallet has a chain - pre-provisioning deposit addresses, or an air-gapped box
//! holding only the mnemonic. External index `n` is `m/84'/coin'/0'/0/n`, the address the
//! wallet's descriptor yields at `n`: the one `getnewaddress` hands out `n`th, and the one
//! `getaddressinfo` reports with `address_index = n`.
//!
//! The account key comes from one of three places:
//!
//! - the wallet itself - the `keys.toml` xpub pin of a watch-only wallet, else the public
//!   descriptors in its database (what `export-xpub` reads). No seed is decrypted, so a
//!   locked or watch-only wallet works;
//! - a BIP-39 mnemonic (`--mnemonic`, from `ZECD_MNEMONIC`/`--mnemonic-file`/stdin), the
//!   air-gapped case;
//! - an account xpub (`--xpub`, the `[fingerprint/84'/coin'/0']xpub...` form `export-xpub`
//!   prints, or a bare xpub).
//!
//! Supplied key material plus an explicit `--wallet` checks the two against each other, as
//! the Zcash command checks a UFVK against its pin: the account xpubs must be equal (the
//! master fingerprint is not compared - a bare-xpub import carries the all-zero one, and it
//! never enters derivation).

use std::path::Path;

use anyhow::{anyhow, bail};
use bdk_wallet::KeychainKind;
use secrecy::{SecretVec, Zeroize};

use crate::coin::{BitcoinNetwork, Coin};
#[cfg(feature = "cli")]
use crate::config::DeriveAddressArgs;
use crate::config::{AppConfig, WalletEntry};
use crate::wallet::store::WalletStore;

use super::keys::AccountKeys;

/// Whether `derive-address` for `wallet` (`None` = the config's default wallet, so a
/// Bitcoin-only config with just `[wallets.btc]` routes here with no flag) is this module's
/// to answer: the wallet's configured coin is Bitcoin. The CLI dispatches on it.
pub fn serves(config: &AppConfig, wallet: Option<&str>) -> bool {
    crate::init::resolve_wallet_entry(config, wallet.unwrap_or(&config.default_wallet)).coin
        == Coin::Bitcoin
}

/// Where the account key came from, for the report and the cross-check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// The wallet's own public key material: its `keys.toml` xpub pin or its database.
    Wallet,
    Mnemonic,
    Xpub,
}

impl KeySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeySource::Wallet => "wallet",
            KeySource::Mnemonic => "mnemonic",
            KeySource::Xpub => "xpub",
        }
    }
}

/// The key material to derive from, with any interactive input already performed by the
/// caller (which is what keeps stdin out of [`derive`]).
pub enum KeyInput {
    /// The named wallet's own public key material (no seed decrypted).
    Wallet,
    /// A BIP-39 mnemonic; only the account xpub is kept, and the seed is zeroized.
    Mnemonic(bip0039::Mnemonic<bip0039::English>),
    /// An encoded account xpub, as `export-xpub` prints.
    Xpub(String),
}

/// A note the CLI prints to stderr before the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeriveNote {
    /// Key material was supplied but the named wallet has no key material to check it
    /// against (not initialized, or no database yet).
    Unchecked { wallet: String, why: String },
    /// The supplied key derives the named wallet's account.
    Verified { wallet: String },
    /// A derived index lies past the wallet's lookahead: a running daemon watches the
    /// addresses it has handed out plus `lookahead` more, so a payment to this index is
    /// seen only once issuance has come within `lookahead` of it.
    BeyondLookahead {
        wallet: String,
        last: u32,
        lookahead: u32,
    },
}

impl std::fmt::Display for DeriveNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeriveNote::Unchecked { wallet, why } => write!(
                f,
                "note: wallet '{wallet}' has no key material to check the supplied key \
                 against ({why}), so it was not verified."
            ),
            DeriveNote::Verified { wallet } => write!(
                f,
                "Verified: the supplied key derives the account of wallet '{wallet}'."
            ),
            DeriveNote::BeyondLookahead {
                wallet,
                last,
                lookahead,
            } => write!(
                f,
                "warning: index {last} is beyond the lookahead of wallet '{wallet}' \
                 ({lookahead}). A running daemon watches the addresses it has handed out \
                 plus {lookahead} more, so a payment here is not seen until getnewaddress \
                 has issued an index within {lookahead} of it, and a restore misses it the \
                 same way. Raise [wallets.{wallet}] lookahead past your highest \
                 pre-provisioned index before handing these addresses out."
            ),
        }
    }
}

/// What to derive - the library-facing form of the flags.
pub struct DeriveOptions<'a> {
    /// `None` selects the default wallet's configuration and skips the cross-check for
    /// supplied key material, as the omitted `--wallet` flag does.
    pub wallet: Option<&'a str>,
    pub key: KeyInput,
    /// `getnewaddress`'s `address_type`: `None`, or `bech32` (the only type the engine
    /// issues).
    pub address_type: Option<&'a str>,
    pub index: u64,
    pub count: u32,
}

/// What was derived, as data.
#[derive(Debug)]
pub struct DeriveOutcome {
    pub network: BitcoinNetwork,
    pub wallet: String,
    pub source: KeySource,
    /// `Some(true)` when supplied key material matched the wallet's (a mismatch is an
    /// error); `None` when nothing was checked.
    pub key_matches: Option<bool>,
    /// The account key in `export-xpub`'s form - what `init --xpub` takes.
    pub xpub: String,
    /// `(index, address)` pairs, in index order.
    pub addresses: Vec<(u32, String)>,
    pub notes: Vec<DeriveNote>,
}

#[cfg(feature = "cli")]
pub fn run(config: &AppConfig, args: &DeriveAddressArgs) -> anyhow::Result<()> {
    if args.count == 0 {
        bail!("--count must be at least 1");
    }
    if args.ufvk.is_some() {
        bail!(
            "--ufvk takes a Zcash Unified Full Viewing Key, and this is a Bitcoin wallet; \
             derive from its account key with --xpub (as `zecd export-xpub` prints), from \
             --mnemonic, or from the wallet itself"
        );
    }
    let key = if let Some(encoded) = &args.xpub {
        KeyInput::Xpub(encoded.clone())
    } else if args.mnemonic || args.mnemonic_file.is_some() {
        KeyInput::Mnemonic(crate::init::read_mnemonic_phrase(
            args.mnemonic_file.as_deref(),
            "Enter the mnemonic phrase to derive from, then press Enter:",
        )?)
    } else {
        KeyInput::Wallet
    };
    let outcome = derive(
        config,
        DeriveOptions {
            wallet: args.wallet.as_deref(),
            key,
            address_type: args.address_type.as_deref(),
            index: args.index,
            count: args.count,
        },
    )?;
    for note in &outcome.notes {
        eprintln!("{note}");
    }
    print(&outcome, args.json);
    Ok(())
}

/// The library core: derive `count` receiving addresses from `opts.key`. No stdin, no
/// stdout/stderr, no network, no datadir lock; the wallet database is read only when the
/// wallet itself is the key source (or the cross-check target) and holds no xpub pin.
pub fn derive(config: &AppConfig, opts: DeriveOptions<'_>) -> anyhow::Result<DeriveOutcome> {
    if opts.count == 0 {
        bail!("--count must be at least 1");
    }
    let wallet = opts.wallet.unwrap_or(&config.default_wallet);
    let entry = crate::init::resolve_wallet_entry(config, wallet);
    if entry.coin != Coin::Bitcoin {
        bail!("wallet '{wallet}' is not a Bitcoin wallet");
    }
    if let Some(kind) = opts
        .address_type
        .map(str::trim)
        .filter(|kind| !kind.is_empty())
    {
        if !kind.eq_ignore_ascii_case("bech32") {
            bail!("address type {kind:?} is not supported for a Bitcoin wallet (bech32 only)");
        }
    }
    let network = entry.bitcoin_network();
    let mut notes = Vec::new();

    let (keys, source) = match opts.key {
        KeyInput::Wallet => (wallet_keys(config, &entry, wallet)?, KeySource::Wallet),
        KeyInput::Mnemonic(mnemonic) => {
            let mut bytes = mnemonic.to_seed("");
            let seed = SecretVec::new(bytes.to_vec());
            bytes.zeroize();
            (AccountKeys::from_seed(&seed, network)?, KeySource::Mnemonic)
        }
        KeyInput::Xpub(encoded) => (AccountKeys::from_xpub(&encoded, network)?, KeySource::Xpub),
    };

    let key_matches = if source != KeySource::Wallet && opts.wallet.is_some() {
        verify_against_wallet(config, &entry, wallet, &keys, &mut notes)?
    } else {
        None
    };

    let first = u32::try_from(opts.index)
        .ok()
        .filter(|i| *i < 1 << 31)
        .ok_or_else(|| {
            anyhow!(
                "--index {} is out of range: address indices are non-hardened (below 2^31)",
                opts.index
            )
        })?;
    let last = first
        .checked_add(opts.count - 1)
        .filter(|l| *l < 1 << 31)
        .ok_or_else(|| {
            anyhow!("--index + --count runs past the last non-hardened index (2^31 - 1)")
        })?;
    if last >= entry.lookahead {
        notes.push(DeriveNote::BeyondLookahead {
            wallet: wallet.to_string(),
            last,
            lookahead: entry.lookahead,
        });
    }
    let addresses = (first..=last)
        .map(|index| {
            keys.address(KeychainKind::External, index)
                .map(|address| (index, address.to_string()))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    Ok(DeriveOutcome {
        network,
        wallet: wallet.to_string(),
        source,
        key_matches,
        xpub: keys.export(),
        addresses,
        notes,
    })
}

/// The wallet's own account key: the `keys.toml` xpub pin of a watch-only wallet, else the
/// public descriptors in its database (`export-xpub`'s read, which also enforces the
/// network).
fn wallet_keys(
    config: &AppConfig,
    entry: &WalletEntry,
    wallet: &str,
) -> anyhow::Result<AccountKeys> {
    let keys_path = entry.keys_path();
    if !WalletStore::exists(&keys_path) {
        bail!(
            "wallet '{wallet}' is not initialized ({} missing). Derive from key material \
             instead: --mnemonic (phrase on stdin, ZECD_MNEMONIC, or --mnemonic-file) or \
             --xpub <key>.",
            keys_path.display()
        );
    }
    pinned_or_stored(config, entry, wallet, &keys_path)
}

fn pinned_or_stored(
    config: &AppConfig,
    entry: &WalletEntry,
    wallet: &str,
    keys_path: &Path,
) -> anyhow::Result<AccountKeys> {
    let store = WalletStore::read(keys_path)?;
    if store.network != config.network {
        bail!(
            "wallet '{wallet}' is a {} wallet, but the configuration selects {}",
            store.network.name(),
            config.network.name()
        );
    }
    if let Some(pin) = store.pinned_xpub() {
        return AccountKeys::from_xpub(pin, entry.bitcoin_network());
    }
    let exported = crate::init::export_xpub_string(config, wallet)?;
    AccountKeys::from_xpub(&exported, entry.bitcoin_network())
}

/// Compare supplied key material with the named wallet's own. A match is the confirmation
/// an operator is after; a mismatch is an error, so the command can gate a script. A wallet
/// with nothing to compare against is reported unchecked rather than failed.
fn verify_against_wallet(
    config: &AppConfig,
    entry: &WalletEntry,
    wallet: &str,
    keys: &AccountKeys,
    notes: &mut Vec<DeriveNote>,
) -> anyhow::Result<Option<bool>> {
    let keys_path = entry.keys_path();
    if !WalletStore::exists(&keys_path) {
        notes.push(DeriveNote::Unchecked {
            wallet: wallet.to_string(),
            why: format!("{} missing", keys_path.display()),
        });
        return Ok(None);
    }
    let store = WalletStore::read(&keys_path)?;
    if store.pinned_xpub().is_none()
        && !crate::btc::store::wallet_db_path(&entry.engine_dir()).exists()
    {
        notes.push(DeriveNote::Unchecked {
            wallet: wallet.to_string(),
            why: "no wallet database yet".to_string(),
        });
        return Ok(None);
    }
    let own = pinned_or_stored(config, entry, wallet, &keys_path)?;
    if own.account_xpub != keys.account_xpub {
        bail!(
            "the supplied key does not match wallet '{wallet}' ({}): these are different \
             wallets, and the addresses below would NOT be watched by that wallet.",
            own.export()
        );
    }
    notes.push(DeriveNote::Verified {
        wallet: wallet.to_string(),
    });
    Ok(Some(true))
}

/// Print the result in the Zcash command's shape: one address per line on stdout with the
/// context on stderr, or one JSON object on stdout under `--json` (carrying the account
/// xpub in place of the UFVK - what pairs a watch-only instance via `init --xpub`).
#[cfg(feature = "cli")]
fn print(outcome: &DeriveOutcome, json: bool) {
    if json {
        let entries: Vec<serde_json::Value> = outcome
            .addresses
            .iter()
            .map(|(index, address)| serde_json::json!({"index": index, "address": address}))
            .collect();
        let mut out = serde_json::json!({
            "network": outcome.network.name(),
            "wallet": outcome.wallet,
            "source": outcome.source.as_str(),
            "address_type": "bech32",
            "xpub": outcome.xpub,
            "addresses": entries,
        });
        if let Some(matches) = outcome.key_matches {
            out["key_matches"] = serde_json::Value::Bool(matches);
        }
        println!("{}", serde_json::to_string_pretty(&out).expect("json"));
        return;
    }
    let range = match outcome.addresses.as_slice() {
        [(only, _)] => format!("index {only}"),
        [(first, _), .., (last, _)] => format!("indices {first}-{last}"),
        [] => "no indices".to_string(),
    };
    eprintln!(
        "Wallet '{}' ({}), bech32, {range}, key source: {}",
        outcome.wallet,
        outcome.network.name(),
        outcome.source.as_str(),
    );
    for (_, address) in &outcome.addresses {
        println!("{address}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc::keys::tests::bip84_seed;

    /// The derivation is the wallet's own: external index `n` is exactly the address a BDK
    /// wallet over the same public descriptors yields at `n` - what `getnewaddress` issues
    /// - on every network, change keychain included.
    #[test]
    fn derived_addresses_match_the_wallet_descriptor() {
        for net in [
            BitcoinNetwork::Main,
            BitcoinNetwork::Testnet4,
            BitcoinNetwork::Regtest,
        ] {
            let keys = AccountKeys::from_seed(&bip84_seed(), net).unwrap();
            let wallet = bdk_wallet::Wallet::create(
                keys.descriptor(KeychainKind::External),
                keys.descriptor(KeychainKind::Internal),
            )
            .network(keys.network)
            .create_wallet_no_persist()
            .unwrap();
            for keychain in [KeychainKind::External, KeychainKind::Internal] {
                for index in [0, 1, 7, 1_000] {
                    assert_eq!(
                        keys.address(keychain, index).unwrap(),
                        wallet.peek_address(keychain, index).address,
                        "{net:?} {keychain:?} {index}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_hardened_index_is_refused() {
        let keys = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Main).unwrap();
        assert!(keys.address(KeychainKind::External, 1 << 31).is_err());
        assert!(keys.address(KeychainKind::External, (1 << 31) - 1).is_ok());
    }
}
