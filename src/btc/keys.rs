//! Key derivation for the BDK engine: the shared BIP-39 seed to BIP 84 descriptors.
//!
//! The same `keys.toml` mnemonic that derives a wallet's Zcash account serves its Bitcoin
//! account - one wallet, one seed, one directory per coin underneath it (see
//! [`crate::coin::Coin::data_dir`]). Derivation is standard BIP 84: `m/84'/0'/0'` on mainnet,
//! `m/84'/1'/0'` on test networks, native-segwit `wpkh` descriptors for the external and
//! internal (change) keychains.
//!
//! The wallet database is created from **public** descriptors ([`Bip84Public`]): the account
//! xpub plus the master fingerprint, never the xprv. That preserves zecd's custody model - the
//! only spending material on disk is the age-encrypted mnemonic in `keys.toml` - and it is
//! what the spend path will build on too (derive signers from the seed at signing time, as the
//! Zcash actor derives its USK per send, rather than persisting keys).

use anyhow::Context as _;
use bdk_wallet::bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::{Network, NetworkKind};
use bdk_wallet::miniscript::descriptor::{DescriptorPublicKey, Wildcard};
use bdk_wallet::miniscript::ForEachKey as _;
use bdk_wallet::template::Bip84Public;
use bdk_wallet::KeychainKind;
use secrecy::{ExposeSecret as _, SecretVec};

use crate::coin::BitcoinNetwork;

/// Map the shared-layer [`BitcoinNetwork`] onto BDK's network type, at the engine's edge -
/// the one place the two vocabularies meet.
pub fn network(net: BitcoinNetwork) -> Network {
    match net {
        BitcoinNetwork::Main => Network::Bitcoin,
        BitcoinNetwork::Testnet3 => Network::Testnet,
        BitcoinNetwork::Testnet4 => Network::Testnet4,
        BitcoinNetwork::Regtest => Network::Regtest,
    }
}

/// The BIP 84 account-level public key material derived from a wallet seed: everything the
/// wallet database is created from, and nothing that can spend.
///
/// The same material arrives two other ways. An **imported** account xpub (`init --xpub`,
/// [`AccountKeys::from_xpub`]) builds a watch-only wallet - the Bitcoin counterpart of a
/// Zcash UFVK import - and [`AccountKeys::from_wallet`] reads it back out of an existing
/// wallet database for `export-xpub`, which is how a spending wallet hands its viewing
/// material to a watch-only twin without ever exposing the seed.
#[derive(Clone, Debug)]
pub struct AccountKeys {
    /// The master key's fingerprint (the key-origin tag in the descriptors).
    pub fingerprint: Fingerprint,
    /// The account xpub at `m/84'/coin'/0'`.
    pub account_xpub: Xpub,
    /// The network the keys were derived for (BIP 84's coin type follows it).
    pub network: Network,
}

impl AccountKeys {
    /// Derive the BIP 84 account keys from a BIP-39 seed (the bytes
    /// `bip0039::Mnemonic::to_seed` produces - the same seed the Zcash account derives from).
    pub fn from_seed(seed: &SecretVec<u8>, net: BitcoinNetwork) -> anyhow::Result<AccountKeys> {
        let network = network(net);
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(network, seed.expose_secret())
            .context("derive BIP 32 master key from seed")?;
        let fingerprint = master.fingerprint(&secp);
        let account_xprv = master
            .derive_priv(&secp, &bip84_account_path(net))
            .context("derive BIP 84 account key")?;
        Ok(AccountKeys {
            fingerprint,
            account_xpub: Xpub::from_priv(&secp, &account_xprv),
            network,
        })
    }

    /// Parse an exported account key (the [`AccountKeys::export`] form,
    /// `[fingerprint/84'/coin'/0']xpub...`) for a watch-only wallet on `net`.
    ///
    /// Strict on purpose: the engine is BIP 84 only (`getaddressinfo` reports
    /// `m/84'/coin'/0'/...` paths, and issuance is bech32), so the key must be the account
    /// node at exactly that path, its own network kind must match the wallet's, and the key
    /// origin (fingerprint + path) must be present - it is what `export-xpub` writes, what
    /// the descriptors carry, and what the spending twin's seed-derived descriptors are
    /// compared against. A bare xpub, a wrong depth, or a trailing `/0/*` is refused
    /// naming the expected form rather than silently building a wallet whose addresses no
    /// paired seed can spend.
    pub fn from_xpub(encoded: &str, net: BitcoinNetwork) -> anyhow::Result<AccountKeys> {
        let network = network(net);
        let key: DescriptorPublicKey = encoded
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid account xpub: {e}"))?;
        let DescriptorPublicKey::XPub(xkey) = key else {
            anyhow::bail!(
                "invalid account xpub: expected an extended public key of the form \
                 [fingerprint/84'/coin'/0']xpub... (as `zecd export-xpub` prints)"
            );
        };
        if !xkey.derivation_path.is_empty() || xkey.wildcard != Wildcard::None {
            anyhow::bail!(
                "invalid account xpub: pass the account-level key alone, without a \
                 derivation suffix such as /0/* (the wallet derives both keychains from it)"
            );
        }
        let Some((fingerprint, origin_path)) = xkey.origin else {
            anyhow::bail!(
                "invalid account xpub: the key origin is missing - expected \
                 [fingerprint/84'/coin'/0']xpub..., the form `zecd export-xpub` prints (the \
                 master fingerprint is what ties the watch-only wallet to its spending twin)"
            );
        };
        let expected_kind = NetworkKind::from(network);
        if xkey.xkey.network != expected_kind {
            anyhow::bail!(
                "invalid account xpub: the key is encoded for {} but this wallet is on {} \
                 ({})",
                match xkey.xkey.network {
                    NetworkKind::Main => "mainnet (xpub)",
                    NetworkKind::Test => "a test network (tpub)",
                },
                match expected_kind {
                    NetworkKind::Main => "mainnet",
                    NetworkKind::Test => "a test network",
                },
                network
            );
        }
        let expected_path = bip84_account_path(net);
        if origin_path != expected_path {
            anyhow::bail!(
                "invalid account xpub: the key origin path is {origin_path}, but this \
                 engine derives BIP 84 accounts at {expected_path} only (bech32, first \
                 account); other derivations are not supported"
            );
        }
        if usize::from(xkey.xkey.depth) != expected_path.len() {
            anyhow::bail!(
                "invalid account xpub: the key is at depth {} but its origin path names \
                 depth {} - not an account-level key",
                xkey.xkey.depth,
                expected_path.len()
            );
        }
        Ok(AccountKeys {
            fingerprint,
            account_xpub: xkey.xkey,
            network,
        })
    }

    /// Read the account keys back out of an existing wallet's public descriptors - what
    /// `export-xpub` prints. Works for any wallet the engine created (seed-derived or
    /// imported, locked or not): the database holds the public descriptors for scanning
    /// anyway, and nothing here touches spending material.
    pub fn from_wallet(wallet: &bdk_wallet::Wallet) -> anyhow::Result<AccountKeys> {
        let descriptor = wallet.public_descriptor(KeychainKind::External);
        let mut found: Option<(Fingerprint, Xpub)> = None;
        descriptor.for_each_key(|key| {
            if let DescriptorPublicKey::XPub(xkey) = key {
                if let Some((fingerprint, _)) = &xkey.origin {
                    found = Some((*fingerprint, xkey.xkey));
                }
            }
            true
        });
        let (fingerprint, account_xpub) = found.ok_or_else(|| {
            anyhow::anyhow!(
                "the wallet's external descriptor carries no origin-tagged account xpub \
                 ({descriptor}); not a wallet this engine created"
            )
        })?;
        Ok(AccountKeys {
            fingerprint,
            account_xpub,
            network: wallet.network(),
        })
    }

    /// The exported form: `[fingerprint/84'/coin'/0']xpub...` - a key-origin-qualified
    /// account key, the expression a descriptor carries between its brackets and the key
    /// itself, so it drops into `wpkh([...]/0/*)` verbatim and parses back with
    /// [`AccountKeys::from_xpub`].
    pub fn export(&self) -> String {
        format!(
            "[{}/{}]{}",
            self.fingerprint,
            bip84_account_path(match self.network {
                Network::Bitcoin => BitcoinNetwork::Main,
                // Testnet3, testnet4, signet and regtest all derive at coin type 1'; the
                // exported key is the same for every one of them.
                _ => BitcoinNetwork::Regtest,
            }),
            self.account_xpub
        )
    }

    /// The public descriptor template for one keychain: `wpkh([fp/84'/c'/0']xpub/{0,1}/*)`.
    pub fn descriptor(&self, keychain: KeychainKind) -> Bip84Public<Xpub> {
        Bip84Public(self.account_xpub, self.fingerprint, keychain)
    }
}

/// The BIP 84 account path for `net`: `84'/0'/0'` on mainnet, `84'/1'/0'` everywhere else.
/// Exactly what BDK's `Bip84Public` template writes as the key origin, so an imported key
/// checked against this reproduces a seed wallet's descriptors byte for byte.
fn bip84_account_path(net: BitcoinNetwork) -> DerivationPath {
    let coin_type = match net {
        BitcoinNetwork::Main => 0,
        BitcoinNetwork::Testnet3 | BitcoinNetwork::Testnet4 | BitcoinNetwork::Regtest => 1,
    };
    DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(84).expect("84 is in range"),
        ChildNumber::from_hardened_idx(coin_type).expect("coin type is in range"),
        ChildNumber::from_hardened_idx(0).expect("0 is in range"),
    ])
}

/// A throwaway in-memory wallet over the **private** BIP 84 descriptors, for signing PSBTs
/// built by the persisted (public-descriptor) wallet - the spend half of the custody model:
/// derived from the seed per send, never persisted, dropped when the send completes. Its
/// key material is byte-identical to what [`AccountKeys`] describes (same master, same
/// paths), so the PSBT's BIP 32 origin metadata routes every input to it.
pub fn signing_wallet(
    seed: &SecretVec<u8>,
    net: BitcoinNetwork,
) -> anyhow::Result<bdk_wallet::Wallet> {
    use bdk_wallet::template::Bip84;
    let network = network(net);
    let master =
        Xpriv::new_master(network, seed.expose_secret()).context("derive BIP 32 master key")?;
    bdk_wallet::Wallet::create(
        Bip84(master, KeychainKind::External),
        Bip84(master, KeychainKind::Internal),
    )
    .network(network)
    .create_wallet_no_persist()
    .map_err(|e| anyhow::anyhow!("build signing wallet: {e}"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The BIP 84 reference vector's mnemonic (test use only - it is the publicly documented
    /// example phrase).
    pub(crate) const BIP84_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    pub(crate) fn bip84_seed() -> SecretVec<u8> {
        let mnemonic = <bip0039::Mnemonic<bip0039::English>>::from_phrase(BIP84_MNEMONIC)
            .expect("valid phrase");
        SecretVec::new(mnemonic.to_seed("").to_vec())
    }

    /// Pins the derivation against the BIP 84 reference vectors: the document's first two
    /// receive addresses and first change address, produced through the same descriptors the
    /// on-disk wallet is created from, plus the master fingerprint the descriptors carry.
    #[test]
    fn derivation_matches_the_bip84_reference_vector() {
        let keys = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Main).unwrap();
        assert_eq!(keys.fingerprint.to_string(), "73c5da0a");
        assert_eq!(keys.network, Network::Bitcoin);
        let mut wallet = bdk_wallet::Wallet::create(
            keys.descriptor(KeychainKind::External),
            keys.descriptor(KeychainKind::Internal),
        )
        .network(keys.network)
        .create_wallet_no_persist()
        .unwrap();
        assert_eq!(
            wallet
                .reveal_next_address(KeychainKind::External)
                .to_string(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert_eq!(
            wallet
                .reveal_next_address(KeychainKind::External)
                .to_string(),
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
        );
        assert_eq!(
            wallet
                .reveal_next_address(KeychainKind::Internal)
                .to_string(),
            "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
        );
    }

    /// The export/import round trip: a seed wallet's exported key rebuilds the identical
    /// descriptors (so a watch-only twin derives the same addresses), the reference
    /// vector's origin is what the string carries, and the wallet-side reader agrees.
    #[test]
    fn exported_xpub_round_trips_into_identical_descriptors() {
        let keys = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Main).unwrap();
        let exported = keys.export();
        assert!(
            exported.starts_with("[73c5da0a/84'/0'/0']xpub"),
            "origin-qualified mainnet form: {exported}"
        );
        let imported = AccountKeys::from_xpub(&exported, BitcoinNetwork::Main).unwrap();
        assert_eq!(imported.fingerprint, keys.fingerprint);
        assert_eq!(imported.account_xpub, keys.account_xpub);
        assert_eq!(imported.network, Network::Bitcoin);
        let build = |k: &AccountKeys| {
            bdk_wallet::Wallet::create(
                k.descriptor(KeychainKind::External),
                k.descriptor(KeychainKind::Internal),
            )
            .network(k.network)
            .create_wallet_no_persist()
            .unwrap()
        };
        let (mut from_seed, mut from_xpub) = (build(&keys), build(&imported));
        for keychain in [KeychainKind::External, KeychainKind::Internal] {
            assert_eq!(
                from_seed.public_descriptor(keychain).to_string(),
                from_xpub.public_descriptor(keychain).to_string()
            );
            assert_eq!(
                from_seed.reveal_next_address(keychain).to_string(),
                from_xpub.reveal_next_address(keychain).to_string()
            );
        }
        // And reading the key back out of either wallet yields the same export.
        assert_eq!(
            AccountKeys::from_wallet(&from_seed).unwrap().export(),
            exported
        );
        assert_eq!(
            AccountKeys::from_wallet(&from_xpub).unwrap().export(),
            exported
        );

        // Test networks: a tpub at coin type 1', identical across testnet3/4 and regtest.
        let test_keys = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Regtest).unwrap();
        let test_exported = test_keys.export();
        assert!(
            test_exported.starts_with("[73c5da0a/84'/1'/0']tpub"),
            "{test_exported}"
        );
        for net in [
            BitcoinNetwork::Testnet3,
            BitcoinNetwork::Testnet4,
            BitcoinNetwork::Regtest,
        ] {
            let imported = AccountKeys::from_xpub(&test_exported, net).unwrap();
            assert_eq!(imported.account_xpub, test_keys.account_xpub);
            assert_eq!(imported.network, network(net));
        }
    }

    /// Every malformed import is refused naming what is wrong, never accepted as a
    /// wallet that no paired seed could spend.
    #[test]
    fn xpub_import_refuses_the_wrong_shapes() {
        let main = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Main).unwrap();
        let test = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Regtest).unwrap();
        let refuse = |encoded: &str, net: BitcoinNetwork, needle: &str| {
            let err = AccountKeys::from_xpub(encoded, net)
                .err()
                .unwrap_or_else(|| panic!("{encoded} must be refused on {net:?}"))
                .to_string();
            assert!(err.contains(needle), "{encoded}: {err}");
        };
        // Garbage.
        refuse("not a key", BitcoinNetwork::Main, "invalid account xpub");
        // A bare xpub without its origin.
        refuse(
            &main.account_xpub.to_string(),
            BitcoinNetwork::Main,
            "key origin is missing",
        );
        // A trailing keychain path / wildcard.
        refuse(
            &format!("{}/0/*", main.export()),
            BitcoinNetwork::Main,
            "without a derivation suffix",
        );
        // The wrong network kind for the wallet.
        refuse(
            &main.export(),
            BitcoinNetwork::Regtest,
            "encoded for mainnet",
        );
        refuse(
            &test.export(),
            BitcoinNetwork::Main,
            "encoded for a test network",
        );
        // A non-BIP-84 origin path (BIP 86's), and a BIP 84 path for the other coin type.
        refuse(
            &format!("[73c5da0a/86'/0'/0']{}", main.account_xpub),
            BitcoinNetwork::Main,
            "BIP 84 accounts at 84'/0'/0' only",
        );
        refuse(
            &format!("[73c5da0a/84'/1'/0']{}", main.account_xpub),
            BitcoinNetwork::Main,
            "BIP 84 accounts at 84'/0'/0' only",
        );
        // A master key (depth 0) claiming the account origin.
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(Network::Bitcoin, bip84_seed().expose_secret()).unwrap();
        refuse(
            &format!("[73c5da0a/84'/0'/0']{}", Xpub::from_priv(&secp, &master)),
            BitcoinNetwork::Main,
            "not an account-level key",
        );
    }

    #[test]
    fn testnets_and_regtest_use_coin_type_one() {
        let testnet3 = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Testnet3).unwrap();
        let testnet4 = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Testnet4).unwrap();
        let regtest = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Regtest).unwrap();
        // Same path (m/84'/1'/0'), same key material - testnet3 and testnet4 differ only as
        // chains, never as key derivations; only the daemon-side network differs.
        assert_eq!(testnet3.account_xpub, regtest.account_xpub);
        assert_eq!(testnet3.account_xpub, testnet4.account_xpub);
        assert_eq!(testnet3.network, Network::Testnet);
        assert_eq!(testnet4.network, Network::Testnet4);
        assert_eq!(regtest.network, Network::Regtest);
    }
}
