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
use bdk_wallet::bitcoin::Network;
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
        let coin_type = match net {
            BitcoinNetwork::Main => 0,
            BitcoinNetwork::Testnet3 | BitcoinNetwork::Testnet4 | BitcoinNetwork::Regtest => 1,
        };
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(84).expect("84 is in range"),
            ChildNumber::from_hardened_idx(coin_type).expect("coin type is in range"),
            ChildNumber::from_hardened_idx(0).expect("0 is in range"),
        ]);
        let account_xprv = master
            .derive_priv(&secp, &path)
            .context("derive BIP 84 account key")?;
        Ok(AccountKeys {
            fingerprint,
            account_xpub: Xpub::from_priv(&secp, &account_xprv),
            network,
        })
    }

    /// The public descriptor template for one keychain: `wpkh([fp/84'/c'/0']xpub/{0,1}/*)`.
    pub fn descriptor(&self, keychain: KeychainKind) -> Bip84Public<Xpub> {
        Bip84Public(self.account_xpub, self.fingerprint, keychain)
    }
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
