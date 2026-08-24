//! On-disk persistence for the BDK engine, over zecd's own rusqlite.
//!
//! BDK ships a rusqlite persister of its own, but `bdk_chain` pins `rusqlite ^0.31`, whose
//! `libsqlite3-sys` cannot coexist with the `rusqlite 0.37` the Zcash engine builds on
//! (`links = "sqlite3"` allows one version per build graph). So this module implements
//! [`WalletPersister`] directly: an append-only log of serde-encoded [`ChangeSet`]s in one
//! table, merged on load ([`bdk_wallet::chain::Merge`]) - the same aggregate-of-changesets
//! model BDK's own persisters use, minus their schema. The wallet database lives at
//! `<wallet>/btc/bdk/wallet.sqlite` ([`wallet_db_path`]); everything in that directory is the
//! engine's own, rebuildable from seed + chain, per the statelessness invariant.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use bdk_wallet::chain::Merge as _;
use bdk_wallet::ChangeSet;
use bdk_wallet::WalletPersister;
use rusqlite::Connection;

/// The BDK wallet database inside a wallet's engine directory.
pub fn wallet_db_path(engine_dir: &Path) -> PathBuf {
    engine_dir.join("wallet.sqlite")
}

/// A [`WalletPersister`] backed by one SQLite table of serde-encoded changesets.
pub struct Persister {
    conn: Connection,
}

impl Persister {
    /// Open (creating parents and schema as needed) the persister at `engine_dir`'s
    /// [`wallet_db_path`]. WAL mode, like the Zcash wallet database, so a future read path
    /// can use short-lived connections without blocking the writer.
    pub fn open(engine_dir: &Path) -> anyhow::Result<Persister> {
        std::fs::create_dir_all(engine_dir)
            .with_context(|| format!("create {}", engine_dir.display()))?;
        let path = wallet_db_path(engine_dir);
        let conn = Connection::open(&path).with_context(|| format!("open {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .context("set WAL mode")?;
        Ok(Persister { conn })
    }

    /// An in-memory persister (tests).
    #[cfg(test)]
    pub fn in_memory() -> Persister {
        Persister {
            conn: Connection::open_in_memory().expect("in-memory sqlite"),
        }
    }
}

/// Create the wallet database from a seed - `zecd init`'s half of the engine (the daemon's
/// half is `crate::btc::actor::spawn`, which loads it back and verifies it against the same
/// seed). Refuses a database that already holds wallet data, mirroring init's
/// no-preexisting-account refusal on the Zcash side.
pub fn create_wallet_db(
    engine_dir: &Path,
    network: crate::coin::BitcoinNetwork,
    seed: &secrecy::SecretVec<u8>,
) -> anyhow::Result<()> {
    use bdk_wallet::{KeychainKind, PersistedWallet, Wallet};
    let keys = crate::btc::keys::AccountKeys::from_seed(seed, network)?;
    let mut persister = Persister::open(engine_dir)?;
    PersistedWallet::create(
        &mut persister,
        Wallet::create(
            keys.descriptor(KeychainKind::External),
            keys.descriptor(KeychainKind::Internal),
        )
        .network(keys.network),
    )
    .map_err(|e| anyhow::anyhow!("create bitcoin wallet database: {e}"))?;
    Ok(())
}

impl WalletPersister for Persister {
    type Error = anyhow::Error;

    fn initialize(persister: &mut Self) -> Result<ChangeSet, Self::Error> {
        persister
            .conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS bdk_changesets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    changeset TEXT NOT NULL
                )",
            )
            .context("create bdk_changesets table")?;
        let mut stmt = persister
            .conn
            .prepare("SELECT changeset FROM bdk_changesets ORDER BY id")
            .context("read changesets")?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .context("read changesets")?;
        let mut aggregate = ChangeSet::default();
        for row in rows {
            let encoded = row.context("read changeset row")?;
            let changeset: ChangeSet =
                serde_json::from_str(&encoded).context("decode stored changeset")?;
            aggregate.merge(changeset);
        }
        Ok(aggregate)
    }

    fn persist(persister: &mut Self, changeset: &ChangeSet) -> Result<(), Self::Error> {
        if changeset.is_empty() {
            return Ok(());
        }
        let encoded = serde_json::to_string(changeset).context("encode changeset")?;
        persister
            .conn
            .execute(
                "INSERT INTO bdk_changesets (changeset) VALUES (?1)",
                [&encoded],
            )
            .context("append changeset")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc::keys::tests::bip84_seed;
    use crate::btc::keys::AccountKeys;
    use crate::coin::BitcoinNetwork;
    use bdk_wallet::{KeychainKind, PersistedWallet, Wallet};

    fn create(persister: &mut Persister) -> PersistedWallet<Persister> {
        let keys = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Regtest).unwrap();
        PersistedWallet::create(
            persister,
            Wallet::create(
                keys.descriptor(KeychainKind::External),
                keys.descriptor(KeychainKind::Internal),
            )
            .network(keys.network),
        )
        .unwrap()
    }

    /// The revealed-address cursor survives a close and reopen: reveal two addresses, persist,
    /// reload, and the next reveal continues the sequence instead of repeating it.
    #[test]
    fn revealed_addresses_survive_a_reload() {
        let dir = tempfile::tempdir().unwrap();
        let engine_dir = dir.path().join("btc").join("bdk");
        let (a0, a1) = {
            let mut persister = Persister::open(&engine_dir).unwrap();
            let mut wallet = create(&mut persister);
            let a0 = wallet
                .reveal_next_address(KeychainKind::External)
                .to_string();
            let a1 = wallet
                .reveal_next_address(KeychainKind::External)
                .to_string();
            assert!(wallet.persist(&mut persister).unwrap());
            (a0, a1)
        };
        let mut persister = Persister::open(&engine_dir).unwrap();
        let mut wallet = PersistedWallet::load(
            &mut persister,
            Wallet::load().check_network(bdk_wallet::bitcoin::Network::Regtest),
        )
        .unwrap()
        .expect("wallet data present");
        let a2 = wallet
            .reveal_next_address(KeychainKind::External)
            .to_string();
        assert_ne!(a2, a0);
        assert_ne!(a2, a1);
        assert_eq!(
            wallet.list_unused_addresses(KeychainKind::External).count(),
            3,
            "all three revealed addresses are known after the reload"
        );
    }

    /// Creating over existing data is refused by `PersistedWallet::create` (the analog of
    /// init's re-init refusal), which is what lets the actor distinguish create from load.
    #[test]
    fn create_refuses_existing_data() {
        let dir = tempfile::tempdir().unwrap();
        let engine_dir = dir.path().join("btc").join("bdk");
        {
            let mut persister = Persister::open(&engine_dir).unwrap();
            create(&mut persister);
        }
        let mut persister = Persister::open(&engine_dir).unwrap();
        let keys = AccountKeys::from_seed(&bip84_seed(), BitcoinNetwork::Regtest).unwrap();
        let err = PersistedWallet::create(
            &mut persister,
            Wallet::create(
                keys.descriptor(KeychainKind::External),
                keys.descriptor(KeychainKind::Internal),
            )
            .network(keys.network),
        );
        assert!(err.is_err(), "second create over the same data must fail");
    }

    /// Empty changesets are not appended: reopening an untouched wallet leaves the log alone.
    #[test]
    fn reopening_without_changes_appends_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let engine_dir = dir.path().join("btc").join("bdk");
        {
            let mut persister = Persister::open(&engine_dir).unwrap();
            create(&mut persister);
        }
        let rows = |p: &Persister| -> i64 {
            p.conn
                .query_row("SELECT COUNT(*) FROM bdk_changesets", [], |r| r.get(0))
                .unwrap()
        };
        let mut persister = Persister::open(&engine_dir).unwrap();
        let before = rows(&persister);
        let mut wallet = PersistedWallet::load(
            &mut persister,
            Wallet::load().check_network(bdk_wallet::bitcoin::Network::Regtest),
        )
        .unwrap()
        .expect("wallet data present");
        wallet.persist(&mut persister).unwrap();
        assert_eq!(rows(&persister), before);
    }
}
