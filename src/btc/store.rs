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
    engine_dir.join(ENGINE_ARTIFACTS[0])
}

/// Everything the engine writes into its directory: the wallet database and its WAL
/// sidecars (a `-wal` holds committed-but-uncheckpointed writes, so the three go together).
/// `zecd rescan` deletes exactly this list; the kyoto header/filter cache lives in a sibling
/// directory (`config::btc_kyoto_dir`) and is deleted alongside. `keys.toml` sits at the
/// wallet root, above both.
pub const ENGINE_ARTIFACTS: [&str; 3] = ["wallet.sqlite", "wallet.sqlite-wal", "wallet.sqlite-shm"];

/// How long a write waits on another connection's lock before failing (`busy_timeout`).
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The layout this module reads and writes, stamped in the database's `user_version`. Bump
/// it when the tables or the changeset encoding change shape; [`check_schema_version`] then
/// refuses a database from a *newer* build with a message that names the way out, rather
/// than failing on the first row `initialize` cannot decode. A fresh database (or one
/// written before the stamp existed - the same layout as version 1) is stamped on open.
const SCHEMA_VERSION: i64 = 1;

/// Stamp a fresh (or pre-stamp) database and refuse one written by a newer layout.
fn check_schema_version(conn: &Connection, path: &Path) -> anyhow::Result<()> {
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .context("read the schema version")?;
    if version == 0 {
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)
            .context("stamp the schema version")?;
    } else if version > SCHEMA_VERSION {
        anyhow::bail!(
            "{} was written by a newer zecd (schema version {version}; this build reads \
             {SCHEMA_VERSION}). Upgrade zecd, or run `zecd rescan --wallet <name>` to rebuild \
             the wallet database from the chain",
            path.display()
        );
    }
    Ok(())
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
        // A second opener (a `rescan` racing a daemon, an operator's sqlite shell) would
        // otherwise turn every write into an immediate `SQLITE_BUSY`, which `persist` can
        // only log - the staged changeset then survives no restart. Wait it out instead.
        conn.busy_timeout(BUSY_TIMEOUT)
            .context("set the sqlite busy timeout")?;
        check_schema_version(&conn, &path)?;
        Ok(Persister { conn })
    }

    /// Run `f` inside one SQLite transaction: every write it makes lands together or not at
    /// all. The actor's retirement needs it - a tombstone without the eviction it accompanies
    /// reloads a transaction as canonical-unconfirmed with its anchors stripped, wrong on
    /// both sides (see [`Persister::retire_tx`]).
    pub fn transactionally<R>(
        &mut self,
        f: impl FnOnce(&mut Persister) -> anyhow::Result<R>,
    ) -> anyhow::Result<R> {
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .context("begin transaction")?;
        match f(self) {
            Ok(value) => {
                self.conn
                    .execute_batch("COMMIT")
                    .context("commit transaction")?;
                Ok(value)
            }
            Err(e) => {
                if let Err(rollback) = self.conn.execute_batch("ROLLBACK") {
                    tracing::warn!("rollback after a failed transaction: {rollback}");
                }
                Err(e)
            }
        }
    }

    /// An in-memory persister (tests).
    #[cfg(test)]
    pub fn in_memory() -> Persister {
        Persister {
            conn: Connection::open_in_memory().expect("in-memory sqlite"),
        }
    }

    /// Record the wallet's resolved birthday anchor: the `(height, hash)` pair a kyoto
    /// first scan starts from instead of the shipped scan floor (`btc::kyoto`'s
    /// `recovery_floor` precedence). Written by `init` when it dialed a bitcoind anyway
    /// (the fresh-wallet tip anchor, the date search) and by the actor when the kyoto
    /// birthday-anchor task resolves a recorded target against the light client's own
    /// headers. One row, overwritten on re-resolution.
    ///
    /// Chain-derived cache, so it belongs in this database rather than `keys.toml`: a
    /// missing or deleted anchor merely sends the next first scan back to the floor path,
    /// which re-resolves and rewrites it. The bitcoind backend never reads it (its emitter
    /// starts at the birthday height directly - no hash needed).
    pub fn save_birthday_anchor(&mut self, height: u32, hash: &str) -> anyhow::Result<()> {
        self.conn
            .execute_batch(ANCHOR_TABLE_SQL)
            .context("create birthday_anchor table")?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO birthday_anchor (id, height, hash) VALUES (0, ?1, ?2)",
                rusqlite::params![height, hash],
            )
            .context("record birthday anchor")?;
        Ok(())
    }

    /// Retire `txid`: record that the wallet evicted it at `evicted_at` (unix seconds) so
    /// that the next load strips every anchor of it that is no longer in the local chain.
    ///
    /// BDK keeps a transaction whose anchor reorged out canonical (unconfirmed) no matter
    /// what evictions it is given - `bdk_chain`'s "leftover" canonicalization path never
    /// consults `last_evicted` - so a reorged-out receive whose inputs were then spent
    /// elsewhere would stay pending forever. BDK also offers no way to drop an
    /// anchor from a live `TxGraph`; the changeset log is the one place it can be edited,
    /// and only on the way in. So the actor writes a tombstone here beside the eviction it
    /// applies, then reloads the wallet ([`crate::btc::actor`]'s `reload_wallet`), and
    /// [`WalletPersister::initialize`] strips the stale anchors while merging. What remains
    /// is BDK's own contract: without an in-chain anchor the transaction is canonical only
    /// while its `last_seen` outruns its `last_evicted`, and a transaction that confirms
    /// after all gains an in-chain anchor the strip leaves alone - evictions are not final.
    pub fn retire_tx(
        &mut self,
        txid: &bdk_wallet::bitcoin::Txid,
        evicted_at: u64,
    ) -> anyhow::Result<()> {
        self.conn
            .execute_batch(RETIRED_TABLE_SQL)
            .context("create retired_txs table")?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO retired_txs (txid, evicted_at) VALUES (?1, ?2)",
                rusqlite::params![txid.to_string(), evicted_at],
            )
            .context("record retired transaction")?;
        Ok(())
    }

    /// Every retired txid (see [`Persister::retire_tx`]).
    pub fn retired_txs(&self) -> anyhow::Result<Vec<bdk_wallet::bitcoin::Txid>> {
        self.conn
            .execute_batch(RETIRED_TABLE_SQL)
            .context("create retired_txs table")?;
        let mut stmt = self
            .conn
            .prepare("SELECT txid FROM retired_txs")
            .context("read retired transactions")?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .context("read retired transactions")?;
        let mut out = Vec::new();
        for row in rows {
            let encoded = row.context("read retired row")?;
            out.push(
                encoded
                    .parse()
                    .with_context(|| format!("decode retired txid {encoded}"))?,
            );
        }
        Ok(out)
    }

    /// Forget the recorded birthday anchor: the actor's answer to an anchor whose block
    /// reorged out of the chain (every redial from it fails header sync, and the escalation
    /// bottoms out there - `kyoto::resync_bottomed_at_anchor`). The next scan falls back to
    /// the network's recovery floor, and the resolution task re-records an anchor against
    /// the live headers.
    pub fn clear_birthday_anchor(&mut self) -> anyhow::Result<()> {
        self.conn
            .execute_batch(ANCHOR_TABLE_SQL)
            .context("create birthday_anchor table")?;
        self.conn
            .execute("DELETE FROM birthday_anchor", [])
            .context("clear birthday anchor")?;
        Ok(())
    }

    /// The recorded birthday anchor, if any - see [`Persister::save_birthday_anchor`].
    pub fn load_birthday_anchor(&self) -> anyhow::Result<Option<(u32, String)>> {
        self.conn
            .execute_batch(ANCHOR_TABLE_SQL)
            .context("create birthday_anchor table")?;
        self.conn
            .query_row(
                "SELECT height, hash FROM birthday_anchor WHERE id = 0",
                [],
                |row| Ok((row.get::<_, u32>(0)?, row.get::<_, String>(1)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
            .context("read birthday anchor")
    }
}

/// The single-row birthday-anchor table (see [`Persister::save_birthday_anchor`]). The
/// `CHECK (id = 0)` pins it to one row so a re-resolution replaces rather than accumulates.
const ANCHOR_TABLE_SQL: &str = "CREATE TABLE IF NOT EXISTS birthday_anchor (
    id INTEGER PRIMARY KEY CHECK (id = 0),
    height INTEGER NOT NULL,
    hash TEXT NOT NULL
)";

/// The retired-transaction tombstones (see [`Persister::retire_tx`]): one row per txid,
/// re-retiring overwrites the time.
const RETIRED_TABLE_SQL: &str = "CREATE TABLE IF NOT EXISTS retired_txs (
    txid TEXT PRIMARY KEY,
    evicted_at INTEGER NOT NULL
)";

/// Strip from a merged changeset every anchor of a retired transaction whose block is not
/// in the changeset's own local chain (the height missing, or held by another hash), and
/// return how many were dropped. An in-chain anchor is left alone: a retired transaction
/// that confirmed after all is confirmed. See [`Persister::retire_tx`].
fn strip_retired_anchors(
    changeset: &mut ChangeSet,
    retired: &[bdk_wallet::bitcoin::Txid],
) -> usize {
    if retired.is_empty() {
        return 0;
    }
    let retired: std::collections::HashSet<_> = retired.iter().copied().collect();
    let chain = &changeset.local_chain.blocks;
    let before = changeset.tx_graph.anchors.len();
    changeset.tx_graph.anchors.retain(|(anchor, txid)| {
        !retired.contains(txid)
            || chain.get(&anchor.block_id.height) == Some(&Some(anchor.block_id.hash))
    });
    before - changeset.tx_graph.anchors.len()
}

/// Create the wallet database from the account's public keys (seed-derived for a spending
/// wallet, imported for a watch-only one) - `zecd init`'s half of the engine (the daemon's
/// half is `crate::btc::actor::spawn`, which loads it back and verifies it against the same
/// keys). Refuses a database that already holds wallet data, mirroring init's
/// no-preexisting-account refusal on the Zcash side.
pub fn create_wallet_db(
    engine_dir: &Path,
    keys: &crate::btc::keys::AccountKeys,
) -> anyhow::Result<()> {
    use bdk_wallet::{KeychainKind, PersistedWallet, Wallet};
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
            .prepare("SELECT id, changeset FROM bdk_changesets ORDER BY id")
            .context("read changesets")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .context("read changesets")?;
        let mut aggregate = ChangeSet::default();
        for row in rows {
            let (id, encoded) = row.context("read changeset row")?;
            // A row this build cannot decode means the encoding moved under the database
            // (a bdk changeset serde change the schema stamp did not anticipate); say what
            // the operator can do about it, since the serde error alone names nothing.
            let changeset: ChangeSet = serde_json::from_str(&encoded).with_context(|| {
                format!(
                    "decode stored changeset row {id}: the wallet database was written with a \
                     changeset encoding this zecd cannot read; run `zecd rescan --wallet <name>` \
                     to rebuild it from the chain"
                )
            })?;
            aggregate.merge(changeset);
        }
        let retired = persister.retired_txs()?;
        let stripped = strip_retired_anchors(&mut aggregate, &retired);
        if stripped > 0 {
            tracing::debug!(
                stripped,
                retired = retired.len(),
                "dropped the out-of-chain anchors of retired transactions on load"
            );
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

    /// A fresh database is stamped with this build's schema version, a pre-stamp one (the
    /// same layout, `user_version` 0) is stamped on open, and one from a newer layout is
    /// refused up front with the way out named - not on the first undecodable row.
    #[test]
    fn the_schema_stamp_admits_older_and_refuses_newer_databases() {
        let dir = tempfile::tempdir().unwrap();
        let engine_dir = dir.path().join("btc").join("bdk");
        let read_version = |p: &Persister| -> i64 {
            p.conn
                .pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        {
            let mut persister = Persister::open(&engine_dir).unwrap();
            assert_eq!(read_version(&persister), SCHEMA_VERSION);
            create(&mut persister);
            // Pretend the stamp never existed (a database from before it did).
            persister
                .conn
                .pragma_update(None, "user_version", 0)
                .unwrap();
        }
        {
            let persister = Persister::open(&engine_dir).unwrap();
            assert_eq!(
                read_version(&persister),
                SCHEMA_VERSION,
                "backfilled on open"
            );
            persister
                .conn
                .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
                .unwrap();
        }
        let err = match Persister::open(&engine_dir) {
            Ok(_) => panic!("a newer schema must be refused"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("newer zecd"), "{err}");
        assert!(err.contains("zecd rescan"), "{err}");
    }

    /// A stored changeset this build cannot decode names the rescan that rebuilds the
    /// database, rather than surfacing the bare serde error.
    #[test]
    fn an_undecodable_changeset_names_the_rescan() {
        let mut persister = Persister::in_memory();
        create(&mut persister);
        persister
            .conn
            .execute(
                "INSERT INTO bdk_changesets (changeset) VALUES (?1)",
                ["{\"not\": \"a changeset\"}"],
            )
            .unwrap();
        let err = format!(
            "{:#}",
            <Persister as WalletPersister>::initialize(&mut persister).unwrap_err()
        );
        assert!(err.contains("zecd rescan"), "{err}");
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

    /// The birthday anchor is a single overwritten row that survives a close and reopen,
    /// and its absence reads as `None` rather than an error (the pre-anchor wallet, and
    /// the deliberate fallback when the row is deleted).
    #[test]
    fn birthday_anchor_round_trips_and_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let engine_dir = dir.path().join("btc").join("bdk");
        {
            let mut persister = Persister::open(&engine_dir).unwrap();
            assert_eq!(persister.load_birthday_anchor().unwrap(), None);
            persister.save_birthday_anchor(146_000, "aa").unwrap();
            // A re-resolution replaces the row rather than accumulating a second one.
            persister.save_birthday_anchor(146_500, "bb").unwrap();
        }
        let mut persister = Persister::open(&engine_dir).unwrap();
        assert_eq!(
            persister.load_birthday_anchor().unwrap(),
            Some((146_500, "bb".to_string()))
        );
        // Cleared (a reorged-out anchor): back to the no-anchor read, ready to re-record.
        persister.clear_birthday_anchor().unwrap();
        assert_eq!(persister.load_birthday_anchor().unwrap(), None);
        persister.save_birthday_anchor(146_600, "cc").unwrap();
        assert_eq!(
            persister.load_birthday_anchor().unwrap(),
            Some((146_600, "cc".to_string()))
        );
    }

    /// A retired transaction whose anchor reorged out is not canonical after a reload - the
    /// retirement BDK cannot express - while one that confirms after all keeps
    /// its in-chain anchor and stays confirmed.
    #[test]
    fn a_retired_transaction_loses_its_stale_anchor_on_load() {
        use bdk_wallet::bitcoin::block::{Header, Version};
        use bdk_wallet::bitcoin::hashes::Hash as _;
        use bdk_wallet::bitcoin::{
            absolute, Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence,
            Transaction, TxIn, TxMerkleNode, TxOut, Txid, Witness,
        };
        use std::str::FromStr as _;
        let block = |prev: BlockHash, nonce: u32, txs: Vec<Transaction>| Block {
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
        let load = |persister: &mut Persister| {
            PersistedWallet::load(
                persister,
                Wallet::load().check_network(bdk_wallet::bitcoin::Network::Regtest),
            )
            .unwrap()
            .expect("wallet data present")
        };
        let dir = tempfile::tempdir().unwrap();
        let engine_dir = dir.path().join("btc").join("bdk");
        let mut persister = Persister::open(&engine_dir).unwrap();
        let mut wallet = create(&mut persister);
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
        // Confirmed at 3, then 3 reorgs out (3' and 4 replace it): pending, per BDK.
        let b1 = block(wallet.latest_checkpoint().hash(), 1, vec![]);
        wallet.apply_block(&b1, 1).unwrap();
        let b2 = block(b1.block_hash(), 2, vec![]);
        wallet.apply_block(&b2, 2).unwrap();
        let b3 = block(b2.block_hash(), 3, vec![receive.clone()]);
        wallet.apply_block(&b3, 3).unwrap();
        let b3b = block(b2.block_hash(), 33, vec![]);
        wallet.apply_block(&b3b, 3).unwrap();
        let b4 = block(b3b.block_hash(), 4, vec![]);
        wallet.apply_block(&b4, 4).unwrap();
        wallet.apply_evicted_txs([(txid, 1_800_000_000)]);
        wallet.persist(&mut persister).unwrap();
        assert_eq!(
            wallet.balance().untrusted_pending,
            Amount::from_sat(50_000_000)
        );
        drop(wallet);

        // The eviction alone changes nothing across a reload (the gap).
        let wallet = load(&mut persister);
        assert_eq!(
            wallet.balance().untrusted_pending,
            Amount::from_sat(50_000_000)
        );
        assert!(wallet.transactions().any(|t| t.tx_node.txid == txid));
        drop(wallet);

        // Retired: the stale anchor is stripped on load and the transaction is gone from
        // the canonical view - not spendable, not pending, not listed.
        persister.retire_tx(&txid, 1_800_000_000).unwrap();
        let mut wallet = load(&mut persister);
        assert_eq!(wallet.balance().untrusted_pending, Amount::ZERO);
        assert_eq!(wallet.balance().confirmed, Amount::ZERO);
        assert!(!wallet.transactions().any(|t| t.tx_node.txid == txid));
        assert_eq!(
            wallet.latest_checkpoint().height(),
            4,
            "the chain is untouched"
        );

        // Confirmed after all at 5: the new anchor is in the chain and survives the next
        // load - retirement is not final, exactly like BDK's evictions.
        let b5 = block(b4.block_hash(), 5, vec![receive.clone()]);
        wallet.apply_block(&b5, 5).unwrap();
        wallet.persist(&mut persister).unwrap();
        drop(wallet);
        let wallet = load(&mut persister);
        assert_eq!(wallet.balance().confirmed, Amount::from_sat(50_000_000));
        assert!(wallet
            .get_tx(txid)
            .is_some_and(|t| t.chain_position.is_confirmed()));
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
