//! The birthday block itself is scanned over kyoto. bip157 fetches filters from
//! `anchor + 1`: the anchor checkpoint is held as the tree's tip with no header of its own,
//! so its block is never filtered. rose therefore records a height birthday's anchor one
//! block BELOW it - a restore told `--birthday H` (the height of the first receive, as
//! `init` instructs) must see a receive mined in block H.
//!
//! Regtest ships no scan floor, so a first sync from a bare height runs from genesis and
//! would find the receive whatever the anchor; what that leg pins is where rose puts the
//! anchor it resolves (`H - 1`). The anchor is only consulted on a wallet with no chain
//! data of its own - what a mainnet `init` records from the per-day table or a bitcoind
//! node - so the suite then plants the anchor row exactly as `init` would, and runs the
//! recovery from it: once at `H - 1` (the receive is found) and once at `H` (the receive
//! is missed - bip157's exclusive semantic, the reason for the `- 1`). The last leg is
//! the control that keeps the others from passing vacuously.
//!
//! Skips cleanly without a bitcoind (`BITCOIND_BIN` or PATH) or a rose built without the
//! `bitcoin` feature - the same two probes as `regtest_btc.rs`.

use rose_regtest_harness::btc::{provisioned, BitcoinD, BtcBackend, RoseBtc};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn btc_kyoto_recovery_from_an_anchor_scans_the_block_above_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(bitcoind) = provisioned(dir.path()) else {
        return;
    };
    let node = BitcoinD::start(&bitcoind, &dir.path().join("btcdata")).await;
    node.mine(101).await;

    // The original wallet, over bitcoind: one receive, mined into block 102 - the
    // wallet's birthday block. Buried under a few more so the tip is elsewhere.
    let (mnemonic, address) = {
        let mut rose = RoseBtc::prepare(
            dir.path().join("original"),
            BtcBackend::Bitcoind,
            &node,
            &["btc"],
        );
        let mnemonic = rose
            .init_ok("btc", &["--birthday", "0"])
            .expect("a fresh init prints its mnemonic");
        rose.start().await;
        rose.wait_height(101).await;
        let address = rose
            .call("getnewaddress", json!([]))
            .await
            .expect("getnewaddress")
            .as_str()
            .unwrap()
            .to_string();
        node.call("sendtoaddress", json!([address, 1.0]))
            .await
            .expect("fund the wallet");
        node.mine(1).await;
        rose.wait_height(102).await;
        rose.wait_wallet_balance("btc", 1.0).await;
        rose.stop();
        (mnemonic, address)
    };
    std::fs::remove_dir_all(dir.path().join("original")).expect("discard the original");
    node.mine(10).await;
    let tip = node.height().await;
    assert_eq!(tip, 112);
    let birthday: u64 = 102;
    let phrase_file = dir.path().join("phrase.txt");
    std::fs::write(&phrase_file, format!("{mnemonic}\n")).unwrap();

    // 1. What rose itself records: a restore told `--birthday 102` with no anchor scans
    //    from the regtest genesis floor and resolves the anchor at 101, one below the
    //    birthday (`btc::kyoto::resolution_target`), once the tip is the reorg margin past
    //    it - the placement the two planted legs below then prove inclusive.
    {
        let mut rose = RoseBtc::prepare(
            dir.path().join("resolved"),
            BtcBackend::Kyoto,
            &node,
            &["btc"],
        );
        rose.init_ok(
            "btc",
            &[
                "--restore",
                "--mnemonic-file",
                phrase_file.to_str().unwrap(),
                "--birthday",
                &birthday.to_string(),
            ],
        );
        rose.start().await;
        rose.wait_height(tip).await;
        rose.wait_wallet_balance("btc", 1.0).await;
        let expected_hash = node.block_hash(birthday - 1).await;
        rose.wait_wallet(
            "btc",
            "getwalletinfo",
            json!([]),
            "the birthday anchor resolves one below the birthday",
            |wi| {
                wi["birthday"]["anchor"]["height"] == json!(birthday - 1)
                    && wi["birthday"]["anchor"]["hash"] == json!(expected_hash)
            },
        )
        .await;
        rose.stop();
    }

    // 2. The planted legs: a recovery from a recorded anchor, the path a mainnet init
    //    takes, finds the birthday block from `H - 1` and misses it from `H`.
    for (anchor_height, seen) in [(birthday - 1, true), (birthday, false)] {
        let name = format!("anchor-{anchor_height}");
        let mut rose = RoseBtc::prepare(dir.path().join(&name), BtcBackend::Kyoto, &node, &["btc"]);
        let printed = rose.init_ok(
            "btc",
            &[
                "--restore",
                "--mnemonic-file",
                phrase_file.to_str().unwrap(),
                "--birthday",
                &birthday.to_string(),
            ],
        );
        assert!(
            printed.is_none(),
            "a restore prints no mnemonic: {printed:?}"
        );
        // What a mainnet init records offline from the per-day table (or a bitcoind init
        // from the node): the anchor row, before the wallet has any chain data.
        let hash = node.block_hash(anchor_height).await;
        plant_anchor(&rose.wallet_db_path("btc"), anchor_height, &hash);

        rose.start().await;
        rose.wait_height(tip).await;
        let info = rose
            .call("getwalletinfo", json!([]))
            .await
            .expect("getwalletinfo");
        assert_eq!(
            info["birthday"]["anchor"]["height"].as_u64(),
            Some(anchor_height),
            "the planted anchor drove the scan: {info}"
        );
        let balance = rose
            .call("getbalance", json!([]))
            .await
            .expect("getbalance")
            .as_f64()
            .unwrap();
        let ai = rose
            .call("getaddressinfo", json!([address]))
            .await
            .expect("getaddressinfo");
        assert_eq!(ai["ismine"], json!(true), "{ai}");
        if seen {
            assert_eq!(
                balance, 1.0,
                "an anchor at {anchor_height} scans block {birthday}, the birthday: {info}"
            );
        } else {
            assert_eq!(
                balance, 0.0,
                "bip157 scans from anchor + 1, so an anchor AT the birthday ({anchor_height}) \
                 must miss its block - the control for the `- 1`: {info}"
            );
        }
        rose.stop();
    }
}

/// Write the single `birthday_anchor` row the engine store keeps (`btc::store`), the way
/// `init` does for a resolvable birthday. `init` creates only BDK's tables; the engine's
/// come up with the daemon, so the table is created here with the store's own DDL
/// (`CREATE TABLE IF NOT EXISTS`, so the daemon's initialize is a no-op on it). Through
/// python's bundled sqlite module, which the CI image has where a `sqlite3` binary may not.
fn plant_anchor(db: &std::path::Path, height: u64, hash: &str) {
    let script = format!(
        "import sqlite3; c = sqlite3.connect({db:?}); \
         c.execute('CREATE TABLE IF NOT EXISTS birthday_anchor (id INTEGER PRIMARY KEY \
         CHECK (id = 0), height INTEGER NOT NULL, hash TEXT NOT NULL)'); \
         c.execute('INSERT OR REPLACE INTO birthday_anchor (id, height, hash) VALUES (0, ?, ?)', \
         ({height}, {hash:?})); c.commit(); \
         print(c.execute('SELECT height, hash FROM birthday_anchor WHERE id = 0').fetchone())",
        db = db.to_str().unwrap(),
    );
    let out = std::process::Command::new("python3")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("python3 runs the anchor plant");
    assert!(
        out.status.success(),
        "planting the anchor: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let shown = String::from_utf8_lossy(&out.stdout);
    assert!(
        shown.contains(&height.to_string()) && shown.contains(hash),
        "anchor row read back: {shown}"
    );
}
