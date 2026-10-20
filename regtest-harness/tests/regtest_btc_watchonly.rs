//! Watch-only (imported xpub) Bitcoin wallet, end to end, over both chain sources: the
//! operator flow `rose export-xpub` on the spending wallet, `rose init --xpub` for a
//! watch-only sibling in the same daemon, and the two running side by side against one
//! regtest Bitcoin Core.
//!
//! What it pins: the per-coin single-spender rule admits the watch-only wallet (and still
//! refuses a second spender); the watch-only wallet derives the spender's exact addresses
//! (BIP 84 is deterministic - the same index yields the same address, unlike Zcash's
//! clock-derived diversifiers); it sees receives, the spender's sends, and change through
//! the pinned public descriptors alone; it reports `private_keys_enabled: false` and
//! `spendable: false`, refuses sends with Bitcoin Core's -4 naming the watch-only custody,
//! and has no `walletpassphrase` at all; it re-exports the identical key it was built from
//! (read from the live daemon's database, lock-free); the pinned key verifies the database
//! across a restart; and a deleted database is rebuilt from the pin and rescanned to the
//! same balance - the Bitcoin analog of a watch-only UFVK wallet's rescannability.
//!
//! Over kyoto the same flow runs with no mempool: nothing is visible at 0-conf, and the
//! spender's send is priced by the P2P fee signals (regtest has no fee oracle).
//!
//! Skips cleanly without a bitcoind (`BITCOIND_BIN` or PATH) or a rose built without the
//! `bitcoin` feature - the same two probes as `regtest_btc.rs`.

use rose_regtest_harness::btc::{provisioned, BitcoinD, BtcBackend, RoseBtc};
use serde_json::json;

const SPENDER: &str = "btc";
const VIEW: &str = "view";

#[tokio::test(flavor = "multi_thread")]
async fn btc_watch_only_xpub_pairs_with_the_spender_over_bitcoind() {
    watch_only_flow(BtcBackend::Bitcoind).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_watch_only_xpub_pairs_with_the_spender_over_kyoto() {
    watch_only_flow(BtcBackend::Kyoto).await;
}

async fn watch_only_flow(backend: BtcBackend) {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(bitcoind) = provisioned(dir.path()) else {
        return;
    };
    let node = BitcoinD::start(&bitcoind, &dir.path().join("btcdata")).await;
    // Past coinbase maturity before rose starts, so a kyoto first sync covers a real span.
    node.mine(101).await;

    // 1. The spending wallet, then its exported account key - read offline from the
    //    database init just created, before any daemon runs.
    let mut rose = RoseBtc::prepare(
        dir.path().join("rosedata"),
        backend,
        &node,
        &[SPENDER, VIEW],
    );
    rose.init_ok(SPENDER, &["--birthday", "0"]);
    let xpub = rose
        .export_xpub(SPENDER)
        .expect("export-xpub on the spender");
    assert!(
        xpub.starts_with('[') && xpub.contains("/84'/1'/0']tpub"),
        "an origin-qualified testnet account key: {xpub}"
    );
    // `export-ufvk` names the right command for this coin.
    let ufvk_err = std::process::Command::new(rose_regtest_harness::rose_bin())
        .args([
            "--datadir",
            rose.datadir.to_str().unwrap(),
            "--regtest",
            "--conf",
            rose.datadir.join("rose.toml").to_str().unwrap(),
            "export-ufvk",
            "--wallet",
            SPENDER,
        ])
        .output()
        .expect("run export-ufvk");
    assert!(!ufvk_err.status.success());
    assert!(
        String::from_utf8_lossy(&ufvk_err.stderr).contains("export-xpub"),
        "{}",
        String::from_utf8_lossy(&ufvk_err.stderr)
    );

    // 2. A second spender is refused by the per-coin guard; the watch-only sibling is not.
    let refused = rose
        .init(VIEW, &["--birthday", "0"])
        .expect_err("a second bitcoin spender must be refused at init");
    assert!(
        refused.contains("at most one spending wallet per coin"),
        "{refused}"
    );
    let (_, stderr) = rose
        .init(VIEW, &["--xpub", &xpub, "--birthday", "0"])
        .expect("init --xpub");
    assert!(
        stderr.contains("Watch-only wallet (imported xpub)"),
        "{stderr}"
    );
    assert!(
        rose.wallet_db_path(VIEW).exists(),
        "init created the database"
    );

    // 3. One daemon serves both; the startup invariant admits the pair.
    rose.start().await;
    let wallets = rose
        .call("listwallets", json!([]))
        .await
        .expect("listwallets");
    assert!(
        wallets.as_array().is_some_and(|w| {
            w.contains(&json!(SPENDER)) && w.contains(&json!(VIEW)) && w.len() == 2
        }),
        "{wallets}"
    );
    rose.wait_wallet_height(SPENDER, 101).await;
    rose.wait_wallet_height(VIEW, 101).await;

    // Same key material, same first address: index 0 on both keychains agrees.
    let addr = rose
        .call_wallet(SPENDER, "getnewaddress", json!([]))
        .await
        .expect("spender getnewaddress");
    let addr = addr.as_str().unwrap().to_string();
    assert!(addr.starts_with("bcrt1"), "{addr}");
    let view_addr = rose
        .call_wallet(VIEW, "getnewaddress", json!([]))
        .await
        .expect("view getnewaddress");
    assert_eq!(view_addr.as_str(), Some(addr.as_str()), "index 0 on both");

    // The wallet-level watch-only signal, exactly as the Zcash side reports it: the
    // per-address flags are byte-identical on both wallets.
    let wi = rose
        .call_wallet(VIEW, "getwalletinfo", json!([]))
        .await
        .expect("view getwalletinfo");
    assert_eq!(wi["private_keys_enabled"], json!(false), "{wi}");
    assert_eq!(wi["coin"], json!("bitcoin"), "{wi}");
    let wi = rose
        .call_wallet(SPENDER, "getwalletinfo", json!([]))
        .await
        .expect("spender getwalletinfo");
    assert_eq!(wi["private_keys_enabled"], json!(true), "{wi}");
    for wallet in [SPENDER, VIEW] {
        let ai = rose
            .call_wallet(wallet, "getaddressinfo", json!([addr]))
            .await
            .expect("getaddressinfo");
        assert_eq!(ai["ismine"], json!(true), "{wallet}: {ai}");
        assert_eq!(ai["iswatchonly"], json!(false), "{wallet}: {ai}");
        assert_eq!(ai["solvable"], json!(true), "{wallet}: {ai}");
        assert_eq!(ai["ischange"], json!(false), "{wallet}: {ai}");
        assert_eq!(ai["hdkeypath"], json!("m/84'/1'/0'/0/0"), "{wallet}: {ai}");
    }

    // 4. A receive lands on both. Over bitcoind the watch-only wallet sees it at 0-conf
    //    through the mempool pass like any wallet; over kyoto nothing is visible until it
    //    confirms.
    let fund_txid = node
        .call("sendtoaddress", json!([addr, 1.0]))
        .await
        .expect("fund");
    if backend == BtcBackend::Bitcoind {
        rose.wait_wallet(
            VIEW,
            "getunconfirmedbalance",
            json!([]),
            "0-conf receive on the watch-only wallet",
            |v| v.as_f64() == Some(1.0),
        )
        .await;
    }
    node.mine(1).await;
    for wallet in [SPENDER, VIEW] {
        rose.wait_wallet_height(wallet, 102).await;
        rose.wait_wallet_balance(wallet, 1.0).await;
    }
    let unspent = rose
        .call_wallet(VIEW, "listunspent", json!([]))
        .await
        .expect("view listunspent");
    assert_eq!(unspent.as_array().map(Vec::len), Some(1), "{unspent}");
    assert_eq!(unspent[0]["txid"], fund_txid, "{unspent}");
    assert_eq!(unspent[0]["spendable"], json!(false), "no keys: {unspent}");
    assert_eq!(unspent[0]["safe"], json!(true), "{unspent}");
    let unspent = rose
        .call_wallet(SPENDER, "listunspent", json!([]))
        .await
        .expect("spender listunspent");
    assert_eq!(unspent[0]["spendable"], json!(true), "{unspent}");

    // 5. The watch-only wallet cannot spend: Bitcoin Core's -4, before any funds check
    //    (it has the funds), naming the watch-only custody. `walletpassphrase` is not a
    //    method Bitcoin wallets serve at all.
    let miner = node.new_address().await;
    for (method, params) in [
        ("sendtoaddress", json!([miner, 0.1])),
        ("sendmany", json!(["", {miner.clone(): 0.1}])),
    ] {
        let (code, msg) = rose
            .call_wallet(VIEW, method, params)
            .await
            .expect_err("a watch-only send must fail");
        assert_eq!(code, -4, "{method}: {msg}");
        assert!(msg.contains("Private keys are disabled"), "{method}: {msg}");
        assert!(msg.contains("watch-only"), "{method}: {msg}");
    }
    let (code, _) = rose
        .call_wallet(VIEW, "walletpassphrase", json!(["pw", 60]))
        .await
        .expect_err("walletpassphrase is not served for bitcoin wallets");
    assert_eq!(code, -32601);
    // Nothing moved.
    let mempool = node.mempool().await;
    assert!(
        mempool.is_empty(),
        "a refused send broadcast nothing: {mempool:?}"
    );

    // 6. The spender's send shows up on the watch-only side: the send entry, the debit,
    //    and the change output (internal keychain) - all from public descriptors.
    let send_txid = rose
        .call_wallet(SPENDER, "sendtoaddress", json!([miner, 0.25]))
        .await
        .expect("spender send");
    assert!(node
        .mempool()
        .await
        .contains(&send_txid.as_str().unwrap().to_string()));
    node.mine(1).await;
    for wallet in [SPENDER, VIEW] {
        rose.wait_wallet_height(wallet, 103).await;
    }
    let spender_balance = rose
        .call_wallet(SPENDER, "getbalance", json!([]))
        .await
        .expect("spender balance");
    rose.wait_wallet_balance(VIEW, spender_balance.as_f64().unwrap())
        .await;
    assert!(
        spender_balance.as_f64().unwrap() < 0.75 && spender_balance.as_f64().unwrap() > 0.74,
        "1.0 minus 0.25 minus a sat/vB-scale fee: {spender_balance}"
    );
    let txs = rose
        .call_wallet(VIEW, "listtransactions", json!([]))
        .await
        .expect("view listtransactions");
    let send_entry = txs
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["txid"] == send_txid)
        .unwrap_or_else(|| panic!("the spender's send is in the watch-only history: {txs}"));
    assert_eq!(send_entry["category"], json!("send"), "{send_entry}");
    assert_eq!(send_entry["amount"].as_f64(), Some(-0.25), "{send_entry}");
    assert_eq!(send_entry["address"], json!(miner), "{send_entry}");
    assert_eq!(send_entry["confirmations"], json!(1), "{send_entry}");
    let unspent = rose
        .call_wallet(VIEW, "listunspent", json!([]))
        .await
        .expect("view listunspent after the send");
    assert_eq!(unspent.as_array().map(Vec::len), Some(1), "{unspent}");
    assert_eq!(
        unspent[0]["txid"], send_txid,
        "the change output: {unspent}"
    );
    let change = unspent[0]["address"].as_str().expect("change address");
    let ai = rose
        .call_wallet(VIEW, "getaddressinfo", json!([change]))
        .await
        .expect("getaddressinfo on the change");
    assert_eq!(ai["ischange"], json!(true), "{ai}");
    assert_eq!(ai["ismine"], json!(true), "{ai}");

    // 7. The key round trip, read from the live daemon's database (lock-free, like
    //    export-ufvk): the watch-only wallet re-exports exactly what it was built from.
    assert_eq!(
        rose.export_xpub(VIEW).expect("export-xpub on the view"),
        xpub
    );
    assert_eq!(
        rose.export_xpub(SPENDER)
            .expect("export-xpub on the spender"),
        xpub
    );

    // 8. Restart: the pinned key verifies the database (the seedless binding check) and
    //    the balance is intact.
    rose.restart().await;
    rose.wait_wallet_height(VIEW, 103).await;
    let balance = rose
        .call_wallet(VIEW, "getbalance", json!([]))
        .await
        .expect("view balance after restart");
    assert_eq!(
        balance, spender_balance,
        "watch-only balance survives a restart"
    );

    // 9. Rebuild from the pin: with the database gone, the daemon recreates it from the
    //    xpub in keys.toml and rescans to the same balance and history.
    rose.stop();
    let db = rose.wallet_db_path(VIEW);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", db.display()));
    }
    assert!(!db.exists());
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    rose.start().await;
    rose.wait_wallet_height(VIEW, 103).await;
    rose.wait_wallet_balance(VIEW, spender_balance.as_f64().unwrap())
        .await;
    let txs = rose
        .call_wallet(VIEW, "listtransactions", json!([]))
        .await
        .expect("view listtransactions after the rebuild");
    let txids: Vec<&str> = txs
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["txid"].as_str())
        .collect();
    assert!(
        txids.contains(&fund_txid.as_str().unwrap())
            && txids.contains(&send_txid.as_str().unwrap()),
        "the rebuilt watch-only wallet recovered both transactions: {txs}"
    );
    let wi = rose
        .call_wallet(VIEW, "getwalletinfo", json!([]))
        .await
        .expect("view getwalletinfo after the rebuild");
    assert_eq!(wi["private_keys_enabled"], json!(false), "{wi}");
}
