//! End-to-end test of the kyoto backend's opt-in 0-conf feed over its **P2P source**
//! (`[mempool] sources = ["p2p"]`, `src/btc/p2p_feed.rs`) against a real regtest Bitcoin
//! Core - the first live exercise of zecd's own relay client: the handshake, the node
//! announcing its mempool to us, and BIP 35 `mempool` snapshots, which need the node to grant
//! this host the `mempool` permission (`-whitelist=mempool@127.0.0.1`; Core disconnects an
//! unpermissioned peer that asks, so the flag is load-bearing).
//!
//! The walk, on a kyoto wallet peered with the node:
//!
//! 1. the feed reports `connected` on `getwalletinfo.mempool_feed`, on the node's P2P port;
//! 2. a payment from the node's wallet shows in `getunconfirmedbalance`,
//!    `listtransactions` and `listunspent 0` **before its block** - the posture the plain
//!    kyoto suite pins the opposite of - and its block then confirms it without a second
//!    history entry (the filter scan anchors the same transaction the feed applied);
//! 3. an RBF replacement (`bumpfee` on the node, same recipient) supersedes the original:
//!    the replacement arrives over relay and BDK's canonicalization drops the conflicting
//!    original, so the 0-conf balance never double-counts, and the replacement confirms;
//! 4. a receive whose input is then **double-spent away** (a replacement paying only the
//!    node's wallet, which the feed never sees since it touches nothing of ours) is the one
//!    case only a snapshot can settle: the node no longer lists it, the actor queues the
//!    eviction, the next scan tip retires it, and the unconfirmed balance returns to zero
//!    while the confirmed balance stands.
//!
//! Skips cleanly without a bitcoind (`BITCOIND_BIN` or PATH) or a zecd built without the
//! `bitcoin` feature - the same two probes as `regtest_btc.rs`.

use std::time::{Duration, Instant};

use serde_json::{json, Value};
use zecd_regtest_harness::btc::{provisioned, BitcoinD, BtcBackend, ZecdBtc, SYNC_TIMEOUT};

/// The node-side grant the snapshot requests need. Loopback covers both the P2P feed and
/// kyoto's own connection (harmless: kyoto never asks).
const MEMPOOL_PERMISSION: &str = "-whitelist=mempool@127.0.0.1";

/// Whole-satoshi amounts as the 8-decimal strings Core's raw-transaction RPCs accept -
/// float arithmetic would hand them more decimals than they take.
fn btc(sats: u64) -> Value {
    Value::String(format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000))
}

fn sats(amount: &Value) -> u64 {
    (amount.as_f64().expect("an amount") * 1e8).round() as u64
}

async fn feed_status(zecd: &ZecdBtc) -> Value {
    zecd.call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo")["mempool_feed"]
        .clone()
}

/// The history entries for `txid` (a receive is one entry per wallet-relevant output).
async fn history_for(zecd: &ZecdBtc, txid: &str) -> Vec<Value> {
    zecd.call("listtransactions", json!(["*", 100]))
        .await
        .expect("listtransactions")
        .as_array()
        .expect("an array")
        .iter()
        .filter(|e| e["txid"] == json!(txid))
        .cloned()
        .collect()
}

/// Until `gettransaction txid` answers Core's `-5` (not a wallet transaction): what a
/// replaced or evicted transaction becomes.
async fn wait_forgotten(zecd: &ZecdBtc, txid: &str, why: &str) {
    let deadline = Instant::now() + SYNC_TIMEOUT;
    loop {
        match zecd.call("gettransaction", json!([txid])).await {
            Err((-5, _)) => return,
            other => assert!(
                Instant::now() < deadline,
                "{txid} was never forgotten ({why}); last gettransaction: {other:?}"
            ),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_p2p_mempool_feed_gives_the_kyoto_wallet_zero_conf() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(bitcoind) = provisioned(dir.path()) else {
        return;
    };
    let node = BitcoinD::start_with(
        &bitcoind,
        &dir.path().join("btcdata"),
        &[MEMPOOL_PERMISSION],
    )
    .await;
    node.mine(101).await;

    // A short snapshot interval so step 4's eviction lands inside the suite's budget: the
    // node re-lists its mempool every ten seconds, and each answer is collected for the
    // source's thirty-second window before it reaches the actor.
    let mut zecd = ZecdBtc::prepare_full(
        dir.path().join("zecddata"),
        BtcBackend::Kyoto,
        &node,
        &["btc"],
        "",
        "[mempool]\nsources = [\"p2p\"]\np2p_snapshot = true\np2p_snapshot_interval_secs = 10\n",
    );
    zecd.init_ok("btc", &["--birthday", "0"]);
    zecd.start().await;
    zecd.wait_height(101).await;

    // 1. The feed is up, on the node the wallet already peers with.
    zecd.wait_wallet(
        "btc",
        "getwalletinfo",
        json!([]),
        "mempool feed connected",
        |v| v["mempool_feed"]["state"] == json!("connected"),
    )
    .await;
    let feed = feed_status(&zecd).await;
    assert_eq!(feed["source"], json!("p2p"), "{feed}");
    let endpoint = feed["endpoint"].as_str().expect("an endpoint");
    assert!(
        endpoint.starts_with(&format!("p2p://127.0.0.1:{}", node.p2p_port)),
        "{endpoint}"
    );
    assert!(
        endpoint.contains("mempool snapshots every 10s"),
        "{endpoint}"
    );

    // 2. A 0-conf receive over relay, confirmed by the filter scan without duplication.
    let addr = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress")
        .as_str()
        .expect("an address")
        .to_string();
    let txid1 = node
        .call("sendtoaddress", json!([addr, 0.5]))
        .await
        .expect("sendtoaddress")
        .as_str()
        .expect("a txid")
        .to_string();
    zecd.wait_unconfirmed(0.5).await;
    let pending = history_for(&zecd, &txid1).await;
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert_eq!(pending[0]["category"], json!("receive"));
    assert_eq!(pending[0]["confirmations"], json!(0));
    assert_eq!(pending[0]["amount"].as_f64(), Some(0.5));
    let unsafe_utxos = zecd
        .call("listunspent", json!([0]))
        .await
        .expect("listunspent 0");
    assert_eq!(
        unsafe_utxos.as_array().map(Vec::len),
        Some(1),
        "{unsafe_utxos}"
    );
    assert_eq!(unsafe_utxos[0]["txid"], json!(txid1));
    let safe_utxos = zecd
        .call("listunspent", json!([]))
        .await
        .expect("listunspent");
    assert_eq!(safe_utxos.as_array().map(Vec::len), Some(0), "{safe_utxos}");
    assert_eq!(
        zecd.call("getbalance", json!([]))
            .await
            .expect("getbalance")
            .as_f64(),
        Some(0.0)
    );

    node.mine(1).await;
    zecd.wait_height(102).await;
    zecd.wait_wallet_balance("btc", 0.5).await;
    zecd.wait_unconfirmed(0.0).await;
    let confirmed = history_for(&zecd, &txid1).await;
    assert_eq!(
        confirmed.len(),
        1,
        "duplicated on confirmation: {confirmed:?}"
    );
    assert_eq!(confirmed[0]["confirmations"], json!(1));
    let feed = feed_status(&zecd).await;
    assert!(feed["matched"].as_u64() >= Some(1), "{feed}");
    assert!(feed["last_delta"].is_u64(), "{feed}");

    // 3. An RBF replacement paying the same address: the replacement arrives over relay,
    // the original drops out of the wallet's view, and nothing is counted twice.
    let txid2 = node
        .call("sendtoaddress", json!([addr, 0.3, "", "", false, true]))
        .await
        .expect("sendtoaddress (replaceable)")
        .as_str()
        .expect("a txid")
        .to_string();
    zecd.wait_unconfirmed(0.3).await;
    let bumped = node
        .call("bumpfee", json!([txid2, {"fee_rate": 50}]))
        .await
        .expect("bumpfee");
    let txid3 = bumped["txid"].as_str().expect("a txid").to_string();
    assert_ne!(txid3, txid2);
    zecd.wait_wallet(
        "btc",
        "gettransaction",
        json!([txid3]),
        "the replacement arrives at 0-conf",
        |v| v["confirmations"] == json!(0) && v["amount"].as_f64() == Some(0.3),
    )
    .await;
    wait_forgotten(&zecd, &txid2, "replaced by fee").await;
    assert_eq!(
        zecd.call("getunconfirmedbalance", json!([]))
            .await
            .expect("getunconfirmedbalance")
            .as_f64(),
        Some(0.3),
        "the replacement alone is pending"
    );
    node.mine(1).await;
    zecd.wait_height(103).await;
    zecd.wait_wallet_balance("btc", 0.8).await;
    zecd.wait_unconfirmed(0.0).await;
    assert_eq!(history_for(&zecd, &txid3).await.len(), 1);
    assert!(history_for(&zecd, &txid2).await.is_empty());

    // 4. A receive double-spent away from the wallet: only a snapshot can settle it.
    let utxos = node
        .call("listunspent", json!([]))
        .await
        .expect("node listunspent");
    let utxo = utxos
        .as_array()
        .expect("an array")
        .iter()
        .find(|u| sats(&u["amount"]) >= 100_000_000)
        .expect("a mature coinbase to spend")
        .clone();
    let input = json!([{"txid": utxo["txid"], "vout": utxo["vout"]}]);
    let value = sats(&utxo["amount"]);
    let miner_addr = node.new_address().await;
    let raw4 = node
        .call(
            "createrawtransaction",
            json!([
                input,
                [{ &addr: btc(20_000_000) }, { &miner_addr: btc(value - 20_000_000 - 10_000) }],
                0,
                true
            ]),
        )
        .await
        .expect("createrawtransaction");
    let signed4 = node
        .call("signrawtransactionwithwallet", json!([raw4]))
        .await
        .expect("signrawtransactionwithwallet");
    assert_eq!(signed4["complete"], json!(true), "{signed4}");
    let txid4 = node
        .call("sendrawtransaction", json!([signed4["hex"]]))
        .await
        .expect("sendrawtransaction")
        .as_str()
        .expect("a txid")
        .to_string();
    zecd.wait_unconfirmed(0.2).await;
    // The replacement spends the same input to the node's own wallet at a higher fee: the
    // node drops the receive for it, and nothing about it reaches the wallet over relay
    // (no output of ours, no input we hold).
    let raw5 = node
        .call(
            "createrawtransaction",
            json!([input, [{ &miner_addr: btc(value - 100_000) }], 0, true]),
        )
        .await
        .expect("createrawtransaction (replacement)");
    let signed5 = node
        .call("signrawtransactionwithwallet", json!([raw5]))
        .await
        .expect("signrawtransactionwithwallet (replacement)");
    let txid5 = node
        .call("sendrawtransaction", json!([signed5["hex"]]))
        .await
        .expect("sendrawtransaction (replacement)")
        .as_str()
        .expect("a txid")
        .to_string();
    let mempool = node.mempool().await;
    assert!(mempool.contains(&txid5), "{mempool:?}");
    assert!(!mempool.contains(&txid4), "{mempool:?}");
    // Mine the replacement, then keep the chain moving: each block is a scan tip at which
    // a settled snapshot's eviction takes effect. The node re-lists its mempool every ten
    // seconds and the source collects each answer for thirty, so a few blocks suffice; a
    // rebroadcast of the dead receive at any of these tips is rejected by the node (its
    // input is spent by a confirmed transaction) and changes nothing.
    node.mine(1).await;
    let mut height = 104;
    zecd.wait_height(height).await;
    let deadline = Instant::now() + SYNC_TIMEOUT;
    loop {
        let pending = zecd
            .call("getunconfirmedbalance", json!([]))
            .await
            .expect("getunconfirmedbalance")
            .as_f64();
        let forgotten = matches!(
            zecd.call("gettransaction", json!([txid4])).await,
            Err((-5, _))
        );
        if pending == Some(0.0) && forgotten {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the double-spent receive {txid4} was never evicted (pending {pending:?}, \
             forgotten {forgotten}); feed: {}",
            feed_status(&zecd).await
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
        node.mine(1).await;
        height += 1;
        zecd.wait_height(height).await;
    }
    assert_eq!(
        zecd.call("getbalance", json!([]))
            .await
            .expect("getbalance")
            .as_f64(),
        Some(0.8),
        "the confirmed balance is untouched by the eviction"
    );
    let feed = feed_status(&zecd).await;
    assert_eq!(feed["state"], json!("connected"), "{feed}");
    assert!(feed["matched"].as_u64() >= Some(3), "{feed}");
    assert_eq!(feed["dropped"], json!(0), "{feed}");
}
