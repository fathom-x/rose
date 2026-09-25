//! A node whose fee estimator has no usable data, live over the bitcoind
//! backend. Testnet4's estimator answered 361 sat/vB at every target while blocks cleared
//! at 1, and a bitcoind-backed wallet paid it on every send. Regtest reproduces the shape:
//! when every transaction the node ever saw paid the same rate and confirmed in the next
//! block, `estimatesmartfee` answers that rate at every target, 2 through 1008.
//!
//! 1. The node's curve is flat at 50 sat/vB (the precondition).
//! 2. On a test network zecd treats a flat curve above the floor as no estimate:
//!    `estimatesmartfee` answers Core's `errors` shape.
//! 3. A send without `fee_rate` takes the test-network fallback, 1 sat/vB, and says so in
//!    `fee_reason`.
//!
//! Skips cleanly without a bitcoind or a zecd built without the `bitcoin` feature.

use serde_json::{json, Value};
use zecd_regtest_harness::btc::{provisioned, BitcoinD, BtcBackend, ZecdBtc};

/// A BTC amount as satoshis.
fn sats(v: &Value) -> u64 {
    (v.as_f64().expect("an amount") * 1e8).round() as u64
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_a_flat_node_fee_curve_is_no_estimate_on_a_test_network() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(bitcoind) = provisioned(dir.path()) else {
        return;
    };
    let node = BitcoinD::start(&bitcoind, &dir.path().join("btcdata")).await;
    node.mine(150).await;

    // The node's whole fee history: five 50 sat/vB payments in each of 40 blocks.
    let miner = node.new_address().await;
    for _ in 0..40 {
        for _ in 0..5 {
            node.call(
                "sendtoaddress",
                json!([miner, 0.1, null, null, false, null, null, null, null, 50]),
            )
            .await
            .expect("a 50 sat/vB payment");
        }
        node.mine(1).await;
    }

    // 1. Flat: the same rate at the fastest target and the slowest.
    for target in [2, 1008] {
        let estimate = node
            .call("estimatesmartfee", json!([target]))
            .await
            .expect("node estimatesmartfee");
        let per_kvb = sats(&estimate["feerate"]);
        assert!(
            (50_000..51_000).contains(&per_kvb),
            "target {target}: {estimate}"
        );
    }

    let mut zecd = ZecdBtc::prepare(
        dir.path().join("zecddata"),
        BtcBackend::Bitcoind,
        &node,
        &["btc"],
    );
    zecd.init_ok("btc", &["--birthday", "0"]);
    zecd.start().await;
    zecd.wait_height(190).await;
    let addr = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    node.call("sendtoaddress", json!([addr, 1.0]))
        .await
        .expect("fund");
    node.mine(1).await;
    zecd.wait_height(191).await;
    zecd.wait_wallet_balance("btc", 1.0).await;

    // 2. No estimate.
    let estimate = zecd
        .call("estimatesmartfee", json!([6]))
        .await
        .expect("estimatesmartfee");
    assert!(estimate.get("feerate").is_none(), "{estimate}");
    assert!(estimate["errors"].is_array(), "{estimate}");

    // 3. The send takes the fallback, not the node's 50 sat/vB.
    let sent = zecd
        .call(
            "sendtoaddress",
            json!([miner, 0.1, null, null, false, null, null, null, null, null, true]),
        )
        .await
        .expect("a send with no fee_rate");
    assert_eq!(sent["fee_reason"], json!("Fallback fee"), "{sent}");
    let txid = sent["txid"].as_str().unwrap().to_string();
    node.wait_mempool_contains(&txid).await;
    let entry = node
        .call("getmempoolentry", json!([txid]))
        .await
        .expect("getmempoolentry");
    let fee = sats(&entry["fees"]["base"]);
    let vsize = entry["vsize"].as_u64().unwrap();
    assert!(fee <= 2 * vsize, "priced at the fallback: {entry}");
}
