//! Ancestor-aware funding live, over both chain sources: a send that spends the change of
//! an unconfirmed cheap send pays for that parent, so the pair confirms at the child's
//! rate. This is the wallet's CPFP (Core since 26.0 does the same).
//!
//! 1. **A 1 sat/vB send** leaves its change as the wallet's only coin.
//! 2. **A 20 sat/vB send** can only spend that change. The node's own view of the child
//!    (`getmempoolentry`) is the proof: its ancestor fee rate, the pair's, clears 20 sat/vB,
//!    not just the child alone.
//! 3. **A foreign sender's unconfirmed payment is not spent** (Core's untrusted rule, which
//!    ancestor pricing needs: the wallet cannot price a stranger's parents). With only it
//!    and the trusted change to draw on, a send larger than the change is `-6`.
//! 4. **Both confirm** in the next block.
//!
//! Skips cleanly without a bitcoind or a zecd built without the `bitcoin` feature.

use serde_json::{json, Value};
use zecd_regtest_harness::btc::{provisioned, BitcoinD, BtcBackend, ZecdBtc};

#[tokio::test(flavor = "multi_thread")]
async fn btc_a_send_pays_for_its_unconfirmed_parent_over_bitcoind() {
    ancestors_flow(BtcBackend::Bitcoind).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_a_send_pays_for_its_unconfirmed_parent_over_kyoto() {
    ancestors_flow(BtcBackend::Kyoto).await;
}

/// `sendtoaddress` with an explicit `fee_rate` (param 9, sat/vB), off the estimator.
fn send_params(to: &str, amount: f64, fee_rate: u32) -> Value {
    json!([to, amount, null, null, false, null, null, null, null, fee_rate])
}

/// A BTC amount as satoshis, from the 8-decimal JSON numbers zecd and the node answer with.
fn sats(v: &Value) -> u64 {
    (v.as_f64().expect("an amount") * 1e8).round() as u64
}

async fn ancestors_flow(backend: BtcBackend) {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(bitcoind) = provisioned(dir.path()) else {
        return;
    };
    let node = BitcoinD::start(&bitcoind, &dir.path().join("btcdata")).await;
    node.mine(101).await;
    let mut zecd = ZecdBtc::prepare(dir.path().join("zecddata"), backend, &node, &["btc"]);
    zecd.init_ok("btc", &["--birthday", "0"]);
    zecd.start().await;
    zecd.wait_height(101).await;

    let addr = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let addr = addr.as_str().unwrap().to_string();
    node.call("sendtoaddress", json!([addr, 1.0]))
        .await
        .expect("fund");
    node.mine(1).await;
    zecd.wait_height(102).await;
    zecd.wait_wallet_balance("btc", 1.0).await;
    let miner = node.new_address().await;

    // 1. The cheap parent.
    let parent = zecd
        .call("sendtoaddress", send_params(&miner, 0.1, 1))
        .await
        .expect("a 1 sat/vB send");
    let parent = parent.as_str().unwrap().to_string();
    node.wait_mempool_contains(&parent).await;
    let parent_entry = node
        .call("getmempoolentry", json!([parent]))
        .await
        .expect("getmempoolentry parent");
    let parent_fee = sats(&parent_entry["fees"]["base"]);
    let parent_vsize = parent_entry["vsize"].as_u64().unwrap();
    assert!(parent_fee < 2 * parent_vsize, "{parent_entry}");

    // 2. The child, spending the parent's change - the only coin.
    let child = zecd
        .call("sendtoaddress", send_params(&miner, 0.1, 20))
        .await
        .expect("a 20 sat/vB send from unconfirmed change");
    let child = child.as_str().unwrap().to_string();
    node.wait_mempool_contains(&child).await;
    let entry = node
        .call("getmempoolentry", json!([child]))
        .await
        .expect("getmempoolentry child");
    assert_eq!(entry["depends"], json!([parent]), "{entry}");
    let ancestor_fee = sats(&entry["fees"]["ancestor"]);
    let ancestor_vsize = entry["ancestorsize"].as_u64().unwrap();
    // BDK prices the child by weight, so over the node's rounded-up vsize it can read up
    // to one vbyte's worth under (561 WU is 140.25 vB, counted as 141); anything more is
    // the parent left unpaid, which would be 19 sat/vB of the parent's size.
    assert!(
        ancestor_fee + 20 >= 20 * ancestor_vsize,
        "the pair pays {ancestor_fee} sat over {ancestor_vsize} vB, under 20 sat/vB: {entry}"
    );
    let child_fee = sats(&entry["fees"]["base"]);
    let child_vsize = entry["vsize"].as_u64().unwrap();
    assert!(
        child_fee > 20 * child_vsize + 10 * parent_vsize,
        "the child pays for its parent: {entry}"
    );

    // 3. A foreign unconfirmed payment is not a funding source: over bitcoind the wallet
    //    sees it at 0-conf (untrusted), over kyoto without a feed it does not see it yet;
    //    either way only the child's change (under 0.8) is spendable.
    node.call("sendtoaddress", json!([addr, 0.5]))
        .await
        .expect("an unconfirmed payment to the wallet");
    if matches!(backend, BtcBackend::Bitcoind) {
        zecd.wait_wallet(
            "btc",
            "getunconfirmedbalance",
            json!([]),
            "the 0-conf receive",
            |v| sats(v) == 50_000_000,
        )
        .await;
    }
    let (code, msg) = zecd
        .call("sendtoaddress", send_params(&miner, 1.0, 2))
        .await
        .expect_err("a send the trusted balance cannot cover");
    assert_eq!(code, -6, "{msg}");

    // 4. Mined together.
    node.mine(1).await;
    zecd.wait_height(103).await;
    for txid in [&parent, &child] {
        let tx = zecd
            .call("gettransaction", json!([txid]))
            .await
            .expect("gettransaction");
        assert_eq!(tx["confirmations"], json!(1), "{tx}");
    }
}
