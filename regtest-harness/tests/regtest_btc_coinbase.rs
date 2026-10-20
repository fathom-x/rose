//! Coinbase maturity on the Bitcoin engine's read path, over both chain sources. A block
//! paid to one of the wallet's addresses is a reward the wallet cannot spend for
//! `COINBASE_MATURITY` (100) blocks, and Core's read RPCs say so: `listunspent` withholds
//! the output, a depth-filtered `getbalance` excludes it, and `getbalances.mine.immature`
//! is where the value shows. BDK's `list_unspent` has no maturity filter, so before the
//! fix `listunspent` and `getbalance 1` counted the reward as spendable the
//! block after it was mined while `getbalances` called it immature - and BDK's own
//! maturity bound is a block earlier than Core's (mature at 100 confirmations, where Core
//! waits for 101), so the actor applies Core's rule to both reads; the 100-confirmation
//! step below is the block on which the two disagree.
//!
//! What it pins: at one confirmation the reward is immature everywhere - `listunspent`
//! (default and `listunspent 1`) is empty, `getbalance`/`getbalance 1` are zero,
//! `getbalances.mine.immature` holds the subsidy; once the block has 100 on top of it
//! (101 confirmations) the same reads flip together - the output is listed, the
//! balances count it, `immature` is zero - and the actual spendability follows: the
//! spender sends the matured reward. Over kyoto the wallet sees the coinbase through
//! the block filters like any other output; the maturity rule is the wallet's own.
//!
//! Skips cleanly without a bitcoind (`BITCOIND_BIN` or PATH) or a rose built without the
//! `bitcoin` feature - the same two probes as `regtest_btc.rs`.

use rose_regtest_harness::btc::{provisioned, BitcoinD, BtcBackend, RoseBtc};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn btc_immature_coinbase_is_withheld_until_maturity_over_bitcoind() {
    coinbase_flow(BtcBackend::Bitcoind).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_immature_coinbase_is_withheld_until_maturity_over_kyoto() {
    coinbase_flow(BtcBackend::Kyoto).await;
}

async fn coinbase_flow(backend: BtcBackend) {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(bitcoind) = provisioned(dir.path()) else {
        return;
    };
    let node = BitcoinD::start(&bitcoind, &dir.path().join("btcdata")).await;
    node.mine(101).await;

    let mut rose = RoseBtc::prepare(dir.path().join("rosedata"), backend, &node, &["btc"]);
    rose.init_ok("btc", &["--birthday", "0"]);
    rose.start().await;
    rose.wait_height(101).await;

    // A block paid to the wallet: the regtest subsidy is still 50 BTC at this height.
    let reward_addr = rose
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let reward_addr = reward_addr.as_str().unwrap().to_string();
    node.mine_to(&reward_addr, 1).await;
    rose.wait_height(102).await;
    rose.wait_wallet(
        "btc",
        "getbalances",
        json!([]),
        "the reward shows as immature",
        |v| v["mine"]["immature"].as_f64() == Some(50.0),
    )
    .await;

    // 1. One confirmation: immature on every read.
    let balances = rose
        .call("getbalances", json!([]))
        .await
        .expect("getbalances");
    assert_eq!(balances["mine"]["trusted"], json!(0.0), "{balances}");
    assert_eq!(balances["mine"]["immature"], json!(50.0), "{balances}");
    for params in [json!([]), json!([1])] {
        let unspent = rose
            .call("listunspent", params.clone())
            .await
            .expect("listunspent");
        assert_eq!(
            unspent,
            json!([]),
            "[{}] listunspent {params} must withhold the immature coinbase",
            backend.label()
        );
    }
    for params in [json!([]), json!(["*", 1])] {
        let balance = rose
            .call("getbalance", params.clone())
            .await
            .expect("getbalance");
        assert_eq!(
            balance,
            json!(0.0),
            "[{}] getbalance {params} must exclude the immature coinbase",
            backend.label()
        );
    }
    let wi = rose
        .call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo");
    assert_eq!(wi["balance"], json!(0.0), "{wi}");
    assert_eq!(wi["immature_balance"], json!(50.0), "{wi}");

    // 2. Ninety-nine more blocks on top: 100 confirmations, still one short.
    node.mine(99).await;
    rose.wait_height(201).await;
    let unspent = rose
        .call("listunspent", json!([]))
        .await
        .expect("listunspent at 100 confirmations");
    assert_eq!(
        unspent,
        json!([]),
        "[{}] one short of maturity",
        backend.label()
    );
    let balances = rose
        .call("getbalances", json!([]))
        .await
        .expect("getbalances at 100 confirmations");
    assert_eq!(balances["mine"]["immature"], json!(50.0), "{balances}");

    // 3. The hundredth block on top: matured, and every read flips together.
    node.mine(1).await;
    rose.wait_height(202).await;
    rose.wait_wallet_balance("btc", 50.0).await;
    let unspent = rose
        .call("listunspent", json!([]))
        .await
        .expect("listunspent at maturity");
    let unspent = unspent.as_array().expect("array");
    assert_eq!(unspent.len(), 1, "[{}] {unspent:?}", backend.label());
    assert_eq!(unspent[0]["address"], json!(reward_addr), "{unspent:?}");
    assert_eq!(unspent[0]["amount"], json!(50.0), "{unspent:?}");
    assert_eq!(unspent[0]["confirmations"], json!(101), "{unspent:?}");
    assert_eq!(unspent[0]["safe"], json!(true), "{unspent:?}");
    let balances = rose
        .call("getbalances", json!([]))
        .await
        .expect("getbalances at maturity");
    assert_eq!(balances["mine"]["trusted"], json!(50.0), "{balances}");
    assert_eq!(balances["mine"]["immature"], json!(0.0), "{balances}");
    let balance = rose
        .call("getbalance", json!(["*", 1]))
        .await
        .expect("getbalance 1 at maturity");
    assert_eq!(balance, json!(50.0));

    // 4. And it spends: the matured reward funds a send.
    let dest = node.new_address().await;
    let txid = rose
        .call("sendtoaddress", json!([dest, 1.0]))
        .await
        .expect("send from the matured reward");
    assert!(txid.as_str().is_some_and(|t| t.len() == 64), "{txid}");
    node.mine(1).await;
    rose.wait_height(203).await;
    let tx = rose
        .call("gettransaction", json!([txid]))
        .await
        .expect("gettransaction");
    assert_eq!(tx["confirmations"], json!(1), "{tx}");
}
