//! `bumpfee` (BIP 125 replacement) live, over both chain sources. A send priced at the
//! 1 sat/vB relay floor is bumped until it confirms, and every one of Core's preconditions
//! is exercised on the way:
//!
//! 1. **A rate under the replacement rules is refused** (`-8`): an explicit `fee_rate` no
//!    higher than the original's cannot replace it.
//! 2. **The default bump replaces the send in the network and in the wallet.** The node's
//!    mempool holds the replacement and no longer the original (Core accepted it as a
//!    BIP 125 replacement - over kyoto that is the light client's announcement, nothing in
//!    the test relays it); the wallet reports the original as gone (`-5`), the replacement
//!    as its send, and a balance charged the replacement's fee - once, not twice. The
//!    answer is Core's `{txid, origfee, fee, errors}`, `fee` above `origfee`.
//! 3. **The replaced original cannot be bumped again** (`-4`, naming the replacement).
//! 4. **A bump with `replaceable = false`** replaces the replacement, and the result stops
//!    signalling BIP 125, so a further bump is Core's `-4` "not BIP 125 replaceable".
//! 5. **It confirms**: mined, the wallet shows it confirmed at its final fee, and a bump of
//!    a mined transaction is `-4` "has been mined".
//! 6. **A transaction with a wallet descendant is refused** (`-8`): a second send spending
//!    the first send's unconfirmed change would be evicted by the replacement.
//!
//! The wallet stamps a replacement's sighting after its original's (the actor's
//! `commit_before_relay` floor), so step 2 immediately after the send - the same second,
//! usually - is the case that floor exists for. Skips cleanly without a bitcoind or a rose
//! built without the `bitcoin` feature.

use rose_regtest_harness::btc::{provisioned, BitcoinD, BtcBackend, RoseBtc};
use serde_json::{json, Value};

#[tokio::test(flavor = "multi_thread")]
async fn btc_bumpfee_replaces_a_send_over_bitcoind() {
    bumpfee_flow(BtcBackend::Bitcoind).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_bumpfee_replaces_a_send_over_kyoto() {
    bumpfee_flow(BtcBackend::Kyoto).await;
}

/// `sendtoaddress` with an explicit `fee_rate` (param 9, sat/vB), off the estimator.
fn send_params(to: &str, amount: f64, fee_rate: u32) -> Value {
    json!([to, amount, null, null, false, null, null, null, null, fee_rate])
}

/// A BTC amount as satoshis, from the 8-decimal JSON numbers rose answers with.
fn sats(v: &Value) -> u64 {
    (v.as_f64().expect("an amount") * 1e8).round() as u64
}

async fn bumpfee_flow(backend: BtcBackend) {
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

    let addr = rose
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let addr = addr.as_str().unwrap().to_string();
    node.call("sendtoaddress", json!([addr, 1.0]))
        .await
        .expect("fund");
    node.mine(1).await;
    rose.wait_height(102).await;
    rose.wait_wallet_balance("btc", 1.0).await;
    let miner = node.new_address().await;

    let original = rose
        .call("sendtoaddress", send_params(&miner, 0.1, 1))
        .await
        .expect("a 1 sat/vB send");
    let original = original.as_str().unwrap().to_string();
    node.wait_mempool_contains(&original).await;

    // 1. No higher than the original's rate: refused, nothing replaced.
    let (code, msg) = rose
        .call("bumpfee", json!([original, {"fee_rate": 1}]))
        .await
        .expect_err("a bump at the original's rate");
    assert_eq!(code, -8, "{msg}");
    assert!(msg.contains("Insufficient fee rate"), "{msg}");

    // 2. The default bump.
    let bumped = rose
        .call("bumpfee", json!([original]))
        .await
        .expect("bumpfee");
    let replacement = bumped["txid"].as_str().unwrap().to_string();
    assert_ne!(replacement, original);
    assert_eq!(bumped["errors"], json!([]), "{bumped}");
    let (origfee, fee) = (sats(&bumped["origfee"]), sats(&bumped["fee"]));
    assert!(fee > origfee, "{bumped}");
    node.wait_mempool_contains(&replacement).await;
    let mempool = node.mempool().await;
    assert!(
        !mempool.contains(&original),
        "the node replaced the original: {mempool:?}"
    );
    let (code, msg) = rose
        .call("gettransaction", json!([original]))
        .await
        .expect_err("the replaced original left the wallet's view");
    assert_eq!(code, -5, "{msg}");
    let tx = rose
        .call("gettransaction", json!([replacement]))
        .await
        .expect("gettransaction replacement");
    // Core reports a send's fee negative.
    assert_eq!(sats(&json!(-tx["fee"].as_f64().unwrap())), fee, "{tx}");
    assert_eq!(tx["bip125-replaceable"], json!("yes"), "{tx}");
    // Charged once, at the replacement's fee: the original's input is spent by the
    // replacement alone, and its change is the one change output.
    let balance = rose
        .call("getbalances", json!([]))
        .await
        .expect("getbalances");
    let mine = &balance["mine"];
    assert_eq!(
        sats(&mine["trusted"]) + sats(&mine["untrusted_pending"]),
        100_000_000 - 10_000_000 - fee,
        "{balance}"
    );

    // 3. The original is already replaced.
    let (code, msg) = rose
        .call("bumpfee", json!([original]))
        .await
        .expect_err("bumping the replaced original");
    assert_eq!(code, -4, "{msg}");
    assert!(msg.contains("already been bumped"), "{msg}");
    assert!(msg.contains(&replacement), "{msg}");

    // 4. Bump the replacement, opting out of BIP 125: the result cannot be bumped again.
    let final_bump = rose
        .call("bumpfee", json!([replacement, {"replaceable": false}]))
        .await
        .expect("bumpfee replaceable=false");
    let final_txid = final_bump["txid"].as_str().unwrap().to_string();
    let final_fee = sats(&final_bump["fee"]);
    assert_eq!(sats(&final_bump["origfee"]), fee, "{final_bump}");
    assert!(final_fee > fee, "{final_bump}");
    node.wait_mempool_contains(&final_txid).await;
    let tx = rose
        .call("gettransaction", json!([final_txid]))
        .await
        .expect("gettransaction final");
    assert_eq!(tx["bip125-replaceable"], json!("no"), "{tx}");
    let (code, msg) = rose
        .call("bumpfee", json!([final_txid]))
        .await
        .expect_err("bumping a non-replaceable transaction");
    assert_eq!(code, -4, "{msg}");
    assert!(msg.contains("not BIP 125 replaceable"), "{msg}");

    // 5. Mined at the final fee.
    let mempool = node.mempool().await;
    assert_eq!(
        mempool,
        vec![final_txid.clone()],
        "only the final replacement"
    );
    node.mine(1).await;
    rose.wait_height(103).await;
    let expected = 100_000_000 - 10_000_000 - final_fee;
    rose.wait_wallet(
        "btc",
        "getbalance",
        json!([]),
        &format!("confirmed balance of {expected} sat"),
        |v| sats(v) == expected,
    )
    .await;
    let (code, msg) = rose
        .call("bumpfee", json!([final_txid]))
        .await
        .expect_err("bumping a mined transaction");
    assert_eq!(code, -4, "{msg}");
    assert!(msg.contains("has been mined"), "{msg}");

    // 6. A wallet descendant blocks the bump: the second send can only spend the first's
    //    unconfirmed change (the wallet's one output), so replacing the first would evict it.
    let parent = rose
        .call("sendtoaddress", send_params(&miner, 0.1, 2))
        .await
        .expect("parent send");
    let parent = parent.as_str().unwrap().to_string();
    node.wait_mempool_contains(&parent).await;
    let child = rose
        .call("sendtoaddress", send_params(&miner, 0.1, 2))
        .await
        .expect("child send, spending the parent's change");
    let child = child.as_str().unwrap().to_string();
    let child_tx = rose
        .call("gettransaction", json!([child]))
        .await
        .expect("gettransaction child");
    assert!(
        child_tx["hex"].as_str().is_some(),
        "the child is the wallet's: {child_tx}"
    );
    let (code, msg) = rose
        .call("bumpfee", json!([parent]))
        .await
        .expect_err("bumping a transaction with a wallet descendant");
    assert_eq!(code, -8, "{msg}");
    assert!(msg.contains("descendants in the wallet"), "{msg}");
    node.wait_mempool_contains(&child).await;
    node.mine(1).await;
    rose.wait_height(104).await;
}
