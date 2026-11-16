//! The spending policy (`[wallets.<name>.spend_policy]`) live, on a Bitcoin wallet
//! with an allowlist of one node address, a 0.3 BTC per-send cap and a 0.5 BTC cap over
//! the 144-block window:
//!
//! 1. `getwalletinfo.spend_policy` reports the rules and the whole allowance left.
//! 2. A send to an address off the allowlist is `-4` naming `allow_recipients`; one over
//!    the per-send cap is `-4` naming `max_per_transaction_sat`. Neither reaches the node.
//! 3. A self-send larger than both caps passes: the wallet's own outputs are exempt.
//! 4. Two allowlisted sends fill the window exactly (0.3 + 0.2); a third that would pass
//!    it is `-4` naming `max_per_day_sat`, and `bumpfee` of the last one still passes (a
//!    replacement counts in place of its original).
//! 5. After a restart the window total is the same (it is read from the wallet's history,
//!    not kept in memory), and a send is still refused.
//! 6. Once the two sends are 144 blocks deep they leave the window and a send passes.
//!
//! The policy is checked in the engine, on the built transaction, the same way over
//! either chain source, so this runs over bitcoind only. Skips cleanly without a bitcoind
//! or a rose built without the `bitcoin` feature.

use rose_regtest_harness::btc::{provisioned, BitcoinD, BtcBackend, RoseBtc};
use serde_json::{json, Value};

/// A BTC amount as satoshis.
fn sats(v: &Value) -> u64 {
    (v.as_f64().expect("an amount") * 1e8).round() as u64
}

fn refused(result: Result<Value, (i64, String)>, rule: &str) {
    match result {
        Err((code, message)) => {
            assert_eq!(code, -4, "{message}");
            assert!(
                message.contains(rule),
                "expected a {rule} refusal: {message}"
            );
            assert!(message.contains("nothing was signed or sent"), "{message}");
        }
        Ok(v) => panic!("expected a {rule} refusal, the send went through: {v}"),
    }
}

async fn policy(rose: &RoseBtc) -> Value {
    let info = rose
        .call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo");
    info["spend_policy"].clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_spend_policy_bounds_recipients_and_amounts_across_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(bitcoind) = provisioned(dir.path()) else {
        return;
    };
    let node = BitcoinD::start(&bitcoind, &dir.path().join("btcdata")).await;
    node.mine(101).await;
    let allowed = node.new_address().await;
    let other = node.new_address().await;
    let mut rose = RoseBtc::prepare_full(
        dir.path().join("rosedata"),
        BtcBackend::Bitcoind,
        &node,
        &["btc"],
        "",
        &format!(
            "[wallets.btc.spend_policy]\nallow_recipients = [\"{allowed}\"]\n\
             max_per_transaction_sat = 30000000\nmax_per_day_sat = 50000000\n"
        ),
    );
    rose.init_ok("btc", &["--birthday", "0"]);
    rose.start().await;
    rose.wait_height(101).await;
    let own = rose
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let own = own.as_str().unwrap().to_string();
    node.call("sendtoaddress", json!([own, 1.0]))
        .await
        .expect("fund");
    node.mine(1).await;
    rose.wait_height(102).await;
    rose.wait_wallet_balance("btc", 1.0).await;

    // 1. The readout.
    let p = policy(&rose).await;
    assert_eq!(p["allow_recipients"], json!(1), "{p}");
    assert_eq!(sats(&p["max_per_transaction"]), 30_000_000, "{p}");
    assert_eq!(sats(&p["max_per_day"]), 50_000_000, "{p}");
    assert_eq!(p["window_blocks"], json!(144), "{p}");
    assert_eq!(sats(&p["spent_in_window"]), 0, "{p}");
    assert_eq!(sats(&p["remaining_in_window"]), 50_000_000, "{p}");

    // 2. Off the allowlist; over the per-send cap.
    refused(
        rose.call("sendtoaddress", json!([other, 0.01])).await,
        "allow_recipients",
    );
    refused(
        rose.call("sendtoaddress", json!([allowed, 0.31])).await,
        "max_per_transaction_sat",
    );
    refused(
        rose.call("sendmany", json!(["", {&allowed: 0.01, &other: 0.01}]))
            .await,
        "allow_recipients",
    );
    assert!(
        node.mempool().await.is_empty(),
        "a refused send reached the node"
    );

    // 3. A self-send larger than either cap.
    let own2 = rose
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let self_send = rose
        .call("sendtoaddress", json!([own2, 0.6]))
        .await
        .expect("a self-send is exempt");
    node.wait_mempool_contains(self_send.as_str().unwrap())
        .await;
    assert_eq!(sats(&policy(&rose).await["spent_in_window"]), 0);

    // 4. Fill the window, then one more.
    let first = rose
        .call("sendtoaddress", json!([allowed, 0.3]))
        .await
        .expect("an allowlisted send at the per-send cap");
    node.wait_mempool_contains(first.as_str().unwrap()).await;
    let second = rose
        .call("sendtoaddress", json!([allowed, 0.2]))
        .await
        .expect("an allowlisted send filling the window");
    let second = second.as_str().unwrap().to_string();
    node.wait_mempool_contains(&second).await;
    let p = policy(&rose).await;
    assert_eq!(sats(&p["spent_in_window"]), 50_000_000, "{p}");
    assert_eq!(sats(&p["remaining_in_window"]), 0, "{p}");
    refused(
        rose.call("sendtoaddress", json!([allowed, 0.00001])).await,
        "max_per_day_sat",
    );
    let bumped = rose
        .call("bumpfee", json!([second]))
        .await
        .expect("a replacement counts in place of its original");
    let replacement = bumped["txid"].as_str().unwrap().to_string();
    node.wait_mempool_contains(&replacement).await;
    assert_eq!(sats(&policy(&rose).await["spent_in_window"]), 50_000_000);
    node.mine(1).await;
    rose.wait_height(103).await;

    // 5. A restart re-derives the total.
    rose.restart().await;
    rose.wait_height(103).await;
    let p = policy(&rose).await;
    assert_eq!(sats(&p["spent_in_window"]), 50_000_000, "{p}");
    refused(
        rose.call("sendtoaddress", json!([allowed, 0.00001])).await,
        "max_per_day_sat",
    );

    // 6. Confirmed at 103, the sends count through tip 246 and drop out at 247.
    node.mine(143).await;
    rose.wait_height(246).await;
    assert_eq!(sats(&policy(&rose).await["spent_in_window"]), 50_000_000);
    node.mine(1).await;
    rose.wait_height(247).await;
    let p = policy(&rose).await;
    assert_eq!(sats(&p["spent_in_window"]), 0, "{p}");
    let txid = rose
        .call("sendtoaddress", json!([allowed, 0.1]))
        .await
        .expect("the window has slid past the earlier sends");
    node.wait_mempool_contains(txid.as_str().unwrap()).await;
}
