//! What a Bitcoin send leaves in the wallet under each relay outcome, over the bitcoind
//! backend - the one with verdicts. A send is committed to the wallet before it is relayed
//! (the actor's `commit_before_relay`, then `relay_committed`), and the record then follows
//! the relay's outcome. Three outcomes, each driven live:
//!
//! 1. **Rejected.** The node refuses the bytes (`-26`, a fee under its relay floor - the
//!    node is started with `-minrelaytxfee` five times the wallet's 1 sat/vB rate). The
//!    node's own code passes through and the record is withdrawn: balance intact, the
//!    input still unspent, no history entry, nothing in the node's mempool.
//! 2. **No verdict.** The broadcast dies before the node answers - an [`RpcProxy`] between
//!    the two drops exactly the `sendrawtransaction` request, so the sync pass, the mempool
//!    pass and the redial all keep working. The send returns its txid **recorded**: the
//!    input is locked (a retry against it is `-6`), and once the path clears the
//!    rebroadcast pass resubmits it on its own - the node's mempool gains it with nothing in
//!    the test broadcasting on the wallet's behalf - and it confirms.
//! 3. **Abandon, then resubmit the same bytes.** `abandontransaction` releases an unrelayed
//!    send's inputs; a later `sendrawtransaction` of its hex must re-canonicalize the record
//!    *before* relaying, or the node would hold a transaction whose inputs the wallet still
//!    counts as free (the double-spend the commit-first order exists to prevent, reopened on
//!    another path).
//!
//! Deleting the withdrawal in the rejection arm fails step 1; relaying before committing,
//! or dropping the record on a transport failure, fails step 2; gating the resubmission on
//! the raw graph rather than the canonical view fails step 3. Step 3 also pins that a
//! `sendrawtransaction` whose bytes reached no node answers `-25` rather than a txid (Core
//! never returns one without mempool acceptance), while still re-recording the transaction.

use serde_json::json;
use zecd_regtest_harness::btc::{provisioned, BitcoinD, RpcProxy, ZecdBtc};

/// `sendtoaddress` with Core's positional layout: param 9 is the explicit `fee_rate`
/// (sat/vB), which keeps every send off the estimator and prices it exactly.
fn send_params(to: &str, amount: f64, fee_rate: u32) -> serde_json::Value {
    json!([to, amount, null, null, false, null, null, null, null, fee_rate])
}

/// Call `method`, retrying while the wallet answers "no connection to the upstream". A
/// broadcast with no verdict drops the bitcoind connection for a redial (the transport may
/// be the problem), and while the proxy keeps dropping `sendrawtransaction` every redial's
/// rebroadcast pass fails the same way and drops it again - so the wallet flaps between
/// connected and not, and a call that needs the node lands in a connected window only
/// sometimes. The refusal comes before coin selection, so it says nothing about what the
/// test asserts; any other answer is returned for the caller to check.
async fn call_when_connected(
    zecd: &ZecdBtc,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, (i64, String)> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        match zecd.call(method, params.clone()).await {
            Err((-4, msg)) if msg.contains("no connection to the upstream") => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "{method}: the wallet never had its upstream connected: {msg}"
                );
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            other => return other,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_send_record_follows_the_relay_outcome_over_bitcoind() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(bitcoind) = provisioned(dir.path()) else {
        return;
    };
    // A relay floor of 5 sat/vB (0.00005 BTC/kvB): a 1 sat/vB send is a verdict, not a
    // relay, while the node's own funding sends (fallbackfee 10 sat/vB) still pass.
    let node = BitcoinD::start_with(
        &bitcoind,
        &dir.path().join("btcdata"),
        &["-minrelaytxfee=0.00005"],
    )
    .await;
    node.mine(101).await;
    let proxy = RpcProxy::start(node.rpc_port).await;

    let mut zecd = ZecdBtc::prepare_bitcoind_at(dir.path().join("zecddata"), proxy.port, &["btc"]);
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

    // 1. Rejected: the node's verdict passes through and the record is withdrawn.
    let (code, msg) = zecd
        .call("sendtoaddress", send_params(&miner, 0.1, 1))
        .await
        .expect_err("a send under the node's relay floor is refused by the node");
    assert_eq!(code, -26, "{msg}");
    assert!(msg.contains("min relay fee"), "{msg}");
    let balance = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance");
    assert_eq!(
        balance.as_f64(),
        Some(1.0),
        "the rejected send's input is not locked"
    );
    let unspent = zecd
        .call("listunspent", json!([0]))
        .await
        .expect("listunspent 0");
    assert_eq!(
        unspent.as_array().map(Vec::len),
        Some(1),
        "the funding output is still the one unspent output: {unspent}"
    );
    let history = zecd
        .call("listtransactions", json!([]))
        .await
        .expect("listtransactions");
    assert_eq!(
        history.as_array().map(Vec::len),
        Some(1),
        "a rejected send leaves no history entry: {history}"
    );
    assert!(
        node.mempool().await.is_empty(),
        "the node never accepted anything"
    );

    // 2. No verdict: the broadcast itself fails, the record stands, the rebroadcast pass
    //    carries it once the path clears.
    proxy.drop_method(Some("sendrawtransaction"));
    let txid = zecd
        .call("sendtoaddress", send_params(&miner, 0.1, 10))
        .await
        .expect("a send with no verdict is committed and returns its txid");
    let txid = txid.as_str().unwrap().to_string();
    assert!(
        !node.mempool().await.contains(&txid),
        "the dropped broadcast never reached the node"
    );
    let tx = zecd
        .call("gettransaction", json!([txid]))
        .await
        .expect("the unrelayed send is a wallet transaction");
    assert_eq!(tx["confirmations"], json!(0), "{tx}");
    let (code, msg) = call_when_connected(&zecd, "sendtoaddress", send_params(&miner, 0.95, 10))
        .await
        .expect_err("the unrelayed send's input is locked against a retry");
    assert_eq!(code, -6, "{msg}");
    // The connection was dropped for redial; the redial goes through the proxy like every
    // other call, and the pass after it resubmits every unconfirmed wallet transaction.
    proxy.drop_method(None);
    node.wait_mempool_contains(&txid).await;
    node.mine(1).await;
    zecd.wait_height(103).await;
    let tx = zecd
        .call("gettransaction", json!([txid]))
        .await
        .expect("the resubmitted send");
    assert_eq!(tx["confirmations"], json!(1), "{tx}");
    let after_send = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance")
        .as_f64()
        .unwrap();
    assert!(
        after_send < 0.9 && after_send > 0.85,
        "1.0 - 0.1 - fee: {after_send}"
    );

    // 3. Abandon an unrelayed send, then resubmit its bytes: the record must come back
    //    before the relay, so the inputs the node now sees spent are spent here too.
    proxy.drop_method(Some("sendrawtransaction"));
    let txid2 = zecd
        .call("sendtoaddress", send_params(&miner, 0.2, 10))
        .await
        .expect("a second unrelayed send");
    let txid2 = txid2.as_str().unwrap().to_string();
    let hex = zecd
        .call("gettransaction", json!([txid2]))
        .await
        .expect("gettransaction")["hex"]
        .as_str()
        .unwrap()
        .to_string();
    zecd.call("abandontransaction", json!([txid2]))
        .await
        .expect("abandon an unrelayed send");
    let (code, msg) = zecd
        .call("gettransaction", json!([txid2]))
        .await
        .expect_err("an abandoned transaction leaves the canonical set");
    assert_eq!(code, -5, "{msg}");
    let after_abandon = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance")
        .as_f64()
        .unwrap();
    assert_eq!(after_abandon, after_send, "abandoning released the input");
    // Still no path to the node: sendrawtransaction does not answer a txid for bytes that
    // reached no mempool (Core never does) - it is -25, and the record is re-committed all
    // the same, so the input stays spent here while the rebroadcast pass carries it.
    let (code, msg) = call_when_connected(&zecd, "sendrawtransaction", json!([hex]))
        .await
        .expect_err("an unrelayed sendrawtransaction is not a success");
    assert_eq!(code, -25, "{msg}");
    zecd.call("gettransaction", json!([txid2]))
        .await
        .expect("the unrelayed resubmission is recorded again");
    proxy.drop_method(None);
    let relayed = call_when_connected(&zecd, "sendrawtransaction", json!([hex]))
        .await
        .expect("resubmit the abandoned send's bytes");
    assert_eq!(relayed, json!(txid2));
    node.wait_mempool_contains(&txid2).await;
    let tx = zecd
        .call("gettransaction", json!([txid2]))
        .await
        .expect("the resubmitted transaction is canonical again");
    assert_eq!(tx["confirmations"], json!(0), "{tx}");
    let after_resubmit = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance")
        .as_f64()
        .unwrap();
    assert!(
        after_resubmit < after_abandon - 0.2,
        "the resubmitted send's input is spent again: {after_resubmit} vs {after_abandon}"
    );
    node.mine(1).await;
    zecd.wait_height(104).await;
    let tx = zecd
        .call("gettransaction", json!([txid2]))
        .await
        .expect("the resubmitted send confirmed");
    assert_eq!(tx["confirmations"], json!(1), "{tx}");
}
