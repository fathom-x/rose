//! Live reorg test for the Bitcoin engine, over both chain sources. The wallet's receive
//! and its own send are confirmed, then the node is told to `invalidateblock` the block
//! that confirmed the receive and mines a longer replacement tail to a different coinbase
//! address (guaranteed-different blocks). Both transactions land in the replacement chain:
//! the receive straight from the node's mempool, the send rebroadcast one block later (its
//! anti-fee-sniping locktime makes it non-final at the reorged height, so Core drops it
//! from the mempool: the test pins that too). The wallet must walk back to the fork point,
//! follow the new tail, converge on the node's best block, and re-anchor both transactions
//! in their new blocks with the balance unchanged.
//!
//! Over bitcoind that is `bdk_bitcoind_rpc`'s emitter walking the wallet's checkpoint back
//! to the fork; over kyoto it is the light client's header reorg surfacing as an `Update`
//! with disconnected blocks that `apply_update` unwinds. Neither path had live coverage.
//!
//! The bitcoind leg then goes one step further: a receive whose block is orphaned and
//! which is **not** re-mined (the node restarts with `-persistmempool=0`, dropping it) must
//! leave the confirmed balance and the UTXO set as they were before it arrived - the
//! orphaned output is not spendable money.
//!
//! Skips cleanly without a bitcoind (`BITCOIND_BIN` or PATH) or a zecd built without the
//! `bitcoin` feature - the same two probes as `regtest_btc.rs`.

use serde_json::json;
use zecd_regtest_harness::btc::{provisioned, BitcoinD, BtcBackend, ZecdBtc};

#[tokio::test(flavor = "multi_thread")]
async fn btc_wallet_follows_a_reorg_over_bitcoind() {
    reorg_flow(BtcBackend::Bitcoind).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_wallet_follows_a_reorg_over_kyoto() {
    reorg_flow(BtcBackend::Kyoto).await;
}

async fn reorg_flow(backend: BtcBackend) {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(bitcoind) = provisioned(dir.path()) else {
        return;
    };
    let mut node = BitcoinD::start(&bitcoind, &dir.path().join("btcdata")).await;
    node.mine(101).await;

    let mut zecd = ZecdBtc::prepare(dir.path().join("zecddata"), backend, &node, &["btc"]);
    zecd.init_ok("btc", &["--birthday", "0"]);
    zecd.start().await;
    zecd.wait_height(101).await;

    // 1. A receive confirmed at 102 and the wallet's own send confirmed at 103.
    let addr = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let addr = addr.as_str().unwrap().to_string();
    let fund_txid = node
        .call("sendtoaddress", json!([addr, 1.0]))
        .await
        .expect("fund");
    let old_102 = node.mine(1).await.remove(0);
    zecd.wait_height(102).await;
    zecd.wait_wallet_balance("btc", 1.0).await;
    let miner = node.new_address().await;
    let send_txid = zecd
        .call(
            "sendtoaddress",
            json!([miner, 0.25, null, null, false, null, null, null, null, 2]),
        )
        .await
        .expect("send");
    let old_103 = node.mine(1).await.remove(0);
    zecd.wait_height(103).await;
    let balance = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance");
    let balance = balance.as_f64().unwrap();
    assert!(balance > 0.74 && balance < 0.75, "{balance}");
    for (txid, hash) in [(&fund_txid, &old_102), (&send_txid, &old_103)] {
        let tx = zecd
            .call("gettransaction", json!([txid]))
            .await
            .expect("gettransaction");
        assert_eq!(tx["blockhash"], json!(hash), "{tx}");
    }

    // 2. The reorg: drop 102 (and 103 above it), so the node is back at 101. The receive
    //    returns to the node's mempool. The wallet's send does not: BDK's builder sets
    //    nLockTime to the tip height (102) against fee sniping, which is non-final for a
    //    block at 102, and Core's reorg handling drops non-final transactions rather than
    //    hold them. So the replacement tail is mined in two steps - one block (the new 102,
    //    carrying the receive), then the send rebroadcast from the wallet's own copy, then
    //    two more (the send in the new 103) - to a fresh coinbase address, so the blocks
    //    are guaranteed to differ.
    node.call("invalidateblock", json!([old_102]))
        .await
        .expect("invalidateblock");
    assert_eq!(
        node.height().await,
        101,
        "the chain diverged below the old tip"
    );
    let mempool = node.mempool().await;
    assert!(
        mempool.contains(&fund_txid.as_str().unwrap().to_string()),
        "the receive is back in the mempool after the invalidation: {mempool:?}"
    );
    assert!(
        !mempool.contains(&send_txid.as_str().unwrap().to_string()),
        "the send (nLockTime 102) is non-final at height 101 and dropped: {mempool:?}"
    );
    let replacement_miner = node.new_address().await;
    let replacement_102 = node.mine_to(&replacement_miner, 1).await.remove(0);
    assert_ne!(
        replacement_102, old_102,
        "the replacement 102 is a different block"
    );
    assert!(node.mempool().await.is_empty(), "the receive was re-mined");
    let send_hex = zecd
        .call("gettransaction", json!([send_txid]))
        .await
        .expect("gettransaction for the send's hex")["hex"]
        .as_str()
        .expect("the wallet keeps the raw send")
        .to_string();
    let rebroadcast = node
        .call("sendrawtransaction", json!([send_hex]))
        .await
        .expect("the send is final again at height 102");
    assert_eq!(rebroadcast, send_txid);
    let replacement_103 = node.mine_to(&replacement_miner, 2).await.remove(0);
    assert!(node.mempool().await.is_empty(), "the send was re-mined");

    // 3. The wallet walks back to the fork and follows the replacement tail past the
    //    old tip, converging on the node's best block.
    zecd.wait_height(104).await;
    zecd.wait_wallet_best_hash("btc", &node.best_hash().await)
        .await;
    zecd.wait_wallet_balance("btc", balance).await;
    // Both transactions are re-anchored in their replacement blocks.
    for (txid, hash, confirmations) in [
        (&fund_txid, &replacement_102, 3),
        (&send_txid, &replacement_103, 2),
    ] {
        let tx = zecd
            .call("gettransaction", json!([txid]))
            .await
            .expect("gettransaction after the reorg");
        assert_eq!(tx["blockhash"], json!(hash), "{tx}");
        assert_eq!(tx["confirmations"], json!(confirmations), "{tx}");
    }
    let unspent = zecd
        .call("listunspent", json!([]))
        .await
        .expect("listunspent after the reorg");
    assert_eq!(
        unspent.as_array().map(Vec::len),
        Some(1),
        "the change: {unspent}"
    );
    assert_eq!(unspent[0]["txid"], send_txid, "{unspent}");
    assert_eq!(unspent[0]["confirmations"], json!(2), "{unspent}");
    // And the wallet still serves: a fresh address and a consistent history.
    let next = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress after the reorg");
    assert!(
        next.as_str().is_some_and(|a| a.starts_with("bcrt1")),
        "{next}"
    );

    if backend != BtcBackend::Bitcoind {
        return;
    }

    // 4. An orphaned receive that is never re-mined. Confirm a second receive at 105,
    //    invalidate its block, and restart the node without its mempool - and without
    //    its wallet, which would otherwise resubmit the transaction on load - so it is
    //    gone for good; mine past the old height. The wallet must show the confirmed
    //    balance and UTXO set from before that receive - and keep serving.
    let orphan_txid = node
        .call("sendtoaddress", json!([addr, 0.5]))
        .await
        .expect("second receive");
    let old_105 = node.mine(1).await.remove(0);
    zecd.wait_height(105).await;
    zecd.wait_wallet_balance("btc", balance + 0.5).await;
    node.call("invalidateblock", json!([old_105]))
        .await
        .expect("invalidateblock 105");
    node.restart(&["-persistmempool=0"]).await;
    assert!(
        node.mempool().await.is_empty(),
        "the orphaned receive did not survive the restart"
    );
    assert_eq!(node.height().await, 104);
    let replacement = node.mine_to(&replacement_miner, 2).await;
    assert_ne!(replacement[0], old_105);

    zecd.wait_height(106).await;
    zecd.wait_wallet_best_hash("btc", &node.best_hash().await)
        .await;
    zecd.wait_wallet_balance("btc", balance).await;
    let unspent = zecd
        .call("listunspent", json!([]))
        .await
        .expect("listunspent after the orphaning");
    assert_eq!(
        unspent.as_array().map(Vec::len),
        Some(1),
        "only the change remains confirmed: {unspent}"
    );
    assert_eq!(unspent[0]["txid"], send_txid, "{unspent}");
    let tx = zecd
        .call("gettransaction", json!([orphan_txid]))
        .await
        .expect("gettransaction on the orphaned receive");
    assert_eq!(
        tx["confirmations"],
        json!(0),
        "the orphaned receive is no longer confirmed: {tx}"
    );
    assert!(
        tx["blockhash"].is_null(),
        "no block anchors it any more: {tx}"
    );
}
