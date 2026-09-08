//! Live reorg test for the Bitcoin engine, over both chain sources. The wallet's receive
//! and its own send are confirmed, then the node is told to `invalidateblock` the block
//! that confirmed the receive and mines a longer replacement tail to a different coinbase
//! address (guaranteed-different blocks). Both transactions land in the replacement chain:
//! the receive straight from the node's mempool, the send **resubmitted by the wallet
//! itself** (its anti-fee-sniping locktime makes it non-final at the reorged height, so
//! Core drops it from the mempool rather than hold it - the test pins that too - and the
//! actor's rebroadcast pass puts it back once the wallet sees the new tip). The wallet must
//! walk back to the fork point, follow the new tail, converge on the node's best block, and
//! re-anchor both transactions in their new blocks with the balance unchanged. Nothing in
//! the test broadcasts the send on the wallet's behalf.
//!
//! Over bitcoind that is `bdk_bitcoind_rpc`'s emitter walking the wallet's checkpoint back
//! to the fork; over kyoto it is the light client's header reorg surfacing as an `Update`
//! with disconnected blocks that `apply_update` unwinds. The two see the reorg at different
//! moments, and the flow below follows that: bitcoind mirrors the node's `invalidateblock`
//! at once, so the wallet resubmits at the replacement 102 and the send confirms in 103; a
//! light client follows work, not an operator's invalidation, so it stays on the old
//! three-block tail until the replacement chain outgrows it at 104, resubmits there, and
//! the send confirms in 105.
//!
//! The bitcoind leg then goes one step further: a receive whose block is orphaned and whose
//! inputs the sender then spends elsewhere, confirming the conflict. The wallet resubmits
//! received payments too (Core's rule, so a sender whose wallet never rebroadcasts cannot
//! leave the recipient waiting), which is exactly why a merely-forgotten receive would come
//! back; a double-spent one cannot, and the wallet must recognise that - the payment is
//! evicted rather than resubmitted at every tip forever - and leave the confirmed balance
//! and the UTXO set as they were before it arrived. The orphaned output is not money.
//!
//! Skips cleanly without a bitcoind (`BITCOIND_BIN` or PATH) or a zecd built without the
//! `bitcoin` feature - the same two probes as `regtest_btc.rs`.

use std::time::{Duration, Instant};

use serde_json::{json, Value};
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
    let node = BitcoinD::start(&bitcoind, &dir.path().join("btcdata")).await;
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
    //    hold them. The replacement tail is mined to a fresh coinbase address, so the blocks
    //    are guaranteed to differ, in steps: one block (the new 102, carrying the receive),
    //    then whatever the backend needs before the wallet sees the reorg and resubmits the
    //    send on its own, then the block that mines it.
    node.call("invalidateblock", json!([old_102]))
        .await
        .expect("invalidateblock");
    assert_eq!(
        node.height().await,
        101,
        "the chain diverged below the old tip"
    );
    let send_txid_str = send_txid.as_str().unwrap().to_string();
    let mempool = node.mempool().await;
    assert!(
        mempool.contains(&fund_txid.as_str().unwrap().to_string()),
        "the receive is back in the mempool after the invalidation: {mempool:?}"
    );
    assert!(
        !mempool.contains(&send_txid_str),
        "the send (nLockTime 102) is non-final at height 101 and dropped: {mempool:?}"
    );
    let replacement_miner = node.new_address().await;
    let replacement_102 = node.mine_to(&replacement_miner, 1).await.remove(0);
    assert_ne!(
        replacement_102, old_102,
        "the replacement 102 is a different block"
    );
    assert!(node.mempool().await.is_empty(), "the receive was re-mined");

    // 3. The wallet resubmits the send itself. It can only do so once it has seen the
    //    reorg (the send is confirmed in its view until then), and the two backends see it
    //    at different heights - see the module doc. Either way the node's mempool receiving
    //    the send with nobody in this test submitting it is the assertion.
    let (send_block, send_height) = match backend {
        BtcBackend::Bitcoind => {
            // The emitter mirrors the node's `invalidateblock`: at the replacement 102 the
            // wallet unconfirms the send, and its locktime is final for the next block.
            zecd.wait_wallet_best_hash("btc", &node.best_hash().await)
                .await;
            node.wait_mempool_contains(&send_txid_str).await;
            let blocks = node.mine_to(&replacement_miner, 2).await;
            (blocks[0].clone(), 103u64)
        }
        BtcBackend::Kyoto => {
            // A light client follows work: the replacement chain has to outgrow the old
            // 103-block tail before it reorgs onto it, so the send is resubmitted at 104.
            node.mine_to(&replacement_miner, 2).await;
            zecd.wait_wallet_best_hash("btc", &node.best_hash().await)
                .await;
            node.wait_mempool_contains(&send_txid_str).await;
            let blocks = node.mine_to(&replacement_miner, 1).await;
            (blocks[0].clone(), 105u64)
        }
    };
    assert!(node.mempool().await.is_empty(), "the send was re-mined");
    let tip = node.height().await;

    //    The wallet walks back to the fork and follows the replacement tail past the old
    //    tip, converging on the node's best block.
    zecd.wait_height(tip).await;
    zecd.wait_wallet_best_hash("btc", &node.best_hash().await)
        .await;
    zecd.wait_wallet_balance("btc", balance).await;
    // Both transactions are re-anchored in their replacement blocks.
    let send_confirmations = tip - send_height + 1;
    for (txid, hash, confirmations) in [
        (&fund_txid, &replacement_102, tip - 102 + 1),
        (&send_txid, &send_block, send_confirmations),
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
    assert_eq!(
        unspent[0]["confirmations"],
        json!(send_confirmations),
        "{unspent}"
    );
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

    // 4. An orphaned receive whose sender double-spends it. Confirm a second receive at
    //    105 and invalidate its block: the payment falls back into the node's mempool (and
    //    the wallet, which resubmits received payments too, would keep it there). Then the
    //    sender - the node's wallet - spends the same inputs to the miner with a fee no
    //    replacement rule can refuse, and that conflict confirms in the new 105. The wallet
    //    must end with the payment evicted: gone from `gettransaction`, the unconfirmed
    //    balance back at zero, the confirmed balance and UTXO set as before it arrived.
    //    Either of two paths gets it there and the test does not care which - the emitter's
    //    mempool pass reports the eviction if the wallet had seen the payment in the mempool
    //    after the invalidation, and otherwise the rebroadcast pass draws a missing-inputs
    //    verdict from the node and marks it evicted itself.
    let orphan_txid = node
        .call("sendtoaddress", json!([addr, 0.5]))
        .await
        .expect("second receive");
    let orphan_txid_str = orphan_txid.as_str().unwrap().to_string();
    let orphan = node
        .call("getrawtransaction", json!([orphan_txid, true]))
        .await
        .expect("decode the second receive");
    let old_105 = node.mine(1).await.remove(0);
    zecd.wait_height(105).await;
    zecd.wait_wallet_balance("btc", balance + 0.5).await;
    node.call("invalidateblock", json!([old_105]))
        .await
        .expect("invalidateblock 105");
    assert_eq!(node.height().await, 104);
    assert!(
        node.mempool().await.contains(&orphan_txid_str),
        "the orphaned receive is back in the node's mempool"
    );
    // The sender's double-spend: the same inputs, all of their value minus a large fee,
    // paid to the miner. Built raw so it pays nothing to the wallet under test.
    let inputs: Vec<Value> = orphan["vin"]
        .as_array()
        .expect("vin")
        .iter()
        .map(|vin| json!({ "txid": vin["txid"], "vout": vin["vout"] }))
        .collect();
    let mut input_total = 0.0;
    for input in &inputs {
        // `include_mempool = false`: the orphaned receive is back in the mempool and
        // spends these very outputs, which the default view would report as gone.
        let utxo = node
            .call("gettxout", json!([input["txid"], input["vout"], false]))
            .await
            .expect("gettxout");
        input_total += utxo["value"]
            .as_f64()
            .expect("the orphaned receive's inputs are unspent again after the invalidation");
    }
    let conflict_amount = ((input_total - 0.01) * 1e8).round() / 1e8;
    let conflict_hex = node
        .call(
            "createrawtransaction",
            json!([inputs, { replacement_miner.clone(): conflict_amount }]),
        )
        .await
        .expect("createrawtransaction");
    let signed = node
        .call("signrawtransactionwithwallet", json!([conflict_hex]))
        .await
        .expect("signrawtransactionwithwallet");
    assert_eq!(signed["complete"], json!(true), "{signed}");
    let conflict_txid = node
        .call("sendrawtransaction", json!([signed["hex"]]))
        .await
        .expect("the double-spend replaces the orphaned receive in the mempool");
    let mempool = node.mempool().await;
    assert!(
        !mempool.contains(&orphan_txid_str),
        "the orphaned receive was replaced: {mempool:?}"
    );
    let replacement = node.mine_to(&replacement_miner, 2).await;
    assert_ne!(replacement[0], old_105);
    assert!(node.mempool().await.is_empty(), "the conflict was mined");
    let conflict = node
        .call(
            "getrawtransaction",
            json!([conflict_txid, true, replacement[0]]),
        )
        .await
        .expect("the conflict is on chain");
    assert_eq!(conflict["blockhash"], json!(replacement[0]), "{conflict}");

    zecd.wait_height(106).await;
    zecd.wait_wallet_best_hash("btc", &node.best_hash().await)
        .await;
    zecd.wait_wallet_balance("btc", balance).await;
    zecd.wait_unconfirmed(0.0).await;
    let unspent = zecd
        .call("listunspent", json!([]))
        .await
        .expect("listunspent after the double-spend");
    assert_eq!(
        unspent.as_array().map(Vec::len),
        Some(1),
        "only the change remains confirmed: {unspent}"
    );
    assert_eq!(unspent[0]["txid"], send_txid, "{unspent}");
    // Evicted: no longer a wallet transaction at all (the conflict bookkeeping Core shows
    // as `walletconflicts` is not implemented - see `src/btc/README.md`).
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match zecd.call("gettransaction", json!([orphan_txid])).await {
            Err((-5, _)) => break,
            other => assert!(
                Instant::now() < deadline,
                "the double-spent receive was never evicted: {other:?}"
            ),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
