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
//! Both legs then go one step further: a receive whose block is orphaned and whose inputs
//! the sender then spends elsewhere, confirming the conflict. The wallet resubmits received
//! payments too (Core's rule, so a sender whose wallet never rebroadcasts cannot leave the
//! recipient waiting), which is exactly why a merely-forgotten receive would come back; a
//! double-spent one cannot, and the wallet must recognise that - the payment is evicted
//! rather than resubmitted at every tip forever - and leave the confirmed balance and the
//! UTXO set as they were before it arrived. The orphaned output is not money. The orphan
//! is funded from a coinbase output the wallet never held, so nothing the wallet watches
//! is in the conflict. Over bitcoind that is still enough: the emitter hands the wallet
//! every block, and BDK's block apply inserts any transaction that conflicts with one the
//! graph holds (`bdk_chain`'s `is_tx_or_conflict_relevant`), so the conflict lands in the
//! graph and canonicalization retires the orphan on its own. Over kyoto the conflict's
//! block matches no filter and is never fetched, and BDK keeps a transaction whose anchor
//! reorged out canonical no matter what evictions it is given - so the
//! retirement is zecd's: a once-confirmed receive still unconfirmed after the regtest
//! reorg margin (6 tips) is tombstoned and the wallet reloaded, its loader stripping the
//! stale anchor. Both legs assert the same end state.
//!
//! The second flow (`chained_flow`) reorgs **two sends in a chain** - the child spends the
//! parent's confirmed change - below both of their locktimes, so both drop from the node at
//! once. Resubmission is then parents first and each transaction only once its own locktime
//! is final: over bitcoind the parent goes straight back at the replacement 102 while the
//! child draws a non-final verdict and waits for the next tip; over kyoto both are
//! re-announced once the light client reorgs, in whatever order the peer asks, and the
//! node's orphan handling pulls the parent for a child that arrived first.
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

#[tokio::test(flavor = "multi_thread")]
async fn btc_wallet_resubmits_chained_sends_after_a_reorg_over_bitcoind() {
    chained_flow(BtcBackend::Bitcoind).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_wallet_resubmits_chained_sends_after_a_reorg_over_kyoto() {
    chained_flow(BtcBackend::Kyoto).await;
}

/// Two sends in a chain, both reorged below their locktimes - see the module doc.
async fn chained_flow(backend: BtcBackend) {
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

    // 1. Fund at 102. The parent send is built at tip 102 (nLockTime 102) and confirms at
    //    103; the child is built at tip 103 (nLockTime 103) spending the parent's confirmed
    //    change - the wallet's only output - and confirms at 104.
    let addr = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let addr = addr.as_str().unwrap().to_string();
    let fund_txid = node
        .call("sendtoaddress", json!([addr, 1.0]))
        .await
        .expect("fund");
    let fund_txid_str = fund_txid.as_str().unwrap().to_string();
    let old_102 = node.mine(1).await.remove(0);
    zecd.wait_height(102).await;
    zecd.wait_wallet_balance("btc", 1.0).await;
    let miner = node.new_address().await;
    let parent_txid = zecd
        .call(
            "sendtoaddress",
            json!([miner, 0.25, null, null, false, null, null, null, null, 2]),
        )
        .await
        .expect("parent send");
    let parent_txid_str = parent_txid.as_str().unwrap().to_string();
    let old_103 = node.mine(1).await.remove(0);
    zecd.wait_height(103).await;
    zecd.wait_wallet_best_hash("btc", &old_103).await;
    let child_txid = zecd
        .call(
            "sendtoaddress",
            json!([miner, 0.1, null, null, false, null, null, null, null, 2]),
        )
        .await
        .expect("child send");
    let child_txid_str = child_txid.as_str().unwrap().to_string();
    let child = node
        .call("getrawtransaction", json!([child_txid, true]))
        .await
        .expect("decode the child");
    assert!(
        child["vin"]
            .as_array()
            .expect("vin")
            .iter()
            .any(|vin| vin["txid"] == parent_txid),
        "the child spends the parent's change: {child}"
    );
    let old_104 = node.mine(1).await.remove(0);
    zecd.wait_height(104).await;
    zecd.wait_wallet_best_hash("btc", &old_104).await;
    let balance = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance");
    let balance = balance.as_f64().unwrap();
    assert!(balance > 0.649 && balance < 0.65, "{balance}");

    // 2. Reorg below both locktimes: drop 102 (and 103, 104 above it). The funding receive
    //    returns to the node's mempool; the parent (nLockTime 102) and the child (103) are
    //    both non-final at height 101 and dropped. The replacement 102 re-mines the receive.
    node.call("invalidateblock", json!([old_102]))
        .await
        .expect("invalidateblock");
    assert_eq!(node.height().await, 101);
    let mempool = node.mempool().await;
    assert!(mempool.contains(&fund_txid_str), "{mempool:?}");
    assert!(!mempool.contains(&parent_txid_str), "{mempool:?}");
    assert!(!mempool.contains(&child_txid_str), "{mempool:?}");
    let replacement_miner = node.new_address().await;
    let replacement_102 = node.mine_to(&replacement_miner, 1).await.remove(0);
    assert_ne!(replacement_102, old_102);
    assert!(node.mempool().await.is_empty(), "the receive was re-mined");

    // 3. Resubmission, parents first, each once its own locktime is final.
    let (parent_block, parent_height, child_block, child_height) = match backend {
        BtcBackend::Bitcoind => {
            // The emitter mirrors the invalidation: at the replacement 102 the wallet
            // unconfirms both sends and resubmits. The parent is final for block 103 and
            // goes straight back; the child is not (its locktime is 103), the node answers
            // non-final, and the pass retries it at the next tip - so it must NOT be in the
            // mempool yet, and must be once 103 exists.
            zecd.wait_wallet_best_hash("btc", &node.best_hash().await)
                .await;
            node.wait_mempool_contains(&parent_txid_str).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
            let mempool = node.mempool().await;
            assert!(
                !mempool.contains(&child_txid_str),
                "the child (nLockTime 103) is non-final at 102 and must wait: {mempool:?}"
            );
            let replacement_103 = node.mine_to(&replacement_miner, 1).await.remove(0);
            assert!(node.mempool().await.is_empty(), "the parent was re-mined");
            zecd.wait_wallet_best_hash("btc", &node.best_hash().await)
                .await;
            node.wait_mempool_contains(&child_txid_str).await;
            let replacement_104 = node.mine_to(&replacement_miner, 1).await.remove(0);
            (replacement_103, 103u64, replacement_104, 104u64)
        }
        BtcBackend::Kyoto => {
            // A light client follows work: the replacement chain has to outgrow the old
            // four-block tail (102..104) before the wallet reorgs, so nothing is resubmitted
            // until the replacement 105. By then both locktimes are final; both are
            // re-announced on detached tasks in no particular order, and a child the node
            // hears first sits in its orphanage until the parent arrives.
            node.mine_to(&replacement_miner, 3).await;
            zecd.wait_wallet_best_hash("btc", &node.best_hash().await)
                .await;
            node.wait_mempool_contains(&parent_txid_str).await;
            node.wait_mempool_contains(&child_txid_str).await;
            let replacement_106 = node.mine_to(&replacement_miner, 1).await.remove(0);
            (replacement_106.clone(), 106u64, replacement_106, 106u64)
        }
    };
    assert!(node.mempool().await.is_empty(), "the chain was re-mined");
    let tip = node.height().await;

    // 4. The wallet converges on the node: every transaction re-anchored in its
    //    replacement block, the balance and the UTXO set as before the reorg.
    zecd.wait_height(tip).await;
    zecd.wait_wallet_best_hash("btc", &node.best_hash().await)
        .await;
    zecd.wait_wallet_balance("btc", balance).await;
    for (txid, hash, height) in [
        (&fund_txid, &replacement_102, 102u64),
        (&parent_txid, &parent_block, parent_height),
        (&child_txid, &child_block, child_height),
    ] {
        let tx = zecd
            .call("gettransaction", json!([txid]))
            .await
            .expect("gettransaction after the reorg");
        assert_eq!(tx["blockhash"], json!(hash), "{tx}");
        assert_eq!(tx["confirmations"], json!(tip - height + 1), "{tx}");
    }
    let unspent = zecd
        .call("listunspent", json!([]))
        .await
        .expect("listunspent after the reorg");
    assert_eq!(
        unspent.as_array().map(Vec::len),
        Some(1),
        "only the child's change: {unspent}"
    );
    assert_eq!(unspent[0]["txid"], child_txid, "{unspent}");
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

    // 4. An orphaned receive whose sender double-spends it. Confirm a second receive at
    //    the next height and invalidate its block: the payment falls back into the node's
    //    mempool (and the wallet, which resubmits received payments too, would keep it
    //    there). Then the sender - the node's wallet - spends the same inputs to the miner
    //    with a fee no replacement rule can refuse, and that conflict confirms in the
    //    replacement block. The wallet must end with the payment evicted: gone from
    //    `gettransaction`, the unconfirmed balance back at zero, the confirmed balance and
    //    UTXO set as before it arrived. The orphan is built raw from an untouched coinbase
    //    output the wallet never held, so no wallet script is in the conflict (the node's
    //    wallet would otherwise fund it from change on the funding transaction, which the
    //    wallet holds because it paid us - a conflict that is relevant outright). Over
    //    bitcoind the emitter applies the conflict's block and BDK inserts the conflict as
    //    a conflict of a graph transaction, retiring the orphan itself (the graph gains a
    //    fourth transaction; the rebroadcast pass never sees a candidate). Over kyoto the
    //    block is never fetched and there is no verdict: the receive, unconfirmed since the
    //    reorg, is retired by the actor once the tip is the regtest reorg margin (6) past
    //    where it fell out.
    let orphan_height = tip + 1;
    let coinbase = node
        .call("listunspent", json!([1]))
        .await
        .expect("node listunspent")
        .as_array()
        .expect("array")
        .iter()
        .find(|u| u["amount"].as_f64() == Some(50.0))
        .cloned()
        .expect("an untouched 50 BTC coinbase output");
    let node_change = node.new_address().await;
    let orphan_hex = node
        .call(
            "createrawtransaction",
            json!([
                [{ "txid": coinbase["txid"], "vout": coinbase["vout"] }],
                { addr.clone(): 0.5, node_change.clone(): 49.499 }
            ]),
        )
        .await
        .expect("createrawtransaction for the second receive");
    let orphan_signed = node
        .call("signrawtransactionwithwallet", json!([orphan_hex]))
        .await
        .expect("sign the second receive");
    assert_eq!(orphan_signed["complete"], json!(true), "{orphan_signed}");
    let orphan_txid = node
        .call("sendrawtransaction", json!([orphan_signed["hex"]]))
        .await
        .expect("second receive");
    let orphan_txid_str = orphan_txid.as_str().unwrap().to_string();
    let orphan = node
        .call("getrawtransaction", json!([orphan_txid, true]))
        .await
        .expect("decode the second receive");
    let old_orphan_block = node.mine(1).await.remove(0);
    zecd.wait_height(orphan_height).await;
    zecd.wait_wallet_balance("btc", balance + 0.5).await;
    node.call("invalidateblock", json!([old_orphan_block]))
        .await
        .expect("invalidateblock the orphaned receive's block");
    assert_eq!(node.height().await, orphan_height - 1);
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
    // Two replacement blocks: the conflict's, and one more so the replacement chain
    // outgrows the orphaned tail (a light client reorgs on work, not on the operator's
    // `invalidateblock`; the bitcoind emitter has already followed it).
    let replacement = node.mine_to(&replacement_miner, 2).await;
    assert_ne!(replacement[0], old_orphan_block);
    assert!(node.mempool().await.is_empty(), "the conflict was mined");
    let conflict = node
        .call(
            "getrawtransaction",
            json!([conflict_txid, true, replacement[0]]),
        )
        .await
        .expect("the conflict is on chain");
    assert_eq!(conflict["blockhash"], json!(replacement[0]), "{conflict}");

    zecd.wait_height(orphan_height + 1).await;
    zecd.wait_wallet_best_hash("btc", &node.best_hash().await)
        .await;
    zecd.wait_wallet_balance("btc", balance).await;
    if backend == BtcBackend::Kyoto {
        // No verdict on this backend: the retirement is on time. The receive fell out at
        // the reorg (the wallet's tip orphan_height + 1); the actor retires it once the tip
        // is `anchor_reorg_margin` (6 on regtest) past that. One block of slack.
        node.mine_to(&replacement_miner, 7).await;
        zecd.wait_height(orphan_height + 8).await;
    }
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
