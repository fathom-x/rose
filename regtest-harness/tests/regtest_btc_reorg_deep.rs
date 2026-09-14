//! A deep reorg for the Bitcoin engine, over both chain sources: the fork lands **below the
//! wallet's birthday anchor**, so every checkpoint the wallet holds - the anchor included -
//! is on a dead branch, and a receive confirmed above the birthday is orphaned with it.
//!
//! The wallet's birthday is 150 on a 205-block chain; the node invalidates 140 and mines a
//! 70-block replacement tail to a fresh coinbase address. The orphaned receive carries
//! `nLockTime = 160`, so Core drops it from the mempool at the reorg (non-final at 139)
//! rather than re-mining it in the first replacement block below the birthday; the wallet
//! resubmits it once its tip passes 160 (Core's rule, the reorg suite pins the mechanics),
//! and one more block confirms it above the birthday on the new chain.
//!
//! Over bitcoind the emitter finds no agreement point among the wallet's checkpoints and
//! re-emits from the birthday on the new chain; BDK's local chain replaces the dead
//! blocks. Over kyoto the light client cannot sync headers from any of the wallet's
//! checkpoints - a peer answers a locator it does not know from genesis, and the batch
//! does not connect - so the actor's escalating redials (`resync_depth`) walk down to the
//! first-scan start, which is the recorded anchor, itself dead. That used to loop forever.
//! Now a redial that already bottomed out at the anchor and failed again
//! marks the anchor suspect: the actor clears it (`Persister::clear_birthday_anchor`) and
//! the next redial starts from the network's recovery floor (genesis on regtest), whose
//! headers do sync; the resolution task then re-records the anchor against the new chain.
//!
//! When the light client happens to be idle at the moment the replacement chain arrives it
//! follows the fork by itself and the escalation never fires. The anchor's block is gone all
//! the same, so after any update that reorged the wallet's tip the actor re-resolves the
//! birthday against the light client's headers and re-records the anchor if it moved (the
//! wallet's own chain cannot tell: BDK keeps a checkpoint below the lowest conflict a sparse
//! update names). Either path ends with an anchor on the new chain, which the last step
//! asserts.
//!
//! A third run puts the fork just under the anchor (`UNDER_ANCHOR`): the light client's
//! header tree reaches below it, so the client reorgs by itself and only the update-time
//! re-resolution can notice the orphaned anchor - the deterministic cover for that path.
//!
//! Both legs end converged on the node's best block, with the receive confirmed on the
//! new chain, the balance unchanged, and - over kyoto - `getwalletinfo.birthday.anchor`
//! naming the new block at 150.
//!
//! Skips cleanly without a bitcoind (`BITCOIND_BIN` or PATH) or a zecd built without the
//! `bitcoin` feature - the same two probes as `regtest_btc.rs`.

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::btc::{provisioned, BitcoinD, BtcBackend, ZecdBtc};

/// The shape of one run: the wallet's birthday, the height the node invalidates (below the
/// birthday, so the anchor's block is orphaned), and the orphaned receive's locktime (above
/// the birthday, so it is re-mined above the birthday on the new chain).
#[derive(Clone, Copy)]
struct Fork {
    birthday: u64,
    fork: u64,
    locktime: u64,
    /// The chain height when the node forks. The daemon is restarted at this height first,
    /// so over kyoto the light client's header tree is a `Sync` tree that starts seven
    /// blocks below it - which decides whether the client can reorg by itself.
    old_tip: u64,
}

/// Deep: the fork is far below the light client's header tree (199..205 after the restart),
/// so the kyoto redials fail header sync and escalate down to the dead anchor.
const DEEP: Fork = Fork {
    birthday: 150,
    fork: 140,
    locktime: 160,
    old_tip: 205,
};

/// Just under the anchor: the fork point (199) is the header tree's first block (206 - 7),
/// so the client reorgs by itself and no redial ever fails - the anchor's block at 200
/// (one below the birthday of 201, where every height birthday anchors) is orphaned all
/// the same, and the actor has to notice from the update alone. The anchor resolves only
/// once the tip is the reorg margin (6) past it, hence 206.
const UNDER_ANCHOR: Fork = Fork {
    birthday: 201,
    fork: 200,
    // Final when broadcast at 201, non-final at 199 once the fork drops the node there.
    locktime: 201,
    old_tip: 206,
};

#[tokio::test(flavor = "multi_thread")]
async fn btc_wallet_survives_a_reorg_below_its_anchor_over_bitcoind() {
    deep_reorg_flow(BtcBackend::Bitcoind, DEEP).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_wallet_survives_a_reorg_below_its_anchor_over_kyoto() {
    deep_reorg_flow(BtcBackend::Kyoto, DEEP).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_wallet_reanchors_after_a_fork_just_under_its_anchor_over_kyoto() {
    deep_reorg_flow(BtcBackend::Kyoto, UNDER_ANCHOR).await;
}

async fn block_hash(node: &BitcoinD, height: u64) -> String {
    node.call("getblockhash", json!([height]))
        .await
        .expect("getblockhash")
        .as_str()
        .unwrap()
        .to_string()
}

async fn deep_reorg_flow(backend: BtcBackend, shape: Fork) {
    let Fork {
        birthday,
        fork,
        locktime,
        old_tip,
    } = shape;
    let new_tip = old_tip + 4;
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(bitcoind) = provisioned(dir.path()) else {
        return;
    };
    let node = BitcoinD::start(&bitcoind, &dir.path().join("btcdata")).await;
    // Net, mempool and validation logging on, so a P2P submission's fate is on record.
    node.call(
        "logging",
        json!([["net", "mempool", "mempoolrej", "validation"]]),
    )
    .await
    .expect("enable node logging");
    node.mine(201).await;

    let mut zecd = ZecdBtc::prepare(dir.path().join("zecddata"), backend, &node, &["btc"]);
    zecd.init_ok("btc", &["--birthday", &birthday.to_string()]);
    zecd.start().await;
    zecd.wait_height(201).await;

    // 1. A receive confirmed at 202, built raw from an old coinbase (height 1, mature on
    //    either side of the fork) with the locktime that keeps it out of the replacement
    //    chain's first blocks.
    let addr = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let addr = addr.as_str().unwrap().to_string();
    let coinbase = node
        .call("listunspent", json!([1]))
        .await
        .expect("node listunspent")
        .as_array()
        .expect("array")
        .iter()
        .find(|u| u["amount"].as_f64() == Some(50.0) && u["confirmations"].as_u64() >= Some(200))
        .cloned()
        .expect("an untouched coinbase from the first blocks");
    let node_change = node.new_address().await;
    let raw = node
        .call(
            "createrawtransaction",
            json!([
                [{ "txid": coinbase["txid"], "vout": coinbase["vout"] }],
                { addr.clone(): 1.0, node_change: 48.999 },
                locktime
            ]),
        )
        .await
        .expect("createrawtransaction");
    let signed = node
        .call("signrawtransactionwithwallet", json!([raw]))
        .await
        .expect("sign");
    assert_eq!(signed["complete"], json!(true), "{signed}");
    let receive_txid = node
        .call("sendrawtransaction", json!([signed["hex"]]))
        .await
        .expect("broadcast the receive");
    let old_202 = node.mine(1).await.remove(0);
    node.mine(old_tip - 202).await;
    zecd.wait_height(old_tip).await;
    zecd.wait_wallet_balance("btc", 1.0).await;
    let tx = zecd
        .call("gettransaction", json!([receive_txid]))
        .await
        .expect("gettransaction");
    assert_eq!(tx["blockhash"], json!(old_202), "{tx}");
    // A height birthday anchors one block below itself (kyoto scans from anchor + 1).
    let anchor_height = birthday - 1;
    let old_anchor_block = block_hash(&node, anchor_height).await;
    if backend == BtcBackend::Kyoto {
        // The birthday resolved to an anchor on the original chain (the resolution waits
        // for the tip to be the reorg margin past the anchor).
        zecd.wait_wallet(
            "btc",
            "getwalletinfo",
            json!([]),
            "the birthday anchor is recorded",
            |wi| wi["birthday"]["anchor"]["hash"] == json!(old_anchor_block),
        )
        .await;
    }
    // Restart at the old tip: over kyoto the light client comes back with a `Sync` header
    // tree from seven blocks below it, which fixes where the fork lands relative to the tree.
    zecd.restart().await;
    zecd.wait_height(old_tip).await;
    zecd.wait_wallet_best_hash("btc", &node.best_hash().await)
        .await;

    // 2. The reorg: invalidate the fork height, below the birthday, and outgrow the old
    //    chain by four blocks to a fresh address. The receive is non-final at the fork and
    //    leaves the node's mempool.
    let old_fork_block = block_hash(&node, fork).await;
    node.call("invalidateblock", json!([old_fork_block]))
        .await
        .expect("invalidateblock");
    assert_eq!(node.height().await, fork - 1);
    assert!(
        node.mempool().await.is_empty(),
        "the non-final receive left the mempool: {:?}",
        node.mempool().await
    );
    let replacement_miner = node.new_address().await;
    node.mine_to(&replacement_miner, new_tip - (fork - 1)).await;
    assert_eq!(node.height().await, new_tip);
    let new_anchor_block = block_hash(&node, anchor_height).await;
    assert_ne!(
        new_anchor_block, old_anchor_block,
        "the anchor's block was orphaned"
    );

    // 3. Convergence: the wallet follows the new chain to its tip. Over kyoto the deep
    //    shape is the escalation bottoming out at the dead anchor, clearing it, and
    //    restarting from genesis - several redials with backoff; the under-anchor shape is
    //    the light client reorging by itself.
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        let wi = zecd
            .call("getwalletinfo", json!([]))
            .await
            .expect("getwalletinfo");
        let best = node.best_hash().await;
        if wi["lastprocessedblock"]["hash"] == json!(best) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "[{}] the wallet never converged on the new chain: {wi}",
            backend.label()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    eprintln!("[{}] converged on the replacement chain", backend.label());

    // 4. The receive: orphaned, resubmitted by the wallet once its tip passed the locktime,
    //    and confirmed again above the birthday by one more block. Balance unchanged.
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if node
            .mempool()
            .await
            .contains(&receive_txid.as_str().unwrap().to_string())
        {
            break;
        }
        if Instant::now() >= deadline {
            // What the node would say to the transaction right now, for the report.
            let verdict = node
                .call("testmempoolaccept", json!([[signed["hex"]]]))
                .await;
            let wi = zecd.call("getwalletinfo", json!([])).await;
            let txid = receive_txid.as_str().unwrap();
            let node_log = std::fs::read_to_string(dir.path().join("btcdata/regtest/debug.log"))
                .unwrap_or_default();
            let mentions: Vec<&str> = node_log
                .lines()
                .filter(|l| {
                    l.contains(&txid[..16])
                        || l.contains("getdata")
                        || l.contains("received: tx")
                        || l.contains("AcceptToMemoryPool")
                        || l.contains("not accepted")
                        || l.contains("rejected")
                        || l.contains("disconnect")
                        || l.contains("peer=0")
                })
                .collect();
            let tail: Vec<&str> = mentions.iter().rev().take(60).rev().copied().collect();
            panic!(
                "[{}] the orphaned receive was never resubmitted to the node; \
                 testmempoolaccept: {verdict:?}; wallet: {wi:?}; node log:\n{}",
                backend.label(),
                tail.join("\n")
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let new_block = node.mine_to(&replacement_miner, 1).await.remove(0);
    zecd.wait_height(new_tip + 1).await;
    zecd.wait_wallet_best_hash("btc", &node.best_hash().await)
        .await;
    zecd.wait_wallet_balance("btc", 1.0).await;
    zecd.wait_wallet(
        "btc",
        "gettransaction",
        json!([receive_txid]),
        "the receive is re-anchored on the new chain",
        |tx| tx["blockhash"] == json!(new_block) && tx["confirmations"] == json!(1),
    )
    .await;
    let unspent = zecd
        .call("listunspent", json!([]))
        .await
        .expect("listunspent");
    assert_eq!(unspent.as_array().map(Vec::len), Some(1), "{unspent}");
    assert_eq!(unspent[0]["txid"], receive_txid, "{unspent}");
    // The wallet holds the whole transaction, witness included - what the resubmission
    // above depended on (bip157 serves witness-stripped blocks unless asked otherwise).
    let tx = zecd
        .call("gettransaction", json!([receive_txid]))
        .await
        .expect("gettransaction");
    let node_hex = node
        .call("getrawtransaction", json!([receive_txid, false, new_block]))
        .await
        .expect("getrawtransaction");
    assert_eq!(
        tx["hex"], node_hex,
        "the wallet's copy must match the node's, witness included"
    );

    // 5. Over kyoto the anchor was cleared and re-resolved against the new chain.
    if backend == BtcBackend::Kyoto {
        zecd.wait_wallet(
            "btc",
            "getwalletinfo",
            json!([]),
            "the birthday anchor names the new chain's block",
            |wi| {
                wi["birthday"]["anchor"]["height"] == json!(anchor_height)
                    && wi["birthday"]["anchor"]["hash"] == json!(new_anchor_block)
            },
        )
        .await;
    }
}
