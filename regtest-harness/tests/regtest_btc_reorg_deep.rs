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
//! (When the light client happens to be idle at the moment the replacement chain arrives it
//! sometimes follows the fork by itself and the escalation never fires; the daemon log of a
//! run that did escalate shows the whole path, and either way the end state below holds.)
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

const BIRTHDAY: u64 = 150;
const FORK: u64 = 140;
const LOCKTIME: u64 = 160;

#[tokio::test(flavor = "multi_thread")]
async fn btc_wallet_survives_a_reorg_below_its_anchor_over_bitcoind() {
    deep_reorg_flow(BtcBackend::Bitcoind).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_wallet_survives_a_reorg_below_its_anchor_over_kyoto() {
    deep_reorg_flow(BtcBackend::Kyoto).await;
}

async fn block_hash(node: &BitcoinD, height: u64) -> String {
    node.call("getblockhash", json!([height]))
        .await
        .expect("getblockhash")
        .as_str()
        .unwrap()
        .to_string()
}

async fn deep_reorg_flow(backend: BtcBackend) {
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
    zecd.init_ok("btc", &["--birthday", &BIRTHDAY.to_string()]);
    zecd.start().await;
    zecd.wait_height(201).await;
    if backend == BtcBackend::Kyoto {
        // The first scan resolved the birthday to an anchor on the original chain.
        let old_150 = block_hash(&node, BIRTHDAY).await;
        zecd.wait_wallet(
            "btc",
            "getwalletinfo",
            json!([]),
            "the birthday anchor is recorded",
            |wi| wi["birthday"]["anchor"]["hash"] == json!(old_150),
        )
        .await;
    }

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
                LOCKTIME
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
    node.mine(3).await;
    zecd.wait_height(205).await;
    zecd.wait_wallet_balance("btc", 1.0).await;
    let tx = zecd
        .call("gettransaction", json!([receive_txid]))
        .await
        .expect("gettransaction");
    assert_eq!(tx["blockhash"], json!(old_202), "{tx}");

    // 2. The deep reorg: invalidate 140, below the birthday and every wallet checkpoint,
    //    and outgrow the old chain with 70 blocks to a fresh address. The receive is
    //    non-final at 139 and leaves the node's mempool.
    let old_140 = block_hash(&node, FORK).await;
    node.call("invalidateblock", json!([old_140]))
        .await
        .expect("invalidateblock");
    assert_eq!(node.height().await, FORK - 1);
    assert!(
        node.mempool().await.is_empty(),
        "the non-final receive left the mempool: {:?}",
        node.mempool().await
    );
    let replacement_miner = node.new_address().await;
    node.mine_to(&replacement_miner, 70).await;
    assert_eq!(node.height().await, 209);
    let new_150 = block_hash(&node, BIRTHDAY).await;
    assert_ne!(new_150, old_140, "sanity");

    // 3. Convergence: the wallet follows the new chain to its tip. Over kyoto this is the
    //    escalation bottoming out at the dead anchor, clearing it, and restarting from
    //    genesis - several redials with backoff.
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
    zecd.wait_height(210).await;
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
                wi["birthday"]["anchor"]["height"] == json!(BIRTHDAY)
                    && wi["birthday"]["anchor"]["hash"] == json!(new_150)
            },
        )
        .await;
    }
}
