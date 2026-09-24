//! The kyoto fee chain live (`[fees]`, `btc/fee_samples.rs`): the block-sample estimate
//! behind the `peer_median` tier and the plausibility check on the HTTP oracles, against a
//! regtest Bitcoin Core and two stand-in oracles this test serves itself.
//!
//! 1. **An implausible oracle falls through.** The stand-in mempool.space answers
//!    1000 sat/vB while recent blocks paid a few dozen; the wallet disbelieves it and takes
//!    the stand-in Esplora's 3 sat/vB.
//! 2. **Blocks that paid well but were not full price at the relay floor.** With both
//!    oracles down the chain reaches the peer tier. Five recent blocks each carry a
//!    100 sat/vB payment, so their averages are tens of sat/vB - the old median-plus-20%
//!    estimator priced a send there - but none was full, so every transaction paying the
//!    floor got in, and the estimate is 1 sat/vB at every target.
//! 3. **A send priced by the peer tier pays that.** `sendtoaddress ... verbose` names
//!    `peer_median`, and the node holds the transaction at about 1 sat/vB.
//!
//! Kyoto only: over bitcoind the fee is `estimatesmartfee`'s. Skips cleanly without a
//! bitcoind or a zecd built without the `bitcoin` feature.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use zecd_regtest_harness::btc::{provisioned, BitcoinD, BtcBackend, ZecdBtc};

/// A BTC amount as satoshis.
fn sats(v: &Value) -> u64 {
    (v.as_f64().expect("an amount") * 1e8).round() as u64
}

/// Serve the two stand-in oracles on one port until the test ends: `/mempool` answers a
/// mempool.space body at 1000 sat/vB, `/esplora` an Esplora body at 3 sat/vB while
/// `esplora_up` holds, and a 503 after.
async fn serve_oracles(esplora_up: Arc<AtomicBool>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind oracles");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let esplora_up = Arc::clone(&esplora_up);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let (status, body) = if request.starts_with("GET /mempool") {
                    (
                        "200 OK",
                        r#"{"fastestFee":1200,"halfHourFee":1100,"hourFee":1000,"economyFee":900,"minimumFee":1}"#,
                    )
                } else if request.starts_with("GET /esplora") && esplora_up.load(Ordering::SeqCst) {
                    ("200 OK", r#"{"1":4.0,"6":3.0,"12":2.0}"#)
                } else {
                    ("503 Service Unavailable", "{}")
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_kyoto_fee_chain_checks_oracles_and_gates_on_fullness() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(bitcoind) = provisioned(dir.path()) else {
        return;
    };
    let esplora_up = Arc::new(AtomicBool::new(true));
    let oracle_port = serve_oracles(Arc::clone(&esplora_up)).await;
    let node = BitcoinD::start(&bitcoind, &dir.path().join("btcdata")).await;
    node.mine(101).await;
    let fees = format!(
        "[fees]\nmempool_space_url = \"http://127.0.0.1:{oracle_port}/mempool\"\n\
         esplora_url = \"http://127.0.0.1:{oracle_port}/esplora\"\n"
    );
    let mut zecd = ZecdBtc::prepare_full(
        dir.path().join("zecddata"),
        BtcBackend::Kyoto,
        &node,
        &["btc"],
        "",
        &fees,
    );
    zecd.init_ok("btc", &["--birthday", "0"]);
    zecd.start().await;
    zecd.wait_height(101).await;

    // Fund the wallet, then five blocks that each carry a 100 sat/vB payment.
    let addr = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let addr = addr.as_str().unwrap().to_string();
    node.call("sendtoaddress", json!([addr, 1.0]))
        .await
        .expect("fund");
    node.mine(1).await;
    let miner = node.new_address().await;
    for _ in 0..5 {
        node.call(
            "sendtoaddress",
            json!([miner, 0.01, null, null, false, null, null, null, null, 100]),
        )
        .await
        .expect("a 100 sat/vB payment");
        node.mine(1).await;
    }
    zecd.wait_height(107).await;
    zecd.wait_wallet_balance("btc", 1.0).await;
    // The precondition step 2 rests on: the tip block's average rate - what the peer tier
    // samples - is far above the floor, and the block is nowhere near full.
    let tip = node
        .call("getbestblockhash", json!([]))
        .await
        .expect("getbestblockhash");
    let block = node
        .call("getblock", json!([tip, 1]))
        .await
        .expect("getblock");
    let stats = node
        .call("getblockstats", json!([tip, ["totalfee"]]))
        .await
        .expect("getblockstats");
    let weight = block["weight"].as_u64().unwrap();
    let average_sat_per_vb = stats["totalfee"].as_u64().unwrap() * 4 / weight;
    assert!(
        average_sat_per_vb >= 20,
        "{average_sat_per_vb} sat/vB: {block}"
    );
    assert!(weight < 100_000, "{block}");

    // 1. mempool.space's 1000 sat/vB is far above anything recent blocks paid: Esplora's
    //    3 sat/vB answers.
    let estimate = zecd
        .call("estimatesmartfee", json!([6]))
        .await
        .expect("estimatesmartfee");
    assert_eq!(estimate["source"], json!("esplora"), "{estimate}");
    assert_eq!(sats(&estimate["feerate"]), 3_000, "{estimate}");

    // 2. Both oracles down: the peer tier, priced at the relay floor because no recent
    //    block was full - whatever the target.
    esplora_up.store(false, Ordering::SeqCst);
    for target in [1, 6, 144] {
        let estimate = zecd
            .call("estimatesmartfee", json!([target]))
            .await
            .expect("estimatesmartfee");
        assert_eq!(estimate["source"], json!("peer_median"), "{estimate}");
        assert_eq!(
            sats(&estimate["feerate"]),
            1_000,
            "target {target}: {estimate}"
        );
    }

    // 3. A send takes the same answer.
    let sent = zecd
        .call(
            "sendtoaddress",
            json!([miner, 0.1, null, null, false, null, null, null, null, null, true]),
        )
        .await
        .expect("a send priced by the peer tier");
    assert_eq!(sent["fee_reason"], json!("peer_median"), "{sent}");
    let txid = sent["txid"].as_str().unwrap().to_string();
    node.wait_mempool_contains(&txid).await;
    let entry = node
        .call("getmempoolentry", json!([txid]))
        .await
        .expect("getmempoolentry");
    let fee = sats(&entry["fees"]["base"]);
    let vsize = entry["vsize"].as_u64().unwrap();
    assert!(
        fee <= 2 * vsize,
        "priced near the floor, not the blocks' averages: {entry}"
    );
}
