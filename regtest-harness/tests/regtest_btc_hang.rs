//! Hang-class fault test for the Bitcoin engine, over both chain sources: a Bitcoin Core
//! that *stops responding without dying* (SIGSTOP). The kernel keeps a stopped process's
//! sockets alive - TCP connects succeed and segments are ACKed - so neither a dead-peer
//! error nor a dial failure ever fires; only a per-request deadline can notice.
//!
//! Over the bitcoind backend that deadline is `btc::chain::RPC_DEADLINE` on the blocking
//! JSON-RPC client the actor drives under `block_in_place`. Three contracts, the same
//! three `regtest_hang.rs` holds the Zcash actor to:
//!
//! 1. the actor's command loop stays live - a read that round-trips through it answers
//!    within a bounded time even while a sync pass is parked on a hung call;
//! 2. the hang is detected - `getwalletinfo.upstream_connected` flips false although the
//!    node never exited and its socket still accepts;
//! 3. recovery is automatic once the node resumes: the wallet reconnects and follows the
//!    blocks mined after the pause.
//!
//! Over kyoto the sync side is a non-blocking poll of the light client's channel, so the
//! command loop cannot park on the peer at all; the P2P connection simply stalls with the
//! peer and resumes with it. The kyoto leg therefore holds the wallet to contracts 1 and
//! 3 only, and additionally pins what the send error text promises: a *send* attempted
//! during the hang fails within the broadcast timeout instead of wedging the actor (the
//! one kyoto path that does await the peer), records nothing, and - because the light
//! client keeps it queued - still relays once the peer resumes, at which point the wallet
//! learns of it from the chain like any foreign spend of its output.
//!
//! Skips cleanly without a bitcoind (`BITCOIND_BIN` or PATH) or a zecd built without the
//! `bitcoin` feature - the same two probes as `regtest_btc.rs`.

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::btc::{provisioned, BitcoinD, BtcBackend, ZecdBtc};

/// Worst-case time for the actor to notice the hang and free its loop: one hung request
/// (two RPC deadlines of 15s - the transport retries a broken socket once) plus generous
/// slack for a reconnect attempt that itself parks on the stopped-but-accepting socket.
const DETECT_TIMEOUT: Duration = Duration::from_secs(90);

#[tokio::test(flavor = "multi_thread")]
async fn btc_hung_upstream_detected_and_recovered_over_bitcoind() {
    hang_flow(BtcBackend::Bitcoind).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_hung_upstream_detected_and_recovered_over_kyoto() {
    hang_flow(BtcBackend::Kyoto).await;
}

async fn hang_flow(backend: BtcBackend) {
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
    // Funded, so the kyoto send probe below gets as far as the broadcast.
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
    let wi = zecd
        .call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo");
    assert_eq!(wi["upstream_connected"], json!(true), "{wi}");
    let miner = node.new_address().await;

    // Hang - don't kill - the node.
    node.pause();
    // Give the actor's next sync pass time to run into the stopped socket, so the probe
    // below measures a command queued *behind* a hung call, not ahead of it.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // 1. The command loop must not wedge behind the hung sync path. `getbalance`
    //    round-trips through the actor and touches no network, so it measures pure
    //    command-loop latency: at most one RPC deadline, never forever.
    let t0 = Instant::now();
    let balance = tokio::time::timeout(DETECT_TIMEOUT, zecd.call("getbalance", json!([])))
        .await
        .expect("the actor command loop must answer while the upstream hangs")
        .expect("getbalance");
    assert_eq!(
        balance.as_f64(),
        Some(1.0),
        "the wallet's own state still serves"
    );
    eprintln!(
        "[{}] actor answered a command in {:?} with the upstream hung",
        backend.label(),
        t0.elapsed()
    );

    match backend {
        BtcBackend::Bitcoind => {
            // 2. The hang is detected: the RPC deadline fails the sync pass, the actor
            //    drops the connection, and the wallet reports it - although the process
            //    never exited and its socket still accepts.
            let deadline = Instant::now() + DETECT_TIMEOUT;
            loop {
                let wi = zecd
                    .call("getwalletinfo", json!([]))
                    .await
                    .expect("getwalletinfo");
                if wi["upstream_connected"] == json!(false) {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "the hung upstream was never detected: {wi}"
                );
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            eprintln!(
                "[{}] hang detected {:?} after the pause",
                backend.label(),
                t0.elapsed()
            );
            // A send while disconnected is refused up front (-4, no upstream), not parked
            // on the dead socket for fee estimation and broadcast.
            let (code, msg) = tokio::time::timeout(
                Duration::from_secs(30),
                zecd.call("sendtoaddress", json!([miner, 0.1])),
            )
            .await
            .expect("a send while the upstream hangs must answer promptly")
            .expect_err("a send with no upstream connection is refused");
            assert_eq!(code, -4, "{msg}");
            assert!(msg.contains("no connection to the upstream"), "{msg}");
        }
        BtcBackend::Kyoto => {
            // The one kyoto path that awaits the peer: a broadcast resolves on the peer's
            // `getdata`, which a stopped peer never sends. It must fail within the
            // broadcast timeout (30s), releasing the actor, rather than wedge it.
            let t1 = Instant::now();
            let (code, msg) = tokio::time::timeout(
                DETECT_TIMEOUT,
                zecd.call(
                    "sendtoaddress",
                    json!([miner, 0.1, null, null, false, null, null, null, null, 2]),
                ),
            )
            .await
            .expect("a kyoto send during the hang must time out, not wedge the actor")
            .expect_err("no peer answers the broadcast");
            eprintln!(
                "[{}] send during the hang failed in {:?}: {code} {msg}",
                backend.label(),
                t1.elapsed()
            );
            assert!(
                t1.elapsed() < Duration::from_secs(60),
                "bounded by the broadcast timeout"
            );
            // And the failed broadcast recorded nothing: the inputs are not locked behind
            // a transaction that never left.
            let balance = zecd
                .call("getbalance", json!([]))
                .await
                .expect("getbalance after the failed send");
            assert_eq!(
                balance.as_f64(),
                Some(1.0),
                "no 0-conf record of a send that never relayed"
            );
        }
    }

    // 3. Recovery is automatic: resume the node, mine, and the wallet follows.
    node.resume();
    let mut expected_balance = 1.0;
    if backend == BtcBackend::Kyoto {
        // The timed-out broadcast was queued, not dropped: once the peer answers again it
        // requests and accepts the transaction. The wallet then meets it on chain as a
        // spend of its own output (the 0.1 gone, the change back on the internal
        // keychain) - exactly the "may still relay" the error text warns about, and why
        // the post-recovery send below has to come after it rather than double-spend it.
        let deadline = Instant::now() + Duration::from_secs(60);
        while node.mempool().await.is_empty() {
            assert!(
                Instant::now() < deadline,
                "the queued kyoto broadcast never relayed after the peer resumed"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        eprintln!(
            "[{}] the queued broadcast relayed {:?} after the resume",
            backend.label(),
            t0.elapsed()
        );
        expected_balance = 0.9;
    }
    node.mine(3).await;
    zecd.wait_height(105).await;
    zecd.wait_wallet_best_hash("btc", &node.best_hash().await)
        .await;
    let wi = zecd
        .call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo after recovery");
    assert_eq!(wi["upstream_connected"], json!(true), "{wi}");
    let balance = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance after recovery")
        .as_f64()
        .unwrap();
    assert!(
        balance <= expected_balance && balance > expected_balance - 0.01,
        "{balance} (expected {expected_balance} less at most a sat/vB-scale fee)"
    );
    // And it spends again over the recovered connection.
    let txid = zecd
        .call(
            "sendtoaddress",
            json!([miner, 0.1, null, null, false, null, null, null, null, 2]),
        )
        .await
        .expect("send after recovery");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !node
        .mempool()
        .await
        .contains(&txid.as_str().unwrap().to_string())
    {
        assert!(
            Instant::now() < deadline,
            "the post-recovery send never relayed"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
