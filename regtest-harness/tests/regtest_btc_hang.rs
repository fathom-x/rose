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
//! 3 only, and additionally pins the broadcast-timeout contract: a *send* attempted during
//! the hang returns within the broadcast timeout instead of wedging the actor (the one
//! kyoto path that does await the peer), and because the light client keeps it queued the
//! send is **recorded** and returns its txid - the inputs lock, so a retry cannot
//! double-spend them - while `abandontransaction` is the release valve. The leg also pins
//! that the valve is complete on the wallet's side: abandoning restarts the light client,
//! whose broadcast queue would otherwise have served the transaction to the peer the moment
//! it resumed, so after the resume the transaction never reaches the node and the released
//! input is spent by the post-recovery send.
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
    // The health server sees the Bitcoin wallet: healthy means running, ready means the
    // chain source reports the wallet at its tip. Before the fix a bitcoin-only
    // daemon's /readyz was 200 with nothing checked and /status listed no wallets.
    let (code, body) = zecd.health_get("healthz").await;
    assert_eq!(code, 200, "{body}");
    let ready = zecd
        .wait_readyz(200, "the synced wallet reports ready")
        .await;
    assert_eq!(ready["ready"], json!(true), "{ready}");
    let w = &ready["wallets"]["btc"];
    assert_eq!(w["coin"], json!("bitcoin"), "{ready}");
    assert_eq!(w["network"], json!("regtest"), "{ready}");
    assert_eq!(w["conn_state"], json!("ready"), "{ready}");
    assert_eq!(w["actor_alive"], json!(true), "{ready}");
    assert_eq!(w["synced_height"], json!(102), "{ready}");
    assert_eq!(w["birthday"], json!(0), "{ready}");
    assert!(
        w["server"]
            .as_str()
            .is_some_and(|s| s.starts_with(backend.label())),
        "{ready}"
    );
    let (_, status) = zecd.health_get("status").await;
    assert_eq!(status["wallets"]["btc"]["ready"], json!(true), "{status}");
    let miner = node.new_address().await;

    let mut queued_txid: Option<String> = None;

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
            // Readiness follows the detection: 503 naming the upstream, while liveness
            // stays 200 - the process is fine, its chain source is not.
            let body = zecd
                .wait_readyz(503, "the hung upstream fails readiness")
                .await;
            assert_eq!(body["reason"], json!("upstream_down"), "{body}");
            assert_eq!(
                body["wallets"]["btc"]["conn_state"],
                json!("down"),
                "{body}"
            );
            let (code, _) = zecd.health_get("healthz").await;
            assert_eq!(code, 200, "/healthz is liveness, not readiness");
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
            // `getdata`, which a stopped peer never sends. It must return within the
            // broadcast timeout (30s), releasing the actor, rather than wedge it - and it
            // returns a txid, not an error: the light client keeps the transaction queued
            // for the next peer, so the wallet records it (Core's commit-then-relay order)
            // rather than let a retry double-spend inputs the network may yet see spent.
            let t1 = Instant::now();
            let txid = tokio::time::timeout(
                DETECT_TIMEOUT,
                zecd.call(
                    "sendtoaddress",
                    json!([miner, 0.1, null, null, false, null, null, null, null, 2]),
                ),
            )
            .await
            .expect("a kyoto send during the hang must time out, not wedge the actor")
            .expect("a broadcast no peer answered is recorded and returns its txid");
            eprintln!(
                "[{}] send during the hang returned in {:?}: {txid}",
                backend.label(),
                t1.elapsed()
            );
            assert!(
                t1.elapsed() < Duration::from_secs(60),
                "bounded by the broadcast timeout"
            );
            // (No node RPC here: the node is stopped, and a call would park the test on it.
            // That the stopped peer never received the transaction is what step 3 shows,
            // when it relays after the resume.)
            // Recorded at 0-conf: the 1.0 input is spent and the change is the wallet's
            // own trusted unconfirmed output, so the trusted balance is 0.9 less the fee.
            let balance = zecd
                .call("getbalance", json!([]))
                .await
                .expect("getbalance after the queued send")
                .as_f64()
                .unwrap();
            assert!(
                balance < 1.0 && balance > 0.89,
                "{balance}: the queued send locks its input and returns its change"
            );
            let tx = zecd
                .call("gettransaction", json!([txid]))
                .await
                .expect("the queued send is a wallet transaction");
            assert_eq!(tx["confirmations"], json!(0), "{tx}");
            // A retry that would need the locked input is refused, not double-spent. An
            // explicit fee rate, like the first send's: fee estimation would otherwise ask
            // the stopped peer for a block, and the light client drops a peer that does not
            // answer a request, which turns the relay after the resume into a reconnect.
            let (code, msg) = zecd
                .call(
                    "sendtoaddress",
                    json!([miner, 0.95, null, null, false, null, null, null, null, 2]),
                )
                .await
                .expect_err("the locked input is not available to a second send");
            assert_eq!(code, -6, "{msg}");
            // The release valve: abandoning it frees the input at once, drops it from the
            // wallet's canonical history, and restarts the light client so its broadcast
            // queue (which still holds the signed bytes, with the `inv` already sitting in
            // the stopped peer's socket) forgets it too.
            zecd.call("abandontransaction", json!([txid]))
                .await
                .expect("abandontransaction on a queued, unrelayed send");
            let balance = zecd
                .call("getbalance", json!([]))
                .await
                .expect("getbalance after the abandonment");
            assert_eq!(
                balance.as_f64(),
                Some(1.0),
                "the abandoned send's input is spendable again"
            );
            let (code, msg) = zecd
                .call("gettransaction", json!([txid]))
                .await
                .expect_err("an abandoned transaction leaves the canonical set");
            assert_eq!(code, -5, "{msg}");
            queued_txid = Some(txid.as_str().unwrap().to_string());
        }
    }

    // 3. Recovery is automatic: resume the node, mine, and the wallet follows.
    node.resume();
    let expected_balance = 1.0;
    if queued_txid.is_some() {
        // The abandonment restarted the light client, so the old node - whose queue held
        // the transaction and whose `inv` the stopped peer is about to read - is gone, and
        // the new one has nothing to serve when the `getdata` comes. Wait for the wallet to
        // be back on the resumed peer before mining, so the window in which the old node
        // would have relayed has actually passed.
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let wi = zecd
                .call("getwalletinfo", json!([]))
                .await
                .expect("getwalletinfo after the abandonment");
            if wi["upstream_connected"] == json!(true) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the restarted light client never reconnected to the resumed peer: {wi}"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        eprintln!(
            "[{}] the restarted light client reconnected {:?} after the resume",
            backend.label(),
            t0.elapsed()
        );
        tokio::time::sleep(Duration::from_secs(3)).await;
        let mempool = node.mempool().await;
        assert!(
            mempool.is_empty(),
            "the abandoned transaction must not reach the node: {mempool:?}"
        );
    }
    node.mine(3).await;
    zecd.wait_height(105).await;
    zecd.wait_wallet_best_hash("btc", &node.best_hash().await)
        .await;
    if let Some(queued) = &queued_txid {
        let (code, msg) = zecd
            .call("gettransaction", json!([queued]))
            .await
            .expect_err("the abandoned transaction stays abandoned");
        assert_eq!(code, -5, "{msg}");
    }
    let wi = zecd
        .call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo after recovery");
    assert_eq!(wi["upstream_connected"], json!(true), "{wi}");
    let ready = zecd
        .wait_readyz(200, "readiness returns once the wallet is back at the tip")
        .await;
    assert_eq!(
        ready["wallets"]["btc"]["synced_height"],
        json!(105),
        "{ready}"
    );
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
