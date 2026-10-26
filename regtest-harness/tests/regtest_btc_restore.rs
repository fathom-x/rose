//! Restore-from-mnemonic for a Bitcoin wallet, end to end: a funded, spending wallet goes
//! away, and a fresh datadir restored from its 24 words (`init --restore --birthday 0`)
//! recovers the full history - receives at two external indexes with an unused one between
//! them (the gap the lookahead must cover), a spend consuming both and its change on the
//! internal keychain - reports the same balance, derives the same account key, and can
//! spend again.
//!
//! Two restores from the same original: one over the bitcoind backend (block emission from
//! the birthday), one over kyoto (a BIP-157 recovery scan from the regtest genesis floor,
//! the path a real light-client restore takes). The original always runs over bitcoind;
//! the kyoto leg is therefore also a cross-backend restore.
//!
//! Along the way the three Bitcoin-served methods no other suite touched: `getbalances`,
//! `getbestblockhash` (the wallet's own checkpoint, against the node's), and
//! `validateaddress`.
//!
//! And the send gate a restore puts in force over kyoto: the kyoto leg is refused
//! every spend - `sendrawtransaction` of a wallet-funded transaction included - until it
//! opts out, and still relays what spends none of its coins. The bitcoind leg waits for
//! the node's mempool: an RPC proxy withholds `getrawmempool` until the leg has seen the
//! send refused, then lets the first mempool pass at tip through, which opens sends and
//! records the view; the database then moves to kyoto and spends at once.
//!
//! Skips cleanly without a bitcoind (`BITCOIND_BIN` or PATH) or a rose built without the
//! `bitcoin` feature - the same two probes as `regtest_btc.rs`.

use rose_regtest_harness::btc::{provisioned, BitcoinD, BtcBackend, RoseBtc, RpcProxy};
use serde_json::{json, Value};

#[tokio::test(flavor = "multi_thread")]
async fn btc_restore_from_mnemonic_recovers_history_over_bitcoind() {
    restore_flow(BtcBackend::Bitcoind).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_restore_from_mnemonic_recovers_history_over_kyoto() {
    restore_flow(BtcBackend::Kyoto).await;
}

/// What the original wallet left on chain, for the restored one to recover.
struct Original {
    mnemonic: String,
    xpub: String,
    addresses: [String; 3],
    fund_txid: Value,
    send_txid: Value,
    balance: f64,
    height: u64,
}

async fn restore_flow(restore_backend: BtcBackend) {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(bitcoind) = provisioned(dir.path()) else {
        return;
    };
    let node = BitcoinD::start(&bitcoind, &dir.path().join("btcdata")).await;
    node.mine(101).await;

    // 1. The original: generated seed, funded at external indexes 0 and 2 (index 1 issued
    //    but never paid - the gap a restore's lookahead must bridge), then a spend large
    //    enough to need both inputs, whose change lands on the internal keychain.
    let original = {
        let mut rose = RoseBtc::prepare(
            dir.path().join("original"),
            BtcBackend::Bitcoind,
            &node,
            &["btc"],
        );
        let mnemonic = rose
            .init_ok("btc", &["--birthday", "0"])
            .expect("a fresh init prints its mnemonic on stdout");
        assert_eq!(
            mnemonic.split_whitespace().count(),
            24,
            "init emits a 24-word phrase: {mnemonic}"
        );
        let xpub = rose.export_xpub("btc").expect("export-xpub");
        rose.start().await;
        rose.wait_height(101).await;
        let mut addresses: [String; 3] = Default::default();
        for slot in addresses.iter_mut() {
            *slot = rose
                .call("getnewaddress", json!([]))
                .await
                .expect("getnewaddress")
                .as_str()
                .unwrap()
                .to_string();
        }
        let fund_txid = node
            .call(
                "sendmany",
                json!(["", {addresses[0].clone(): 1.0, addresses[2].clone(): 0.5}]),
            )
            .await
            .expect("fund indexes 0 and 2");
        node.mine(1).await;
        rose.wait_height(102).await;
        rose.wait_wallet_balance("btc", 1.5).await;
        let miner = node.new_address().await;
        let send_txid = rose
            .call("sendtoaddress", json!([miner, 1.2]))
            .await
            .expect("original send");
        node.mine(1).await;
        rose.wait_height(103).await;
        let balance = rose
            .call("getbalance", json!([]))
            .await
            .expect("getbalance")
            .as_f64()
            .unwrap();
        assert!(
            balance > 0.29 && balance < 0.3,
            "1.5 - 1.2 - fee: {balance}"
        );
        rose.stop();
        Original {
            mnemonic,
            xpub,
            addresses,
            fund_txid,
            send_txid,
            balance,
            height: 103,
        }
    };
    // The original datadir is never touched again; the restore knows only the phrase.
    std::fs::remove_dir_all(dir.path().join("original")).expect("discard the original datadir");

    // 2. Restore on a fresh datadir from the phrase alone (a file, the non-interactive
    //    path), scanning from genesis. Over bitcoind through a proxy that withholds the
    //    node's mempool, so step 5 can see a send wait for it.
    let proxy = match restore_backend {
        BtcBackend::Bitcoind => {
            let proxy = RpcProxy::start(node.rpc_port).await;
            proxy.drop_method(Some("getrawmempool"));
            Some(proxy)
        }
        BtcBackend::Kyoto => None,
    };
    let restored_dir = dir.path().join("restored");
    let mut rose = match &proxy {
        Some(proxy) => RoseBtc::prepare_bitcoind_at(restored_dir, proxy.port, &["btc"]),
        None => RoseBtc::prepare(restored_dir, restore_backend, &node, &["btc"]),
    };
    let phrase_file = dir.path().join("phrase.txt");
    std::fs::write(&phrase_file, format!("{}\n", original.mnemonic)).unwrap();
    let printed = rose.init_ok(
        "btc",
        &[
            "--restore",
            "--mnemonic-file",
            phrase_file.to_str().unwrap(),
            "--birthday",
            "0",
        ],
    );
    assert!(
        printed.is_none(),
        "a restore prints no mnemonic (nothing new to back up): {printed:?}"
    );
    // Same seed: the same account key, before any chain data is seen.
    assert_eq!(rose.export_xpub("btc").expect("export-xpub"), original.xpub);
    rose.start().await;
    rose.wait_height(original.height).await;

    // 3. Full recovery: balance, both receives (across the unused index), the send and
    //    its change - none of which the restored wallet ever saw live.
    rose.wait_wallet_balance("btc", original.balance).await;
    let txs = rose
        .call("listtransactions", json!([]))
        .await
        .expect("listtransactions");
    let entries = txs.as_array().unwrap();
    let receives: Vec<&Value> = entries
        .iter()
        .filter(|e| e["txid"] == original.fund_txid)
        .collect();
    assert_eq!(receives.len(), 2, "one receive entry per paid index: {txs}");
    for (address, amount) in [(&original.addresses[0], 1.0), (&original.addresses[2], 0.5)] {
        let entry = receives
            .iter()
            .find(|e| e["address"].as_str() == Some(address))
            .unwrap_or_else(|| panic!("receive at {address} recovered: {txs}"));
        assert_eq!(entry["category"], json!("receive"), "{entry}");
        assert_eq!(entry["amount"].as_f64(), Some(amount), "{entry}");
        assert_eq!(entry["confirmations"], json!(2), "{entry}");
    }
    let send = entries
        .iter()
        .find(|e| e["txid"] == original.send_txid)
        .unwrap_or_else(|| panic!("the spend recovered: {txs}"));
    assert_eq!(send["category"], json!("send"), "{send}");
    assert_eq!(send["amount"].as_f64(), Some(-1.2), "{send}");
    assert!(send["fee"].as_f64().is_some_and(|f| f < 0.0), "{send}");
    let unspent = rose
        .call("listunspent", json!([]))
        .await
        .expect("listunspent");
    assert_eq!(unspent.as_array().map(Vec::len), Some(1), "{unspent}");
    assert_eq!(
        unspent[0]["txid"], original.send_txid,
        "the change: {unspent}"
    );
    let change = unspent[0]["address"].as_str().unwrap();
    let ai = rose
        .call("getaddressinfo", json!([change]))
        .await
        .expect("getaddressinfo on the change");
    assert_eq!(ai["ischange"], json!(true), "{ai}");
    // Every issued address belongs to the restored wallet at its original index - the
    // unpaid one included (within the lookahead, never revealed here, still recognised).
    for (index, address) in original.addresses.iter().enumerate() {
        let ai = rose
            .call("getaddressinfo", json!([address]))
            .await
            .expect("getaddressinfo");
        assert_eq!(ai["ismine"], json!(true), "index {index}: {ai}");
        assert_eq!(ai["address_index"], json!(index), "{ai}");
        assert_eq!(ai["ischange"], json!(false), "{ai}");
    }

    // 4. The reads no other suite exercises. `getbalances` mirrors Core's shape and agrees
    //    with `getbalance`; the wallet's best block is the node's; `validateaddress` is a
    //    parse, never an error.
    let balances = rose
        .call("getbalances", json!([]))
        .await
        .expect("getbalances");
    assert_eq!(
        balances["mine"]["trusted"].as_f64(),
        Some(original.balance),
        "{balances}"
    );
    assert_eq!(
        balances["mine"]["untrusted_pending"].as_f64(),
        Some(0.0),
        "{balances}"
    );
    assert_eq!(
        balances["mine"]["immature"].as_f64(),
        Some(0.0),
        "{balances}"
    );
    let best = rose
        .call("getbestblockhash", json!([]))
        .await
        .expect("getbestblockhash");
    assert_eq!(
        best.as_str(),
        Some(node.best_hash().await.as_str()),
        "{best}"
    );
    let valid = rose
        .call("validateaddress", json!([original.addresses[0]]))
        .await
        .expect("validateaddress");
    assert_eq!(valid["isvalid"], json!(true), "{valid}");
    assert_eq!(valid["address"], json!(original.addresses[0]), "{valid}");
    let invalid = rose
        .call("validateaddress", json!(["bcrt1qnotanaddress"]))
        .await
        .expect("validateaddress on garbage answers, never errors");
    assert_eq!(invalid["isvalid"], json!(false), "{invalid}");
    // A mainnet address is not valid for this regtest wallet.
    let wrong_net = rose
        .call(
            "validateaddress",
            json!(["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]),
        )
        .await
        .expect("validateaddress");
    assert_eq!(wrong_net["isvalid"], json!(false), "{wrong_net}");

    // 5. The restored wallet spends: seed-derived signers over recovered inputs (the
    //    change output, which only the internal keychain's restore made spendable). Over
    //    kyoto an explicit fee_rate prices it; over bitcoind estimatesmartfee has no data
    //    on a regtest chain either, so the same explicit rate keeps the legs identical.
    let miner = node.new_address().await;
    let send = json!([miner, 0.2, null, null, false, null, null, null, null, 2]);
    if let Some(proxy) = &proxy {
        // 5. (bitcoind) The restored database may be missing the original's unconfirmed
        //    sends until the node's mempool is matched against it, and the proxy has
        //    withheld that mempool all along: sends wait, though every block is in. A send
        //    beyond the balance probes the gate without spending - refused for the wait
        //    (`-4`) while it holds, for the funds (`-6`) once it lifts.
        let probe = json!([miner, 1000.0, null, null, false, null, null, null, null, 2]);
        // Each failed pass redials, and a probe that lands between dials is refused for
        // the connection (also `-4`) before it reaches the gate, so read until the gate
        // answers - and after lifting, until the funds do.
        let gate = |what: &'static str, done: fn(i64, &str) -> bool| {
            let rose = &rose;
            let probe = probe.clone();
            async move {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
                loop {
                    let (code, msg) = rose
                        .call("sendtoaddress", probe.clone())
                        .await
                        .expect_err("a probe beyond the balance never sends");
                    if done(code, &msg) {
                        return;
                    }
                    assert_eq!(code, -4, "{what}: {msg}");
                    assert!(
                        msg.contains("mempool view not yet established")
                            || msg.contains("no connection to the upstream"),
                        "{what}: {msg}"
                    );
                    assert!(std::time::Instant::now() < deadline, "{what}: {msg}");
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
            }
        };
        gate(
            "a restored bitcoind wallet waits for the node's mempool",
            |code, msg| code == -4 && msg.contains("mempool view not yet established"),
        )
        .await;
        proxy.drop_method(None);
        gate("the first mempool pass at tip opens sends", |code, _| {
            code == -6
        })
        .await;
    }
    if restore_backend == BtcBackend::Kyoto {
        // 5a. Over kyoto a restored wallet has no view of the original's unconfirmed sends
        //     (a light client sees them only once mined), and this stack's feed relays
        //     but takes no mempool snapshots - so it refuses to spend rather than risk a
        //     double spend. Bitcoind's mempool pass is that view; its leg spends.
        let refused = |what: &str, (code, msg): (i64, String)| {
            assert_eq!(code, -4, "{what}: {msg}");
            assert!(msg.contains("double-spend"), "{what}: {msg}");
            assert!(
                msg.contains("allow_sends_without_mempool_view"),
                "{what}: {msg}"
            );
        };
        refused(
            "a restored kyoto wallet with no mempool view",
            rose.call("sendtoaddress", send.clone())
                .await
                .expect_err("a restored kyoto wallet refuses to spend without a mempool view"),
        );
        // A caller-built spend of the wallet's coins is a spend like any other. The gate
        // runs before anything checks a signature, so an unsigned transaction over the
        // recovered change output is enough to reach it.
        let utxos = rose
            .call("listunspent", json!([]))
            .await
            .expect("listunspent");
        let utxo = &utxos.as_array().expect("an array")[0];
        let sats = (utxo["amount"].as_f64().unwrap() * 1e8).round() as u64;
        let unsigned = node
            .call(
                "createrawtransaction",
                json!([
                    [{"txid": utxo["txid"], "vout": utxo["vout"]}],
                    {miner.clone(): (sats - 10_000) as f64 / 1e8}
                ]),
            )
            .await
            .expect("createrawtransaction over a wallet output");
        refused(
            "sendrawtransaction of a wallet-funded transaction",
            rose.call("sendrawtransaction", json!([unsigned]))
                .await
                .expect_err("a raw spend of the wallet's coins is gated too"),
        );
        // A transaction that spends none of the wallet's coins is no spend of its: the
        // gated wallet still relays it.
        let foreign = node
            .call(
                "createrawtransaction",
                json!([[], {node.new_address().await: 0.1}]),
            )
            .await
            .expect("createrawtransaction");
        let foreign = node
            .call("fundrawtransaction", json!([foreign]))
            .await
            .expect("fundrawtransaction")["hex"]
            .clone();
        let foreign = node
            .call("signrawtransactionwithwallet", json!([foreign]))
            .await
            .expect("signrawtransactionwithwallet")["hex"]
            .clone();
        let relayed = rose
            .call("sendrawtransaction", json!([foreign]))
            .await
            .expect("a foreign transaction is relayed by a gated wallet");
        node.wait_mempool_contains(relayed.as_str().unwrap()).await;
        // 5b. Persisted with the database, not held in memory: a restart of the synced
        //     datadir - which now has history of its own - is still refused, or a restart
        //     would be the way around the refusal.
        rose.restart().await;
        rose.wait_height(original.height).await;
        refused(
            "the same wallet after a restart",
            rose.call("sendtoaddress", send.clone())
                .await
                .expect_err("a restart does not lift the refusal"),
        );
        // 5c. The opt-out spends - and every start says, on the console, what it risks.
        rose.set_wallet_option("btc", "allow_sends_without_mempool_view = true");
        let log = dir.path().join("restored-opted-out.log");
        rose.log_to(log.clone());
        rose.restart().await;
        rose.wait_height(original.height).await;
        let logged = std::fs::read_to_string(&log).expect("the daemon log");
        assert!(
            logged.contains("allow_sends_without_mempool_view is set")
                && logged.contains("DOUBLE SPEND"),
            "the opted-out start warns of the double-spend risk:\n{logged}"
        );
    }
    let restored_send = rose
        .call("sendtoaddress", send)
        .await
        .expect("the restored wallet spends");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !node
        .mempool()
        .await
        .contains(&restored_send.as_str().unwrap().to_string())
    {
        assert!(
            std::time::Instant::now() < deadline,
            "the restored wallet's send never reached the node mempool"
        );
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    node.mine(1).await;
    rose.wait_height(original.height + 1).await;
    let tx = rose
        .call("gettransaction", json!([restored_send]))
        .await
        .expect("gettransaction on the restored send");
    assert_eq!(tx["confirmations"], json!(1), "{tx}");
    let balance = rose
        .call("getbalance", json!([]))
        .await
        .expect("getbalance")
        .as_f64()
        .unwrap();
    assert!(
        balance < original.balance - 0.2 && balance > original.balance - 0.21,
        "{balance} after spending 0.2 from {}",
        original.balance
    );

    // 6. The bitcoind leg's mempool pass at tip matched the node's whole mempool against
    //    the restored wallet and recorded the view as established. Moved to kyoto -
    //    whose feed here takes no snapshots, so an unverified database would be refused -
    //    the same database spends at once: the record outlives the backend and the restart.
    if restore_backend == BtcBackend::Bitcoind {
        rose.set_wallet_backend("btc", BtcBackend::Kyoto, &node);
        rose.restart().await;
        rose.wait_height(original.height + 1).await;
        let send = json!([miner, 0.01, null, null, false, null, null, null, null, 2]);
        let moved = rose
            .call("sendtoaddress", send)
            .await
            .expect("a database whose view was established spends over kyoto at once");
        node.wait_mempool_contains(moved.as_str().unwrap()).await;
    }
}
