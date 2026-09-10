//! The Bitcoin engine's address lookahead (`[wallets.<name>] lookahead`), the knob a restore
//! or an xpub import needs when the wallet's history skipped more addresses than BDK's
//! default of 25 watches: an original wallet hands out thirty receiving addresses and is
//! paid at index 0 and index 29 only - a run of 28 never-paid addresses between them, wider
//! than the default - and is then restored twice from its 24 words.
//!
//! What it pins, over both chain sources: a restore at the default lookahead recovers the
//! first payment and **silently misses** the second (the trap the lookahead knob exists for, and the
//! reason the knob exists - over kyoto the node even fetches the block, since the recovery
//! scan watches 100 scripts, but the wallet's own index attributes an output only within
//! its lookahead); a restore with `lookahead = 40` recovers both, reports the paid address
//! at its original index, and the wallet spends the recovered funds. The original always
//! runs over bitcoind.
//!
//! Skips cleanly without a bitcoind (`BITCOIND_BIN` or PATH) or a zecd built without the
//! `bitcoin` feature - the same two probes as `regtest_btc.rs`.

use serde_json::json;
use zecd_regtest_harness::btc::{provisioned, BitcoinD, BtcBackend, ZecdBtc};

/// How many receiving addresses the original hands out; the last one is paid.
const ISSUED: usize = 30;

#[tokio::test(flavor = "multi_thread")]
async fn btc_lookahead_bridges_a_gap_the_default_misses_over_bitcoind() {
    lookahead_flow(BtcBackend::Bitcoind).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_lookahead_bridges_a_gap_the_default_misses_over_kyoto() {
    lookahead_flow(BtcBackend::Kyoto).await;
}

async fn lookahead_flow(restore_backend: BtcBackend) {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(bitcoind) = provisioned(dir.path()) else {
        return;
    };
    let node = BitcoinD::start(&bitcoind, &dir.path().join("btcdata")).await;
    node.mine(101).await;

    // 1. The original: thirty addresses issued, the first and the last paid.
    let (mnemonic, first, last) = {
        let mut zecd = ZecdBtc::prepare(
            dir.path().join("original"),
            BtcBackend::Bitcoind,
            &node,
            &["btc"],
        );
        let mnemonic = zecd
            .init_ok("btc", &["--birthday", "0"])
            .expect("a generated wallet prints its mnemonic");
        zecd.start().await;
        zecd.wait_height(101).await;
        let mut addresses = Vec::with_capacity(ISSUED);
        for _ in 0..ISSUED {
            let a = zecd
                .call("getnewaddress", json!([]))
                .await
                .expect("getnewaddress");
            addresses.push(a.as_str().unwrap().to_string());
        }
        let first = addresses[0].clone();
        let last = addresses[ISSUED - 1].clone();
        node.call("sendtoaddress", json!([first, 1.0]))
            .await
            .expect("pay index 0");
        node.call("sendtoaddress", json!([last, 2.0]))
            .await
            .expect("pay the last index");
        node.mine(1).await;
        zecd.wait_height(102).await;
        zecd.wait_wallet_balance("btc", 3.0).await;
        zecd.stop();
        (mnemonic, first, last)
    };
    let height = node.height().await;
    let phrase_file = dir.path().join("phrase.txt");
    std::fs::write(&phrase_file, format!("{mnemonic}\n")).unwrap();

    // 2. Restored at the default lookahead (25): index 29 lies past the window from
    //    index 0, so the second payment is not attributed - the balance is the first
    //    payment alone. This is the documented gap, pinned so a change in BDK's default
    //    or in the engine's attribution shows up here.
    {
        let mut zecd = ZecdBtc::prepare(
            dir.path().join("restore-default"),
            restore_backend,
            &node,
            &["btc"],
        );
        zecd.init_ok(
            "btc",
            &[
                "--restore",
                "--mnemonic-file",
                phrase_file.to_str().unwrap(),
                "--birthday",
                "0",
            ],
        );
        zecd.start().await;
        zecd.wait_height(height).await;
        zecd.wait_wallet_balance("btc", 1.0).await;
        // Give a late attribution every chance before calling it missed.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let balance = zecd
            .call("getbalance", json!([]))
            .await
            .expect("getbalance");
        assert_eq!(
            balance,
            json!(1.0),
            "[{}] the default lookahead cannot bridge {} unpaid addresses",
            restore_backend.label(),
            ISSUED - 2
        );
        let ai = zecd
            .call("getaddressinfo", json!([last]))
            .await
            .expect("getaddressinfo");
        assert_eq!(
            ai["ismine"],
            json!(false),
            "index {} is past the default window: {ai}",
            ISSUED - 1
        );
        zecd.stop();
    }

    // 3. Restored with the knob raised past the gap: both payments, the paid address
    //    recognised at its index, and the recovered funds spend.
    {
        let mut zecd = ZecdBtc::prepare_with(
            dir.path().join("restore-wide"),
            restore_backend,
            &node,
            &["btc"],
            "lookahead = 40",
        );
        zecd.init_ok(
            "btc",
            &[
                "--restore",
                "--mnemonic-file",
                phrase_file.to_str().unwrap(),
                "--birthday",
                "0",
            ],
        );
        zecd.start().await;
        zecd.wait_height(height).await;
        zecd.wait_wallet_balance("btc", 3.0).await;
        for (index, address) in [(0usize, &first), (ISSUED - 1, &last)] {
            let ai = zecd
                .call("getaddressinfo", json!([address]))
                .await
                .expect("getaddressinfo");
            assert_eq!(ai["ismine"], json!(true), "index {index}: {ai}");
            assert_eq!(ai["address_index"], json!(index), "{ai}");
        }
        let descriptors = zecd
            .call("listdescriptors", json!([]))
            .await
            .expect("listdescriptors");
        let external = &descriptors["descriptors"][0];
        assert_eq!(
            external["range"][1],
            json!(ISSUED as u64 + 40),
            "the range end is the next index plus the lookahead: {descriptors}"
        );
        let dest = node.new_address().await;
        let txid = zecd
            .call("sendtoaddress", json!([dest, 2.5]))
            .await
            .expect("spend the recovered funds (needs both payments)");
        assert!(txid.as_str().is_some_and(|t| t.len() == 64), "{txid}");
        node.mine(1).await;
        zecd.wait_height(height + 1).await;
        let tx = zecd
            .call("gettransaction", json!([txid]))
            .await
            .expect("gettransaction");
        assert_eq!(tx["confirmations"], json!(1), "{tx}");
    }
}
