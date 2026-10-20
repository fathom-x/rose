//! The Bitcoin engine's address lookahead (`[wallets.<name>] lookahead`), the knob a restore
//! or an xpub import needs when the wallet's history skipped more addresses than BDK's
//! default of 25 watches: an original wallet hands out thirty receiving addresses and is
//! paid at index 0 and index 29 only - a run of 28 never-paid addresses between them, wider
//! than the default - and is then restored twice from its 24 words.
//!
//! What it pins, over both chain sources: a restore at the default lookahead recovers the
//! first payment and **silently misses** the second (the trap the lookahead knob exists for, and the
//! reason the knob exists - over kyoto the light client watches the same `lookahead`
//! scripts, so the block is never fetched either); a restore with `lookahead = 40`
//! recovers both, reports the paid address at its original index, and the wallet spends
//! the recovered funds; and so does a restore
//! at the default lookahead with `initial_scan = 30`, the one-time floor that covers a
//! pre-issued address set without widening the window for the wallet's life. The original
//! always runs over bitcoind, and its `getwalletinfo.recovery` readout flips to
//! `restorable: false` when it issues past the horizon and back once the payment lands.
//!
//! The second test pins the other half of a restore over kyoto: a wallet paid
//! at 140 *consecutive* addresses - no gap at all - restored at the default lookahead. A
//! recovery scan hands the light client a fixed script set at start (`lookahead` past the
//! last revealed index) and never rescans the blocks it has passed, so the restore used to
//! stop at the end of that set and report synced; now the actor notices the reveals
//! walking past the watched set, rebuilds the client from the first block that could hold
//! a missed payment with the set the index now gives, and repeats until a pass reveals
//! nothing new - six passes here, one per lookahead of history.
//!
//! Skips cleanly without a bitcoind (`BITCOIND_BIN` or PATH) or a rose built without the
//! `bitcoin` feature - the same two probes as `regtest_btc.rs`.

use rose_regtest_harness::btc::{provisioned, BitcoinD, BtcBackend, RoseBtc};
use serde_json::json;

/// How many receiving addresses the original hands out; the last one is paid.
const ISSUED: usize = 30;

/// How many consecutive receive addresses the second original is paid at: several
/// lookaheads (25) of history, so a restore that never widens its set stops well short.
const USED: usize = 140;
/// Addresses paid per transaction and block in that history. At most the lookahead: BDK
/// indexes a transaction's outputs in one pass, so a payment to an index more than a
/// lookahead past the last revealed one is missed when it sorts before the reveal that
/// would have covered it, and Core shuffles `sendmany` outputs.
const PER_BLOCK: usize = 20;
/// What each of those addresses is paid, in sats (a whole number of them, so the expected
/// total is exact in the f64 the RPC answers), so the restored balance counts the
/// recovered ones.
const PER_ADDRESS_SAT: u64 = 1_000_000;

/// The original's whole history as a `getbalance` reading.
fn paid_total() -> f64 {
    (USED as u64 * PER_ADDRESS_SAT) as f64 / 1e8
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_lookahead_bridges_a_gap_the_default_misses_over_bitcoind() {
    lookahead_flow(BtcBackend::Bitcoind).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_lookahead_bridges_a_gap_the_default_misses_over_kyoto() {
    lookahead_flow(BtcBackend::Kyoto).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_restore_over_kyoto_discovers_used_addresses_past_the_recovery_set() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(bitcoind) = provisioned(dir.path()) else {
        return;
    };
    let node = BitcoinD::start(&bitcoind, &dir.path().join("btcdata")).await;
    node.mine(101).await;

    // 1. The original, over bitcoind: `USED` addresses issued in order and every one paid,
    //    `PER_BLOCK` per transaction and block.
    let (mnemonic, addresses) = {
        let mut rose = RoseBtc::prepare(
            dir.path().join("original"),
            BtcBackend::Bitcoind,
            &node,
            &["btc"],
        );
        let mnemonic = rose
            .init_ok("btc", &["--birthday", "0"])
            .expect("a generated wallet prints its mnemonic");
        rose.start().await;
        rose.wait_height(101).await;
        let mut addresses = Vec::with_capacity(USED);
        for _ in 0..USED {
            let a = rose
                .call("getnewaddress", json!([]))
                .await
                .expect("getnewaddress");
            addresses.push(a.as_str().unwrap().to_string());
        }
        for batch in addresses.chunks(PER_BLOCK) {
            let outputs: serde_json::Map<String, serde_json::Value> = batch
                .iter()
                .map(|a| (a.clone(), json!(PER_ADDRESS_SAT as f64 / 1e8)))
                .collect();
            node.call("sendmany", json!(["", outputs]))
                .await
                .expect("pay a batch of addresses");
            node.mine(1).await;
        }
        let height = node.height().await;
        rose.wait_height(height).await;
        rose.wait_wallet_balance("btc", paid_total()).await;
        rose.stop();
        (mnemonic, addresses)
    };
    let height = node.height().await;
    let phrase_file = dir.path().join("phrase.txt");
    std::fs::write(&phrase_file, format!("{mnemonic}\n")).unwrap();

    // 2. Restored over kyoto at the default lookahead. The first recovery scan watches
    //    indexes 0..=24 and the blocks it fetches reveal through 39; the block paying
    //    40..=59 matched no filter. The actor rescans from below the first block that
    //    paid an index whose reveal put an unwatched one in the window, with the set the
    //    index now gives, and repeats - each pass a lookahead further - until one reveals
    //    nothing new.
    let mut rose = RoseBtc::prepare(
        dir.path().join("restore-kyoto"),
        BtcBackend::Kyoto,
        &node,
        &["btc"],
    );
    rose.init_ok(
        "btc",
        &[
            "--restore",
            "--mnemonic-file",
            phrase_file.to_str().unwrap(),
            "--birthday",
            "0",
        ],
    );
    rose.start().await;
    rose.wait_height(height).await;
    rose.wait_wallet_balance("btc", paid_total()).await;
    let last = &addresses[USED - 1];
    let ai = rose
        .call("getaddressinfo", json!([last]))
        .await
        .expect("getaddressinfo");
    assert_eq!(ai["ismine"], json!(true), "index {}: {ai}", USED - 1);
    assert_eq!(ai["address_index"], json!(USED - 1), "{ai}");
    let descriptors = rose
        .call("listdescriptors", json!([]))
        .await
        .expect("listdescriptors");
    assert_eq!(
        descriptors["descriptors"][0]["range"][1],
        json!(USED as u64 + 25),
        "the range end is the next index plus the default lookahead: {descriptors}"
    );
    // Once a pass has revealed nothing past its set, the wallet is ready.
    rose.wait_readyz(200, "the discovery loop completed").await;
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
        let mut rose = RoseBtc::prepare(
            dir.path().join("original"),
            BtcBackend::Bitcoind,
            &node,
            &["btc"],
        );
        let mnemonic = rose
            .init_ok("btc", &["--birthday", "0"])
            .expect("a generated wallet prints its mnemonic");
        rose.start().await;
        rose.wait_height(101).await;
        let mut addresses = Vec::with_capacity(ISSUED);
        for _ in 0..ISSUED {
            let a = rose
                .call("getnewaddress", json!([]))
                .await
                .expect("getnewaddress");
            addresses.push(a.as_str().unwrap().to_string());
        }
        let first = addresses[0].clone();
        let last = addresses[ISSUED - 1].clone();
        // Index 29 lies past the default horizon (24): the daemon warned, and the readout
        // says a restore would miss it...
        let wi = rose
            .call("getwalletinfo", json!([]))
            .await
            .expect("getwalletinfo");
        assert_eq!(wi["recovery"]["horizon"], json!(24), "{wi}");
        assert_eq!(wi["recovery"]["issued_through"], json!(ISSUED - 1), "{wi}");
        assert_eq!(wi["recovery"]["restorable"], json!(false), "{wi}");
        node.call("sendtoaddress", json!([first, 1.0]))
            .await
            .expect("pay index 0");
        node.call("sendtoaddress", json!([last, 2.0]))
            .await
            .expect("pay the last index");
        node.mine(1).await;
        rose.wait_height(102).await;
        rose.wait_wallet_balance("btc", 3.0).await;
        // ...until the payment there leads a restore on: the horizon follows funding.
        let wi = rose
            .call("getwalletinfo", json!([]))
            .await
            .expect("getwalletinfo");
        assert_eq!(wi["recovery"]["horizon"], json!(ISSUED - 1 + 25), "{wi}");
        assert_eq!(wi["recovery"]["restorable"], json!(true), "{wi}");
        rose.stop();
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
        let mut rose = RoseBtc::prepare(
            dir.path().join("restore-default"),
            restore_backend,
            &node,
            &["btc"],
        );
        rose.init_ok(
            "btc",
            &[
                "--restore",
                "--mnemonic-file",
                phrase_file.to_str().unwrap(),
                "--birthday",
                "0",
            ],
        );
        rose.start().await;
        rose.wait_height(height).await;
        rose.wait_wallet_balance("btc", 1.0).await;
        // Give a late attribution every chance before calling it missed.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let balance = rose
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
        let ai = rose
            .call("getaddressinfo", json!([last]))
            .await
            .expect("getaddressinfo");
        assert_eq!(
            ai["ismine"],
            json!(false),
            "index {} is past the default window: {ai}",
            ISSUED - 1
        );
        rose.stop();
    }

    // 3. Restored with the knob raised past the gap: both payments, the paid address
    //    recognised at its index, and the recovered funds spend.
    {
        let mut rose = RoseBtc::prepare_with(
            dir.path().join("restore-wide"),
            restore_backend,
            &node,
            &["btc"],
            "lookahead = 40",
        );
        rose.init_ok(
            "btc",
            &[
                "--restore",
                "--mnemonic-file",
                phrase_file.to_str().unwrap(),
                "--birthday",
                "0",
            ],
        );
        rose.start().await;
        rose.wait_height(height).await;
        rose.wait_wallet_balance("btc", 3.0).await;
        for (index, address) in [(0usize, &first), (ISSUED - 1, &last)] {
            let ai = rose
                .call("getaddressinfo", json!([address]))
                .await
                .expect("getaddressinfo");
            assert_eq!(ai["ismine"], json!(true), "index {index}: {ai}");
            assert_eq!(ai["address_index"], json!(index), "{ai}");
        }
        let descriptors = rose
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
        let txid = rose
            .call("sendtoaddress", json!([dest, 2.5]))
            .await
            .expect("spend the recovered funds (needs both payments)");
        assert!(txid.as_str().is_some_and(|t| t.len() == 64), "{txid}");
        node.mine(1).await;
        rose.wait_height(height + 1).await;
        let tx = rose
            .call("gettransaction", json!([txid]))
            .await
            .expect("gettransaction");
        assert_eq!(tx["confirmations"], json!(1), "{tx}");
    }

    // 4. Restored at the default lookahead with the floor instead: indexes 0..30 are
    //    revealed at spawn, so the scan watches both paid addresses from its first pass,
    //    and the cursor continues past the floor.
    {
        let mut rose = RoseBtc::prepare_with(
            dir.path().join("restore-floor"),
            restore_backend,
            &node,
            &["btc"],
            &format!("initial_scan = {ISSUED}"),
        );
        rose.init_ok(
            "btc",
            &[
                "--restore",
                "--mnemonic-file",
                phrase_file.to_str().unwrap(),
                "--birthday",
                "0",
            ],
        );
        rose.start().await;
        rose.wait_height(height + 1).await;
        // Phase 3 spent 2.5 of the 3.0 to the node; what is left is the change (fee off).
        let balance = rose
            .call("getbalance", json!([]))
            .await
            .expect("getbalance");
        let left = balance.as_f64().unwrap();
        assert!(
            left > 0.49 && left < 0.5,
            "[{}] {balance}",
            restore_backend.label()
        );
        let ai = rose
            .call("getaddressinfo", json!([last]))
            .await
            .expect("getaddressinfo");
        assert_eq!(ai["ismine"], json!(true), "{ai}");
        assert_eq!(ai["address_index"], json!(ISSUED - 1), "{ai}");
        let wi = rose
            .call("getwalletinfo", json!([]))
            .await
            .expect("getwalletinfo");
        assert_eq!(wi["recovery"]["initial_scan"], json!(ISSUED), "{wi}");
        assert_eq!(wi["recovery"]["issued_through"], json!(ISSUED - 1), "{wi}");
        assert_eq!(wi["recovery"]["restorable"], json!(true), "{wi}");
        let next = rose
            .call(
                "getaddressinfo",
                json!([rose
                    .call("getnewaddress", json!([]))
                    .await
                    .expect("getnewaddress")]),
            )
            .await
            .expect("getaddressinfo");
        assert_eq!(next["address_index"], json!(ISSUED), "{next}");
    }
}
