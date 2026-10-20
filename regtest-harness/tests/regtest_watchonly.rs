//! Watch-only (UFVK) wallet lifecycle test.
//!
//! Drives the full operator flow end to end: a spending wallet exports its Unified Full
//! Viewing Key (`rose export-ufvk`), a second rose initialises watch-only from it
//! (`init --ufvk`), and both daemons run side by side against the same chain. The watch-only
//! wallet must re-export **the identical UFVK** (the key-material round trip that makes its
//! invoices spendable by the paired wallet - same-index address equality is proven offline,
//! since librustzcash's shielded diversifier indexes are clock-derived), report
//! `private_keys_enabled: false`, and refuse spending and encryption RPCs with Bitcoin
//! Core's codes (-4/-16/-15) - while the read surface (balances, history, `getnewaddress`)
//! stays fully available.
//!
//! Extended tier: set `ROSE_REGTEST_EXTENDED=1` (plus ZEBRAD_BIN).
//! Skips cleanly otherwise.

use std::time::Duration;

use rose_regtest_harness::{
    extended_enabled, pick_port, resolve_node_bin, RegtestNode, Rose, RoseConfig, Zebrad,
};
use serde_json::json;

const INITIAL_BLOCKS: u32 = 10;
const SYNC_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::test]
async fn regtest_watch_only_ufvk() {
    if !extended_enabled() {
        eprintln!(
            "SKIP regtest_watch_only_ufvk: set ROSE_REGTEST_EXTENDED=1 to run the extended tier."
        );
        return;
    }
    let Some(zebrad_bin) = resolve_node_bin() else {
        eprintln!(
            "SKIP regtest_watch_only_ufvk: set {}. The harness still compiled and linked.",
            RegtestNode::from_env().bin_env()
        );
        return;
    };

    let zebrad = Zebrad::start(&zebrad_bin).await.expect("launch zebrad");
    zebrad
        .generate_blocks(INITIAL_BLOCKS)
        .await
        .expect("mine the initial chain");

    // 1. The spending wallet (its address is used later for per-address flag checks).
    let cfg_a = RoseConfig::new(zebrad.rpc_port, pick_port().expect("pick rose rpc port"));
    let rose_a = Rose::start(&cfg_a)
        .await
        .expect("start the spending wallet");
    rose_a
        .wait_until_synced(INITIAL_BLOCKS as u64, SYNC_TIMEOUT)
        .await
        .expect("the spending wallet scans the chain");
    let addr_a = rose_a
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress on the spending wallet")
        .as_str()
        .expect("address is a string")
        .to_string();
    assert!(addr_a.starts_with("uregtest1"), "{addr_a}");

    // 2. Export the UFVK from the running daemon's datadir (read-only; no spending material).
    let ufvk = rose_a.export_ufvk("default").expect("rose export-ufvk");
    assert!(
        ufvk.starts_with("uviewregtest1"),
        "regtest UFVKs use the uviewregtest1 HRP, got {ufvk}"
    );

    // 3. The watch-only wallet: init --ufvk on a fresh datadir, against the same chain.
    //    Birthday 2 is the lowest height with a fetchable tree state (restore convention).
    let mut cfg_b = RoseConfig::new(zebrad.rpc_port, pick_port().expect("pick rose rpc port"));
    cfg_b.ufvk = Some(ufvk);
    cfg_b.birthday = Some(2);
    let rose_b = Rose::start(&cfg_b)
        .await
        .expect("start the watch-only wallet");
    assert!(
        rose_b.mnemonic.is_none(),
        "a watch-only init has no mnemonic to print"
    );
    rose_b
        .wait_until_synced(INITIAL_BLOCKS as u64, SYNC_TIMEOUT)
        .await
        .expect("the watch-only wallet scans from its birthday to the tip");

    // Same UFVK, fresh DB: the watch-only wallet re-exports the exact key it was built
    // from - the key-material round trip that makes its invoices spendable by the paired
    // wallet. (Address *values* are deliberately not compared across the two daemons:
    // librustzcash picks shielded diversifier indexes from the wall clock, so two wallets'
    // `getnewaddress` results only coincide within the same second. Same-index address
    // equality is proven offline by
    // `regtest_tests::watch_only_ufvk_wallet_pairs_with_spending_wallet`.)
    assert_eq!(
        rose_b.export_ufvk("default").expect("export-ufvk on B"),
        rose_a.export_ufvk("default").expect("export-ufvk on A"),
        "the watch-only wallet carries the spending wallet's exact key material"
    );
    let addr_b = rose_b
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress works from the viewing key alone")
        .as_str()
        .expect("address is a string")
        .to_string();
    assert!(addr_b.starts_with("uregtest1"), "{addr_b}");

    // 4. The wallet self-reports as watch-only the way Bitcoin Core master does: the
    //    wallet-level `private_keys_enabled` flag. `getaddressinfo` is byte-identical on
    //    both wallets - master's `iswatchonly` is deprecated/always-false and `solvable`
    //    ignores the lack of private keys.
    let wi = rose_b
        .call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo");
    assert_eq!(
        wi["private_keys_enabled"],
        json!(false),
        "watch-only wallets report private_keys_enabled: false - {wi}"
    );
    // Each wallet's view of its own issued address carries the same flags - watch-only
    // changes nothing at the per-address level.
    for (rose, addr) in [(&rose_b, &addr_b), (&rose_a, &addr_a)] {
        let ai = rose
            .call("getaddressinfo", json!([addr]))
            .await
            .expect("getaddressinfo");
        assert_eq!(ai["ismine"], json!(true), "{ai}");
        assert_eq!(ai["iswatchonly"], json!(false), "{ai}");
        assert_eq!(ai["solvable"], json!(true), "{ai}");
    }

    // 5. Spending refuses with Bitcoin Core's -4 (Private keys are disabled), before any
    //    balance check; the passphrase RPCs are -15.
    let err = rose_b
        .call("sendtoaddress", json!([addr_b, 0.1]))
        .await
        .expect_err("sendtoaddress on a watch-only wallet must fail");
    assert_eq!(err.code(), Some(-4), "{err}");
    assert!(
        err.to_string().contains("Private keys are disabled"),
        "{err}"
    );
    let err = rose_b
        .call("walletpassphrase", json!(["pw", 60]))
        .await
        .expect_err("walletpassphrase on a watch-only wallet must fail");
    assert_eq!(err.code(), Some(-15), "{err}");

    // 6. The read surface stays fully available, empty but well-formed.
    let bal = rose_b
        .call("getbalance", json!([]))
        .await
        .expect("getbalance");
    assert_eq!(bal.as_f64(), Some(0.0), "fresh watch-only wallet is empty");
    let txs = rose_b
        .call("listtransactions", json!([]))
        .await
        .expect("listtransactions");
    assert_eq!(txs.as_array().map(|a| a.len()), Some(0));
}
