//! End-to-end test of the account-to-keys binding (`wallet::binding`): `rose init` pins the
//! account's UFVK into `keys.toml`, startup verifies the wallet database against the pin
//! (backfilling it on a pre-pin `keys.toml`), and a swapped `data.sqlite` refuses to serve,
//! both at daemon startup and at `rose init` time.
//!
//! Skips cleanly when the node binary isn't provisioned (so plain `cargo test` and the
//! build-only CI path still validate that the harness compiles). Provide `ZEBRAD_BIN` to run
//! the full flow. Runs in the default (non-extended) tier: it needs only one
//! zebra and two short-lived rose instances.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use rose_regtest_harness::{
    pick_port, resolve_node_bin, rose_bin, RegtestNode, Rose, RoseConfig, Zebrad,
};
use serde_json::json;

/// Blocks mined before launching rose. Regtest mining is cheap (PoW disabled).
const INITIAL_BLOCKS: u32 = 10;
/// Generous: rose scan over a fresh regtest chain.
const SYNC_TIMEOUT: Duration = Duration::from_secs(120);

/// Read the pinned `ufvk` value out of a wallet's `keys.toml`, if present.
fn pinned_ufvk(keys_toml: &Path) -> Option<String> {
    let text = std::fs::read_to_string(keys_toml).expect("read keys.toml");
    text.lines().find_map(|line| {
        line.strip_prefix("ufvk = \"")
            .and_then(|rest| rest.strip_suffix('"'))
            .map(str::to_string)
    })
}

/// Rewrite `keys.toml` without its `ufvk` line, simulating a file written by a rose from
/// before the pin existed (the upgrade path the daemon must backfill).
fn strip_pin(keys_toml: &Path) {
    let text = std::fs::read_to_string(keys_toml).expect("read keys.toml");
    let stripped: String = text
        .lines()
        .filter(|line| !line.starts_with("ufvk = "))
        .map(|line| format!("{line}\n"))
        .collect();
    std::fs::write(keys_toml, stripped).expect("rewrite keys.toml without the pin");
}

#[tokio::test]
async fn regtest_account_binding() {
    let Some(zebrad_bin) = resolve_node_bin() else {
        eprintln!(
            "SKIP regtest_account_binding: set {} to run the live e2e. The harness still compiled \
             and linked.",
            RegtestNode::from_env().bin_env()
        );
        return;
    };

    let zebrad = Zebrad::start(&zebrad_bin)
        .await
        .expect("launch zebrad regtest");
    zebrad
        .generate_blocks(INITIAL_BLOCKS)
        .await
        .expect("mine initial regtest blocks");

    // ---- 1. init pins the account UFVK into keys.toml, and it matches export-ufvk ----

    let cfg = RoseConfig::new(zebrad.rpc_port, pick_port().expect("pick rose rpc port"));
    let mut rose = Rose::start(&cfg).await.expect("start rose");
    rose.wait_until_synced(INITIAL_BLOCKS as u64, SYNC_TIMEOUT)
        .await
        .expect("rose scans to the regtest tip");

    let keys_toml = rose.wallet_dir("default").join("keys.toml");
    let pin = pinned_ufvk(&keys_toml).expect("rose init must pin the account UFVK");
    assert!(
        pin.starts_with("uviewregtest1"),
        "the pin is a regtest-encoded UFVK, got {pin}"
    );
    let exported = rose.export_ufvk("default").expect("export-ufvk");
    assert_eq!(
        pin, exported,
        "the pinned UFVK is exactly the account's (export-ufvk) key"
    );

    // ---- 2. a pre-pin keys.toml starts normally and gets the pin backfilled ----

    rose.stop_keeping_datadir().await.expect("stop rose");
    strip_pin(&keys_toml);
    assert_eq!(pinned_ufvk(&keys_toml), None, "pin stripped for the test");
    rose.respawn().await.expect("a legacy keys.toml must start");
    let addr = rose
        .call("getnewaddress", json!([]))
        .await
        .expect("the upgraded wallet serves RPCs");
    assert!(addr.as_str().unwrap_or_default().starts_with("uregtest1"));
    assert_eq!(
        pinned_ufvk(&keys_toml).as_deref(),
        Some(exported.as_str()),
        "startup backfills the pin trust-on-first-use with the account's real UFVK"
    );

    // ---- 3. a swapped data.sqlite refuses to serve (fail closed) ----

    // A second, unrelated wallet supplies the foreign database (its own fresh mnemonic).
    let cfg_b = RoseConfig::new(zebrad.rpc_port, pick_port().expect("pick second rpc port"));
    let mut foreign = Rose::start(&cfg_b).await.expect("start the foreign rose");
    foreign
        .stop_keeping_datadir()
        .await
        .expect("stop the foreign rose");
    let foreign_db = foreign.engine_dir("default").join("data.sqlite");

    rose.stop_keeping_datadir().await.expect("stop rose again");
    let engine_dir = rose.engine_dir("default");
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(engine_dir.join(format!("data.sqlite{suffix}")));
    }
    std::fs::copy(&foreign_db, engine_dir.join("data.sqlite")).expect("swap in the foreign db");

    let stderr = rose
        .respawn_expect_startup_failure()
        .await
        .expect("a swapped database must refuse startup");
    assert!(
        stderr.contains("keys.toml") && stderr.contains("does not"),
        "the refusal names the binding mismatch; stderr:\n{stderr}"
    );

    // ---- 4. `rose init` refuses a database that already contains an account ----

    // The foreign wallet's datadir, with keys.toml removed: exactly the audit's scenario of a
    // pre-existing account-bearing database in a directory about to be initialized. The guard
    // runs before any interactive or network I/O, so the refusal is immediate.
    std::fs::remove_file(foreign.wallet_dir("default").join("keys.toml"))
        .expect("remove the foreign wallet's keys.toml");
    let out = Command::new(rose_bin())
        .args([
            "--datadir",
            foreign.datadir().to_str().unwrap(),
            "--regtest",
            "init",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run rose init on the account-bearing datadir");
    assert!(
        !out.status.success(),
        "init into an account-bearing database must refuse"
    );
    let init_err = String::from_utf8_lossy(&out.stderr);
    assert!(
        init_err.contains("already contains"),
        "the init refusal names the pre-existing account; stderr:\n{init_err}"
    );
}
