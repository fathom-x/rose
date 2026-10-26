//! Passphrase-encrypted Bitcoin spending wallet, end to end, over both chain sources: the
//! operator flow `rose init --encrypt` and the Core-style `walletpassphrase`/`walletlock`
//! lifecycle against one regtest Bitcoin Core.
//!
//! What it pins: init pins the account xpub beside the encrypted seed; the daemon starts the
//! wallet locked (`unlocked_until: 0` on `getwalletinfo`, `locked` on `/status` and
//! `/readyz`, which still reports ready - reads, addresses and receives all work locked); a
//! send is Core's `-13` until `walletpassphrase`, a wrong passphrase `-14`; unlocked, a send
//! signs and relays; `walletlock` relocks at once and a short timeout relocks on its own; a
//! restart comes back locked; and `rose rescan` rebuilds the database from the pinned xpub
//! while the wallet stays locked, after which an unlock spends again. Over bitcoind it also
//! runs `conformance.py --passphrase` against the encrypted wallet (the encryption section's
//! lock/unlock state machine).
//!
//! Skips cleanly without a bitcoind (`BITCOIND_BIN` or PATH) or a rose built without the
//! `bitcoin` feature - the same two probes as `regtest_btc.rs`.

use rose_regtest_harness::btc::{provisioned, BitcoinD, BtcBackend, RoseBtc};
use serde_json::{json, Value};

const WALLET: &str = "btc";
const PASS: &str = "regtest-btc-pass";

#[tokio::test(flavor = "multi_thread")]
async fn btc_encrypted_wallet_locks_and_unlocks_over_bitcoind() {
    encrypted_flow(BtcBackend::Bitcoind).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_encrypted_wallet_locks_and_unlocks_over_kyoto() {
    encrypted_flow(BtcBackend::Kyoto).await;
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn unlocked_until(rose: &RoseBtc) -> i64 {
    let wi = rose
        .call_wallet(WALLET, "getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo");
    wi["unlocked_until"]
        .as_i64()
        .unwrap_or_else(|| panic!("an encrypted wallet reports unlocked_until: {wi}"))
}

/// `/status`'s lock flags: the top-level `locked` and the wallet's own.
async fn status_locked(rose: &RoseBtc) -> (bool, bool) {
    let (code, status) = rose.health_get("status").await;
    assert_eq!(code, 200, "{status}");
    assert_eq!(
        status["wallets"][WALLET]["encrypted"],
        json!(true),
        "{status}"
    );
    (
        status["locked"] == json!(true),
        status["wallets"][WALLET]["locked"] == json!(true),
    )
}

/// A send that must be refused as locked: Core's `-13`, naming `walletpassphrase`.
async fn assert_send_needs_unlock(rose: &RoseBtc, to: &str, what: &str) {
    let (code, msg) = rose
        .call_wallet(WALLET, "sendtoaddress", json!([to, 0.1]))
        .await
        .expect_err("a locked wallet must refuse to send");
    assert_eq!(code, -13, "{what}: {msg}");
    assert!(msg.contains("walletpassphrase"), "{what}: {msg}");
}

async fn unlock(rose: &RoseBtc, timeout: i64) {
    let reply = rose
        .call_wallet(WALLET, "walletpassphrase", json!([PASS, timeout]))
        .await
        .expect("walletpassphrase with the right passphrase");
    assert_eq!(reply, Value::Null);
}

async fn encrypted_flow(backend: BtcBackend) {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(bitcoind) = provisioned(dir.path()) else {
        return;
    };
    let node = BitcoinD::start(&bitcoind, &dir.path().join("btcdata")).await;
    // Past coinbase maturity before rose starts, so a kyoto first sync covers a real span.
    node.mine(101).await;

    // 1. Init with a passphrase: the seed is scrypt-encrypted, and the account xpub is
    //    pinned beside it (what the locked daemon verifies, and rebuilds, the database from).
    let mut rose = RoseBtc::prepare(dir.path().join("rosedata"), backend, &node, &[WALLET]);
    let mnemonic = rose
        .init_encrypted(WALLET, PASS, &["--birthday", "0"])
        .expect("a generated wallet prints its mnemonic");
    assert_eq!(mnemonic.split_whitespace().count(), 24, "{mnemonic}");
    let xpub = rose.export_xpub(WALLET).expect("export-xpub");
    let keys_toml = std::fs::read_to_string(rose.datadir.join(WALLET).join("keys.toml"))
        .expect("read keys.toml");
    assert!(
        keys_toml.contains("encryption = \"passphrase\""),
        "{keys_toml}"
    );
    assert!(
        keys_toml.contains(&format!("xpub = \"{xpub}\"")),
        "keys.toml pins the account xpub: {keys_toml}"
    );
    assert!(
        !rose.datadir.join("identity.txt").exists(),
        "the passphrase model needs no identity file"
    );

    // 2. The daemon starts it locked, yet ready for reads.
    rose.start().await;
    rose.wait_wallet_height(WALLET, 101).await;
    assert_eq!(unlocked_until(&rose).await, 0, "starts locked");
    let wi = rose
        .call_wallet(WALLET, "getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo");
    assert_eq!(wi["private_keys_enabled"], json!(true), "{wi}");
    assert_eq!(status_locked(&rose).await, (true, true));
    let readyz = rose.wait_readyz(200, "a locked wallet is read-ready").await;
    assert_eq!(readyz["locked"], json!(true), "{readyz}");

    // 3. Addresses and receives need no seed.
    let addr = rose
        .call_wallet(WALLET, "getnewaddress", json!([]))
        .await
        .expect("getnewaddress while locked");
    let addr = addr.as_str().unwrap().to_string();
    assert!(addr.starts_with("bcrt1"), "{addr}");
    node.call("sendtoaddress", json!([addr, 1.0]))
        .await
        .expect("fund");
    node.mine(1).await;
    rose.wait_wallet_height(WALLET, 102).await;
    rose.wait_wallet_balance(WALLET, 1.0).await;

    // 4. Locked: a send is -13 before any funds check; a wrong passphrase is -14 and leaves
    //    it locked; malformed arguments are -8.
    let miner = node.new_address().await;
    assert_send_needs_unlock(&rose, &miner, "locked at startup").await;
    let (code, msg) = rose
        .call_wallet(
            WALLET,
            "walletpassphrase",
            json!(["not-the-passphrase", 60]),
        )
        .await
        .expect_err("a wrong passphrase is refused");
    assert_eq!(code, -14, "{msg}");
    assert_eq!(unlocked_until(&rose).await, 0);
    let (code, msg) = rose
        .call_wallet(WALLET, "walletpassphrase", json!([PASS, -1]))
        .await
        .expect_err("a negative timeout is refused");
    assert_eq!(code, -8, "{msg}");
    assert!(node.mempool().await.is_empty(), "nothing was broadcast");

    // 5. Unlocked: reported as a future relock time, and a send signs and relays.
    unlock(&rose, 600).await;
    let until = unlocked_until(&rose).await;
    assert!(until > unix_now() + 500, "unlocked_until {until}");
    assert_eq!(status_locked(&rose).await, (false, false));
    let txid = rose
        .call_wallet(WALLET, "sendtoaddress", json!([miner, 0.25]))
        .await
        .expect("an unlocked wallet sends");
    let txid = txid.as_str().unwrap().to_string();
    node.wait_mempool_contains(&txid).await;
    node.mine(1).await;
    rose.wait_wallet_height(WALLET, 103).await;

    // 6. walletlock relocks at once.
    let reply = rose
        .call_wallet(WALLET, "walletlock", json!([]))
        .await
        .expect("walletlock");
    assert_eq!(reply, Value::Null);
    assert_eq!(unlocked_until(&rose).await, 0);
    assert_eq!(status_locked(&rose).await, (true, true));
    assert_send_needs_unlock(&rose, &miner, "after walletlock").await;

    // 7. A short timeout relocks on its own.
    unlock(&rose, 2).await;
    rose.wait_wallet(
        WALLET,
        "getwalletinfo",
        json!([]),
        "the unlock expires",
        |wi| wi["unlocked_until"] == json!(0),
    )
    .await;
    assert_send_needs_unlock(&rose, &miner, "after the timeout").await;

    // 8. The shared conformance suite's encryption state machine (bitcoind leg, as
    //    `regtest_btc.rs` runs the unencrypted one). Run unlocked, as the Zcash funded e2e
    //    does: the send sections assert argument errors (-5, -3), and a locked wallet
    //    answers -13 before parsing a send's arguments, as Bitcoin Core does. The
    //    encryption section locks and re-unlocks it and leaves it unlocked.
    if backend == BtcBackend::Bitcoind {
        unlock(&rose, 600).await;
        run_conformance(rose.rpc_port);
    }

    // 9. A restart comes back locked, with the balance intact.
    rose.restart().await;
    rose.wait_wallet_height(WALLET, 103).await;
    assert_eq!(
        unlocked_until(&rose).await,
        0,
        "locked again after a restart"
    );
    let balance = rose
        .call_wallet(WALLET, "getbalance", json!([]))
        .await
        .expect("getbalance after restart");
    let balance = balance.as_f64().unwrap();
    assert!(
        balance > 0.74 && balance < 0.75,
        "1.0 minus 0.25 minus a fee: {balance}"
    );

    // 10. `rose rescan` while locked: the database is rebuilt from the pinned xpub, with
    //     no passphrase, and rescanned to the same balance.
    rose.stop();
    let stderr = rose.rescan(WALLET).expect("rescan an encrypted wallet");
    assert!(stderr.contains("while it stays locked"), "{stderr}");
    assert!(!rose.wallet_db_path(WALLET).exists());
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    rose.start().await;
    rose.wait_wallet_height(WALLET, 103).await;
    rose.wait_wallet_balance(WALLET, balance).await;
    assert_eq!(
        unlocked_until(&rose).await,
        0,
        "the rebuild did not unlock it"
    );
    assert_send_needs_unlock(&rose, &miner, "after the rebuild").await;

    // 11. And the rebuilt wallet spends once unlocked - over bitcoind, whose mempool pass
    //     shows it any send made before the rebuild. Over kyoto the rebuilt database cannot
    //     see those until they confirm, and this stack's feed relays but takes no
    //     snapshots, so unlocked it still refuses (the opt-out and the persisted
    //     refusal are regtest_btc_restore's). Unlock is checked first: a locked wallet is
    //     -13 above, before the gate is consulted.
    unlock(&rose, 600).await;
    let sent = rose
        .call_wallet(WALLET, "sendtoaddress", json!([miner, 0.1]))
        .await;
    if backend == BtcBackend::Kyoto {
        let (code, msg) =
            sent.expect_err("a rebuilt kyoto wallet refuses to spend without a mempool view");
        assert_eq!(code, -4, "{msg}");
        assert!(msg.contains("double-spend"), "{msg}");
        return;
    }
    let txid = sent.expect("the rebuilt wallet sends once unlocked");
    node.wait_mempool_contains(txid.as_str().unwrap()).await;
}

fn run_conformance(rpc_port: u16) {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("harness lives inside the rose repo")
        .join("scripts/conformance.py");
    let out = std::process::Command::new("python3")
        .arg(&script)
        .args([
            "--coin",
            "bitcoin",
            "--url",
            &format!("http://127.0.0.1:{rpc_port}/"),
            "--user",
            "zec",
            "--password",
            "secret",
            "--passphrase",
            PASS,
        ])
        .output();
    match out {
        Err(e) => eprintln!("SKIP conformance.py: python3 unavailable ({e})"),
        Ok(out) => {
            println!("{}", String::from_utf8_lossy(&out.stdout));
            assert!(
                out.status.success(),
                "conformance.py reported failures:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}
