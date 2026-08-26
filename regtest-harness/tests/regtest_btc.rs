//! End-to-end test of the BDK engine's bitcoind chain source: a bitcoin wallet against a
//! real regtest Bitcoin Core - sync from genesis, a 0-conf mempool receive, confirmation,
//! a wallet-built send (seed-derived signers) confirmed back into the node, `sendmany`,
//! history/UTXO shapes, and checkpoint persistence across a daemon restart.
//!
//! Skips cleanly when either half is not provisioned, so plain `cargo test` and the
//! standard CI legs (which build zecd without the `bitcoin` feature and carry no bitcoind)
//! still validate that the harness compiles:
//!  * `BITCOIND_BIN` (or a `bitcoind` on PATH) selects the node binary - Bitcoin Core
//!    v30.x is what the bdk_bitcoind_rpc line is tested against upstream;
//!  * the zecd under test must carry the `bitcoin` cargo feature (probed via
//!    `config check` on a `coin = "bitcoin"` config - a default build refuses it).

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use zecd_regtest_harness::{pick_port, zecd_bin};

const SYNC_TIMEOUT: Duration = Duration::from_secs(120);

/// Locate a bitcoind: `$BITCOIND_BIN`, else PATH. `None` skips the test.
fn bitcoind_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BITCOIND_BIN") {
        return Some(PathBuf::from(p));
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join("bitcoind"))
        .find(|p| p.is_file())
}

/// Whether the zecd under test carries the `bitcoin` feature: a default build's
/// `config check` refuses `coin = "bitcoin"` ("this build supports: zcash").
fn zecd_has_bitcoin_feature(datadir: &std::path::Path) -> bool {
    let conf = datadir.join("probe.toml");
    std::fs::write(
        &conf,
        "default_wallet = \"btc\"\n[wallets.btc]\ncoin = \"bitcoin\"\n",
    )
    .expect("write probe config");
    let out = Command::new(zecd_bin())
        .args([
            "--datadir",
            datadir.to_str().unwrap(),
            "--regtest",
            "config",
            "check",
            "--conf",
            conf.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("run zecd config check");
    let stderr = String::from_utf8_lossy(&out.stderr);
    !stderr.contains("unsupported coin")
}

/// A guard that kills a child process on drop, so a failed assertion never leaks daemons.
struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct BitcoinD {
    _proc: KillOnDrop,
    client: reqwest::Client,
    url: String,
}

impl BitcoinD {
    async fn start(bin: &std::path::Path, datadir: &std::path::Path, rpc_port: u16) -> BitcoinD {
        std::fs::create_dir_all(datadir).unwrap();
        let proc = Command::new(bin)
            .args([
                "-regtest",
                &format!("-datadir={}", datadir.display()),
                &format!("-rpcport={rpc_port}"),
                "-rpcuser=harness",
                "-rpcpassword=harness",
                "-listen=0",
                "-fallbackfee=0.0001",
                "-printtoconsole=0",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bitcoind");
        let node = BitcoinD {
            _proc: KillOnDrop(proc),
            client: reqwest::Client::new(),
            url: format!("http://127.0.0.1:{rpc_port}/"),
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if node.call("getblockchaininfo", json!([])).await.is_ok() {
                return node;
            }
            assert!(Instant::now() < deadline, "bitcoind RPC never came up");
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        // The node wallet lives at /wallet/miner once created; bitcoind routes
        // wallet-agnostic calls fine through the bare endpoint until then, but after
        // createwallet every wallet call must name it - simplest is to always use the
        // wallet path once it exists, which the bare-endpoint fallback below handles.
        for url in [format!("{}wallet/miner", self.url), self.url.clone()] {
            let resp = self
                .client
                .post(&url)
                .basic_auth("harness", Some("harness"))
                .json(&json!({"jsonrpc": "1.0", "id": "h", "method": method, "params": params}))
                .send()
                .await;
            let Ok(resp) = resp else { continue };
            let Ok(body) = resp.json::<Value>().await else {
                continue;
            };
            if body["error"].is_null() {
                return Ok(body["result"].clone());
            }
            // A "wallet not found" on the wallet path falls through to the bare endpoint.
            let code = body["error"]["code"].as_i64().unwrap_or(0);
            if code != -18 {
                return Err(body["error"].to_string());
            }
        }
        Err(format!("no endpoint answered {method}"))
    }

    async fn mine(&self, n: u64) {
        let addr = self
            .call("getnewaddress", json!([]))
            .await
            .expect("miner address");
        self.call("generatetoaddress", json!([n, addr]))
            .await
            .expect("mine");
    }
}

struct ZecdBtc {
    proc: Option<KillOnDrop>,
    client: reqwest::Client,
    url: String,
    datadir: PathBuf,
    conf: PathBuf,
    rpc_port: u16,
}

impl ZecdBtc {
    fn spawn_daemon(
        datadir: &std::path::Path,
        conf: &std::path::Path,
        rpc_port: u16,
    ) -> KillOnDrop {
        KillOnDrop(
            Command::new(zecd_bin())
                .args([
                    "--datadir",
                    datadir.to_str().unwrap(),
                    "--regtest",
                    "--conf",
                    conf.to_str().unwrap(),
                    "--rpcuser",
                    "zec",
                    "--rpcpassword",
                    "secret",
                    "--rpcport",
                    &rpc_port.to_string(),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn zecd"),
        )
    }

    async fn start(datadir: PathBuf, bitcoind_rpc_port: u16) -> ZecdBtc {
        std::fs::create_dir_all(&datadir).unwrap();
        let conf = datadir.join("zecd.toml");
        // A tight sync interval so the 0-conf mempool pass lands quickly; the health
        // server is disabled to avoid a port pick for a surface this test does not assert.
        std::fs::write(
            &conf,
            format!(
                "default_wallet = \"btc\"\n\
                 [wallets.btc]\n\
                 coin = \"bitcoin\"\n\
                 server = \"bitcoind://127.0.0.1:{bitcoind_rpc_port}\"\n\
                 [bitcoind]\n\
                 rpc_user = \"harness\"\n\
                 rpc_password = \"harness\"\n\
                 [sync]\n\
                 interval_secs = 1\n\
                 [health]\n\
                 enabled = false\n"
            ),
        )
        .unwrap();
        let init = Command::new(zecd_bin())
            .args([
                "--datadir",
                datadir.to_str().unwrap(),
                "--regtest",
                "--conf",
                conf.to_str().unwrap(),
                "init",
                "--wallet",
                "btc",
            ])
            .output()
            .expect("run zecd init");
        assert!(
            init.status.success(),
            "zecd init failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        let rpc_port = pick_port().expect("pick zecd rpc port");
        let z = ZecdBtc {
            proc: Some(Self::spawn_daemon(&datadir, &conf, rpc_port)),
            client: reqwest::Client::new(),
            url: format!("http://127.0.0.1:{rpc_port}/wallet/btc"),
            datadir,
            conf,
            rpc_port,
        };
        z.wait_rpc_up().await;
        z
    }

    async fn restart(&mut self) {
        self.proc = None; // drop kills the old daemon and releases the datadir lock
        tokio::time::sleep(Duration::from_secs(1)).await;
        self.proc = Some(Self::spawn_daemon(&self.datadir, &self.conf, self.rpc_port));
        self.wait_rpc_up().await;
    }

    async fn wait_rpc_up(&self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if self.call("getwalletinfo", json!([])).await.is_ok() {
                return;
            }
            assert!(Instant::now() < deadline, "zecd RPC never came up");
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, (i64, String)> {
        let resp = self
            .client
            .post(&self.url)
            .basic_auth("zec", Some("secret"))
            .json(&json!({"jsonrpc": "1.0", "id": "t", "method": method, "params": params}))
            .send()
            .await
            .map_err(|e| (0, e.to_string()))?;
        let body: Value = resp.json().await.map_err(|e| (0, e.to_string()))?;
        if body["error"].is_null() {
            Ok(body["result"].clone())
        } else {
            Err((
                body["error"]["code"].as_i64().unwrap_or(0),
                body["error"]["message"].to_string(),
            ))
        }
    }

    async fn wait_height(&self, target: u64) {
        let deadline = Instant::now() + SYNC_TIMEOUT;
        loop {
            if let Ok(h) = self.call("getblockcount", json!([])).await {
                if h.as_u64() == Some(target) {
                    return;
                }
            }
            assert!(
                Instant::now() < deadline,
                "zecd never synced to height {target}"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Poll until `getunconfirmedbalance` reaches `expected` zats (a 0-conf receive needs
    /// one mempool pass, which the 1s sync interval delivers promptly).
    async fn wait_unconfirmed(&self, expected: f64) {
        let deadline = Instant::now() + SYNC_TIMEOUT;
        loop {
            if let Ok(v) = self.call("getunconfirmedbalance", json!([])).await {
                if v.as_f64() == Some(expected) {
                    return;
                }
            }
            assert!(
                Instant::now() < deadline,
                "unconfirmed balance never reached {expected}"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_wallet_receives_and_sends_against_regtest_bitcoind() {
    let Some(bitcoind) = bitcoind_bin() else {
        eprintln!("skipping: no bitcoind (set BITCOIND_BIN or put bitcoind on PATH)");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    if !zecd_has_bitcoin_feature(dir.path()) {
        eprintln!(
            "skipping: the zecd under test was built without the `bitcoin` feature \
             (build with --features bitcoin)"
        );
        return;
    }

    let btc_rpc_port = pick_port().expect("pick bitcoind rpc port");
    let node = BitcoinD::start(&bitcoind, &dir.path().join("btcdata"), btc_rpc_port).await;
    node.call("createwallet", json!(["miner"]))
        .await
        .expect("create miner wallet");

    let mut zecd = ZecdBtc::start(dir.path().join("zecddata"), btc_rpc_port).await;
    let address = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let address = address.as_str().expect("address string").to_string();
    assert!(address.starts_with("bcrt1"), "{address}");

    // Sync from genesis past coinbase maturity.
    node.mine(101).await;
    zecd.wait_height(101).await;

    // A mempool receive is visible at 0-conf...
    let fund_txid = node
        .call("sendtoaddress", json!([address, 1.0]))
        .await
        .expect("fund zecd");
    zecd.wait_unconfirmed(1.0).await;
    let listed = zecd
        .call("listtransactions", json!([]))
        .await
        .expect("listtransactions");
    assert_eq!(listed[0]["category"], json!("receive"));
    assert_eq!(listed[0]["confirmations"], json!(0));
    assert_eq!(listed[0]["txid"], fund_txid);
    // Per-output fan-out: the receive entry names the receiving address and its outpoint
    // index (the funding tx's other output - the node's change - never appears).
    assert_eq!(listed[0]["address"], json!(address));
    assert!(listed[0]["vout"].is_u64(), "{}", listed[0]);
    assert_eq!(listed[0]["label"], json!(""));
    assert_eq!(listed.as_array().map(Vec::len), Some(1));
    // ...but only through the 0-conf surfaces. Core's getbalance is TRUSTED funds - a
    // foreign unconfirmed receive is excluded - and Core's listunspent defaults to
    // minconf=1; `listunspent 0` opts in and marks the output unsafe.
    let balance = zecd.call("getbalance", json!([])).await.expect("balance");
    assert_eq!(balance.as_f64(), Some(0.0), "0-conf receive is not trusted");
    let unspent = zecd
        .call("listunspent", json!([]))
        .await
        .expect("listunspent");
    assert_eq!(unspent, json!([]), "default minconf=1 hides 0-conf");
    let unspent0 = zecd
        .call("listunspent", json!([0]))
        .await
        .expect("listunspent 0");
    assert_eq!(unspent0.as_array().map(Vec::len), Some(1));
    assert_eq!(unspent0[0]["confirmations"], json!(0));
    assert_eq!(unspent0[0]["safe"], json!(false));

    // ...and confirms into the spendable balance.
    node.mine(1).await;
    zecd.wait_height(102).await;
    let balance = zecd.call("getbalance", json!([])).await.expect("balance");
    assert_eq!(balance.as_f64(), Some(1.0));
    let unspent = zecd
        .call("listunspent", json!([]))
        .await
        .expect("listunspent");
    assert_eq!(unspent.as_array().map(Vec::len), Some(1));
    assert_eq!(unspent[0]["confirmations"], json!(1));
    assert_eq!(unspent[0]["safe"], json!(true));

    // The wallet builds, signs (seed-derived signers), and broadcasts a send; the node's
    // mempool accepting it is the proof the signatures are valid.
    let miner_addr = node
        .call("getnewaddress", json!([]))
        .await
        .expect("miner address");
    let send_txid = zecd
        .call("sendtoaddress", json!([miner_addr, 0.25]))
        .await
        .expect("zecd send");
    let mempool = node
        .call("getrawmempool", json!([]))
        .await
        .expect("getrawmempool");
    assert!(
        mempool.as_array().is_some_and(|m| m.contains(&send_txid)),
        "send txid must be in the node mempool: {mempool}"
    );

    node.mine(1).await;
    zecd.wait_height(103).await;
    let entries = zecd
        .call("listtransactions", json!([]))
        .await
        .expect("listtransactions");
    let send_entry = entries
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["txid"] == send_txid)
        .expect("send entry present");
    assert_eq!(send_entry["category"], json!("send"));
    assert_eq!(send_entry["amount"].as_f64(), Some(-0.25));
    assert!(
        send_entry["fee"].as_f64().is_some_and(|f| f < 0.0),
        "send entries carry a negative fee: {send_entry}"
    );
    // The fan-out names the recipient, and hides the change output: exactly one entry for
    // this txid, addressed to the miner.
    assert_eq!(send_entry["address"], miner_addr);
    let send_entry_count = entries
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["txid"] == send_txid)
        .count();
    assert_eq!(send_entry_count, 1, "change must not appear: {entries}");
    // Change landed on the internal keychain and reports as such.
    let unspent = zecd
        .call("listunspent", json!([]))
        .await
        .expect("listunspent");
    let change_addr = unspent[0]["address"].as_str().expect("change address");
    let info = zecd
        .call("getaddressinfo", json!([change_addr]))
        .await
        .expect("getaddressinfo");
    assert_eq!(info["ischange"], json!(true));
    assert_eq!(info["ismine"], json!(true));

    // A multi-recipient send in one transaction fans out to one send entry per recipient.
    let m1 = node.call("getnewaddress", json!([])).await.unwrap();
    let m2 = node.call("getnewaddress", json!([])).await.unwrap();
    let many_txid = zecd
        .call(
            "sendmany",
            json!(["", {m1.as_str().unwrap(): 0.1, m2.as_str().unwrap(): 0.2}]),
        )
        .await
        .expect("sendmany");
    node.mine(1).await;
    zecd.wait_height(104).await;
    let many = zecd
        .call("gettransaction", json!([many_txid]))
        .await
        .expect("gettransaction sendmany");
    // Top-level amount is the net wallet impact excluding the fee; the details carry one
    // send element per recipient with its own address/amount/vout, change hidden.
    assert_eq!(many["amount"].as_f64(), Some(-0.3), "{many}");
    let details = many["details"].as_array().expect("details array");
    assert_eq!(details.len(), 2, "one detail per recipient: {many}");
    for (addr, amount) in [(&m1, -0.1), (&m2, -0.2)] {
        let detail = details
            .iter()
            .find(|d| &d["address"] == addr)
            .unwrap_or_else(|| panic!("recipient {addr} missing: {many}"));
        assert_eq!(detail["category"], json!("send"));
        assert_eq!(detail["amount"].as_f64(), Some(amount));
        assert!(detail["vout"].is_u64());
    }
    assert_ne!(details[0]["vout"], details[1]["vout"]);

    // The synced checkpoint and the balance survive a daemon restart (BDK changesets
    // persisted through zecd's own rusqlite persister) - the wallet resumes from its
    // checkpoint rather than rescanning from genesis.
    let balance_before = zecd
        .call("getbalance", json!([]))
        .await
        .expect("balance before restart");
    zecd.restart().await;
    zecd.wait_height(104).await;
    let balance_after = zecd
        .call("getbalance", json!([]))
        .await
        .expect("balance after restart");
    assert_eq!(balance_before, balance_after);
    let info = zecd
        .call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo");
    assert_eq!(info["coin"], json!("bitcoin"));
    assert_eq!(info["lastprocessedblock"]["height"], json!(104));
}
