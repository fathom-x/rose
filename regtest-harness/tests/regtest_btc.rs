//! End-to-end test of the BDK engine's bitcoind chain source: a bitcoin wallet against a
//! real regtest Bitcoin Core - sync from genesis, a 0-conf mempool receive, confirmation,
//! a wallet-built send (seed-derived signers) confirmed back into the node, `sendmany`,
//! an explicit `fee_rate` priced into the node's mempool, `subtractfeefromamount`/
//! `subtractfeefrom` (including the whole-balance drain), history/UTXO shapes, and
//! checkpoint persistence across a daemon restart.
//!
//! Skips cleanly when either half is not provisioned, so plain `cargo test` and the
//! standard CI legs (which build rose without the `bitcoin` feature and carry no bitcoind)
//! still validate that the harness compiles:
//!  * `BITCOIND_BIN` (or a `bitcoind` on PATH) selects the node binary - Bitcoin Core
//!    v30.x is what the bdk_bitcoind_rpc line is tested against upstream;
//!  * the rose under test must carry the `bitcoin` cargo feature (probed via
//!    `config check` on a `coin = "bitcoin"` config - a default build refuses it).

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rose_regtest_harness::{pick_port, rose_bin, rosed_bin};
use serde_json::{json, Value};

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

/// Whether the rose under test carries the `bitcoin` feature: a default build's
/// `config check` refuses `coin = "bitcoin"` ("this build supports: zcash").
fn rose_has_bitcoin_feature(datadir: &std::path::Path) -> bool {
    let conf = datadir.join("probe.toml");
    std::fs::write(
        &conf,
        "default_wallet = \"btc\"\n[wallets.btc]\ncoin = \"bitcoin\"\n",
    )
    .expect("write probe config");
    let out = Command::new(rose_bin())
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
        .expect("run rose config check");
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

struct RoseBtc {
    proc: Option<KillOnDrop>,
    client: reqwest::Client,
    url: String,
    datadir: PathBuf,
    conf: PathBuf,
    rpc_port: u16,
}

impl RoseBtc {
    fn spawn_daemon(
        datadir: &std::path::Path,
        conf: &std::path::Path,
        rpc_port: u16,
    ) -> KillOnDrop {
        KillOnDrop(
            Command::new(rosed_bin())
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
                .expect("spawn rose"),
        )
    }

    async fn start(datadir: PathBuf, bitcoind_rpc_port: u16) -> RoseBtc {
        std::fs::create_dir_all(&datadir).unwrap();
        let conf = datadir.join("rose.toml");
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
        let init = Command::new(rose_bin())
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
            .expect("run rose init");
        assert!(
            init.status.success(),
            "rose init failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        let rpc_port = pick_port().expect("pick rose rpc port");
        let z = RoseBtc {
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
            assert!(Instant::now() < deadline, "rose RPC never came up");
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
                "rose never synced to height {target}"
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
    if !rose_has_bitcoin_feature(dir.path()) {
        eprintln!(
            "skipping: the rose under test was built without the `bitcoin` feature \
             (build with --features bitcoin)"
        );
        return;
    }

    let btc_rpc_port = pick_port().expect("pick bitcoind rpc port");
    let node = BitcoinD::start(&bitcoind, &dir.path().join("btcdata"), btc_rpc_port).await;
    node.call("createwallet", json!(["miner"]))
        .await
        .expect("create miner wallet");

    let mut rose = RoseBtc::start(dir.path().join("rosedata"), btc_rpc_port).await;
    let address = rose
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let address = address.as_str().expect("address string").to_string();
    assert!(address.starts_with("bcrt1"), "{address}");

    // Sync from genesis past coinbase maturity.
    node.mine(101).await;
    rose.wait_height(101).await;

    // A mempool receive is visible at 0-conf...
    let fund_txid = node
        .call("sendtoaddress", json!([address, 1.0]))
        .await
        .expect("fund rose");
    rose.wait_unconfirmed(1.0).await;
    let listed = rose
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
    let balance = rose.call("getbalance", json!([])).await.expect("balance");
    assert_eq!(balance.as_f64(), Some(0.0), "0-conf receive is not trusted");
    let unspent = rose
        .call("listunspent", json!([]))
        .await
        .expect("listunspent");
    assert_eq!(unspent, json!([]), "default minconf=1 hides 0-conf");
    let unspent0 = rose
        .call("listunspent", json!([0]))
        .await
        .expect("listunspent 0");
    assert_eq!(unspent0.as_array().map(Vec::len), Some(1));
    assert_eq!(unspent0[0]["confirmations"], json!(0));
    assert_eq!(unspent0[0]["safe"], json!(false));

    // ...and confirms into the spendable balance.
    node.mine(1).await;
    rose.wait_height(102).await;
    let balance = rose.call("getbalance", json!([])).await.expect("balance");
    assert_eq!(balance.as_f64(), Some(1.0));
    let unspent = rose
        .call("listunspent", json!([]))
        .await
        .expect("listunspent");
    assert_eq!(unspent.as_array().map(Vec::len), Some(1));
    assert_eq!(unspent[0]["confirmations"], json!(1));
    assert_eq!(unspent[0]["safe"], json!(true));

    // `listreceivedbyaddress` with `include_empty` enumerates every issued receiving
    // address with its derivation index (rose's `address_index` extension) - the one that
    // was funded carries the amount and txid, the default minconf hides nothing at 1 conf,
    // and change never appears. Without `include_empty` only the funded address is listed.
    let received = rose
        .call("listreceivedbyaddress", json!([0, true]))
        .await
        .expect("listreceivedbyaddress");
    let funded = received
        .as_array()
        .expect("array")
        .iter()
        .find(|e| e["address"] == json!(address))
        .expect("the funded address is listed");
    assert_eq!(funded["amount"].as_f64(), Some(1.0), "{funded}");
    assert_eq!(funded["confirmations"], json!(1));
    assert_eq!(funded["txids"], json!([fund_txid]));
    assert_eq!(funded["label"], json!(""));
    assert!(funded["address_index"].is_u64(), "{funded}");
    let only_funded = rose
        .call("listreceivedbyaddress", json!([]))
        .await
        .expect("listreceivedbyaddress default");
    assert_eq!(only_funded.as_array().map(Vec::len), Some(1));
    assert_eq!(only_funded[0]["address"], json!(address));

    // `listdescriptors` is Core's shape over the two public descriptors, the xpub inside;
    // the private form is refused (the database holds no private material).
    let descriptors = rose
        .call("listdescriptors", json!([]))
        .await
        .expect("listdescriptors");
    let descs = descriptors["descriptors"].as_array().expect("descriptors");
    assert_eq!(descs.len(), 2, "{descriptors}");
    let external = descs[0]["desc"].as_str().expect("desc");
    assert!(
        external.starts_with("wpkh([") && external.contains("/0/*)#"),
        "{external}"
    );
    assert_eq!(descs[0]["internal"], json!(false));
    assert_eq!(descs[1]["internal"], json!(true));
    assert!(descs[1]["desc"].as_str().unwrap().contains("/1/*)#"));
    assert!(
        descs[0]["next_index"].as_u64().unwrap() >= 1,
        "{descriptors}"
    );
    let private = rose.call("listdescriptors", json!([true])).await;
    assert!(private.is_err(), "private descriptors must be refused");

    // The wallet builds, signs (seed-derived signers), and broadcasts a send; the node's
    // mempool accepting it is the proof the signatures are valid.
    let miner_addr = node
        .call("getnewaddress", json!([]))
        .await
        .expect("miner address");
    let send_txid = rose
        .call("sendtoaddress", json!([miner_addr, 0.25]))
        .await
        .expect("rose send");
    let mempool = node
        .call("getrawmempool", json!([]))
        .await
        .expect("getrawmempool");
    assert!(
        mempool.as_array().is_some_and(|m| m.contains(&send_txid)),
        "send txid must be in the node mempool: {mempool}"
    );

    node.mine(1).await;
    rose.wait_height(103).await;
    let entries = rose
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
    let unspent = rose
        .call("listunspent", json!([]))
        .await
        .expect("listunspent");
    let change_addr = unspent[0]["address"].as_str().expect("change address");
    let info = rose
        .call("getaddressinfo", json!([change_addr]))
        .await
        .expect("getaddressinfo");
    assert_eq!(info["ischange"], json!(true));
    assert_eq!(info["ismine"], json!(true));

    // A multi-recipient send in one transaction fans out to one send entry per recipient.
    // It also asks for `replaceable = false` (param 5), which is honored rather than ignored:
    // every input carries the final-but-for-locktime sequence, where the default send above
    // signalled BIP 125 - read off the node's own decoding of the raw transactions.
    let m1 = node.call("getnewaddress", json!([])).await.unwrap();
    let m2 = node.call("getnewaddress", json!([])).await.unwrap();
    let many_txid = rose
        .call(
            "sendmany",
            json!(["", {m1.as_str().unwrap(): 0.1, m2.as_str().unwrap(): 0.2}, null, null, null, false]),
        )
        .await
        .expect("sendmany");
    let sequences = |tx: &serde_json::Value| -> Vec<u64> {
        tx["vin"]
            .as_array()
            .expect("vin")
            .iter()
            .map(|i| i["sequence"].as_u64().expect("sequence"))
            .collect()
    };
    let many_raw = node
        .call("getrawtransaction", json!([many_txid, true]))
        .await
        .expect("getrawtransaction sendmany");
    assert!(
        sequences(&many_raw).iter().all(|s| *s == 0xFFFF_FFFE),
        "a replaceable=false send must not signal BIP 125: {many_raw}"
    );
    let unconfirmed = rose
        .call("gettransaction", json!([many_txid]))
        .await
        .expect("gettransaction unconfirmed sendmany");
    assert_eq!(
        unconfirmed["bip125-replaceable"],
        json!("no"),
        "{unconfirmed}"
    );
    // Already confirmed, and the node keeps no txindex: decode rose's own copy of it.
    let first_hex = rose
        .call("gettransaction", json!([send_txid]))
        .await
        .expect("gettransaction default send")["hex"]
        .clone();
    let first_raw = node
        .call("decoderawtransaction", json!([first_hex]))
        .await
        .expect("decoderawtransaction default send");
    assert!(
        sequences(&first_raw).iter().all(|s| *s == 0xFFFF_FFFD),
        "the default send signals BIP 125: {first_raw}"
    );
    node.mine(1).await;
    rose.wait_height(104).await;
    let many = rose
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

    // An explicit fee_rate (param 9, sat/vB) prices the send verbatim: the node's own
    // mempool entry proves the paid rate is the caller's number, not an estimate. It also
    // asks for `verbose` (param 10): Core's {txid, fee_reason}, the reason naming the
    // caller's own rate.
    let rated = rose
        .call(
            "sendtoaddress",
            json!([miner_addr, 0.05, null, null, false, null, null, null, null, 25, true]),
        )
        .await
        .expect("fee_rate send");
    assert_eq!(rated["fee_reason"], json!("PayTxFee set"), "{rated}");
    let rated_txid = rated["txid"].clone();
    let entry = node
        .call("getmempoolentry", json!([rated_txid]))
        .await
        .expect("mempool entry for the rated send");
    // BDK prices against transaction weight, so measure sat/vB the same way (weight / 4);
    // the node's `vsize` rounds up to whole vbytes, which can read a fraction under the
    // named rate. By weight the paid rate is never below the caller's number.
    let fee_sat = (entry["fees"]["base"].as_f64().unwrap() * 1e8).round();
    let rate = fee_sat * 4.0 / entry["weight"].as_f64().unwrap();
    assert!(
        (25.0..26.0).contains(&rate),
        "explicit fee_rate honored: {rate} sat/vB ({entry})"
    );
    node.mine(1).await;
    rose.wait_height(105).await;

    // subtractfeefromamount: the recipient receives amount minus fee, and the sender is
    // debited exactly the stated amount - the fee no longer comes out of the change.
    let balance_before = rose.call("getbalance", json!([])).await.expect("balance");
    let sffo_txid = rose
        .call("sendtoaddress", json!([miner_addr, 0.1, null, null, true]))
        .await
        .expect("subtract-fee send");
    node.mine(1).await;
    rose.wait_height(106).await;
    let tx = rose
        .call("gettransaction", json!([sffo_txid]))
        .await
        .expect("gettransaction subtract-fee");
    let amount = tx["amount"].as_f64().unwrap();
    let fee = tx["fee"].as_f64().unwrap();
    assert!(amount > -0.1, "the recipient paid the fee: {tx}");
    assert_eq!(
        ((amount + fee) * 1e8).round() as i64,
        -10_000_000,
        "recipient amount plus fee is exactly the stated amount: {tx}"
    );
    let balance_after = rose.call("getbalance", json!([])).await.expect("balance");
    let debit =
        ((balance_before.as_f64().unwrap() - balance_after.as_f64().unwrap()) * 1e8).round() as i64;
    assert_eq!(debit, 10_000_000, "sender debited exactly the amount");

    // sendmany's subtractfeefrom: only the listed recipient's amount pays the fee; the
    // unlisted one receives its stated amount untouched.
    let m3 = node.call("getnewaddress", json!([])).await.unwrap();
    let m4 = node.call("getnewaddress", json!([])).await.unwrap();
    let many_txid = rose
        .call(
            "sendmany",
            json!([
                "",
                {m3.as_str().unwrap(): 0.02, m4.as_str().unwrap(): 0.03},
                null,
                null,
                [m4]
            ]),
        )
        .await
        .expect("sendmany subtractfeefrom");
    node.mine(1).await;
    rose.wait_height(107).await;
    let many = rose
        .call("gettransaction", json!([many_txid]))
        .await
        .expect("gettransaction sendmany subtractfeefrom");
    let details = many["details"].as_array().expect("details array");
    let fee = many["fee"].as_f64().unwrap();
    let d3 = details
        .iter()
        .find(|d| d["address"] == m3)
        .expect("unlisted recipient detail");
    assert_eq!(d3["amount"].as_f64(), Some(-0.02), "{many}");
    let d4 = details
        .iter()
        .find(|d| d["address"] == m4)
        .expect("listed recipient detail");
    assert_eq!(
        ((d4["amount"].as_f64().unwrap() + fee) * 1e8).round() as i64,
        -3_000_000,
        "the listed recipient alone paid the fee: {many}"
    );

    // The synced checkpoint and the balance survive a daemon restart (BDK changesets
    // persisted through rose's own rusqlite persister) - the wallet resumes from its
    // checkpoint rather than rescanning from genesis.
    let balance_before = rose
        .call("getbalance", json!([]))
        .await
        .expect("balance before restart");
    rose.restart().await;
    rose.wait_height(107).await;
    let balance_after = rose
        .call("getbalance", json!([]))
        .await
        .expect("balance after restart");
    assert_eq!(balance_before, balance_after);
    let info = rose
        .call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo");
    assert_eq!(info["coin"], json!("bitcoin"));
    assert_eq!(info["lastprocessedblock"]["height"], json!(107));

    // The whole-balance drain: sending the full balance with subtractfeefromamount empties
    // the wallet - the case the flag exists for, and the one where coin selection must
    // target the amount alone (selecting for amount plus fee would refuse it as
    // insufficient). Run after the restart, so it also proves the resumed wallet spends.
    let balance = rose.call("getbalance", json!([])).await.expect("balance");
    assert!(balance.as_f64().unwrap() > 0.0);
    let drain_txid = rose
        .call(
            "sendtoaddress",
            json!([miner_addr, balance, null, null, true]),
        )
        .await
        .expect("whole-balance drain");
    node.mine(1).await;
    rose.wait_height(108).await;
    let tx = rose
        .call("gettransaction", json!([drain_txid]))
        .await
        .expect("gettransaction drain");
    assert_eq!(tx["confirmations"], json!(1), "{tx}");
    let balance = rose.call("getbalance", json!([])).await.expect("balance");
    assert_eq!(balance.as_f64(), Some(0.0), "drained to zero");
    let unspent = rose
        .call("listunspent", json!([]))
        .await
        .expect("listunspent");
    assert_eq!(unspent, json!([]), "no change output survives a drain");

    // The sub-dust surplus shape: the selected input exceeds the stated amount by less
    // than a change output's dust bound (here 150 sats), so no exact fee fixed point
    // exists - the surplus folds into the fee, as Core does with sub-dust change, rather
    // than the subtract-fee loop failing to converge.
    node.call("sendtoaddress", json!([address, 0.001]))
        .await
        .expect("refund one utxo");
    node.mine(1).await;
    rose.wait_height(109).await;
    let sub_dust_txid = rose
        .call(
            "sendtoaddress",
            json!([miner_addr, 0.00099850, null, null, true]),
        )
        .await
        .expect("sub-dust surplus subtract-fee send");
    node.mine(1).await;
    rose.wait_height(110).await;
    let tx = rose
        .call("gettransaction", json!([sub_dust_txid]))
        .await
        .expect("gettransaction sub-dust");
    assert_eq!(tx["confirmations"], json!(1), "{tx}");
    let balance = rose.call("getbalance", json!([])).await.expect("balance");
    assert_eq!(balance.as_f64(), Some(0.0), "sub-dust surplus went to fee");

    // Broadcast-failure classification: a rebroadcast of the already-confirmed
    // transaction is a node REJECTION, and the node's own verify-family answer passes
    // through (-27 "already in utxo set") - not a blanket -26, and not the -4 transport
    // shape, which is reserved for obtaining no verdict at all.
    let hex = tx["hex"].as_str().expect("tx hex").to_string();
    let (code, msg) = rose
        .call("sendrawtransaction", json!([hex]))
        .await
        .expect_err("rebroadcast of a confirmed tx must be rejected");
    assert_eq!(code, -27, "node's own rejection code passes through: {msg}");

    // ---- conformance.py, Bitcoin mode, against the live funded wallet ----
    // The same python-bitcoinrpc-style client the Zcash suites run: Decimal amounts, Core
    // error codes, arity, batching, over every method the engine serves. Its send checks
    // all reject at argument parsing, so it moves no funds; the sends above are the live
    // coverage of the send path.
    run_conformance(rose.rpc_port);
}

/// Run `scripts/conformance.py --coin bitcoin` against the regtest daemon, exactly as
/// `regtest_funded.rs::run_conformance` does for a Zcash wallet. Skips with a notice when
/// `python3` is unavailable so a local run without it does not fail confusingly.
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
