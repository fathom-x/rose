//! End-to-end test of the BDK engine's **kyoto** chain source: a bitcoin wallet speaking
//! BIP-157/158 to a real regtest Bitcoin Core serving compact block filters
//! (`-blockfilterindex -peerblockfilters`) - the first live coverage the kyoto backend has.
//! It walks: a first sync from genesis (`ScanType::Recovery` anchored at the regtest
//! genesis floor), the no-mempool posture (a receive is invisible until it confirms), a
//! confirmed receive found via a filter match, a wallet-built send priced by kyoto's own
//! P2P fee signals (the relay floor + recent-block estimate - regtest has no mempool.space,
//! so this is the one path that exercises them end-to-end) and broadcast via
//! `submit_package`, checkpoint persistence across a restart (`ScanType::Sync`), and a
//! second send from the resumed wallet spending the first send's change - priced by an
//! explicit `fee_rate`, the operator's override for exactly this oracle-less backend.
//!
//! Deliberately a sibling of `regtest_btc.rs` rather than a shared module: each regtest
//! binary is an independent stack (ports, node flags, config shape all differ here), and
//! the bitcoind-dialect shapes it does not re-assert (sendmany fan-out, 0-conf mempool
//! surfaces, address/history details) are that test's job.
//!
//! Skips cleanly under the same two probes as `regtest_btc.rs`: no bitcoind provisioned,
//! or a rose built without the `bitcoin` feature.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rose_regtest_harness::{pick_port, rose_bin, rosed_bin};
use serde_json::{json, Value};

/// Generous: a kyoto first sync downloads headers and filters for the whole regtest chain
/// and only reports at tip, and the node builds its filter index in the background.
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
    /// Unlike the bitcoind-dialect test's node, this one LISTENS on P2P (kyoto dials it as
    /// a trusted peer) and serves compact block filters - `-peerblockfilters` is what
    /// answers `cfilter` requests, and it needs `-blockfilterindex` underneath.
    async fn start(
        bin: &std::path::Path,
        datadir: &std::path::Path,
        rpc_port: u16,
        p2p_port: u16,
    ) -> BitcoinD {
        std::fs::create_dir_all(datadir).unwrap();
        let proc = Command::new(bin)
            .args([
                "-regtest",
                &format!("-datadir={}", datadir.display()),
                &format!("-rpcport={rpc_port}"),
                "-rpcuser=harness",
                "-rpcpassword=harness",
                "-listen=1",
                &format!("-bind=127.0.0.1:{p2p_port}"),
                "-blockfilterindex=1",
                "-peerblockfilters=1",
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
        // Wallet calls route through /wallet/miner once that wallet exists; the bare
        // endpoint covers everything before it does (see regtest_btc.rs).
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

    /// Poll the node's mempool until `txid` appears: a kyoto broadcast resolves on the
    /// peer's `getdata`, which can land a beat before the transaction is accepted.
    async fn wait_mempool_contains(&self, txid: &Value) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(mempool) = self.call("getrawmempool", json!([])).await {
                if mempool.as_array().is_some_and(|m| m.contains(txid)) {
                    return;
                }
            }
            assert!(
                Instant::now() < deadline,
                "send txid never entered the node mempool"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

struct RoseKyoto {
    proc: Option<KillOnDrop>,
    client: reqwest::Client,
    url: String,
    datadir: PathBuf,
    conf: PathBuf,
    rpc_port: u16,
}

impl RoseKyoto {
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

    async fn start(datadir: PathBuf, bitcoind_p2p_port: u16) -> RoseKyoto {
        std::fs::create_dir_all(&datadir).unwrap();
        let conf = datadir.join("rose.toml");
        // The kyoto grammar: an explicit trusted peer (the bare token is refused on
        // regtest, which has no DNS seeds), which also makes the light client
        // whitelist-only with required_peers capped at 1. No [bitcoind] credentials -
        // nothing on this path authenticates. The mempool feed is switched off: its `p2p`
        // source runs by default for a wallet with a trusted peer, and this suite pins the
        // feed-less posture (a receive invisible until it confirms); the feed itself is
        // `regtest_btc_p2p_mempool`'s.
        std::fs::write(
            &conf,
            format!(
                "default_wallet = \"btc\"\n\
                 [wallets.btc]\n\
                 coin = \"bitcoin\"\n\
                 server = \"kyoto://127.0.0.1:{bitcoind_p2p_port}\"\n\
                 [sync]\n\
                 interval_secs = 1\n\
                 [health]\n\
                 enabled = false\n\
                 [mempool]\n\
                 sources = []\n"
            ),
        )
        .unwrap();
        // Kyoto init is fully offline; height 0 (also what a regtest kyoto wallet now
        // defaults to) scans the whole (tiny) regtest chain from the genesis recovery
        // floor. Kept explicit so the suite pins the flag's height path too.
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
                "--birthday",
                "0",
            ])
            .output()
            .expect("run rose init");
        assert!(
            init.status.success(),
            "rose init failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        let rpc_port = pick_port().expect("pick rose rpc port");
        let z = RoseKyoto {
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

    /// Wait for the wallet's own applied height (kyoto reports it only when a sync
    /// reaches the network tip, so this is also "the last update landed").
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
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_wallet_receives_and_sends_over_kyoto_bip157() {
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
    let btc_p2p_port = pick_port().expect("pick bitcoind p2p port");
    let node = BitcoinD::start(
        &bitcoind,
        &dir.path().join("btcdata"),
        btc_rpc_port,
        btc_p2p_port,
    )
    .await;
    node.call("createwallet", json!(["miner"]))
        .await
        .expect("create miner wallet");
    // Mine past coinbase maturity BEFORE rose starts: the first kyoto sync then covers a
    // real chain span (headers + filters from genesis) rather than an empty one.
    node.mine(110).await;

    let mut rose = RoseKyoto::start(dir.path().join("rosedata"), btc_p2p_port).await;
    rose.wait_height(110).await;
    let address = rose
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let address = address.as_str().expect("address string").to_string();
    assert!(address.starts_with("bcrt1"), "{address}");

    // Fund the wallet. Filters are block-derived, so kyoto has NO mempool: the receive
    // must stay invisible on every 0-conf surface until it confirms. "Nothing happened"
    // has no event to await, so the assertion is held across several of the actor's sync
    // passes rather than read once, milliseconds after the send, when it would pass even
    // against a backend that did see the mempool.
    node.call("sendtoaddress", json!([address, 1.0]))
        .await
        .expect("fund rose");
    let hold = std::time::Instant::now();
    while hold.elapsed() < std::time::Duration::from_secs(6) {
        let unconfirmed = rose
            .call("getunconfirmedbalance", json!([]))
            .await
            .expect("getunconfirmedbalance");
        assert_eq!(
            unconfirmed.as_f64(),
            Some(0.0),
            "kyoto has no mempool; a receive cannot appear at 0-conf"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    // Confirming it makes the block's filter match the wallet's script; kyoto downloads
    // that one block and the receive lands.
    node.mine(1).await;
    rose.wait_height(111).await;
    let balance = rose.call("getbalance", json!([])).await.expect("balance");
    assert_eq!(balance.as_f64(), Some(1.0));
    let unspent = rose
        .call("listunspent", json!([]))
        .await
        .expect("listunspent");
    assert_eq!(unspent.as_array().map(Vec::len), Some(1));
    assert_eq!(unspent[0]["confirmations"], json!(1));

    // The wallet builds, signs, prices, and broadcasts a send entirely over P2P: regtest
    // has no mempool.space endpoint, so the fee rate comes from kyoto's own signals (the
    // peers' relay floor and the recent-block fee estimate) through the sanity ceiling, and
    // the broadcast is `submit_package` resolving on the node's `getdata`. The node's
    // mempool accepting the transaction proves the signatures, the fee, and the relay.
    let miner_addr = node
        .call("getnewaddress", json!([]))
        .await
        .expect("miner address");
    let send_txid = rose
        .call("sendtoaddress", json!([miner_addr, 0.25]))
        .await
        .expect("rose send over kyoto");
    node.wait_mempool_contains(&send_txid).await;
    // The wallet records its own send at 0-conf (it authored it; no mempool needed).
    let entries = rose
        .call("listtransactions", json!([]))
        .await
        .expect("listtransactions");
    let send_entry = entries
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["txid"] == send_txid)
        .expect("own send recorded at 0-conf");
    assert_eq!(send_entry["category"], json!("send"));
    assert_eq!(send_entry["confirmations"], json!(0));

    node.mine(1).await;
    rose.wait_height(112).await;
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
    assert_eq!(send_entry["amount"].as_f64(), Some(-0.25));
    assert_eq!(send_entry["confirmations"], json!(1));

    // The checkpoint survives a restart: the resumed wallet takes `ScanType::Sync` (its
    // latest checkpoint is now well above 0) instead of re-running the recovery scan,
    // and its balance is intact.
    let balance_before = rose
        .call("getbalance", json!([]))
        .await
        .expect("balance before restart");
    rose.restart().await;
    rose.wait_height(112).await;
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
    assert_eq!(info["lastprocessedblock"]["height"], json!(112));

    // And the resumed wallet can spend - this send's only spendable input is the first
    // send's change, so it proves change attribution and input tracking survived both
    // the kyoto confirmation path and the restart. It carries an explicit `fee_rate`
    // (param 9, sat/vB): on this backend that is the one way to price a send trusting
    // neither mempool.space nor the peers' coarse signals, and the node's mempool entry
    // proves the caller's number is what got paid.
    let second_txid = rose
        .call(
            "sendtoaddress",
            json!([miner_addr, 0.1, null, null, false, null, null, null, null, 3]),
        )
        .await
        .expect("second send after restart");
    node.wait_mempool_contains(&second_txid).await;
    let entry = node
        .call("getmempoolentry", json!([second_txid]))
        .await
        .expect("mempool entry for the rated send");
    // Measured by weight, as in `regtest_btc.rs`: BDK prices against weight, and the
    // node's rounded-up `vsize` can read a fraction under the named rate.
    let fee_sat = (entry["fees"]["base"].as_f64().unwrap() * 1e8).round();
    let rate = fee_sat * 4.0 / entry["weight"].as_f64().unwrap();
    assert!(
        (3.0..4.0).contains(&rate),
        "explicit fee_rate honored over kyoto: {rate} sat/vB ({entry})"
    );
    node.mine(1).await;
    rose.wait_height(113).await;
    let balance = rose
        .call("getbalance", json!([]))
        .await
        .expect("final balance");
    // 1.0 funded, minus two sends and their fees: anything at or above 0.649 means both
    // sends drew sane sat/vB-scale fees rather than a signal-inflated one.
    let final_balance = balance.as_f64().expect("numeric balance");
    assert!(
        (0.649..0.65).contains(&final_balance),
        "unexpected final balance {final_balance}"
    );
}
