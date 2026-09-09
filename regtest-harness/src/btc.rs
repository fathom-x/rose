//! Drivers for the Bitcoin (BDK engine) regtest suites: a regtest Bitcoin Core and a
//! `--features bitcoin` zecd over either of its chain sources.
//!
//! The first two Bitcoin suites (`regtest_btc.rs`, `regtest_btc_kyoto.rs`) each carry their
//! own copy of these drivers, on purpose - one stack per binary, nothing shared. The suites
//! written after them (watch-only pairing, restore, reorg) run the *same* scenario over both
//! backends and bring up several wallets and daemons per test, which is where a shared
//! driver earns its keep. The node here always listens on P2P and serves compact block
//! filters, so one `BitcoinD` serves a bitcoind-dialect zecd and a kyoto one alike.
//!
//! Provisioning is the same pair of probes as the original suites: `BITCOIND_BIN` (or a
//! `bitcoind` on PATH) for the node, and a zecd carrying the `bitcoin` feature (probed via
//! `config check` on a `coin = "bitcoin"` config). [`provisioned`] runs both and prints the
//! standard `skipping:` line, so a plain `cargo test` passes through in milliseconds.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::{pick_port, zecd_bin};

/// How long a zecd wallet gets to reach a height, balance, or hash. Generous: a kyoto
/// first sync downloads headers and filters for the whole regtest chain, and the node
/// builds its filter index in the background.
pub const SYNC_TIMEOUT: Duration = Duration::from_secs(120);

/// Locate a bitcoind: `$BITCOIND_BIN`, else PATH. `None` means skip.
pub fn bitcoind_bin() -> Option<PathBuf> {
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
pub fn zecd_has_bitcoin_feature(datadir: &Path) -> bool {
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

/// Both provisioning probes at once. `Some(bitcoind)` when the test can run; `None` after
/// printing the `skipping:` line the CI logs are grepped for.
pub fn provisioned(datadir: &Path) -> Option<PathBuf> {
    let Some(bitcoind) = bitcoind_bin() else {
        eprintln!("skipping: no bitcoind (set BITCOIND_BIN or put bitcoind on PATH)");
        return None;
    };
    if !zecd_has_bitcoin_feature(datadir) {
        eprintln!(
            "skipping: the zecd under test was built without the `bitcoin` feature \
             (build with --features bitcoin)"
        );
        return None;
    }
    Some(bitcoind)
}

/// A guard that kills a child process on drop, so a failed assertion never leaks daemons.
pub struct KillOnDrop(pub Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A regtest Bitcoin Core with a `miner` wallet, listening on P2P and serving compact
/// block filters (`-blockfilterindex -peerblockfilters`) so a kyoto zecd can use it too.
pub struct BitcoinD {
    proc: Option<KillOnDrop>,
    client: reqwest::Client,
    url: String,
    bin: PathBuf,
    datadir: PathBuf,
    pub rpc_port: u16,
    pub p2p_port: u16,
}

impl BitcoinD {
    /// Start a node on harness-allocated ports and create its `miner` wallet. The wallet
    /// is deliberately NOT registered to load on startup: a wallet reloaded by
    /// [`BitcoinD::restart`] resubmits its unconfirmed transactions to the mempool, which
    /// is exactly what a restart with `-persistmempool=0` is used to prevent.
    pub async fn start(bin: &Path, datadir: &Path) -> BitcoinD {
        std::fs::create_dir_all(datadir).unwrap();
        let rpc_port = pick_port().expect("pick bitcoind rpc port");
        let p2p_port = pick_port().expect("pick bitcoind p2p port");
        let mut node = BitcoinD {
            proc: None,
            client: reqwest::Client::new(),
            url: format!("http://127.0.0.1:{rpc_port}/"),
            bin: bin.to_path_buf(),
            datadir: datadir.to_path_buf(),
            rpc_port,
            p2p_port,
        };
        node.spawn(&[]).await;
        node.call("createwallet", json!(["miner"]))
            .await
            .expect("create miner wallet");
        node
    }

    async fn spawn(&mut self, extra: &[&str]) {
        let mut args = vec![
            "-regtest".to_string(),
            format!("-datadir={}", self.datadir.display()),
            format!("-rpcport={}", self.rpc_port),
            "-rpcuser=harness".to_string(),
            "-rpcpassword=harness".to_string(),
            "-listen=1".to_string(),
            format!("-bind=127.0.0.1:{}", self.p2p_port),
            "-blockfilterindex=1".to_string(),
            "-peerblockfilters=1".to_string(),
            "-fallbackfee=0.0001".to_string(),
            "-printtoconsole=0".to_string(),
        ];
        args.extend(extra.iter().map(|a| a.to_string()));
        let proc = Command::new(&self.bin)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bitcoind");
        self.proc = Some(KillOnDrop(proc));
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            match self.call("getblockchaininfo", json!([])).await {
                Ok(_) => return,
                Err(_) if Instant::now() < deadline => {}
                Err(e) => panic!("bitcoind RPC never came up: {e}"),
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Stop the node gracefully and start it again with `extra` flags appended -
    /// `-persistmempool=0` drops whatever was in the mempool. The `miner` wallet stays
    /// unloaded afterwards (see [`BitcoinD::start`]); mining to an address the caller
    /// already holds still works, wallet calls do not.
    pub async fn restart(&mut self, extra: &[&str]) {
        // A graceful `stop` so the block index (with any invalidity marks) flushes; the
        // guard's kill on drop is the backstop.
        let _ = self.call("stop", json!([])).await;
        if let Some(mut proc) = self.proc.take() {
            let deadline = Instant::now() + Duration::from_secs(30);
            while proc.0.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        self.spawn(extra).await;
    }

    /// Pause the node with SIGSTOP, simulating a *hung* upstream: its sockets stay open
    /// and accepting, but no request is ever answered - the failure a kill cannot
    /// reproduce and only a per-request deadline can detect. Resume with
    /// [`BitcoinD::resume`].
    pub fn pause(&self) {
        self.signal("STOP");
    }

    /// Resume a [`BitcoinD::pause`]d node (SIGCONT); it picks up where it stopped.
    pub fn resume(&self) {
        self.signal("CONT");
    }

    fn signal(&self, sig: &str) {
        let pid = self.proc.as_ref().expect("node is running").0.id();
        let status = Command::new("kill")
            .arg(format!("-{sig}"))
            .arg(pid.to_string())
            .status()
            .expect("spawn kill");
        assert!(status.success(), "kill -{sig} {pid} exited with {status}");
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        // The node wallet lives at /wallet/miner once created; wallet-agnostic calls
        // route fine through the bare endpoint until then, and after createwallet every
        // wallet call must name it - so try the wallet path first and fall back.
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

    pub async fn new_address(&self) -> String {
        self.call("getnewaddress", json!([]))
            .await
            .expect("miner address")
            .as_str()
            .expect("address string")
            .to_string()
    }

    /// Mine `n` blocks to a fresh miner address; returns their hashes.
    pub async fn mine(&self, n: u64) -> Vec<String> {
        let addr = self.new_address().await;
        self.mine_to(&addr, n).await
    }

    pub async fn mine_to(&self, address: &str, n: u64) -> Vec<String> {
        self.call("generatetoaddress", json!([n, address]))
            .await
            .expect("mine")
            .as_array()
            .expect("block hashes")
            .iter()
            .map(|h| h.as_str().unwrap().to_string())
            .collect()
    }

    pub async fn height(&self) -> u64 {
        self.call("getblockcount", json!([]))
            .await
            .expect("getblockcount")
            .as_u64()
            .unwrap()
    }

    pub async fn block_hash(&self, height: u64) -> String {
        self.call("getblockhash", json!([height]))
            .await
            .expect("getblockhash")
            .as_str()
            .unwrap()
            .to_string()
    }

    pub async fn best_hash(&self) -> String {
        self.call("getbestblockhash", json!([]))
            .await
            .expect("getbestblockhash")
            .as_str()
            .unwrap()
            .to_string()
    }

    pub async fn mempool(&self) -> Vec<String> {
        self.call("getrawmempool", json!([]))
            .await
            .expect("getrawmempool")
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().to_string())
            .collect()
    }

    /// Until the node's mempool holds `txid` - how a test observes the wallet's own
    /// rebroadcast landing, since the wallet reports nothing about a resubmission itself.
    pub async fn wait_mempool_contains(&self, txid: &str) {
        let deadline = Instant::now() + SYNC_TIMEOUT;
        loop {
            let mempool = self.mempool().await;
            if mempool.iter().any(|t| t == txid) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {txid} to reach the node's mempool; it holds {mempool:?}"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

/// Which chain source the zecd under test dials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcBackend {
    /// `bitcoind://` JSON-RPC against the node.
    Bitcoind,
    /// `kyoto://` BIP-157 over the node's P2P port (a trusted peer; regtest has no seeds).
    Kyoto,
}

impl BtcBackend {
    pub fn label(self) -> &'static str {
        match self {
            BtcBackend::Bitcoind => "bitcoind",
            BtcBackend::Kyoto => "kyoto",
        }
    }
}

/// A `--features bitcoin` zecd serving one or more `coin = "bitcoin"` wallets over one
/// backend. Built in two steps - [`ZecdBtc::prepare`] writes the config, then each wallet is
/// initialized with the flags the scenario needs - so a watch-only wallet can be created
/// from a sibling's exported key before the daemon ever starts.
pub struct ZecdBtc {
    proc: Option<KillOnDrop>,
    client: reqwest::Client,
    base_url: String,
    pub datadir: PathBuf,
    conf: PathBuf,
    pub rpc_port: u16,
    default_wallet: String,
}

impl ZecdBtc {
    /// Write the daemon config for `wallets` (the first is `default_wallet`), all on
    /// `backend` against `node`. A tight sync interval so mempool passes land quickly; the
    /// health server is disabled to avoid a port pick for a surface these suites do not
    /// assert.
    pub fn prepare(
        datadir: PathBuf,
        backend: BtcBackend,
        node: &BitcoinD,
        wallets: &[&str],
    ) -> ZecdBtc {
        std::fs::create_dir_all(&datadir).unwrap();
        let conf = datadir.join("zecd.toml");
        let server = match backend {
            BtcBackend::Bitcoind => format!("bitcoind://127.0.0.1:{}", node.rpc_port),
            BtcBackend::Kyoto => format!("kyoto://127.0.0.1:{}", node.p2p_port),
        };
        let mut text = format!("default_wallet = \"{}\"\n", wallets[0]);
        for wallet in wallets {
            text.push_str(&format!(
                "[wallets.{wallet}]\ncoin = \"bitcoin\"\nserver = \"{server}\"\n"
            ));
        }
        if backend == BtcBackend::Bitcoind {
            text.push_str("[bitcoind]\nrpc_user = \"harness\"\nrpc_password = \"harness\"\n");
        }
        text.push_str("[sync]\ninterval_secs = 1\n[health]\nenabled = false\n");
        std::fs::write(&conf, text).unwrap();
        ZecdBtc {
            proc: None,
            client: reqwest::Client::new(),
            base_url: String::new(),
            datadir,
            conf,
            rpc_port: 0,
            default_wallet: wallets[0].to_string(),
        }
    }

    fn cli(&self) -> Command {
        let mut cmd = Command::new(zecd_bin());
        cmd.args([
            "--datadir",
            self.datadir.to_str().unwrap(),
            "--regtest",
            "--conf",
            self.conf.to_str().unwrap(),
        ]);
        cmd
    }

    /// `zecd init --wallet <wallet> <extra...>`. `Ok((stdout, stderr))` on success (stdout
    /// carries a generated mnemonic), `Err(stderr)` on a refusal.
    pub fn init(&self, wallet: &str, extra: &[&str]) -> Result<(String, String), String> {
        let out = self
            .cli()
            .args(["init", "--wallet", wallet])
            .args(extra)
            .output()
            .expect("run zecd init");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        if out.status.success() {
            Ok((stdout, stderr))
        } else {
            Err(stderr)
        }
    }

    /// [`ZecdBtc::init`] that must succeed; returns the generated mnemonic when there is
    /// one (the last non-empty stdout line - a restore or an import prints none).
    pub fn init_ok(&self, wallet: &str, extra: &[&str]) -> Option<String> {
        let (stdout, _) = self
            .init(wallet, extra)
            .unwrap_or_else(|stderr| panic!("zecd init --wallet {wallet} failed: {stderr}"));
        stdout
            .lines()
            .map(str::trim)
            .rfind(|l| !l.is_empty())
            .map(str::to_string)
    }

    /// `zecd export-xpub --wallet <wallet>`: the account key, or the refusal's stderr.
    pub fn export_xpub(&self, wallet: &str) -> Result<String, String> {
        let out = self
            .cli()
            .args(["export-xpub", "--wallet", wallet])
            .output()
            .expect("run zecd export-xpub");
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).into_owned())
        }
    }

    /// The BDK wallet database of `wallet` (what a rebuild-from-pin test deletes).
    pub fn wallet_db_path(&self, wallet: &str) -> PathBuf {
        self.datadir
            .join(wallet)
            .join("btc")
            .join("bdk")
            .join("wallet.sqlite")
    }

    /// Spawn the daemon (on a fresh RPC port the first time) and wait for its RPC.
    pub async fn start(&mut self) {
        if self.rpc_port == 0 {
            self.rpc_port = pick_port().expect("pick zecd rpc port");
            self.base_url = format!("http://127.0.0.1:{}/", self.rpc_port);
        }
        let proc = self
            .cli()
            .args([
                "--rpcuser",
                "zec",
                "--rpcpassword",
                "secret",
                "--rpcport",
                &self.rpc_port.to_string(),
            ])
            .stdout(Stdio::null())
            .stderr(match std::env::var_os("ZECD_REGTEST_BTC_LOG") {
                // Debug hook: ZECD_REGTEST_BTC_LOG=<dir> keeps each daemon's stderr as
                // <dir>/zecd-<rpc port>.log (the port makes a rerun's files distinct).
                Some(dir) => std::fs::File::create(
                    std::path::Path::new(&dir).join(format!("zecd-{}.log", self.rpc_port)),
                )
                .map(Stdio::from)
                .unwrap_or_else(|_| Stdio::null()),
                None => Stdio::null(),
            })
            .spawn()
            .expect("spawn zecd");
        self.proc = Some(KillOnDrop(proc));
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if self.call("getwalletinfo", json!([])).await.is_ok() {
                return;
            }
            assert!(Instant::now() < deadline, "zecd RPC never came up");
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Kill the daemon (the guard's drop releases the datadir lock).
    pub fn stop(&mut self) {
        self.proc = None;
    }

    pub async fn restart(&mut self) {
        self.stop();
        tokio::time::sleep(Duration::from_secs(1)).await;
        self.start().await;
    }

    /// Call the default wallet.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, (i64, String)> {
        self.call_wallet(&self.default_wallet.clone(), method, params)
            .await
    }

    /// Call `/wallet/<wallet>`.
    pub async fn call_wallet(
        &self,
        wallet: &str,
        method: &str,
        params: Value,
    ) -> Result<Value, (i64, String)> {
        let resp = self
            .client
            .post(format!("{}wallet/{wallet}", self.base_url))
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

    /// Poll `wallet` until `pred` accepts the result of `method`, or panic with `what`.
    pub async fn wait_wallet(
        &self,
        wallet: &str,
        method: &str,
        params: Value,
        what: &str,
        pred: impl Fn(&Value) -> bool,
    ) {
        let deadline = Instant::now() + SYNC_TIMEOUT;
        let mut last = None;
        loop {
            match self.call_wallet(wallet, method, params.clone()).await {
                Ok(v) if pred(&v) => return,
                Ok(v) => last = Some(v),
                Err(_) => {}
            }
            assert!(
                Instant::now() < deadline,
                "wallet '{wallet}': {what} never happened (last {method}: {last:?})"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    pub async fn wait_height(&self, target: u64) {
        self.wait_wallet_height(&self.default_wallet.clone(), target)
            .await;
    }

    pub async fn wait_wallet_height(&self, wallet: &str, target: u64) {
        self.wait_wallet(
            wallet,
            "getblockcount",
            json!([]),
            &format!("sync to height {target}"),
            |v| v.as_u64() == Some(target),
        )
        .await;
    }

    /// Until the wallet's best block is `hash` (the reorg convergence check).
    pub async fn wait_wallet_best_hash(&self, wallet: &str, hash: &str) {
        self.wait_wallet(
            wallet,
            "getbestblockhash",
            json!([]),
            &format!("converge on best block {hash}"),
            |v| v.as_str() == Some(hash),
        )
        .await;
    }

    /// Until `getbalance` (trusted, confirmed) equals `expected`.
    pub async fn wait_wallet_balance(&self, wallet: &str, expected: f64) {
        self.wait_wallet(
            wallet,
            "getbalance",
            json!([]),
            &format!("balance {expected}"),
            |v| v.as_f64() == Some(expected),
        )
        .await;
    }

    /// Until `getunconfirmedbalance` equals `expected` (the bitcoind backend's 0-conf
    /// surface; kyoto has none).
    pub async fn wait_unconfirmed(&self, expected: f64) {
        self.wait_wallet(
            &self.default_wallet.clone(),
            "getunconfirmedbalance",
            json!([]),
            &format!("unconfirmed balance {expected}"),
            |v| v.as_f64() == Some(expected),
        )
        .await;
    }
}
