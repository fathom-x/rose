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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
/// printing the `skipping:` line the `btc-e2e` CI job greps its log for (a skip there fails
/// the job: it supplies both prerequisites, so a skip is a broken job, not a missing one).
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
        Self::start_with(bin, datadir, &[]).await
    }

    /// [`BitcoinD::start`] with `extra` flags appended to the node's command line - a
    /// permission such as `-whitelist=mempool@127.0.0.1`. NB [`BitcoinD::restart`] takes its
    /// own `extra`; pass the flags again there if the scenario still needs them.
    pub async fn start_with(bin: &Path, datadir: &Path, extra: &[&str]) -> BitcoinD {
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
        node.spawn(extra).await;
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

/// A fault-injecting relay between a zecd and its bitcoind's JSON-RPC port, for the one
/// send outcome no signal can reach: a **transport failure at the broadcast itself**. A
/// SIGSTOP hangs every call, so the sync pass detects the outage first and the send is
/// refused up front (`-4`, no upstream) before it reaches the broadcast; a kill races the
/// next sync pass the same way. This relay forwards every request byte for byte, except
/// that while [`RpcProxy::drop_method`] names one it closes the connection on any request
/// whose body names that method, without answering: the node never sees the request and
/// the client gets a broken socket - a failure with no verdict - while every other call
/// (the sync pass, the mempool pass, the redial) keeps working. One HTTP request per
/// read, framed by `Content-Length`, which is how both `bitcoincore-rpc` and Core's HTTP
/// server speak.
pub struct RpcProxy {
    pub port: u16,
    dropped: Arc<Mutex<Option<String>>>,
}

impl RpcProxy {
    /// Listen on a picked loopback port and forward to bitcoind's RPC at `upstream_port`.
    pub async fn start(upstream_port: u16) -> RpcProxy {
        let port = pick_port().expect("pick proxy port");
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("bind the rpc proxy");
        let dropped: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let rule = dropped.clone();
        tokio::spawn(async move {
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    return;
                };
                let rule = rule.clone();
                tokio::spawn(async move {
                    let _ = relay_rpc(client, upstream_port, rule).await;
                });
            }
        });
        RpcProxy { port, dropped }
    }

    /// From now on, drop (close without answering) every request naming `method`;
    /// `None` restores full forwarding. Takes effect on the next request.
    pub fn drop_method(&self, method: Option<&str>) {
        *self.dropped.lock().unwrap() = method.map(str::to_string);
    }
}

/// One proxied connection: request from the client, verdict, response from the node,
/// repeated while the client keeps the connection open. Returning closes both sockets.
async fn relay_rpc(
    mut client: TcpStream,
    upstream_port: u16,
    rule: Arc<Mutex<Option<String>>>,
) -> std::io::Result<()> {
    let mut upstream = TcpStream::connect(("127.0.0.1", upstream_port)).await?;
    loop {
        let Some(request) = read_http_message(&mut client).await? else {
            return Ok(());
        };
        let dropped = rule
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|m| String::from_utf8_lossy(&request).contains(&format!("\"{m}\"")));
        if dropped {
            return Ok(());
        }
        upstream.write_all(&request).await?;
        let Some(response) = read_http_message(&mut upstream).await? else {
            return Ok(());
        };
        client.write_all(&response).await?;
    }
}

/// Read one HTTP message (headers plus a `Content-Length` body) off `stream`; `None` on a
/// clean EOF before any byte.
async fn read_http_message(stream: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    let header_end = loop {
        if stream.read(&mut byte).await? == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(std::io::ErrorKind::UnexpectedEof.into())
            };
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break buf.len();
        }
    };
    let headers = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
    let length = headers
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await?;
    buf.extend_from_slice(&body);
    Ok(Some(buf))
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
    /// The `[health]` port (`/healthz` `/readyz` `/status`), picked at `prepare` so the
    /// config can name it before the daemon starts.
    pub health_port: u16,
    default_wallet: String,
}

impl ZecdBtc {
    /// Write the daemon config for `wallets` (the first is `default_wallet`), all on
    /// `backend` against `node`. A tight sync interval so mempool passes land quickly; the
    /// health server is on, on a picked port, so a suite can hold `/readyz` and `/status`
    /// to the Bitcoin wallets (see [`ZecdBtc::health_url`]).
    pub fn prepare(
        datadir: PathBuf,
        backend: BtcBackend,
        node: &BitcoinD,
        wallets: &[&str],
    ) -> ZecdBtc {
        Self::prepare_with(datadir, backend, node, wallets, "")
    }

    /// [`ZecdBtc::prepare`] with `wallet_extra` (TOML lines) appended to every wallet's
    /// `[wallets.<name>]` table - a per-wallet knob such as `lookahead = 40`.
    pub fn prepare_with(
        datadir: PathBuf,
        backend: BtcBackend,
        node: &BitcoinD,
        wallets: &[&str],
        wallet_extra: &str,
    ) -> ZecdBtc {
        Self::prepare_full(datadir, backend, node, wallets, wallet_extra, "")
    }

    /// [`ZecdBtc::prepare_with`] plus `global_extra` (TOML, whole tables) appended after the
    /// wallet tables - a daemon-wide section such as `[mempool]`.
    pub fn prepare_full(
        datadir: PathBuf,
        backend: BtcBackend,
        node: &BitcoinD,
        wallets: &[&str],
        wallet_extra: &str,
        global_extra: &str,
    ) -> ZecdBtc {
        let server = match backend {
            BtcBackend::Bitcoind => format!("bitcoind://127.0.0.1:{}", node.rpc_port),
            BtcBackend::Kyoto => format!("kyoto://127.0.0.1:{}", node.p2p_port),
        };
        Self::prepare_at(
            datadir,
            &server,
            backend == BtcBackend::Bitcoind,
            wallets,
            wallet_extra,
            global_extra,
        )
    }

    /// The bitcoind backend dialed at an explicit RPC port rather than the node's own - an
    /// [`RpcProxy`] standing between the two. Credentials are the node's.
    pub fn prepare_bitcoind_at(datadir: PathBuf, rpc_port: u16, wallets: &[&str]) -> ZecdBtc {
        Self::prepare_at(
            datadir,
            &format!("bitcoind://127.0.0.1:{rpc_port}"),
            true,
            wallets,
            "",
            "",
        )
    }

    fn prepare_at(
        datadir: PathBuf,
        server: &str,
        bitcoind_credentials: bool,
        wallets: &[&str],
        wallet_extra: &str,
        global_extra: &str,
    ) -> ZecdBtc {
        std::fs::create_dir_all(&datadir).unwrap();
        let conf = datadir.join("zecd.toml");
        let mut text = format!("default_wallet = \"{}\"\n", wallets[0]);
        for wallet in wallets {
            text.push_str(&format!(
                "[wallets.{wallet}]\ncoin = \"bitcoin\"\nserver = \"{server}\"\n{wallet_extra}\n"
            ));
        }
        if bitcoind_credentials {
            text.push_str("[bitcoind]\nrpc_user = \"harness\"\nrpc_password = \"harness\"\n");
        }
        text.push_str(global_extra);
        if !global_extra.is_empty() && !global_extra.ends_with('\n') {
            text.push('\n');
        }
        let health_port = pick_port().expect("pick zecd health port");
        text.push_str(&format!(
            "[sync]\ninterval_secs = 1\n[health]\nbind = \"127.0.0.1\"\nport = {health_port}\n"
        ));
        std::fs::write(&conf, text).unwrap();
        ZecdBtc {
            proc: None,
            client: reqwest::Client::new(),
            base_url: String::new(),
            datadir,
            conf,
            rpc_port: 0,
            health_port,
            default_wallet: wallets[0].to_string(),
        }
    }

    /// The health server's base URL (`http://127.0.0.1:<health_port>`).
    pub fn health_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.health_port)
    }

    /// `GET <health_url>/<path>`: the HTTP status and the JSON body.
    pub async fn health_get(&self, path: &str) -> (u16, Value) {
        let resp = self
            .client
            .get(format!("{}/{path}", self.health_url()))
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET /{path}: {e}"));
        let code = resp.status().as_u16();
        let body = resp.json().await.unwrap_or(Value::Null);
        (code, body)
    }

    /// Poll `/readyz` until its status code is `code`, or panic with `what`.
    pub async fn wait_readyz(&self, code: u16, what: &str) -> Value {
        let deadline = Instant::now() + SYNC_TIMEOUT;
        loop {
            let (got, body) = self.health_get("readyz").await;
            if got == code {
                return body;
            }
            assert!(
                Instant::now() < deadline,
                "/readyz never reached {code}: {what} (last: {got} {body})"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
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

    /// The running daemon's pid (what a benchmark reads `/proc/<pid>/status` for).
    pub fn pid(&self) -> Option<u32> {
        self.proc.as_ref().map(|p| p.0.id())
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
