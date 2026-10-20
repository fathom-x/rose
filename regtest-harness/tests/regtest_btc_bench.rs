//! Capacity benchmark for the Bitcoin kyoto wallet under the enclave's constraints: how the
//! wallet's own costs grow with its history.
//!
//! One regtest bitcoind (the funder: its `miner` wallet pays the wallet under test) and one
//! kyoto rose, the enclave's backend, on one chain. The wallet is funded in steps to N
//! received outputs (`ROSE_BENCH_BTC_STEPS`, cumulative), the deposit shape an exchange
//! wallet sees: by default one transaction per receive, 24 per block (Core's ancestor
//! limit for the funder's unconfirmed change chain). At every step:
//!
//! * `reads`: `getbalance`, `listunspent`, `listtransactions` (100), `getwalletinfo`
//!   latency, the median of five calls each.
//! * `memory`: the live daemon's RSS and high-water mark from `/proc`, plus the memory
//!   cgroup's current and peak when the daemon runs in its own scope (the `systemd-run
//!   --scope` wrapper the deployment's bench uses: those count a tmpfs datadir too, as the
//!   enclave's RAM-backed storage does).
//! * `datadir`: the wallet datadir's size on disk.
//! * `sends`: `ROSE_BENCH_BTC_SENDS` back-to-back `sendtoaddress` to the funder, each one's
//!   RPC latency and the time until the node's mempool holds it; then one `sendmany`
//!   paying `ROSE_BENCH_BTC_FANOUT` funder addresses.
//! * `burst`: one block paying `ROSE_BENCH_BTC_BURST` of the wallet's own addresses in one
//!   transaction: the catch-up time for a block full of own receives.
//! * `catchup`: per funding block, mine-to-wallet-at-height (min/median/max per step).
//! * `restore`: a from-seed restore on a fresh datadir (`init --restore --birthday 0`,
//!   what every enclave boot does): time to RPC up, time to the tip, time until the
//!   balance settles, whether it equals the original's (`balance_match`) and how much was
//!   recovered, then the same reads and memory on the restored daemon. Off with
//!   `ROSE_BENCH_BTC_RESTORE=0`.
//!
//! Both wallets run with `[wallets.btc] lookahead` set to cover every address the run
//! will use (`ROSE_BENCH_BTC_LOOKAHEAD`, default the last step plus the bursts plus 100),
//! because a kyoto recovery scan watches only the wallet's lookahead past what it has
//! revealed (100 at least): at the default of 25 a restore of a wallet with more than
//! about 125 used receive addresses stops short and reports itself synced (measured 138
//! of 1490 outputs at 1000 receives). The live wallet carries the same lookahead so its
//! per-block cost is the restorable configuration's. `ROSE_BENCH_BTC_LOOKAHEAD=default`
//! leaves both at 25 to measure that shortfall.
//!
//! What this does NOT measure: first-sync memory under a fast mainnet filter stream (the
//! filter backlog bip157 queues unbounded): a regtest
//! chain's filters are kilobytes. STEVE and the mempool feed are out too (`sources = []`,
//! RPC on loopback); the deployment measures those separately.
//!
//! Every line is prefixed `BENCH`; the whole result is one `BENCH_RESULTS <json>` line and,
//! with `ROSE_BENCH_BTC_OUT=<file>`, that JSON pretty-printed to the file.
//!
//! Configuration (all env; the first is the switch, so a plain `cargo test` skips in
//! milliseconds and CI never runs this):
//!   ROSE_BENCH_BTC_STEPS          = "1000,10000"      cumulative received outputs (required)
//!   ROSE_BENCH_BTC_OUTPUTS_PER_TX = 1                 outputs per funding transaction
//!   ROSE_BENCH_BTC_TXS_PER_BLOCK  = 24                funding transactions per block
//!   ROSE_BENCH_BTC_SENDS          = 20                sends per step (0 disables)
//!   ROSE_BENCH_BTC_FANOUT         = 100               outputs of the fan-out send (0 disables)
//!   ROSE_BENCH_BTC_BURST          = 500               own outputs in the burst block (0 disables)
//!   ROSE_BENCH_BTC_RESTORE        = 1                 restore at each step
//!   ROSE_BENCH_BTC_LOOKAHEAD      = auto              both wallets' lookahead (auto, N, default)
//!   ROSE_BENCH_BTC_OUT            = <file>            where to write the JSON
//!   ROSE_BIN (a `bitcoin`-feature rose; the deployment passes the enclave's own binary),
//!   BITCOIND_BIN, as for every Bitcoin suite.

use std::path::Path;
use std::time::{Duration, Instant};

use rose_regtest_harness::btc::{provisioned, BitcoinD, BtcBackend, RoseBtc};
use serde_json::{json, Value};

/// What each funding output pays (0.001 BTC): small, so 50k of them fit in a few coinbases.
const RECEIVE_BTC: f64 = 0.001;
/// Funding blocks mined up front: 101 for maturity, plus one mature coinbase (50 BTC) per
/// 40k receives at RECEIVE_BTC, with room for fees.
const MATURITY: u64 = 101;
/// The restore of a large wallet is the long pole; its own deadline, not the harness's.
const RESTORE_TIMEOUT: Duration = Duration::from_secs(4 * 3600);
const CATCHUP_TIMEOUT: Duration = Duration::from_secs(600);
/// A restore whose balance has not moved for this long, at the tip, has stopped.
const SETTLE: Duration = Duration::from_secs(30);

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn ms(d: Duration) -> u64 {
    d.as_millis() as u64
}

fn median(mut v: Vec<u64>) -> u64 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    v[v.len() / 2]
}

/// The daemon's memory: `/proc/<pid>/status` (RSS and the high-water mark, kB), and when
/// the daemon's cgroup is not this process's own (a per-daemon scope), that cgroup's
/// `memory.current` and `memory.peak` (bytes; tmpfs pages the daemon wrote count there).
fn memory(pid: u32) -> Value {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let kb = |key: &str| -> Option<u64> {
        status
            .lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
    };
    let mut out = json!({"rss_kb": kb("VmRSS:"), "hwm_kb": kb("VmHWM:")});
    let cgroup_of = |p: &str| -> Option<String> {
        std::fs::read_to_string(p)
            .ok()?
            .lines()
            .find_map(|l| l.strip_prefix("0::").map(str::to_string))
    };
    if let (Some(theirs), Some(ours)) = (
        cgroup_of(&format!("/proc/{pid}/cgroup")),
        cgroup_of("/proc/self/cgroup"),
    ) {
        if theirs != ours {
            let read = |f: &str| -> Option<u64> {
                std::fs::read_to_string(format!("/sys/fs/cgroup{theirs}/{f}"))
                    .ok()?
                    .trim()
                    .parse()
                    .ok()
            };
            out["cgroup"] = json!({
                "path": theirs,
                "current_bytes": read("memory.current"),
                "peak_bytes": read("memory.peak"),
                "max_bytes": read("memory.max"),
            });
        }
    }
    out
}

fn dir_size(path: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .map(|e| {
            let p = e.path();
            if p.is_dir() {
                dir_size(&p)
            } else {
                e.metadata().map(|m| m.len()).unwrap_or(0)
            }
        })
        .sum()
}

async fn new_address(rose: &RoseBtc) -> String {
    rose.call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress")
        .as_str()
        .unwrap()
        .to_string()
}

/// Mine one block and wait for the wallet to report its height: the catch-up time.
async fn mine_and_catch_up(node: &BitcoinD, rose: &RoseBtc) -> u64 {
    let target = node.height().await + 1;
    node.mine(1).await;
    let t = Instant::now();
    wait_height(rose, target, CATCHUP_TIMEOUT).await;
    ms(t.elapsed())
}

async fn wait_height(rose: &RoseBtc, target: u64, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let mut last = Value::Null;
    loop {
        if let Ok(v) = rose.call("getblockcount", json!([])).await {
            if v.as_u64() == Some(target) {
                return;
            }
            last = v;
        }
        assert!(
            Instant::now() < deadline,
            "the wallet never reached height {target} (last {last})"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// The read RPCs a GUI or an operator issues, the median of five each.
async fn reads(rose: &RoseBtc) -> Value {
    let mut out = json!({});
    for (name, method, params) in [
        ("getbalance", "getbalance", json!([])),
        ("listunspent", "listunspent", json!([])),
        (
            "listtransactions_100",
            "listtransactions",
            json!(["*", 100]),
        ),
        ("getwalletinfo", "getwalletinfo", json!([])),
    ] {
        let mut samples = Vec::new();
        for _ in 0..5 {
            let t = Instant::now();
            rose.call(method, params.clone()).await.expect(method);
            samples.push(ms(t.elapsed()));
        }
        out[name] = json!(median(samples));
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn regtest_btc_bench() {
    let Some(steps_spec) = std::env::var("ROSE_BENCH_BTC_STEPS").ok() else {
        eprintln!("SKIP regtest_btc_bench: set ROSE_BENCH_BTC_STEPS=1000,10000");
        return;
    };
    let steps: Vec<u64> = steps_spec
        .split(',')
        .map(|s| {
            s.trim()
                .parse()
                .expect("ROSE_BENCH_BTC_STEPS: comma-separated counts")
        })
        .collect();
    assert!(
        steps.windows(2).all(|w| w[0] < w[1]),
        "ROSE_BENCH_BTC_STEPS must increase: {steps:?}"
    );
    let outputs_per_tx = env_u64("ROSE_BENCH_BTC_OUTPUTS_PER_TX", 1).max(1);
    let txs_per_block = env_u64("ROSE_BENCH_BTC_TXS_PER_BLOCK", 24).max(1);
    let sends = env_u64("ROSE_BENCH_BTC_SENDS", 20);
    let fanout = env_u64("ROSE_BENCH_BTC_FANOUT", 100);
    let burst = env_u64("ROSE_BENCH_BTC_BURST", 500);
    let restore = env_u64("ROSE_BENCH_BTC_RESTORE", 1) == 1;
    let lookahead = match std::env::var("ROSE_BENCH_BTC_LOOKAHEAD").as_deref() {
        Err(_) | Ok("auto") | Ok("") => {
            Some(steps.last().copied().unwrap_or(0) + burst * steps.len() as u64 + 100)
        }
        Ok("default") => None,
        Ok(n) => Some(
            n.parse()
                .expect("ROSE_BENCH_BTC_LOOKAHEAD: auto, default or a number"),
        ),
    };
    let wallet_extra = lookahead
        .map(|n| format!("lookahead = {n}\n"))
        .unwrap_or_default();

    let dir = tempfile::tempdir().expect("tempdir");
    let Some(bitcoind) = provisioned(dir.path()) else {
        return;
    };
    let rose_version = std::process::Command::new(rose_regtest_harness::rosed_bin())
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    eprintln!(
        "BENCH btc rose={rose_version:?} steps={steps:?} outputs_per_tx={outputs_per_tx} txs_per_block={txs_per_block} sends={sends} fanout={fanout} burst={burst} restore={restore} lookahead={lookahead:?} tmp={}",
        dir.path().display()
    );

    // The funder: enough mature coinbases for every receive, the burst blocks and fees.
    let node = BitcoinD::start(&bitcoind, &dir.path().join("btcdata")).await;
    let total_receives = steps.last().copied().unwrap_or(0) + burst * steps.len() as u64;
    let coinbases = total_receives / 40_000 + 2;
    node.mine(MATURITY + coinbases).await;

    // The wallet under test: kyoto, no mempool feed (the kyoto suite's posture).
    let mut rose = RoseBtc::prepare_full(
        dir.path().join("wallet"),
        BtcBackend::Kyoto,
        &node,
        &["btc"],
        &wallet_extra,
        "[mempool]\nsources = []\n",
    );
    let mnemonic = rose
        .init_ok("btc", &["--birthday", "0"])
        .expect("a fresh init prints its mnemonic");
    let t0 = Instant::now();
    rose.start().await;
    let startup_ms = ms(t0.elapsed());
    wait_height(&rose, node.height().await, CATCHUP_TIMEOUT).await;
    eprintln!(
        "BENCH up port={} startup_ms={startup_ms} height={}",
        rose.rpc_port,
        node.height().await
    );

    let mut results: Vec<Value> = Vec::new();
    let mut received: u64 = 0;
    let phrase_file = dir.path().join("phrase.txt");
    std::fs::write(&phrase_file, format!("{mnemonic}\n")).unwrap();

    for step in steps {
        // --- fund to `step` received outputs ------------------------------------------
        let base_balance = rose
            .call("getbalance", json!([]))
            .await
            .expect("getbalance")
            .as_f64()
            .unwrap();
        let received_before = received;
        let t_fund = Instant::now();
        let mut catchup = Vec::new();
        let mut blocks = 0u64;
        while received < step {
            let mut in_block = 0;
            while in_block < txs_per_block && received < step {
                let n = outputs_per_tx.min(step - received);
                let mut outs = serde_json::Map::new();
                for _ in 0..n {
                    outs.insert(new_address(&rose).await, json!(RECEIVE_BTC));
                }
                node.call("sendmany", json!(["", outs]))
                    .await
                    .expect("funder sendmany");
                received += n;
                in_block += 1;
            }
            catchup.push(mine_and_catch_up(&node, &rose).await);
            blocks += 1;
        }
        let fund_ms = ms(t_fund.elapsed());
        // The balance is what it was plus what was paid, rounded as the wallet rounds it.
        let balance_expected =
            ((base_balance + (received - received_before) as f64 * RECEIVE_BTC) * 1e8).round()
                / 1e8;
        let deadline = Instant::now() + CATCHUP_TIMEOUT;
        loop {
            let b = rose
                .call("getbalance", json!([]))
                .await
                .expect("getbalance");
            if b.as_f64() == Some(balance_expected) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "balance {b} never became {balance_expected}"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let catchup_stats = json!({
            "blocks": blocks,
            "min_ms": catchup.iter().copied().min().unwrap_or(0),
            "median_ms": median(catchup.clone()),
            "max_ms": catchup.iter().copied().max().unwrap_or(0),
        });
        eprintln!(
            "BENCH step={step} funded received={received} blocks={blocks} fund_ms={fund_ms} catchup={catchup_stats}"
        );

        // --- the live wallet at this size ---------------------------------------------
        let live_reads = reads(&rose).await;
        let live_memory = memory(rose.pid().expect("live pid"));
        let live_datadir = dir_size(&rose.datadir);
        let height = node.height().await;
        eprintln!(
            "BENCH step={step} live reads={live_reads} memory={live_memory} datadir_bytes={live_datadir}"
        );

        // --- sends: back-to-back, each relayed to the node's mempool --------------------
        let mut send_results = Vec::new();
        if sends > 0 {
            let sink = node.new_address().await;
            for i in 0..sends {
                let t = Instant::now();
                let r = rose.call("sendtoaddress", json!([sink, 0.0005])).await;
                let rpc_ms = ms(t.elapsed());
                match r {
                    Ok(txid) => {
                        let t2 = Instant::now();
                        node.wait_mempool_contains(txid.as_str().unwrap()).await;
                        let relay_ms = ms(t2.elapsed());
                        send_results.push(json!({"i": i, "rpc_ms": rpc_ms, "relay_ms": relay_ms}));
                    }
                    Err((code, msg)) => {
                        eprintln!("BENCH step={step} send i={i} FAILED {code} {msg}");
                        send_results.push(json!({"i": i, "rpc_ms": rpc_ms, "error": msg}));
                    }
                }
            }
            let ok: Vec<u64> = send_results
                .iter()
                .filter_map(|s| s["rpc_ms"].as_u64().filter(|_| s["error"].is_null()))
                .collect();
            eprintln!(
                "BENCH step={step} sends n={} ok={} rpc_median_ms={} rpc_max_ms={}",
                sends,
                ok.len(),
                median(ok.clone()),
                ok.iter().max().copied().unwrap_or(0)
            );
        }
        let mut fanout_result = Value::Null;
        if fanout > 0 {
            let mut outs = serde_json::Map::new();
            for _ in 0..fanout {
                outs.insert(node.new_address().await, json!(0.0001));
            }
            let t = Instant::now();
            let r = rose.call("sendmany", json!(["", outs])).await;
            let rpc_ms = ms(t.elapsed());
            fanout_result = match r {
                Ok(txid) => {
                    let t2 = Instant::now();
                    node.wait_mempool_contains(txid.as_str().unwrap()).await;
                    json!({"outputs": fanout, "rpc_ms": rpc_ms, "relay_ms": ms(t2.elapsed())})
                }
                Err((code, msg)) => {
                    json!({"outputs": fanout, "rpc_ms": rpc_ms, "error": format!("{code} {msg}")})
                }
            };
            eprintln!("BENCH step={step} fanout={fanout_result}");
        }
        let mut post_send_catchup_ms = None;
        if sends > 0 || fanout > 0 {
            post_send_catchup_ms = Some(mine_and_catch_up(&node, &rose).await);
        }

        // --- the burst block: many own receives in one transaction ----------------------
        let mut burst_result = Value::Null;
        if burst > 0 {
            let mut outs = serde_json::Map::new();
            for _ in 0..burst {
                outs.insert(new_address(&rose).await, json!(RECEIVE_BTC));
            }
            node.call("sendmany", json!(["", outs]))
                .await
                .expect("burst sendmany");
            received += burst;
            let catchup_ms = mine_and_catch_up(&node, &rose).await;
            burst_result = json!({"outputs": burst, "catchup_ms": catchup_ms});
            eprintln!("BENCH step={step} burst={burst_result}");
        }

        // What the wallet holds now, for the restore to match.
        let balance = rose
            .call("getbalance", json!([]))
            .await
            .expect("getbalance");
        let unspent = rose
            .call("listunspent", json!([]))
            .await
            .expect("listunspent")
            .as_array()
            .map(Vec::len)
            .unwrap_or(0);
        let tip = node.height().await;

        // --- restore from seed on a fresh datadir ---------------------------------------
        let mut restore_result = Value::Null;
        if restore {
            let rdir = dir.path().join(format!("restore-{step}"));
            let mut restored = RoseBtc::prepare_full(
                rdir.clone(),
                BtcBackend::Kyoto,
                &node,
                &["btc"],
                &wallet_extra,
                "[mempool]\nsources = []\n",
            );
            let t = Instant::now();
            restored.init_ok(
                "btc",
                &[
                    "--restore",
                    "--mnemonic-file",
                    phrase_file.to_str().unwrap(),
                    "--birthday",
                    "0",
                ],
            );
            let init_ms = ms(t.elapsed());
            let t = Instant::now();
            restored.start().await;
            let up_ms = ms(t.elapsed());
            wait_height(&restored, tip, RESTORE_TIMEOUT).await;
            let height_ms = ms(t.elapsed());
            // At the tip is not yet recovered: wait for the balance to reach the original's,
            // or to stop moving (a restore that cannot see every address stops short and
            // reports itself synced; that is recorded, not waited on).
            let deadline = Instant::now() + RESTORE_TIMEOUT;
            let mut last = Value::Null;
            let mut unchanged_since = Instant::now();
            let settled;
            loop {
                let b = restored
                    .call("getbalance", json!([]))
                    .await
                    .expect("getbalance");
                if b == balance {
                    settled = true;
                    break;
                }
                if b != last {
                    last = b;
                    unchanged_since = Instant::now();
                } else if unchanged_since.elapsed() > SETTLE {
                    settled = false;
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "the restore never settled (balance {last}, original {balance})"
                );
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            let recovered_ms = ms(t.elapsed());
            let r_balance = restored
                .call("getbalance", json!([]))
                .await
                .expect("getbalance");
            let r_unspent = restored
                .call("listunspent", json!([]))
                .await
                .expect("listunspent")
                .as_array()
                .map(Vec::len)
                .unwrap_or(0);
            let r_reads = reads(&restored).await;
            let r_memory = memory(restored.pid().expect("restored pid"));
            let r_datadir = dir_size(&rdir);
            restore_result = json!({
                "init_ms": init_ms, "up_ms": up_ms, "height_ms": height_ms,
                "recovered_ms": recovered_ms, "height": tip,
                "balance": r_balance, "balance_match": settled,
                "unspent": r_unspent, "unspent_match": r_unspent == unspent,
                "reads": r_reads, "memory": r_memory, "datadir_bytes": r_datadir,
            });
            eprintln!("BENCH step={step} restore={restore_result}");
            restored.stop();
            let _ = std::fs::remove_dir_all(&rdir);
        }

        results.push(json!({
            "step": step, "received": received, "height": height,
            "fund_ms": fund_ms, "catchup": catchup_stats,
            "live": {"reads": live_reads, "memory": live_memory, "datadir_bytes": live_datadir},
            "sends": send_results, "fanout": fanout_result,
            "post_send_catchup_ms": post_send_catchup_ms,
            "burst": burst_result,
            "balance": balance, "unspent": unspent,
            "restore": restore_result,
        }));
    }

    let all = json!({
        "rose": rose_version,
        "config": {
            "outputs_per_tx": outputs_per_tx, "txs_per_block": txs_per_block,
            "sends": sends, "fanout": fanout, "burst": burst, "restore": restore,
            "lookahead": lookahead,
        },
        "steps": results,
    });
    eprintln!("BENCH_RESULTS {}", serde_json::to_string(&all).unwrap());
    if let Ok(out) = std::env::var("ROSE_BENCH_BTC_OUT") {
        std::fs::write(&out, serde_json::to_string_pretty(&all).unwrap()).expect("write results");
        eprintln!("BENCH wrote {out}");
    }
    rose.stop();
}
