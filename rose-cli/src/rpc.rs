//! The JSON-RPC client half of `rose`, modeled on `bitcoin-cli`: one HTTP POST per call to
//! the daemon the configuration describes, the method's parameters taken from the command
//! line, the result printed, and an RPC error reported the way `bitcoin-cli` reports it (the
//! `error code:` / `error message:` pair on stderr, the code's magnitude as the exit status).
//!
//! The daemon is found exactly as `rosed` would bind: `[rpc] port` from the resolved
//! configuration (so `--conf`, `--datadir`, `--rpcport` all apply), and the credentials from
//! `--rpcuser`/`--rpcpassword` (or the `[rpc]` pair) when given, else the cookie file the
//! daemon writes at startup. `--rpcconnect` names a host other than the bind address, and
//! `--rpcwallet` targets one wallet through the `/wallet/<name>` endpoint.

use std::ffi::OsString;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rosed::config::AppConfig;
use serde_json::{json, Value};

/// The client's own flags. They are `rose`'s, not the daemon's, so they live here rather than
/// on the shared [`rosed::config::Cli`]; and they are not `global`, so they come before the
/// method name (after it, every word is a parameter - `rose getbalance "*" 6`).
#[derive(Debug, Clone, Default, clap::Args)]
pub struct ClientArgs {
    /// Send RPC calls to this host (default: `[rpc] bind` when it names one address, else
    /// 127.0.0.1). The port is `[rpc] port` or `--rpcport`.
    #[arg(long = "rpcconnect", value_name = "HOST")]
    pub rpc_connect: Option<String>,

    /// Send RPC calls for this wallet (the daemon's `/wallet/<name>` endpoint). Without it
    /// the daemon answers from its default wallet.
    #[arg(long = "rpcwallet", value_name = "NAME")]
    pub rpc_wallet: Option<String>,

    /// Read the daemon's cookie from this file instead of `[rpc] cookiefile`
    /// (`<datadir>/.cookie`). Ignored when `--rpcuser`/`--rpcpassword` are given.
    #[arg(long = "rpccookiefile", value_name = "FILE")]
    pub rpc_cookie_file: Option<PathBuf>,

    /// Give up on a call after this many seconds (0 = never).
    #[arg(long = "rpcclienttimeout", value_name = "SECS", default_value_t = 900)]
    pub rpc_client_timeout: u64,
}

/// Run one RPC call: `words[0]` is the method, the rest its parameters.
pub async fn run(config: &AppConfig, args: &ClientArgs, words: &[OsString]) -> anyhow::Result<()> {
    let mut words = words.iter().map(|w| {
        w.to_str()
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("argument {w:?} is not valid UTF-8"))
    });
    let method = words
        .next()
        .ok_or_else(|| anyhow!("no RPC method given"))??;
    let params = words
        .map(|w| w.map(param_value))
        .collect::<anyhow::Result<Vec<Value>>>()?;

    let target = Target::from_config(config, args)?;
    let outcome = call(&target, &method, params, args.rpc_client_timeout).await?;
    match outcome {
        Outcome::Result(result) => {
            let text = render_result(&result);
            if !text.is_empty() {
                println!("{text}");
            }
            Ok(())
        }
        Outcome::Error { code, message } => {
            // bitcoin-cli's shape, to the letter: the pair on stderr and the code's
            // magnitude as the exit status (`RPC_INVALID_PARAMETER` -8 exits 8).
            eprintln!("error code: {code}\nerror message:\n{message}");
            std::process::exit(code.unsigned_abs().min(255) as i32);
        }
    }
}

/// One command-line word as a JSON-RPC parameter: JSON when it parses as JSON (`6`, `true`,
/// `["a","b"]`, `{"k":1}`), else the word itself as a string - so an address or a label needs
/// no quoting while a number stays a number.
fn param_value(word: String) -> Value {
    serde_json::from_str(&word).unwrap_or(Value::String(word))
}

/// What `bitcoin-cli` prints for a result: nothing for `null`, a string bare (no quotes), and
/// anything else as indented JSON.
fn render_result(result: &Value) -> String {
    match result {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => serde_json::to_string_pretty(other).expect("a JSON value serializes"),
    }
}

/// Where a call goes and how it authenticates.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    url: String,
    authorization: String,
}

impl Target {
    fn from_config(config: &AppConfig, args: &ClientArgs) -> anyhow::Result<Target> {
        let host = match &args.rpc_connect {
            Some(host) => host.clone(),
            None => rpc_host(config.rpc.bind),
        };
        let host = match host.parse::<IpAddr>() {
            Ok(IpAddr::V6(v6)) => format!("[{v6}]"),
            _ => host,
        };
        let path = match &args.rpc_wallet {
            Some(wallet) => format!("/wallet/{wallet}"),
            None => "/".to_string(),
        };
        let url = format!("http://{host}:{port}{path}", port = config.rpc.port);

        let credential = match (&config.rpc.user, &config.rpc.password) {
            (Some(user), Some(password)) => format!("{user}:{}", password.expose()),
            (Some(user), None) => bail!(
                "--rpcuser {user} needs --rpcpassword (or ROSE_RPC_PASSWORD); with neither, \
                 the daemon's cookie file is used"
            ),
            (None, _) => {
                let path = args
                    .rpc_cookie_file
                    .clone()
                    .or_else(|| config.rpc.cookiefile.clone())
                    .ok_or_else(|| anyhow!("no RPC credentials: pass --rpcuser/--rpcpassword"))?;
                let cookie = std::fs::read_to_string(&path).with_context(|| {
                    format!(
                        "reading the daemon's cookie file {}: is rosed running with this datadir \
                         and configuration? Otherwise pass --rpcuser/--rpcpassword",
                        path.display()
                    )
                })?;
                let cookie = cookie.trim();
                if !cookie.contains(':') {
                    bail!("cookie file {} is not `user:password`", path.display());
                }
                cookie.to_string()
            }
        };
        Ok(Target {
            url,
            authorization: basic_header(&credential),
        })
    }
}

/// The host a client dials for a daemon bound at `bind`: the bind address when it names one
/// interface, loopback when it is the unspecified address (every interface).
fn rpc_host(bind: IpAddr) -> String {
    if bind.is_unspecified() {
        match bind {
            IpAddr::V4(_) => "127.0.0.1".to_string(),
            IpAddr::V6(_) => "::1".to_string(),
        }
    } else {
        bind.to_string()
    }
}

fn basic_header(credential: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(credential)
    )
}

enum Outcome {
    Result(Value),
    Error { code: i64, message: String },
}

/// Largest response body the client reads: generous for `listtransactions` over a busy
/// wallet, bounded so a misbehaving endpoint cannot exhaust memory.
const MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;

async fn call(
    target: &Target,
    method: &str,
    params: Vec<Value>,
    timeout_secs: u64,
) -> anyhow::Result<Outcome> {
    let body = json!({ "jsonrpc": "1.0", "id": "rose", "method": method, "params": params });
    let req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(&target.url)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::AUTHORIZATION, &target.authorization)
        .body(Full::new(Bytes::from(body.to_string())))
        .context("building the RPC request")?;
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();

    let round_trip = async {
        let response = client
            .request(req)
            .await
            .with_context(|| format!("could not connect to the daemon at {}", target.url))?;
        let status = response.status();
        let body = http_body_util::Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|e| anyhow!("reading the RPC response: {e}"))?
            .to_bytes();
        Ok::<_, anyhow::Error>((status, body))
    };
    let (status, body) = if timeout_secs == 0 {
        round_trip.await?
    } else {
        tokio::time::timeout(Duration::from_secs(timeout_secs), round_trip)
            .await
            .map_err(|_| anyhow!("the daemon did not answer within {timeout_secs}s"))??
    };

    // Bitcoin Core carries the JSON error envelope on non-200 statuses too, so the body is
    // read whatever the status; only a body with no envelope falls back to the status line.
    match serde_json::from_slice::<Value>(&body) {
        Ok(envelope) => {
            if let Some(err) = envelope.get("error").filter(|e| !e.is_null()) {
                return Ok(Outcome::Error {
                    code: err.get("code").and_then(Value::as_i64).unwrap_or(-1),
                    message: err
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown error")
                        .to_string(),
                });
            }
            if !status.is_success() {
                bail!("the daemon answered HTTP {status} with no error object");
            }
            Ok(Outcome::Result(
                envelope.get("result").cloned().unwrap_or(Value::Null),
            ))
        }
        Err(_) if status == hyper::StatusCode::UNAUTHORIZED => {
            bail!("Authorization failed: Incorrect rpcuser or rpcpassword")
        }
        Err(e) => bail!(
            "the daemon answered HTTP {status} with a non-JSON body ({e}): {}",
            String::from_utf8_lossy(&body)
                .chars()
                .take(200)
                .collect::<String>()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rosed::config::ConfigOverrides;

    #[test]
    fn a_word_is_json_when_it_parses_and_a_string_otherwise() {
        assert_eq!(param_value("6".into()), json!(6));
        assert_eq!(param_value("true".into()), json!(true));
        assert_eq!(param_value("[\"a\",1]".into()), json!(["a", 1]));
        assert_eq!(param_value("{\"k\":1}".into()), json!({"k": 1}));
        assert_eq!(param_value("0.001".into()), json!(0.001));
        assert_eq!(
            param_value("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".into()),
            json!("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
        );
        assert_eq!(param_value("*".into()), json!("*"));
    }

    #[test]
    fn results_render_the_way_bitcoin_cli_prints_them() {
        assert_eq!(render_result(&Value::Null), "");
        assert_eq!(render_result(&json!("txid-here")), "txid-here");
        assert_eq!(render_result(&json!(42)), "42");
        assert_eq!(render_result(&json!({"a": 1})), "{\n  \"a\": 1\n}");
    }

    #[test]
    fn an_unspecified_bind_is_dialed_on_loopback() {
        assert_eq!(rpc_host("0.0.0.0".parse().unwrap()), "127.0.0.1");
        assert_eq!(rpc_host("::".parse().unwrap()), "::1");
        assert_eq!(rpc_host("10.0.0.5".parse().unwrap()), "10.0.0.5");
    }

    fn config_with(dir: &std::path::Path, extra: ConfigOverrides) -> AppConfig {
        AppConfig::resolve_overrides(&ConfigOverrides {
            datadir: Some(dir.to_path_buf()),
            regtest: true,
            ..extra
        })
        .expect("resolve")
    }

    #[test]
    fn explicit_credentials_win_and_select_the_wallet_path() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_with(
            dir.path(),
            ConfigOverrides {
                rpc_user: Some("alice".into()),
                rpc_password: Some(rosed::secret::Password::new("hunter2")),
                rpc_port: Some(18232),
                ..Default::default()
            },
        );
        let args = ClientArgs {
            rpc_wallet: Some("btc".into()),
            ..Default::default()
        };
        let target = Target::from_config(&config, &args).unwrap();
        assert_eq!(target.url, "http://127.0.0.1:18232/wallet/btc");
        assert_eq!(target.authorization, basic_header("alice:hunter2"));
    }

    #[test]
    fn without_credentials_the_datadir_cookie_is_read() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".cookie"), "__cookie__:s3cret\n").unwrap();
        let config = config_with(dir.path(), ConfigOverrides::default());
        let target = Target::from_config(&config, &ClientArgs::default()).unwrap();
        assert_eq!(target.authorization, basic_header("__cookie__:s3cret"));
        assert!(target.url.ends_with("/"), "{}", target.url);
    }

    #[test]
    fn a_missing_cookie_names_the_file_and_the_remedy() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_with(dir.path(), ConfigOverrides::default());
        let err = Target::from_config(&config, &ClientArgs::default()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains(".cookie") && msg.contains("--rpcuser"),
            "{msg}"
        );
    }

    #[test]
    fn a_user_without_a_password_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_with(
            dir.path(),
            ConfigOverrides {
                rpc_user: Some("alice".into()),
                ..Default::default()
            },
        );
        let err = Target::from_config(&config, &ClientArgs::default()).unwrap_err();
        assert!(err.to_string().contains("--rpcpassword"), "{err}");
    }
}
