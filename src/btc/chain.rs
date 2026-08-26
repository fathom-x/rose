//! The BDK engine's chain access: resolving a Bitcoin wallet's upstream endpoint and dialing
//! bitcoind's JSON-RPC.
//!
//! The one backend today is a **local bitcoind** ("full mode", the analog of the Zcash
//! engine's `zebra://`): plaintext HTTP JSON-RPC, local-only by the same cleartext-credential
//! policy the zebra backend enforces, with the block/mempool emission handled by
//! `bdk_bitcoind_rpc`'s checkpoint-anchored [`Emitter`](bdk_bitcoind_rpc::Emitter) (driven by
//! the actor). A BIP-157 light mode (kyoto/bip157 - the lightwalletd analog, with better
//! privacy) is the planned second backend; when it lands, this module grows the enum seam the
//! Zcash side's `chain::AnySource` models, and the token grammar a second scheme.
//!
//! Token grammar (`[wallets.<name>] server` on a bitcoin wallet):
//!  * `bitcoind` - the default: a local bitcoind at `127.0.0.1` on the network's standard RPC
//!    port (8332 main / 18332 test / 18443 regtest).
//!  * `bitcoind://host:port` - an explicit bitcoind JSON-RPC endpoint (plaintext HTTP,
//!    local-only by policy - the same gate as `zebra://`).
//!
//! The Zcash tokens (`zebra`, `zecrocks`, `https://...`) are refused here by construction: a
//! bitcoin wallet cannot dial a Zcash upstream, and the error says which grammar applies.
//! Credentials ride the global `[bitcoind]` section (`rpc_user`/`rpc_password`/`rpc_cookie`),
//! mirroring `[zebra]` - a cookie file wins over the pair, and nothing set means no auth
//! (bitcoind always mints a cookie, so an explicit `rpc_cookie` path is the usual answer).

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context as _};
use bdk_bitcoind_rpc::bitcoincore_rpc::{self, RpcApi as _};
use bdk_wallet::bitcoin::{FeeRate, Transaction, Txid};

use crate::chain::zebra::{host_is_local, CleartextPolicy};
use crate::coin::BitcoinNetwork;

/// bitcoind's standard JSON-RPC ports, per network. Unlike zebra (which ships with RPC
/// disabled and has no port to inherit), these are bitcoind's own defaults, so the bare
/// `bitcoind` token composes with a stock local node.
pub const BITCOIND_RPC_PORT_MAIN: u16 = 8332;
pub const BITCOIND_RPC_PORT_TESTNET3: u16 = 18332;
pub const BITCOIND_RPC_PORT_TESTNET4: u16 = 48332;
pub const BITCOIND_RPC_PORT_REGTEST: u16 = 18443;

/// `[bitcoind]` credentials, mirroring the `[zebra]` section: a cookie file supersedes the
/// user/password pair, and nothing set dials unauthenticated (which a stock bitcoind refuses -
/// its RPC always requires auth - but the refusal then comes from the node, actionably).
#[derive(Clone, Debug, Default)]
pub struct BitcoindAuth {
    pub user: Option<String>,
    pub password: Option<String>,
    pub cookie: Option<PathBuf>,
}

impl BitcoindAuth {
    /// Whether any credential source is configured (decides if the cleartext gate applies),
    /// without reading the cookie file - same contract as `ZebraAuth::is_configured`.
    pub fn is_configured(&self) -> bool {
        self.cookie.is_some() || self.user.is_some() || self.password.is_some()
    }

    /// Configuration-only validation (no file read, safe pre-deployment): the pair must be
    /// set together; a cookie makes the pair irrelevant.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.cookie.is_some() {
            return Ok(());
        }
        match (&self.user, &self.password) {
            (Some(_), None) | (None, Some(_)) => Err(anyhow!(
                "[bitcoind] rpc_user and rpc_password must be set together"
            )),
            _ => Ok(()),
        }
    }

    fn to_rpc_auth(&self) -> bitcoincore_rpc::Auth {
        if let Some(cookie) = &self.cookie {
            return bitcoincore_rpc::Auth::CookieFile(cookie.clone());
        }
        match (&self.user, &self.password) {
            (Some(user), Some(password)) => {
                bitcoincore_rpc::Auth::UserPass(user.clone(), password.clone())
            }
            _ => bitcoincore_rpc::Auth::None,
        }
    }
}

/// A resolved bitcoind endpoint: everything needed to dial it, plus the connect-time checks
/// that need no network (`preflight`), which is what `zecd config check` reports from.
#[derive(Clone, Debug)]
pub struct BitcoindEndpoint {
    host: String,
    port: u16,
    network: BitcoinNetwork,
    auth: BitcoindAuth,
    cleartext_policy: CleartextPolicy,
}

impl BitcoindEndpoint {
    pub fn describe(&self) -> String {
        format!("bitcoind {}:{}", self.host, self.port)
    }

    /// The configuration-only checks a connect would fail on: credential shape, and the
    /// cleartext-credential locality gate (the bitcoind RPC is plaintext HTTP, exactly like
    /// zebra's, so credentials must not ride to a globally-routable host).
    pub fn preflight(&self) -> anyhow::Result<()> {
        self.auth.validate()?;
        if self.auth.is_configured()
            && !host_is_local(&self.host, self.cleartext_policy.rfc1918_is_local)
            && !self.cleartext_policy.allow_remote_cleartext
        {
            bail!(
                "refusing to send bitcoind RPC credentials in cleartext to the \
                 globally-routable host '{}': the bitcoind connection is plaintext HTTP, so \
                 the credentials would cross the public internet in the clear. Point zecd at \
                 a loopback or private-network bitcoind, tunnel the RPC port over \
                 SSH/WireGuard and use the local end, or set `[backend] \
                 allow_remote_cleartext = true` if the hop is already secured.",
                self.host
            );
        }
        Ok(())
    }

    /// Dial the endpoint: construct the client and verify it with one `getblockchaininfo`
    /// round trip - which also checks the node's chain against the wallet's network, the
    /// bitcoind analog of the zebra backend's network verification (a testnet wallet fed
    /// mainnet blocks would corrupt silently, so a mismatch is refused, not warned).
    ///
    /// Blocking (the underlying client is synchronous); the actor calls it under
    /// `tokio::task::block_in_place`.
    pub fn connect_blocking(&self) -> anyhow::Result<BitcoindRpc> {
        self.preflight()?;
        let url = format!("http://{}:{}", self.host, self.port);
        let client = bitcoincore_rpc::Client::new(&url, self.auth.to_rpc_auth())
            .with_context(|| format!("construct RPC client for {}", self.describe()))?;
        let info = client
            .get_blockchain_info()
            .with_context(|| format!("getblockchaininfo from {}", self.describe()))?;
        let expected = crate::btc::keys::network(self.network);
        if info.chain != expected {
            bail!(
                "{} serves the {} chain but this wallet is a {} wallet - refusing to sync \
                 across networks",
                self.describe(),
                info.chain,
                expected
            );
        }
        Ok(BitcoindRpc {
            client: Arc::new(client),
            tip_at_connect: info.blocks,
        })
    }
}

/// Resolve one bitcoin wallet's upstream endpoint from its entry: the wallet's own `server`
/// token, else the global `[bitcoind] server` default, else the built-in `bitcoind` (a
/// local node on the network-standard port) - the same global-default-with-per-wallet-
/// override shape `[backend] server` gives Zcash wallets. The `[bitcoind]` credentials and
/// the cleartext-locality policy stay global. The bitcoin counterpart of
/// `backend::resolve_for_wallet`, kept here so the shared `backend` module stays free of
/// engine-specific grammar.
pub fn resolve_for_wallet(
    config: &crate::config::AppConfig,
    entry: &crate::config::WalletEntry,
) -> anyhow::Result<BitcoindEndpoint> {
    debug_assert_eq!(entry.coin, crate::coin::Coin::Bitcoin);
    let network = entry.bitcoin_network();
    let token = entry
        .backend
        .server
        .as_deref()
        .or(config.bitcoind.server.as_deref())
        .unwrap_or("bitcoind");
    let (host, port) = resolve(token, network)?;
    Ok(BitcoindEndpoint {
        host,
        port,
        network,
        auth: BitcoindAuth {
            user: config.bitcoind.rpc_user.clone(),
            password: config.bitcoind.rpc_password.clone(),
            cookie: config.bitcoind.rpc_cookie.clone(),
        },
        cleartext_policy: CleartextPolicy {
            rfc1918_is_local: config.backend.rfc1918_is_local,
            allow_remote_cleartext: config.backend.allow_remote_cleartext,
        },
    })
}

/// Parse the bitcoin server token into `(host, port)`. See the module doc for the grammar.
pub fn resolve(token: &str, network: BitcoinNetwork) -> anyhow::Result<(String, u16)> {
    if token == "bitcoind" {
        let port = match network {
            BitcoinNetwork::Main => BITCOIND_RPC_PORT_MAIN,
            BitcoinNetwork::Testnet3 => BITCOIND_RPC_PORT_TESTNET3,
            BitcoinNetwork::Testnet4 => BITCOIND_RPC_PORT_TESTNET4,
            BitcoinNetwork::Regtest => BITCOIND_RPC_PORT_REGTEST,
        };
        return Ok(("127.0.0.1".to_string(), port));
    }
    let Some(rest) = token.strip_prefix("bitcoind://") else {
        // Name the grammar that applies here; a Zcash token on a bitcoin wallet is the likely
        // mistake, so say explicitly that those name Zcash upstreams.
        bail!(
            "invalid server '{token}' for a bitcoin wallet: expected 'bitcoind' (a local \
             bitcoind on the standard port) or 'bitcoind://host:port' (the zebra/lightwalletd \
             tokens name Zcash upstreams)"
        );
    };
    let rest = rest.trim_end_matches('/');
    let (host, port_str) = rest
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("invalid endpoint '{token}', expected bitcoind://host:port"))?;
    if host.is_empty() {
        bail!("invalid endpoint '{token}': empty host");
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow!("invalid port in '{token}'"))?;
    Ok((host.to_string(), port))
}

/// A connected bitcoind: the shared blocking RPC client (the `Arc` is what the emitter holds
/// too) plus what the dial learned. All calls are blocking - callers run under
/// `block_in_place`.
pub struct BitcoindRpc {
    client: Arc<bitcoincore_rpc::Client>,
    /// The node's block height at connect time (progress logging).
    pub tip_at_connect: u64,
}

impl BitcoindRpc {
    /// The shared client, for constructing the block/mempool emitter.
    pub fn client(&self) -> Arc<bitcoincore_rpc::Client> {
        self.client.clone()
    }

    /// Broadcast a transaction; the returned txid is the node's acceptance. An application
    /// rejection (mempool policy, missing inputs) comes back as `Err` with bitcoind's own
    /// message, which the RPC layer maps onto `-26`.
    pub fn broadcast_blocking(&self, tx: &Transaction) -> anyhow::Result<Txid> {
        self.client
            .send_raw_transaction(tx)
            .map_err(|e| anyhow!("{e}"))
    }

    /// The node's smart-fee estimate for confirmation within `target` blocks, as a
    /// `FeeRate`, or `None` when the node has no estimate (fresh regtest chains, thin
    /// mempools). The estimate comes back in BTC/kvB; the ceiling division keeps the
    /// resulting whole-sat/vB rate at or above the node's, never below a min-relay boundary.
    pub fn estimate_fee_rate_blocking(&self, target: u16) -> anyhow::Result<Option<FeeRate>> {
        let res = self
            .client
            .estimate_smart_fee(target, None)
            .map_err(|e| anyhow!("estimatesmartfee: {e}"))?;
        Ok(res.fee_rate.map(|per_kvb| {
            let sat_per_vb = per_kvb.to_sat().div_ceil(1000).max(1);
            FeeRate::from_sat_per_vb_u32(u32::try_from(sat_per_vb).unwrap_or(u32::MAX))
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_token_resolves_to_the_network_standard_port() {
        for (network, port) in [
            (BitcoinNetwork::Main, BITCOIND_RPC_PORT_MAIN),
            (BitcoinNetwork::Testnet3, BITCOIND_RPC_PORT_TESTNET3),
            (BitcoinNetwork::Testnet4, BITCOIND_RPC_PORT_TESTNET4),
            (BitcoinNetwork::Regtest, BITCOIND_RPC_PORT_REGTEST),
        ] {
            let (host, resolved) = resolve("bitcoind", network).unwrap();
            assert_eq!(host, "127.0.0.1");
            assert_eq!(resolved, port);
        }
    }

    #[test]
    fn explicit_endpoints_parse_and_bad_tokens_name_the_grammar() {
        let (host, port) = resolve("bitcoind://10.0.0.5:18443", BitcoinNetwork::Regtest).unwrap();
        assert_eq!(host, "10.0.0.5");
        assert_eq!(port, 18443);
        // A trailing slash is tolerated, like the Zcash grammar.
        let (host, port) = resolve("bitcoind://node:8332/", BitcoinNetwork::Main).unwrap();
        assert_eq!((host.as_str(), port), ("node", 8332));

        // The Zcash tokens are the likely mistake; the error must say which grammar applies.
        for bad in ["zebra", "zecrocks", "https://x.example", "zebra://h:1"] {
            let err = resolve(bad, BitcoinNetwork::Main).unwrap_err().to_string();
            assert!(err.contains("bitcoind"), "{bad}: {err}");
            assert!(err.contains("Zcash upstreams"), "{bad}: {err}");
        }
        for bad in ["bitcoind://", "bitcoind://:8332", "bitcoind://h:notaport"] {
            assert!(resolve(bad, BitcoinNetwork::Main).is_err(), "{bad}");
        }
        // No port on the explicit form is an error (there is no https-style default here).
        assert!(resolve("bitcoind://host", BitcoinNetwork::Main).is_err());
    }

    /// The endpoint precedence: a wallet's own `server` wins, else the global
    /// `[bitcoind] server`, else the built-in `bitcoind` default - resolved through the
    /// real config path so the fallback chain is the one the daemon and `config check` use.
    #[cfg(feature = "cli")]
    #[test]
    fn wallet_server_overrides_the_global_bitcoind_default() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("zecd.toml");
        std::fs::write(
            &conf,
            "network = \"regtest\"\ndatadir = \"/d\"\n\
             [bitcoind]\nserver = \"bitcoind://10.0.0.9:1234\"\n\
             [wallets.global_default]\ncoin = \"bitcoin\"\n\
             [wallets.overridden]\ncoin = \"bitcoin\"\nserver = \"bitcoind://10.0.0.7:4321\"\n",
        )
        .unwrap();
        let cli = crate::config::Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let config = crate::config::AppConfig::resolve(&cli).unwrap();
        let global = resolve_for_wallet(&config, &config.wallets["global_default"]).unwrap();
        assert_eq!(global.describe(), "bitcoind 10.0.0.9:1234");
        let own = resolve_for_wallet(&config, &config.wallets["overridden"]).unwrap();
        assert_eq!(own.describe(), "bitcoind 10.0.0.7:4321");

        // With no [bitcoind] server, the built-in default is a local node on the
        // network-standard port (regtest here).
        std::fs::write(
            &conf,
            "network = \"regtest\"\ndatadir = \"/d\"\n[wallets.btc]\ncoin = \"bitcoin\"\n",
        )
        .unwrap();
        let cli = crate::config::Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let config = crate::config::AppConfig::resolve(&cli).unwrap();
        let builtin = resolve_for_wallet(&config, &config.wallets["btc"]).unwrap();
        assert_eq!(builtin.describe(), "bitcoind 127.0.0.1:18443");
    }

    #[test]
    fn auth_validation_mirrors_the_zebra_rules() {
        assert!(BitcoindAuth::default().validate().is_ok());
        assert!(!BitcoindAuth::default().is_configured());
        let half = BitcoindAuth {
            user: Some("u".into()),
            ..Default::default()
        };
        assert!(half.validate().is_err());
        assert!(half.is_configured());
        // A cookie supersedes the pair, so a half-set pair beside it is fine.
        let cookie = BitcoindAuth {
            user: Some("u".into()),
            password: None,
            cookie: Some("/tmp/cookie".into()),
        };
        assert!(cookie.validate().is_ok());
    }

    fn endpoint(host: &str, auth: BitcoindAuth, policy: CleartextPolicy) -> BitcoindEndpoint {
        BitcoindEndpoint {
            host: host.to_string(),
            port: 18443,
            network: BitcoinNetwork::Regtest,
            auth,
            cleartext_policy: policy,
        }
    }

    #[test]
    fn preflight_gates_credentialed_cleartext_by_locality() {
        let creds = BitcoindAuth {
            user: Some("u".into()),
            password: Some("p".into()),
            cookie: None,
        };
        let policy = CleartextPolicy::default();
        // Loopback and (by default) private-network hosts pass.
        assert!(endpoint("127.0.0.1", creds.clone(), policy)
            .preflight()
            .is_ok());
        assert!(endpoint("10.1.2.3", creds.clone(), policy)
            .preflight()
            .is_ok());
        // A globally-routable host with credentials is refused...
        let err = endpoint("203.0.113.9", creds.clone(), policy)
            .preflight()
            .unwrap_err()
            .to_string();
        assert!(err.contains("cleartext"), "{err}");
        // ...unless explicitly allowed, and always without credentials (chain data is public).
        let open = CleartextPolicy {
            allow_remote_cleartext: true,
            ..policy
        };
        assert!(endpoint("203.0.113.9", creds, open).preflight().is_ok());
        assert!(endpoint("203.0.113.9", BitcoindAuth::default(), policy)
            .preflight()
            .is_ok());
        // The strict posture excludes private ranges too.
        let strict = CleartextPolicy {
            rfc1918_is_local: false,
            ..policy
        };
        let creds = BitcoindAuth {
            user: Some("u".into()),
            password: Some("p".into()),
            cookie: None,
        };
        assert!(endpoint("10.1.2.3", creds, strict).preflight().is_err());
    }
}
