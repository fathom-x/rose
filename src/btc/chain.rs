//! The BDK engine's chain access: resolving a Bitcoin wallet's upstream endpoint and dialing
//! bitcoind's JSON-RPC.
//!
//! Two backends live behind [`BtcEndpoint`], the enum seam the Zcash side's
//! `chain::AnySource` models:
//!
//!  * **A local bitcoind** ("full mode", the analog of `zebra://`): plaintext HTTP JSON-RPC,
//!    local-only by the same cleartext-credential policy the zebra backend enforces, with
//!    block/mempool emission handled by `bdk_bitcoind_rpc`'s checkpoint-anchored
//!    [`Emitter`](bdk_bitcoind_rpc::Emitter) (driven by the actor).
//!  * **Kyoto**, a BIP-157/158 compact-block-filter light client ([`crate::btc::kyoto`]) - the
//!    privacy analog of the Zcash light mode, peering over P2P with no server and no
//!    credentials at all. It carries no mempool and no fee estimator; that module's doc has
//!    the full divergence list.
//!
//! Token grammar (`[wallets.<name>] server` on a bitcoin wallet):
//!  * `bitcoind` - the default: a local bitcoind at `127.0.0.1` on the network's standard RPC
//!    port (8332 main / 18332 test / 18443 regtest).
//!  * `bitcoind://host:port` - an explicit bitcoind JSON-RPC endpoint (plaintext HTTP,
//!    local-only by policy - the same gate as `zebra://`).
//!  * `kyoto` - the light client, finding peers through the network's DNS seeds. The
//!    credential-free counterpart of `zecrocks`, and like it, meaningless on regtest (no
//!    seeds), where it is refused naming the explicit form.
//!  * `kyoto://host:port` - the light client pinned to a trusted peer, which must be an IP
//!    address (a P2P address, not a DNS name) serving compact filters. Naming peers switches
//!    the node to whitelist-only, so discovery does not silently top up an operator's chosen
//!    set. A comma-separated list (`kyoto://10.0.0.1:8333,10.0.0.2:8333`) names several, any
//!    one of which keeps the wallet syncing - an operator's own replicas as failover.
//!
//! The Zcash tokens (`zebra`, `zecrocks`, `https://...`) are refused here by construction: a
//! bitcoin wallet cannot dial a Zcash upstream, and the error says which grammar applies.
//! Credentials ride the global `[bitcoind]` section (`rpc_user`/`rpc_password`/`rpc_cookie`),
//! mirroring `[zebra]` - a cookie file wins over the pair, and nothing set means no auth
//! (bitcoind always mints a cookie, so an explicit `rpc_cookie` path is the usual answer).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _};
use bdk_bitcoind_rpc::bitcoincore_rpc::{self, RpcApi as _};
use bdk_wallet::bitcoin::{FeeRate, Transaction, Txid};

use crate::backend::{host_is_local, CleartextPolicy};
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
/// that need no network (`preflight`), which is what `rose config check` reports from.
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
                 the credentials would cross the public internet in the clear. Point rose at \
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
    /// `tokio::task::block_in_place`. Every request the client makes carries
    /// [`RPC_DEADLINE`] as its socket deadline - the only thing that can notice a node that
    /// *hangs* without dying (a stopped process's sockets stay open and keep accepting), and
    /// what bounds how long one sync pass can park the actor's command loop.
    pub fn connect_blocking(&self) -> anyhow::Result<BitcoindRpc> {
        self.preflight()?;
        let url = format!("http://{}:{}", self.host, self.port);
        let (user, password) = self
            .auth
            .to_rpc_auth()
            .get_user_pass()
            .with_context(|| format!("read credentials for {}", self.describe()))?;
        let mut transport = bitcoincore_rpc::jsonrpc::simple_http::Builder::new()
            .url(&url)
            .with_context(|| format!("construct RPC client for {}", self.describe()))?
            .timeout(RPC_DEADLINE);
        if let Some(user) = user {
            transport = transport.auth(user, password);
        }
        let client = bitcoincore_rpc::Client::from_jsonrpc(
            bitcoincore_rpc::jsonrpc::Client::with_transport(transport.build()),
        );
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

/// The per-request socket deadline on the bitcoind JSON-RPC connection (read and write).
/// Explicit rather than the transport crate's default so a dependency bump cannot silently
/// remove it: without a deadline a hung node parks the actor's sync pass forever, and with
/// it the pass fails, the connection is dropped, and the reconnect loop takes over (each
/// attempt bounded the same way). The transport retries a request once on a fresh socket
/// when the first attempt's socket breaks, so the worst case for one hung request - and
/// for how long one sync pass can park the actor's command loop - is **twice** this
/// (`regtest_btc_hang.rs` measures it). Comfortably above a `getblock` of a full mainnet
/// block over loopback; in line with the Zcash backend's per-RPC deadline.
pub const RPC_DEADLINE: Duration = Duration::from_secs(15);

/// A resolved bitcoin upstream, in either dialect. The engine's counterpart of the Zcash
/// side's [`crate::chain::AnySource`]: the two backends share nothing but this seam, because
/// they differ in shape as much as in protocol - a blocking pull against an authenticated
/// local RPC versus an async push from a credential-free P2P node.
#[derive(Clone, Debug)]
pub enum BtcEndpoint {
    Bitcoind(BitcoindEndpoint),
    Kyoto(crate::btc::kyoto::KyotoEndpoint),
}

impl BtcEndpoint {
    pub fn describe(&self) -> String {
        match self {
            BtcEndpoint::Bitcoind(e) => e.describe(),
            BtcEndpoint::Kyoto(e) => e.describe(),
        }
    }

    /// The configuration-only checks a connect would fail on, shared with `rose config check`
    /// so both dialects report their unreachable-by-construction cases offline.
    pub fn preflight(&self) -> anyhow::Result<()> {
        match self {
            BtcEndpoint::Bitcoind(e) => e.preflight(),
            BtcEndpoint::Kyoto(e) => e.preflight(),
        }
    }
}

/// Whether a server token names the kyoto backend. Kept separate from [`resolve`] so the
/// caller decides which endpoint to build without parsing the token twice.
fn is_kyoto_token(token: &str) -> bool {
    token == "kyoto" || token.starts_with("kyoto://")
}

/// Parse a kyoto token into its trusted-peer list (empty for the bare `kyoto`).
///
/// A peer must be an IP address: this is a P2P address that goes into the node's peer book,
/// not a URL host, and kyoto's own address type is `AddrV2`. The port is optional, defaulting
/// to the network's standard P2P port inside kyoto. An IPv6 literal with a port must be
/// bracketed (`kyoto://[2001:db8::1]:8333`): an unbracketed multi-colon string is taken
/// whole as the address, since `2001:db8::1:8333` is itself a valid IPv6 address and
/// guessing a port out of it would silently whitelist a different peer.
///
/// Several peers are comma-separated (`kyoto://10.0.0.1:8333,10.0.0.2:8333`), in the order
/// written. The list is a failover set, not a quorum: the endpoint requires one connection
/// from it (see [`KyotoEndpoint::new`](crate::btc::kyoto::KyotoEndpoint::new)), so a named
/// replica being down costs nothing while another answers. A repeated address is refused
/// rather than deduplicated - it is a copy-paste slip that would otherwise silently leave
/// the operator with one peer where they believe they have two.
pub fn resolve_kyoto_peers(token: &str) -> anyhow::Result<Vec<(std::net::IpAddr, Option<u16>)>> {
    if token == "kyoto" {
        return Ok(Vec::new());
    }
    let rest = token
        .strip_prefix("kyoto://")
        .ok_or_else(|| anyhow!("invalid kyoto endpoint '{token}'"))?
        .trim_end_matches('/');
    if rest.is_empty() {
        bail!("invalid endpoint '{token}': empty peer address");
    }
    let mut peers = Vec::new();
    for item in rest.split(',') {
        let item = item.trim();
        if item.is_empty() {
            bail!("invalid endpoint '{token}': empty peer address in the list");
        }
        let peer = parse_kyoto_peer(item, token)?;
        if peers.contains(&peer) {
            bail!(
                "invalid endpoint '{token}': peer '{item}' is listed twice (each replica \
                 once; the list is a failover set)"
            );
        }
        peers.push(peer);
    }
    Ok(peers)
}

/// One `host[:port]` item of a kyoto token, with `token` naming the whole for error messages.
fn parse_kyoto_peer(rest: &str, token: &str) -> anyhow::Result<(std::net::IpAddr, Option<u16>)> {
    // Split off the optional `:port`. Count the colons first: an unbracketed IPv6 literal
    // is all address, and only a bracketed one can carry a port.
    let (host, port) = if let Some(bracketed) = rest.strip_prefix('[') {
        match bracketed.split_once(']') {
            Some((h, "")) => (h, None),
            Some((h, p)) => match p.strip_prefix(':') {
                Some(p) => (h, Some(p)),
                None => bail!("invalid endpoint '{token}': expected ':port' after ']'"),
            },
            None => bail!("invalid endpoint '{token}': unclosed '['"),
        }
    } else if rest.matches(':').count() > 1 {
        (rest, None)
    } else {
        match rest.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        }
    };
    let ip: std::net::IpAddr = host.parse().map_err(|_| {
        anyhow!(
            "invalid kyoto peer '{host}' in '{token}': a kyoto peer is a P2P address, so it \
             must be an IP address rather than a DNS name (resolve it yourself, or use the \
             bare 'kyoto' token to discover peers through the network's DNS seeds)"
        )
    })?;
    let port = match port {
        Some(p) => Some(
            p.parse::<u16>()
                .map_err(|_| anyhow!("invalid port in '{token}'"))?,
        ),
        None => None,
    };
    Ok((ip, port))
}

/// Validate a server token in either dialect and describe what it resolves to, for
/// `config check` and `config show` - which see tokens (including the global
/// `[bitcoind] server` default) with no wallet to build an endpoint against.
pub fn describe_token(token: &str, network: BitcoinNetwork) -> anyhow::Result<String> {
    if is_kyoto_token(token) {
        let peers = resolve_kyoto_peers(token)?;
        return Ok(crate::btc::kyoto::describe_peers(&peers));
    }
    let (host, port) = resolve(token, network)?;
    Ok(format!("bitcoind {host}:{port}"))
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
) -> anyhow::Result<BtcEndpoint> {
    debug_assert_eq!(entry.coin, crate::coin::Coin::Bitcoin);
    let network = entry.bitcoin_network();
    let token = entry
        .backend
        .server
        .as_deref()
        .or(config.bitcoind.server.as_deref())
        .unwrap_or("bitcoind");
    // The light client carries no credentials and no cleartext gate, so it shares none of the
    // bitcoind branch's endpoint state - only the wallet's own directory, for its header store.
    if is_kyoto_token(token) {
        let peers = resolve_kyoto_peers(token)?;
        let data_dir = crate::config::btc_kyoto_dir(&entry.dir);
        return Ok(BtcEndpoint::Kyoto(
            crate::btc::kyoto::KyotoEndpoint::new(network, peers, data_dir)
                .with_receive_window(config.backend.p2p_receive_window_bytes),
        ));
    }
    let (host, port) = resolve(token, network)?;
    Ok(BtcEndpoint::Bitcoind(BitcoindEndpoint {
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
    }))
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
             bitcoind on the standard port), 'bitcoind://host:port', 'kyoto' (the BIP-157 \
             light client, peers from the network's DNS seeds) or 'kyoto://ip:port' (the \
             light client pinned to a trusted peer; several comma-separated as failover) - \
             the zebra/lightwalletd tokens name Zcash upstreams"
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

/// A broadcast failure, split the way the caller must answer it.
///
/// A **rejection** means the node received the transaction and refused it: retrying the
/// same bytes cannot succeed, and the node's own verify-family error code and message are
/// the caller's answer (`-25` missing inputs, `-26` policy, `-27` already known - the same
/// vocabulary rose speaks, so they pass through). A **transport** failure means no verdict
/// was obtained at all: the transaction may or may not have reached the node, retrying is
/// the right move once the upstream is reachable, and a bitcoind connection is dropped for
/// redial per the `Conn` convention.
#[derive(Debug)]
pub enum BroadcastError {
    Rejected { code: i32, message: String },
    Transport(anyhow::Error),
}

/// Classify a `bitcoincore-rpc` failure: only `JsonRpc(Rpc(_))` is the node itself
/// answering with an application error - every other variant (I/O, HTTP, serde, local
/// validation) is a failure to get a verdict.
fn classify_broadcast_error(e: bitcoincore_rpc::Error) -> BroadcastError {
    match e {
        bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::Error::Rpc(rpc)) => {
            BroadcastError::Rejected {
                code: rpc.code,
                message: rpc.message,
            }
        }
        other => BroadcastError::Transport(anyhow!("{other}")),
    }
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

    /// Broadcast a transaction; the returned txid is the node's acceptance. Failures come
    /// back classified as [`BroadcastError`]: an application rejection (mempool policy,
    /// missing inputs) with bitcoind's own code and message, a transport failure as the
    /// retry-shaped variant.
    pub fn broadcast_blocking(&self, tx: &Transaction) -> Result<Txid, BroadcastError> {
        self.client
            .send_raw_transaction(tx)
            .map_err(classify_broadcast_error)
    }

    /// The block hash at `height`, for `init`'s birthday anchor (the resolved
    /// `(height, hash)` pair a kyoto first scan can start from - see
    /// `btc::store::Persister::save_birthday_anchor`).
    pub fn block_hash_blocking(&self, height: u32) -> anyhow::Result<String> {
        Ok(self
            .client
            .get_block_hash(u64::from(height))
            .map_err(|e| anyhow!("getblockhash {height}: {e}"))?
            .to_string())
    }

    /// The header time at `height`, for `init`'s date-birthday binary search - two cheap
    /// calls (`getblockhash` + `getblockheader`), never a block fetch.
    pub fn block_time_blocking(&self, height: u32) -> anyhow::Result<u64> {
        let hash = self
            .client
            .get_block_hash(u64::from(height))
            .map_err(|e| anyhow!("getblockhash {height}: {e}"))?;
        let header = self
            .client
            .get_block_header_info(&hash)
            .map_err(|e| anyhow!("getblockheader {hash}: {e}"))?;
        Ok(u64::try_from(header.time).unwrap_or(u64::MAX))
    }

    /// The node's smart-fee estimate for confirmation within `target` blocks, as a
    /// `FeeRate`, or `None` when the node has no estimate (fresh regtest chains, thin
    /// mempools). The estimate comes back in BTC/kvB; the ceiling division keeps the
    /// resulting whole-sat/vB rate at or above the node's, never below a min-relay boundary.
    pub fn estimate_fee_rate_blocking(
        &self,
        target: u16,
        conservative: Option<bool>,
    ) -> anyhow::Result<Option<FeeRate>> {
        let mode = conservative.map(|conservative| {
            if conservative {
                bitcoincore_rpc::json::EstimateMode::Conservative
            } else {
                bitcoincore_rpc::json::EstimateMode::Economical
            }
        });
        let res = self
            .client
            .estimate_smart_fee(target, mode)
            .map_err(|e| anyhow!("estimatesmartfee: {e}"))?;
        Ok(res.fee_rate.map(|per_kvb| {
            let sat_per_vb = per_kvb.to_sat().div_ceil(1000).max(1);
            FeeRate::from_sat_per_vb_u32(u32::try_from(sat_per_vb).unwrap_or(u32::MAX))
        }))
    }
}

/// The short and long ends of the curve [`fee_curve_is_flat`] reads: Core's fastest
/// target and its longest.
pub const FEE_CURVE_SHORT_TARGET: u16 = 2;
pub const FEE_CURVE_LONG_TARGET: u16 = 1008;

/// How close, in percent, the long-horizon estimate may come to the short one before the
/// curve counts as flat.
const FEE_CURVE_FLAT_PERCENT: u64 = 90;

/// Whether a node's fee-estimate curve is flat above the relay floor: its 1008-block
/// estimate at least [`FEE_CURVE_FLAT_PERCENT`] of its 2-block one, and the 2-block one
/// above 1 sat/vB. A working estimator prices the long horizon well below the short one
/// unless both sit at the floor; a curve flat at hundreds of sat/vB is an estimator with no
/// usable data. Testnet4's min-difficulty blocks do exactly this: sparse, contested blocks
/// carrying fee-bidding spam gave 361 sat/vB at every target while blocks cleared at 1.
/// The caller treats it as "no estimate" on test networks only.
pub fn fee_curve_is_flat(short: FeeRate, long: FeeRate) -> bool {
    short > FeeRate::from_sat_per_vb_u32(1)
        && long.to_sat_per_kwu() * 100 >= short.to_sat_per_kwu() * FEE_CURVE_FLAT_PERCENT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flat_curve_above_the_floor_is_no_estimate() {
        let vb = FeeRate::from_sat_per_vb_u32;
        // Testnet4's broken estimator: the same rate at every target.
        assert!(fee_curve_is_flat(vb(361), vb(361)));
        assert!(fee_curve_is_flat(vb(361), vb(330)));
        // A working curve slopes down to the long horizon.
        assert!(!fee_curve_is_flat(vb(40), vb(8)));
        assert!(!fee_curve_is_flat(vb(12), vb(10)));
        // Flat at the floor is a quiet market, and the fallback would say the same.
        assert!(!fee_curve_is_flat(vb(1), vb(1)));
    }

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
    fn kyoto_tokens_resolve_to_a_trusted_peer_list() {
        // The bare token means DNS-seed discovery: no peers pinned.
        assert!(resolve_kyoto_peers("kyoto").unwrap().is_empty());

        let peers = resolve_kyoto_peers("kyoto://192.0.2.7:8333").unwrap();
        assert_eq!(peers, vec![("192.0.2.7".parse().unwrap(), Some(8333))]);

        // The port is optional - kyoto substitutes the network's standard P2P port.
        let peers = resolve_kyoto_peers("kyoto://192.0.2.7").unwrap();
        assert_eq!(peers, vec![("192.0.2.7".parse().unwrap(), None)]);

        // A trailing slash is tolerated, like the bitcoind grammar.
        assert_eq!(
            resolve_kyoto_peers("kyoto://192.0.2.7:8333/").unwrap(),
            vec![("192.0.2.7".parse().unwrap(), Some(8333))]
        );
    }

    #[test]
    fn a_comma_separated_token_names_several_peers_in_order() {
        // Two replicas of one operator's node: either alone keeps the wallet syncing.
        let peers = resolve_kyoto_peers("kyoto://192.0.2.7:8333,192.0.2.8:8333").unwrap();
        assert_eq!(
            peers,
            vec![
                ("192.0.2.7".parse().unwrap(), Some(8333)),
                ("192.0.2.8".parse().unwrap(), Some(8333)),
            ]
        );
        // Whitespace around the commas and a per-item port are both tolerated; bracketed
        // IPv6 items keep their own port split.
        let peers =
            resolve_kyoto_peers("kyoto://192.0.2.7, [2001:db8::1]:8333 ,192.0.2.9:1/").unwrap();
        assert_eq!(
            peers,
            vec![
                ("192.0.2.7".parse().unwrap(), None),
                ("2001:db8::1".parse().unwrap(), Some(8333)),
                ("192.0.2.9".parse().unwrap(), Some(1)),
            ]
        );
        // An empty item is a typo, not an implicit DNS-seed fallback.
        for bad in [
            "kyoto://192.0.2.7,",
            "kyoto://,192.0.2.7",
            "kyoto://192.0.2.7,,192.0.2.8",
        ] {
            assert!(resolve_kyoto_peers(bad).is_err(), "{bad}");
        }
        // A repeated peer is refused: the operator believes they named two.
        let err = resolve_kyoto_peers("kyoto://192.0.2.7:8333,192.0.2.7:8333").unwrap_err();
        assert!(err.to_string().contains("listed twice"), "{err}");
        // One bad item fails the whole token, naming the grammar.
        assert!(resolve_kyoto_peers("kyoto://192.0.2.7,node.example:8333").is_err());
    }

    #[test]
    fn an_ipv6_peer_survives_the_port_split() {
        // The naive rsplit_once(':') would shred an IPv6 literal; bracketed form carries a
        // port, bare form does not.
        let peers = resolve_kyoto_peers("kyoto://[2001:db8::1]:8333").unwrap();
        assert_eq!(peers, vec![("2001:db8::1".parse().unwrap(), Some(8333))]);
        let peers = resolve_kyoto_peers("kyoto://2001:db8::1").unwrap();
        assert_eq!(peers, vec![("2001:db8::1".parse().unwrap(), None)]);
        // Brackets without a port are legal - the port is documented optional, and this
        // form used to be refused with a misleading "invalid port" error.
        let peers = resolve_kyoto_peers("kyoto://[2001:db8::1]").unwrap();
        assert_eq!(peers, vec![("2001:db8::1".parse().unwrap(), None)]);
        // An unbracketed multi-colon string is all address, never address-plus-port:
        // "2001:db8::1:8333" IS a valid IPv6 address, so guessing a port out of it would
        // silently whitelist a different peer. A port needs brackets.
        let peers = resolve_kyoto_peers("kyoto://2001:db8::1:8333").unwrap();
        assert_eq!(peers, vec![("2001:db8::1:8333".parse().unwrap(), None)]);
        // Bracket syntax errors are named, not shredded.
        for bad in ["kyoto://[2001:db8::1", "kyoto://[2001:db8::1]8333"] {
            assert!(resolve_kyoto_peers(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_dns_name_peer_is_refused_naming_why() {
        // A P2P peer goes into an address book as an `AddrV2`, so a hostname cannot be one;
        // the error has to say that rather than looking like a typo.
        let err = resolve_kyoto_peers("kyoto://node.example.com:8333")
            .unwrap_err()
            .to_string();
        assert!(err.contains("IP address"), "{err}");
        assert!(err.contains("DNS seeds"), "{err}");
        for bad in ["kyoto://", "kyoto://192.0.2.7:notaport"] {
            assert!(resolve_kyoto_peers(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn describe_token_covers_both_dialects() {
        assert_eq!(
            describe_token("bitcoind", BitcoinNetwork::Main).unwrap(),
            "bitcoind 127.0.0.1:8332"
        );
        assert!(describe_token("kyoto", BitcoinNetwork::Main)
            .unwrap()
            .contains("dns-seeded"));
        assert!(
            describe_token("kyoto://192.0.2.7:8333", BitcoinNetwork::Main)
                .unwrap()
                .contains("192.0.2.7:8333")
        );
        // A list names every peer, so `config check` shows exactly what will be dialed.
        let listed =
            describe_token("kyoto://192.0.2.7:8333,192.0.2.8", BitcoinNetwork::Main).unwrap();
        assert!(
            listed.contains("192.0.2.7:8333") && listed.contains("192.0.2.8"),
            "{listed}"
        );
        assert!(describe_token("nonsense", BitcoinNetwork::Main).is_err());
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
            // Both backends must be discoverable from the refusal, not just the default one.
            assert!(err.contains("kyoto"), "{bad}: {err}");
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
        let conf = dir.path().join("rose.toml");
        std::fs::write(
            &conf,
            "network = \"regtest\"\ndatadir = \"/d\"\n\
             [bitcoind]\nserver = \"bitcoind://10.0.0.9:1234\"\n\
             [wallets.global_default]\ncoin = \"bitcoin\"\n\
             [wallets.overridden]\ncoin = \"bitcoin\"\nserver = \"bitcoind://10.0.0.7:4321\"\n",
        )
        .unwrap();
        let cli = crate::config::Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
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
        let cli = crate::config::Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
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

    /// The rejection/transport split: only the node itself answering an application error
    /// classifies as a rejection (with its own code and message passed through); every
    /// failure to obtain a verdict - I/O here, but any non-`Rpc` variant - is transport.
    #[test]
    fn broadcast_errors_classify_rejection_vs_transport() {
        let rejected = classify_broadcast_error(bitcoincore_rpc::Error::JsonRpc(
            bitcoincore_rpc::jsonrpc::Error::Rpc(bitcoincore_rpc::jsonrpc::error::RpcError {
                code: -27,
                message: "Transaction outputs already in utxo set".to_string(),
                data: None,
            }),
        ));
        match rejected {
            BroadcastError::Rejected { code, message } => {
                assert_eq!(code, -27);
                assert!(message.contains("already in utxo set"), "{message}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        let transport = classify_broadcast_error(bitcoincore_rpc::Error::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionRefused,
        )));
        assert!(
            matches!(transport, BroadcastError::Transport(_)),
            "{transport:?}"
        );
    }
}
