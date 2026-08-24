//! The RPC methods served for Bitcoin wallets - the handler half of the second sanctioned
//! engine seam (the registry being the first; see the shared-layer boundary in the project docs).
//!
//! [`dispatch`] is a sub-table consulted by `dispatch_zecd` when the addressed wallet is a
//! Bitcoin one: `Some` for the methods the BDK engine serves (which must be exactly the
//! methods `METHOD_COINS` lists for [`crate::coin::Coin::Bitcoin`] - the
//! `bitcoin_slice_matches_method_coins` test pins the two together), `None` to fall through
//! to the shared table (the wallet-independent shell). Everything here speaks the same wire
//! shapes as the Zcash handlers: bare 8-decimal JSON amounts, Bitcoin Core field names, the
//! same error codes.
//!
//! Phase-1 scope: address issuance and the wallet-shaped reads. The engine has no chain
//! source yet, so balances and UTXOs reflect only the local database (zero on a fresh
//! wallet) and nothing reports confirmations above 0.

use serde_json::{json, Value};

use crate::amount::zats_to_value;
use crate::btc::actor::BtcWalletHandle;
use crate::coin::BitcoinNetwork;
use crate::error::RpcError;
use crate::server::jsonrpc::RpcRequest;

/// The methods this module serves, in dispatch order - the data the lockstep test compares
/// against `METHOD_COINS`. Test-only: the live routing is [`dispatch`]'s match, and this
/// list exists to pin that match against the gate.
#[cfg(test)]
pub(crate) const BITCOIN_METHODS: &[&str] = &[
    "getnewaddress",
    "getbalance",
    "getbalances",
    "getunconfirmedbalance",
    "getwalletinfo",
    "listunspent",
    "getaddressinfo",
    "validateaddress",
];

/// Route one request for a Bitcoin wallet. `None` = not a method this engine serves
/// (dispatch falls through to the shared, wallet-independent table; the `METHOD_COINS` gate
/// has already answered -32601 for everything else).
pub(crate) async fn dispatch(
    handle: &BtcWalletHandle,
    req: &RpcRequest,
) -> Option<Result<Value, RpcError>> {
    Some(match req.method.as_str() {
        "getnewaddress" => getnewaddress(handle, req).await,
        "getbalance" => getbalance(handle, req).await,
        "getbalances" => getbalances(handle).await,
        "getunconfirmedbalance" => getunconfirmedbalance(handle).await,
        "getwalletinfo" => getwalletinfo(handle).await,
        "listunspent" => listunspent(handle).await,
        "getaddressinfo" => getaddressinfo(handle, req).await,
        "validateaddress" => validateaddress(handle, req).await,
        _ => return None,
    })
}

fn opt_str(req: &RpcRequest, i: usize) -> Option<String> {
    req.param(i).and_then(|v| v.as_str()).map(|s| s.to_string())
}

async fn getnewaddress(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    // Same statelessness rule as the Zcash handler: no labels, ever.
    if opt_str(req, 0).is_some_and(|s| !s.is_empty()) {
        return Err(RpcError::invalid_parameter(
            "labels are not supported (zecd is stateless); call getnewaddress without a label",
        ));
    }
    // The engine derives BIP 84 native segwit; that is the only address type it can issue.
    if let Some(kind) = opt_str(req, 1)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        if !kind.eq_ignore_ascii_case("bech32") {
            return Err(RpcError::invalid_parameter(format!(
                "address type {kind:?} is not supported for a Bitcoin wallet (bech32 only)"
            )));
        }
    }
    let addr = handle.new_address().await?;
    Ok(Value::String(addr))
}

async fn getbalance(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    // Bitcoin Core's first parameter is the legacy dummy account ("*" or omitted).
    if let Some(dummy) = opt_str(req, 0) {
        if !dummy.is_empty() && dummy != "*" {
            return Err(RpcError::invalid_parameter(
                "dummy first argument must be \"*\" or omitted (accounts are not supported)",
            ));
        }
    }
    let minconf = match req.param(1) {
        None | Some(Value::Null) => 0,
        Some(v) => v
            .as_u64()
            .ok_or_else(|| RpcError::invalid_parameter("minconf must be a non-negative integer"))?,
    };
    let b = handle.balance().await?;
    // Core's "total available": trusted funds, plus untrusted pending only at minconf 0.
    let mut sats = b.confirmed + b.trusted_pending;
    if minconf == 0 {
        sats += b.untrusted_pending;
    }
    Ok(zats_to_value(sats))
}

async fn getbalances(handle: &BtcWalletHandle) -> Result<Value, RpcError> {
    let b = handle.balance().await?;
    Ok(json!({
        "mine": {
            "trusted": zats_to_value(b.confirmed + b.trusted_pending),
            "untrusted_pending": zats_to_value(b.untrusted_pending),
            "immature": zats_to_value(b.immature),
        },
    }))
}

async fn getunconfirmedbalance(handle: &BtcWalletHandle) -> Result<Value, RpcError> {
    let b = handle.balance().await?;
    Ok(zats_to_value(b.untrusted_pending))
}

async fn getwalletinfo(handle: &BtcWalletHandle) -> Result<Value, RpcError> {
    let b = handle.balance().await?;
    Ok(json!({
        "walletname": handle.name,
        "walletversion": 169900,
        "format": "sqlite",
        "balance": zats_to_value(b.confirmed + b.trusted_pending),
        "unconfirmed_balance": zats_to_value(b.untrusted_pending),
        "immature_balance": zats_to_value(b.immature),
        "keypoolsize": 1,
        "keypoolsize_hd_internal": 0,
        "paytxfee": zats_to_value(0),
        "private_keys_enabled": handle.has_seed,
        "avoid_reuse": false,
        // No chain source yet, so there is no scan to report progress on.
        "scanning": false,
        // zecd extension: which engine serves this wallet. The Zcash handler reports its own
        // extensions (pools, transparent) here; `coin` is the field a mixed-coin deployment
        // tells wallets apart by.
        "coin": "bitcoin",
    }))
}

async fn listunspent(handle: &BtcWalletHandle) -> Result<Value, RpcError> {
    let utxos = handle.list_unspent().await?;
    let entries: Vec<Value> = utxos
        .into_iter()
        .map(|u| {
            let mut obj = json!({
                "txid": u.txid,
                "vout": u.vout,
                "amount": zats_to_value(u.amount_sat),
                // The engine tracks no chain tip yet, so nothing can report depth.
                "confirmations": 0,
                "spendable": handle.has_seed,
                "solvable": true,
                "safe": false,
            });
            if let Some(address) = u.address {
                obj["address"] = Value::String(address);
            }
            obj
        })
        .collect();
    Ok(Value::Array(entries))
}

async fn getaddressinfo(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    let Some(address) = opt_str(req, 0) else {
        return Err(RpcError::invalid_parameter("address is required"));
    };
    let info = handle.address_info(address.clone()).await?;
    let mut obj = json!({
        "address": address,
        "ismine": info.is_mine,
        // Matches the Zcash handler (and Core master): per-address watch-only died with
        // legacy wallets; the wallet-level flag is the signal.
        "iswatchonly": false,
        "solvable": info.is_mine,
        "ischange": info.derivation.is_some_and(|(change, _)| change),
    });
    if let Some((change, index)) = info.derivation {
        let coin_type = match handle.network {
            BitcoinNetwork::Main => 0,
            BitcoinNetwork::Test | BitcoinNetwork::Regtest => 1,
        };
        obj["hdkeypath"] = Value::String(format!(
            "m/84'/{coin_type}'/0'/{}/{index}",
            if change { 1 } else { 0 }
        ));
        // The same zecd extension the Zcash handler exposes for transparent addresses: the
        // child index, so an operator can reconcile issued ranges without parsing the path.
        obj["address_index"] = json!(index);
    }
    Ok(obj)
}

async fn validateaddress(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    let Some(address) = opt_str(req, 0) else {
        return Err(RpcError::invalid_parameter("address is required"));
    };
    // The actor's parse enforces the wallet's own network, exactly what validateaddress
    // answers; a parse failure is `isvalid: false`, never an error (Bitcoin Core's contract).
    match handle.address_info(address.clone()).await {
        Ok(_) => Ok(json!({ "isvalid": true, "address": address })),
        Err(_) => Ok(json!({ "isvalid": false })),
    }
}

#[cfg(test)]
mod tests {
    /// Every method this module serves is exactly a method `METHOD_COINS` lists for Bitcoin,
    /// and vice versa - the gate and the sub-table cannot drift apart, or a method would
    /// either 404 despite having a handler or reach the Zcash-typed path.
    #[test]
    fn bitcoin_slice_matches_method_coins() {
        let gated: std::collections::BTreeSet<&str> = crate::rpc::methods_served_for_bitcoin();
        let served: std::collections::BTreeSet<&str> =
            super::BITCOIN_METHODS.iter().copied().collect();
        assert_eq!(gated, served, "METHOD_COINS vs btc_methods::dispatch drift");
    }

    /// The whole dispatch path against a live Bitcoin wallet actor: the slice methods answer
    /// with their wire shapes, the coin gate 404s everything the engine does not serve (a
    /// Zcash-dialect write and a `z_*` method alike), and the wallet-independent shell still
    /// answers. This is the seam test - it goes through `rpc::dispatch`, so the safelist,
    /// arity, gate, and sub-table run exactly as an HTTP or embedded call would.
    #[cfg(feature = "cli")]
    #[tokio::test(flavor = "multi_thread")]
    async fn dispatch_serves_a_bitcoin_wallet_end_to_end() {
        use crate::btc::keys::tests::bip84_seed;
        use crate::server::jsonrpc::RpcRequest;
        use crate::state::AppState;
        use crate::wallet::{CoinWallet, WalletRegistry};
        use clap::Parser as _;
        use serde_json::{json, Value};
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("zecd.toml");
        std::fs::write(
            &conf,
            format!(
                "network = \"test\"\ndatadir = {:?}\ndefault_wallet = \"btc\"\n\
                 [wallets.btc]\ncoin = \"bitcoin\"\n",
                dir.path()
            ),
        )
        .unwrap();
        let cli = crate::config::Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let config = crate::config::AppConfig::resolve(&cli).unwrap();
        let entry = &config.wallets["btc"];
        let handle = crate::btc::actor::spawn(crate::btc::actor::BtcActorConfig {
            name: "btc".to_string(),
            engine_dir: entry.engine_dir(),
            network: entry.bitcoin_network(),
            seed: Some(bip84_seed()),
            wallet_holds_seed: true,
        })
        .unwrap();
        let mut registry = WalletRegistry::new("btc".to_string());
        registry.insert(CoinWallet::Bitcoin(handle));
        let state = AppState {
            config: Arc::new(config),
            registry: Arc::new(registry),
            started_at: std::time::Instant::now(),
            shutdown_tx: tokio::sync::watch::channel(false).0,
            shutting_down: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            work_queue: Arc::new(tokio::sync::Semaphore::new(16)),
            active: crate::state::ActiveCommands::default(),
            operations: Arc::new(crate::operations::OperationRegistry::new()),
        };
        let call = |method: &str, params: Vec<Value>| {
            let req = RpcRequest::positional(method.to_string(), params);
            let state = &state;
            async move { crate::rpc::dispatch(state, None, &req).await }
        };

        let address = call("getnewaddress", vec![]).await.unwrap();
        let address = address.as_str().unwrap().to_string();
        assert!(address.starts_with("tb1"), "{address}");

        // Amounts are bare 8-decimal JSON numbers, like every zecd balance.
        let balance = call("getbalance", vec![]).await.unwrap();
        assert_eq!(balance.to_string(), "0.00000000");
        let balances = call("getbalances", vec![]).await.unwrap();
        assert_eq!(balances["mine"]["trusted"].to_string(), "0.00000000");

        let info = call("getwalletinfo", vec![]).await.unwrap();
        assert_eq!(info["coin"], json!("bitcoin"));
        assert_eq!(info["private_keys_enabled"], json!(true));
        assert_eq!(info["scanning"], json!(false));

        assert_eq!(call("listunspent", vec![]).await.unwrap(), json!([]));

        let addr_info = call("getaddressinfo", vec![json!(address.clone())])
            .await
            .unwrap();
        assert_eq!(addr_info["ismine"], json!(true));
        assert_eq!(addr_info["ischange"], json!(false));
        assert_eq!(addr_info["hdkeypath"], json!("m/84'/1'/0'/0/0"));
        assert_eq!(addr_info["address_index"], json!(0));

        let valid = call("validateaddress", vec![json!(address.clone())])
            .await
            .unwrap();
        assert_eq!(valid["isvalid"], json!(true));
        let invalid = call("validateaddress", vec![json!("not-an-address")])
            .await
            .unwrap();
        assert_eq!(invalid["isvalid"], json!(false));

        // The wallet-independent shell answers regardless of coin.
        assert_eq!(call("listwallets", vec![]).await.unwrap(), json!(["btc"]));

        // Everything the engine does not serve reads as method-not-found: a Zcash-dialect
        // write, a chain read (no chain source yet), and a z_* extension alike.
        for gated in [
            "sendtoaddress",
            "getblockcount",
            "z_sendmany",
            "listtransactions",
        ] {
            let err = call(gated, vec![]).await.unwrap_err();
            assert_eq!(
                err.code,
                crate::error::codes::RPC_METHOD_NOT_FOUND,
                "{gated} must 404 for a bitcoin wallet"
            );
        }

        // Labels stay refused (statelessness), and non-bech32 address types are refused.
        let err = call("getnewaddress", vec![json!("label")])
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_PARAMETER);
        let err = call("getnewaddress", vec![json!(""), json!("legacy")])
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_PARAMETER);
    }
}
