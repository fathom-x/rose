//! Control RPCs: stop, uptime, help, getrpcinfo.

use serde_json::{json, Value};

use crate::error::RpcError;
use crate::state::AppState;

/// `stop` - request graceful shutdown (in-flight requests finish; new ones get 503).
///
/// Gated to regtest (matching Zallet): on mainnet/testnet it reports method-not-found so a
/// stray `stop` can't take down a production daemon over RPC. Stop a live node with a signal
/// (SIGINT/SIGTERM) instead.
pub(crate) fn stop(state: &AppState) -> Result<Value, RpcError> {
    if !state.config.network.is_regtest() {
        return Err(RpcError::method_not_found("stop"));
    }
    state.trigger_shutdown();
    Ok(Value::String("zecd stopping".to_string()))
}

/// `uptime` - seconds since the daemon started.
pub(crate) fn uptime(state: &AppState) -> Result<Value, RpcError> {
    Ok(json!(state.started_at.elapsed().as_secs()))
}

/// `help` - a short orientation string (zecd has no per-method help pages; the README's
/// method table is the reference).
pub(crate) fn help() -> Result<Value, RpcError> {
    Ok(Value::String(
        "zecd: a Bitcoin-Core-style JSON-RPC server for shielded-first Zcash. \
         Supported methods include getblockchaininfo, getnetworkinfo, getwalletinfo, \
         getnewaddress, z_getaddressforaccount, getbalance, sendtoaddress, sendmany, \
         listtransactions, gettransaction, validateaddress. See the README for the full list \
         and limits."
            .to_string(),
    ))
}

/// `getrpcinfo` - the currently-executing commands, Bitcoin Core's load-visibility RPC.
pub(crate) fn getrpcinfo(state: &AppState) -> Result<Value, RpcError> {
    // active_commands: one entry per currently-executing command, with elapsed microseconds -
    // the same shape as Bitcoin Core's getrpcinfo (gives visibility under load).
    let active: Vec<Value> = state
        .active
        .snapshot()
        .into_iter()
        .map(|(method, micros)| json!({ "method": method, "duration": micros as u64 }))
        .collect();
    // We log to stderr/tracing rather than a debug.log file, so logpath is empty.
    Ok(json!({ "active_commands": active, "logpath": "" }))
}

/// `listwallets` - the names of all loaded wallets (every `[wallets.<name>]` in the config).
///
/// Here rather than with the wallet handlers because it reads the registry's key set and
/// touches no wallet: it is part of the wallet-independent shell every build serves, like the
/// rest of this module.
pub(crate) fn listwallets(state: &AppState) -> Result<Value, RpcError> {
    Ok(json!(state.registry.names()))
}

/// `listwalletdir` - the wallets available on disk, whether or not they are loaded.
///
/// Bitcoin Core's shape (`{"wallets": [{"name": ...}, ...]}`). For zecd this is the fleet's
/// manifest directory: the wallets an operator has provisioned, which is what they reconcile
/// against when a name is missing from `listwallets`. Configured `[wallets.<name>]` entries are
/// listed too - they are equally "on disk available", and omitting them would make the two RPCs
/// disagree for reasons that have nothing to do with the fleet.
///
/// zecd extension: a `warnings` array naming any manifest that could not be read. Those wallets
/// are skipped at startup rather than taking the daemon down, so this is where an operator sees
/// that a file they wrote is not being served - without it, a skipped wallet is indistinguishable
/// from one that was never provisioned. Absent when there are none, so the Core-shaped response
/// is unchanged for a healthy fleet.
///
/// Beside `listwallets` for the same reason it is: the configured-wallet half reads the
/// config and touches no wallet, so every build serves it - a bitcoin-only zecd answered
/// method-not-found here after the engine gate landed, which `conformance.py`'s shared
/// "wallets" section (both coins) trips on. Only the fleet half, which is Zcash's, is gated.
pub(crate) fn listwalletdir(state: &AppState) -> Result<Value, RpcError> {
    let mut names: Vec<String> = state.config.wallets.keys().cloned().collect();
    #[allow(unused_mut)]
    let mut warnings: Vec<String> = Vec::new();
    #[cfg(feature = "zcash")]
    if let Some(fleet) = &state.fleet {
        match crate::fleet::load_manifests(fleet.manifest_dir()) {
            Ok((members, skipped)) => {
                names.extend(members.into_iter().map(|m| m.name));
                warnings.extend(
                    skipped
                        .into_iter()
                        .map(|s| format!("{}: {}", s.path.display(), s.reason)),
                );
            }
            // A manifest directory the daemon cannot read is an operator-visible problem, but it
            // must not make listing the rest fail - that is exactly when this RPC is being used.
            Err(e) => {
                tracing::warn!("listwalletdir: reading the fleet manifests: {e:#}");
                warnings.push(format!("{}: {e:#}", fleet.manifest_dir().display()));
            }
        }
    }
    names.sort();
    names.dedup();
    let wallets: Vec<Value> = names
        .into_iter()
        .map(|name| json!({ "name": name }))
        .collect();
    let mut out = json!({ "wallets": wallets });
    if !warnings.is_empty() {
        out["warnings"] = json!(warnings);
    }
    Ok(out)
}
