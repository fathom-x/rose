//! Control RPCs: stop, uptime, help, getrpcinfo, and the wallet-registry shell (listwallets,
//! listwalletdir, createwallet, loadwallet, unloadwallet) every build serves.

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

/// `createwallet "wallet_name" ( disable_private_keys blank passphrase avoid_reuse descriptors
/// load_on_startup external_signer )` - onboard a **view wallet** into the fleet, without
/// restarting the daemon.
///
/// zecd's divergence from Bitcoin Core is forced by what a Zcash wallet is: Core creates a wallet
/// that generates its own keys, while a monitored Zcash wallet is defined by a viewing key it is
/// given. So this RPC requires `ufvk` and `birthday` (in the options object, param 8), and every
/// Core flag that would ask for a *spending* wallet is refused rather than ignored - zecd loads at
/// most one wallet with spending keys, and it is not created over the network. `disable_private_keys`
/// is accepted only as `true`, which is what a fleet wallet is.
///
/// The birthday is required for the same reason it is in a manifest: defaulting it would silently
/// choose between a full-chain rescan and a tip-only scan that misses the wallet's funds.
///
/// Returns Core's `{"name": ..., "warning": ...}`.
///
/// Here rather than with the wallet handlers for `listwalletdir`'s reason: the parameter contract
/// and the configured-wallet refusal are engine-independent, and `conformance.py`'s shared
/// "wallets" section asserts them against a bitcoin-only build too. Only the onboarding itself
/// is the Zcash fleet's; a build without that engine refuses there with `-4`.
pub(crate) async fn createwallet(state: &AppState, params: &[Value]) -> Result<Value, RpcError> {
    let name = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_parameter("createwallet requires a wallet name"))?
        .to_string();

    // Core's positional flags. Only the ones that describe a watch-only wallet are honoured; the
    // rest are refused, because silently ignoring a request for a spending wallet would hand back
    // a wallet that cannot do what the caller asked for.
    if let Some(v) = params.get(1) {
        if v.as_bool() == Some(false) {
            return Err(RpcError::invalid_parameter(
                "createwallet on zecd creates a watch-only wallet from a viewing key, so \
                 disable_private_keys must be true (or omitted). zecd loads at most one wallet \
                 with spending keys, created offline with `zecd init`.",
            ));
        }
    }
    for (index, flag) in [(3usize, "passphrase"), (7, "external_signer")] {
        if params.get(index).is_some_and(|v| !v.is_null()) {
            return Err(RpcError::invalid_parameter(format!(
                "createwallet does not support {flag}: a fleet wallet holds no spending material"
            )));
        }
    }

    let options = params.get(8).cloned().unwrap_or(Value::Null);
    let ufvk = options
        .get("ufvk")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RpcError::invalid_parameter(
                "createwallet requires a \"ufvk\" in its options object (param 8): a monitored \
                 Zcash wallet is defined by the viewing key it is given",
            )
        })?
        .to_string();
    let birthday = options
        .get("birthday")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            RpcError::invalid_parameter(
                "createwallet requires a \"birthday\" height in its options object (param 8): \
                 defaulting it would either rescan the whole chain or miss the wallet's funds",
            )
        })?;
    let birthday = u32::try_from(birthday)
        .map_err(|_| RpcError::invalid_parameter("birthday is not a block height"))?;

    #[cfg(not(feature = "zcash"))]
    {
        let _ = (state, name, ufvk, birthday);
        Err(no_zcash_engine("view wallets cannot be onboarded"))
    }
    #[cfg(feature = "zcash")]
    {
        let fleet = state.fleet.as_ref().ok_or_else(|| {
            RpcError::wallet(
                "no fleet on this node, so view wallets cannot be onboarded. Set [fleet] \
                 enabled = true and restart. The fleet is experimental: its manifest format, \
                 [fleet] keys and wallet-management RPCs may change in a patch release. (An \
                 embedded host may also have been built without a fleet manager.)"
                    .to_string(),
            )
        })?;
        let member = crate::wallet::shard::ShardMember {
            name: name.clone(),
            ufvk,
            birthday: zcash_protocol::consensus::BlockHeight::from_u32(birthday),
        };
        fleet
            .onboard(&state.registry, member, true)
            .await
            .map_err(onboard_error)?;
        Ok(json!({
            "name": name,
            // The wallet is served immediately but has not scanned yet, which a caller reading a zero
            // balance a moment later needs to know.
            "warning": "the wallet is loaded; its balance and history are empty until the shard \
                        scans from its birthday",
        }))
    }
}

/// `unloadwallet ( "wallet_name" load_on_startup )` - stop serving a wallet.
///
/// As in Bitcoin Core, this does not delete anything: the wallet's manifest and its account stay
/// where they are, so a restart (or `loadwallet`) serves it again. Its shard also keeps scanning
/// for it - the account is still in that database, and removing it would rewind the shard and
/// re-scan every other wallet in it, which is a far larger action than "stop answering for this
/// name". That is the whole operation: the name leaves the RPC surface and nothing else changes,
/// which is why the response says so in its `warning` rather than leaving a caller to infer that
/// unloading freed some scanning work. Retiring a wallet for good is a different job: remove its
/// manifest, then rebuild the shard to stop scanning its account.
///
/// The arguments are validated **before** the wallet is resolved, so a malformed call answers the
/// same way whichever wallet it names - the rule `getnewaddress` already follows for its
/// `address_type`.
pub(crate) fn unloadwallet(
    state: &AppState,
    params: &[Value],
    routed: Option<&str>,
) -> Result<Value, RpcError> {
    let name = unloadwallet_target(params, routed)?;
    reject_unsupported_load_on_startup(params.get(1))?;
    // Only fleet wallets are unloadable: `loadwallet` restores from the fleet manifests, so
    // unloading a configured `[wallets.<name>]` entry (the spending wallet included) would be
    // irreversible until a restart - and `listwalletdir` would keep calling it loadable.
    if state.config.wallets.contains_key(name) {
        return Err(RpcError::wallet(format!(
            "wallet '{name}' is a configured [wallets.{name}] entry, which stays loaded for the \
             daemon's lifetime; only fleet wallets can be unloaded (to retire it, remove the \
             config entry and restart)"
        )));
    }
    if !state.registry.remove(name) {
        return Err(RpcError::wallet_not_found(format!(
            "Requested wallet does not exist or is not loaded: {name}"
        )));
    }
    Ok(json!({
        "name": name,
        // Core's `warning` is where a caller learns what this call did not do, and here that is
        // most of what "unload" usually implies: the account stays in its shard, which keeps
        // trial-decrypting every block for it, so nothing is freed and nothing is deleted.
        "warning": "the wallet is no longer served; its account stays in its shard and is still \
                    scanned, so unloading frees no scanning work, and a restart or loadwallet \
                    serves this wallet again",
    }))
}

/// Resolve which wallet `unloadwallet` was asked to unload, from its positional argument and the
/// `/wallet/<name>` route.
///
/// Bitcoin Core accepts either and **refuses** the two when they disagree, which is the behavior
/// worth copying: one of them is a client bug, and quietly preferring either can unload a wallet
/// the caller never named. Core's message is reproduced verbatim so a Core-shaped client's error
/// handling matches.
pub(crate) fn unloadwallet_target<'a>(
    params: &'a [Value],
    routed: Option<&'a str>,
) -> Result<&'a str, RpcError> {
    let named = match params.first() {
        // Absent or an explicit null: Core's "take it from the endpoint" spelling.
        None | Some(Value::Null) => None,
        Some(Value::String(name)) => Some(name.as_str()),
        Some(_) => {
            return Err(RpcError::type_error(
                "unloadwallet wallet_name must be a string",
            ))
        }
    };
    match (named, routed) {
        (Some(named), Some(routed)) if named != routed => Err(RpcError::invalid_parameter(
            "RPC endpoint wallet and wallet_name parameter specify different wallets",
        )),
        (Some(name), _) => Ok(name),
        (None, Some(routed)) => Ok(routed),
        (None, None) => Err(RpcError::invalid_parameter(
            "unloadwallet requires a wallet name",
        )),
    }
}

/// Accept `unloadwallet`'s `load_on_startup` only where zecd can honor it.
///
/// The fleet manifest **is** zecd's startup list, and `unloadwallet` deliberately leaves it in
/// place (that is what lets `loadwallet` restore the wallet). So `true` ("keep loading this wallet
/// at startup") is already the truth and costs nothing to accept, while `false` ("stop loading it
/// at startup") is a promise this RPC cannot keep - and silently ignoring it would have the wallet
/// reappear at the next restart of a daemon the operator believes they retired it from. Refusing
/// it names the manifest the operator actually has to remove, and follows `createwallet`, which
/// likewise rejects the Core flags it cannot honor rather than dropping them.
pub(crate) fn reject_unsupported_load_on_startup(value: Option<&Value>) -> Result<(), RpcError> {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(true)) => Ok(()),
        Some(Value::Bool(false)) => Err(RpcError::invalid_parameter(
            "unloadwallet does not support load_on_startup = false: a fleet wallet's manifest is \
             zecd's startup list, and unloading leaves it in place so loadwallet can restore the \
             wallet. Delete the wallet's manifest from the fleet manifest directory to keep it \
             unloaded across restarts (its account stays in its shard either way)",
        )),
        Some(_) => Err(RpcError::type_error(
            "unloadwallet load_on_startup must be a boolean",
        )),
    }
}

/// `loadwallet "filename" ( load_on_startup )` - serve a wallet that is provisioned but not
/// loaded: one added to the manifest directory while the daemon ran, or one `unloadwallet`
/// dropped.
pub(crate) async fn loadwallet(state: &AppState, params: &[Value]) -> Result<Value, RpcError> {
    let name = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_parameter("loadwallet requires a wallet name"))?
        .to_string();
    #[cfg(not(feature = "zcash"))]
    {
        let _ = (state, name);
        Err(no_zcash_engine("wallets cannot be loaded at runtime"))
    }
    #[cfg(feature = "zcash")]
    {
        let fleet = state.fleet.as_ref().ok_or_else(|| {
            RpcError::wallet(
                "no fleet on this node, so wallets cannot be loaded at runtime. Set [fleet] \
                 enabled = true and restart. The fleet is experimental: its manifest format, \
                 [fleet] keys and wallet-management RPCs may change in a patch release. (An \
                 embedded host may also have been built without a fleet manager.)"
                    .to_string(),
            )
        })?;
        let (members, _skipped) = crate::fleet::load_manifests(fleet.manifest_dir())
            .map_err(|e| RpcError::wallet(format!("reading the fleet manifests: {e:#}")))?;
        // A skipped manifest is not found here, so an unreadable file for this very name surfaces as
        // "no wallet '<name>'" - correct as far as it goes, and `listwalletdir`'s warnings say why.
        let member = members
            .into_iter()
            .find(|m| m.name == name)
            .ok_or_else(|| {
                RpcError::wallet_not_found(format!(
                    "no wallet '{name}' in the fleet manifest directory ({}); see listwalletdir",
                    fleet.manifest_dir().display()
                ))
            })?;
        // The manifest is already on disk, so this is a load, not a create.
        fleet
            .onboard(&state.registry, member, false)
            .await
            .map_err(onboard_error)?;
        Ok(json!({ "name": name, "warning": "" }))
    }
}

/// Map an onboarding refusal onto Bitcoin Core's error dialect.
#[cfg(feature = "zcash")]
fn onboard_error(e: crate::fleet::OnboardError) -> RpcError {
    use crate::fleet::OnboardError;
    match e {
        // Core's `RPC_WALLET_ALREADY_EXISTS` case.
        OnboardError::NameTaken(_) => RpcError::wallet(e.to_string()),
        OnboardError::BadName(_) | OnboardError::BadKey(_) => {
            RpcError::invalid_parameter(e.to_string())
        }
        OnboardError::Failed(_) => RpcError::wallet(e.to_string()),
    }
}

/// The refusal a build without the Zcash engine gives the fleet-backed management RPCs. The
/// fleet (view wallets onboarded from a UFVK) is Zcash's, so there is nothing to enable - unlike
/// the `[fleet] enabled = false` refusal, which names the knob.
#[cfg(not(feature = "zcash"))]
fn no_zcash_engine(what: &str) -> RpcError {
    RpcError::wallet(format!(
        "{what}: runtime wallet management is the Zcash fleet's, and this build does not \
         include the Zcash engine. Configure wallets as [wallets.<name>] entries instead."
    ))
}
