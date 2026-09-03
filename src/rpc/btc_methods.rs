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
//! Scope: address issuance, the wallet-shaped reads, the wallet's local chain view
//! (`getblockcount`/`getbestblockhash` answer from the wallet's own synced checkpoint, the
//! same authority the Zcash handlers use), history (`listtransactions`/`gettransaction`),
//! and sends (`sendtoaddress`/`sendmany`/`sendrawtransaction`) - built, signed with
//! seed-derived signers, and broadcast through the wallet's bitcoind upstream.

use serde_json::{json, Value};

use crate::amount::{signed_zats_to_value, value_to_sat_per_kvb, value_to_zats, zats_to_value};
use crate::btc::actor::{BtcConnState, BtcSendOptions, BtcTxDetail, BtcTxRecord, BtcWalletHandle};
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
    "getblockcount",
    "getbestblockhash",
    "listtransactions",
    "gettransaction",
    "sendtoaddress",
    "sendmany",
    "sendrawtransaction",
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
        "listunspent" => listunspent(handle, req).await,
        "getaddressinfo" => getaddressinfo(handle, req).await,
        "validateaddress" => validateaddress(handle, req).await,
        "getblockcount" => Ok(json!(handle.status().synced_height)),
        "getbestblockhash" => Ok(json!(handle.status().synced_hash)),
        "listtransactions" => listtransactions(handle, req).await,
        "gettransaction" => gettransaction(handle, req).await,
        "sendtoaddress" => sendtoaddress(handle, req).await,
        "sendmany" => sendmany(handle, req).await,
        "sendrawtransaction" => sendrawtransaction(handle, req).await,
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
    // Core's getbalance is TRUSTED funds only: confirmed outputs plus the wallet's own
    // unconfirmed change - never an unconfirmed receive from a foreign sender, even at
    // minconf 0 (that value lives in getunconfirmedbalance / getbalances.untrusted_pending).
    let sats: u64 = if minconf == 0 {
        let b = handle.balance().await?;
        b.confirmed + b.trusted_pending
    } else {
        // minconf >= 1 is a plain depth filter; unconfirmed change is below any such depth.
        handle
            .list_unspent()
            .await?
            .iter()
            .filter(|u| u.confirmations >= minconf)
            .map(|u| u.amount_sat)
            .sum()
    };
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
    let status = handle.status();
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
        // Core's shape: `false`, or an object while a scan is running. The catch-up against
        // the upstream is the closest thing this wallet has to a rescan.
        "scanning": if status.conn_state == BtcConnState::Syncing {
            json!({ "duration": 0, "progress": 0.0 })
        } else {
            json!(false)
        },
        // Core master's `lastprocessedblock`: the wallet's own synced checkpoint, which is
        // also what `getblockcount`/`getbestblockhash` answer for this wallet.
        "lastprocessedblock": {
            "hash": status.synced_hash,
            "height": status.synced_height,
        },
        // zecd extension: which engine serves this wallet. The Zcash handler reports its own
        // extensions (pools, transparent) here; `coin` is the field a mixed-coin deployment
        // tells wallets apart by.
        "coin": "bitcoin",
    }))
}

/// `listunspent [minconf] [maxconf] [addresses] [include_unsafe]` - Bitcoin Core's argument
/// shape, mirroring the Zcash handler's semantics: `minconf` defaults to **1**, so an
/// unconfirmed receive is hidden until asked for with `listunspent 0` (exactly Core), and
/// `safe` is confirmed-or-own-change.
async fn listunspent(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    let depth = |v: Option<&Value>, name: &str, default: u64| -> Result<u64, RpcError> {
        match v {
            None | Some(Value::Null) => Ok(default),
            Some(v) => v.as_u64().ok_or_else(|| {
                RpcError::invalid_parameter(format!("{name} must be a non-negative integer"))
            }),
        }
    };
    let minconf = depth(req.param(0), "minconf", 1)?;
    let maxconf = depth(req.param(1), "maxconf", 9_999_999)?;
    let filter: Option<std::collections::BTreeSet<String>> = match req.param(2) {
        None | Some(Value::Null) => None,
        Some(Value::Array(addrs)) => {
            let mut set = std::collections::BTreeSet::new();
            for a in addrs {
                let Some(a) = a.as_str() else {
                    return Err(RpcError::type_error("addresses must be strings"));
                };
                // The actor's parse enforces validity and the wallet's network (Core
                // rejects an invalid filter address rather than silently matching nothing).
                handle.address_info(a.to_string()).await?;
                if !set.insert(a.to_string()) {
                    return Err(RpcError::invalid_parameter(format!(
                        "Invalid parameter, duplicated address: {a}"
                    )));
                }
            }
            Some(set)
        }
        Some(_) => return Err(RpcError::type_error("addresses must be an array")),
    };
    let include_unsafe = match req.param(3) {
        None | Some(Value::Null) => true,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(RpcError::type_error("include_unsafe must be a boolean")),
    };
    let utxos = handle.list_unspent().await?;
    let entries: Vec<Value> = utxos
        .into_iter()
        .filter(|u| {
            u.confirmations >= minconf
                && u.confirmations <= maxconf
                && (include_unsafe || u.trusted)
                && filter
                    .as_ref()
                    .is_none_or(|f| u.address.as_ref().is_some_and(|a| f.contains(a)))
        })
        .map(|u| {
            let mut obj = json!({
                "txid": u.txid,
                "vout": u.vout,
                "amount": zats_to_value(u.amount_sat),
                "confirmations": u.confirmations,
                "spendable": handle.has_seed,
                "solvable": true,
                "safe": u.trusted,
            });
            if let Some(address) = u.address {
                obj["address"] = Value::String(address);
            }
            obj
        })
        .collect();
    Ok(Value::Array(entries))
}

/// Core's `bip125-replaceable` vocabulary: `"yes"` only while the transaction is both
/// unconfirmed and explicitly signaling BIP 125.
fn bip125_replaceable(e: &BtcTxRecord) -> &'static str {
    if e.confirmations == 0 && e.explicit_rbf {
        "yes"
    } else {
        "no"
    }
}

/// One `gettransaction details` element: the per-output slice (Core's per-output fan-out,
/// the same accounting as the Zcash side's `tx_entries`; the label field is the usual
/// stateless `""`). Transaction-level fields live on the enclosing object.
fn detail_json(e: &BtcTxRecord, d: &BtcTxDetail) -> Value {
    let mut obj = json!({
        "category": d.category,
        "amount": signed_zats_to_value(d.amount_sat),
        "label": "",
        "vout": d.vout,
    });
    if let Some(address) = &d.address {
        obj["address"] = json!(address);
    }
    if d.category == "send" {
        if let Some(fee) = e.fee_sat {
            // Core reports the fee on send entries, negative.
            obj["fee"] = signed_zats_to_value(-i64::try_from(fee).unwrap_or(i64::MAX));
        }
    }
    obj
}

/// One `listtransactions` element: a [`detail_json`] slice joined with its transaction's
/// own fields, exactly Core's flattened shape.
fn tx_entry_json(e: &BtcTxRecord, d: &BtcTxDetail) -> Value {
    let mut obj = detail_json(e, d);
    obj["confirmations"] = json!(e.confirmations);
    obj["txid"] = json!(e.txid);
    obj["time"] = json!(e.time);
    obj["timereceived"] = json!(e.time);
    obj["bip125-replaceable"] = json!(bip125_replaceable(e));
    if let (Some(hash), Some(height)) = (&e.blockhash, e.height) {
        obj["blockhash"] = json!(hash);
        obj["blockheight"] = json!(height);
    }
    obj
}

async fn listtransactions(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    // The label argument is meaningless in a stateless wallet: only "*" (or omitted) is
    // accepted, exactly as the Zcash handler treats it.
    if let Some(label) = opt_str(req, 0) {
        if !label.is_empty() && label != "*" {
            return Err(RpcError::invalid_parameter(
                "labels are not supported (zecd is stateless); pass \"*\" or omit the label",
            ));
        }
    }
    let count = match req.param(1) {
        None | Some(Value::Null) => 10,
        Some(v) => v
            .as_u64()
            .ok_or_else(|| RpcError::invalid_parameter("count must be a non-negative integer"))?
            as usize,
    };
    let skip = match req.param(2) {
        None | Some(Value::Null) => 0,
        Some(v) => v
            .as_u64()
            .ok_or_else(|| RpcError::invalid_parameter("skip must be a non-negative integer"))?
            as usize,
    };
    let records = handle.list_transactions().await?;
    // Flatten to per-output entries first (a change-only transaction contributes none);
    // Core's pagination then applies to the entries: skip from the newest end, return up
    // to `count`, oldest first.
    let entries: Vec<Value> = records
        .iter()
        .flat_map(|e| e.details.iter().map(move |d| tx_entry_json(e, d)))
        .collect();
    let upper = entries.len().saturating_sub(skip);
    let lower = upper.saturating_sub(count);
    Ok(Value::Array(entries[lower..upper].to_vec()))
}

async fn gettransaction(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    let Some(txid) = opt_str(req, 0) else {
        return Err(RpcError::invalid_parameter("txid is required"));
    };
    let entry = handle
        .get_transaction(txid.clone())
        .await?
        .ok_or_else(|| RpcError::invalid_address_or_key("Invalid or non-wallet transaction id"))?;
    // Core's top-level `amount` is the net wallet impact excluding the fee - the sum of the
    // details (a self-payment's send+receive pair nets to zero, change never appears).
    let amount_sat: i64 = entry.details.iter().map(|d| d.amount_sat).sum();
    let details: Vec<Value> = entry
        .details
        .iter()
        .map(|d| detail_json(&entry, d))
        .collect();
    let mut obj = json!({
        "amount": signed_zats_to_value(amount_sat),
        "confirmations": entry.confirmations,
        "txid": entry.txid,
        "time": entry.time,
        "timereceived": entry.time,
        "bip125-replaceable": bip125_replaceable(&entry),
        "details": details,
        "hex": entry.hex,
    });
    if let Some(fee) = entry.fee_sat {
        obj["fee"] = signed_zats_to_value(-i64::try_from(fee).unwrap_or(i64::MAX));
    }
    if let (Some(hash), Some(height)) = (&entry.blockhash, entry.height) {
        obj["blockhash"] = json!(hash);
        obj["blockheight"] = json!(height);
    }
    Ok(obj)
}

async fn sendtoaddress(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    let addr = req.require_str(0, "sendtoaddress requires an address")?;
    let amount = match req.param(1) {
        None | Some(Value::Null) => {
            return Err(RpcError::missing_param("sendtoaddress requires an amount"))
        }
        Some(v) => value_to_zats(v)?,
    };
    // Params 2/3 (comment, comment_to) are metadata and safe to ignore (zecd is stateless).
    // Param 4 (subtractfeefromamount): the fee comes out of the amount sent - the recipient
    // receives amount minus fee and the sender is debited exactly the amount.
    let subtract = match req.param(4) {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => {
            return Err(RpcError::type_error(
                "subtractfeefromamount must be a boolean",
            ))
        }
    };
    // Params 6/7 (conf_target, estimate_mode) are refused when engaged; param 9
    // (fee_rate) is an explicit rate in sat/vB, honored verbatim instead of the
    // upstream's estimate (Core's argument, Core's 3-decimal precision).
    reject_fee_estimation_params(req)?;
    let options = BtcSendOptions {
        fee_rate_sat_per_kvb: parse_fee_rate(req.param(9))?,
        subtract_fee_from: if subtract { vec![0] } else { Vec::new() },
    };
    let txid = handle
        .send(vec![(addr.to_string(), amount)], options)
        .await?;
    Ok(Value::String(txid))
}

/// Parse an optional `fee_rate` parameter (sat/vB) into sat/kvB, `None` when disengaged.
/// A rate below the 1 sat/vB relay floor is refused up front, as Core refuses one below
/// `minrelaytxfee`: a send priced under the floor builds a transaction no node relays -
/// on bitcoind that fails late at broadcast, and over kyoto a peer's `getdata` counts as
/// broadcast success, so the unminable transaction would be recorded at 0-conf with its
/// inputs locked behind it and no bumpfee/abandon to free them.
fn parse_fee_rate(v: Option<&Value>) -> Result<Option<u64>, RpcError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let kvb = value_to_sat_per_kvb(v)?;
            if kvb < 1_000 {
                return Err(RpcError::invalid_parameter(format!(
                    "fee_rate ({}.{:03} sat/vB) is lower than the minimum relay fee rate \
                     (1.000 sat/vB)",
                    kvb / 1_000,
                    kvb % 1_000
                )));
            }
            Ok(Some(kvb))
        }
    }
}

/// Refuse an engaged `conf_target`/`estimate_mode` pair (the same positions, 6/7, on both
/// send methods). The wallet estimates at one fixed target and cannot honor either, and a
/// named target it would silently ignore is a mischarge - the refuse-don't-mischarge rule,
/// which also covers Core's own `-8` for combining them with an explicit `fee_rate`.
/// Core's disengaged shapes are accepted: `null`, and for `estimate_mode` also `""` and
/// `"unset"`.
fn reject_fee_estimation_params(req: &RpcRequest) -> Result<(), RpcError> {
    if req.param(6).is_some_and(|v| !v.is_null()) {
        return Err(RpcError::invalid_parameter(
            "conf_target is not supported (the wallet estimates at a fixed target; pass an \
             explicit fee_rate to price the send yourself)",
        ));
    }
    match req.param(7) {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) if s.is_empty() || s.eq_ignore_ascii_case("unset") => Ok(()),
        Some(_) => Err(RpcError::invalid_parameter(
            "estimate_mode is not supported (the wallet estimates at a fixed target; pass \
             an explicit fee_rate to price the send yourself)",
        )),
    }
}

async fn sendmany(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    // Bitcoin Core's first parameter is the legacy dummy account, which must be "".
    if let Some(dummy) = opt_str(req, 0) {
        if !dummy.is_empty() {
            return Err(RpcError::invalid_parameter(
                "dummy first argument must be \"\" (accounts are not supported)",
            ));
        }
    }
    let Some(Value::Object(map)) = req.param(1) else {
        return Err(RpcError::invalid_parameter(
            "sendmany requires an {\"address\": amount} object",
        ));
    };
    if map.is_empty() {
        return Err(RpcError::invalid_parameter("sendmany requires recipients"));
    }
    let mut recipients = Vec::with_capacity(map.len());
    for (addr, amount) in map {
        recipients.push((addr.clone(), value_to_zats(amount)?));
    }
    // Param 4 (subtractfeefrom): the addresses whose amounts pay the fee, each of which
    // must be a recipient - a name that matches nothing would silently shift the fee back
    // onto the sender, the mischarge this used to refuse outright.
    let subtract_fee_from = match req.param(4) {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(addrs)) => {
            let mut indices = Vec::with_capacity(addrs.len());
            for a in addrs {
                let Some(a) = a.as_str() else {
                    return Err(RpcError::type_error(
                        "subtractfeefrom must be an array of address strings",
                    ));
                };
                let idx = recipients
                    .iter()
                    .position(|(addr, _)| addr == a)
                    .ok_or_else(|| {
                        RpcError::invalid_parameter(format!(
                            "subtractfeefrom names an address that is not a recipient: {a}"
                        ))
                    })?;
                if indices.contains(&idx) {
                    return Err(RpcError::invalid_parameter(format!(
                        "Invalid parameter, duplicated address: {a}"
                    )));
                }
                indices.push(idx);
            }
            indices
        }
        Some(_) => {
            return Err(RpcError::type_error(
                "subtractfeefrom must be an array of address strings",
            ))
        }
    };
    // Params 6/7 (conf_target, estimate_mode) are refused when engaged; param 8
    // (fee_rate) is an explicit rate in sat/vB, as on sendtoaddress (where it is
    // param 9 - Core's own positional layouts differ between the two).
    reject_fee_estimation_params(req)?;
    let options = BtcSendOptions {
        fee_rate_sat_per_kvb: parse_fee_rate(req.param(8))?,
        subtract_fee_from,
    };
    let txid = handle.send(recipients, options).await?;
    Ok(Value::String(txid))
}

async fn sendrawtransaction(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    let hex = req.require_str(0, "sendrawtransaction requires a hex string")?;
    let txid = handle.broadcast(hex.to_string()).await?;
    Ok(Value::String(txid))
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
            BitcoinNetwork::Testnet3 | BitcoinNetwork::Testnet4 | BitcoinNetwork::Regtest => 1,
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
        let (handle, _task) = crate::btc::actor::spawn(crate::btc::actor::BtcActorConfig {
            name: "btc".to_string(),
            engine_dir: entry.engine_dir(),
            network: entry.bitcoin_network(),
            seed: Some(bip84_seed()),
            wallet_holds_seed: true,
            imported_keys: None,
            endpoint: None,
            fees: crate::config::FeesConfig::default(),
            birthday: 0,
            birthday_time: None,
            sync_interval: std::time::Duration::from_secs(20),
            reconnect_base: std::time::Duration::from_secs(1),
            reconnect_max: std::time::Duration::from_secs(60),
            shutdown: tokio::sync::watch::channel(false).1,
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
        // The wallet's own chain view: a fresh wallet sits at its genesis checkpoint, and
        // getblockcount/getbestblockhash answer from the same authority.
        assert_eq!(info["lastprocessedblock"]["height"], json!(0));
        assert_eq!(call("getblockcount", vec![]).await.unwrap(), json!(0));
        let best = call("getbestblockhash", vec![]).await.unwrap();
        assert_eq!(
            best, info["lastprocessedblock"]["hash"],
            "hash authorities agree"
        );

        assert_eq!(call("listunspent", vec![]).await.unwrap(), json!([]));
        assert_eq!(call("listtransactions", vec![]).await.unwrap(), json!([]));

        // History misses and offline sends fail with their Core codes rather than panicking:
        // an unknown txid is -5, a send with no upstream connection is -4, and a raw
        // broadcast without an upstream is -4 too.
        let err = call("gettransaction", vec![json!("00".repeat(32))])
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_ADDRESS_OR_KEY);
        let err = call(
            "sendtoaddress",
            vec![json!(address.clone()), json!(0.001_f64)],
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_WALLET_ERROR);
        let err = call("sendrawtransaction", vec![json!("0000")])
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_WALLET_ERROR);
        // sendmany parameter shape: a non-object recipient set is -8 before any wallet work.
        let err = call("sendmany", vec![json!(""), json!("nope")])
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_PARAMETER);

        // The optional send parameters are validated before any wallet work: a non-boolean
        // subtractfeefromamount is -3, a subtractfeefrom name that is not a recipient (or
        // a duplicated one) is -8, and a zero or malformed fee_rate is -8/-3.
        let err = call(
            "sendtoaddress",
            vec![
                json!(address.clone()),
                json!(0.001_f64),
                json!(null),
                json!(null),
                json!("yes"),
            ],
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_TYPE_ERROR);
        let err = call(
            "sendtoaddress",
            vec![
                json!(address.clone()),
                json!(0.001_f64),
                json!(null),
                json!(null),
                json!(null),
                json!(null),
                json!(null),
                json!(null),
                json!(null),
                json!(0),
            ],
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_PARAMETER);
        // A rate under the 1 sat/vB relay floor is refused up front (Core's minrelay
        // posture), naming both numbers.
        let err = call(
            "sendtoaddress",
            vec![
                json!(address.clone()),
                json!(0.001_f64),
                json!(null),
                json!(null),
                json!(null),
                json!(null),
                json!(null),
                json!(null),
                json!(null),
                json!(0.05),
            ],
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_PARAMETER);
        assert!(err.message.contains("0.050 sat/vB"), "{}", err.message);
        // conf_target and estimate_mode cannot be honored, so engaging either is -8;
        // the disengaged estimate_mode shapes ("", "unset") fall through to the send
        // itself, which fails -4 offline - proof they passed validation.
        let mut params = vec![
            json!(address.clone()),
            json!(0.001_f64),
            json!(null),
            json!(null),
            json!(null),
            json!(null),
            json!(1),
        ];
        let err = call("sendtoaddress", params.clone()).await.unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_PARAMETER);
        assert!(err.message.contains("conf_target"), "{}", err.message);
        params[6] = json!(null);
        params.push(json!("economical"));
        let err = call("sendtoaddress", params.clone()).await.unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_PARAMETER);
        assert!(err.message.contains("estimate_mode"), "{}", err.message);
        params[7] = json!("unset");
        let err = call("sendtoaddress", params).await.unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_WALLET_ERROR);
        let err = call(
            "sendmany",
            vec![
                json!(""),
                json!({ address.clone(): 0.001_f64 }),
                json!(null),
                json!(null),
                json!(["not-a-recipient"]),
            ],
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_PARAMETER);
        assert!(err.message.contains("not a recipient"), "{}", err.message);
        let err = call(
            "sendmany",
            vec![
                json!(""),
                json!({ address.clone(): 0.001_f64 }),
                json!(null),
                json!(null),
                json!([address.clone(), address.clone()]),
            ],
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_PARAMETER);
        assert!(err.message.contains("duplicated"), "{}", err.message);

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
        // node read, the passphrase surface, and a z_* extension alike.
        for gated in [
            "getblockchaininfo",
            "signmessage",
            "z_sendmany",
            "walletpassphrase",
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
