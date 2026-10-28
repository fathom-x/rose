//! The RPC methods served for Bitcoin wallets - the handler half of the second sanctioned
//! engine seam (the registry being the first; see the shared-layer boundary in the project docs).
//!
//! [`dispatch`] is a sub-table consulted by `dispatch_rose` when the addressed wallet is a
//! Bitcoin one: `Some` for the methods the BDK engine serves (which must be exactly the
//! methods `METHOD_COINS` lists for [`crate::coin::Coin::Bitcoin`] - the
//! `bitcoin_slice_matches_method_coins` test pins the two together), `None` to fall through
//! to the shared table (the wallet-independent shell). Everything here speaks the same wire
//! shapes as the Zcash handlers: bare 8-decimal JSON amounts, Bitcoin Core field names, the
//! same error codes.
//!
//! Scope: address issuance, the wallet-shaped reads, the wallet's local chain view
//! (`getblockcount`/`getbestblockhash` answer from the wallet's own synced checkpoint, the
//! same authority the Zcash handlers use), history (`listtransactions`/`gettransaction`,
//! `listreceivedbyaddress` - which with `include_empty` is also the enumeration of every
//! issued receiving address, each tagged with its derivation index), the public descriptors
//! (`listdescriptors`, Core's shape, the xpub included), and sends (`sendtoaddress`/`sendmany`/`sendrawtransaction`) - built, signed with
//! seed-derived signers, and broadcast through the wallet's bitcoind upstream.

use bdk_wallet::bitcoin::Txid;

use std::str::FromStr as _;

use serde_json::{json, Value};

use crate::amount::{signed_zats_to_value, value_to_sat_per_kvb, value_to_zats, zats_to_value};
use crate::btc::actor::{
    BtcBumpOptions, BtcConnState, BtcFeeSplit, BtcReceipt, BtcSendOptions, BtcSent, BtcSyncStatus,
    BtcTxDetail, BtcTxRecord, BtcWalletHandle, MempoolFeedStatus,
};
use crate::coin::BitcoinNetwork;
use crate::error::RpcError;
use crate::rpc::params::{
    check_balance_dummy, count_from_params, depth_param, walletpassphrase_args,
};
use crate::server::jsonrpc::RpcRequest;

/// A non-negative depth argument (`minconf`, `maxconf`) with the Zcash handlers' error
/// contract, so both engines answer a Core client identically: a non-number is `-3`, a
/// negative number `-8`, `null`/absent the default.
fn depth(v: Option<&Value>, name: &str, default: u64) -> Result<u64, RpcError> {
    let n = depth_param(v, name, i64::try_from(default).unwrap_or(i64::MAX))?;
    u64::try_from(n)
        .map_err(|_| RpcError::invalid_parameter(format!("{name} must be a non-negative integer")))
}

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
    "listreceivedbyaddress",
    "listdescriptors",
    "sendtoaddress",
    "sendmany",
    "sendrawtransaction",
    "abandontransaction",
    "bumpfee",
    "getblockchaininfo",
    "getnetworkinfo",
    "estimatesmartfee",
    "getreceivedbyaddress",
    "listsinceblock",
    "walletpassphrase",
    "walletlock",
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
        "listreceivedbyaddress" => listreceivedbyaddress(handle, req).await,
        "listdescriptors" => listdescriptors(handle, req).await,
        "sendtoaddress" => sendtoaddress(handle, req).await,
        "sendmany" => sendmany(handle, req).await,
        "sendrawtransaction" => sendrawtransaction(handle, req).await,
        "abandontransaction" => abandontransaction(handle, req).await,
        "bumpfee" => bumpfee(handle, req).await,
        "getblockchaininfo" => Ok(getblockchaininfo(handle)),
        "getnetworkinfo" => Ok(crate::rpc::network::networkinfo_json(
            handle.status().conn_state != BtcConnState::Down,
        )),
        "estimatesmartfee" => estimatesmartfee(handle, req).await,
        "getreceivedbyaddress" => getreceivedbyaddress(handle, req).await,
        "listsinceblock" => listsinceblock(handle, req).await,
        "walletpassphrase" => walletpassphrase(handle, req).await,
        "walletlock" => handle.lock().await.map(|()| Value::Null),
        _ => return None,
    })
}

/// `getblockchaininfo` from the wallet's own chain view - the same authority
/// `getblockcount`/`getbestblockhash` answer from, never a proxy of the node's tip. `chain` is
/// Core's name (`main`, `test`, `testnet4`, `regtest`). The wallet does not track the node's
/// header count or block times, so `headers` is its own height and there is no `time`/
/// `mediantime`; `initialblockdownload`/`verificationprogress` follow the connection state
/// (catching up to the source's tip, or at it).
fn getblockchaininfo(handle: &BtcWalletHandle) -> Value {
    let status = handle.status();
    let syncing = status.conn_state != BtcConnState::Ready;
    json!({
        "chain": match handle.network {
            BitcoinNetwork::Main => "main",
            BitcoinNetwork::Testnet3 => "test",
            BitcoinNetwork::Testnet4 => "testnet4",
            BitcoinNetwork::Regtest => "regtest",
        },
        "blocks": status.synced_height,
        "headers": status.synced_height,
        "bestblockhash": status.synced_hash,
        "difficulty": 1.0,
        "verificationprogress": if syncing { 0.0 } else { 1.0 },
        "initialblockdownload": syncing,
        "size_on_disk": 0,
        "pruned": false,
        "warnings": "",
    })
}

/// `estimatesmartfee conf_target ( "estimate_mode" )` - Core's argument rules (a target in
/// 1..=1008, else `-8`; `estimate_mode` one of `unset`/`economical`/`conservative`) over the
/// wallet's backend: bitcoind's own estimator at the requested target and mode, or over
/// kyoto the `[fees]` chain a send prices from (which answers one horizon, so the target is
/// echoed rather than honored - the `source` extension says which answered). No estimate is
/// Core's `errors` shape, not an RPC error.
async fn estimatesmartfee(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    let target = match req.param(0) {
        None | Some(Value::Null) => {
            return Err(RpcError::missing_param(
                "estimatesmartfee requires conf_target",
            ))
        }
        Some(v) => v
            .as_i64()
            .ok_or_else(|| RpcError::type_error("conf_target must be an integer"))?,
    };
    let target = u16::try_from(target)
        .ok()
        .filter(|t| (1..=1008).contains(t))
        .ok_or_else(|| {
            RpcError::invalid_parameter("Invalid conf_target, must be between 1 and 1008")
        })?;
    let conservative = match req.param(1) {
        None | Some(Value::Null) => None,
        Some(Value::String(mode)) => match mode.to_ascii_lowercase().as_str() {
            "unset" | "" => None,
            "economical" => Some(false),
            "conservative" => Some(true),
            _ => {
                return Err(RpcError::invalid_parameter(
                    "Invalid estimate_mode parameter",
                ))
            }
        },
        Some(_) => return Err(RpcError::type_error("estimate_mode must be a string")),
    };
    Ok(match handle.estimate_fee(target, conservative).await? {
        Some((sat_per_kvb, source)) => json!({
            "feerate": zats_to_value(sat_per_kvb),
            "blocks": target,
            "source": source,
        }),
        None => json!({
            "errors": ["Insufficient data or no feerate found"],
            "blocks": target,
        }),
    })
}

/// `getreceivedbyaddress "address" ( minconf include_immature_coinbase )` - Core's contract:
/// an invalid address is `-5`, one the wallet does not own `-4` "Address not found in
/// wallet", else the total received at `minconf` depth (default 1). Immature coinbase is
/// withheld unless asked for, as in Core.
async fn getreceivedbyaddress(
    handle: &BtcWalletHandle,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let address = req.require_str(0, "getreceivedbyaddress requires an address")?;
    let minconf = depth(req.param(1), "minconf", 1)?;
    let include_immature = match req.param(2) {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => {
            return Err(RpcError::type_error(
                "include_immature_coinbase must be a boolean",
            ))
        }
    };
    let info = handle.address_info(address.to_string()).await?;
    if !info.is_mine {
        return Err(RpcError::wallet("Address not found in wallet"));
    }
    let total: u64 = handle
        .received_by_address()
        .await?
        .into_iter()
        .filter(|a| a.address == address)
        .flat_map(|a| a.receipts)
        .filter(|r| r.confirmations >= minconf && (include_immature || !r.immature))
        .map(|r| r.amount_sat)
        .sum();
    Ok(zats_to_value(total))
}

/// `listsinceblock ( "blockhash" target_confirmations include_watchonly include_removed )`,
/// Core's shape: `transactions` (the `listtransactions` entries
/// of everything mined above `blockhash`, plus everything unconfirmed), `removed` (always
/// empty: a reorged-away transaction is simply re-reported, or dropped from the wallet), and
/// `lastblock`, the cursor for the next call. A malformed hash is `-5` "Block not found"; a
/// well-formed one the wallet's chain does not hold reads as "since the beginning", so a
/// poller feeding back a reorged-away cursor re-reads rather than wedging (the Zcash
/// handler's rule). Core's later `include_change`/`label` are over the four-argument cap
/// both engines share, so they are the arity error.
async fn listsinceblock(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    let since = match req.param(0) {
        None | Some(Value::Null) => None,
        Some(Value::String(hash)) if hash.is_empty() => None,
        Some(Value::String(hash)) => Some(
            bdk_wallet::bitcoin::BlockHash::from_str(hash)
                .map_err(|_| RpcError::invalid_address_or_key("Block not found"))?,
        ),
        Some(_) => return Err(RpcError::type_error("blockhash must be a string")),
    };
    let target_confirmations = match req.param(1) {
        None | Some(Value::Null) => 1u32,
        Some(v) => match v.as_i64() {
            Some(n) if (1..=i64::from(u32::MAX)).contains(&n) => n as u32,
            _ => return Err(RpcError::invalid_parameter("Invalid parameter")),
        },
    };
    let flag = |i: usize, name: &str| -> Result<bool, RpcError> {
        match req.param(i) {
            None | Some(Value::Null) => Ok(false),
            Some(Value::Bool(b)) => Ok(*b),
            Some(_) => Err(RpcError::type_error(format!("{name} must be a boolean"))),
        }
    };
    let _include_watchonly = flag(2, "include_watchonly")?;
    let _include_removed = flag(3, "include_removed")?;
    let since = handle.since_block(since, target_confirmations).await?;
    let transactions: Vec<Value> = since
        .records
        .iter()
        .flat_map(|e| e.details.iter().map(move |d| tx_entry_json(e, d)))
        .collect();
    Ok(json!({
        "transactions": transactions,
        "removed": [],
        "lastblock": since.lastblock,
    }))
}

fn opt_str(req: &RpcRequest, i: usize) -> Option<String> {
    req.param(i).and_then(|v| v.as_str()).map(|s| s.to_string())
}

async fn getnewaddress(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    // Same statelessness rule as the Zcash handler: no labels, ever.
    if opt_str(req, 0).is_some_and(|s| !s.is_empty()) {
        return Err(RpcError::invalid_parameter(
            "labels are not supported (rose is stateless); call getnewaddress without a label",
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
    // Bitcoin Core's first parameter is the legacy dummy account ("*" or omitted); the shared
    // check answers Core's -32 for anything else, exactly as the Zcash handler does.
    check_balance_dummy(req.param(0))?;
    let minconf = depth(req.param(1), "minconf", 0)?;
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
            .filter(|u| !u.immature && u.confirmations >= minconf)
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
    let recovery = handle.recovery().await?;
    // Core's txcount: every wallet transaction, visible history entry or not - counted,
    // not built.
    let txcount = handle.tx_count().await?;
    let mut info = json!({
        "walletname": handle.name,
        "walletversion": 169900,
        "format": "sqlite",
        "balance": zats_to_value(b.confirmed + b.trusted_pending),
        "unconfirmed_balance": zats_to_value(b.untrusted_pending),
        "immature_balance": zats_to_value(b.immature),
        "txcount": txcount,
        "keypoolsize": 1,
        "keypoolsize_hd_internal": 0,
        "paytxfee": zats_to_value(0),
        // `private_keys_enabled` stays true for an encrypted wallet, as in Core: the keys
        // exist, they are locked.
        "private_keys_enabled": handle.has_seed,
        "avoid_reuse": false,
        // A descriptor wallet, as every Core wallet since 23 (`listdescriptors` serves it).
        "descriptors": true,
        // Core's shape: `false`, or an object while a scan is running. The catch-up against
        // the upstream is the closest thing this wallet has to a rescan; see
        // `scanning_json` for the object.
        "scanning": scanning_json(&status, unix_now()),
        // Core master's `lastprocessedblock`: the wallet's own synced checkpoint, which is
        // also what `getblockcount`/`getbestblockhash` answer for this wallet.
        "lastprocessedblock": {
            "hash": status.synced_hash,
            "height": status.synced_height,
        },
        // rose extension: whether the wallet's chain source is connected right now. The
        // Zcash side answers this through `getpeerinfo`, which Bitcoin wallets do not
        // serve (nothing here has peers in Core's sense); this is the one signal that a
        // hung or unreachable upstream has been noticed - it flips false when the actor
        // drops the connection and back once a reconnect succeeds.
        "upstream_connected": status.conn_state != BtcConnState::Down,
        // rose extension: the wallet birthday and how it resolved - the same object the Zcash
        // handler reports. `height` is the recorded birthday (`keys.toml`), where a rebuild
        // scans from; `time` the birthday block's own time once the chain source has
        // answered (bitcoind at connect, kyoto once its headers cover it), else the offline
        // record - the operator's date when init kept one, else the shipped per-day table's
        // day for the height - or null off-table; `anchor` the `(height, hash)` checkpoint a
        // kyoto first scan
        // actually started from once one is recorded (by init, or by the first sync's own
        // resolution), else null - so an operator can see the anchor climb from the shipped
        // floor to the true height on a fresh wallet, and a bitcoind-backed wallet, whose
        // emitter starts from the birthday by height, shows null for good.
        "birthday": {
            "height": handle.birthday,
            "time": status.birthday_block_time.or(handle.birthday_time),
            "anchor": status
                .birthday_anchor
                .as_ref()
                .map(|(height, hash)| json!({ "height": height, "hash": hash })),
        },
        // rose extension: the opt-in mempool feed (`[mempool]`, kyoto only) - the one source
        // of 0-conf sightings on that backend, so a merchant integration can tell "no
        // payment detected" from "nothing could have been detected". `state` is `disabled`
        // (no feed configured for this wallet: the default, and always over bitcoind, which
        // has a mempool of its own), `connecting` (configured, socket down or not yet up),
        // or `connected`; the rest is present only when a feed is configured.
        //
        // `snapshot_applied` (a snapshot-taking P2P feed only) is whether the mempool view is
        // established since the feed last connected - for a wallet started from an empty
        // datadir, whether its own unconfirmed transactions from before have been found.
        // Sends wait for it, so it is what a readiness check keys on before spending.
        "mempool_feed": match &status.mempool_feed {
            None => json!({ "state": "disabled" }),
            Some(feed) => {
                let mut obj = json!({
                    "state": if feed.connected { "connected" } else { "connecting" },
                    "source": feed.source,
                    "endpoint": feed.endpoint,
                    "last_delta": feed.last_delta,
                    "deltas": feed.deltas,
                    "matched": feed.matched,
                    "dropped": feed.dropped,
                });
                if let Some(applied) = feed.snapshot_applied {
                    obj["snapshot_applied"] = json!(applied);
                    obj["snapshot_progress"] = snapshot_progress_json(feed, unix_now());
                }
                if let Some(bloom) = feed.peer_bloom {
                    obj["peer_bloom"] = json!(bloom);
                }
                obj
            }
        },
        // rose extension: whether a send would be refused before it reached coin selection,
        // and why - the connection check and the send gate (`BtcActor::send_gate`: the
        // mempool-view wait), as the status publishes them. `open` is what a payout
        // service polls before sending instead of learning from a `-4`; `reason` is the
        // refusal's own text when closed; `history` is the persisted seed-history record
        // (`fresh`, `unverified`, `verified`, or `unrecorded` for a database from before it)
        // that decides whether the gate arms; the opt-out is named so an operator can see
        // it is set without the daemon's log, which an enclave does not keep. The signer,
        // the lock and the funds are separate checks a send still makes.
        "send_gate": status.send_gate.to_json(),
        // rose extension: what a from-seed restore under this wallet's configuration would
        // recover, the Bitcoin counterpart of the Zcash handler's `transparent` block (see
        // `src/btc/README.md`, "Restores and the address lookahead"). `horizon` is the
        // highest external index such a restore re-derives without further funding
        // (`max(initial_scan, highest paid index + 1) + lookahead - 1`), `issued_through`
        // the highest index handed out so far (null before the first), and `restorable`
        // whether every issued address lies within the horizon - false exactly when
        // `getnewaddress` has gone past it, which the daemon also warns about at the time;
        // the fix is raising `[wallets.<name>] initial_scan` past `issued_through`.
        "recovery": {
            "initial_scan": recovery.initial_scan,
            "lookahead": recovery.lookahead,
            "horizon": recovery.horizon,
            "issued_through": recovery.issued_through,
            "restorable": recovery.restorable,
        },
        // rose extension: which engine serves this wallet. The Zcash handler reports its own
        // extensions (pools, transparent) here; `coin` is the field a mixed-coin deployment
        // tells wallets apart by.
        "coin": "bitcoin",
    });
    // Core reports `unlocked_until` only for an encrypted wallet: the unix time the unlock
    // expires, 0 while locked.
    if let Some(until) = handle.unlocked_until() {
        info["unlocked_until"] = json!(until);
    }
    Ok(info)
}

/// `getwalletinfo.scanning`: Core's `false` once the wallet is at its source's tip, else
/// Core's `{duration, progress}` plus rose's two heights, so a client can show "height X
/// of Y" and a payout service can read how far the catch-up has come. `progress` is the
/// band scanned over the band to scan (`BtcSyncStatus::scan`: from the connection's scan
/// start to the source's tip), `height` the height scanned through so far (over kyoto an
/// estimate from the light client's filter progress, since its one update moves the
/// wallet's checkpoint only at the end), `tip` the source's tip or null before it has
/// said, and `duration` the seconds since the catch-up started. With no connection
/// running one (between redials), the wallet's own height and nothing else.
fn scanning_json(status: &BtcSyncStatus, now: u64) -> Value {
    if status.conn_state != BtcConnState::Syncing {
        return json!(false);
    }
    match &status.scan {
        Some(scan) => json!({
            "duration": now.saturating_sub(scan.started),
            "progress": scan.fraction(),
            "height": scan.height.max(status.synced_height),
            "tip": scan.tip,
        }),
        None => json!({
            "duration": 0,
            "progress": 0.0,
            "height": status.synced_height,
            "tip": null,
        }),
    }
}

/// `getwalletinfo.mempool_feed.snapshot_progress`, for a feed that takes snapshots: null
/// between snapshots, else the one being collected - what the node has announced since the
/// request (`announced`), what is still being fetched (`pending`), when it was requested
/// (`requested_at`, unix seconds) and how long since (`elapsed`), and the collection
/// `window` in seconds after which the snapshot is delivered once nothing is pending. A
/// client shows fetched-over-announced (indeterminate while `announced` is 0: the node has
/// not answered yet) and the window elapsing.
fn snapshot_progress_json(feed: &MempoolFeedStatus, now: u64) -> Value {
    match &feed.snapshot_progress {
        None => Value::Null,
        Some(p) => json!({
            "announced": p.announced,
            "pending": p.pending,
            "requested_at": p.requested_at,
            "elapsed": now.saturating_sub(p.requested_at),
            "window": p.window_secs,
        }),
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `walletpassphrase <passphrase> <timeout>` - decrypt the seed into memory for `timeout`
/// seconds (auto-relock after), with the Zcash handler's argument rules and codes: wrong
/// passphrase `-14`, unencrypted wallet `-15`, a seed that does not derive the wallet's
/// account `-4`.
async fn walletpassphrase(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    let (passphrase, timeout) = walletpassphrase_args(req)?;
    handle.unlock(passphrase, timeout).await?;
    Ok(Value::Null)
}

/// `listunspent [minconf] [maxconf] [addresses] [include_unsafe] [query_options]` - Bitcoin
/// Core's argument shape, mirroring the Zcash handler's semantics: `minconf` defaults to
/// **1**, so an unconfirmed receive is hidden until asked for with `listunspent 0` (exactly
/// Core), and `safe` is confirmed-or-own-change. `query_options` takes Core's keys
/// (`minimumAmount`, `maximumAmount`, `maximumCount`, `minimumSumAmount`,
/// `include_immature_coinbase`); an unknown key is Core's `-3` "Unexpected key", never
/// silently ignored.
async fn listunspent(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
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
    let query = UnspentQuery::parse(req.param(4))?;
    let utxos = handle.list_unspent().await?;
    let mut entries = Vec::new();
    let mut sum: u64 = 0;
    for u in utxos {
        if !(u.confirmations >= minconf
            && u.confirmations <= maxconf
            && (include_unsafe || u.trusted)
            && (query.include_immature_coinbase || !u.immature)
            && u.amount_sat >= query.minimum_amount
            && u.amount_sat <= query.maximum_amount
            && filter
                .as_ref()
                .is_none_or(|f| u.address.as_ref().is_some_and(|a| f.contains(a))))
        {
            continue;
        }
        sum = sum.saturating_add(u.amount_sat);
        let mut obj = json!({
            "txid": u.txid,
            "vout": u.vout,
            "amount": zats_to_value(u.amount_sat),
            "confirmations": u.confirmations,
            "scriptPubKey": u.script_pubkey,
            "spendable": handle.has_seed && !u.immature,
            "solvable": true,
            "safe": u.trusted,
        });
        if let Some(address) = u.address {
            obj["address"] = Value::String(address);
        }
        if let Some(desc) = u.desc {
            obj["desc"] = Value::String(desc);
        }
        entries.push(obj);
        // Core stops at whichever limit is reached first.
        if query.maximum_count.is_some_and(|max| entries.len() >= max)
            || query.minimum_sum_amount.is_some_and(|min| sum >= min)
        {
            break;
        }
    }
    Ok(Value::Array(entries))
}

/// `listunspent`'s `query_options` object, in Core's vocabulary. Amounts are BTC values
/// parsed like every amount (`-3` for a malformed one).
struct UnspentQuery {
    minimum_amount: u64,
    maximum_amount: u64,
    /// `None` = unlimited (Core's default, and what `0` means there too).
    maximum_count: Option<usize>,
    minimum_sum_amount: Option<u64>,
    include_immature_coinbase: bool,
}

impl UnspentQuery {
    fn parse(v: Option<&Value>) -> Result<Self, RpcError> {
        let mut query = UnspentQuery {
            minimum_amount: 0,
            maximum_amount: u64::MAX,
            maximum_count: None,
            minimum_sum_amount: None,
            include_immature_coinbase: false,
        };
        let map = match v {
            None | Some(Value::Null) => return Ok(query),
            Some(Value::Object(map)) => map,
            Some(_) => return Err(RpcError::type_error("query_options must be an object")),
        };
        for (key, value) in map {
            if value.is_null() {
                continue;
            }
            match key.as_str() {
                "minimumAmount" => query.minimum_amount = value_to_zats(value)?,
                "maximumAmount" => query.maximum_amount = value_to_zats(value)?,
                "minimumSumAmount" => query.minimum_sum_amount = Some(value_to_zats(value)?),
                "maximumCount" => {
                    let n = value
                        .as_i64()
                        .ok_or_else(|| RpcError::type_error("maximumCount must be an integer"))?;
                    if n < 0 {
                        return Err(RpcError::invalid_parameter(
                            "Invalid parameter, maximumCount must be non-negative",
                        ));
                    }
                    query.maximum_count = usize::try_from(n).ok().filter(|n| *n > 0);
                }
                "include_immature_coinbase" => {
                    query.include_immature_coinbase = value.as_bool().ok_or_else(|| {
                        RpcError::type_error("include_immature_coinbase must be a boolean")
                    })?
                }
                other => {
                    return Err(RpcError::type_error(format!("Unexpected key {other}")));
                }
            }
        }
        Ok(query)
    }
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
    obj["walletconflicts"] = json!([]);
    obj["bip125-replaceable"] = json!(bip125_replaceable(e));
    // Core's WalletTxToJSON: a mined transaction carries its block fields, an unmined one
    // carries `trusted` instead - true only when the wallet funded it (the same trust rule
    // `listunspent` applies: a foreign 0-conf receive is untrusted).
    if let (Some(hash), Some(height)) = (&e.blockhash, e.height) {
        obj["blockhash"] = json!(hash);
        obj["blockheight"] = json!(height);
        obj["blocktime"] = json!(e.time);
    } else {
        obj["trusted"] = json!(e.fee_sat.is_some());
    }
    obj
}

async fn listtransactions(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    // The label argument is meaningless in a stateless wallet: only "*" (or omitted) is
    // accepted, exactly as the Zcash handler treats it.
    if let Some(label) = opt_str(req, 0) {
        if !label.is_empty() && label != "*" {
            return Err(RpcError::invalid_parameter(
                "labels are not supported (rose is stateless); pass \"*\" or omit the label",
            ));
        }
    }
    // Shared with the Zcash handler: a negative count/skip is -8, a non-number -3.
    let (count, skip) = count_from_params(req, 1, 2)?;
    // The actor applies Core's pagination over the per-output entries (a change-only
    // transaction contributes none): skip from the newest end, up to `count`, oldest
    // first - building only that window. Each record comes back holding exactly the
    // entries inside it, so this is a flatten, not a slice.
    let records = handle.list_transactions(count, skip).await?;
    let entries: Vec<Value> = records
        .iter()
        .flat_map(|e| e.details.iter().map(move |d| tx_entry_json(e, d)))
        .collect();
    Ok(Value::Array(entries))
}

async fn gettransaction(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    let Some(txid) = opt_str(req, 0) else {
        return Err(RpcError::invalid_parameter("txid is required"));
    };
    // A malformed txid is Core's -8 (`ParseHashV`), as on `abandontransaction`; only a
    // well-formed one the wallet does not hold is -5.
    let txid = parse_txid(&txid)?.to_string();
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
        "walletconflicts": [],
        "details": details,
        "hex": entry.hex,
    });
    if let Some(fee) = entry.fee_sat {
        obj["fee"] = signed_zats_to_value(-i64::try_from(fee).unwrap_or(i64::MAX));
    }
    if let (Some(hash), Some(height)) = (&entry.blockhash, entry.height) {
        obj["blocktime"] = json!(entry.time);
        obj["blockhash"] = json!(hash);
        obj["blockheight"] = json!(height);
    }
    Ok(obj)
}

/// `listreceivedbyaddress [minconf] [include_empty] [include_watchonly] [address_filter]
/// [include_immature_coinbase]` - Core's shape over the wallet's receiving addresses, the same
/// semantics as the Zcash handler: change is never counted, `label` is always `""`,
/// `include_watchonly` is accepted and ignored (watch-only is wallet-level), and
/// `include_immature_coinbase` is accepted and ignored (an address this wallet hands out is
/// never a coinbase destination). `include_empty` unions every address the wallet has ever
/// revealed, which makes `listreceivedbyaddress 0 true` the enumeration of the issued set -
/// Core has no `listaddresses` either. Each entry carries rose's `address_index` extension,
/// the external-keychain derivation index `getaddressinfo` reports as `address_index`, so a
/// caller reconciling an issued range never needs one `getaddressinfo` per address.
/// Entries ascend by index. A filter naming an address that is not the wallet's answers `[]`.
async fn listreceivedbyaddress(
    handle: &BtcWalletHandle,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let minconf = depth(req.param(0), "minconf", 1)?;
    let flag = |v: Option<&Value>, name: &str| -> Result<bool, RpcError> {
        match v {
            None | Some(Value::Null) => Ok(false),
            Some(Value::Bool(b)) => Ok(*b),
            Some(_) => Err(RpcError::type_error(format!("{name} must be a boolean"))),
        }
    };
    let include_empty = flag(req.param(1), "include_empty")?;
    let _include_watchonly = flag(req.param(2), "include_watchonly")?;
    let filter = match req.param(3) {
        None | Some(Value::Null) => None,
        Some(Value::String(a)) => {
            // The actor's parse enforces validity and the wallet's network, as Core does
            // before matching (an invalid filter is an error, a foreign one matches nothing).
            handle.address_info(a.clone()).await?;
            Some(a.clone())
        }
        Some(_) => return Err(RpcError::type_error("address_filter must be a string")),
    };
    let include_immature_coinbase = flag(req.param(4), "include_immature_coinbase")?;
    let entries: Vec<Value> = handle
        .received_by_address()
        .await?
        .into_iter()
        .filter(|a| filter.as_deref().is_none_or(|f| f == a.address))
        .filter_map(|a| {
            let counted: Vec<&BtcReceipt> = a
                .receipts
                .iter()
                .filter(|r| {
                    r.confirmations >= minconf && (include_immature_coinbase || !r.immature)
                })
                .collect();
            if counted.is_empty() && !include_empty {
                return None;
            }
            let amount: u64 = counted.iter().map(|r| r.amount_sat).sum();
            let confirmations = counted.iter().map(|r| r.confirmations).min().unwrap_or(0);
            let mut txids: Vec<&str> = counted.iter().map(|r| r.txid.as_str()).collect();
            txids.dedup();
            Some(json!({
                "address": a.address,
                "amount": zats_to_value(amount),
                "confirmations": confirmations,
                "label": "",
                "txids": txids,
                "address_index": a.index,
            }))
        })
        .collect();
    Ok(Value::Array(entries))
}

/// `listdescriptors [private]` - Bitcoin Core's shape: the wallet's two public descriptors
/// (receiving `/0/*`, change `/1/*`), each with its next unused index and the range the
/// wallet watches. This is where the account xpub is read over RPC (`rose export-xpub` is
/// the offline route). `private = true` is refused with `-4`: the database holds public
/// descriptors only and the seed never leaves the process, so there is no private
/// descriptor to return - Core answers a private-keys-disabled wallet the same way.
async fn listdescriptors(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    match req.param(0) {
        None | Some(Value::Null) | Some(Value::Bool(false)) => {}
        Some(Value::Bool(true)) => {
            return Err(RpcError::wallet(
                "Private descriptors are not available over RPC: the wallet database holds \
                 public descriptors only and the seed never leaves the process (the mnemonic \
                 in keys.toml is the private backup)",
            ))
        }
        Some(_) => return Err(RpcError::type_error("private must be a boolean")),
    }
    let descriptors: Vec<Value> = handle
        .descriptors()
        .await?
        .into_iter()
        .map(|d| {
            json!({
                "desc": d.desc,
                "timestamp": d.timestamp,
                "active": true,
                "internal": d.internal,
                "range": [0, d.range_end],
                "next": d.next_index,
                "next_index": d.next_index,
            })
        })
        .collect();
    Ok(json!({
        "wallet_name": handle.name,
        "descriptors": descriptors,
    }))
}

async fn sendtoaddress(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    let addr = req.require_str(0, "sendtoaddress requires an address")?;
    let amount = match req.param(1) {
        None | Some(Value::Null) => {
            return Err(RpcError::missing_param("sendtoaddress requires an amount"))
        }
        Some(v) => value_to_zats(v)?,
    };
    // Params 2/3 (comment, comment_to) are metadata and safe to ignore (rose is stateless).
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
    // Param 11 is the Zcash engine's memo extension; a Bitcoin output carries none, and
    // dropping one silently would lose what the caller meant to send.
    if req
        .param(11)
        .is_some_and(|v| !v.is_null() && v.as_str() != Some(""))
    {
        return Err(RpcError::invalid_parameter(
            "memo is not supported (a Bitcoin output carries no memo)",
        ));
    }
    let subtract_fee_from = if subtract { vec![0] } else { Vec::new() };
    let options = BtcSendOptions {
        fee_rate_sat_per_kvb: parse_fee_rate(req.param(9))?,
        fee_split: parse_fee_split(req.param(12), &subtract_fee_from)?,
        subtract_fee_from,
        non_replaceable: !parse_replaceable(req.param(5))?,
    };
    // Param 10 (verbose) is validated before the send, so a malformed flag never moves funds.
    let verbose = parse_verbose(req.param(10))?;
    let sent = handle
        .send(vec![(addr.to_string(), amount)], options)
        .await?;
    Ok(send_result(sent, verbose))
}

/// Parse rose's `fee_split` extension (position 12 on `sendtoaddress`, 10 on `sendmany`):
/// how the recipients named to pay the fee share it. `"equal"` (or absent) is Core's
/// `subtractfeefrom`: the whole fee, divided equally. `"output"` charges each paying
/// recipient only its own output's block space at the send's rate, and the sender's change
/// pays the rest (inputs, overhead, change, unconfirmed parents). An unknown value is `-8`,
/// and so is `"output"` with no paying recipient, which would otherwise change nothing
/// without saying so.
fn parse_fee_split(v: Option<&Value>, payers: &[usize]) -> Result<BtcFeeSplit, RpcError> {
    let split = match v {
        None | Some(Value::Null) => return Ok(BtcFeeSplit::Equal),
        Some(Value::String(s)) => match s.as_str() {
            "" | "equal" => BtcFeeSplit::Equal,
            "output" => BtcFeeSplit::Output,
            other => {
                return Err(RpcError::invalid_parameter(format!(
                    "Invalid fee_split \"{other}\" (expected \"equal\" or \"output\")"
                )))
            }
        },
        Some(_) => return Err(RpcError::type_error("fee_split must be a string")),
    };
    if split == BtcFeeSplit::Output && payers.is_empty() {
        return Err(RpcError::invalid_parameter(
            "fee_split \"output\" needs recipients that pay the fee (subtractfeefromamount / \
             subtractfeefrom)",
        ));
    }
    Ok(split)
}

/// Parse the optional `verbose` flag of the send methods (position 10 on `sendtoaddress`, 9
/// on `sendmany`, Core's layouts).
fn parse_verbose(v: Option<&Value>) -> Result<bool, RpcError> {
    match v {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(RpcError::type_error("verbose must be a boolean")),
    }
}

/// A send's answer: the bare txid, or Core's `{txid, fee_reason}` object under `verbose`.
fn send_result(sent: BtcSent, verbose: bool) -> Value {
    if verbose {
        json!({"txid": sent.txid, "fee_reason": sent.fee_reason})
    } else {
        Value::String(sent.txid)
    }
}

/// Parse an optional `fee_rate` parameter (sat/vB) into sat/kvB, `None` when disengaged.
/// A rate below the 1 sat/vB relay floor is refused up front, as Core refuses one below
/// `minrelaytxfee`: a send priced under the floor builds a transaction no node relays -
/// on bitcoind that fails late at broadcast, and over kyoto a peer's `getdata` counts as
/// broadcast success, so the unminable transaction would be recorded at 0-conf with its
/// inputs locked behind it until a `bumpfee` or `abandontransaction` freed them.
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

/// Parse the optional `replaceable` parameter (position 5 on both send methods): whether
/// the send signals BIP 125 replaceability. Omitted or `null` is `true` - BDK's default,
/// and Core's `-walletrbf` default. `false` is honored (every input gets a final-but-for-
/// locktime `nSequence`), never ignored: a caller who asked for a non-replaceable send and
/// got an RBF one would read `bip125-replaceable: "yes"` back on a transaction it meant
/// the recipient to be able to trust at 0-conf.
fn parse_replaceable(v: Option<&Value>) -> Result<bool, RpcError> {
    match v {
        None | Some(Value::Null) => Ok(true),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(RpcError::type_error("replaceable must be a boolean")),
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
        fee_split: parse_fee_split(req.param(10), &subtract_fee_from)?,
        subtract_fee_from,
        non_replaceable: !parse_replaceable(req.param(5))?,
    };
    let verbose = parse_verbose(req.param(9))?;
    let sent = handle.send(recipients, options).await?;
    Ok(send_result(sent, verbose))
}

async fn sendrawtransaction(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    let hex = req.require_str(0, "sendrawtransaction requires a hex string")?;
    let max_fee_rate = parse_max_fee_rate(req.param(1))?;
    let txid = handle.broadcast(hex.to_string(), max_fee_rate).await?;
    Ok(Value::String(txid))
}

/// Bitcoin Core's `DEFAULT_MAX_RAW_TX_FEE_RATE` (0.10 BTC/kvB), in sat/kvB: the
/// `sendrawtransaction` fee-rate cap when the caller names none.
const DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB: u64 = 10_000_000;

/// Parse `sendrawtransaction`'s `maxfeerate` (BTC/kvB) into sat/kvB, Core's `ParseFeeRate`:
/// omitted or `null` is the 0.10 BTC/kvB default, `0` disables the check, and the amount
/// errors are `AmountFromValue`'s (`-3` for a non-number, a malformed literal or a negative
/// value). A rate at or above 1 BTC/kvB is Core's `-8`: it would not bound anything.
fn parse_max_fee_rate(v: Option<&Value>) -> Result<u64, RpcError> {
    match v {
        None | Some(Value::Null) => Ok(DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB),
        Some(v) => {
            let sat_per_kvb = value_to_zats(v)?;
            if sat_per_kvb >= crate::amount::COIN {
                return Err(RpcError::invalid_parameter(
                    "Fee rates larger than or equal to 1BTC/kvB are not accepted",
                ));
            }
            Ok(sat_per_kvb)
        }
    }
}

/// `abandontransaction "txid"` - Core's shape and codes: `null` on success; a malformed txid
/// is `-8` (Core's `ParseHashV` messages), an unknown one `-5` "Invalid or non-wallet
/// transaction id", a confirmed or mempool-held one `-5` "Transaction not eligible for
/// abandonment". The wallet-side rules, and the kyoto caveat (no mempool view to check
/// against), are on `btc::actor::BtcActor::do_abandon`.
async fn abandontransaction(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    let txid = parse_txid(req.require_str(0, "txid is required")?)?;
    handle.abandon_transaction(txid).await?;
    Ok(Value::Null)
}

/// `bumpfee "txid" ( options )` - Bitcoin Core's shape: `{txid, origfee, fee, errors}`, the
/// fees in BTC and `errors` always empty (Core's field for warnings it no longer emits). The
/// options object takes Core's keys, strictly - an unknown key is Core's `-3` "Unexpected
/// key": `fee_rate` (sat/vB, the relay floor refused up front as on the send methods) and
/// `replaceable` are honored; `conf_target`/`estimate_mode` are refused when engaged, as on
/// the send methods (the wallet estimates at one fixed target); `outputs` and
/// `original_change_index` (Core's reduce-an-output bump) are refused rather than ignored.
/// Preconditions, fee rules and codes: `btc::actor::BtcActor::do_bump_fee`.
async fn bumpfee(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    let txid = parse_txid(req.require_str(0, "txid is required")?)?;
    let options = match req.param(1) {
        None | Some(Value::Null) => serde_json::Map::new(),
        Some(Value::Object(map)) => map.clone(),
        Some(_) => return Err(RpcError::type_error("options must be an object")),
    };
    const KNOWN: &[&str] = &[
        "conf_target",
        "fee_rate",
        "replaceable",
        "estimate_mode",
        "outputs",
        "original_change_index",
    ];
    if let Some(key) = options.keys().find(|k| !KNOWN.contains(&k.as_str())) {
        return Err(RpcError::type_error(format!("Unexpected key {key}")));
    }
    if options.get("conf_target").is_some_and(|v| !v.is_null()) {
        return Err(RpcError::invalid_parameter(
            "conf_target is not supported (the wallet estimates at a fixed target; pass an \
             explicit fee_rate to price the bump yourself)",
        ));
    }
    match options.get("estimate_mode") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) if s.is_empty() || s.eq_ignore_ascii_case("unset") => {}
        Some(_) => {
            return Err(RpcError::invalid_parameter(
                "estimate_mode is not supported (the wallet estimates at a fixed target; \
                 pass an explicit fee_rate to price the bump yourself)",
            ))
        }
    }
    for key in ["outputs", "original_change_index"] {
        if options.get(key).is_some_and(|v| !v.is_null()) {
            return Err(RpcError::invalid_parameter(format!(
                "{key} is not supported: a bump keeps every recipient output and takes the \
                 higher fee from the change (or from added inputs)"
            )));
        }
    }
    let options = BtcBumpOptions {
        fee_rate_sat_per_kvb: parse_fee_rate(options.get("fee_rate"))?,
        non_replaceable: !parse_replaceable(options.get("replaceable"))?,
    };
    let bumped = handle.bump_fee(txid, options).await?;
    Ok(json!({
        "txid": bumped.txid,
        "origfee": zats_to_value(bumped.orig_fee_sat),
        "fee": zats_to_value(bumped.fee_sat),
        "errors": [],
    }))
}

/// A txid argument, with Core's `ParseHashV` messages and code (`-8`): the wrong length and
/// non-hex are refused before anything looks the transaction up.
fn parse_txid(txid: &str) -> Result<Txid, RpcError> {
    if txid.len() != 64 {
        return Err(RpcError::invalid_parameter(format!(
            "txid must be of length 64 (not {}, for '{txid}')",
            txid.len()
        )));
    }
    Txid::from_str(txid).map_err(|_| {
        RpcError::invalid_parameter(format!("txid must be hexadecimal string (not '{txid}')"))
    })
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
        // Stateless: no labels, ever - but the field is Core's shape.
        "labels": [],
    });
    // The actor's parse already accepted it for this network, so this cannot fail.
    if let Ok(parsed) = parse_address(&address, handle.network) {
        address_fields(&parsed, &mut obj);
    }
    if let Some(key) = &info.key {
        obj["pubkey"] = json!(key.pubkey);
        obj["desc"] = json!(key.desc);
        obj["hdmasterfingerprint"] = json!(key.fingerprint);
    }
    if let Some((change, index)) = info.derivation {
        let coin_type = match handle.network {
            BitcoinNetwork::Main => 0,
            BitcoinNetwork::Testnet3 | BitcoinNetwork::Testnet4 | BitcoinNetwork::Regtest => 1,
        };
        obj["hdkeypath"] = Value::String(format!(
            "m/84'/{coin_type}'/0'/{}/{index}",
            if change { 1 } else { 0 }
        ));
        // The same rose extension the Zcash handler exposes for transparent addresses: the
        // child index, so an operator can reconcile issued ranges without parsing the path.
        obj["address_index"] = json!(index);
    }
    Ok(obj)
}

async fn validateaddress(handle: &BtcWalletHandle, req: &RpcRequest) -> Result<Value, RpcError> {
    let Some(address) = opt_str(req, 0) else {
        return Err(RpcError::invalid_parameter("address is required"));
    };
    // Valid means valid for the wallet's own network, exactly what Core answers; a parse
    // failure is `isvalid: false` with Core's `error`/`error_locations`, never an RPC error.
    // Pure address arithmetic - no wallet state is consulted, so the actor is not involved.
    match parse_address(&address, handle.network) {
        Ok(parsed) => {
            let mut obj = json!({ "isvalid": true, "address": address });
            address_fields(&parsed, &mut obj);
            Ok(obj)
        }
        Err(error) => Ok(json!({ "isvalid": false, "error_locations": [], "error": error })),
    }
}

/// Parse an address for the wallet's network, answering Core's `validateaddress` wording
/// for the two ways it fails.
fn parse_address(
    address: &str,
    network: BitcoinNetwork,
) -> Result<bdk_wallet::bitcoin::Address, String> {
    let unchecked = bdk_wallet::bitcoin::Address::from_str(address)
        .map_err(|_| "Invalid or unsupported Segwit (Bech32) or Base58 encoding.".to_string())?;
    unchecked
        .require_network(crate::btc::keys::network(network))
        .map_err(|_| "Invalid chain prefix".to_string())
}

/// The address-derived fields `validateaddress` and `getaddressinfo` share, Core's
/// `DescribeAddress`: the script, and what kind of output it is.
fn address_fields(address: &bdk_wallet::bitcoin::Address, obj: &mut Value) {
    use bdk_wallet::bitcoin::AddressType;
    let spk = address.script_pubkey();
    obj["scriptPubKey"] = json!(spk.to_hex_string());
    obj["isscript"] = json!(matches!(
        address.address_type(),
        Some(AddressType::P2sh | AddressType::P2wsh | AddressType::P2tr)
    ));
    match address.witness_program() {
        Some(program) => {
            obj["iswitness"] = json!(true);
            obj["witness_version"] = json!(program.version().to_num());
            obj["witness_program"] = json!(program
                .program()
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>());
        }
        None => obj["iswitness"] = json!(false),
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

    /// `getwalletinfo.scanning` and `mempool_feed.snapshot_progress` from the status: Core's
    /// `false` at tip; while syncing the catch-up's fraction, heights and duration, with the
    /// wallet's own height and no tip when no connection is running one; and the snapshot
    /// being collected with its elapsed time, null between snapshots.
    #[test]
    fn scanning_and_snapshot_progress_report_the_two_waits() {
        use crate::btc::actor::{
            BtcConnState, BtcSyncStatus, MempoolFeedStatus, ScanProgress, SendGateStatus,
        };
        use crate::btc::mempool_feed::SnapshotProgress;
        use serde_json::json;
        let status = |conn_state, scan| BtcSyncStatus {
            conn_state,
            synced_height: 1_000,
            synced_hash: String::new(),
            birthday_anchor: None,
            birthday_block_time: None,
            scan,
            mempool_feed: None,
            send_gate: SendGateStatus {
                open: true,
                reason: None,
                history: "fresh",
                allow_sends_without_mempool_view: false,
            },
        };
        let scan = ScanProgress {
            from: 1_000,
            height: 1_050,
            tip: Some(1_200),
            started: 5_000,
        };
        assert_eq!(
            super::scanning_json(&status(BtcConnState::Ready, Some(scan.clone())), 5_030),
            json!(false)
        );
        assert_eq!(
            super::scanning_json(&status(BtcConnState::Down, None), 5_030),
            json!(false)
        );
        assert_eq!(
            super::scanning_json(&status(BtcConnState::Syncing, Some(scan.clone())), 5_030),
            json!({ "duration": 30, "progress": 0.25, "height": 1_050, "tip": 1_200 })
        );
        assert_eq!(
            super::scanning_json(&status(BtcConnState::Syncing, None), 5_030),
            json!({ "duration": 0, "progress": 0.0, "height": 1_000, "tip": null })
        );
        // A kyoto estimate behind the wallet's own checkpoint never reads below it.
        let behind = ScanProgress {
            height: 900,
            tip: None,
            ..scan
        };
        let v = super::scanning_json(&status(BtcConnState::Syncing, Some(behind)), 5_000);
        assert_eq!(v["height"], json!(1_000));
        assert_eq!(v["tip"], json!(null));
        assert_eq!(v["progress"], json!(0.0));

        let mut feed = MempoolFeedStatus {
            source: "p2p",
            endpoint: "p2p://127.0.0.1:1".into(),
            connected: true,
            last_delta: None,
            deltas: 0,
            matched: 0,
            dropped: 0,
            snapshot_applied: Some(false),
            peer_bloom: Some(true),
            snapshot_progress: None,
        };
        assert_eq!(super::snapshot_progress_json(&feed, 5_000), json!(null));
        feed.snapshot_progress = Some(SnapshotProgress {
            announced: 120,
            pending: 20,
            requested_at: 4_990,
            window_secs: 30,
        });
        assert_eq!(
            super::snapshot_progress_json(&feed, 5_000),
            json!({
                "announced": 120,
                "pending": 20,
                "requested_at": 4_990,
                "elapsed": 10,
                "window": 30,
            })
        );
    }

    /// `sendrawtransaction`'s `maxfeerate` parses as Core's `ParseFeeRate`: BTC/kvB to
    /// sat/kvB, Core's 0.10 default when omitted or null, `0` kept (it disables the check),
    /// `AmountFromValue`'s `-3`s, and `-8` at or above 1 BTC/kvB.
    #[test]
    fn maxfeerate_parses_like_core() {
        use crate::error::codes;
        use serde_json::json;
        let parse = |v: serde_json::Value| super::parse_max_fee_rate(Some(&v));
        assert_eq!(super::parse_max_fee_rate(None).unwrap(), 10_000_000);
        assert_eq!(parse(json!(null)).unwrap(), 10_000_000);
        assert_eq!(parse(json!(0)).unwrap(), 0);
        assert_eq!(parse(json!(0.01)).unwrap(), 1_000_000);
        assert_eq!(parse(json!("0.00001")).unwrap(), 1_000);
        assert_eq!(parse(json!(0.99999999)).unwrap(), 99_999_999);
        for bad in [json!(-0.1), json!("abc"), json!(true), json!(0.000000001)] {
            assert_eq!(
                parse(bad.clone()).unwrap_err().code,
                codes::RPC_TYPE_ERROR,
                "{bad}"
            );
        }
        let err = parse(json!(1)).unwrap_err();
        assert_eq!(err.code, codes::RPC_INVALID_PARAMETER);
        assert!(err.message.contains("1BTC/kvB"), "{}", err.message);
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
        let conf = dir.path().join("rose.toml");
        std::fs::write(
            &conf,
            format!(
                "network = \"test\"\ndatadir = {:?}\ndefault_wallet = \"btc\"\n\
                 [wallets.btc]\ncoin = \"bitcoin\"\n",
                dir.path()
            ),
        )
        .unwrap();
        let cli = crate::config::Cli::parse_from(["rose", "--conf", conf.to_str().unwrap()]);
        let config = crate::config::AppConfig::resolve(&cli).unwrap();
        let entry = &config.wallets["btc"];
        let (handle, _task) = crate::btc::actor::spawn(crate::btc::actor::BtcActorConfig {
            name: "btc".to_string(),
            engine_dir: entry.engine_dir(),
            network: entry.bitcoin_network(),
            seed: Some(bip84_seed()),
            wallet_holds_seed: true,
            encrypted: false,
            keys_path: entry.keys_path(),
            imported_keys: Some(
                crate::btc::keys::AccountKeys::from_seed(&bip84_seed(), entry.bitcoin_network())
                    .unwrap(),
            ),
            endpoint: None,
            fees: crate::config::FeesConfig::default(),
            mempool: crate::config::MempoolConfig::default(),
            birthday: 0,
            birthday_time: None,
            lookahead: crate::btc::actor::DEFAULT_LOOKAHEAD,
            initial_scan: 0,
            allow_sends_without_mempool_view: false,
            sync_interval: std::time::Duration::from_secs(20),
            reconnect_base: std::time::Duration::from_secs(1),
            reconnect_max: std::time::Duration::from_secs(60),
            shutdown: tokio::sync::watch::channel(false).1,
        })
        .unwrap();
        let registry = WalletRegistry::new("btc".to_string());
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
            #[cfg(feature = "zcash")]
            fleet: None,
            #[cfg(feature = "zcash")]
            spend_limits: crate::config::SpendLimits::new(&crate::config::SpendConfig::default()),
        };
        let call = |method: &str, params: Vec<Value>| {
            let req = RpcRequest::positional(method.to_string(), params);
            let state = &state;
            async move { crate::rpc::dispatch(state, None, &req).await }
        };

        let address = call("getnewaddress", vec![]).await.unwrap();
        let address = address.as_str().unwrap().to_string();
        assert!(address.starts_with("tb1"), "{address}");

        // Amounts are bare 8-decimal JSON numbers, like every rose balance.
        let balance = call("getbalance", vec![]).await.unwrap();
        assert_eq!(balance.to_string(), "0.00000000");
        let balances = call("getbalances", vec![]).await.unwrap();
        assert_eq!(balances["mine"]["trusted"].to_string(), "0.00000000");

        let info = call("getwalletinfo", vec![]).await.unwrap();
        assert_eq!(info["coin"], json!("bitcoin"));
        // The birthday object, in the shape both engines share: the recorded height, no
        // kept date, and no anchor on a wallet that has never resolved one.
        assert_eq!(
            info["birthday"],
            json!({ "height": 0, "time": null, "anchor": null })
        );
        assert_eq!(info["private_keys_enabled"], json!(true));
        assert_eq!(info["descriptors"], json!(true));
        // Unencrypted: Core omits `unlocked_until` entirely.
        assert!(info.get("unlocked_until").is_none(), "{info}");
        assert_eq!(info["scanning"], json!(false));
        // The wallet's own chain view: a fresh wallet sits at its genesis checkpoint, and
        // getblockcount/getbestblockhash answer from the same authority.
        assert_eq!(info["lastprocessedblock"]["height"], json!(0));
        // No `[mempool]` section: the feed reports itself disabled rather than absent, so a
        // client can tell "nothing detected" from "nothing could be".
        assert_eq!(info["mempool_feed"], json!({ "state": "disabled" }));
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

        // Core's getaddressinfo fields for an own address: the script and output kind,
        // the owning key (BIP 84 path in the inferred descriptor, with its checksum), and
        // the stateless empty labels.
        assert_eq!(addr_info["labels"], json!([]));
        assert_eq!(addr_info["iswitness"], json!(true));
        assert_eq!(addr_info["witness_version"], json!(0));
        assert_eq!(addr_info["isscript"], json!(false));
        let spk = addr_info["scriptPubKey"].as_str().unwrap();
        assert!(spk.starts_with("0014") && spk.len() == 44, "{spk}");
        assert_eq!(addr_info["witness_program"].as_str().unwrap(), &spk[4..]);
        let desc = addr_info["desc"].as_str().unwrap();
        let pubkey = addr_info["pubkey"].as_str().unwrap();
        assert!(desc.starts_with("wpkh(["), "{desc}");
        assert!(desc.contains("/84'/1'/0'/0/0]"), "{desc}");
        assert!(desc.contains(pubkey), "{desc} vs {pubkey}");
        assert!(
            desc.contains(")#"),
            "the descriptor carries its checksum: {desc}"
        );

        let valid = call("validateaddress", vec![json!(address.clone())])
            .await
            .unwrap();
        assert_eq!(valid["isvalid"], json!(true));
        assert_eq!(valid["scriptPubKey"], json!(spk));
        assert_eq!(valid["iswitness"], json!(true));
        let invalid = call("validateaddress", vec![json!("not-an-address")])
            .await
            .unwrap();
        assert_eq!(invalid["isvalid"], json!(false));
        assert!(invalid["error"].is_string(), "{invalid}");
        assert_eq!(invalid["error_locations"], json!([]));
        // A mainnet address on this testnet wallet is invalid, naming the chain.
        let foreign = call(
            "validateaddress",
            vec![json!("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")],
        )
        .await
        .unwrap();
        assert_eq!(foreign["isvalid"], json!(false));
        assert_eq!(foreign["error"], json!("Invalid chain prefix"));

        // gettransaction: a malformed txid is -8 (Core's ParseHashV), a well-formed
        // unknown one -5.
        let err = call("gettransaction", vec![json!("zz")]).await.unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_PARAMETER);
        let err = call("gettransaction", vec![json!("00".repeat(32))])
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_ADDRESS_OR_KEY);

        // The chain and network reads a Bitcoin wallet now serves, from its own view.
        let chain = call("getblockchaininfo", vec![]).await.unwrap();
        assert_eq!(chain["chain"], json!("test"));
        assert_eq!(chain["blocks"], json!(0));
        let net = call("getnetworkinfo", vec![]).await.unwrap();
        assert_eq!(net["connections"], json!(0), "no upstream here: {net}");
        // Nothing received, nothing since genesis, and the cursor is the wallet's tip.
        assert_eq!(
            call("getreceivedbyaddress", vec![json!(address.clone())])
                .await
                .unwrap()
                .to_string(),
            "0.00000000"
        );
        let err = call(
            "getreceivedbyaddress",
            vec![json!("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")],
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_WALLET_ERROR);
        let since = call("listsinceblock", vec![]).await.unwrap();
        assert_eq!(since["transactions"], json!([]));
        assert_eq!(since["removed"], json!([]));
        assert_eq!(since["lastblock"], info["lastprocessedblock"]["hash"]);
        let err = call("listsinceblock", vec![json!("nothex")])
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_ADDRESS_OR_KEY);
        // estimatesmartfee validates Core's target range before needing an upstream.
        let err = call("estimatesmartfee", vec![json!(0)]).await.unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_PARAMETER);
        let err = call("estimatesmartfee", vec![json!(6), json!("fastest")])
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_PARAMETER);

        // listunspent's query_options: unknown keys are refused, known ones accepted.
        let err = call(
            "listunspent",
            vec![
                json!(0),
                json!(null),
                json!(null),
                json!(null),
                json!({"bogus": 1}),
            ],
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_TYPE_ERROR);
        let unspent = call(
            "listunspent",
            vec![
                json!(0),
                json!(null),
                json!(null),
                json!(null),
                json!({"minimumAmount": 0.001, "maximumCount": 5}),
            ],
        )
        .await
        .unwrap();
        assert_eq!(unspent, json!([]));

        // The wallet-independent shell answers regardless of coin.
        assert_eq!(call("listwallets", vec![]).await.unwrap(), json!(["btc"]));
        // So do the registry operations, with the contract conformance.py's shared "wallets"
        // section asserts: createwallet's parameter refusals are -8 in every build, and the
        // configured wallet is refused an unload (-4) rather than dropped. A bitcoin-only build
        // answered all of them -32601 when their arms were gated on the Zcash engine.
        let code = |r: Result<Value, crate::error::RpcError>| r.unwrap_err().code;
        use crate::error::codes::{RPC_INVALID_PARAMETER, RPC_WALLET_ERROR, RPC_WALLET_NOT_FOUND};
        assert_eq!(
            code(call("createwallet", vec![]).await),
            RPC_INVALID_PARAMETER
        );
        assert_eq!(
            code(call("createwallet", vec![json!("tmp")]).await),
            RPC_INVALID_PARAMETER
        );
        assert_eq!(
            code(call("createwallet", vec![json!("tmp"), json!(false)]).await),
            RPC_INVALID_PARAMETER
        );
        let mut full = vec![json!("tmp"), json!(true)];
        full.extend(std::iter::repeat_n(Value::Null, 6));
        full.push(json!({ "ufvk": "uview1x", "birthday": 1 }));
        assert_eq!(code(call("createwallet", full).await), RPC_WALLET_ERROR);
        assert_eq!(
            code(call("unloadwallet", vec![json!("btc")]).await),
            RPC_WALLET_ERROR
        );
        assert_eq!(
            code(call("unloadwallet", vec![json!("nope")]).await),
            RPC_WALLET_NOT_FOUND
        );
        assert_eq!(
            code(call("loadwallet", vec![json!("nope")]).await),
            RPC_WALLET_ERROR
        );
        assert_eq!(call("listwallets", vec![]).await.unwrap(), json!(["btc"]));

        // Everything the engine does not serve reads as method-not-found: a Zcash-dialect
        // node read, message signing, and a z_* extension alike.
        for gated in ["getrawtransaction", "signmessage", "z_sendmany"] {
            let err = call(gated, vec![]).await.unwrap_err();
            assert_eq!(
                err.code,
                crate::error::codes::RPC_METHOD_NOT_FOUND,
                "{gated} must 404 for a bitcoin wallet"
            );
        }

        // The passphrase surface is served (Core's semantics, the Zcash handler's argument
        // rules): malformed arguments are refused before the wallet is consulted, and on an
        // unencrypted wallet both calls are the wrong-encryption-state error.
        for (params, expected) in [
            (
                vec![json!("x"), json!(-1)],
                crate::error::codes::RPC_INVALID_PARAMETER,
            ),
            (
                vec![json!(""), json!(60)],
                crate::error::codes::RPC_INVALID_PARAMETER,
            ),
            (
                vec![json!("x"), json!("soon")],
                crate::error::codes::RPC_INVALID_PARAMETER,
            ),
            (
                vec![json!("x"), json!(60)],
                crate::error::codes::RPC_WALLET_WRONG_ENC_STATE,
            ),
        ] {
            assert_eq!(
                code(call("walletpassphrase", params.clone()).await),
                expected,
                "walletpassphrase {params:?}"
            );
        }
        assert_eq!(
            code(call("walletlock", vec![]).await),
            crate::error::codes::RPC_WALLET_WRONG_ENC_STATE
        );

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
