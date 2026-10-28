//! Network RPCs: getnetworkinfo, getconnectioncount, ping, getpeerinfo.

use serde_json::{json, Value};

use crate::amount::zats_to_value;
use crate::error::RpcError;
use crate::state::AppState;

fn connected(state: &AppState) -> bool {
    // The Zcash upstream's connection state, which is what this dialect's `getnetworkinfo`
    // reports. A Bitcoin default wallet has always read as disconnected here (`get` refused
    // it); in a build with no Zcash engine every wallet is that case.
    #[cfg(feature = "zcash")]
    {
        state
            .registry
            .get(None)
            .map(|w| w.status().connected)
            .unwrap_or(false)
    }
    #[cfg(not(feature = "zcash"))]
    {
        let _ = state;
        false
    }
}

/// What a Bitcoin wallet's `getnetworkinfo` reports as `protocolversion`: the ZIP 204 value is
/// a Zcash notion, so the Bitcoin engine keeps the fixed value it has always reported.
#[cfg(any(feature = "bitcoin", not(feature = "zcash")))]
pub(crate) const BITCOIN_PROTOCOL_VERSION: u32 = 170100;

/// rose's own version in Bitcoin Core's numeric encoding (major*10000 + minor*100 + patch),
/// derived from Cargo.toml so it can't drift from the crate version.
fn version_number() -> u64 {
    // Each component's leading digit run, so a pre-release suffix (e.g. "0-rc0") still encodes.
    let mut parts = env!("CARGO_PKG_VERSION").split('.').map(|p| {
        p.split(|c: char| !c.is_ascii_digit())
            .next()
            .unwrap_or("")
            .parse::<u64>()
            .unwrap_or(0)
    });
    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    let patch = parts.next().unwrap_or(0);
    major * 10000 + minor * 100 + patch
}

/// `getnetworkinfo` - daemon version/identity in Bitcoin Core's shape; `connections` counts
/// the single chain upstream (1 when connected, 0 otherwise). That upstream is a local zebrad in
/// the default full mode, a lightwalletd in light mode; nothing here depends on which.
/// `protocolversion` is the ZIP 204 version of the newest upgrade this build schedules on the
/// daemon's network (`ZNetwork::protocol_version`), so it moves with the consensus rules the
/// build actually follows rather than staying at whatever a release once hard-coded.
pub(crate) fn getnetworkinfo(state: &AppState) -> Result<Value, RpcError> {
    // The ZIP 204 version is the Zcash engine's; a build without it reports the fixed value
    // the Bitcoin engine does.
    #[cfg(feature = "zcash")]
    let protocolversion = state.config.network.protocol_version();
    #[cfg(not(feature = "zcash"))]
    let protocolversion = BITCOIN_PROTOCOL_VERSION;
    Ok(networkinfo_json(connected(state), protocolversion))
}

/// The `getnetworkinfo` object, given whether the wallet's upstream is connected and the
/// protocol version to report - shared with the Bitcoin engine's handler, so both report the
/// same shape (the Bitcoin handler passes [`BITCOIN_PROTOCOL_VERSION`]).
pub(crate) fn networkinfo_json(up: bool, protocolversion: u32) -> Value {
    json!({
        "version": version_number(),
        "subversion": format!("/rose:{}/", env!("CARGO_PKG_VERSION")),
        "protocolversion": protocolversion,
        "localservices": "0000000000000000",
        "localservicesnames": [],
        "localrelay": false,
        "timeoffset": 0,
        "networkactive": true,
        "connections": if up { 1 } else { 0 },
        "connections_in": 0,
        "connections_out": if up { 1 } else { 0 },
        "networks": [],
        "relayfee": zats_to_value(1000),
        "incrementalfee": zats_to_value(1000),
        "localaddresses": [],
        "warnings": ""
    })
}

/// `getconnectioncount` - 1 while the chain upstream (zebrad or lightwalletd) is reachable,
/// else 0.
pub(crate) fn getconnectioncount(state: &AppState) -> Result<Value, RpcError> {
    Ok(json!(if connected(state) { 1 } else { 0 }))
}

/// `getpeerinfo` - the active chain upstream (zebrad or lightwalletd) as the single "peer",
/// with its `conn_state` (down|syncing|ready) as an extension field.
#[cfg(feature = "zcash")]
pub(crate) fn getpeerinfo(state: &AppState) -> Result<Value, RpcError> {
    // rose's single "peer" is the active chain upstream. Report it (with its connection
    // state) when connected; otherwise an empty peer list, as bitcoind does with no peers.
    let Ok(w) = state.registry.get(None) else {
        return Ok(Value::Array(vec![]));
    };
    let st = w.status();
    if !st.connected {
        return Ok(Value::Array(vec![]));
    }
    Ok(json!([{
        "id": 0,
        "addr": st.server.clone().unwrap_or_default(),
        "inbound": false,
        "conn_state": st.conn_state.as_str(),
        // Stays true while the post-scan enhancement backlog drains, to agree with `conn_state`
        // (which is `syncing` until the wallet is truly ready to serve full history).
        "syncing": st.scanning || st.pending_enhancements > 0,
    }]))
}

/// The peer list of a build with no Zcash engine: empty, as bitcoind reports with no peers.
/// The "peer" this method describes is the lightwalletd upstream, which such a build has no
/// way to dial; a Bitcoin wallet's own chain source is not one (kyoto peers with many, a
/// bitcoind connection is not a peer at all), so inventing an entry would misreport it.
#[cfg(not(feature = "zcash"))]
pub(crate) fn getpeerinfo(_state: &AppState) -> Result<Value, RpcError> {
    Ok(Value::Array(vec![]))
}

/// `ping` - liveness no-op (there is no P2P peer to ping).
pub(crate) fn ping() -> Result<Value, RpcError> {
    Ok(Value::Null)
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_number_encodes_cargo_version() {
        let v = super::version_number();
        assert!(v > 0, "version must encode to a nonzero number");
        // 0.1.0 -> 100, 1.2.3 -> 10203; sanity-check the arithmetic shape. The patch component
        // may carry a pre-release suffix (e.g. "0-rc0"), so compare against its leading digit run.
        let patch: u64 = env!("CARGO_PKG_VERSION")
            .split('.')
            .nth(2)
            .unwrap()
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(v % 100, patch);
    }
}
