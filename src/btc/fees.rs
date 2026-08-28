//! The mempool.space fee oracle: the fee source for the kyoto backend.
//!
//! A BIP-157 light client has no `estimatesmartfee`. The signals it *can* produce - the
//! peers' BIP-133 relay floor and a median of recent blocks' coinbase-derived fee averages -
//! are a floor and a backward-looking average respectively, neither of which predicts
//! confirmation time (see [`crate::btc::kyoto::estimate_fee_rate`]). mempool.space publishes
//! an actual forward estimate over plain HTTPS, so the kyoto spend path asks it first and
//! falls back to the on-chain signals when it cannot be reached.
//!
//! ## The tradeoff this makes
//!
//! Kyoto's premise is that the wallet talks to no server. This lookup is a deliberate
//! exception, and it is worth being precise about its cost: mempool.space learns that some IP
//! is about to build a transaction, and roughly when. It does **not** learn addresses,
//! amounts, or which transaction resulted - the transaction itself still goes out over the
//! P2P layer to kyoto's own peers. That is a far smaller leak than an Electrum or Esplora
//! backend, which queries per address, but it is not nothing, and it is a timing correlation
//! that did not exist before.
//!
//! Three things bound it: the request is made only when a send is being built (never on a
//! sync pass, never at startup), it carries no wallet data whatsoever, and a failure is not
//! fatal - the send proceeds on kyoto's own estimate.
//!
//! The bitcoind backend never reaches this module: it has a real fee estimator locally.

use std::time::Duration;

use anyhow::{anyhow, Context as _};
use bdk_wallet::bitcoin::FeeRate;
use http_body_util::BodyExt as _;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tracing::debug;

use crate::coin::BitcoinNetwork;

/// How long the whole lookup may take before the caller falls back. Deliberately short: this
/// sits in the middle of a `sendtoaddress`, and a slow answer is worth less than a fast
/// fallback to the on-chain signals.
const TIMEOUT: Duration = Duration::from_secs(4);

/// A ceiling on what any fee source is allowed to say, in sat/vB. Every source on the spend
/// path is a third party - mempool.space over HTTPS, a bitcoind's `estimatesmartfee`, and
/// (least trusted of all) the kyoto peers' BIP-133 feefilter and block averages - and
/// without a bound, a compromised or dishonest answer could burn an arbitrary amount of a
/// wallet's balance as fee. 2000 sat/vB is far above any fee market Bitcoin has sustained,
/// so this never binds in normal operation - it only turns an absurd answer into a rejected
/// one.
///
/// Enforced twice, deliberately: this module discards an over-ceiling mempool.space answer
/// early (so the send *falls back* to the on-chain signals), and [`enforce_sanity_ceiling`]
/// is the backstop at the `do_send` chokepoint that every rate from every source passes
/// through - which is what makes a peer-dictated feefilter a refusal instead of a payment.
const SANITY_CEILING_SAT_PER_VB: u64 = 2_000;

/// The chokepoint check: the rate a send is about to pay, whatever source produced it, may
/// not exceed [`SANITY_CEILING_SAT_PER_VB`]. A violation is an error - refusing beats
/// paying, and the message names the number so an operator can tell a fee spike from a
/// dishonest signal. Note this deliberately also refuses when the peers' *relay floor*
/// exceeds the ceiling: clamping downward instead would build a transaction below the floor
/// that no peer will relay, which fails slower and less legibly than this does.
pub(crate) fn enforce_sanity_ceiling(rate: FeeRate) -> anyhow::Result<FeeRate> {
    if rate
        > FeeRate::from_sat_per_vb_u32(u32::try_from(SANITY_CEILING_SAT_PER_VB).unwrap_or(u32::MAX))
    {
        return Err(anyhow!(
            "the fee estimate is {} sat/vB, above the {SANITY_CEILING_SAT_PER_VB} sat/vB \
             sanity ceiling; refusing to pay it. A dishonest peer or a broken oracle can \
             inflate fee signals - if the market is genuinely this high, wait for it to \
             cool, or send from a backend you trust (a local bitcoind, or kyoto pinned to \
             a peer you control)",
            rate.to_sat_per_vb_ceil()
        ));
    }
    Ok(rate)
}

/// The response body's shape. Every field is sat/vB; only `hourFee` is read (the ~6-block
/// target the engine asks bitcoind for), but naming the rest documents what the endpoint
/// offers if a caller ever wants a configurable target.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Recommended {
    #[allow(dead_code)]
    fastest_fee: u64,
    #[allow(dead_code)]
    half_hour_fee: u64,
    hour_fee: u64,
    #[allow(dead_code)]
    economy_fee: u64,
    #[allow(dead_code)]
    minimum_fee: u64,
}

/// The endpoint for `network`, or `None` where mempool.space has nothing to say - regtest is
/// a private chain with no fee market and no public instance.
fn endpoint(network: BitcoinNetwork) -> Option<&'static str> {
    match network {
        BitcoinNetwork::Main => Some("https://mempool.space/api/v1/fees/recommended"),
        BitcoinNetwork::Testnet3 => Some("https://mempool.space/testnet/api/v1/fees/recommended"),
        BitcoinNetwork::Testnet4 => Some("https://mempool.space/testnet4/api/v1/fees/recommended"),
        BitcoinNetwork::Regtest => None,
    }
}

/// The recommended fee rate for a ~1 hour (6 block) confirmation target, or `None` when this
/// network has no oracle. An unreachable or malformed answer is an `Err`, which the caller
/// treats as "fall back", not as a failed send.
pub async fn recommended_fee_rate(network: BitcoinNetwork) -> anyhow::Result<Option<FeeRate>> {
    let Some(url) = endpoint(network) else {
        return Ok(None);
    };
    let fetched = tokio::time::timeout(TIMEOUT, fetch(url))
        .await
        .map_err(|_| anyhow!("mempool.space did not answer within {TIMEOUT:?}"))??;

    if fetched.hour_fee == 0 {
        return Err(anyhow!("mempool.space returned a zero fee rate"));
    }
    if fetched.hour_fee > SANITY_CEILING_SAT_PER_VB {
        return Err(anyhow!(
            "mempool.space returned {} sat/vB, above the {SANITY_CEILING_SAT_PER_VB} sat/vB \
             sanity ceiling; ignoring it rather than paying it",
            fetched.hour_fee
        ));
    }
    let rate = FeeRate::from_sat_per_vb_u32(u32::try_from(fetched.hour_fee).unwrap_or(u32::MAX));
    debug!(
        sat_per_vb = fetched.hour_fee,
        %url,
        "mempool.space fee estimate"
    );
    Ok(Some(rate))
}

async fn fetch(url: &str) -> anyhow::Result<Recommended> {
    // Roots come from the compiled-in Mozilla set (`webpki-tokio`), so this does not depend on
    // the host having a populated trust store - the musl release images ship no CA bundle.
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .build();
    let client: Client<_, String> = Client::builder(TokioExecutor::new()).build(https);

    let uri: hyper::Uri = url.parse().with_context(|| format!("parse {url}"))?;
    let response = client
        .get(uri)
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(anyhow!("{url} answered {status}"));
    }
    let body = response
        .into_body()
        .collect()
        .await
        .with_context(|| format!("read the body of {url}"))?
        .to_bytes();
    serde_json::from_slice(&body).with_context(|| format!("parse the fee JSON from {url}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_public_network_has_an_endpoint_and_regtest_has_none() {
        assert!(endpoint(BitcoinNetwork::Main)
            .unwrap()
            .contains("mempool.space"));
        // The testnet paths differ, and swapping them would silently price a testnet4 send
        // off the testnet3 market.
        assert!(endpoint(BitcoinNetwork::Testnet3)
            .unwrap()
            .contains("/testnet/"));
        assert!(endpoint(BitcoinNetwork::Testnet4)
            .unwrap()
            .contains("/testnet4/"));
        assert!(endpoint(BitcoinNetwork::Regtest).is_none());
    }

    #[test]
    fn the_sanity_ceiling_is_enforced_at_the_chokepoint() {
        assert!(enforce_sanity_ceiling(FeeRate::from_sat_per_vb_u32(1)).is_ok());
        // At the ceiling passes - it is a bound on absurdity, not a working range.
        let at = FeeRate::from_sat_per_vb_u32(2_000);
        assert_eq!(enforce_sanity_ceiling(at).unwrap(), at);
        // Above it refuses, naming both numbers so an operator can tell a fee spike from
        // a dishonest signal.
        let err = enforce_sanity_ceiling(FeeRate::from_sat_per_vb_u32(5_000))
            .unwrap_err()
            .to_string();
        assert!(err.contains("5000 sat/vB"), "{err}");
        assert!(err.contains("2000"), "{err}");
        assert!(err.contains("refusing"), "{err}");
    }

    #[test]
    fn the_body_shape_deserializes_from_the_documented_response() {
        let body =
            br#"{"fastestFee":12,"halfHourFee":10,"hourFee":7,"economyFee":3,"minimumFee":1}"#;
        let parsed: Recommended = serde_json::from_slice(body).unwrap();
        assert_eq!(parsed.hour_fee, 7);
        assert_eq!(parsed.fastest_fee, 12);
        assert_eq!(parsed.minimum_fee, 1);
    }
}
