//! The fee-oracle chain: the fee source for the kyoto backend.
//!
//! A BIP-157 light client has no `estimatesmartfee`. The signals it *can* produce - the
//! peers' BIP-133 relay floor and an estimate from recent blocks' coinbase-derived fee
//! averages - are a floor and a backward-looking statistic respectively, neither of which
//! sees the mempool (see [`crate::btc::kyoto::estimate_fee_rate`]). So the kyoto spend path
//! asks HTTP oracles that publish an actual forward estimate first, and keeps the on-chain
//! signals as the last resort.
//!
//! The chain is `[fees] sources`, by default mempool.space -> Esplora -> the peer-derived
//! estimate ([`crate::config::DEFAULT_FEE_SOURCES`]). [`oracle_chain`] resolves it against the
//! network into the tiers that can actually answer, and the caller walks them in order,
//! taking the first success - every tier falls through on failure, the peer-derived one
//! included, so `["peer_median", "mempool_space"]` asks a server only when the peers cannot
//! answer. Two independent oracles rather than one is the point: they are
//! run by different operators and compute their numbers differently (mempool.space projects
//! blocks from its own mempool view; Esplora reports a node's `estimatesmartfee`), so one
//! being down, rate-limiting, or wrong does not leave the send pricing itself off the relay
//! floor alone. The character of the estimate does change when the fallback engages, which is
//! acceptable for a fallback and worth knowing when reading a fee back.
//!
//! ## The tradeoff this makes
//!
//! Kyoto's premise is that the wallet talks to no server. These lookups are a deliberate
//! exception, and it is worth being precise about their cost: the oracle learns that some IP
//! is about to build a transaction, and roughly when. It does **not** learn addresses,
//! amounts, or which transaction resulted - the transaction itself still goes out over the
//! P2P layer to kyoto's own peers. That is a far smaller leak than an Electrum or Esplora
//! *wallet* backend, which queries per address, but it is not nothing, and it is a timing
//! correlation that did not exist before. The Esplora tier makes it a second party of the
//! same class, though only when the first is unreachable.
//!
//! Four things bound it. The request is made only when a send is being built (never on a sync
//! pass, never at startup), it carries no wallet data whatsoever, and a failure is not fatal -
//! the send proceeds on kyoto's own estimate. And the endpoints are configurable: pointed at a
//! self-hosted mempool.space or Esplora (`[fees] mempool_space_url` / `esplora_url`), the
//! lookup goes to infrastructure the operator controls, which removes the disclosure rather
//! than accepting it. An operator who wants the original no-server posture unconditionally
//! sets `sources = ["peer_median"]`.
//!
//! An oracle is trusted to see the mempool, not to be right about everything: the actor
//! checks each HTTP answer against what recent blocks paid (`kyoto::oracle_ceiling`) and
//! falls through past one far above them, as it would past an unreachable one.
//!
//! The bitcoind backend never reaches this module: it has a real fee estimator locally.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{anyhow, Context as _};
use bdk_wallet::bitcoin::FeeRate;
use http_body_util::{BodyExt as _, Limited};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tracing::debug;

use crate::coin::BitcoinNetwork;
use crate::config::{FeeSource, FeesConfig};

/// How long a single tier may take before the caller moves on. Deliberately short: this sits
/// in the middle of a `sendtoaddress`, and a slow answer is worth less than a fast fallback.
/// It bounds each tier rather than the chain, so the default two-oracle chain can spend twice
/// this before reaching the peer-derived signals - still under the wall clock a light client's
/// own cold-start block fetches can take.
const TIMEOUT: Duration = Duration::from_secs(4);

/// The confirmation target every HTTP tier is read at, in blocks - the engine's one fee
/// target, shared with what it asks bitcoind's `estimatesmartfee` for, so a wallet cannot
/// price the same send differently depending on which backend answered.
pub(crate) const TARGET_BLOCKS: u16 = crate::btc::actor::FEE_TARGET_BLOCKS;

/// A ceiling on what any fee source is allowed to say, in sat/vB. Every source on the spend
/// path is a third party - the HTTP oracles over HTTPS, a bitcoind's `estimatesmartfee`, and
/// (least trusted of all) the kyoto peers' BIP-133 feefilter and block averages - and
/// without a bound, a compromised or dishonest answer could burn an arbitrary amount of a
/// wallet's balance as fee. 2000 sat/vB is far above any fee market Bitcoin has sustained,
/// so this never binds in normal operation - it only turns an absurd answer into a rejected
/// one.
///
/// Enforced twice, deliberately: this module discards an over-ceiling oracle answer early (so
/// the send *falls through* to the next tier), and [`enforce_sanity_ceiling`] is the backstop
/// at the `do_send` chokepoint that every rate from every source passes through - which is
/// what makes a peer-dictated feefilter a refusal instead of a payment. The early check applies
/// to an operator's own overridden endpoint too: cheap insurance against a trusted-but-broken
/// source, and it keeps every tier's answer subject to the same rule.
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

/// One resolved tier of the chain, in the order `[fees] sources` names them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeTier {
    /// An HTTP oracle: which dialect to parse, and the URL to ask - a built-in public
    /// endpoint, or the operator's override.
    Http { source: FeeSource, url: String },
    /// Kyoto's own peer-derived signals. No third party, no URL, so nothing to resolve.
    PeerMedian,
}

/// The mempool.space endpoint for `network`, or `None` where the public instance has nothing
/// to say - regtest is a private chain with no fee market and no public instance.
fn mempool_space_endpoint(network: BitcoinNetwork) -> Option<&'static str> {
    match network {
        BitcoinNetwork::Main => Some("https://mempool.space/api/v1/fees/recommended"),
        BitcoinNetwork::Testnet3 => Some("https://mempool.space/testnet/api/v1/fees/recommended"),
        BitcoinNetwork::Testnet4 => Some("https://mempool.space/testnet4/api/v1/fees/recommended"),
        BitcoinNetwork::Regtest => None,
    }
}

/// The Esplora endpoint for `network`, or `None` where no public instance serves it.
///
/// Blockstream.info runs mainnet and testnet3 only: its `/testnet4/api/` path answers with the
/// explorer's HTML rather than JSON, i.e. there is no testnet4 Esplora to fall back to
/// (checked directly, 2026-09). So on testnet4 - the network the dev stack targets - and on
/// regtest, this tier is inert unless `[fees] esplora_url` names an instance that does serve
/// it. That is one of the reasons the override exists.
fn esplora_endpoint(network: BitcoinNetwork) -> Option<&'static str> {
    match network {
        BitcoinNetwork::Main => Some("https://blockstream.info/api/fee-estimates"),
        BitcoinNetwork::Testnet3 => Some("https://blockstream.info/testnet/api/fee-estimates"),
        BitcoinNetwork::Testnet4 | BitcoinNetwork::Regtest => None,
    }
}

/// Resolve `[fees]` against the network into the tiers that can actually answer, in order.
///
/// An HTTP tier with neither an override nor a built-in endpoint for this network is
/// **skipped**, not an error: "mempool.space has no regtest instance" and "Blockstream runs no
/// testnet4 Esplora" are facts about the world, and a chain that named them should degrade to
/// its next tier rather than refuse to start. What that costs is visibility, which is why
/// `rose config check` reports a named-but-inert tier as a warning.
pub fn oracle_chain(fees: &FeesConfig, network: BitcoinNetwork) -> Vec<FeeTier> {
    fees.sources
        .iter()
        .filter_map(|&source| match source {
            FeeSource::PeerMedian => Some(FeeTier::PeerMedian),
            // Every other source is an HTTP oracle, and is in the chain only if this network
            // has an endpoint for it.
            _ => endpoint_for(fees, source, network).map(|url| FeeTier::Http { source, url }),
        })
        .collect()
}

/// The URL one HTTP source would be asked at: the operator's override, else the built-in
/// public endpoint for this network, else nothing. `PeerMedian` has no endpoint at all.
pub fn endpoint_for(
    fees: &FeesConfig,
    source: FeeSource,
    network: BitcoinNetwork,
) -> Option<String> {
    match source {
        FeeSource::MempoolSpace => fees
            .mempool_space_url
            .clone()
            .or_else(|| mempool_space_endpoint(network).map(str::to_string)),
        FeeSource::Esplora => fees
            .esplora_url
            .clone()
            .or_else(|| esplora_endpoint(network).map(str::to_string)),
        FeeSource::PeerMedian => None,
    }
}

/// Refuse a `[fees]` URL override that could never be fetched, at config-resolution time
/// rather than mid-send. `key` names the offending setting so the message points at the line
/// to fix.
///
/// Plain `http://` is permitted: an override's whole purpose is a self-hosted instance, which
/// on a trusted LAN may legitimately not run TLS, and unlike the `[zebra]`/`[bitcoind]`
/// endpoints this request carries no credentials - only the fact that a send is being built.
/// The answer is still bounded by [`SANITY_CEILING_SAT_PER_VB`], so a tampered plaintext reply
/// cannot dictate an absurd fee. Note the compiled-in Mozilla root set is the only TLS trust
/// anchor here (the musl release images ship no CA bundle), so an `https://` instance with a
/// privately-issued certificate will fail to connect - use `http://` on a trusted network, or
/// a publicly-issued certificate.
pub fn validate_endpoint_override(key: &str, url: &str) -> anyhow::Result<()> {
    let uri: hyper::Uri = url
        .parse()
        .with_context(|| format!("[fees] {key} is not a valid URL: {url:?}"))?;
    match uri.scheme_str() {
        Some("http") | Some("https") => {}
        _ => anyhow::bail!(
            "[fees] {key} must be an http:// or https:// URL, got {url:?} (give the full \
             endpoint path, e.g. \"https://mempool.example/api/v1/fees/recommended\")"
        ),
    }
    if uri.host().is_none_or(str::is_empty) {
        anyhow::bail!("[fees] {key} has no host: {url:?}");
    }
    Ok(())
}

/// mempool.space's response body, reduced to the one field read: `hourFee` (sat/vB, the
/// [`TARGET_BLOCKS`] target). The endpoint also serves `fastestFee`, `halfHourFee`,
/// `economyFee` and `minimumFee`; they are deliberately not declared, so an upstream
/// rename or removal of a band this code never reads cannot break the whole oracle
/// (serde ignores unknown fields). A configurable target would add its band here.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Recommended {
    hour_fee: f64,
}

/// Ask one HTTP tier. `Ok` is a rate that has already passed the zero and ceiling checks;
/// every failure - unreachable, malformed, out of range - is an `Err` the caller treats as
/// "fall through to the next tier", never as a failed send.
pub async fn http_fee_rate(source: FeeSource, url: &str) -> anyhow::Result<FeeRate> {
    let body = tokio::time::timeout(TIMEOUT, fetch(url))
        .await
        .map_err(|_| anyhow!("{} did not answer within {TIMEOUT:?}", source.as_str()))??;
    let sat_per_vb = match source {
        FeeSource::MempoolSpace => parse_mempool_space(&body)?,
        FeeSource::Esplora => parse_esplora(&body)?,
        // Unreachable by construction: `oracle_chain` never builds an `Http` tier for it.
        FeeSource::PeerMedian => return Err(anyhow!("the peer median is not an HTTP oracle")),
    };
    let rate = rate_from_sat_per_vb(source, sat_per_vb)?;
    debug!(
        source = source.as_str(),
        sat_per_vb,
        %url,
        "fee estimate"
    );
    Ok(rate)
}

/// mempool.space's own projected-block heuristic, read at `hourFee` - its ~1 hour band, which
/// is [`TARGET_BLOCKS`] at ten-minute spacing. The endpoint publishes named bands rather than
/// per-target numbers, so unlike the Esplora tier this is a fixed field and not a lookup: a
/// changed target needs a different band picked here (`halfHourFee`, `economyFee`), and the
/// assertion below is what stops that from being silent.
const _: () = assert!(
    TARGET_BLOCKS == 6,
    "mempool.space is read at `hourFee`, its ~6-block band; a different TARGET_BLOCKS needs a \
     different field (halfHourFee, economyFee) in parse_mempool_space"
);

fn parse_mempool_space(body: &[u8]) -> anyhow::Result<f64> {
    let parsed: Recommended =
        serde_json::from_slice(body).context("parse the mempool.space fee JSON")?;
    Ok(parsed.hour_fee)
}

/// Esplora's `/fee-estimates`: `{"<target in blocks>": sat_per_vb, ...}` as floats, from the
/// backing node's `estimatesmartfee`. Read at [`TARGET_BLOCKS`] exactly rather than picking a
/// nearby key - a neighbouring target is a different question, and an instance that cannot
/// answer this one is better handled by the next tier than by silently repricing the send.
fn parse_esplora(body: &[u8]) -> anyhow::Result<f64> {
    let parsed: BTreeMap<String, f64> =
        serde_json::from_slice(body).context("parse the Esplora fee JSON")?;
    parsed
        .get(&TARGET_BLOCKS.to_string())
        .copied()
        .ok_or_else(|| anyhow!("Esplora returned no {TARGET_BLOCKS}-block fee estimate"))
}

/// Turn an oracle's sat/vB into a [`FeeRate`], refusing the answers that must not price a
/// send: a non-finite or negative number (a broken source), zero (a transaction no peer would
/// relay), and anything above [`SANITY_CEILING_SAT_PER_VB`].
///
/// Rounding is upward, so a sub-1 sat/vB estimate - which Esplora reports in a quiet market -
/// becomes 1 sat/vB rather than the zero that would fail to relay.
fn rate_from_sat_per_vb(source: FeeSource, value: f64) -> anyhow::Result<FeeRate> {
    let name = source.as_str();
    if !value.is_finite() || value < 0.0 {
        return Err(anyhow!("{name} returned a nonsensical fee rate ({value})"));
    }
    if value > SANITY_CEILING_SAT_PER_VB as f64 {
        return Err(anyhow!(
            "{name} returned {value} sat/vB, above the {SANITY_CEILING_SAT_PER_VB} sat/vB \
             sanity ceiling; ignoring it rather than paying it"
        ));
    }
    let sat_per_vb = value.ceil() as u64;
    if sat_per_vb == 0 {
        return Err(anyhow!("{name} returned a zero fee rate"));
    }
    Ok(FeeRate::from_sat_per_vb_u32(
        u32::try_from(sat_per_vb).unwrap_or(u32::MAX),
    ))
}

async fn fetch(url: &str) -> anyhow::Result<Vec<u8>> {
    // Roots come from the compiled-in Mozilla set (`webpki-tokio`), so this does not depend on
    // the host having a populated trust store - the musl release images ship no CA bundle.
    // Plaintext is accepted for the sake of a self-hosted override on a trusted network (see
    // `validate_endpoint_override`); the built-in endpoints are all https, and the connector
    // picks per-URL scheme, so this never downgrades one of those.
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
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
    // Bounded by size, not only by the tier's timeout: a timeout bounds the body by
    // bandwidth alone, and an answer is a few hundred bytes (Esplora's whole target table
    // is about one KiB), so anything past the cap is not a fee estimate worth parsing.
    let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
        .collect()
        .await
        .map_err(|e| anyhow!("read the body of {url}: {e}"))?
        .to_bytes();
    Ok(body.to_vec())
}

/// The largest fee-oracle response [`fetch`] reads. Generous against every known answer
/// shape (mempool.space's recommended-fees object is ~100 bytes, Esplora's
/// `/fee-estimates` table ~1 KiB) and small enough that a hostile or broken endpoint
/// cannot make a send buffer megabytes.
const MAX_RESPONSE_BYTES: usize = 16 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    fn config(sources: &[FeeSource]) -> FeesConfig {
        FeesConfig {
            sources: sources.to_vec(),
            ..FeesConfig::default()
        }
    }

    #[test]
    fn every_public_network_has_a_mempool_space_endpoint_and_regtest_has_none() {
        assert!(mempool_space_endpoint(BitcoinNetwork::Main)
            .unwrap()
            .contains("mempool.space"));
        // The testnet paths differ, and swapping them would silently price a testnet4 send
        // off the testnet3 market.
        assert!(mempool_space_endpoint(BitcoinNetwork::Testnet3)
            .unwrap()
            .contains("/testnet/"));
        assert!(mempool_space_endpoint(BitcoinNetwork::Testnet4)
            .unwrap()
            .contains("/testnet4/"));
        assert!(mempool_space_endpoint(BitcoinNetwork::Regtest).is_none());
    }

    #[test]
    fn esplora_covers_main_and_testnet3_only() {
        assert!(esplora_endpoint(BitcoinNetwork::Main)
            .unwrap()
            .ends_with("/api/fee-estimates"));
        assert!(esplora_endpoint(BitcoinNetwork::Testnet3)
            .unwrap()
            .contains("/testnet/"));
        // Blockstream.info serves no testnet4 Esplora (its /testnet4/api/ path answers with
        // the explorer HTML), so the tier is inert there unless an override names one.
        assert!(esplora_endpoint(BitcoinNetwork::Testnet4).is_none());
        assert!(esplora_endpoint(BitcoinNetwork::Regtest).is_none());
    }

    #[test]
    fn the_default_chain_is_both_oracles_then_the_peers() {
        let chain = oracle_chain(&FeesConfig::default(), BitcoinNetwork::Main);
        assert_eq!(
            chain,
            vec![
                FeeTier::Http {
                    source: FeeSource::MempoolSpace,
                    url: mempool_space_endpoint(BitcoinNetwork::Main).unwrap().into(),
                },
                FeeTier::Http {
                    source: FeeSource::Esplora,
                    url: esplora_endpoint(BitcoinNetwork::Main).unwrap().into(),
                },
                FeeTier::PeerMedian,
            ]
        );
    }

    #[test]
    fn a_tier_with_no_endpoint_for_the_network_is_skipped_not_failed() {
        // testnet4 has a mempool.space instance but no Esplora; regtest has neither. Either
        // way the chain degrades to what can answer rather than refusing.
        assert_eq!(
            oracle_chain(&FeesConfig::default(), BitcoinNetwork::Testnet4),
            vec![
                FeeTier::Http {
                    source: FeeSource::MempoolSpace,
                    url: mempool_space_endpoint(BitcoinNetwork::Testnet4)
                        .unwrap()
                        .into(),
                },
                FeeTier::PeerMedian,
            ]
        );
        assert_eq!(
            oracle_chain(&FeesConfig::default(), BitcoinNetwork::Regtest),
            vec![FeeTier::PeerMedian]
        );
    }

    #[test]
    fn an_override_supplies_a_tier_the_network_has_no_public_instance_for() {
        let fees = FeesConfig {
            esplora_url: Some("http://esplora.internal/api/fee-estimates".into()),
            ..FeesConfig::default()
        };
        // testnet4's otherwise-inert Esplora tier is now live, at the operator's instance.
        assert!(
            oracle_chain(&fees, BitcoinNetwork::Testnet4).contains(&FeeTier::Http {
                source: FeeSource::Esplora,
                url: "http://esplora.internal/api/fee-estimates".into(),
            })
        );
        // And the override wins over the built-in endpoint where there is one.
        assert!(
            oracle_chain(&fees, BitcoinNetwork::Main).contains(&FeeTier::Http {
                source: FeeSource::Esplora,
                url: "http://esplora.internal/api/fee-estimates".into(),
            })
        );
    }

    #[test]
    fn the_source_list_orders_and_disables_tiers() {
        // Reordered: the peer median first means no third party is contacted at all unless it
        // fails, which is the privacy-maximal shape.
        let reordered = oracle_chain(
            &config(&[FeeSource::PeerMedian, FeeSource::MempoolSpace]),
            BitcoinNetwork::Main,
        );
        assert_eq!(reordered[0], FeeTier::PeerMedian);
        assert_eq!(reordered.len(), 2);
        // Emptied: no estimation at all, so every send must carry an explicit fee rate.
        assert!(oracle_chain(&config(&[]), BitcoinNetwork::Main).is_empty());
    }

    #[test]
    fn overrides_must_be_fetchable_urls() {
        assert!(validate_endpoint_override(
            "esplora_url",
            "https://esplora.example/api/fee-estimates"
        )
        .is_ok());
        // Plaintext is allowed on purpose: a self-hosted instance on a trusted LAN.
        assert!(
            validate_endpoint_override("mempool_space_url", "http://10.0.0.2:3006/api").is_ok()
        );
        // A bare host is the likely typo, and it names the key so the fix is obvious.
        let err = validate_endpoint_override("mempool_space_url", "mempool.example")
            .unwrap_err()
            .to_string();
        assert!(err.contains("mempool_space_url"), "{err}");
        assert!(err.contains("http://"), "{err}");
        assert!(validate_endpoint_override("esplora_url", "ftp://esplora.example/x").is_err());
        assert!(validate_endpoint_override("esplora_url", "https:///no-host").is_err());
    }

    /// Serve one canned body (or a status) at `/` and hand back its `http://` URL. The
    /// in-process fake-server pattern `chain/zebra.rs` uses, which is what lets the HTTP path
    /// itself - client, status handling, body read, per-tier fallthrough - be covered offline
    /// rather than only by the `#[ignore]`d live test below.
    async fn serve(status: u16, body: &'static str) -> String {
        use axum::response::IntoResponse as _;
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(move || async move {
                (axum::http::StatusCode::from_u16(status).unwrap(), body).into_response()
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/")
    }

    /// The whole HTTP tier, end to end against a fake oracle: a served body becomes a rate, and
    /// each way a tier can fail is an `Err` - which is what the caller turns into "try the next
    /// source" rather than a failed send.
    #[tokio::test]
    async fn an_http_tier_answers_or_fails_in_a_way_the_chain_can_fall_through() {
        let url = serve(
            200,
            r#"{"fastestFee":12,"halfHourFee":10,"hourFee":7,"economyFee":3,"minimumFee":1}"#,
        )
        .await;
        assert_eq!(
            http_fee_rate(FeeSource::MempoolSpace, &url).await.unwrap(),
            FeeRate::from_sat_per_vb_u32(7)
        );
        let url = serve(200, r#"{"1":2.108,"6":1.067,"12":0.379}"#).await;
        assert_eq!(
            http_fee_rate(FeeSource::Esplora, &url).await.unwrap(),
            FeeRate::from_sat_per_vb_u32(2)
        );

        // An oracle that is up but unhealthy, one serving something else entirely (a captive
        // portal, or Blockstream's explorer HTML on a path with no API behind it), one whose
        // answer is out of range, and an endpoint that is not listening at all.
        let url = serve(503, "unavailable").await;
        assert!(http_fee_rate(FeeSource::MempoolSpace, &url).await.is_err());
        let url = serve(200, "<!DOCTYPE html><title>Explorer</title>").await;
        assert!(http_fee_rate(FeeSource::Esplora, &url).await.is_err());
        let url = serve(200, r#"{"1":2.0,"6":9000.0}"#).await;
        assert!(http_fee_rate(FeeSource::Esplora, &url)
            .await
            .unwrap_err()
            .to_string()
            .contains("sanity ceiling"));
        assert!(
            http_fee_rate(FeeSource::MempoolSpace, "http://127.0.0.1:1/")
                .await
                .is_err()
        );

        // An answer past the body cap is refused while it is read, not parsed after being
        // buffered whole - even one that would have parsed (a valid object padded with
        // whitespace, which JSON ignores).
        let padded = format!(
            r#"{{"fastestFee":12,"halfHourFee":10,"hourFee":7{}}}"#,
            " ".repeat(MAX_RESPONSE_BYTES)
        );
        let url = serve(200, Box::leak(padded.into_boxed_str())).await;
        assert!(http_fee_rate(FeeSource::MempoolSpace, &url).await.is_err());
    }

    /// The one thing the offline tests cannot check: that each parser still matches what its
    /// live endpoint actually serves. Both are third-party APIs that can change shape without
    /// warning, and a drift here degrades silently - the tier just always fails and the chain
    /// quietly shortens - so this is `#[ignore]`d (network, like `backend.rs`'s testnet tests)
    /// rather than absent. Run with `cargo test --features bitcoin -- --include-ignored`.
    ///
    /// NB it needs *direct* egress: the trust anchors are the compiled-in Mozilla roots (see
    /// `fetch`), so behind a TLS-intercepting proxy this fails `UnknownIssuer` however healthy
    /// the endpoints are.
    #[tokio::test]
    #[ignore = "requires network access to the public fee oracles"]
    async fn the_public_oracles_still_answer_in_the_shape_we_parse() {
        for (source, network) in [
            (FeeSource::MempoolSpace, BitcoinNetwork::Main),
            (FeeSource::MempoolSpace, BitcoinNetwork::Testnet4),
            (FeeSource::Esplora, BitcoinNetwork::Main),
            (FeeSource::Esplora, BitcoinNetwork::Testnet3),
        ] {
            let url = endpoint_for(&FeesConfig::default(), source, network).unwrap();
            let rate = http_fee_rate(source, &url)
                .await
                .unwrap_or_else(|e| panic!("{} at {url}: {e:#}", source.as_str()));
            // Nothing tighter than the checks the send path itself applies: the point is that
            // the body parsed and produced a usable rate, not what the market is today.
            assert!(rate >= FeeRate::from_sat_per_vb_u32(1), "{url}");
            assert!(enforce_sanity_ceiling(rate).is_ok(), "{url}");
        }
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
    fn every_oracle_answer_passes_the_same_zero_and_ceiling_checks() {
        for source in [FeeSource::MempoolSpace, FeeSource::Esplora] {
            assert_eq!(
                rate_from_sat_per_vb(source, 7.0).unwrap(),
                FeeRate::from_sat_per_vb_u32(7)
            );
            // A sub-1 sat/vB market (Esplora reports fractions) rounds up rather than down to
            // a rate no peer would relay.
            assert_eq!(
                rate_from_sat_per_vb(source, 0.379).unwrap(),
                FeeRate::from_sat_per_vb_u32(1)
            );
            assert!(rate_from_sat_per_vb(source, 0.0)
                .unwrap_err()
                .to_string()
                .contains("zero"));
            assert!(rate_from_sat_per_vb(source, 2_001.0)
                .unwrap_err()
                .to_string()
                .contains("sanity ceiling"));
            assert!(rate_from_sat_per_vb(source, f64::NAN).is_err());
            assert!(rate_from_sat_per_vb(source, -1.0).is_err());
        }
    }

    #[test]
    fn the_mempool_space_body_deserializes_from_the_documented_response() {
        let body =
            br#"{"fastestFee":12,"halfHourFee":10,"hourFee":7,"economyFee":3,"minimumFee":1}"#;
        assert_eq!(parse_mempool_space(body).unwrap(), 7.0);
    }

    #[test]
    fn the_esplora_body_is_read_at_the_six_block_target() {
        // Trimmed from a live https://blockstream.info/api/fee-estimates response
        // (2026-09): string keys, float sat/vB values, unordered.
        let body = br#"{"12":0.379,"1":2.108,"6":1.067,"3":1.195,"1008":0.1}"#;
        assert_eq!(parse_esplora(body).unwrap(), 1.067);
        // An instance that cannot answer this target falls through to the next tier rather
        // than being repriced off a neighbouring one.
        let err = parse_esplora(br#"{"1":2.108,"3":1.195}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("6-block"), "{err}");
    }
}
