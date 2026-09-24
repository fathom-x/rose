//! The kyoto peer tier's fee model: a ring of recent block samples and the estimate drawn
//! from it. Pure data and arithmetic; `kyoto.rs` fetches the blocks that fill it.
//!
//! A filter client has no mempool, so the only fee evidence it can verify is what recent
//! blocks paid. Each sample is one block's average fee rate - `(coinbase output - subsidy)
//! / weight`, committed to by a PoW-checked header - and its weight. The estimate follows
//! the design of lightninglabs/neutrino#351 (open at the time of writing), minus the parts
//! a light client that rarely downloads blocks cannot feed:
//!
//! - **Recency weighting.** A sample's weight halves every [`HALF_LIFE_BLOCKS`] blocks of
//!   age. Neutrino uses a 30-minute half-life that adapts to volatility; blocks are this
//!   ring's only clock, and a fixed half-life keeps the arithmetic reviewable.
//! - **A quantile per confirmation target.** Block fee rates are right-skewed, so the
//!   statistic is a weighted empirical quantile rather than a mean. Target `n` takes
//!   `p = 1 - 0.15^(1/n)`: the rate that beat at least one of `n` blocks with 85%
//!   probability, if blocks were independent draws. Target 1 is the 85th percentile,
//!   target 6 the 27th.
//! - **A congestion gate.** A block that was not full took every transaction that paid the
//!   relay floor, so its average says what its payers chose, not what inclusion cost. The
//!   estimate is blended from the quantile toward the relay floor by the recency-weighted
//!   share of blocks at least [`FULL_BLOCK_PERCENT`] full. An idle market prices at the
//!   floor; a market of full blocks prices at the quantile.
//!
//! The average rate of a full block already sits above the marginal rate it took (the
//! average includes its highest payers), which is why the old 20% market-lag markup is
//! gone: the quantile is the insurance now, and `bumpfee` is the remedy.
//!
//! The ring holds [`CAPACITY`] blocks by height. It lives in memory only (the stateless
//! rule); a restart refills it. A reorg is caught by hash: every refresh checks each
//! sample's hash against the header chain and drops the ones a reorg replaced.

use std::collections::BTreeMap;
use std::time::Instant;

use bdk_wallet::bitcoin::{BlockHash, FeeRate};

/// How many blocks the ring holds: four half-lives, past which a sample weighs 1/16.
pub const CAPACITY: usize = 24;

/// Recency weighting: a sample's weight halves every this many blocks (about an hour).
pub const HALF_LIFE_BLOCKS: f64 = 6.0;

/// A block at least this full, by weight, counts as congested.
pub const FULL_BLOCK_PERCENT: u64 = 95;

/// The consensus block weight limit.
const MAX_BLOCK_WEIGHT_WU: u64 = 4_000_000;

/// The share of the estimate's probability left to chance per block (`p = 1 - 0.15^(1/n)`).
const MISS_PROBABILITY: f64 = 0.15;

/// The relay floor, 1 sat/vB, that an idle market prices at.
const RELAY_FLOOR: FeeRate = FeeRate::from_sat_per_kwu(250);

/// One block's fee evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockSample {
    pub hash: BlockHash,
    /// The block's average fee rate, in sat/kwu.
    pub fee_rate_sat_per_kwu: u64,
    pub weight_wu: u64,
}

impl BlockSample {
    fn is_full(&self) -> bool {
        self.weight_wu * 100 >= MAX_BLOCK_WEIGHT_WU * FULL_BLOCK_PERCENT
    }
}

/// What [`FeeSamples::estimate`] answers, with the pieces that made it for the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Estimate {
    pub rate: FeeRate,
    /// The target's quantile of block averages, before the gate.
    pub quantile: FeeRate,
    /// The recency-weighted share of full blocks, in percent.
    pub congestion_percent: u64,
    pub samples: usize,
}

/// The ring. See the module doc.
#[derive(Debug, Default)]
pub struct FeeSamples {
    by_height: BTreeMap<u32, BlockSample>,
    /// When an estimate last read the ring; the background sampler stops once this is old.
    last_used: Option<Instant>,
}

impl FeeSamples {
    /// Record a block. Past capacity the lowest height goes, so backfilling old blocks can
    /// never push out recent ones: a sample below a full ring's lowest height is ignored.
    pub fn insert(&mut self, height: u32, sample: BlockSample) {
        if self.by_height.len() >= CAPACITY
            && !self.by_height.contains_key(&height)
            && self
                .by_height
                .keys()
                .next()
                .is_some_and(|lowest| height < *lowest)
        {
            return;
        }
        self.by_height.insert(height, sample);
        while self.by_height.len() > CAPACITY {
            self.by_height.pop_first();
        }
    }

    /// The sample at `height`, if any.
    pub fn get(&self, height: u32) -> Option<&BlockSample> {
        self.by_height.get(&height)
    }

    /// The recorded heights, ascending.
    pub fn heights(&self) -> Vec<u32> {
        self.by_height.keys().copied().collect()
    }

    /// Forget one height (its block was reorged out).
    pub fn remove(&mut self, height: u32) {
        self.by_height.remove(&height);
    }

    /// Forget every height above `tip` (the chain got shorter).
    pub fn truncate_above(&mut self, tip: u32) {
        self.by_height.retain(|height, _| *height <= tip);
    }

    pub fn len(&self) -> usize {
        self.by_height.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_height.is_empty()
    }

    pub fn mark_used(&mut self, now: Instant) {
        self.last_used = Some(now);
    }

    pub fn last_used(&self) -> Option<Instant> {
        self.last_used
    }

    /// The heights in the window of `depth` blocks ending at `tip` that the ring lacks,
    /// newest first.
    pub fn missing(&self, tip: u32, depth: u32) -> Vec<u32> {
        let first = tip.saturating_sub(depth.saturating_sub(1));
        (first..=tip)
            .rev()
            .filter(|height| !self.by_height.contains_key(height))
            .collect()
    }

    /// The highest block average among samples within [`CAPACITY`] blocks of `tip`: the
    /// most the recent chain says anyone paid, for the HTTP oracles' plausibility check.
    pub fn highest_recent(&self, tip: u32) -> Option<FeeRate> {
        self.recent(tip)
            .map(|(_, s)| s.fee_rate_sat_per_kwu)
            .max()
            .map(FeeRate::from_sat_per_kwu)
    }

    /// The estimate for confirmation within `target` blocks, from the samples within
    /// [`CAPACITY`] blocks of `tip`, or `None` with no such sample.
    pub fn estimate(&self, tip: u32, target: u16) -> Option<Estimate> {
        let mut weighted: Vec<(u64, f64, bool)> = self
            .recent(tip)
            .map(|(height, sample)| {
                let age = f64::from(tip.saturating_sub(height));
                (
                    sample.fee_rate_sat_per_kwu,
                    0.5f64.powf(age / HALF_LIFE_BLOCKS),
                    sample.is_full(),
                )
            })
            .collect();
        if weighted.is_empty() {
            return None;
        }
        let total: f64 = weighted.iter().map(|(_, w, _)| w).sum();
        let full: f64 = weighted
            .iter()
            .filter(|(_, _, full)| *full)
            .map(|(_, w, _)| w)
            .sum();
        let congestion = (full / total).clamp(0.0, 1.0);
        weighted.sort_by_key(|(rate, _, _)| *rate);
        let p = quantile_for_target(target);
        let mut cumulative = 0.0;
        let mut quantile = weighted[weighted.len() - 1].0;
        for (rate, w, _) in &weighted {
            cumulative += w;
            if cumulative >= p * total {
                quantile = *rate;
                break;
            }
        }
        let floor = RELAY_FLOOR.to_sat_per_kwu();
        let gated = if quantile > floor {
            floor + ((quantile - floor) as f64 * congestion).round() as u64
        } else {
            floor
        };
        Some(Estimate {
            rate: FeeRate::from_sat_per_kwu(gated),
            quantile: FeeRate::from_sat_per_kwu(quantile),
            congestion_percent: (congestion * 100.0).round() as u64,
            samples: weighted.len(),
        })
    }

    fn recent(&self, tip: u32) -> impl Iterator<Item = (u32, &BlockSample)> {
        let lowest = tip.saturating_sub(CAPACITY as u32 - 1);
        self.by_height
            .range(lowest..=tip)
            .map(|(height, sample)| (*height, sample))
    }
}

/// `p = 1 - 0.15^(1/n)`, the quantile for a `target`-block estimate.
pub fn quantile_for_target(target: u16) -> f64 {
    1.0 - MISS_PROBABILITY.powf(1.0 / f64::from(target.max(1)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::hashes::Hash as _;

    fn sample(n: u8, sat_per_vb: u64, full: bool) -> BlockSample {
        BlockSample {
            hash: BlockHash::from_byte_array([n; 32]),
            fee_rate_sat_per_kwu: sat_per_vb * 250,
            weight_wu: if full { 3_990_000 } else { 1_000_000 },
        }
    }

    #[test]
    fn quantiles_follow_the_target() {
        assert!((quantile_for_target(1) - 0.85).abs() < 1e-9);
        assert!((quantile_for_target(2) - 0.6127).abs() < 1e-3);
        assert!((quantile_for_target(6) - 0.2716).abs() < 1e-3);
        assert!(quantile_for_target(0) == quantile_for_target(1));
        assert!(quantile_for_target(1008) > 0.0);
    }

    #[test]
    fn the_ring_keeps_the_highest_heights() {
        let mut ring = FeeSamples::default();
        for h in 0..(CAPACITY as u32 + 5) {
            ring.insert(h, sample(h as u8, 1, false));
        }
        assert_eq!(ring.len(), CAPACITY);
        assert_eq!(ring.heights()[0], 5);
        // A backfill below a full ring's floor is ignored rather than evicting a recent block.
        ring.insert(1, sample(1, 1, false));
        assert_eq!(ring.heights()[0], 5);
        // A reorg: the tip went back, then one block was replaced.
        ring.truncate_above(20);
        assert_eq!(*ring.heights().last().unwrap(), 20);
        ring.remove(20);
        assert_eq!(ring.missing(20, 3), vec![20]);
        assert_eq!(ring.missing(22, 3), vec![22, 21, 20]);
        assert_eq!(ring.missing(19, 3), Vec::<u32>::new());
    }

    #[test]
    fn an_idle_market_prices_at_the_relay_floor() {
        let mut ring = FeeSamples::default();
        for h in 0..10 {
            ring.insert(h, sample(h as u8, 30, false));
        }
        let e = ring.estimate(9, 6).unwrap();
        assert_eq!(e.rate, RELAY_FLOOR);
        assert_eq!(e.quantile, FeeRate::from_sat_per_vb_u32(30));
        assert_eq!(e.congestion_percent, 0);
        // Fee-less blocks (regtest) likewise.
        let mut ring = FeeSamples::default();
        ring.insert(1, sample(1, 0, true));
        assert_eq!(ring.estimate(1, 1).unwrap().rate, RELAY_FLOOR);
    }

    #[test]
    fn a_congested_market_prices_at_the_targets_quantile() {
        let mut ring = FeeSamples::default();
        // Ten full blocks, 10..=100 sat/vB.
        for (i, rate) in [10, 20, 30, 40, 50, 60, 70, 80, 90, 100].iter().enumerate() {
            ring.insert(i as u32, sample(i as u8, *rate, true));
        }
        let fast = ring.estimate(9, 1).unwrap();
        let slow = ring.estimate(9, 6).unwrap();
        assert_eq!(fast.congestion_percent, 100);
        assert_eq!(fast.rate, fast.quantile);
        assert!(fast.rate > slow.rate, "{fast:?} {slow:?}");
        assert!(slow.rate >= FeeRate::from_sat_per_vb_u32(10));
        assert!(fast.rate <= FeeRate::from_sat_per_vb_u32(100));
    }

    #[test]
    fn recent_blocks_outweigh_old_ones() {
        let mut ring = FeeSamples::default();
        // Old blocks cheap, recent blocks dear, all full.
        for h in 0..12 {
            ring.insert(h, sample(h as u8, if h < 6 { 5 } else { 50 }, true));
        }
        // The median by count would sit on the boundary; by recency it is the dear side.
        let e = ring.estimate(11, 2).unwrap();
        assert_eq!(e.rate, FeeRate::from_sat_per_vb_u32(50));
    }

    #[test]
    fn half_full_blocks_blend_toward_the_floor() {
        let mut ring = FeeSamples::default();
        ring.insert(10, sample(10, 41, true));
        ring.insert(9, sample(9, 41, false));
        let e = ring.estimate(10, 1).unwrap();
        assert!(
            e.congestion_percent > 50 && e.congestion_percent < 100,
            "{e:?}"
        );
        assert!(e.rate > RELAY_FLOOR && e.rate < e.quantile, "{e:?}");
    }

    #[test]
    fn samples_outside_the_window_are_ignored() {
        let mut ring = FeeSamples::default();
        ring.insert(1, sample(1, 50, true));
        assert!(ring.estimate(1 + CAPACITY as u32, 1).is_none());
        assert_eq!(
            ring.highest_recent(1),
            Some(FeeRate::from_sat_per_vb_u32(50))
        );
        assert_eq!(ring.highest_recent(100), None);
    }
}
