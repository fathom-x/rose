//! Ancestor-aware funding: a send that spends an output of an unconfirmed transaction pays
//! whatever it takes for that transaction's unconfirmed ancestry to be mined at the send's
//! own rate - Bitcoin Core's behaviour since 26.0 (bitcoin/bitcoin#26152), and the wallet's
//! child-pays-for-parent. A 1 sat/vB send stuck under a rising market is unstuck by the
//! next send that spends its change, at that send's rate, with no separate RPC.
//!
//! The mechanism is Core's. Every unconfirmed candidate output is priced at its *effective
//! value*: its value less its **bump fee**, the fee its ancestors lack at the target rate.
//! Coin selection runs on those values, so it prefers a confirmed coin to one that drags a
//! cheap parent along, just as Core's does. The selected outputs then carry their real
//! values into the transaction, and the difference lands in the fee. Two selected outputs
//! that share an ancestor would each have paid for it, so the change output gets back the
//! excess of the individual bump fees over the **combined** bump fee of the whole
//! selection (Core's `CalculateCombinedBumpFee`).
//!
//! A bump fee is what a miner sorting by ancestor score would leave unpaid. A small mining
//! simulation - Core's `MiniMiner`, over the ancestors alone - first takes out every
//! ancestor package that already clears the target by itself. Whatever remains is short,
//! and the bump is that remainder's shortfall at the target rate. So a parent that some
//! earlier high-fee child already pays for costs nothing again.
//!
//! What the wallet cannot price, it does not spend. Over kyoto the wallet sees a foreign
//! sender's unconfirmed payment without its parents' values, and over either backend its
//! ancestry is outside the wallet. Core refuses such an output by default (it is not
//! "trusted"; `include_unsafe` opts in), and so does this: only an unconfirmed output
//! whose whole unconfirmed ancestry is the wallet's own funded transactions, each with a
//! known fee, is a candidate. The rest are marked unspendable before selection.
//!
//! One gap remains, shared with Core: a descendant of the ancestors that is *not* in the
//! wallet (someone else's CPFP of a payment to us) is invisible here, so the bump can
//! overpay for ancestors a stranger already paid for. It never underpays.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bdk_wallet::bitcoin::{Amount, FeeRate, OutPoint, Script, Txid};
use bdk_wallet::coin_selection::{
    CoinSelectionAlgorithm, CoinSelectionResult, DefaultCoinSelectionAlgorithm, Excess,
    InsufficientFunds,
};
use bdk_wallet::{Utxo, WeightedUtxo};
use rand::RngCore;

/// One unconfirmed wallet transaction, as [`Ancestry::new`] takes it.
#[derive(Debug, Clone)]
pub struct Unconfirmed {
    pub txid: Txid,
    /// Its fee in satoshis, or `None` where the wallet cannot compute it (an input it does
    /// not hold the value of).
    pub fee: Option<u64>,
    pub vsize: u64,
    /// Whether the wallet funded it (Core's trust rule, `BtcActor::funded_txids`).
    pub funded: bool,
    /// The txids its inputs spend. A parent that is not itself an [`Unconfirmed`] entry is
    /// taken as confirmed, unless it is listed in `unknown_parents`.
    pub parents: Vec<Txid>,
    /// Whether some input spends a transaction the wallet does not hold at all, so its
    /// confirmation status is unknown.
    pub unknown_parents: bool,
}

#[derive(Debug)]
struct Node {
    fee: u64,
    vsize: u64,
    /// Unconfirmed parents only.
    parents: Vec<Txid>,
}

/// The wallet's priceable unconfirmed transactions, and which of them may be spent from.
#[derive(Debug, Default)]
pub struct Ancestry {
    nodes: HashMap<Txid, Node>,
    /// Transactions whose outputs may fund a send: funded, fee known, every unconfirmed
    /// ancestor likewise.
    spendable: HashSet<Txid>,
}

impl Ancestry {
    pub fn new(txs: impl IntoIterator<Item = Unconfirmed>) -> Self {
        let txs: HashMap<Txid, Unconfirmed> = txs.into_iter().map(|tx| (tx.txid, tx)).collect();
        let nodes: HashMap<Txid, Node> = txs
            .values()
            .filter_map(|tx| {
                Some((
                    tx.txid,
                    Node {
                        fee: tx.fee?,
                        vsize: tx.vsize,
                        parents: tx
                            .parents
                            .iter()
                            .filter(|p| txs.contains_key(*p))
                            .copied()
                            .collect::<HashSet<_>>()
                            .into_iter()
                            .collect(),
                    },
                ))
            })
            .collect();
        // A transaction is spendable when it and every unconfirmed ancestor pass. Resolved
        // by a fixed point, which also leaves any cycle (impossible in a real graph)
        // unspendable rather than looping.
        let own_ok = |tx: &Unconfirmed| tx.funded && tx.fee.is_some() && !tx.unknown_parents;
        let mut spendable: HashSet<Txid> = HashSet::new();
        loop {
            let before = spendable.len();
            for tx in txs.values() {
                if !spendable.contains(&tx.txid)
                    && own_ok(tx)
                    && tx
                        .parents
                        .iter()
                        .all(|p| !txs.contains_key(p) || spendable.contains(p))
                {
                    spendable.insert(tx.txid);
                }
            }
            if spendable.len() == before {
                break;
            }
        }
        Self { nodes, spendable }
    }

    /// Whether an unconfirmed transaction's outputs may fund a send. `false` for a
    /// transaction this set does not know, which the caller only asks about when the
    /// wallet holds it unconfirmed.
    pub fn is_spendable(&self, txid: &Txid) -> bool {
        self.spendable.contains(txid)
    }

    /// The fee, in satoshis, that spending outputs of `txids` must add so their unconfirmed
    /// ancestry (themselves included) is mined at `rate_sat_per_kvb`. A confirmed or unknown
    /// txid contributes nothing. See the module doc for the mining simulation.
    pub fn bump_fee(&self, txids: impl IntoIterator<Item = Txid>, rate_sat_per_kvb: u64) -> u64 {
        let mut cluster: HashSet<Txid> = HashSet::new();
        let mut stack: Vec<Txid> = txids
            .into_iter()
            .filter(|t| self.nodes.contains_key(t))
            .collect();
        while let Some(txid) = stack.pop() {
            if cluster.insert(txid) {
                stack.extend(self.nodes[&txid].parents.iter().copied());
            }
        }
        loop {
            // The package a miner takes next: the highest-rate ancestor set still left.
            let best = cluster
                .iter()
                .map(|txid| {
                    let set = self.ancestors_within(*txid, &cluster);
                    let (fee, vsize) = self.totals(&set);
                    (set, fee, vsize)
                })
                .max_by(|(_, fa, va), (_, fb, vb)| {
                    (u128::from(*fa) * u128::from(*vb)).cmp(&(u128::from(*fb) * u128::from(*va)))
                });
            match best {
                Some((set, fee, vsize)) if meets(fee, vsize, rate_sat_per_kvb) => {
                    cluster.retain(|t| !set.contains(t));
                }
                _ => break,
            }
        }
        let (fee, vsize) = self.totals(&cluster);
        fee_at(rate_sat_per_kvb, vsize).saturating_sub(fee)
    }

    fn ancestors_within(&self, txid: Txid, within: &HashSet<Txid>) -> HashSet<Txid> {
        let mut set = HashSet::new();
        let mut stack = vec![txid];
        while let Some(txid) = stack.pop() {
            if within.contains(&txid) && set.insert(txid) {
                stack.extend(self.nodes[&txid].parents.iter().copied());
            }
        }
        set
    }

    fn totals(&self, set: &HashSet<Txid>) -> (u64, u64) {
        set.iter().fold((0, 0), |(fee, vsize), txid| {
            let node = &self.nodes[txid];
            (fee + node.fee, vsize + node.vsize)
        })
    }
}

/// Core's `CFeeRate::GetFee`: the fee for `vsize` at `rate`, rounded up.
fn fee_at(rate_sat_per_kvb: u64, vsize: u64) -> u64 {
    let fee = (u128::from(rate_sat_per_kvb) * u128::from(vsize)).div_ceil(1_000);
    u64::try_from(fee).unwrap_or(u64::MAX)
}

/// Whether `fee` over `vsize` is at or above the rate.
fn meets(fee: u64, vsize: u64, rate_sat_per_kvb: u64) -> bool {
    u128::from(fee) * 1_000 >= u128::from(rate_sat_per_kvb) * u128::from(vsize)
}

/// BDK's default coin selection over effective values: see the module doc. Hand it to
/// `TxBuilder::coin_selection`; after the build, [`Self::paid`] reads the combined bump fee
/// the selection carries.
#[derive(Debug)]
pub struct AncestorAware {
    ancestry: Arc<Ancestry>,
    rate_sat_per_kvb: u64,
    paid: Arc<AtomicU64>,
    inner: DefaultCoinSelectionAlgorithm,
}

impl AncestorAware {
    pub fn new(ancestry: Arc<Ancestry>, rate: FeeRate) -> Self {
        Self {
            ancestry,
            rate_sat_per_kvb: rate.to_sat_per_kwu().saturating_mul(4),
            paid: Arc::new(AtomicU64::new(0)),
            inner: DefaultCoinSelectionAlgorithm::default(),
        }
    }

    /// A handle on the combined bump fee the last selection carried (0 until one ran).
    pub fn paid(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.paid)
    }

    /// Lower a candidate to its effective value, returning its real value and the bump fee
    /// it now carries - or `None` for an optional candidate that cannot pay its own way.
    fn discount(&self, utxo: &mut WeightedUtxo, required: bool) -> Option<(Amount, u64)> {
        let Utxo::Local(local) = &mut utxo.utxo else {
            return Some((utxo.utxo.txout().value, 0));
        };
        let value = local.txout.value;
        let bump = self
            .ancestry
            .bump_fee([local.outpoint.txid], self.rate_sat_per_kvb);
        if bump >= value.to_sat() && !required {
            return None;
        }
        local.txout.value = value
            .checked_sub(Amount::from_sat(bump))
            .unwrap_or(Amount::ZERO);
        Some((value, bump))
    }
}

impl CoinSelectionAlgorithm for AncestorAware {
    fn coin_select<R: RngCore>(
        &self,
        mut required_utxos: Vec<WeightedUtxo>,
        optional_utxos: Vec<WeightedUtxo>,
        fee_rate: FeeRate,
        target_amount: Amount,
        drain_script: &Script,
        rand: &mut R,
    ) -> Result<CoinSelectionResult, InsufficientFunds> {
        let mut real: HashMap<OutPoint, (Amount, u64)> = HashMap::new();
        for utxo in &mut required_utxos {
            if let Some(entry) = self.discount(utxo, true) {
                real.insert(utxo.utxo.outpoint(), entry);
            }
        }
        let optional_utxos: Vec<WeightedUtxo> = optional_utxos
            .into_iter()
            .filter_map(|mut utxo| {
                let entry = self.discount(&mut utxo, false)?;
                real.insert(utxo.utxo.outpoint(), entry);
                Some(utxo)
            })
            .collect();
        let mut result = self.inner.coin_select(
            required_utxos,
            optional_utxos,
            fee_rate,
            target_amount,
            drain_script,
            rand,
        )?;
        // Real values back into the transaction, then the shared-ancestor refund.
        let mut individual = 0u64;
        let mut bumped = Vec::new();
        for utxo in &mut result.selected {
            if let Utxo::Local(local) = utxo {
                if let Some((value, bump)) = real.get(&local.outpoint) {
                    local.txout.value = *value;
                    individual += bump;
                    if *bump > 0 {
                        bumped.push(local.outpoint.txid);
                    }
                }
            }
        }
        let combined = self.ancestry.bump_fee(bumped, self.rate_sat_per_kvb);
        let refund = individual.saturating_sub(combined);
        // A changeless selection keeps the refund as fee: it is under the change output's
        // own cost or dust bound, which is why there is no change.
        if let Excess::Change { amount, .. } = &mut result.excess {
            *amount += Amount::from_sat(refund);
        }
        result.fee_amount += Amount::from_sat(combined);
        self.paid.store(combined, Ordering::Relaxed);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::hashes::Hash as _;

    fn txid(n: u8) -> Txid {
        Txid::from_byte_array([n; 32])
    }

    fn tx(n: u8, fee: u64, vsize: u64, parents: &[u8]) -> Unconfirmed {
        Unconfirmed {
            txid: txid(n),
            fee: Some(fee),
            vsize,
            funded: true,
            parents: parents.iter().map(|p| txid(*p)).collect(),
            unknown_parents: false,
        }
    }

    #[test]
    fn a_cheap_parent_is_topped_up_to_the_target() {
        // 1 sat/vB parent of 200 vB; target 10 sat/vB: 2000 - 200 short.
        let a = Ancestry::new([tx(1, 200, 200, &[])]);
        assert_eq!(a.bump_fee([txid(1)], 10_000), 1_800);
        // Already at the target: nothing.
        assert_eq!(a.bump_fee([txid(1)], 1_000), 0);
        // Confirmed (unknown to the set): nothing.
        assert_eq!(a.bump_fee([txid(9)], 10_000), 0);
    }

    #[test]
    fn a_grandparent_is_paid_for_through_the_chain() {
        // A (1 sat/vB) <- B (1 sat/vB): spending B pays for both.
        let a = Ancestry::new([tx(1, 100, 100, &[]), tx(2, 100, 100, &[1])]);
        assert_eq!(a.bump_fee([txid(2)], 5_000), 1_000 - 200);
        // Spending A alone pays for A alone.
        assert_eq!(a.bump_fee([txid(1)], 5_000), 400);
    }

    #[test]
    fn an_ancestor_already_paid_for_costs_nothing_again() {
        // A (1 sat/vB, 100 vB) <- B (19 sat/vB, 100 vB): the package clears 10 sat/vB, so
        // a miner takes it without our help.
        let a = Ancestry::new([tx(1, 100, 100, &[]), tx(2, 1_900, 100, &[1])]);
        assert_eq!(a.bump_fee([txid(2)], 10_000), 0);
        // A high-fee parent does not subsidise a cheap child: A (20 sat/vB) is mined alone,
        // and B (1 sat/vB) is short on its own.
        let a = Ancestry::new([tx(1, 2_000, 100, &[]), tx(2, 100, 100, &[1])]);
        assert_eq!(a.bump_fee([txid(2)], 10_000), 900);
    }

    #[test]
    fn shared_ancestors_are_paid_for_once() {
        // Two outputs of the same cheap parent A.
        let a = Ancestry::new([
            tx(1, 100, 100, &[]),
            tx(2, 100, 100, &[1]),
            tx(3, 100, 100, &[1]),
        ]);
        let each = a.bump_fee([txid(2)], 2_000);
        assert_eq!(each, 400 - 200);
        assert_eq!(a.bump_fee([txid(2), txid(3)], 2_000), 600 - 300);
        assert!(a.bump_fee([txid(2), txid(3)], 2_000) < 2 * each);
    }

    #[test]
    fn only_a_fully_priceable_own_ancestry_is_spendable() {
        let mut foreign = tx(1, 0, 100, &[]);
        foreign.funded = false;
        let mut unpriced = tx(3, 0, 100, &[]);
        unpriced.fee = None;
        let mut orphan = tx(5, 100, 100, &[]);
        orphan.unknown_parents = true;
        let a = Ancestry::new([
            foreign,
            tx(2, 100, 100, &[1]),
            unpriced,
            tx(4, 100, 100, &[3]),
            orphan,
            tx(6, 100, 100, &[]),
            tx(7, 100, 100, &[6]),
        ]);
        for n in [1, 2, 3, 4, 5] {
            assert!(!a.is_spendable(&txid(n)), "{n}");
        }
        for n in [6, 7] {
            assert!(a.is_spendable(&txid(n)), "{n}");
        }
    }
}
