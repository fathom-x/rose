//! The spending policy (`[wallets.<name>.spend_policy]`) as the Bitcoin engine
//! enforces it: a recipient allowlist, a per-send cap and a cap over a block window.
//!
//! What it bounds is the RPC caller. Whoever holds the RPC credentials can otherwise move
//! the whole balance in one call; with a policy, a stolen password moves at most the caps,
//! and only to addresses the deployment already trusts. In an attested enclave the policy
//! sits in the baked config, which the measurement covers, so the attestation vouches for
//! it; that is why it is config-file only, with no environment override and no RPC that
//! changes it.
//!
//! The rules, all checked on the built (unsigned) transaction, before a signer exists:
//!
//! * Only outputs to scripts the wallet does not own are restricted or counted: change and
//!   self-sends pass and cost nothing. "Owns" is BDK's `is_mine`, the revealed scripts plus
//!   the lookahead.
//! * `allow_recipients`: every external output must pay an allowlisted script.
//! * `max_per_transaction_sat`: the external outputs of this one transaction, summed.
//! * `max_per_day_sat`: this transaction's external total plus that of every transaction
//!   the wallet funded that is unconfirmed or confirmed within the last
//!   [`WINDOW_BLOCKS`] blocks of the wallet's tip. A replacement (`bumpfee`) is counted in
//!   place of its original, not beside it.
//!
//! Fees are not counted: `[fees] max_tx_fee_sat` bounds those.
//!
//! **Statelessness.** The window total is a read over the wallet's own history (the
//! transactions it funded, with their confirmation heights), never a counter of its own,
//! so a restart re-derives the same total from the database, and a from-seed restore from
//! the chain once the wallet has caught up. The one gap is the post-restore window in
//! which an earlier instance's unconfirmed sends are not yet known: the send gate
//! (`BtcActor::send_gate`) already refuses every send there until a mempool view exists.
//! Counting in blocks, not wall-clock time, keeps the host's clock out of it: a parent host
//! can move an enclave's clock, not the chain. A host withholding blocks only freezes the
//! window, which tightens it.

use std::collections::HashSet;

use bdk_wallet::bitcoin::{Address, Network, ScriptBuf, TxOut, Txid};

use crate::config::SpendPolicyConfig;

pub use crate::config::SPEND_POLICY_WINDOW_BLOCKS as WINDOW_BLOCKS;

/// A resolved policy, the allowlist as scripts.
#[derive(Debug, Clone)]
pub struct SpendPolicy {
    /// `None` restricts nothing.
    allow: Option<HashSet<ScriptBuf>>,
    max_per_transaction_sat: Option<u64>,
    max_per_day_sat: Option<u64>,
    network: Network,
}

/// One wallet-funded transaction's payments to scripts the wallet does not own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outflow {
    pub txid: Txid,
    /// The confirming block's height; `None` while unconfirmed.
    pub height: Option<u32>,
    /// Satoshis paid to scripts outside the wallet.
    pub paid_sat: u64,
}

/// Why the policy refuses a send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// An external output pays a script not on the allowlist.
    NotAllowed { recipient: String },
    /// The send alone pays more than `max_per_transaction_sat`.
    OverTransaction { paid_sat: u64, cap_sat: u64 },
    /// The send would take the window total past `max_per_day_sat`.
    OverWindow {
        paid_sat: u64,
        spent_sat: u64,
        cap_sat: u64,
    },
}

impl Refusal {
    /// The `-4` message: names the knob, and for a cap what is left.
    pub fn message(&self) -> String {
        match self {
            Refusal::NotAllowed { recipient } => format!(
                "Spending policy: {recipient} is not in this wallet's \
                 [wallets.<name>.spend_policy] allow_recipients; nothing was signed or sent"
            ),
            Refusal::OverTransaction { paid_sat, cap_sat } => format!(
                "Spending policy: this send pays {} to recipients outside the wallet, over \
                 max_per_transaction_sat ({}); nothing was signed or sent",
                btc(*paid_sat),
                btc(*cap_sat),
            ),
            Refusal::OverWindow {
                paid_sat,
                spent_sat,
                cap_sat,
            } => format!(
                "Spending policy: this send pays {} to recipients outside the wallet, and \
                 {} has already gone out in the last {WINDOW_BLOCKS} blocks (unconfirmed \
                 sends included); max_per_day_sat ({}) leaves {} for now; nothing was \
                 signed or sent",
                btc(*paid_sat),
                btc(*spent_sat),
                btc(*cap_sat),
                btc(cap_sat.saturating_sub(*spent_sat)),
            ),
        }
    }

    /// A short tag for the audit log.
    pub fn rule(&self) -> &'static str {
        match self {
            Refusal::NotAllowed { .. } => "allow_recipients",
            Refusal::OverTransaction { .. } => "max_per_transaction_sat",
            Refusal::OverWindow { .. } => "max_per_day_sat",
        }
    }
}

fn btc(sat: u64) -> String {
    format!(
        "{}.{:08} BTC",
        sat / crate::amount::COIN,
        sat % crate::amount::COIN
    )
}

impl SpendPolicy {
    /// The engine's form of a resolved config, `None` when the config sets no rule. The
    /// addresses were validated for `network` at resolve; one that no longer parses is an
    /// error here rather than a dropped entry, so the allowlist never silently widens or
    /// narrows.
    pub fn from_config(
        config: &SpendPolicyConfig,
        network: Network,
    ) -> anyhow::Result<Option<Self>> {
        if !config.is_active() {
            return Ok(None);
        }
        let allow = match &config.allow_recipients {
            None => None,
            Some(list) => {
                let mut set = HashSet::with_capacity(list.len());
                for addr in list {
                    let address: Address = addr
                        .parse::<Address<_>>()
                        .map_err(|e| anyhow::anyhow!("spend_policy allow_recipients {addr}: {e}"))?
                        .require_network(network)
                        .map_err(|e| {
                            anyhow::anyhow!("spend_policy allow_recipients {addr}: {e}")
                        })?;
                    set.insert(address.script_pubkey());
                }
                Some(set)
            }
        };
        Ok(Some(SpendPolicy {
            allow,
            max_per_transaction_sat: config.max_per_transaction_sat,
            max_per_day_sat: config.max_per_day_sat,
            network,
        }))
    }

    /// How many recipients the allowlist names, `None` with no allowlist.
    pub fn allow_count(&self) -> Option<usize> {
        self.allow.as_ref().map(HashSet::len)
    }

    pub fn max_per_transaction_sat(&self) -> Option<u64> {
        self.max_per_transaction_sat
    }

    pub fn max_per_day_sat(&self) -> Option<u64> {
        self.max_per_day_sat
    }

    /// Check a built transaction's external outputs (`external`: the outputs to scripts
    /// the wallet does not own) against every rule, given what already went out in the
    /// window (`window_spent_sat`, from [`window_total`]). The allowlist first, then the
    /// per-send cap, then the window, so the message names the most specific problem.
    pub fn check(&self, external: &[&TxOut], window_spent_sat: u64) -> Result<(), Refusal> {
        if let Some(allow) = &self.allow {
            if let Some(out) = external.iter().find(|o| !allow.contains(&o.script_pubkey)) {
                let recipient = Address::from_script(&out.script_pubkey, self.network)
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| format!("script {}", out.script_pubkey));
                return Err(Refusal::NotAllowed { recipient });
            }
        }
        let paid_sat = external
            .iter()
            .fold(0u64, |sum, o| sum.saturating_add(o.value.to_sat()));
        if let Some(cap_sat) = self.max_per_transaction_sat {
            if paid_sat > cap_sat {
                return Err(Refusal::OverTransaction { paid_sat, cap_sat });
            }
        }
        if let Some(cap_sat) = self.max_per_day_sat {
            if window_spent_sat.saturating_add(paid_sat) > cap_sat {
                return Err(Refusal::OverWindow {
                    paid_sat,
                    spent_sat: window_spent_sat,
                    cap_sat,
                });
            }
        }
        Ok(())
    }
}

/// Whether a transaction at `height` (`None`: unconfirmed) is inside the window ending at
/// the wallet's `tip`: unconfirmed always, confirmed when it is one of the last
/// [`WINDOW_BLOCKS`] blocks (the tip itself is the first). A height above the tip (a view
/// that has not caught up) counts too: the rule only ever errs toward counting.
pub fn in_window(height: Option<u32>, tip: u32) -> bool {
    match height {
        None => true,
        Some(h) => tip.saturating_sub(h) < WINDOW_BLOCKS,
    }
}

/// The external total of every outflow in the window ending at `tip`, skipping `exclude`
/// (the original a replacement takes the place of).
pub fn window_total(outflows: &[Outflow], tip: u32, exclude: Option<Txid>) -> u64 {
    outflows
        .iter()
        .filter(|o| Some(o.txid) != exclude && in_window(o.height, tip))
        .fold(0u64, |sum, o| sum.saturating_add(o.paid_sat))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::hashes::Hash as _;
    use bdk_wallet::bitcoin::Amount;

    /// A distinct regtest address per `n` (a P2WSH of a one-byte script).
    fn addr(n: u8) -> String {
        Address::p2wsh(&ScriptBuf::from_bytes(vec![n]), Network::Regtest).to_string()
    }

    fn txid(n: u8) -> Txid {
        Txid::from_byte_array([n; 32])
    }

    fn out(addr: &str, sat: u64) -> TxOut {
        let address: Address = addr
            .parse::<Address<_>>()
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap();
        TxOut {
            value: Amount::from_sat(sat),
            script_pubkey: address.script_pubkey(),
        }
    }

    fn policy(allow: Option<&[&str]>, per_tx: Option<u64>, per_day: Option<u64>) -> SpendPolicy {
        SpendPolicy::from_config(
            &SpendPolicyConfig {
                allow_recipients: allow.map(|a| a.iter().map(|s| s.to_string()).collect()),
                max_per_transaction_sat: per_tx,
                max_per_day_sat: per_day,
            },
            Network::Regtest,
        )
        .unwrap()
        .unwrap()
    }

    #[test]
    fn no_rule_is_no_policy() {
        assert!(
            SpendPolicy::from_config(&SpendPolicyConfig::default(), Network::Regtest)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn window_counts_unconfirmed_and_the_last_144_blocks_only() {
        let tip = 1_000;
        assert!(in_window(None, tip));
        assert!(in_window(Some(tip), tip));
        assert!(in_window(Some(tip - (WINDOW_BLOCKS - 1)), tip));
        assert!(!in_window(Some(tip - WINDOW_BLOCKS), tip));
        // A view behind its own record errs toward counting.
        assert!(in_window(Some(tip + 5), tip));
        // A young chain: everything since genesis is in the window.
        assert!(in_window(Some(0), 10));

        let outflows = [
            Outflow {
                txid: txid(1),
                height: None,
                paid_sat: 10,
            },
            Outflow {
                txid: txid(2),
                height: Some(tip),
                paid_sat: 100,
            },
            Outflow {
                txid: txid(3),
                height: Some(tip - 143),
                paid_sat: 1_000,
            },
            Outflow {
                txid: txid(4),
                height: Some(tip - 144),
                paid_sat: 10_000,
            },
        ];
        assert_eq!(window_total(&outflows, tip, None), 1_110);
        // A replacement is counted in place of its original.
        assert_eq!(window_total(&outflows, tip, Some(txid(1))), 1_100);
        // The window slides: one block later the oldest counted send drops out.
        assert_eq!(window_total(&outflows, tip + 1, None), 110);
    }

    #[test]
    fn allowlist_refuses_an_unlisted_recipient_and_names_it() {
        let allowed = addr(1);
        let p = policy(Some(&[&allowed]), None, None);
        let ok = out(&allowed, 5_000);
        let bad = out(&addr(2), 1);
        assert_eq!(p.check(&[&ok], 0), Ok(()));
        let refusal = p.check(&[&ok, &bad], 0).unwrap_err();
        assert_eq!(refusal, Refusal::NotAllowed { recipient: addr(2) });
        assert!(refusal.message().contains("allow_recipients"));
        // No external output at all (a self-send): nothing to refuse.
        assert_eq!(p.check(&[], 0), Ok(()));
    }

    #[test]
    fn per_transaction_cap_sums_every_external_output() {
        let p = policy(None, Some(10_000), None);
        let a = out(&addr(1), 6_000);
        let b = out(&addr(2), 4_000);
        assert_eq!(p.check(&[&a, &b], 0), Ok(()));
        let c = out(&addr(2), 4_001);
        let refusal = p.check(&[&a, &c], 0).unwrap_err();
        assert_eq!(
            refusal,
            Refusal::OverTransaction {
                paid_sat: 10_001,
                cap_sat: 10_000
            }
        );
        assert!(refusal.message().contains("max_per_transaction_sat"));
    }

    #[test]
    fn window_cap_counts_what_already_went_out_and_reports_the_rest() {
        let p = policy(None, None, Some(100_000));
        let send = out(&addr(2), 40_000);
        assert_eq!(p.check(&[&send], 60_000), Ok(()));
        let refusal = p.check(&[&send], 60_001).unwrap_err();
        assert_eq!(
            refusal,
            Refusal::OverWindow {
                paid_sat: 40_000,
                spent_sat: 60_001,
                cap_sat: 100_000
            }
        );
        let msg = refusal.message();
        assert!(msg.contains("max_per_day_sat"), "{msg}");
        assert!(msg.contains("leaves 0.00039999 BTC"), "{msg}");
    }

    #[test]
    fn the_allowlist_is_checked_before_the_caps() {
        let p = policy(Some(&[&addr(1)]), Some(1), Some(1));
        let bad = out(&addr(2), 5);
        assert_eq!(p.check(&[&bad], 0).unwrap_err().rule(), "allow_recipients");
    }

    #[test]
    fn btc_formats_eight_places() {
        assert_eq!(btc(1), "0.00000001 BTC");
        assert_eq!(btc(150_000_000), "1.50000000 BTC");
    }
}
