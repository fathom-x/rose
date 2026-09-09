//! The shipped per-day birthday table: an offline resolution of a mainnet `--birthday` to
//! a `(height, hash)` scan anchor, for the kyoto `init` path that has no node to ask.
//!
//! `init` on a kyoto wallet stays offline, so before this table a date resolved to
//! nothing better than the shipped scan floor - or, for a date before it, SegWit
//! activation - and a height below the floor started the first scan there too; the true
//! anchor was only found once the first sync had downloaded headers from 2017. The table
//! gives init the answer up front: for every UTC day since SegWit activation, the height
//! and hash of the first block whose header time is at or after that day's midnight,
//! read from a trusted node by `scripts/btc-birthday-table.py` and shipped as
//! `birthdays-main.bin` (~36 bytes a day; the format is documented in the script).
//!
//! The entries are checkpoints in the same sense as [`super::kyoto`]'s scan floors: the
//! first scan trusts a recorded anchor verbatim, so every entry is a block the generator
//! cut at least a thousand blocks below its node's tip, and a regenerated table only
//! *extends* the shipped one (the script checks that). Unlike the floors the table is
//! not load-bearing for backward compatibility - it is consulted at `init` only, and a
//! wallet's anchor lives in its own database - so appending days per release is free.
//!
//! Both lookups err low, as every birthday resolution in zecd does: a date resolves to
//! the first block of the *previous* day (the shared one-day margin, so a block mined
//! late on the day with a drifted-back header time is still covered), and a height to
//! the last day entry at or below it. An anchor a little early only scans a few more
//! filters; one too late would skip funds. Past the table's end - a date or height newer
//! than the build - the last entry still serves, as a **floor** rather than an exact
//! anchor: it is the newest checkpoint the build knows, so a first scan starts there
//! ([`super::kyoto`]'s `recovery_floor` consults it) and the first sync's own resolution
//! refines the birthday from that point. Before the table's start there is nothing to add:
//! SegWit activation, the caller's history floor, is the block before the first entry.

use std::sync::OnceLock;

use bdk_wallet::bitcoin::hashes::Hash as _;
use bdk_wallet::bitcoin::BlockHash;

use crate::coin::BitcoinNetwork;

/// Mainnet, generated 2026-09-04 from a Bitcoin Core 30.2 node at height 965535
/// (entries cut 1000 blocks below it): 2017-08-25 (height 481915) to 2026-08-29
/// (height 964497), 3292 days.
static MAIN_TABLE: &[u8] = include_bytes!("birthdays-main.bin");

const DAY_SECS: u64 = 86_400;
const HEADER_LEN: usize = 8;
const ENTRY_LEN: usize = 4 + 32;

/// A parsed table: `days[i]` is the first block of day `first_day + i`.
struct DayTable {
    /// Days since the unix epoch of entry 0's UTC midnight.
    first_day: u64,
    days: Vec<(u32, BlockHash)>,
}

impl DayTable {
    fn parse(raw: &[u8]) -> Result<DayTable, &'static str> {
        if raw.len() < HEADER_LEN {
            return Err("table shorter than its header");
        }
        let first_day = u64::from(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]));
        let count = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
        if raw.len() != HEADER_LEN + count * ENTRY_LEN {
            return Err("table length does not match its entry count");
        }
        if count == 0 {
            return Err("table holds no entries");
        }
        let mut days = Vec::with_capacity(count);
        let mut previous = 0u32;
        let (entries, rest) = raw[HEADER_LEN..].as_chunks::<ENTRY_LEN>();
        debug_assert!(rest.is_empty(), "checked by the length test above");
        for entry in entries {
            let height = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
            if height <= previous {
                return Err("table heights are not strictly increasing");
            }
            previous = height;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&entry[4..]);
            days.push((height, BlockHash::from_byte_array(hash)));
        }
        Ok(DayTable { first_day, days })
    }

    /// The first block of the day holding `time`, if the table covers that day.
    fn day_of(&self, time: u64) -> Option<(u32, BlockHash)> {
        let index = usize::try_from((time / DAY_SECS).checked_sub(self.first_day)?).ok()?;
        self.days.get(index).copied()
    }

    /// The last day entry at or below `height`, if any.
    fn at_or_below(&self, height: u32) -> Option<(u32, BlockHash)> {
        let index = self.days.partition_point(|(h, _)| *h <= height);
        index.checked_sub(1).map(|i| self.days[i])
    }

    /// The day (since the epoch) of the last entry.
    fn last_day(&self) -> u64 {
        self.first_day + self.days.len() as u64 - 1
    }

    /// The last entry: the newest checkpoint the table holds.
    fn last(&self) -> (u32, BlockHash) {
        *self.days.last().expect("the parser accepts no empty table")
    }
}

fn table(network: BitcoinNetwork) -> Option<&'static DayTable> {
    static MAIN: OnceLock<DayTable> = OnceLock::new();
    match network {
        BitcoinNetwork::Main => Some(MAIN.get_or_init(|| {
            DayTable::parse(MAIN_TABLE).expect("the shipped table is valid; a unit test parses it")
        })),
        // The testnets' shipped floors are recent enough, and their chains reorg deeply;
        // regtest chains are built per run.
        BitcoinNetwork::Testnet3 | BitcoinNetwork::Testnet4 | BitcoinNetwork::Regtest => None,
    }
}

/// A table entry resolved for a birthday: a checkpoint at or below it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DayAnchor {
    pub height: u32,
    pub hash: BlockHash,
    /// Whether the entry is within a day of blocks of the birthday - a scan anchor `init`
    /// records as final. `false` past the table's end, where the last entry is only the
    /// newest floor this build knows and the first sync still has to resolve the birthday
    /// above it.
    pub exact: bool,
}

/// Resolve a `--birthday` date (unix seconds of its UTC midnight) offline: the first block
/// of the previous UTC day - the one-day margin `init`'s node-backed search applies - as
/// an exact anchor; past the table's last day, the last entry as a floor. `None` before
/// the table, where the caller's history floor (SegWit activation) is the answer.
pub fn anchor_for_date(network: BitcoinNetwork, date: u64) -> Option<DayAnchor> {
    let table = table(network)?;
    let day = date.checked_sub(DAY_SECS)?;
    if let Some((height, hash)) = table.day_of(day) {
        return Some(DayAnchor {
            height,
            hash,
            exact: true,
        });
    }
    (day / DAY_SECS > table.last_day()).then(|| {
        let (height, hash) = table.last();
        DayAnchor {
            height,
            hash,
            exact: false,
        }
    })
}

/// The UTC midnight (unix seconds) of the day the table places `height` in: the day of the
/// last entry at or below it. At or before the block's own header time by construction (the
/// entry is the first block of that day), so it serves as a conservative "created no later
/// than" timestamp - what `listdescriptors` reports when no operator date was recorded.
/// `None` below the table's first entry, and on the networks without a table.
pub fn day_start_for_height(network: BitcoinNetwork, height: u32) -> Option<u64> {
    let table = table(network)?;
    let index = table
        .days
        .partition_point(|(h, _)| *h <= height)
        .checked_sub(1)?;
    Some((table.first_day + index as u64) * DAY_SECS)
}

/// Resolve a `--birthday` height offline: the last day entry at or below it - within a day
/// of blocks of the birthday while the table covers it (exact), the table's last entry as
/// a floor past its end. `None` below the table's first entry.
pub fn anchor_for_height(network: BitcoinNetwork, height: u32) -> Option<DayAnchor> {
    let table = table(network)?;
    let (entry_height, hash) = table.at_or_below(height)?;
    Some(DayAnchor {
        height: entry_height,
        hash,
        exact: height <= table.last().0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn midnight(date: &str) -> u64 {
        let ymd: Vec<i64> = date.split('-').map(|p| p.parse().unwrap()).collect();
        u64::try_from(crate::init::days_from_civil(ymd[0], ymd[1], ymd[2])).unwrap() * DAY_SECS
    }

    /// The shipped mainnet table parses, starts the day after SegWit activation, and
    /// advances by a plausible number of blocks a day - the checks the generator's format
    /// promise reduces to.
    #[test]
    fn shipped_mainnet_table_is_well_formed() {
        let table = table(BitcoinNetwork::Main).unwrap();
        assert_eq!(table.first_day * DAY_SECS, midnight("2017-08-25"));
        assert!(table.days.len() >= 3292, "{}", table.days.len());
        assert_eq!(table.days[0].0, 481_915);
        assert_eq!(
            table.days[0].1.to_string(),
            "0000000000000000012e615427e05955a38606a06e3bc36a52491089333448a2"
        );
        for pair in table.days.windows(2) {
            let delta = pair[1].0 - pair[0].0;
            assert!((30..=400).contains(&delta), "{pair:?}");
        }
        for network in [
            BitcoinNetwork::Testnet3,
            BitcoinNetwork::Testnet4,
            BitcoinNetwork::Regtest,
        ] {
            assert!(anchor_for_date(network, midnight("2025-01-01")).is_none());
            assert!(anchor_for_height(network, 1_000_000).is_none());
        }
        assert!(DayTable::parse(&MAIN_TABLE[..HEADER_LEN]).is_err());
        let mut empty = MAIN_TABLE[..HEADER_LEN].to_vec();
        empty[4..].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            DayTable::parse(&empty).err(),
            Some("table holds no entries")
        );
    }

    /// Two independently recorded mainnet facts bracket the table: the shipped kyoto scan
    /// floor (block 960000, mined 2026-07-28) falls between that day's entry and the
    /// next, and block 800000 (mined 2023-07-24 01:39 UTC) likewise.
    #[test]
    fn table_agrees_with_the_shipped_scan_floor() {
        let table = table(BitcoinNetwork::Main).unwrap();
        let floor = crate::btc::kyoto::scan_floor(BitcoinNetwork::Main).unwrap();
        let (floor_height, floor_time) = (floor.height, floor.time);
        let day = table.day_of(floor_time).unwrap().0;
        let next = table.day_of(floor_time + DAY_SECS).unwrap().0;
        assert!(
            day <= floor_height && floor_height < next,
            "{day} {floor_height} {next}"
        );
        let day = table.day_of(midnight("2023-07-24")).unwrap().0;
        let next = table.day_of(midnight("2023-07-25")).unwrap().0;
        assert!(day <= 800_000 && 800_000 < next, "{day} {next}");
    }

    /// A date resolves exactly to the first block of the previous day; a date before the
    /// table resolves to nothing (SegWit activation is the caller's floor); a date past
    /// the table resolves to the last entry, marked as a floor.
    #[test]
    fn dates_resolve_a_day_low_within_the_table() {
        let table = table(BitcoinNetwork::Main).unwrap();
        let anchor = anchor_for_date(BitcoinNetwork::Main, midnight("2025-01-02")).unwrap();
        assert_eq!(
            (anchor.height, anchor.hash),
            table.day_of(midnight("2025-01-01")).unwrap()
        );
        assert_eq!(anchor.height, 877_259);
        assert!(anchor.exact);
        // The first day the table can answer is the one after its first entry's day.
        assert!(anchor_for_date(BitcoinNetwork::Main, midnight("2017-08-25")).is_none());
        assert!(anchor_for_date(BitcoinNetwork::Main, 0).is_none());
        let first = anchor_for_date(BitcoinNetwork::Main, midnight("2017-08-26")).unwrap();
        assert_eq!((first.height, first.hash), table.days[0]);
        assert!(first.exact);
        // The last day is exact; every later day is the last entry as a floor.
        let last_day = table.last_day() * DAY_SECS;
        let on_last = anchor_for_date(BitcoinNetwork::Main, last_day + DAY_SECS).unwrap();
        assert_eq!((on_last.height, on_last.hash), table.last());
        assert!(on_last.exact);
        for later in [last_day + 2 * DAY_SECS, last_day + 400 * DAY_SECS, u64::MAX] {
            let floor = anchor_for_date(BitcoinNetwork::Main, later).unwrap();
            assert_eq!((floor.height, floor.hash), table.last(), "{later}");
            assert!(!floor.exact, "{later}");
        }
    }

    /// A height resolves to the last day entry at or below it: exact on an entry, the
    /// previous entry between two, nothing below the first, and the last entry as a floor
    /// past the table's end.
    #[test]
    fn heights_resolve_to_the_last_entry_at_or_below() {
        let table = table(BitcoinNetwork::Main).unwrap();
        let entry = |i: usize, exact: bool| DayAnchor {
            height: table.days[i].0,
            hash: table.days[i].1,
            exact,
        };
        let (h0, _) = table.days[0];
        let (h1, _) = table.days[1];
        assert!(anchor_for_height(BitcoinNetwork::Main, h0 - 1).is_none());
        assert_eq!(
            anchor_for_height(BitcoinNetwork::Main, h0),
            Some(entry(0, true))
        );
        assert_eq!(
            anchor_for_height(BitcoinNetwork::Main, h1 - 1),
            Some(entry(0, true))
        );
        assert_eq!(
            anchor_for_height(BitcoinNetwork::Main, h1),
            Some(entry(1, true))
        );
        let last = table.days.len() - 1;
        let (last_height, _) = table.last();
        assert_eq!(
            anchor_for_height(BitcoinNetwork::Main, last_height),
            Some(entry(last, true))
        );
        for past in [last_height + 1, last_height + 100_000, u32::MAX] {
            assert_eq!(
                anchor_for_height(BitcoinNetwork::Main, past),
                Some(entry(last, false)),
                "{past}"
            );
        }
        // 877100 (the height an operator would pass for "start of 2025") anchors within
        // a day of blocks below itself: at the last entry not above it, with the next
        // entry above.
        let DayAnchor { height, exact, .. } =
            anchor_for_height(BitcoinNetwork::Main, 877_100).unwrap();
        assert!(exact);
        let index = table.days.iter().position(|(h, _)| *h == height).unwrap();
        assert!(height <= 877_100 && 877_100 - height < 300, "{height}");
        assert!(table.days[index + 1].0 > 877_100);
    }

    /// A height maps to the midnight of its table day: the 2025-01-01 entry's height and
    /// the last block of that day both give that midnight, the block before gives the day
    /// before, and heights below the table (or any height on a table-less network) give
    /// nothing.
    #[test]
    fn day_start_for_height_is_the_entrys_day() {
        let table = table(BitcoinNetwork::Main).unwrap();
        let (h, _) = table.day_of(midnight("2025-01-01")).unwrap();
        let (next, _) = table.day_of(midnight("2025-01-02")).unwrap();
        assert_eq!(
            day_start_for_height(BitcoinNetwork::Main, h),
            Some(midnight("2025-01-01"))
        );
        assert_eq!(
            day_start_for_height(BitcoinNetwork::Main, next - 1),
            Some(midnight("2025-01-01"))
        );
        assert_eq!(
            day_start_for_height(BitcoinNetwork::Main, h - 1),
            Some(midnight("2024-12-31"))
        );
        assert_eq!(day_start_for_height(BitcoinNetwork::Main, 481_824), None);
        assert_eq!(
            day_start_for_height(BitcoinNetwork::Testnet4, 150_000),
            None
        );
    }

    /// The parser refuses a truncated, mis-sized or non-monotonic table rather than
    /// shipping a wrong anchor.
    #[test]
    fn parser_refuses_malformed_tables() {
        assert!(DayTable::parse(&[]).is_err());
        assert!(DayTable::parse(&MAIN_TABLE[..MAIN_TABLE.len() - 1]).is_err());
        let mut swapped = MAIN_TABLE.to_vec();
        let (a, b) = (HEADER_LEN, HEADER_LEN + ENTRY_LEN);
        let first = swapped[a..a + ENTRY_LEN].to_vec();
        let second = swapped[b..b + ENTRY_LEN].to_vec();
        swapped[a..a + ENTRY_LEN].copy_from_slice(&second);
        swapped[b..b + ENTRY_LEN].copy_from_slice(&first);
        assert_eq!(
            DayTable::parse(&swapped).err(),
            Some("table heights are not strictly increasing")
        );
    }
}
