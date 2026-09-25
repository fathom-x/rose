//! The currency a `zecd` wallet serves, and the chain it serves it on.
//!
//! [`Coin`] is what the shared layer - config, the wallet registry, dispatch, the address
//! codec - names when it needs to say *which* currency a wallet deals in, so those modules
//! stop hard-coding the answer and stop reaching for `zcash_protocol` to express it. A wallet
//! carries its own value rather than reading a global, which is what lets an error message
//! ("Invalid Zcash address") and a backend token be resolved from the wallet being served.
//!
//! A wallet's concrete chain is derived from (its coin, the daemon's network environment) via
//! [`Coin::chain`], never configured independently: `--testnet`/`--regtest` say "this daemon
//! is a testnet daemon", which makes a mainnet wallet inside a testnet daemon unrepresentable
//! rather than merely rejected.

use crate::network::ZNetwork;

/// The coin a wallet serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Coin {
    /// Zcash, served by the librustzcash-backed engine (`crate::wallet`/`crate::sync`/
    /// `crate::chain`). The variant exists only in a build carrying the `zcash` feature, so a
    /// bitcoin-only build's `SUPPORTED` set - and every error message derived from it - names
    /// bitcoin alone.
    #[cfg(feature = "zcash")]
    Zcash,
    /// Bitcoin, served by the BDK-backed engine (`crate::btc`). The variant exists only in a
    /// build carrying the `bitcoin` feature, so a default build's `SUPPORTED` set - and every
    /// error message derived from it - names zcash alone.
    #[cfg(feature = "bitcoin")]
    Bitcoin,
}

impl Coin {
    /// Every coin zecd serves, in the order error messages list them.
    pub const SUPPORTED: &'static [Coin] = &[
        #[cfg(feature = "zcash")]
        Coin::Zcash,
        #[cfg(feature = "bitcoin")]
        Coin::Bitcoin,
    ];

    /// The coin a wallet serves when its entry names none - the build's first engine, which is
    /// Zcash wherever that engine is compiled in and Bitcoin in a bitcoin-only build.
    ///
    /// Derived from [`Coin::SUPPORTED`] rather than written down, so the implicit `default`
    /// wallet (and every internal fallback that used to spell `Coin::Zcash`) resolves to an
    /// engine this build actually has. `lib.rs` refuses a build with no engine at all, so the
    /// index is always in bounds.
    pub const DEFAULT: Coin = Coin::SUPPORTED[0];

    /// The lower-case token form: `"zcash"`.
    pub fn name(self) -> &'static str {
        match self {
            #[cfg(feature = "zcash")]
            Coin::Zcash => "zcash",
            #[cfg(feature = "bitcoin")]
            Coin::Bitcoin => "bitcoin",
        }
    }

    /// The display name used in wire-visible messages, e.g. `"Invalid Zcash address"`.
    pub fn display_name(self) -> &'static str {
        match self {
            #[cfg(feature = "zcash")]
            Coin::Zcash => "Zcash",
            #[cfg(feature = "bitcoin")]
            Coin::Bitcoin => "Bitcoin",
        }
    }

    /// The subdirectory of a **wallet** directory holding this coin's state: `zec` for Zcash,
    /// so a wallet's Zcash data lives under `<datadir>/<wallet>/zec/`
    /// ([`crate::config::coin_dir`]).
    ///
    /// It sits inside the wallet rather than above it because `keys.toml` - the one file in a
    /// wallet directory that is zecd's own - is derived from a BIP-39 seed that serves every
    /// coin at once. One wallet, one seed, one directory per coin underneath it.
    ///
    /// The token is short and coin-specific rather than [`Coin::name`], because it is a path
    /// component operators type and complete - and it is **frozen** once a release ships it:
    /// changing a coin's directory name is a data migration ([`crate::migrate`]), not a rename.
    pub fn data_dir(self) -> &'static str {
        match self {
            #[cfg(feature = "zcash")]
            Coin::Zcash => "zec",
            #[cfg(feature = "bitcoin")]
            Coin::Bitcoin => "btc",
        }
    }

    /// The subdirectory of [`Coin::data_dir`] holding the wallet-storage **engine**'s own files:
    /// `lrz` (librustzcash) for Zcash, so a Zcash wallet's databases live under
    /// `<datadir>/<wallet>/zec/lrz/` ([`crate::config::engine_dir`]).
    ///
    /// A coin is an engine here, so today this is one directory per coin either way. It is a
    /// level of its own so that everything a *particular* library owns is separable from the
    /// coin's own state: replacing librustzcash - or running a migration between two of its
    /// incompatible schema generations - is then a sibling directory and a rescan, not an
    /// archaeology exercise over a shared one. Nothing zecd owns goes in here; `keys.toml`,
    /// which the seed and the chain cannot rebuild, stays at the wallet root where no engine
    /// swap can reach it.
    ///
    /// Frozen once shipped, exactly like [`Coin::data_dir`].
    pub fn engine_dir(self) -> &'static str {
        match self {
            #[cfg(feature = "zcash")]
            Coin::Zcash => "lrz",
            #[cfg(feature = "bitcoin")]
            Coin::Bitcoin => "bdk",
        }
    }

    /// Parse a token produced by [`Coin::name`]. `None` for anything zecd does not serve.
    pub fn parse(s: &str) -> Option<Coin> {
        Coin::SUPPORTED.iter().copied().find(|c| c.name() == s)
    }

    /// The supported coin tokens, comma-separated, for error messages.
    pub fn supported_names() -> String {
        Coin::SUPPORTED
            .iter()
            .map(|c| c.name())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// This coin's chain within the daemon's network environment, with the default Bitcoin
    /// testnet ([`BitcoinTestnet::Testnet3`]) when the environment is the test one. Config
    /// resolution uses [`Coin::chain_with`] so the `btc_testnet` key can pick the other
    /// public Bitcoin test network; everything else (tests, the implicit Zcash default
    /// wallet) takes the default through here.
    pub fn chain(self, env: ZNetwork) -> CoinNetwork {
        #[cfg(feature = "bitcoin")]
        {
            self.chain_with(env, BitcoinTestnet::default())
        }
        #[cfg(not(feature = "bitcoin"))]
        {
            match self {
                Coin::Zcash => CoinNetwork::Zcash(env),
            }
        }
    }

    /// [`Coin::chain`] with an explicit Bitcoin testnet selection: which of the two public
    /// Bitcoin test networks a testnet daemon's Bitcoin wallets ride (the `btc_testnet`
    /// config key). A Zcash wallet's chain ignores it - the Zcash environment has one public
    /// testnet - and outside the test environment it is inert by construction
    /// ([`BitcoinNetwork::from_environment`] only consults it for [`ZNetwork::Test`]).
    #[cfg(feature = "bitcoin")]
    pub fn chain_with(self, env: ZNetwork, btc_testnet: BitcoinTestnet) -> CoinNetwork {
        match self {
            #[cfg(feature = "zcash")]
            Coin::Zcash => CoinNetwork::Zcash(env),
            Coin::Bitcoin => {
                CoinNetwork::Bitcoin(BitcoinNetwork::from_environment(env, btc_testnet))
            }
        }
    }
}

/// A wallet's concrete chain: its coin plus the network environment the daemon runs in.
///
/// Derived, never configured. `--testnet`/`--regtest` say "this daemon is a testnet daemon";
/// each wallet's chain follows from (its coin, that environment) via [`Coin::chain`], which
/// is what makes a mainnet wallet inside a testnet daemon unrepresentable rather than merely
/// rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoinNetwork {
    /// A Zcash chain (mainnet, testnet, or a local regtest chain).
    #[cfg(feature = "zcash")]
    Zcash(ZNetwork),
    /// A Bitcoin chain (mainnet, one of the two public testnets, or a local regtest chain).
    #[cfg(feature = "bitcoin")]
    Bitcoin(BitcoinNetwork),
}

impl CoinNetwork {
    /// The coin this chain belongs to.
    pub fn coin(self) -> Coin {
        match self {
            #[cfg(feature = "zcash")]
            CoinNetwork::Zcash(_) => Coin::Zcash,
            #[cfg(feature = "bitcoin")]
            CoinNetwork::Bitcoin(_) => Coin::Bitcoin,
        }
    }
}

/// The Bitcoin chain a wallet serves, derived from the daemon's network environment like
/// every [`CoinNetwork`].
///
/// A zecd-owned enum, not `bdk_wallet::bitcoin::Network`: [`CoinNetwork`] is a shared-layer
/// type, and the engine-boundary rule keeps engine types out of cross-coin enums. The BDK
/// engine maps this onto its own network type at its edge (`crate::btc`), the same way
/// [`ZNetwork`] stays the Zcash engine's internal `Parameters` value.
#[cfg(feature = "bitcoin")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinNetwork {
    /// Production Bitcoin.
    Main,
    /// The original public test network (Bitcoin Core's `-testnet`).
    Testnet3,
    /// The BIP-94 public test network (Bitcoin Core's `-testnet4`). Same key derivation and
    /// address encoding as testnet3 (coin type `1'`, `tb1` HRP) - a different chain
    /// (genesis, network magic), which the wallet database records at creation.
    Testnet4,
    /// A local regtest chain.
    Regtest,
}

#[cfg(feature = "bitcoin")]
impl BitcoinNetwork {
    /// The Bitcoin chain within the daemon's network environment: a testnet daemon's Bitcoin
    /// wallets are testnet wallets, exactly as its Zcash wallets are - with `btc_testnet`
    /// picking *which* public Bitcoin testnet, since Bitcoin has two live ones where Zcash
    /// has one.
    pub fn from_environment(env: ZNetwork, testnet: BitcoinTestnet) -> BitcoinNetwork {
        match env {
            ZNetwork::Main => BitcoinNetwork::Main,
            ZNetwork::Test => match testnet {
                BitcoinTestnet::Testnet3 => BitcoinNetwork::Testnet3,
                BitcoinTestnet::Testnet4 => BitcoinNetwork::Testnet4,
            },
            ZNetwork::Regtest => BitcoinNetwork::Regtest,
        }
    }

    /// The short network name: `"main"` and `"regtest"` match [`ZNetwork::name`]'s
    /// vocabulary; the test environment names its concrete chain (`"testnet3"` /
    /// `"testnet4"`), since the environment word `"test"` no longer identifies one.
    pub fn name(self) -> &'static str {
        match self {
            BitcoinNetwork::Main => "main",
            BitcoinNetwork::Testnet3 => "testnet3",
            BitcoinNetwork::Testnet4 => "testnet4",
            BitcoinNetwork::Regtest => "regtest",
        }
    }
}

/// Which public Bitcoin test network a testnet daemon's Bitcoin wallets use - the value of
/// the top-level `btc_testnet` config key.
///
/// A daemon-global refinement of the network *environment*, not a per-wallet chain choice:
/// `--testnet` still says "this daemon is a testnet daemon", and this key says what that
/// means for Bitcoin, where two public test networks are live. The default is testnet3,
/// matching Bitcoin Core's own `-testnet` and preserving the engine's previous behaviour.
#[cfg(feature = "bitcoin")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BitcoinTestnet {
    /// The original public test network (`"testnet3"`).
    #[default]
    Testnet3,
    /// The BIP-94 public test network (`"testnet4"`).
    Testnet4,
}

#[cfg(feature = "bitcoin")]
impl BitcoinTestnet {
    /// Parse the config token. `None` for anything else; the caller owns the error message
    /// (which should name [`BitcoinTestnet::supported_names`]).
    pub fn parse(s: &str) -> Option<BitcoinTestnet> {
        match s.trim() {
            "testnet3" => Some(BitcoinTestnet::Testnet3),
            "testnet4" => Some(BitcoinTestnet::Testnet4),
            _ => None,
        }
    }

    /// The token form, round-tripping through [`BitcoinTestnet::parse`].
    pub fn name(self) -> &'static str {
        match self {
            BitcoinTestnet::Testnet3 => "testnet3",
            BitcoinTestnet::Testnet4 => "testnet4",
        }
    }

    /// The accepted tokens, for error messages.
    pub fn supported_names() -> &'static str {
        "testnet3, testnet4"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `SUPPORTED` is the one source the `coin` key's parse, its "this build supports: ..."
    /// refusal and the implicit wallet's [`Coin::DEFAULT`] all derive from, so pin it to the
    /// engines this build actually carries - in both directions, so neither a missing engine
    /// nor a phantom one can go unnoticed.
    #[test]
    fn supported_lists_exactly_the_compiled_engines() {
        assert_eq!(Coin::parse("zcash").is_some(), cfg!(feature = "zcash"));
        assert_eq!(Coin::parse("bitcoin").is_some(), cfg!(feature = "bitcoin"));
        assert_eq!(Coin::parse("zzz"), None);
        assert_eq!(Coin::parse("ZCASH"), None, "tokens are case-sensitive");

        let expected: Vec<&str> = [
            cfg!(feature = "zcash").then_some("zcash"),
            cfg!(feature = "bitcoin").then_some("bitcoin"),
        ]
        .into_iter()
        .flatten()
        .collect();
        assert!(!expected.is_empty(), "a build carries at least one engine");
        assert_eq!(Coin::supported_names(), expected.join(", "));
        assert_eq!(Coin::SUPPORTED.len(), expected.len());
        assert_eq!(Coin::DEFAULT, Coin::SUPPORTED[0]);
        // The round trip, over the whole table rather than the literals above: it is the loop
        // where a second coin's parse/name mismatch would show up.
        for coin in Coin::SUPPORTED {
            assert_eq!(Coin::parse(coin.name()), Some(*coin));
        }
    }

    #[cfg(feature = "bitcoin")]
    #[test]
    fn bitcoin_chain_derivation_follows_the_environment() {
        assert_eq!(Coin::parse("bitcoin"), Some(Coin::Bitcoin));
        for (env, expected) in [
            (ZNetwork::Main, BitcoinNetwork::Main),
            (ZNetwork::Test, BitcoinNetwork::Testnet3),
            (crate::network::regtest(), BitcoinNetwork::Regtest),
        ] {
            let chain = Coin::Bitcoin.chain(env);
            assert_eq!(chain, CoinNetwork::Bitcoin(expected));
            assert_eq!(chain.coin(), Coin::Bitcoin);
        }
        // `btc_testnet` refines only the test environment: testnet4 selects the other public
        // testnet there, and is inert (by construction) on main and regtest.
        for testnet in [BitcoinTestnet::Testnet3, BitcoinTestnet::Testnet4] {
            let expected = match testnet {
                BitcoinTestnet::Testnet3 => BitcoinNetwork::Testnet3,
                BitcoinTestnet::Testnet4 => BitcoinNetwork::Testnet4,
            };
            assert_eq!(
                Coin::Bitcoin.chain_with(ZNetwork::Test, testnet),
                CoinNetwork::Bitcoin(expected)
            );
            assert_eq!(
                Coin::Bitcoin.chain_with(ZNetwork::Main, testnet),
                CoinNetwork::Bitcoin(BitcoinNetwork::Main)
            );
            assert_eq!(
                Coin::Bitcoin.chain_with(crate::network::regtest(), testnet),
                CoinNetwork::Bitcoin(BitcoinNetwork::Regtest)
            );
            // A Zcash chain never consults the Bitcoin testnet selection.
            #[cfg(feature = "zcash")]
            assert_eq!(
                Coin::Zcash.chain_with(ZNetwork::Test, testnet),
                CoinNetwork::Zcash(ZNetwork::Test)
            );
        }
        // main/regtest keep ZNetwork::name's vocabulary; the test environment names its
        // concrete chain, since "test" no longer identifies one.
        assert_eq!(BitcoinNetwork::Main.name(), "main");
        assert_eq!(BitcoinNetwork::Testnet3.name(), "testnet3");
        assert_eq!(BitcoinNetwork::Testnet4.name(), "testnet4");
        assert_eq!(BitcoinNetwork::Regtest.name(), "regtest");
    }

    /// The `btc_testnet` token grammar: the two public testnets round-trip, the default is
    /// testnet3 (Bitcoin Core's own `-testnet`, and the engine's previous behaviour), and
    /// anything else - the environment word "test" included - is a parse failure for the
    /// config layer to report.
    #[cfg(feature = "bitcoin")]
    #[test]
    fn btc_testnet_tokens_round_trip_and_default_to_testnet3() {
        assert_eq!(BitcoinTestnet::default(), BitcoinTestnet::Testnet3);
        for testnet in [BitcoinTestnet::Testnet3, BitcoinTestnet::Testnet4] {
            assert_eq!(BitcoinTestnet::parse(testnet.name()), Some(testnet));
        }
        for bad in ["test", "testnet", "signet", "TESTNET4", ""] {
            assert_eq!(BitcoinTestnet::parse(bad), None, "{bad:?} must not parse");
        }
    }

    #[cfg(feature = "zcash")]
    #[test]
    fn zcash_chain_derivation_is_identity_for_all_environments() {
        for env in [ZNetwork::Main, ZNetwork::Test, crate::network::regtest()] {
            let chain = Coin::Zcash.chain(env);
            assert_eq!(chain, CoinNetwork::Zcash(env));
            assert_eq!(chain.coin(), Coin::Zcash);
        }
    }

    /// These names are path components every deployment of a release has on disk, so they are
    /// frozen: a change is a migration, not a rename. Pinning them here makes that explicit
    /// rather than leaving it to whoever edits the match arms.
    #[test]
    fn directory_names_are_frozen_and_distinct() {
        #[cfg(feature = "zcash")]
        {
            assert_eq!(Coin::Zcash.data_dir(), "zec");
            assert_eq!(Coin::Zcash.engine_dir(), "lrz");
        }
        #[cfg(feature = "bitcoin")]
        {
            assert_eq!(Coin::Bitcoin.data_dir(), "btc");
            assert_eq!(Coin::Bitcoin.engine_dir(), "bdk");
        }
        let mut seen = std::collections::BTreeSet::new();
        for coin in Coin::SUPPORTED {
            for dir in [coin.data_dir(), coin.engine_dir()] {
                assert!(
                    !dir.is_empty() && !dir.contains('/') && !dir.starts_with('.'),
                    "{dir:?} must be a plain path component"
                );
            }
            assert!(
                seen.insert(coin.data_dir()),
                "two coins share the data directory {:?}",
                coin.data_dir()
            );
        }
    }
}
