//! JSON-RPC method dispatch.

pub mod blockchain;
#[cfg(feature = "bitcoin")]
pub mod btc_methods;
pub mod control;
pub mod network;
pub mod rawtx;
pub mod signmessage;
pub mod util;
pub mod wallet_methods;

use serde_json::Value;

use crate::coin::Coin;
use crate::error::RpcError;
use crate::server::jsonrpc::RpcRequest;
use crate::state::AppState;

/// Every RPC method name zecd implements, used to validate the `[rpc] allowed_methods`
/// safelist at startup. Keep this in lockstep with the `dispatch` table; the
/// `all_methods_matches_dispatch_tables` test enforces it.
pub const ALL_METHODS: &[&str] = &[
    // Control
    "stop",
    "uptime",
    "help",
    "getrpcinfo",
    // Network
    "getnetworkinfo",
    "getconnectioncount",
    "getpeerinfo",
    "ping",
    // Blockchain
    "getblockchaininfo",
    "getblockcount",
    "getbestblockhash",
    "getblockhash",
    "getblockheader",
    "waitfornewblock",
    "waitforblock",
    "waitforblockheight",
    "waitforsync",
    // Utility
    "validateaddress",
    "signmessage",
    "verifymessage",
    "settxfee",
    "estimatesmartfee",
    "estimatefee",
    "getmempoolinfo",
    // Raw transactions
    "getrawtransaction",
    "sendrawtransaction",
    // Wallet - reads
    "getbalance",
    "getbalances",
    "getunconfirmedbalance",
    "getwalletinfo",
    "getaddressinfo",
    "listtransactions",
    "z_listtransactions",
    "listsinceblock",
    "gettransaction",
    "listunspent",
    "getreceivedbyaddress",
    "listreceivedbyaddress",
    "listdescriptors",
    "listwallets",
    "listwalletdir",
    // Wallet - management (fleet onboarding)
    "createwallet",
    "loadwallet",
    "unloadwallet",
    // Wallet - writes / async
    "getnewaddress",
    "sendtoaddress",
    "sendmany",
    "walletpassphrase",
    "walletlock",
    // Wallet - async operations (zcashd-style)
    "z_sendmany",
    "z_shieldcoinbase",
    "z_mergetoaddress",
    "z_getoperationstatus",
    "z_getoperationresult",
    "z_listoperationids",
    "z_waitforoperation",
    // Wallet - address derivation (zcashd-style)
    "z_getaddressforaccount",
];

/// Whether `name` is an RPC method zecd implements (see [`ALL_METHODS`]).
pub fn is_known_method(name: &str) -> bool {
    ALL_METHODS.contains(&name)
}

/// The maximum number of *positional* parameters each method accepts. Bitcoin Core rejects a
/// call carrying more positional arguments than the method declares (it raises the help text,
/// `RPC_MISC_ERROR`/-1); zecd mirrors that via [`check_arity`] in dispatch, closing the gap where
/// handlers silently ignored trailing junk. Counts follow Bitcoin Core's / zcashd's argument
/// lists, plus zecd's own trailing extension args where they exist (e.g. `sendtoaddress`'s
/// `memo` at index 11 → arity 12). Object params are unaffected: an object request body yields
/// zero positional params, so an object-shaped call never trips the bound.
///
/// Kept in lockstep with [`ALL_METHODS`] by the `arity_table_matches_all_methods` test.
const MAX_POSITIONAL_ARGS: &[(&str, usize)] = &[
    // Control
    ("stop", 0),
    ("uptime", 0),
    ("help", 1),
    ("getrpcinfo", 0),
    // Network
    ("getnetworkinfo", 0),
    ("getconnectioncount", 0),
    ("getpeerinfo", 0),
    ("ping", 0),
    // Blockchain
    ("getblockchaininfo", 0),
    ("getblockcount", 0),
    ("getbestblockhash", 0),
    ("getblockhash", 1),
    ("getblockheader", 2),
    ("waitfornewblock", 1),
    ("waitforblock", 2),
    ("waitforblockheight", 2),
    ("waitforsync", 1),
    // Utility
    ("validateaddress", 1),
    ("settxfee", 1),
    ("estimatesmartfee", 2),
    ("estimatefee", 1),
    ("getmempoolinfo", 0),
    // Raw transactions
    ("getrawtransaction", 3),
    ("sendrawtransaction", 2),
    // Wallet - reads
    ("getbalance", 4),
    ("getbalances", 0),
    ("getunconfirmedbalance", 0),
    ("getwalletinfo", 0),
    ("getaddressinfo", 1),
    ("listtransactions", 4),
    ("z_listtransactions", 5),
    ("listsinceblock", 4),
    ("gettransaction", 3),
    ("listunspent", 5),
    ("getreceivedbyaddress", 3),
    ("listreceivedbyaddress", 5),
    ("listdescriptors", 1),
    ("listwallets", 0),
    ("listwalletdir", 0),
    // Wallet - management (fleet onboarding). `createwallet` keeps Bitcoin Core's eight
    // positional parameters so a Core-shaped client's call is accepted (and its
    // spending-wallet flags explicitly refused); zecd's own arguments ride in the options
    // object at param 8.
    ("createwallet", 9),
    ("loadwallet", 2),
    ("unloadwallet", 2),
    // Wallet - writes / async
    ("getnewaddress", 2),
    ("sendtoaddress", 12),
    ("sendmany", 10),
    ("walletpassphrase", 2),
    ("walletlock", 0),
    ("signmessage", 2),
    ("verifymessage", 3),
    // Wallet - async operations (zcashd-style)
    ("z_sendmany", 5),
    ("z_shieldcoinbase", 6),
    ("z_mergetoaddress", 7),
    ("z_getoperationstatus", 1),
    ("z_getoperationresult", 1),
    ("z_listoperationids", 1),
    ("z_waitforoperation", 2),
    // Wallet - address derivation (zcashd-style)
    ("z_getaddressforaccount", 3),
];

/// Which coins a method serves.
///
/// A method a wallet cannot serve is indistinguishable from one that does not exist, so the
/// gate answers `-32601` - the precedent the removed label methods set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MethodCoins {
    /// Served by every wallet: the shared shell, the chain reads, and the Bitcoin-dialect
    /// wallet surface.
    All,
    /// Served only by the listed coins.
    Only(&'static [Coin]),
}

/// The coins that serve each dispatched method.
///
/// Four tiers. `All` marks the wallet-independent shell (control methods and the registry
/// list), which no engine is involved in serving. The nine `z_*` methods are Zcash-only by
/// nature (shielded sends, the shielding/merge sweeps, the async-operation trio, zcashd's
/// account address derivation). `BITCOIN_ONLY` holds the Core methods that only make sense
/// for a descriptor wallet (`listdescriptors`). Everything else is the shared Bitcoin-Core
/// dialect *in shape*, but each method is listed for a coin only once that coin's engine
/// actually serves it - a method the engine cannot serve yet must read as method-not-found,
/// not reach a Zcash-typed handler. The BDK engine's surface grows by moving entries from
/// `ZCASH_ONLY` to `ZCASH_AND_BITCOIN` alongside the handler branch that serves them.
///
/// Kept in lockstep with [`ALL_METHODS`] by the `method_coins_table_matches_all_methods` test.
const ZCASH_ONLY: &[Coin] = &[Coin::Zcash];
/// The methods the BDK engine serves so far (in a build without the `bitcoin` feature this
/// set is identical to [`ZCASH_ONLY`], so the table needs no cfg of its own).
const ZCASH_AND_BITCOIN: &[Coin] = &[
    Coin::Zcash,
    #[cfg(feature = "bitcoin")]
    Coin::Bitcoin,
];
/// Methods only the BDK engine serves (a descriptor wallet has descriptors; a Zcash account
/// has viewing keys, exported offline by `export-ufvk`). Empty in a build without the
/// feature, so the gate answers `-32601` everywhere, exactly as for an unknown method.
const BITCOIN_ONLY: &[Coin] = &[
    #[cfg(feature = "bitcoin")]
    Coin::Bitcoin,
];
const METHOD_COINS: &[(&str, MethodCoins)] = &[
    // Control
    ("stop", MethodCoins::All),
    ("uptime", MethodCoins::All),
    ("help", MethodCoins::All),
    ("getrpcinfo", MethodCoins::All),
    // Network
    ("getnetworkinfo", MethodCoins::Only(ZCASH_ONLY)),
    ("getconnectioncount", MethodCoins::Only(ZCASH_ONLY)),
    ("getpeerinfo", MethodCoins::Only(ZCASH_ONLY)),
    ("ping", MethodCoins::All),
    // Blockchain
    ("getblockchaininfo", MethodCoins::Only(ZCASH_ONLY)),
    ("getblockcount", MethodCoins::Only(ZCASH_AND_BITCOIN)),
    ("getbestblockhash", MethodCoins::Only(ZCASH_AND_BITCOIN)),
    ("getblockhash", MethodCoins::Only(ZCASH_ONLY)),
    ("getblockheader", MethodCoins::Only(ZCASH_ONLY)),
    ("waitfornewblock", MethodCoins::Only(ZCASH_ONLY)),
    ("waitforblock", MethodCoins::Only(ZCASH_ONLY)),
    ("waitforblockheight", MethodCoins::Only(ZCASH_ONLY)),
    ("waitforsync", MethodCoins::Only(ZCASH_ONLY)),
    // Utility
    ("validateaddress", MethodCoins::Only(ZCASH_AND_BITCOIN)),
    ("estimatesmartfee", MethodCoins::Only(ZCASH_ONLY)),
    ("estimatefee", MethodCoins::Only(ZCASH_ONLY)),
    ("getmempoolinfo", MethodCoins::Only(ZCASH_ONLY)),
    ("signmessage", MethodCoins::Only(ZCASH_ONLY)),
    ("verifymessage", MethodCoins::Only(ZCASH_ONLY)),
    ("settxfee", MethodCoins::Only(ZCASH_ONLY)),
    // Raw transactions
    ("sendrawtransaction", MethodCoins::Only(ZCASH_AND_BITCOIN)),
    ("getrawtransaction", MethodCoins::Only(ZCASH_ONLY)),
    // Wallet - reads
    ("getbalance", MethodCoins::Only(ZCASH_AND_BITCOIN)),
    ("getbalances", MethodCoins::Only(ZCASH_AND_BITCOIN)),
    (
        "getunconfirmedbalance",
        MethodCoins::Only(ZCASH_AND_BITCOIN),
    ),
    ("getwalletinfo", MethodCoins::Only(ZCASH_AND_BITCOIN)),
    ("listwallets", MethodCoins::All),
    ("listwalletdir", MethodCoins::All),
    ("listtransactions", MethodCoins::Only(ZCASH_AND_BITCOIN)),
    ("listsinceblock", MethodCoins::Only(ZCASH_ONLY)),
    ("gettransaction", MethodCoins::Only(ZCASH_AND_BITCOIN)),
    ("listunspent", MethodCoins::Only(ZCASH_AND_BITCOIN)),
    ("getreceivedbyaddress", MethodCoins::Only(ZCASH_ONLY)),
    (
        "listreceivedbyaddress",
        MethodCoins::Only(ZCASH_AND_BITCOIN),
    ),
    ("listdescriptors", MethodCoins::Only(BITCOIN_ONLY)),
    ("getaddressinfo", MethodCoins::Only(ZCASH_AND_BITCOIN)),
    ("z_listtransactions", MethodCoins::Only(ZCASH_ONLY)),
    // Wallet - management (fleet onboarding). Bitcoin-dialect method names, so `All`: what is
    // engine-specific is the format of `createwallet`'s `ufvk` option, not the method itself.
    ("createwallet", MethodCoins::All),
    ("loadwallet", MethodCoins::All),
    ("unloadwallet", MethodCoins::All),
    // Wallet - writes
    ("getnewaddress", MethodCoins::Only(ZCASH_AND_BITCOIN)),
    ("sendtoaddress", MethodCoins::Only(ZCASH_AND_BITCOIN)),
    ("sendmany", MethodCoins::Only(ZCASH_AND_BITCOIN)),
    ("walletpassphrase", MethodCoins::Only(ZCASH_ONLY)),
    ("walletlock", MethodCoins::Only(ZCASH_ONLY)),
    // Wallet - async operations
    ("z_sendmany", MethodCoins::Only(ZCASH_ONLY)),
    ("z_shieldcoinbase", MethodCoins::Only(ZCASH_ONLY)),
    ("z_mergetoaddress", MethodCoins::Only(ZCASH_ONLY)),
    ("z_getoperationstatus", MethodCoins::Only(ZCASH_ONLY)),
    ("z_getoperationresult", MethodCoins::Only(ZCASH_ONLY)),
    ("z_listoperationids", MethodCoins::Only(ZCASH_ONLY)),
    ("z_waitforoperation", MethodCoins::Only(ZCASH_ONLY)),
    // Wallet - address derivation (zcashd-style)
    ("z_getaddressforaccount", MethodCoins::Only(ZCASH_ONLY)),
];

/// The methods `METHOD_COINS` lists as served for Bitcoin wallets - the gate's half of the
/// lockstep contract with `btc_methods::BITCOIN_METHODS` (see the test there).
#[cfg(all(test, feature = "bitcoin"))]
pub(crate) fn methods_served_for_bitcoin() -> std::collections::BTreeSet<&'static str> {
    METHOD_COINS
        .iter()
        .filter(
            |(_, coins)| matches!(coins, MethodCoins::Only(set) if set.contains(&Coin::Bitcoin)),
        )
        .map(|(m, _)| *m)
        .collect()
}

/// The coins serving `method`, or `None` when the method is unknown.
fn method_coins(method: &str) -> Option<MethodCoins> {
    METHOD_COINS
        .iter()
        .find(|(m, _)| *m == method)
        .map(|(_, c)| *c)
}

/// The positional-argument cap for `method`, or `None` when the method is unknown (the
/// method-not-found path handles those).
fn max_positional_args(method: &str) -> Option<usize> {
    MAX_POSITIONAL_ARGS
        .iter()
        .find(|(m, _)| *m == method)
        .map(|(_, n)| *n)
}

/// Enforce Bitcoin Core's arity rule: a positional call may not carry more arguments than the
/// method declares. Excess positional params are rejected with `RPC_MISC_ERROR` (-1), matching
/// Core (which raises the method help text). Unknown methods are left to the dispatch table's
/// method-not-found handling.
fn check_arity(req: &RpcRequest) -> Result<(), RpcError> {
    if let Some(max) = max_positional_args(&req.method) {
        if req.params.len() > max {
            return Err(RpcError::misc(format!(
                "{} takes at most {} argument(s) ({} provided)",
                req.method,
                max,
                req.params.len()
            )));
        }
    }
    Ok(())
}

/// Route a parsed request to zecd's method table. `wallet` is the wallet name from a
/// `/wallet/<name>` path (or `None` for the default wallet).
pub(crate) async fn dispatch(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    // RPC method safelist: when `[rpc] allowed_methods` is non-empty, ONLY those methods are
    // served. A blocked method is rejected exactly like one that does not exist (-32601 →
    // HTTP 404), so a locked-down server discloses nothing about the surface it has disabled.
    // An empty safelist (the default) imposes no restriction.
    let safelist = &state.config.rpc.allowed_methods;
    if !safelist.is_empty() && !safelist.iter().any(|m| m == &req.method) {
        return Err(RpcError::method_not_found(&req.method));
    }
    // Reject over-arity positional calls before dispatch (Bitcoin Core's help error, -1). Runs
    // after the safelist so a disabled method still reads as method-not-found, not a bad-arity
    // hint about a surface the operator hid.
    check_arity(req)?;
    // Coin gate: a method its wallet's engine cannot serve reads as method-not-found, exactly
    // like a safelisted-out one. Deliberately non-erroring on an unresolvable wallet: dispatch
    // only knows the wallet *name* (handlers resolve the handle themselves), so failing here
    // would reorder every coin-restricted handler's own errors - an unknown wallet must keep
    // answering -18, and a bad parameter must keep answering its own code.
    if let Some(MethodCoins::Only(coins)) = method_coins(&req.method) {
        if let Ok(wallet) = state.registry.get_coin(wallet) {
            if !coins.contains(&wallet.coin()) {
                return Err(RpcError::method_not_found(&req.method));
            }
        }
    }
    dispatch_zecd(state, wallet, req).await
}

/// zecd's method table.
async fn dispatch_zecd(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    // A Bitcoin wallet's methods are served by the engine's own sub-table; `None` means a
    // wallet-independent method (the shared arms below serve it), since the coin gate above
    // has already 404'd everything the engine does not serve.
    #[cfg(feature = "bitcoin")]
    if let Ok(crate::wallet::CoinWallet::Bitcoin(handle)) = state.registry.get_coin(wallet) {
        if let Some(result) = btc_methods::dispatch(&handle, req).await {
            return result;
        }
    }
    match req.method.as_str() {
        // Control
        "stop" => control::stop(state),
        "uptime" => control::uptime(state),
        "help" => control::help(),
        "getrpcinfo" => control::getrpcinfo(state),

        // Network
        "getnetworkinfo" => network::getnetworkinfo(state),
        "getconnectioncount" => network::getconnectioncount(state),
        "getpeerinfo" => network::getpeerinfo(state),
        "ping" => network::ping(),

        // Blockchain
        "getblockchaininfo" => blockchain::getblockchaininfo(state, wallet),
        "getblockcount" => blockchain::getblockcount(state, wallet),
        "getbestblockhash" => blockchain::getbestblockhash(state, wallet),
        "getblockhash" => blockchain::getblockhash(state, wallet, req),
        "getblockheader" => blockchain::getblockheader(state, wallet, req),
        "waitfornewblock" => blockchain::waitfornewblock(state, wallet, req).await,
        "waitforblock" => blockchain::waitforblock(state, wallet, req).await,
        "waitforblockheight" => blockchain::waitforblockheight(state, wallet, req).await,
        "waitforsync" => blockchain::waitforsync(state, wallet, req).await,

        // Utility
        "validateaddress" => util::validateaddress(state, wallet, req),
        "signmessage" => signmessage::signmessage(state, wallet, req).await,
        "verifymessage" => signmessage::verifymessage(state, wallet, req),
        "settxfee" => util::settxfee(req),
        "estimatesmartfee" => util::estimatesmartfee(req),
        "estimatefee" => util::estimatefee(req),
        "getmempoolinfo" => util::getmempoolinfo(),

        // Raw transactions (served via the wallet's lightwalletd connection)
        "getrawtransaction" => rawtx::getrawtransaction(state, wallet, req).await,
        "sendrawtransaction" => rawtx::sendrawtransaction(state, wallet, req).await,

        // Wallet - reads
        "getbalance" => wallet_methods::getbalance(state, wallet, req),
        "getbalances" => wallet_methods::getbalances(state, wallet),
        "getunconfirmedbalance" => wallet_methods::getunconfirmedbalance(state, wallet),
        "getwalletinfo" => wallet_methods::getwalletinfo(state, wallet),
        "getaddressinfo" => wallet_methods::getaddressinfo(state, wallet, req),
        "listtransactions" => wallet_methods::listtransactions(state, wallet, req),
        "z_listtransactions" => wallet_methods::z_listtransactions(state, wallet, req),
        "listsinceblock" => wallet_methods::listsinceblock(state, wallet, req),
        "gettransaction" => wallet_methods::gettransaction(state, wallet, req).await,
        "listunspent" => wallet_methods::listunspent(state, wallet, req),
        "getreceivedbyaddress" => wallet_methods::getreceivedbyaddress(state, wallet, req),
        "listreceivedbyaddress" => wallet_methods::listreceivedbyaddress(state, wallet, req),
        "listwallets" => wallet_methods::listwallets(state),
        "listwalletdir" => wallet_methods::listwalletdir(state),

        // Wallet - management (fleet onboarding)
        "createwallet" => wallet_methods::createwallet(state, &req.params).await,
        "loadwallet" => wallet_methods::loadwallet(state, &req.params).await,
        "unloadwallet" => wallet_methods::unloadwallet(state, &req.params, wallet),

        // Wallet - writes / async
        "getnewaddress" => wallet_methods::getnewaddress(state, wallet, req).await,
        "sendtoaddress" => wallet_methods::sendtoaddress(state, wallet, req).await,
        "sendmany" => wallet_methods::sendmany(state, wallet, req).await,
        "walletpassphrase" => wallet_methods::walletpassphrase(state, wallet, req).await,
        "walletlock" => wallet_methods::walletlock(state, wallet).await,

        // Wallet - async operations (zcashd-style; the send itself runs on a background task)
        "z_sendmany" => wallet_methods::z_sendmany(state, wallet, req),
        "z_shieldcoinbase" => wallet_methods::z_shieldcoinbase(state, wallet, req).await,
        "z_mergetoaddress" => wallet_methods::z_mergetoaddress(state, wallet, req).await,
        "z_getoperationstatus" => wallet_methods::z_getoperationstatus(state, wallet, req),
        "z_getoperationresult" => wallet_methods::z_getoperationresult(state, wallet, req),
        "z_listoperationids" => wallet_methods::z_listoperationids(state, wallet, req),
        "z_waitforoperation" => wallet_methods::z_waitforoperation(state, wallet, req).await,

        // Wallet - address derivation (zcashd-style; exact-or-next diversified UA)
        "z_getaddressforaccount" => {
            wallet_methods::z_getaddressforaccount(state, wallet, req).await
        }

        // Bitcoin-only, served by `btc_methods` above; for every other wallet the coin gate
        // has already answered -32601, so this arm is never reached. It exists so the
        // dispatch table and `ALL_METHODS` stay in lockstep (the test scans these arms).
        "listdescriptors" => Err(RpcError::method_not_found(&req.method)),

        other => Err(RpcError::method_not_found(other)),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    /// Extract the method names from a dispatch `match` by scanning the non-test source for
    /// `"name" =>` arms - the only place either dispatch module uses that shape. Splitting at
    /// `#[cfg(test)]` keeps this test's own string literals out of the result.
    fn dispatch_arms(src: &str) -> BTreeSet<String> {
        let code = src.split("#[cfg(test)]").next().unwrap_or(src);
        let mut out = BTreeSet::new();
        for line in code.lines() {
            if let Some(rest) = line.trim_start().strip_prefix('"') {
                if let Some(end) = rest.find('"') {
                    if rest[end + 1..].trim_start().starts_with("=>") {
                        out.insert(rest[..end].to_string());
                    }
                }
            }
        }
        out
    }

    /// `ALL_METHODS` must be exactly the set of methods in the dispatch table - no stale
    /// entries (a safelist would reject a real method) and nothing missing (a real method
    /// couldn't be safelisted). This pins the list to the source of truth without probing
    /// dispatch (which has side effects, e.g. `stop`).
    #[test]
    fn all_methods_matches_dispatch_tables() {
        let from_tables = dispatch_arms(include_str!("mod.rs"));
        let declared: BTreeSet<String> = super::ALL_METHODS.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            from_tables, declared,
            "ALL_METHODS is out of sync with the dispatch table"
        );
        // No duplicates in the declared slice (the set would silently absorb them otherwise).
        assert_eq!(
            super::ALL_METHODS.len(),
            declared.len(),
            "ALL_METHODS contains duplicate method names"
        );
    }

    /// The arity table must name exactly the methods in `ALL_METHODS` - no gaps (an unlisted
    /// method would silently keep accepting extra positional junk) and no strays (a typo'd key
    /// never fires). This keeps [`super::check_arity`] total over the dispatch surface.
    #[test]
    fn method_coins_table_matches_all_methods() {
        let declared: BTreeSet<String> = super::ALL_METHODS.iter().map(|s| s.to_string()).collect();
        let coins: BTreeSet<String> = super::METHOD_COINS
            .iter()
            .map(|(m, _)| m.to_string())
            .collect();
        assert_eq!(
            coins, declared,
            "METHOD_COINS is out of sync with ALL_METHODS"
        );
        assert_eq!(
            super::METHOD_COINS.len(),
            coins.len(),
            "METHOD_COINS contains duplicate method names"
        );
    }

    /// The data itself. The `z_*` surface must stay gated to Zcash (a new `z_*` method that
    /// forgets its restriction fails here), `All` is reserved for the wallet-independent
    /// shell, and every wallet-touching method names Zcash among its coins (the dialect is
    /// implemented there first; a Bitcoin-only method does not exist).
    #[test]
    fn method_coin_tiers_hold() {
        use crate::coin::Coin;
        // The registry operations (`listwalletdir`, `createwallet`, `loadwallet`,
        // `unloadwallet`) act on the set of wallets, not on one, so they sit in the shell too.
        const WALLET_INDEPENDENT: &[&str] = &[
            "stop",
            "uptime",
            "help",
            "getrpcinfo",
            "ping",
            "listwallets",
            "listwalletdir",
            "createwallet",
            "loadwallet",
            "unloadwallet",
        ];
        /// Core methods with no Zcash meaning at all: the only entries allowed to leave
        /// Zcash out of their coin set.
        const BITCOIN_ONLY_METHODS: &[&str] = &["listdescriptors"];
        for (method, coins) in super::METHOD_COINS {
            if method.starts_with("z_") {
                assert_eq!(
                    *coins,
                    super::MethodCoins::Only(&[Coin::Zcash]),
                    "{method} is a Zcash extension and must be gated to Zcash"
                );
            }
            match coins {
                super::MethodCoins::All => assert!(
                    WALLET_INDEPENDENT.contains(method),
                    "{method} resolves a wallet, so it must name the coins that serve it"
                ),
                super::MethodCoins::Only(coins) => {
                    assert!(
                        WALLET_INDEPENDENT.iter().all(|m| m != method),
                        "{method} is wallet-independent and should be MethodCoins::All"
                    );
                    if BITCOIN_ONLY_METHODS.contains(method) {
                        assert_eq!(
                            *coins,
                            super::BITCOIN_ONLY,
                            "{method} is a descriptor-wallet method and must be gated to Bitcoin"
                        );
                    } else {
                        assert!(
                            coins.contains(&Coin::Zcash),
                            "{method}: every other wallet-touching method is served for Zcash"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn arity_table_matches_all_methods() {
        let declared: BTreeSet<String> = super::ALL_METHODS.iter().map(|s| s.to_string()).collect();
        let arity: BTreeSet<String> = super::MAX_POSITIONAL_ARGS
            .iter()
            .map(|(m, _)| m.to_string())
            .collect();
        assert_eq!(
            arity, declared,
            "MAX_POSITIONAL_ARGS is out of sync with ALL_METHODS"
        );
        assert_eq!(
            super::MAX_POSITIONAL_ARGS.len(),
            arity.len(),
            "MAX_POSITIONAL_ARGS contains duplicate method names"
        );
    }
}
