#!/usr/bin/env python3
"""Bitcoin-Core RPC conformance check for zecd.

Uses the same client logic as `python-bitcoinrpc`'s AuthServiceProxy (HTTP Basic auth,
JSON-RPC 1.0 envelope, amounts decoded as `decimal.Decimal`, errors raised from the
`{code,message}` object) to prove zecd's wire format is what real Bitcoin RPC clients parse.

It asserts the fields/types BTCPay-style integrations and Bitcoin RPC libraries read, that
amounts round-trip as exact decimals (not floats), batching works, and errors carry the
expected Bitcoin Core codes.

Usage:  python3 scripts/conformance.py [--coin zcash|bitcoin] [--url http://127.0.0.1:18232/]
                                       [--user u] [--password p]
                                       [--passphrase <wallet passphrase>]

`--coin` selects the engine the wallet under test runs on (default `zcash`). The checks are
organised as sections, each tagged with the coins it applies to - a readable copy of
`rpc::METHOD_COINS`: a section tagged with both coins asserts the shared Bitcoin-Core shape
against either engine, a Zcash-only one covers the `z_*` extensions, the chain reads and the
shielded fields, a Bitcoin-only one the descriptor-wallet surface (`listdescriptors`, the
BIP 84 derivation fields). A method served for a new coin gets its checks by adding the tag.
In Bitcoin mode every send check rejects at argument parsing, so the suite moves no funds.

`--passphrase`: the wallet passphrase, when the wallet under test is encrypted (Zcash only -
the Bitcoin engine has no passphrase RPCs). Enables the full encryption state machine
(lock/unlock/passphrase-change round-trips); the wallet is left as it was found (same
passphrase, unlocked).
"""
import argparse
import base64
import decimal
import json
import sys
import time
import urllib.request
import urllib.error


class JSONRPCException(Exception):
    def __init__(self, err):
        super().__init__(err.get("message"))
        self.code = err.get("code")


class AuthServiceProxy:
    """A minimal stand-in for python-bitcoinrpc's AuthServiceProxy (same semantics)."""

    def __init__(self, url, user, password):
        self._url = url
        self._auth = b"Basic " + base64.b64encode(f"{user}:{password}".encode())

    def _post(self, payload):
        body = json.dumps(payload).encode()
        req = urllib.request.Request(self._url, data=body)
        req.add_header("Authorization", self._auth.decode())
        req.add_header("Content-Type", "application/json")
        try:
            resp = urllib.request.urlopen(req, timeout=30)
            raw = resp.read()
        except urllib.error.HTTPError as e:
            # Bitcoin Core returns HTTP 500 with the error object for RPC errors, 401 for auth.
            if e.code == 401:
                raise JSONRPCException({"code": 401, "message": "unauthorized"})
            raw = e.read()
        # The hallmark behaviour real clients rely on: amounts decode as Decimal.
        return json.loads(raw, parse_float=decimal.Decimal)

    def call(self, method, *params):
        r = self._post({"jsonrpc": "1.0", "id": "conf", "method": method, "params": list(params)})
        if r.get("error") is not None:
            raise JSONRPCException(r["error"])
        return r["result"]

    def batch(self, calls):
        payload = [{"jsonrpc": "1.0", "id": i, "method": m, "params": list(p)} for i, (m, p) in enumerate(calls)]
        return self._post(payload)


ZCASH = "zcash"
BITCOIN = "bitcoin"
BOTH = (ZCASH, BITCOIN)

# The amount every Bitcoin-mode send check names: a valid amount (under the 21M cap, so it
# parses) that no test wallet can afford. The checks are meant to be refused while their
# arguments are parsed, and they are; this is the second guard, so a check whose refusal
# ever moves later (or disappears) fails on insufficient funds instead of paying.
UNAFFORDABLE = "20999999"

# The sections, in run order. Each is `(title, coins, fn)`; `main` runs the ones tagged
# with the selected coin, in this order, so the Zcash run is the same sequence of checks
# it always was.
SECTIONS = []


def section(title, *coins):
    def register(fn):
        SECTIONS.append((title, frozenset(coins), fn))
        return fn
    return register


class Ctx:
    """What the sections share: the client, the check recorder, the arguments, and the
    handful of values one section establishes for later ones (the tip, the wallet info,
    the balance, a fresh own address)."""

    def __init__(self, rpc, ck, args):
        self.rpc = rpc
        self.ck = ck
        self.args = args
        self.coin = args.coin


@section("getblockchaininfo fields/types", *BOTH)
def s_getblockchaininfo(ctx):
    rpc, ck = ctx.rpc, ctx.ck
    bci = rpc.call("getblockchaininfo")
    for f in ("chain", "blocks", "headers", "bestblockhash", "verificationprogress",
              "initialblockdownload", "pruned", "difficulty", "warnings"):
        ck(f"has {f}", f in bci, type(bci.get(f)).__name__)
    ck("chain is a Core chain name", bci["chain"] in ("main", "test", "testnet4", "regtest"),
       bci["chain"])
    ck("blocks is int", isinstance(bci["blocks"], int))
    ck("bestblockhash 64-hex", isinstance(bci["bestblockhash"], str) and len(bci["bestblockhash"]) == 64)


@section("blocks/hash consistency", *BOTH)
def s_chain_tip(ctx):
    rpc, ck = ctx.rpc, ctx.ck
    # The classic poller pattern must hold: getblockhash(getblockcount()) succeeds and
    # agrees with getbestblockhash (all three describe the fully-scanned block).
    count = rpc.call("getblockcount")
    ck("getblockcount is int", isinstance(count, int))
    best = rpc.call("getbestblockhash")
    if ctx.coin == ZCASH:
        at_count = rpc.call("getblockhash", count)
        ck("getblockhash(getblockcount()) == getbestblockhash", best == at_count, f"{best} != {at_count}")
    else:
        # The Bitcoin engine serves no getblockhash; the pair describes the wallet's own
        # synced checkpoint, which getwalletinfo.lastprocessedblock repeats (checked there).
        ck("getbestblockhash 64-hex", isinstance(best, str) and len(best) == 64, best)
    ctx.count, ctx.best = count, best


@section("waitfor block RPCs", ZCASH)
def s_waitfor(ctx):
    rpc, ck = ctx.rpc, ctx.ck
    count, best = ctx.count, ctx.best
    # These answer "has the wallet scanned to height N?" - the question a balance poll cannot,
    # since an incoming payment is credited from the mempool before its block is scanned. All
    # three return {hash, height} describing the fully-scanned block, and a timeout returns that
    # block rather than raising (Bitcoin Core's contract).
    w = rpc.call("waitforblockheight", count)
    ck("waitforblockheight returns {hash,height}", isinstance(w, dict) and set(w) == {"hash", "height"}, w)
    ck("waitforblockheight(getblockcount()) returns now", w["height"] >= count, f"{w['height']} < {count}")
    ck("waitforblockheight hash is 64-hex", isinstance(w["hash"], str) and len(w["hash"]) == 64)
    # An unreachable height with a short timeout must come back with the current tip, not an error.
    w = rpc.call("waitforblockheight", count + 1_000_000, 250)
    ck("waitforblockheight timeout returns the current tip", w["height"] >= count, w)
    w = rpc.call("waitfornewblock", 250)
    ck("waitfornewblock timeout returns the current tip", w["height"] >= count, w)
    # waitforblock watches the tip for one hash: either it is still the tip, or the chain moved on.
    w = rpc.call("waitforblock", best, 250)
    ck("waitforblock(tip) returns that block", w["hash"] == best or w["height"] > count, f"{w} vs {best}@{count}")
    # waitforsync is zecd's extension: it answers the *other* half of "caught up" - whether the
    # transaction-enhancement backlog has drained, which is what makes memos readable. The
    # daemon under test is synced, so this returns promptly with synced=True.
    w = rpc.call("waitforsync", 30_000)
    ck("waitforsync returns the sync-state shape",
       isinstance(w, dict)
       and set(w) == {"hash", "height", "chain_tip", "synced",
                      "pending_enhancements", "enhanced_through"}, w)
    ck("waitforsync reports synced on a caught-up wallet", w["synced"] is True, w)
    ck("waitforsync drained backlog is 0", w["pending_enhancements"] == 0, w)
    # `height` is the scanned height and `chain_tip` is what it is measured against, which is
    # what lets a caller render progress without opening its own connection to the chain.
    # `synced` is exactly `scanned >= tip` (and is false while the tip is unknown), so on a
    # caught-up wallet the tip must be a known height that the scan has already reached.
    ck("waitforsync reports the chain tip as a height when synced",
       isinstance(w["chain_tip"], int) and w["chain_tip"] >= 0, w)
    ck("waitforsync scanned height has reached the chain tip when synced",
       w["chain_tip"] <= w["height"], w)
    # Once synced, the watermark must be a real height - `null` means "unknown", and a caller
    # advancing a memo cursor relies on this being present exactly when it is safe to advance.
    ck("waitforsync enhanced_through is a height when synced",
       isinstance(w["enhanced_through"], int) and w["enhanced_through"] >= 0, w)
    ck("waitforsync enhanced_through does not exceed the scanned height",
       w["enhanced_through"] <= w["height"], w)
    try:
        rpc.call("waitforsync", -1)
        ck("waitforsync negative timeout raises", False)
    except JSONRPCException as e:
        ck("waitforsync negative timeout -> code -1", e.code == -1, e.code)
    try:
        rpc.call("waitforsync", "soon")
        ck("waitforsync non-integer timeout raises", False)
    except JSONRPCException as e:
        ck("waitforsync non-integer timeout -> code -3", e.code == -3, e.code)
    try:
        rpc.call("waitforblockheight")
        ck("waitforblockheight without a height raises", False)
    except JSONRPCException as e:
        ck("waitforblockheight without a height -> code -1", e.code == -1, e.code)
    try:
        rpc.call("waitforblockheight", "soon")
        ck("waitforblockheight non-integer height raises", False)
    except JSONRPCException as e:
        ck("waitforblockheight non-integer height -> code -3", e.code == -3, e.code)
    try:
        rpc.call("waitfornewblock", -1)
        ck("negative timeout raises", False)
    except JSONRPCException as e:
        ck("negative timeout -> code -1", e.code == -1, e.code)
    try:
        rpc.call("waitforblock", "xyz", 250)
        ck("waitforblock bad hash raises", False)
    except JSONRPCException as e:
        ck("waitforblock bad hash -> code -8", e.code == -8, e.code)


@section("control methods", *BOTH)
def s_control(ctx):
    rpc, ck = ctx.rpc, ctx.ck
    h = rpc.call("help")
    ck("help is a string naming methods", isinstance(h, str) and "getblockchaininfo" in h)
    up = rpc.call("uptime")
    ck("uptime is a non-negative int", isinstance(up, int) and up >= 0, up)
    ck("ping returns null", rpc.call("ping") is None)
    ri = rpc.call("getrpcinfo")
    ck("getrpcinfo.active_commands is list", isinstance(ri.get("active_commands"), list))
    # Bitcoin Core's getrpcinfo reports itself as an active command.
    ck("getrpcinfo lists itself active",
       any(c.get("method") == "getrpcinfo" for c in ri.get("active_commands", [])))
    ck("active command carries duration",
       all("duration" in c for c in ri.get("active_commands", [])))
    ck("getrpcinfo has logpath", "logpath" in ri)


@section("fee & mempool stubs", ZCASH)
def s_fee_stubs(ctx):
    rpc, ck = ctx.rpc, ctx.ck
    esf = rpc.call("estimatesmartfee", 2)
    ck("estimatesmartfee.feerate is Decimal",
       isinstance(esf.get("feerate"), decimal.Decimal), repr(esf.get("feerate")))
    ck("estimatesmartfee echoes blocks", esf.get("blocks") == 2, esf.get("blocks"))
    ck("estimatefee is Decimal", isinstance(rpc.call("estimatefee"), decimal.Decimal))
    mp = rpc.call("getmempoolinfo")
    ck("getmempoolinfo.loaded", mp.get("loaded") is True)
    for f in ("size", "bytes", "usage", "maxmempool"):
        ck(f"getmempoolinfo.{f} is int", isinstance(mp.get(f), int), repr(mp.get(f)))
    ck("getmempoolinfo.mempoolminfee is Decimal",
       isinstance(mp.get("mempoolminfee"), decimal.Decimal), repr(mp.get("mempoolminfee")))


@section("estimatesmartfee", BITCOIN)
def s_estimatesmartfee_bitcoin(ctx):
    rpc, ck = ctx.rpc, ctx.ck
    # The wallet's backend estimate (bitcoind's own estimator, or the kyoto fee chain): a
    # BTC/kvB Decimal, or Core's `errors` shape when there is no data (a fresh regtest node
    # has none) - never an RPC error for "no estimate". The target is echoed either way.
    esf = rpc.call("estimatesmartfee", 6)
    ck("estimatesmartfee echoes blocks", esf.get("blocks") == 6, repr(esf))
    ck("estimatesmartfee has a Decimal feerate or an errors list",
       isinstance(esf.get("feerate"), decimal.Decimal) or isinstance(esf.get("errors"), list),
       repr(esf))
    ck("estimatesmartfee economical accepted",
       rpc.call("estimatesmartfee", 6, "economical").get("blocks") == 6)
    for bad in ((0,), (1009,), (6, "fastest")):
        try:
            rpc.call("estimatesmartfee", *bad)
            ck(f"estimatesmartfee {bad} raises", False)
        except JSONRPCException as e:
            ck(f"estimatesmartfee {bad} -> code -8", e.code == -8, e.code)


@section("getnetworkinfo fields", *BOTH)
def s_getnetworkinfo(ctx):
    rpc, ck = ctx.rpc, ctx.ck
    ni = rpc.call("getnetworkinfo")
    for f in ("version", "subversion", "protocolversion", "connections", "relayfee", "networks", "warnings"):
        ck(f"has {f}", f in ni)
    ck("relayfee is Decimal", isinstance(ni["relayfee"], decimal.Decimal), repr(ni["relayfee"]))


@section("getpeerinfo shape", ZCASH)
def s_getpeerinfo(ctx):
    rpc, ck = ctx.rpc, ctx.ck
    pi = rpc.call("getpeerinfo")
    ck("getpeerinfo is list", isinstance(pi, list))
    # Reflects the active lightwalletd upstream; on a synced daemon there should be one "peer".
    if pi:
        ck("peer has addr", isinstance(pi[0].get("addr"), str) and bool(pi[0]["addr"]))
    # getconnectioncount agrees with the peer list (the single lightwalletd "peer").
    cc = rpc.call("getconnectioncount")
    ck("getconnectioncount matches getpeerinfo", cc == len(pi), f"{cc} != {len(pi)}")


@section("getwalletinfo fields", *BOTH)
def s_getwalletinfo(ctx):
    rpc, ck = ctx.rpc, ctx.ck
    wi = rpc.call("getwalletinfo")
    for f in ("walletname", "balance", "unconfirmed_balance", "immature_balance", "txcount", "paytxfee"):
        ck(f"has {f}", f in wi)
    ck("balance is Decimal (not float)", isinstance(wi["balance"], decimal.Decimal), repr(wi["balance"]))
    # A seeded wallet can sign; only watch-only (init --ufvk / --xpub) wallets report False here.
    ck("private_keys_enabled is True", wi.get("private_keys_enabled") is True,
       repr(wi.get("private_keys_enabled")))
    if ctx.coin == BITCOIN:
        ck("getwalletinfo.descriptors is True", wi.get("descriptors") is True,
           repr(wi.get("descriptors")))
    # zecd extension, same shape on both engines: the recorded birthday height, its date as a
    # UTC midnight when known (the operator's, or the mainnet per-day table's) or None, and the
    # resolved scan anchor {height, hash} or None (always None on Zcash and bitcoind wallets).
    bd = wi.get("birthday")
    ck("getwalletinfo has a birthday object", isinstance(bd, dict), repr(bd))
    if isinstance(bd, dict):
        ck("birthday.height is a height", isinstance(bd.get("height"), int) and bd["height"] >= 0, bd)
        ck("birthday.time is unix seconds or None",
           bd.get("time") is None or (isinstance(bd["time"], int) and bd["time"] > 0), bd)
        anchor = bd.get("anchor")
        ck("birthday.anchor is None or {height, hash}",
           anchor is None or (isinstance(anchor, dict) and isinstance(anchor.get("height"), int)
                              and isinstance(anchor.get("hash"), str) and len(anchor["hash"]) == 64),
           anchor)
        if ctx.coin == ZCASH:
            ck("a Zcash birthday has no deferred date or anchor",
               bd.get("time") is None and anchor is None, bd)
    scanning = wi.get("scanning")
    if ctx.coin == ZCASH:
        # The transparent observability block appears only when [pools] transparent is enabled; this
        # daemon is shielded-only, so it must be absent (the default response shape is unchanged). The
        # present-and-populated case is asserted by the regtest_transparent e2e.
        ck("getwalletinfo omits transparent block when disabled", "transparent" not in wi)
        # `scanning` is Core's union: an object while scanning or draining the enhancement backlog,
        # literal False when idle. When it is an object it carries zecd's `pending_enhancements`
        # extension - the only route to the backlog count for a caller with no health server (an
        # embedded node, or any pure JSON-RPC client). This suite usually runs against a caught-up
        # daemon, so accept either shape and only constrain the object form.
        ck("getwalletinfo scanning is an object or False",
           scanning is False or isinstance(scanning, dict), repr(scanning))
        # `enhanced_through` is top-level, NOT inside `scanning` - that object is False once the
        # wallet is idle, which is precisely when a consumer following history as a log is ready to
        # advance its cursor and therefore needs the watermark. The field must be present (possibly
        # null) in both states, which is the property this asserts.
        ck("getwalletinfo carries a top-level enhanced_through", "enhanced_through" in wi, wi.keys())
        ck("enhanced_through is a height or null",
           wi["enhanced_through"] is None
           or (isinstance(wi["enhanced_through"], int) and wi["enhanced_through"] >= 0),
           repr(wi.get("enhanced_through")))
        ck("enhanced_through is not nested inside scanning",
           not (isinstance(scanning, dict) and "enhanced_through" in scanning), repr(scanning))
        if isinstance(scanning, dict):
            ck("scanning carries pending_enhancements", "pending_enhancements" in scanning,
               repr(scanning))
            ck("pending_enhancements is a non-negative integer",
               isinstance(scanning.get("pending_enhancements"), int)
               and scanning["pending_enhancements"] >= 0,
               repr(scanning.get("pending_enhancements")))
    else:
        # The Bitcoin engine's extensions: `coin` names the engine, `lastprocessedblock` (Core
        # master's field) is the wallet's own synced checkpoint - the same pair getblockcount /
        # getbestblockhash answer - and `upstream_connected` is the one signal that the chain
        # source is reachable (Bitcoin wallets serve no getpeerinfo).
        ck("getwalletinfo.coin is bitcoin", wi.get("coin") == "bitcoin", repr(wi.get("coin")))
        lpb = wi.get("lastprocessedblock")
        ck("lastprocessedblock is {hash,height}",
           isinstance(lpb, dict) and set(lpb) == {"hash", "height"}, lpb)
        # The wallet may still be applying blocks while this runs (a catch-up, or a block that
        # just landed), so compare against a fresh read and let the three settle (bounded)
        # rather than pinning the tip captured earlier.
        agrees = False
        for _ in range(40):
            count_now, best_now = rpc.call("getblockcount"), rpc.call("getbestblockhash")
            lpb = rpc.call("getwalletinfo")["lastprocessedblock"]
            if lpb == {"hash": best_now, "height": count_now}:
                agrees = True
                break
            time.sleep(0.5)
        ck("lastprocessedblock == {getbestblockhash, getblockcount}", agrees, lpb)
        ck("upstream_connected is a bool", isinstance(wi.get("upstream_connected"), bool),
           repr(wi.get("upstream_connected")))
        ck("getwalletinfo scanning is an object or False",
           scanning is False or isinstance(scanning, dict), repr(scanning))
        ck("txcount is an int", isinstance(wi["txcount"], int), repr(wi["txcount"]))
        # No passphrase RPCs on this engine, so no encryption state to report.
        ck("getwalletinfo omits unlocked_until", "unlocked_until" not in wi)
    ctx.wi = wi


@section("amounts are exact decimals", *BOTH)
def s_amounts(ctx):
    rpc, ck = ctx.rpc, ctx.ck
    bal = rpc.call("getbalance")
    ck("getbalance is Decimal", isinstance(bal, decimal.Decimal), repr(bal))
    ck("getunconfirmedbalance is Decimal",
       isinstance(rpc.call("getunconfirmedbalance"), decimal.Decimal))
    # 8-dp string form, no float drift
    ck("getbalance 8-dp serialisable", str(bal) == format(bal, "f") or bal == bal)

    # minconf is honored: 1-conf balance includes at least everything the (stricter)
    # default spendability policy counts; an impossibly deep minconf excludes everything.
    bal1 = rpc.call("getbalance", "*", 1)
    ck("getbalance('*',1) is Decimal", isinstance(bal1, decimal.Decimal), repr(bal1))
    ck("getbalance('*',1) >= getbalance()", bal1 >= bal, f"{bal1} < {bal}")
    ck("getbalance('*',99999999) == 0", rpc.call("getbalance", "*", 99999999) == 0)
    try:
        rpc.call("getbalance", "account1")
        ck("getbalance bad dummy raises", False)
    except JSONRPCException as e:
        ck("getbalance bad dummy -> code -32", e.code == -32, e.code)
    try:
        rpc.call("getbalance", "*", "six")
        ck("getbalance non-numeric minconf raises", False)
    except JSONRPCException as e:
        ck("getbalance non-numeric minconf -> code -3", e.code == -3, e.code)
    ctx.bal = bal


@section("getblockheader", ZCASH)
def s_getblockheader(ctx):
    rpc, ck = ctx.rpc, ctx.ck
    tip_hash = rpc.call("getblockhash", rpc.call("getblockcount"))
    hdr = rpc.call("getblockheader", tip_hash)
    for f in ("hash", "confirmations", "height", "time", "mediantime"):
        ck(f"header has {f}", f in hdr)
    ck("header echoes hash", hdr["hash"] == tip_hash)
    ck("tip header confirmations == 1", hdr["confirmations"] == 1, hdr["confirmations"])
    ck("header has previousblockhash", "previousblockhash" in hdr)
    prev = rpc.call("getblockheader", hdr["previousblockhash"])
    ck("prev header links forward", prev.get("nextblockhash") == tip_hash)
    try:
        rpc.call("getblockheader", "00" * 32)
        ck("unknown header raises", False)
    except JSONRPCException as e:
        ck("unknown header -> code -5", e.code == -5, e.code)
    try:
        rpc.call("getblockheader", "xyz")
        ck("bad header hash raises", False)
    except JSONRPCException as e:
        ck("bad header hash -> code -8", e.code == -8, e.code)
    try:
        rpc.call("getblockheader", tip_hash, False)
        ck("verbose=false raises", False)
    except JSONRPCException as e:
        ck("verbose=false -> code -8", e.code == -8, e.code)


@section("getbalances", *BOTH)
def s_getbalances(ctx):
    rpc, ck, bal = ctx.rpc, ctx.ck, ctx.bal
    gb = rpc.call("getbalances")
    mine = gb.get("mine", {})
    for f in ("trusted", "untrusted_pending", "immature"):
        ck(f"mine.{f} is Decimal", isinstance(mine.get(f), decimal.Decimal), repr(mine.get(f)))
    ck("mine.trusted == getbalance", mine.get("trusted") == bal)
    if ctx.coin == ZCASH:
        # zecd extension: mine.coinbase is the portion of trusted that is mature transparent
        # coinbase - spendable only via z_shieldcoinbase, so it is broken out for callers to see
        # how much of trusted cannot move through the regular send paths. A subset of trusted (not
        # a fourth bucket): the Core triple still totals the wallet. This wallet holds no coinbase,
        # so the value is zero; the populated case is asserted by the regtest coinbase e2e.
        ck("mine.coinbase is Decimal", isinstance(mine.get("coinbase"), decimal.Decimal),
           repr(mine.get("coinbase")))
        ck("mine.coinbase is a subset of trusted",
           decimal.Decimal(0) <= mine.get("coinbase") <= mine.get("trusted"),
           repr(mine.get("coinbase")))


@section("addresses", *BOTH)
def s_addresses(ctx):
    rpc, ck = ctx.rpc, ctx.ck
    if ctx.coin == ZCASH:
        # zecd is stateless: getnewaddress takes no label (a label would be off-chain state with no
        # on-chain source). A non-empty label argument is rejected -8 (checked below).
        addr = rpc.call("getnewaddress")
        ck("getnewaddress unified",
           isinstance(addr, str) and addr.startswith(("u1", "utest1", "uregtest1")))
        va = rpc.call("validateaddress", addr)
        ck("validateaddress.isvalid", va["isvalid"] is True)
        ck("validateaddress echoes address", va.get("address") == addr)
        # Extension fields: the address's receiver verdicts (a default getnewaddress UA always
        # exposes an Orchard receiver in the default Orchard-only config).
        ck("validateaddress has isvalid_orchard", "isvalid_orchard" in va)
        ck("validateaddress.isvalid_orchard on Orchard UA", va["isvalid_orchard"] is True)
        # receiver_types enumerates the pools an address can receive into; an Orchard-only UA
        # carries "orchard".
        ck("validateaddress.receiver_types lists orchard",
           isinstance(va.get("receiver_types"), list) and "orchard" in va["receiver_types"],
           va.get("receiver_types"))
        # A per-call receiver override (constrained to enabled pools) still yields a UA. "unified"
        # and "orchard" are always valid against the default config; an unknown type is -5.
        a2 = rpc.call("getnewaddress", "", "orchard")
        ck("getnewaddress orchard override",
           isinstance(a2, str) and a2.startswith(("u1", "utest1", "uregtest1")))
        ck("getnewaddress orchard override isvalid_orchard",
           rpc.call("validateaddress", a2)["isvalid_orchard"] is True)
        try:
            rpc.call("getnewaddress", "", "boguspool")
            ck("getnewaddress unknown receiver raises", False)
        except JSONRPCException as e:
            ck("getnewaddress unknown receiver -> -5", e.code == -5, e.code)
        # Transparent receiving is off by default: address_type "transparent" is rejected (-8) unless
        # the wallet opts in via [pools] transparent = true. (The transparent happy path is covered by
        # the regtest_transparent e2e, which enables it.)
        try:
            rpc.call("getnewaddress", "", "transparent")
            ck("getnewaddress transparent on shielded-only wallet raises", False)
        except JSONRPCException as e:
            ck("getnewaddress transparent -> -8 when disabled", e.code == -8, e.code)
        # Bitcoin Core returns only the verdict + error details for invalid input.
        bad = rpc.call("validateaddress", "not-an-address")
        ck("invalid validateaddress.isvalid False", bad["isvalid"] is False)
        ck("invalid validateaddress has no address echo",
           "address" not in bad and "scriptPubKey" not in bad and "isscript" not in bad)
        ck("invalid validateaddress has error fields",
           "error" in bad and "error_locations" in bad)
        ai = rpc.call("getaddressinfo", addr)
        ck("getaddressinfo.ismine", ai["ismine"] is True)
        ck("getaddressinfo has no isvalid", "isvalid" not in ai)
        for f in ("scriptPubKey", "solvable", "iswatchonly", "isscript", "iswitness", "labels",
                  "isvalid_orchard", "receiver_types"):
            ck(f"getaddressinfo has {f}", f in ai)
        # zecd is stateless: the labels field is retained for Core shape but is always empty.
        ck("getaddressinfo.labels always empty (stateless)", ai["labels"] == [], repr(ai["labels"]))
        # Own addresses are solvable; iswatchonly is deprecated/always false in Core master
        # (these hold on watch-only wallets too - the signal is private_keys_enabled).
        ck("getaddressinfo.solvable on own address", ai["solvable"] is True)
        ck("getaddressinfo.iswatchonly always False", ai["iswatchonly"] is False)
        # The BIP 44 derivation fields describe a transparent address's place in the address chain, so
        # they are absent entirely for a shielded one (rather than present-and-null). Their populated
        # form is asserted in the transparent regtest e2e.
        for f in ("hdkeypath", "address_index", "ischange"):
            ck(f"getaddressinfo omits {f} for a shielded address", f not in ai)
    else:
        # The engine derives BIP 84 native segwit and nothing else: a bech32 address on every
        # network, `bech32` the only accepted address_type, labels refused like the Zcash side.
        addr = rpc.call("getnewaddress")
        ck("getnewaddress bech32",
           isinstance(addr, str) and addr.startswith(("bc1q", "tb1q", "bcrt1q")), addr)
        ck("getnewaddress accepts address_type bech32",
           rpc.call("getnewaddress", "", "bech32").startswith(("bc1q", "tb1q", "bcrt1q")))
        try:
            rpc.call("getnewaddress", "", "legacy")
            ck("getnewaddress legacy raises", False)
        except JSONRPCException as e:
            ck("getnewaddress legacy -> -8 (bech32 only)", e.code == -8, e.code)
        va = rpc.call("validateaddress", addr)
        ck("validateaddress.isvalid", va["isvalid"] is True)
        ck("validateaddress echoes address", va.get("address") == addr)
        for f in ("scriptPubKey", "isscript", "iswitness", "witness_version", "witness_program"):
            ck(f"validateaddress has {f}", f in va)
        ck("validateaddress: a bech32 address is witness v0", va.get("witness_version") == 0
           and va.get("iswitness") is True and va.get("isscript") is False, repr(va))
        # Bitcoin Core returns the verdict and its error fields for invalid input, no echo.
        bad = rpc.call("validateaddress", "not-an-address")
        ck("invalid validateaddress.isvalid False", bad["isvalid"] is False)
        ck("invalid validateaddress has no address echo", "address" not in bad)
        ck("invalid validateaddress has error fields",
           isinstance(bad.get("error"), str) and bad.get("error_locations") == [], repr(bad))
        ai = rpc.call("getaddressinfo", addr)
        ck("getaddressinfo.labels always empty (stateless)", ai.get("labels") == [],
           repr(ai.get("labels")))
        ck("getaddressinfo.scriptPubKey matches validateaddress",
           ai.get("scriptPubKey") == va.get("scriptPubKey"))
        ck("getaddressinfo carries the owning key",
           isinstance(ai.get("pubkey"), str) and ai.get("pubkey", "") in ai.get("desc", "")
           and isinstance(ai.get("hdmasterfingerprint"), str), repr(ai))
        ck("getaddressinfo.ismine", ai["ismine"] is True)
        ck("getaddressinfo has no isvalid", "isvalid" not in ai)
        ck("getaddressinfo.solvable on own address", ai["solvable"] is True)
        ck("getaddressinfo.iswatchonly always False", ai["iswatchonly"] is False)
        # The BIP 84 derivation fields are present for every own address: Core's hdkeypath
        # (receiving keychain, so /0/<index>) and ischange, plus zecd's address_index.
        ck("getaddressinfo.ischange False on a receiving address", ai.get("ischange") is False,
           repr(ai.get("ischange")))
        ck("getaddressinfo.address_index is an int", isinstance(ai.get("address_index"), int),
           repr(ai.get("address_index")))
        ck("getaddressinfo.hdkeypath is the BIP 84 receiving path",
           isinstance(ai.get("hdkeypath"), str)
           and ai["hdkeypath"].startswith("m/84'/") and "'/0'/0/" in ai["hdkeypath"]
           and ai["hdkeypath"].endswith(f"/{ai.get('address_index')}"), ai.get("hdkeypath"))
    try:
        rpc.call("getaddressinfo", "not-an-address")
        ck("getaddressinfo invalid raises", False)
    except JSONRPCException as e:
        ck("getaddressinfo invalid -> code -5", e.code == -5, e.code)
    ctx.addr = addr


@section("signmessage / verifymessage", ZCASH)
def s_signmessage(ctx):
    rpc, ck, addr = ctx.rpc, ctx.ck, ctx.addr
    # signmessage signs with a transparent address's key; verifymessage recovers the signer and
    # compares the address (Bitcoin Core's pair, ported from zallet). This wallet is shielded-only
    # (no transparent addresses to own), so the happy-path round-trip is covered by the
    # regtest_transparent e2e; here we assert the argument/error contract, which is
    # network-independent. A "t2..." regtest P2SH address is a valid transparent address that does
    # not refer to a key.
    P2SH_ADDR = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v"
    try:
        rpc.call("signmessage", "not-an-address", "hello")
        ck("signmessage invalid address raises", False)
    except JSONRPCException as e:
        ck("signmessage invalid address -> -5", e.code == -5, e.code)
    try:
        # A shielded UA is not a transparent address: rejected before the seed is touched.
        rpc.call("signmessage", addr, "hello")
        ck("signmessage shielded address raises", False)
    except JSONRPCException as e:
        ck("signmessage shielded address -> -5", e.code == -5, e.code)
    try:
        rpc.call("signmessage", P2SH_ADDR, "hello")
        ck("signmessage P2SH address raises", False)
    except JSONRPCException as e:
        ck("signmessage P2SH address -> -3", e.code == -3, e.code)
    # verifymessage error/edge contract. Malformed base64 is -5; a P2SH address is -3; a
    # well-formed-but-wrong-length signature verifies false (not an error).
    try:
        rpc.call("verifymessage", P2SH_ADDR, "AAAA", "hello")
        ck("verifymessage P2SH address raises", False)
    except JSONRPCException as e:
        ck("verifymessage P2SH address -> -3", e.code == -3, e.code)
    try:
        rpc.call("verifymessage", "not-an-address", "AAAA", "hello")
        ck("verifymessage invalid address raises", False)
    except JSONRPCException as e:
        ck("verifymessage invalid address -> -3", e.code == -3, e.code)
    # (The malformed-base64 -5, wrong-length -> false, and full sign->verify round-trip against a
    # real transparent key are covered by the src/rpc/signmessage.rs unit tests - which pin
    # zallet's forum vector - and the regtest_transparent e2e.)


@section("z_getaddressforaccount", ZCASH)
def s_z_getaddressforaccount(ctx):
    rpc, ck, addr = ctx.rpc, ctx.ck, ctx.addr
    # zcashd-syntax derivation of a Unified Address for the wallet's single account (0). zecd is
    # shielded-only: the default config is Orchard-only, so a default UA carries just "orchard".
    a = rpc.call("z_getaddressforaccount", 0)
    ck("z_getaddressforaccount.account is 0", a["account"] == 0)
    ck("z_getaddressforaccount returns a UA",
       isinstance(a["address"], str) and a["address"].startswith(("u1", "utest1", "uregtest1")))
    ck("z_getaddressforaccount.receiver_types is orchard",
       a["receiver_types"] == ["orchard"], a["receiver_types"])
    ck("z_getaddressforaccount.diversifier_index is an int",
       isinstance(a["diversifier_index"], int), repr(a["diversifier_index"]))
    # Re-deriving at the SAME diversifier index with the same receivers is idempotent: it returns
    # the exact same object (the key zcashd invariant, wallet_accounts.py:93).
    j = a["diversifier_index"]
    a_again = rpc.call("z_getaddressforaccount", 0, [], j)
    ck("z_getaddressforaccount is idempotent at a fixed index", a_again == a, (a_again, a))
    # The next auto-selected address differs (a fresh, unused diversifier).
    b = rpc.call("z_getaddressforaccount", 0)
    ck("z_getaddressforaccount auto-index advances", b["address"] != a["address"])
    # An explicit diversifier index re-derives the exact orchard-only UA at that index. We use a
    # high, fixed index rather than 0: zcash_client_sqlite parks each account's default address at
    # the first index with a valid Sapling diversifier (index 0 about half the time, seed-
    # dependent), and librustzcash refuses to expose a second UA with different receivers at an
    # already-used index (DiversifierIndexReuse -> -4). A large index can't collide with that
    # low-index default (nor with the clock-derived auto indices above), and Orchard diversifiers
    # are valid at every index.
    jx = 1_000_000
    zx = rpc.call("z_getaddressforaccount", 0, ["orchard"], jx)
    ck("z_getaddressforaccount at a fixed index (orchard)", zx["diversifier_index"] == jx)
    ck("z_getaddressforaccount fixed index receiver_types", zx["receiver_types"] == ["orchard"])
    # "p2pkh" derives a bare t-address, but only on a wallet with [pools] transparent = true.
    # This daemon is shielded-only, so it is rejected -8 with the enabling remedy. (The
    # transparent-enabled behaviour - deriving the bare address at an explicit BIP 44 child index -
    # is exercised live in regtest_transparent.rs.)
    try:
        rpc.call("z_getaddressforaccount", 0, ["p2pkh"])
        ck("z_getaddressforaccount p2pkh raises", False)
    except JSONRPCException as e:
        ck("z_getaddressforaccount p2pkh (transparent off) -> -8", e.code == -8, e.code)
    # p2pkh can never be combined with a shielded receiver: ZIP-316 forbids a transparent-only
    # unified address, and zecd hands transparent receivers out bare rather than mixing them in.
    try:
        rpc.call("z_getaddressforaccount", 0, ["p2pkh", "orchard"])
        ck("z_getaddressforaccount p2pkh+orchard raises", False)
    except JSONRPCException as e:
        ck("z_getaddressforaccount p2pkh+orchard -> -8", e.code == -8, e.code)
    # p2sh is never derivable (zecd holds no redeem scripts).
    try:
        rpc.call("z_getaddressforaccount", 0, ["p2sh"])
        ck("z_getaddressforaccount p2sh raises", False)
    except JSONRPCException as e:
        ck("z_getaddressforaccount p2sh -> -8", e.code == -8, e.code)
    # A pool not enabled on this wallet (Sapling, in the Orchard-only default) is also -8.
    try:
        rpc.call("z_getaddressforaccount", 0, ["sapling"])
        ck("z_getaddressforaccount disabled pool raises", False)
    except JSONRPCException as e:
        ck("z_getaddressforaccount disabled pool -> -8", e.code == -8, e.code)
    # An unknown receiver token is -8.
    try:
        rpc.call("z_getaddressforaccount", 0, ["bogus"])
        ck("z_getaddressforaccount unknown receiver raises", False)
    except JSONRPCException as e:
        ck("z_getaddressforaccount unknown receiver -> -8", e.code == -8, e.code)
    # Only account 0 exists (one account per wallet): a different in-range account is -4.
    try:
        rpc.call("z_getaddressforaccount", 1)
        ck("z_getaddressforaccount account 1 raises", False)
    except JSONRPCException as e:
        ck("z_getaddressforaccount account 1 -> -4", e.code == -4, e.code)
    # An out-of-range account number is -8.
    try:
        rpc.call("z_getaddressforaccount", -1)
        ck("z_getaddressforaccount account -1 raises", False)
    except JSONRPCException as e:
        ck("z_getaddressforaccount account -1 -> -8", e.code == -8, e.code)
    # A diversifier index beyond the 11-byte space is -8.
    try:
        rpc.call("z_getaddressforaccount", 0, [], 2 ** 88)
        ck("z_getaddressforaccount huge diversifier raises", False)
    except JSONRPCException as e:
        ck("z_getaddressforaccount huge diversifier -> -8", e.code == -8, e.code)
    # A negative diversifier index is -8.
    try:
        rpc.call("z_getaddressforaccount", 0, [], -1)
        ck("z_getaddressforaccount negative diversifier raises", False)
    except JSONRPCException as e:
        ck("z_getaddressforaccount negative diversifier -> -8", e.code == -8, e.code)
    # A missing required argument is Bitcoin Core's help error (-1), never -32602 (which Core
    # reserves for framing and never emits from a handler).
    try:
        rpc.call("z_getaddressforaccount")
        ck("z_getaddressforaccount no args raises", False)
    except JSONRPCException as e:
        ck("z_getaddressforaccount no args -> -1", e.code == -1, e.code)


@section("received-by-address", *BOTH)
def s_received_by_address(ctx):
    rpc, ck, addr = ctx.rpc, ctx.ck, ctx.addr
    recv = rpc.call("getreceivedbyaddress", addr)
    ck("getreceivedbyaddress is Decimal", isinstance(recv, decimal.Decimal), repr(recv))
    ck("fresh address received 0", recv == 0)
    lra = rpc.call("listreceivedbyaddress", 1, True)
    ck("listreceivedbyaddress is list", isinstance(lra, list))
    fresh = next((e for e in lra if e.get("address") == addr), None)
    ck("fresh address listed with include_empty", fresh is not None)
    # include_empty surfaces every generated address (this is zecd's `listaddresses`
    # equivalent), and an unused one reports zeros: no amount, no confirmations, no txids.
    if fresh is not None:
        ck("fresh entry amount 0", fresh.get("amount") == 0, repr(fresh.get("amount")))
        ck("fresh entry confirmations 0", fresh.get("confirmations") == 0, repr(fresh.get("confirmations")))
        ck("fresh entry no txids", fresh.get("txids") == [], repr(fresh.get("txids")))
        if ctx.coin == BITCOIN:
            # zecd extension: the receiving keychain index, the same value getaddressinfo
            # reports - so an issued range reconciles from this one call.
            ck("entry carries address_index", isinstance(fresh.get("address_index"), int),
               repr(fresh.get("address_index")))
            ck("address_index matches getaddressinfo",
               fresh.get("address_index") == rpc.call("getaddressinfo", addr).get("address_index"))
            ck("entries ascend by address_index",
               [e["address_index"] for e in lra] == sorted(e["address_index"] for e in lra))
    # include_immature_coinbase (Core's 3rd/5th parameter). This wallet holds no coinbase, so
    # the flag must be accepted on both methods and change nothing; the maturity behaviour it
    # governs is exercised live in the coinbase regtest e2e.
    recv_imm = rpc.call("getreceivedbyaddress", addr, 1, True)
    ck("getreceivedbyaddress include_immature_coinbase is Decimal",
       isinstance(recv_imm, decimal.Decimal), repr(recv_imm))
    ck("no coinbase -> include_immature_coinbase changes nothing", recv_imm == recv)
    lra_imm = rpc.call("listreceivedbyaddress", 1, True, False, None, True)
    ck("listreceivedbyaddress include_immature_coinbase is list", isinstance(lra_imm, list))
    ck("no coinbase -> listed entries unchanged", lra_imm == lra)
    # address_filter (Core's 4th parameter, pushed into SQL like getreceivedbyaddress's
    # address): with include_empty the filtered call returns exactly the one address; without
    # it an unused address yields an empty list, not an error.
    lra_f = rpc.call("listreceivedbyaddress", 1, True, False, addr)
    ck("address_filter returns exactly the filtered address",
       [e.get("address") for e in lra_f] == [addr], repr(lra_f))
    lra_f_used = rpc.call("listreceivedbyaddress", 1, False, False, addr)
    ck("address_filter on an unused address without include_empty is empty",
       lra_f_used == [], repr(lra_f_used))
    try:
        rpc.call("getreceivedbyaddress", "not-an-address")
        ck("invalid address raises", False)
    except JSONRPCException as e:
        ck("invalid address -> code -5", e.code == -5, e.code)
    if ctx.coin == BITCOIN:
        try:
            rpc.call("listreceivedbyaddress", 1, True, False, "not-an-address")
            ck("invalid address_filter raises", False)
        except JSONRPCException as e:
            ck("invalid address_filter -> code -5", e.code == -5, e.code)


@section("stateless: label methods are removed", *BOTH)
def s_labels_removed(ctx):
    rpc, ck, addr = ctx.rpc, ctx.ck, ctx.addr
    # zecd keeps no off-chain label store, so the label-dedicated methods are not implemented at
    # all - every one is method-not-found (-32601), like any unknown method.
    for m, params in (
        ("setlabel", [addr, "x"]),
        ("getaddressesbylabel", ["x"]),
        ("listlabels", []),
        ("getreceivedbylabel", ["x"]),
        ("listreceivedbylabel", []),
    ):
        try:
            rpc.call(m, *params)
            ck(f"{m} raises (removed in stateless mode)", False)
        except JSONRPCException as e:
            ck(f"{m} -> method not found (-32601)", e.code == -32601, e.code)
    if ctx.coin == ZCASH:
        # Descriptor-wallet methods exist for the BDK engine only; a Zcash wallet cannot serve
        # them, and a method a wallet cannot serve is indistinguishable from one that does not exist.
        for m, params in (("listdescriptors", []), ("abandontransaction", ["00" * 32])):
            try:
                rpc.call(m, *params)
                ck(f"{m} raises on a Zcash wallet", False)
            except JSONRPCException as e:
                ck(f"{m} -> method not found (-32601) on a Zcash wallet", e.code == -32601, e.code)
    # A non-empty label argument to getnewaddress is rejected (-8); the address itself is fine.
    try:
        rpc.call("getnewaddress", "mylabel")
        ck("getnewaddress label raises", False)
    except JSONRPCException as e:
        ck("getnewaddress label -> code -8", e.code == -8, e.code)


@section("listdescriptors", BITCOIN)
def s_listdescriptors(ctx):
    rpc, ck = ctx.rpc, ctx.ck
    # Core's shape over the wallet's two public BIP 84 descriptors: the receiving chain
    # (/0/*) first, change (/1/*) second, the origin-qualified account xpub inside both, and
    # the keychain's next index. Public material only.
    ld = rpc.call("listdescriptors")
    ck("listdescriptors has wallet_name", isinstance(ld.get("wallet_name"), str), ld.get("wallet_name"))
    ds = ld.get("descriptors")
    ck("listdescriptors has two descriptors", isinstance(ds, list) and len(ds) == 2, ds)
    for d, internal, chain in ((ds[0], False, "/0/*)#"), (ds[1], True, "/1/*)#")):
        for f in ("desc", "timestamp", "active", "internal", "range", "next", "next_index"):
            ck(f"descriptor has {f}", f in d, d.keys())
        ck(f"descriptor internal={internal}", d.get("internal") is internal, d.get("internal"))
        ck("descriptor is an origin-qualified wpkh",
           isinstance(d.get("desc"), str) and d["desc"].startswith("wpkh([") and chain in d["desc"],
           d.get("desc"))
        ck("descriptor is active", d.get("active") is True)
        ck("descriptor range is [0, n]",
           isinstance(d.get("range"), list) and len(d["range"]) == 2 and d["range"][0] == 0
           and d["range"][1] >= d.get("next", 0), d.get("range"))
        ck("descriptor next == next_index", d.get("next") == d.get("next_index"))
    # Both keychains share one account key: the bracketed origin and the key are identical
    # up to the chain suffix.
    ck("both descriptors carry the same account key",
       ds[0]["desc"].split("/0/*")[0] == ds[1]["desc"].split("/1/*")[0])
    # The private form is refused: the database holds public descriptors only and the seed
    # never leaves the process (Core answers a private-keys-disabled wallet the same way).
    try:
        rpc.call("listdescriptors", True)
        ck("listdescriptors private raises", False)
    except JSONRPCException as e:
        ck("listdescriptors private -> code -4", e.code == -4, e.code)
    try:
        rpc.call("listdescriptors", "yes")
        ck("listdescriptors non-boolean raises", False)
    except JSONRPCException as e:
        ck("listdescriptors non-boolean -> code -3", e.code == -3, e.code)


@section("abandontransaction", BITCOIN)
def s_abandontransaction(ctx):
    rpc, ck = ctx.rpc, ctx.ck
    # Core's eligibility matrix, without abandoning anything: a confirmed transaction is
    # "not eligible", an unknown txid is "non-wallet", a malformed one fails parsing (-8)
    # in ParseHashV's two shapes, a missing one is -1. The live abandonment of a genuinely
    # stuck transaction is regtest_btc_hang.rs's kyoto leg.
    confirmed = [t for t in rpc.call("listtransactions", "*", 50) if t["confirmations"] > 0]
    if confirmed:
        try:
            rpc.call("abandontransaction", confirmed[0]["txid"])
            ck("abandontransaction on a confirmed tx raises", False)
        except JSONRPCException as e:
            ck("abandontransaction confirmed -> code -5", e.code == -5, e.code)
            ck("abandontransaction confirmed -> not eligible",
               "not eligible" in str(e), str(e))
    try:
        rpc.call("abandontransaction", "00" * 32)
        ck("abandontransaction unknown txid raises", False)
    except JSONRPCException as e:
        ck("abandontransaction unknown -> code -5", e.code == -5, e.code)
        ck("abandontransaction unknown -> non-wallet", "non-wallet" in str(e), str(e))
    try:
        rpc.call("abandontransaction", "abc")
        ck("abandontransaction short txid raises", False)
    except JSONRPCException as e:
        ck("abandontransaction short txid -> code -8", e.code == -8, e.code)
        ck("abandontransaction short txid names the length", "length 64" in str(e), str(e))
    try:
        rpc.call("abandontransaction", "zz" * 32)
        ck("abandontransaction non-hex txid raises", False)
    except JSONRPCException as e:
        ck("abandontransaction non-hex txid -> code -8", e.code == -8, e.code)
    try:
        rpc.call("abandontransaction")
        ck("abandontransaction without txid raises", False)
    except JSONRPCException as e:
        ck("abandontransaction without txid -> code -1", e.code == -1, e.code)


@section("wallets", *BOTH)
def s_wallets(ctx):
    rpc, ck = ctx.rpc, ctx.ck
    lw = rpc.call("listwallets")
    ck("listwallets is a non-empty list of strings",
       isinstance(lw, list) and bool(lw) and all(isinstance(w, str) for w in lw), lw)

    # listwalletdir: Bitcoin Core's {"wallets": [{"name": ...}]}. Every loaded wallet is also
    # available on disk, so listwallets must be a subset of it.
    lwd = rpc.call("listwalletdir")
    ck("listwalletdir has a wallets array",
       isinstance(lwd, dict) and isinstance(lwd.get("wallets"), list), lwd)
    on_disk = {w.get("name") for w in lwd["wallets"] if isinstance(w, dict)}
    ck("listwalletdir entries are {name: str} objects",
       all(isinstance(n, str) for n in on_disk), on_disk)
    ck("every loaded wallet is available on disk", set(lw) <= on_disk, (lw, on_disk))

    # createwallet onboards a *view* wallet, so it needs a viewing key and a birthday and refuses
    # every Bitcoin Core flag that would ask for a spending wallet. The parameter rejections are
    # what a conformance run can assert without provisioning key material.
    try:
        rpc.call("createwallet")
        ck("createwallet with no name raises", False)
    except JSONRPCException as e:
        ck("createwallet with no name -> -8", e.code == -8, e.code)
    try:
        rpc.call("createwallet", "conformance-tmp")
        ck("createwallet without a ufvk raises", False)
    except JSONRPCException as e:
        ck("createwallet without a ufvk -> -8", e.code == -8, e.code)
    try:
        rpc.call("createwallet", "conformance-tmp", True, None, None, None, None, None, None,
                 {"ufvk": "uview1notarealkey"})
        ck("createwallet without a birthday raises", False)
    except JSONRPCException as e:
        ck("createwallet without a birthday -> -8", e.code == -8, e.code)
    try:
        # zecd loads at most one wallet with spending keys, and it is not created over the wire.
        rpc.call("createwallet", "conformance-tmp", False)
        ck("createwallet asking for spending keys raises", False)
    except JSONRPCException as e:
        ck("createwallet disable_private_keys=false -> -8", e.code == -8, e.code)

    # loadwallet / unloadwallet name a wallet that is not loaded: -18, as for any unknown wallet.
    for method in ("loadwallet", "unloadwallet"):
        try:
            rpc.call(method, "definitely-not-a-wallet")
            ck(f"{method} on an unknown wallet raises", False)
        except JSONRPCException as e:
            ck(f"{method} unknown wallet -> -18 or -4", e.code in (-18, -4), e.code)

    # A configured [wallets.<name>] entry is refused, not unloaded: loadwallet only restores
    # fleet-manifest wallets, so unloading a configured one (the spending wallet included)
    # would be irreversible until a restart.
    configured = rpc.call("getwalletinfo").get("walletname")
    try:
        rpc.call("unloadwallet", configured)
        ck("unloadwallet on a configured wallet raises", False)
    except JSONRPCException as e:
        ck("unloadwallet configured wallet -> -4", e.code == -4, e.code)
    ck("the configured wallet is still served after the refusal",
       isinstance(rpc.call("getwalletinfo"), dict))


@section("listunspent", *BOTH)
def s_listunspent(ctx):
    rpc, ck, addr = ctx.rpc, ctx.ck, ctx.addr
    lu = rpc.call("listunspent")
    ck("listunspent is list", isinstance(lu, list))
    if lu:
        u = lu[0]
        fields = ("txid", "vout", "address", "amount", "confirmations", "spendable", "solvable", "safe")
        if ctx.coin == ZCASH:
            fields += ("pool",)
        else:
            # Core's per-output script and the inferred descriptor of the owning key.
            fields += ("scriptPubKey", "desc")
        for f in fields:
            ck(f"utxo has {f}", f in u)
        ck("utxo amount is Decimal", isinstance(u["amount"], decimal.Decimal))
        if ctx.coin == ZCASH:
            # zecd extension: every note is labelled with its shielded pool.
            ck("utxo pool is a known shielded pool",
               all(e["pool"] in ("sapling", "orchard", "ironwood") for e in lu),
               [e["pool"] for e in lu])
    ck("listunspent include_unsafe=false only safe",
       all(e["safe"] for e in rpc.call("listunspent", 0, 9999999, [], False)))
    # A freshly generated address has no notes; the filter validates its entries.
    ck("listunspent fresh-address filter empty",
       rpc.call("listunspent", 1, 9999999, [addr]) == [])
    try:
        rpc.call("listunspent", 1, 9999999, ["nonsense"])
        ck("listunspent bad filter address raises", False)
    except JSONRPCException as e:
        ck("listunspent bad filter address -> code -5", e.code == -5, e.code)
    try:
        rpc.call("listunspent", 1, 9999999, [addr, addr])
        ck("listunspent duplicated filter address raises", False)
    except JSONRPCException as e:
        ck("listunspent duplicated filter address -> code -8", e.code == -8, e.code)
    try:
        rpc.call("listunspent", "one")
        ck("listunspent non-numeric minconf raises", False)
    except JSONRPCException as e:
        ck("listunspent non-numeric minconf -> code -3", e.code == -3, e.code)
    if ctx.coin == BITCOIN:
        if lu:
            u = lu[0]
            ck("utxo desc is a checksummed wpkh descriptor",
               u["desc"].startswith("wpkh([") and "#" in u["desc"], u["desc"])
        # query_options (Core's 5th parameter): the limits apply, an unknown key is -3.
        everything = rpc.call("listunspent", 0)
        one = rpc.call("listunspent", 0, 9999999, None, True, {"maximumCount": 1})
        ck("query_options maximumCount caps the list", len(one) == min(1, len(everything)),
           (len(one), len(everything)))
        huge = rpc.call("listunspent", 0, 9999999, None, True, {"minimumAmount": 20000000})
        ck("query_options minimumAmount filters", huge == [], repr(huge))
        try:
            rpc.call("listunspent", 0, 9999999, None, True, {"bogus": 1})
            ck("query_options unknown key raises", False)
        except JSONRPCException as e:
            ck("query_options unknown key -> code -3", e.code == -3, e.code)


@section("history", *BOTH)
def s_history(ctx):
    rpc, ck = ctx.rpc, ctx.ck
    txs = rpc.call("listtransactions", "*", 20)
    ck("listtransactions is list", isinstance(txs, list))
    if txs:
        t = txs[0]
        for f in ("address", "category", "amount", "confirmations", "txid", "time",
                  "timereceived", "walletconflicts"):
            ck(f"tx has {f}", f in t)
        ck("tx amount is Decimal", isinstance(t["amount"], decimal.Decimal), repr(t["amount"]))
        ck("tx category valid", t["category"] in ("send", "receive"))
        # Bitcoin Core's WalletTxToJSON: mined txs carry block fields (and no `trusted`);
        # unmined txs carry `trusted` instead.
        if t["confirmations"] > 0:
            for f in ("blockhash", "blockheight", "blocktime"):
                ck(f"mined tx has {f}", f in t)
            ck("mined tx has no trusted", "trusted" not in t)
            ck("mined tx time == blocktime", t["time"] == t["blocktime"])
        else:
            ck("unmined tx has trusted", "trusted" in t)
        if ctx.coin == BITCOIN:
            ck("tx label is empty (stateless)", t.get("label") == "", repr(t.get("label")))
            ck("tx bip125-replaceable is yes/no/unknown",
               t.get("bip125-replaceable") in ("yes", "no", "unknown"), t.get("bip125-replaceable"))
            sends = [e for e in txs if e["category"] == "send"]
            if sends:
                ck("send entries carry a negative Decimal fee",
                   all(isinstance(e.get("fee"), decimal.Decimal) and e["fee"] < 0 for e in sends),
                   [e.get("fee") for e in sends])
        gt = rpc.call("gettransaction", t["txid"])
        ck("gettransaction amount Decimal", isinstance(gt["amount"], decimal.Decimal))
        ck("gettransaction has details list", isinstance(gt.get("details"), list))
        ck("gettransaction hex hex-string", isinstance(gt.get("hex"), str) and len(gt["hex"]) % 2 == 0)
        ck("gettransaction has walletconflicts", gt.get("walletconflicts") == [])
        ck("gettransaction has timereceived", "timereceived" in gt)
        if gt["confirmations"] > 0:
            ck("gettransaction mined has blockhash", "blockhash" in gt)

        if ctx.coin == ZCASH:
            print("== getrawtransaction ==")
            raw = rpc.call("getrawtransaction", t["txid"])
            ck("getrawtransaction returns hex", isinstance(raw, str) and len(raw) % 2 == 0 and raw)
            if gt.get("hex"):
                ck("getrawtransaction matches gettransaction.hex", raw == gt["hex"])
            v = rpc.call("getrawtransaction", t["txid"], 1)
            ck("verbose is object", isinstance(v, dict))
            for f in ("hex", "txid", "size", "version", "locktime", "vin", "vout"):
                ck(f"verbose has {f}", f in v)
            ck("verbose txid echoes", v.get("txid") == t["txid"])
            ck("verbose hex matches", v.get("hex") == raw)
            ck("verbose vin/vout are lists", isinstance(v.get("vin"), list) and isinstance(v.get("vout"), list))


@section("z_listtransactions (extension)", ZCASH)
def s_z_listtransactions(ctx):
    rpc, ck = ctx.rpc, ctx.ck
    # z_listtransactions is a zecd EXTENSION (no such method in zcashd) with zcashd's z_*
    # vocabulary, so it is checked for self-consistency, not held to a bitcoind shape.
    ztx = rpc.call("z_listtransactions", 20)
    ck("z_listtransactions is list", isinstance(ztx, list))
    if ztx:
        z = ztx[0]
        for f in ("txid", "status", "confirmations", "pool", "category", "amount",
                  "amountZat", "address", "outindex", "change", "outgoing",
                  "walletconflicts"):
            ck(f"z_listtransactions entry has {f}", f in z)
        ck("z_listtransactions amount is Decimal", isinstance(z["amount"], decimal.Decimal))
        ck("z_listtransactions amountZat is int", isinstance(z["amountZat"], int))
        ck("z_listtransactions pool valid",
           z["pool"] in ("transparent", "sapling", "orchard", "ironwood"))
        ck("z_listtransactions category valid", z["category"] in ("send", "receive"))
        ck("z_listtransactions status valid",
           z["status"] in ("mined", "waiting", "expired", "expiringsoon"))
        ck("z_listtransactions outgoing is bool", isinstance(z["outgoing"], bool))
        # A send entry's amount is negative; outgoing tracks the send category.
        ck("z_listtransactions send sign", (z["amountZat"] < 0) == (z["category"] == "send"))
    try:
        rpc.call("z_listtransactions", -1)
        ck("z_listtransactions negative count raises", False)
    except JSONRPCException as e:
        ck("z_listtransactions negative count -> -8", e.code == -8, e.code)

    # The height range is zecd's incremental cursor: [start_height, end_height). An unreachable
    # window is empty rather than an error, and an inverted one is rejected outright (it can only
    # ever be empty, so it almost certainly means the arguments were swapped).
    tip = rpc.call("getblockcount")
    windowed = rpc.call("z_listtransactions", 100, 0, False, 0, tip + 1)
    ck("z_listtransactions accepts a height range", isinstance(windowed, list))
    ck("z_listtransactions full range covers the unbounded read",
       len(windowed) >= len([z for z in ztx if z["status"] == "mined"]), len(windowed))
    future = rpc.call("z_listtransactions", 100, 0, False, tip + 1_000_000, tip + 1_000_001)
    ck("z_listtransactions future-only range is empty", future == [], future)
    try:
        rpc.call("z_listtransactions", 100, 0, False, 50, 10)
        ck("z_listtransactions inverted range raises", False)
    except JSONRPCException as e:
        ck("z_listtransactions inverted range -> -8", e.code == -8, e.code)
    try:
        rpc.call("z_listtransactions", 100, 0, False, -1)
        ck("z_listtransactions negative start_height raises", False)
    except JSONRPCException as e:
        ck("z_listtransactions negative start_height -> -8", e.code == -8, e.code)
    try:
        rpc.call("z_listtransactions", 100, 0, False, "soon")
        ck("z_listtransactions non-integer start_height raises", False)
    except JSONRPCException as e:
        ck("z_listtransactions non-integer start_height -> -3", e.code == -3, e.code)


@section("listsinceblock (restart-safe poller)", *BOTH)
def s_listsinceblock(ctx):
    rpc, ck = ctx.rpc, ctx.ck
    lsb = rpc.call("listsinceblock")
    ck("has transactions list", isinstance(lsb.get("transactions"), list))
    ck("has removed list", isinstance(lsb.get("removed"), list))
    # Every history entry names its pool: `vout` is the index within that pool's bundle, so
    # (txid, vout) is ambiguous for a transaction with outputs in more than one pool - and this
    # is the natural incremental cursor, where that ambiguity would bite.
    for t in lsb["transactions"] if ctx.coin == ZCASH else []:
        ck("listsinceblock entry has pool", "pool" in t, t)
        ck("listsinceblock pool valid",
           t["pool"] in ("transparent", "sapling", "orchard", "ironwood"), t.get("pool"))
        break
    ck("lastblock 64-hex", isinstance(lsb.get("lastblock"), str) and len(lsb["lastblock"]) == 64)
    # The daemon may still be scanning a just-mined block when this suite starts (the
    # harness proceeds as soon as a tx hits 1 confirmation), so the `best` captured at the
    # top of the run can be stale here. Compare lastblock against the *current* best hash,
    # re-reading both until they settle (bounded), instead of pinning the earlier snapshot.
    lsb_matches_best = False
    for _ in range(40):
        if lsb["lastblock"] == rpc.call("getbestblockhash"):
            lsb_matches_best = True
            break
        time.sleep(0.5)
        lsb = rpc.call("listsinceblock")
    ck("lastblock == getbestblockhash", lsb_matches_best, lsb["lastblock"])
    again = rpc.call("listsinceblock", lsb["lastblock"])
    ck("since lastblock reports only unconfirmed",
       all(t["confirmations"] < 1 for t in again["transactions"]))
    # A well-formed but unknown blockhash (e.g. a cursor whose block was reorged away) does NOT
    # wedge the poller: zecd lists from the earliest scanned block (re-reports, never misses)
    # instead of erroring, so a reorg can't kill the lastblock cursor loop.
    reorged = rpc.call("listsinceblock", "00" * 32)
    ck("reorged-away cursor lists instead of raising",
       isinstance(reorged.get("transactions"), list)
       and isinstance(reorged.get("lastblock"), str) and len(reorged["lastblock"]) == 64)
    # A malformed hash is a clear client error and still raises -5.
    try:
        rpc.call("listsinceblock", "not-a-block-hash")
        ck("malformed block raises", False)
    except JSONRPCException as e:
        ck("malformed block -> code -5", e.code == -5, e.code)


@section("error handling (JSONRPCException with Bitcoin Core codes)", *BOTH)
def s_errors(ctx):
    rpc, ck, addr, args = ctx.rpc, ctx.ck, ctx.addr, ctx.args
    if ctx.coin == BITCOIN:
        s_errors_bitcoin(ctx)
        return
    try:
        rpc.call("gettransaction", "00" * 32)
        ck("gettransaction unknown raises", False)
    except JSONRPCException as e:
        ck("gettransaction unknown -> code -5", e.code == -5, e.code)
    try:
        rpc.call("no_such_method_xyz")
        ck("unknown method raises", False)
    except JSONRPCException as e:
        ck("unknown method -> code -32601", e.code == -32601, e.code)
    try:
        rpc.call("listtransactions", "*", -1)
        ck("negative count raises", False)
    except JSONRPCException as e:
        ck("negative count -> code -8", e.code == -8, e.code)
    try:
        rpc.call("getnewaddress", "", "bech32")
        ck("unknown address type raises", False)
    except JSONRPCException as e:
        ck("unknown address type -> code -5", e.code == -5, e.code)
    try:
        # Amount as a string (zecd accepts both); the reject fires before any send logic.
        rpc.call("sendtoaddress", addr, "0.1", "", "", True)
        ck("subtractfeefromamount raises", False)
    except JSONRPCException as e:
        ck("subtractfeefromamount -> code -8", e.code == -8, e.code)
    try:
        # Zero amounts are rejected before any send logic, like Bitcoin Core.
        rpc.call("sendtoaddress", addr, 0)
        ck("zero amount raises", False)
    except JSONRPCException as e:
        ck("zero amount -> code -3", e.code == -3, e.code)
    try:
        # Typed arguments: a non-numeric minconf is -3, never silently the default.
        rpc.call("getreceivedbyaddress", addr, "six")
        ck("non-numeric minconf raises", False)
    except JSONRPCException as e:
        ck("non-numeric minconf -> code -3", e.code == -3, e.code)
    try:
        # The memo extension param (11) validates hex before any send logic. Positions
        # 4..=10 are subtractfeefromamount/replaceable/conf_target/estimate_mode/
        # avoid_reuse/fee_rate/verbose - seven nulls before the memo.
        rpc.call("sendtoaddress", addr, "0.1", "", "", None, None, None, None,
                 None, None, None, "not-hex")
        ck("bad memo hex raises", False)
    except JSONRPCException as e:
        ck("bad memo hex -> code -8", e.code == -8, e.code)
    try:
        # A non-boolean verbose (position 10) is a -3 type error.
        rpc.call("sendtoaddress", addr, "0.1", "", "", None, None, None, None,
                 None, None, "not-a-bool")
        ck("non-boolean verbose raises", False)
    except JSONRPCException as e:
        ck("non-boolean verbose -> code -3", e.code == -3, e.code)
    try:
        # settxfee gets the explicit ZIP-317 -8, like every other fee instruction.
        rpc.call("settxfee", 0.0001)
        ck("settxfee raises", False)
    except JSONRPCException as e:
        ck("settxfee -> code -8", e.code == -8, e.code)
    # lastblock is always a 64-hex-char cursor, even at absurd depths.
    lsb = rpc.call("listsinceblock")
    ck("lastblock is 64 hex chars", len(lsb["lastblock"]) == 64, lsb["lastblock"])
    lsb = rpc.call("listsinceblock", "", 99999999)
    ck("deep target lastblock still 64 chars", len(lsb["lastblock"]) == 64, lsb["lastblock"])
    try:
        # fee_rate (param 9): an explicit fee instruction; fees are ZIP-317 and never settable.
        rpc.call("sendtoaddress", addr, "0.1", "", "", False, False, None, "", False, 25)
        ck("sendtoaddress fee_rate raises", False)
    except JSONRPCException as e:
        ck("sendtoaddress fee_rate -> code -8", e.code == -8, e.code)
    try:
        rpc.call("sendmany", "", {addr: "0.1"}, 1, "", [], False, None, "", 25)
        ck("sendmany fee_rate raises", False)
    except JSONRPCException as e:
        ck("sendmany fee_rate -> code -8", e.code == -8, e.code)
    # Arity: like Bitcoin Core, a call with more positional arguments than the method accepts is
    # rejected (-1, the help error) rather than silently ignoring the trailing junk. A no-arg
    # method with one extra arg, and a one-arg method with a second, both trip it.
    try:
        rpc.call("getblockcount", 1)
        ck("getblockcount extra arg raises", False)
    except JSONRPCException as e:
        ck("getblockcount extra arg -> code -1", e.code == -1, e.code)
    try:
        rpc.call("validateaddress", addr, "extra")
        ck("validateaddress extra arg raises", False)
    except JSONRPCException as e:
        ck("validateaddress extra arg -> code -1", e.code == -1, e.code)
    # z_sendmany is zcashd's async send: it returns an opid; the trio z_getoperationstatus /
    # z_getoperationresult / z_listoperationids track it. These checks all reject (or query
    # empty) *before* any send is spawned, so they move no money. addr is the wallet's own
    # address, so the fromaddress ownership check passes and later validation fires.
    try:
        # An explicit fee is ZIP-317 -8, like the synchronous sends.
        rpc.call("z_sendmany", addr, [{"address": addr, "amount": "0.1"}], 1, 0.0001)
        ck("z_sendmany fee raises", False)
    except JSONRPCException as e:
        ck("z_sendmany fee -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_sendmany", addr, [])
        ck("z_sendmany empty amounts raises", False)
    except JSONRPCException as e:
        ck("z_sendmany empty amounts -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_sendmany", addr, [{"address": addr, "amount": "0.1"}], 1, None, "Bogus")
        ck("z_sendmany unknown privacyPolicy raises", False)
    except JSONRPCException as e:
        ck("z_sendmany unknown privacyPolicy -> code -8", e.code == -8, e.code)
    try:
        # A repeated recipient is -8, as in zcashd. zecd can be configured to permit repeated
        # *shielded* recipients ([rpc] allow_duplicate_shielded_recipients, for protocols that
        # batch memo-carrying payments to one address); this daemon runs the default, so the
        # refusal must still stand - the opt-in must not have become the behaviour.
        rpc.call("z_sendmany", addr,
                 [{"address": addr, "amount": "0.1"}, {"address": addr, "amount": "0.2"}])
        ck("z_sendmany duplicate recipient raises", False)
    except JSONRPCException as e:
        ck("z_sendmany duplicate recipient -> code -8", e.code == -8, e.code)
        ck("z_sendmany duplicate recipient names the address",
           "duplicated recipient address" in str(e), str(e))
    try:
        # An unparseable fromaddress is -5 before any send logic.
        rpc.call("z_sendmany", "not-an-address", [{"address": addr, "amount": "0.1"}])
        ck("z_sendmany bad fromaddress raises", False)
    except JSONRPCException as e:
        ck("z_sendmany bad fromaddress -> code -5", e.code == -5, e.code)
    try:
        # A missing fromaddress is Bitcoin Core's help error (-1, via require_str), not the
        # framing-only -32602.
        rpc.call("z_sendmany")
        ck("z_sendmany no args raises", False)
    except JSONRPCException as e:
        ck("z_sendmany no args -> code -1", e.code == -1, e.code)
    try:
        # A transparent funding source (ANY_TADDR / a t-address fromaddress) requires the
        # AllowRevealedSenders rung; the daemon under test runs the default policy
        # (AllowRevealedRecipients), so this is a synchronous -4, zcashd's code for it.
        rpc.call("z_sendmany", "ANY_TADDR", [{"address": addr, "amount": "0.1"}])
        ck("z_sendmany ANY_TADDR default policy raises", False)
    except JSONRPCException as e:
        ck("z_sendmany ANY_TADDR default policy -> code -4", e.code == -4, e.code)
        ck("z_sendmany ANY_TADDR default policy names the gate",
           "Insufficient privacy policy" in str(e), str(e))
    try:
        # The privacy gate fires before recipient checks under FullPrivacy too.
        rpc.call("z_sendmany", "ANY_TADDR", [{"address": addr, "amount": "0.1"}],
                 1, None, "FullPrivacy")
        ck("z_sendmany ANY_TADDR FullPrivacy raises", False)
    except JSONRPCException as e:
        ck("z_sendmany ANY_TADDR FullPrivacy -> code -4", e.code == -4, e.code)
    # Under AllowRevealedSenders the gate passes and an operation is spawned; the amount is far
    # above any transparent balance the wallet under test could hold, so the operation fails
    # async with -6 (insufficient funds) - or -13 if the wallet happens to be locked - and no
    # money can move.
    opid = rpc.call("z_sendmany", "ANY_TADDR", [{"address": addr, "amount": "100.0"}],
                    1, None, "AllowRevealedSenders")
    ck("z_sendmany ANY_TADDR AllowRevealedSenders -> opid", opid.startswith("opid-"), opid)
    st = rpc.call("z_waitforoperation", opid, 60)
    ck("z_sendmany ANY_TADDR op finished", st.get("finished") is True, st)
    ck("z_sendmany ANY_TADDR op failed -6/-13 (no transparent funds)",
       st.get("status") == "failed"
       and st.get("error", {}).get("code") in (-6, -13), st)
    # A shielded fromaddress under AllowRevealedSenders spawns too (the policy name is a real
    # rung now, not collapsed onto AllowRevealedRecipients); same guaranteed async failure.
    opid = rpc.call("z_sendmany", addr, [{"address": addr, "amount": "100.0"}],
                    1, None, "AllowRevealedSenders")
    ck("z_sendmany shielded from AllowRevealedSenders -> opid", opid.startswith("opid-"), opid)
    st = rpc.call("z_waitforoperation", opid, 60)
    ck("z_sendmany shielded from AllowRevealedSenders op failed -6/-13",
       st.get("finished") is True
       and st.get("error", {}).get("code") in (-6, -13), st)
    try:
        rpc.call("z_sendmany", addr, "notarray")
        ck("z_sendmany non-array amounts raises", False)
    except JSONRPCException as e:
        ck("z_sendmany non-array amounts -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_sendmany", addr, ["notanobject"])
        ck("z_sendmany non-object entry raises", False)
    except JSONRPCException as e:
        ck("z_sendmany non-object entry -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_sendmany", addr, [{"address": addr, "amount": "0.1", "bogus": 1}])
        ck("z_sendmany unknown key raises", False)
    except JSONRPCException as e:
        ck("z_sendmany unknown key -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_sendmany", addr, [{"amount": "0.1"}])
        ck("z_sendmany missing address raises", False)
    except JSONRPCException as e:
        ck("z_sendmany missing address -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_sendmany", addr, [{"address": addr}])
        ck("z_sendmany missing amount raises", False)
    except JSONRPCException as e:
        ck("z_sendmany missing amount -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_sendmany", addr, [{"address": addr, "amount": "0.1", "memo": 123}])
        ck("z_sendmany non-string memo raises", False)
    except JSONRPCException as e:
        ck("z_sendmany non-string memo -> code -3", e.code == -3, e.code)
    try:
        rpc.call("z_sendmany", addr,
                 [{"address": addr, "amount": "0.1"}, {"address": addr, "amount": "0.2"}])
        ck("z_sendmany duplicate recipient raises", False)
    except JSONRPCException as e:
        ck("z_sendmany duplicate recipient -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_sendmany", addr, [{"address": addr, "amount": "0.1"}], "six")
        ck("z_sendmany non-integer minconf raises", False)
    except JSONRPCException as e:
        ck("z_sendmany non-integer minconf -> code -3", e.code == -3, e.code)
    # z_shieldcoinbase (zcashd's coinbase-sweeping async op). All of these reject before any
    # operation is spawned, so they move no money. The final well-formed call fails -6 ("Could
    # not find any coinbase funds to shield.") on a wallet holding no mature coinbase - or -13
    # if the wallet happens to be locked - never a success here.
    try:
        rpc.call("z_shieldcoinbase")
        ck("z_shieldcoinbase no args raises", False)
    except JSONRPCException as e:
        ck("z_shieldcoinbase no args -> code -1", e.code == -1, e.code)
    try:
        # fromaddress must be a taddr or "*"; a shielded/invalid one is -5 (zcashd's
        # RPC_INVALID_ADDRESS_OR_KEY).
        rpc.call("z_shieldcoinbase", addr, addr)
        ck("z_shieldcoinbase shielded fromaddress raises", False)
    except JSONRPCException as e:
        ck("z_shieldcoinbase shielded fromaddress -> code -5", e.code == -5, e.code)
    try:
        # toaddress that doesn't parse is zcashd's -8 "unknown address format".
        rpc.call("z_shieldcoinbase", "*", "not-an-address")
        ck("z_shieldcoinbase bad toaddress raises", False)
    except JSONRPCException as e:
        ck("z_shieldcoinbase bad toaddress -> code -8", e.code == -8, e.code)
    try:
        # An explicit fee is ZIP-317 -8, like every other send.
        rpc.call("z_shieldcoinbase", "*", addr, 0.0001)
        ck("z_shieldcoinbase fee raises", False)
    except JSONRPCException as e:
        ck("z_shieldcoinbase fee -> code -8", e.code == -8, e.code)
    try:
        # zcashd: "Limit on maximum number of utxos cannot be negative".
        rpc.call("z_shieldcoinbase", "*", addr, None, -1)
        ck("z_shieldcoinbase negative limit raises", False)
    except JSONRPCException as e:
        ck("z_shieldcoinbase negative limit -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_shieldcoinbase", "*", addr, None, None, None, "Bogus")
        ck("z_shieldcoinbase unknown privacyPolicy raises", False)
    except JSONRPCException as e:
        ck("z_shieldcoinbase unknown privacyPolicy -> code -8", e.code == -8, e.code)
    try:
        # Shielding coinbase reveals the source addresses, so FullPrivacy is contradictory.
        rpc.call("z_shieldcoinbase", "*", addr, None, None, None, "FullPrivacy")
        ck("z_shieldcoinbase FullPrivacy raises", False)
    except JSONRPCException as e:
        ck("z_shieldcoinbase FullPrivacy -> code -8", e.code == -8, e.code)
    try:
        # Well-formed, but this wallet holds no mature coinbase: -6 (or -13 while locked).
        rpc.call("z_shieldcoinbase", "*", addr)
        ck("z_shieldcoinbase without coinbase raises", False)
    except JSONRPCException as e:
        ck("z_shieldcoinbase without coinbase -> code -6/-13",
           e.code in (-6, -13), e.code)
    # z_mergetoaddress (zcashd's consolidation sweep, async). All of these reject before any
    # operation is spawned, so they move no money.
    try:
        # A missing fromaddresses is Bitcoin Core's help error (-1), like the other required
        # args; a present-but-non-array one is -8 (below).
        rpc.call("z_mergetoaddress")
        ck("z_mergetoaddress no args raises", False)
    except JSONRPCException as e:
        ck("z_mergetoaddress no args -> code -1", e.code == -1, e.code)
    try:
        rpc.call("z_mergetoaddress", "notarray", addr)
        ck("z_mergetoaddress non-array fromaddresses raises", False)
    except JSONRPCException as e:
        ck("z_mergetoaddress non-array fromaddresses -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_mergetoaddress", [], addr)
        ck("z_mergetoaddress empty fromaddresses raises", False)
    except JSONRPCException as e:
        ck("z_mergetoaddress empty fromaddresses -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_mergetoaddress", ["ANY_SPROUT"], addr)
        ck("z_mergetoaddress ANY_SPROUT raises", False)
    except JSONRPCException as e:
        ck("z_mergetoaddress ANY_SPROUT -> code -8", e.code == -8, e.code)
    try:
        # One source class per merge: transparent and shielded sources never mix.
        rpc.call("z_mergetoaddress", ["ANY_TADDR", "ANY_ORCHARD"], addr)
        ck("z_mergetoaddress mixed source classes raises", False)
    except JSONRPCException as e:
        ck("z_mergetoaddress mixed source classes -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_mergetoaddress", ["ANY_TADDR", "ANY_TADDR"], addr)
        ck("z_mergetoaddress duplicate entry raises", False)
    except JSONRPCException as e:
        ck("z_mergetoaddress duplicate entry -> code -8", e.code == -8, e.code)
    try:
        # A wildcard plus an explicit address of the same class is -8 (zcashd's rule); the own
        # shielded address alongside ANY_SAPLING trips it.
        rpc.call("z_mergetoaddress", ["ANY_SAPLING", addr], addr)
        ck("z_mergetoaddress wildcard+explicit raises", False)
    except JSONRPCException as e:
        ck("z_mergetoaddress wildcard+explicit -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_mergetoaddress", ["not-an-address"], addr)
        ck("z_mergetoaddress bad source address raises", False)
    except JSONRPCException as e:
        ck("z_mergetoaddress bad source address -> code -5", e.code == -5, e.code)
    try:
        rpc.call("z_mergetoaddress", [addr], "not-an-address")
        ck("z_mergetoaddress bad toaddress raises", False)
    except JSONRPCException as e:
        ck("z_mergetoaddress bad toaddress -> code -8", e.code == -8, e.code)
    try:
        # An explicit fee is ZIP-317 -8, like every send.
        rpc.call("z_mergetoaddress", [addr], addr, 0.0001)
        ck("z_mergetoaddress fee raises", False)
    except JSONRPCException as e:
        ck("z_mergetoaddress fee -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_mergetoaddress", [addr], addr, None, -1)
        ck("z_mergetoaddress negative transparent_limit raises", False)
    except JSONRPCException as e:
        ck("z_mergetoaddress negative transparent_limit -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_mergetoaddress", [addr], addr, None, None, "fifty")
        ck("z_mergetoaddress non-integer shielded_limit raises", False)
    except JSONRPCException as e:
        ck("z_mergetoaddress non-integer shielded_limit -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_mergetoaddress", [addr], addr, None, None, None, "not-hex")
        ck("z_mergetoaddress bad memo hex raises", False)
    except JSONRPCException as e:
        ck("z_mergetoaddress bad memo hex -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_mergetoaddress", [addr], addr, None, None, None, None, "Bogus")
        ck("z_mergetoaddress unknown privacyPolicy raises", False)
    except JSONRPCException as e:
        ck("z_mergetoaddress unknown privacyPolicy -> code -8", e.code == -8, e.code)
    try:
        # A transparent source needs the AllowRevealedSenders rung; the daemon under test runs
        # the default policy, so this is a synchronous -4 (same gate as z_sendmany's).
        rpc.call("z_mergetoaddress", ["ANY_TADDR"], addr)
        ck("z_mergetoaddress ANY_TADDR default policy raises", False)
    except JSONRPCException as e:
        ck("z_mergetoaddress ANY_TADDR default policy -> code -4", e.code == -4, e.code)
        ck("z_mergetoaddress ANY_TADDR default policy names the gate",
           "Insufficient privacy policy" in str(e), str(e))
    try:
        # A malformed opid is -8; a well-formed-but-unknown one is silently omitted (below).
        rpc.call("z_getoperationstatus", ["not-an-opid"])
        ck("z_getoperationstatus bad opid raises", False)
    except JSONRPCException as e:
        ck("z_getoperationstatus bad opid -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_getoperationstatus", "notarray")
        ck("z_getoperationstatus non-array raises", False)
    except JSONRPCException as e:
        ck("z_getoperationstatus non-array -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_getoperationstatus", [123])
        ck("z_getoperationstatus non-string opid raises", False)
    except JSONRPCException as e:
        ck("z_getoperationstatus non-string opid -> code -8", e.code == -8, e.code)
    ck("z_listoperationids returns a list", isinstance(rpc.call("z_listoperationids"), list))
    _unknown_opid = "opid-00000000-0000-0000-0000-000000000000"
    ck("z_getoperationstatus unknown opid omitted",
       rpc.call("z_getoperationstatus", [_unknown_opid]) == [])
    ck("z_getoperationresult unknown opid omitted",
       rpc.call("z_getoperationresult", [_unknown_opid]) == [])
    # z_waitforoperation is zecd's blocking alternative to the poll loop: it takes ONE opid (not
    # an array) plus an optional timeout in seconds. Unlike the tracking trio it rejects an
    # unknown opid rather than omitting it - there would be nothing to wait for, so blocking for
    # the full timeout would just hide a client bug. None of these checks ever blocks: they all
    # fail argument validation, or name an operation that does not exist.
    try:
        rpc.call("z_waitforoperation")
        ck("z_waitforoperation no args raises", False)
    except JSONRPCException as e:
        ck("z_waitforoperation no args -> code -1", e.code == -1, e.code)
    try:
        rpc.call("z_waitforoperation", "not-an-opid")
        ck("z_waitforoperation bad opid raises", False)
    except JSONRPCException as e:
        ck("z_waitforoperation bad opid -> code -8", e.code == -8, e.code)
    try:
        # It takes a bare opid, not the trio's array - a present-but-non-string arg is Core's -3.
        rpc.call("z_waitforoperation", [_unknown_opid])
        ck("z_waitforoperation array opid raises", False)
    except JSONRPCException as e:
        ck("z_waitforoperation array opid -> code -3", e.code == -3, e.code)
    try:
        rpc.call("z_waitforoperation", _unknown_opid)
        ck("z_waitforoperation unknown opid raises", False)
    except JSONRPCException as e:
        ck("z_waitforoperation unknown opid -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_waitforoperation", _unknown_opid, -1)
        ck("z_waitforoperation negative timeout raises", False)
    except JSONRPCException as e:
        ck("z_waitforoperation negative timeout -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_waitforoperation", _unknown_opid, "soon")
        ck("z_waitforoperation non-integer timeout raises", False)
    except JSONRPCException as e:
        ck("z_waitforoperation non-integer timeout -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_waitforoperation", _unknown_opid, 0, "extra")
        ck("z_waitforoperation extra arg raises", False)
    except JSONRPCException as e:
        ck("z_waitforoperation extra arg -> code -1", e.code == -1, e.code)
    try:
        rpc.call("getrawtransaction", "00" * 32)
        ck("getrawtransaction unknown raises", False)
    except JSONRPCException as e:
        ck("getrawtransaction unknown -> code -5", e.code == -5, e.code)
    try:
        rpc.call("getrawtransaction", "not-a-txid")
        ck("getrawtransaction bad txid raises", False)
    except JSONRPCException as e:
        ck("getrawtransaction bad txid -> code -8", e.code == -8, e.code)
    try:
        rpc.call("sendrawtransaction", "00ff")
        ck("sendrawtransaction undecodable raises", False)
    except JSONRPCException as e:
        ck("sendrawtransaction undecodable -> code -22", e.code == -22, e.code)
    try:
        AuthServiceProxy(args.url, args.user, "wrong-password").call("getblockcount")
        ck("bad auth raises", False)
    except JSONRPCException as e:
        ck("bad auth -> 401", e.code == 401, e.code)


def s_errors_bitcoin(ctx):
    """The Bitcoin engine's error contract. Every send below is rejected while its arguments
    are parsed - before coin selection, signing, or broadcast - so nothing can move."""
    rpc, ck, addr, args = ctx.rpc, ctx.ck, ctx.addr, ctx.args
    try:
        rpc.call("gettransaction", "00" * 32)
        ck("gettransaction unknown raises", False)
    except JSONRPCException as e:
        ck("gettransaction unknown -> code -5", e.code == -5, e.code)
    try:
        # A malformed txid is Core's ParseHashV -8, distinct from an unknown one.
        rpc.call("gettransaction", "zz")
        ck("gettransaction malformed raises", False)
    except JSONRPCException as e:
        ck("gettransaction malformed -> code -8", e.code == -8, e.code)
    try:
        rpc.call("sendtoaddress", addr, UNAFFORDABLE, "", "", False, None, None, None, None,
                 None, "yes")
        ck("sendtoaddress non-boolean verbose raises", False)
    except JSONRPCException as e:
        ck("sendtoaddress non-boolean verbose -> code -3", e.code == -3, e.code)
    try:
        rpc.call("no_such_method_xyz")
        ck("unknown method raises", False)
    except JSONRPCException as e:
        ck("unknown method -> code -32601", e.code == -32601, e.code)
    try:
        rpc.call("listtransactions", "*", -1)
        ck("negative count raises", False)
    except JSONRPCException as e:
        ck("negative count -> code -8", e.code == -8, e.code)
    try:
        rpc.call("listtransactions", "*", "ten")
        ck("non-numeric count raises", False)
    except JSONRPCException as e:
        ck("non-numeric count -> code -3", e.code == -3, e.code)
    try:
        rpc.call("listtransactions", "mylabel")
        ck("listtransactions label raises", False)
    except JSONRPCException as e:
        ck("listtransactions label -> code -8 (stateless)", e.code == -8, e.code)
    try:
        # Zero amounts are rejected before any send logic, like Bitcoin Core.
        rpc.call("sendtoaddress", addr, 0)
        ck("zero amount raises", False)
    except JSONRPCException as e:
        ck("zero amount -> code -3", e.code == -3, e.code)
    try:
        # A missing amount is Bitcoin Core's help error (-1).
        rpc.call("sendtoaddress", addr)
        ck("sendtoaddress no amount raises", False)
    except JSONRPCException as e:
        ck("sendtoaddress no amount -> code -1", e.code == -1, e.code)
    try:
        # An address that does not parse for this network is -5, before any send logic.
        rpc.call("sendtoaddress", "not-an-address", UNAFFORDABLE)
        ck("sendtoaddress bad address raises", False)
    except JSONRPCException as e:
        ck("sendtoaddress bad address -> code -5", e.code == -5, e.code)
    try:
        # fee_rate (param 9) below the 1 sat/vB relay floor is refused up front: no node would
        # relay it, and a light-client broadcast would still record it at 0-conf.
        rpc.call("sendtoaddress", addr, UNAFFORDABLE, "", "", False, False, None, "", False, 0.5)
        ck("sendtoaddress sub-floor fee_rate raises", False)
    except JSONRPCException as e:
        ck("sendtoaddress sub-floor fee_rate -> code -8", e.code == -8, e.code)
    try:
        # conf_target (param 6) cannot be honored: the wallet estimates at a fixed target.
        rpc.call("sendtoaddress", addr, UNAFFORDABLE, "", "", False, False, 3)
        ck("sendtoaddress conf_target raises", False)
    except JSONRPCException as e:
        ck("sendtoaddress conf_target -> code -8", e.code == -8, e.code)
    try:
        rpc.call("sendtoaddress", addr, UNAFFORDABLE, "", "", "yes")
        ck("sendtoaddress non-boolean subtractfeefromamount raises", False)
    except JSONRPCException as e:
        ck("sendtoaddress non-boolean subtractfeefromamount -> code -3", e.code == -3, e.code)
    try:
        rpc.call("sendmany", "", {addr: 0})
        ck("sendmany zero amount raises", False)
    except JSONRPCException as e:
        ck("sendmany zero amount -> code -3", e.code == -3, e.code)
    try:
        rpc.call("sendmany", "", {"not-an-address": UNAFFORDABLE})
        ck("sendmany bad address raises", False)
    except JSONRPCException as e:
        ck("sendmany bad address -> code -5", e.code == -5, e.code)
    try:
        rpc.call("sendrawtransaction", "00ff")
        ck("sendrawtransaction undecodable raises", False)
    except JSONRPCException as e:
        ck("sendrawtransaction undecodable -> code -22", e.code == -22, e.code)
    # Everything the engine does not serve is method-not-found, whatever the dialect: Zcash's
    # block lookups and fee stubs, the passphrase pair, and the z_* extensions alike.
    for m, params in (
        ("getblockhash", [0]),
        ("settxfee", [0.0001]),
        ("walletpassphrase", ["x", 60]),
        ("walletlock", []),
        ("getrawtransaction", ["00" * 32]),
        ("z_sendmany", [addr, []]),
        ("z_getaddressforaccount", [0]),
    ):
        try:
            rpc.call(m, *params)
            ck(f"{m} raises on a Bitcoin wallet", False)
        except JSONRPCException as e:
            ck(f"{m} -> method not found (-32601) on a Bitcoin wallet", e.code == -32601, e.code)
    # Arity: like Bitcoin Core, a call with more positional arguments than the method accepts is
    # rejected (-1, the help error) rather than silently ignoring the trailing junk.
    try:
        rpc.call("getblockcount", 1)
        ck("getblockcount extra arg raises", False)
    except JSONRPCException as e:
        ck("getblockcount extra arg -> code -1", e.code == -1, e.code)
    try:
        rpc.call("validateaddress", addr, "extra")
        ck("validateaddress extra arg raises", False)
    except JSONRPCException as e:
        ck("validateaddress extra arg -> code -1", e.code == -1, e.code)
    try:
        rpc.call("listdescriptors", False, "extra")
        ck("listdescriptors extra arg raises", False)
    except JSONRPCException as e:
        ck("listdescriptors extra arg -> code -1", e.code == -1, e.code)
    if ctx.coin == BITCOIN:
        try:
            rpc.call("abandontransaction", "00" * 32, "extra")
            ck("abandontransaction extra arg raises", False)
        except JSONRPCException as e:
            ck("abandontransaction extra arg -> code -1", e.code == -1, e.code)
        # replaceable (param 5) is honored, so a non-boolean is a type error (-3) rather than
        # being ignored - refused at argument parsing, so this moves no funds.
        try:
            rpc.call("sendtoaddress", addr, UNAFFORDABLE, "", "", False, "no")
            ck("sendtoaddress non-boolean replaceable raises", False)
        except JSONRPCException as e:
            ck("sendtoaddress non-boolean replaceable -> code -3", e.code == -3, e.code)
        try:
            rpc.call("sendmany", "", {addr: UNAFFORDABLE}, 1, "", None, "no")
            ck("sendmany non-boolean replaceable raises", False)
        except JSONRPCException as e:
            ck("sendmany non-boolean replaceable -> code -3", e.code == -3, e.code)
    try:
        AuthServiceProxy(args.url, args.user, "wrong-password").call("getblockcount")
        ck("bad auth raises", False)
    except JSONRPCException as e:
        ck("bad auth -> 401", e.code == 401, e.code)


@section("wallet encryption state", ZCASH)
def s_encryption(ctx):
    rpc, ck, addr, args, wi = ctx.rpc, ctx.ck, ctx.addr, ctx.args, ctx.wi
    # Adapts to the wallet under test: an encrypted wallet reports unlocked_until and verifies
    # passphrases (-14 on a wrong one); an unencrypted wallet rejects the passphrase RPCs with
    # -15, exactly like running bitcoind with an unencrypted wallet.
    if "unlocked_until" in wi:
        ck("unlocked_until is an int when encrypted", isinstance(wi["unlocked_until"], int))
        try:
            rpc.call("walletpassphrase", "definitely-not-the-passphrase", 60)
            ck("wrong passphrase raises", False)
        except JSONRPCException as e:
            ck("wrong passphrase -> -14", e.code == -14, e.code)
        if args.passphrase:
            # The lock/unlock state machine with the real passphrase: unlock (unlocked_until
            # advances), lock (send -> -13), re-unlock. The wallet ends as found: unlocked.
            ck("passphrase unlocks",
               rpc.call("walletpassphrase", args.passphrase, 600) is None)
            ck("unlocked_until > 0 while unlocked",
               rpc.call("getwalletinfo")["unlocked_until"] > 0)
            ck("walletlock returns null", rpc.call("walletlock") is None)
            ck("locked wallet reports unlocked_until 0",
               rpc.call("getwalletinfo")["unlocked_until"] == 0)
            try:
                # The lock check precedes input selection, so no funds are needed.
                rpc.call("sendtoaddress", addr, "0.01")
                ck("locked wallet refuses to send", False)
            except JSONRPCException as e:
                ck("locked send -> -13", e.code == -13, e.code)
            ck("re-unlocked after the lock round-trip",
               rpc.call("walletpassphrase", args.passphrase, 600) is None)
    else:
        ck("getwalletinfo omits unlocked_until when unencrypted", "unlocked_until" not in wi)
        try:
            rpc.call("walletpassphrase", "anything", 60)
            ck("walletpassphrase on unencrypted raises", False)
        except JSONRPCException as e:
            ck("walletpassphrase unencrypted -> -15", e.code == -15, e.code)
        try:
            rpc.call("walletlock")
            ck("walletlock on unencrypted raises", False)
        except JSONRPCException as e:
            ck("walletlock unencrypted -> -15", e.code == -15, e.code)
    # Argument validation happens before the encryption-state check: a negative timeout is -8
    # in both wallet states.
    try:
        rpc.call("walletpassphrase", "anything", -1)
        ck("negative timeout raises", False)
    except JSONRPCException as e:
        ck("walletpassphrase negative timeout -> -8", e.code == -8, e.code)


@section("batch", *BOTH)
def s_batch(ctx):
    rpc, ck = ctx.rpc, ctx.ck
    out = rpc.batch([("getblockcount", []), ("no_such", [])])
    ck("batch returns array", isinstance(out, list) and len(out) == 2)
    ck("batch[0] ok, [1] error", out[0]["error"] is None and out[1]["error"]["code"] == -32601)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--coin", choices=(ZCASH, BITCOIN), default=ZCASH,
                    help="the engine the wallet under test runs on (selects the sections)")
    ap.add_argument("--url", default="http://127.0.0.1:18232/")
    ap.add_argument("--user", default="u")
    ap.add_argument("--password", default="p")
    ap.add_argument("--passphrase", default="",
                    help="wallet passphrase (enables the encrypted-wallet state-machine checks)")
    args = ap.parse_args()
    rpc = AuthServiceProxy(args.url, args.user, args.password)

    passed = failed = 0

    def ck(name, cond, detail=""):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"  PASS {name} {detail}")
        else:
            failed += 1
            print(f"  FAIL {name} {detail}")

    if args.coin == BITCOIN:
        # The third guard: never run the send checks against real money. Every one is
        # refused at argument parsing and names an unaffordable amount, but a mainnet wallet
        # is not the place to find out that one no longer is.
        chain = rpc.call("getblockchaininfo").get("chain")
        if chain == "main":
            print("refusing to run the Bitcoin conformance checks against a mainnet wallet "
                  f"({args.url}); point --url at a test network")
            return 2

    ctx = Ctx(rpc, ck, args)
    for title, coins, run in SECTIONS:
        if args.coin in coins:
            print(f"== {title} ==")
            run(ctx)

    print(f"\nCONFORMANCE ({args.coin}): {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
