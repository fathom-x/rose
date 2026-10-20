#!/usr/bin/env python3
"""Mine blocks on Bitcoin testnet4 (or regtest) through a local bitcoind.

Testnet keeps Bitcoin's 20-minute exception: a block whose timestamp is more
than 20 minutes past its parent's may be mined at difficulty 1 (~2^32 hashes,
CPU territory) instead of the chain's real difficulty. This miner exploits it
the way testnet4's other miners do: it takes getblocktemplate, sets the header
time to parent + 20m01s, drops nBits to the minimum, and grinds nonces across
every core. On regtest the template is mined as-is (its target is trivial), so
the same script drives a regtest dev stack and doubles as the e2e test of the
block construction.

A header's timestamp may sit at most 2 hours past a node's clock, and testnet4
miners routinely future-date their blocks to push the next min-difficulty
window out; the miner computes the earliest legal moment, waits for it with a
countdown, and re-templates whenever the tip moves. A solution pre-ground for that
moment would otherwise freeze the tx set ~20 minutes early, so during the hold the
miner keeps re-grinding whenever the mempool moves, submitting the freshest solution
in hand at window open (the pre-ground one is the fallback, so the race is never lost
to freshness).

Stdlib only. Defaults target the deploy/docker-compose.btc-testnet4.yml node.

By default it runs as a live "good testnet citizen" service (the deployed shape): it
polls the local rose for unconfirmed wallet transactions and mines ONE
mempool-inclusive block whenever one is actually waiting - so it confirms your sends
(and everyone else's pending txs, at no extra cost) without grinding when there is
nothing to do. It asks rose rather than deriving addresses from an xpub because rose
already tracks its own txs and issues new addresses over time; a static xpub would
drift.

    ROSE_RPC_PASSWORD=... python3 scripts/btc-miner.py

--no-watch-mempool is the one-shot mode: mine --blocks N blocks on the current tip
and exit, no rose needed when --address is given. That is what drives a regtest dev
stack and doubles as the e2e test of the block construction.

    python3 scripts/btc-miner.py --no-watch-mempool --address tb1q... --watch <txid>
    python3 scripts/btc-miner.py --no-watch-mempool --url http://127.0.0.1:18443 --address bcrt1q... --blocks 101
    python3 scripts/btc-miner.py --bench

Add --blocks N to mine pending wallet txs to N confirmations instead of one: a lone
block at a contested height is orphaned whenever a competing min-diff miner's block
propagates better, so depth - each successive block pre-ground during the previous
20-minute wait - is what makes a confirmation stick. Depth counts the node's active
chain, so confirmations mined by anyone stand the miner down.

Omit --address and it fetches a fresh payout address from rose (getnewaddress) at
startup - so a service unit needs no address pinned in it; pass --address to pin one.

When a competing block shows up at our height (a same-height tie the node resolves
by first-seen), the miner adopts that block's transactions: it reads them off the
node and resubmits each to our own mempool, so whatever the rival miner confirmed
that we never saw rides into our next block too. Anything already known, conflicting
with our chain, or coinbase-derived is skipped by the node itself. --no-adopt-fork-txs
turns it off.
"""

import argparse
import base64
import hashlib
import json
import multiprocessing as mp
import os
import struct
import sys
import time
import urllib.error
import urllib.request

TTY = sys.stdout.isatty()
_inplace_dirty = False


def log(msg, inplace=False):
    """Print a timestamped line. On a terminal an inplace line rewrites in place with
    \\r; piped to a log file (the deployed case) it becomes an ordinary flushed line so
    nothing is swallowed by stdout buffering. A normal line after an inplace one first
    closes the pending \\r line, so the two never run together on screen."""
    global _inplace_dirty
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    if inplace and TTY:
        print(line, end="\r", flush=True)
        _inplace_dirty = True
    else:
        if _inplace_dirty:
            print(flush=True)
            _inplace_dirty = False
        print(line, flush=True)


MIN_DIFF_BITS = "1d00ffff"  # testnet3/testnet4 powLimit, difficulty 1
MAX_FUTURE_SECS = 2 * 60 * 60  # consensus: header time <= adjusted time + 2h
FUTURE_MARGIN_SECS = 60  # stay this far under the cap (peer clocks differ)
HOLD_REFRESH_MIN_SECS = 90  # re-grind a moved mempool only while this much hold remains
NONCE_SPACE = 1 << 32


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


class Rpc:
    def __init__(self, url, user, password):
        self.url = url
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.auth = f"Basic {token}"
        self.n = 0

    def __call__(self, method, params=None):
        self.n += 1
        body = json.dumps(
            {"jsonrpc": "1.0", "id": self.n, "method": method, "params": params or []}
        ).encode()
        req = urllib.request.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json", "Authorization": self.auth},
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                r = json.load(resp)
        except urllib.error.HTTPError as e:
            r = json.load(e)
        if r.get("error"):
            raise RuntimeError(f"{method}: {r['error']['message']} ({r['error']['code']})")
        return r["result"]


def varint(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def push(data):
    assert len(data) <= 75
    return bytes([len(data)]) + data


def script_num(n):
    # Minimal CScriptNum encoding.
    out = bytearray()
    while n:
        out.append(n & 0xFF)
        n >>= 8
    if out and out[-1] & 0x80:
        out.append(0)
    return bytes(out)


def bip34_height(n):
    """The BIP34 coinbase-height prefix, encoded as Bitcoin Core's `CScript() << n`
    (which is what the consensus check reconstructs and byte-compares against). For
    1..16 that is a single opcode OP_1..OP_16, for 0 it is OP_0, and otherwise a data
    push of the minimal CScriptNum. Getting 1..16 wrong is `bad-cb-height` - it only
    bites a fresh regtest chain, since testnet/mainnet are long past height 16."""
    if 1 <= n <= 16:
        return bytes([0x50 + n])  # OP_1 .. OP_16
    if n == 0:
        return b"\x00"  # OP_0
    return push(script_num(n))


def build_coinbase(height, value_sats, payout_script, extranonce, commitment_script, tag=b""):
    """Return (txid_bytes_le, block_serialization) for the coinbase. `tag` is an
    optional identifying byte string appended to the scriptSig after the BIP34
    height and extranonce - the conventional miner-signature slot, readable in any
    explorer's coinbase view."""
    script_sig = bip34_height(height) + push(extranonce)
    if tag:
        script_sig += push(tag)
    assert len(script_sig) <= 100, "coinbase scriptSig over the 100-byte consensus limit"
    tx_in = b"\x00" * 32 + b"\xff" * 4 + varint(len(script_sig)) + script_sig + b"\xff" * 4
    outs = struct.pack("<Q", value_sats) + varint(len(payout_script)) + payout_script
    n_outs = 1
    if commitment_script:
        outs += struct.pack("<Q", 0) + varint(len(commitment_script)) + commitment_script
        n_outs += 1
    core = b"\x02\x00\x00\x00"  # version 2
    body = varint(1) + tx_in + varint(n_outs) + outs
    locktime = b"\x00" * 4
    no_witness = core + body + locktime
    if commitment_script:
        # Witness form for the block: marker+flag, one witness item - the 32-byte
        # reserved value the default_witness_commitment was computed over.
        witness = varint(1) + varint(32) + b"\x00" * 32
        full = core + b"\x00\x01" + body + witness + locktime
    else:
        full = no_witness
    return sha256d(no_witness), full


def merkle_root(hashes):
    layer = list(hashes)
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [sha256d(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def bits_to_target(bits_hex):
    exp = int(bits_hex[:2], 16)
    mantissa = int(bits_hex[2:], 16)
    return mantissa << (8 * (exp - 3))


def grind(first64, tail12, target, start, stride, found, progress, stop):
    """Worker: grind nonces start, start+stride, ... over one header.

    The first 64 header bytes are constant across nonces, so each try reuses
    a midstate copy: one 16-byte update + finalize + one 32-byte hash.
    """
    base = hashlib.sha256(first64)
    sha = hashlib.sha256
    zbytes = (256 - target.bit_length()) // 8
    ztail = b"\x00" * zbytes
    n = start
    count = 0
    while n < NONCE_SPACE:
        h = base.copy()
        h.update(tail12 + n.to_bytes(4, "little"))
        d = sha(h.digest()).digest()
        if (not zbytes or d[-zbytes:] == ztail) and int.from_bytes(d, "little") < target:
            found.put(n)
            return
        n += stride
        count += 1
        if not count & 0xFFFFF:  # every ~1M tries
            with progress.get_lock():
                progress.value += 0x100000
            if stop.is_set():
                return
    found.put(-1)  # nonce space exhausted for this stride


def bench(seconds=3.0):
    first64 = os.urandom(64)
    tail12 = os.urandom(12)
    base = hashlib.sha256(first64)
    sha = hashlib.sha256
    n = 0
    t0 = time.time()
    while time.time() - t0 < seconds:
        for _ in range(100_000):
            h = base.copy()
            h.update(tail12 + n.to_bytes(4, "little"))
            sha(h.digest()).digest()
            n += 1
    rate = n / (time.time() - t0)
    cores = os.cpu_count() or 1
    total = rate * cores
    print(f"single-core: {rate/1e6:.2f} MH/s; x{cores} cores ~ {total/1e6:.2f} MH/s")
    print(f"difficulty-1 block (2^32 expected hashes): ~{NONCE_SPACE/total/60:.1f} min expected")


# Blocks this process has had accepted, as (height, hash). Consulted on a reorg to
# report whether one of our own blocks was the casualty.
MINED_BLOCKS = []

# Last contested-fork state we warned about, so the check is quiet until it changes.
_LAST_FORK_STATE = None

# getchaintips statuses for a non-active tip the node could still adopt (a
# competing chain): fully validated, headers valid but blocks not fully validated,
# or headers only. "invalid" (rejected) is excluded.
CONTENDING_TIP_STATUSES = {"valid-fork", "valid-headers", "headers-only"}

# Statuses whose block data the node holds on disk, so getblock can read the txs.
# "headers-only" has none (and btc_p2p_push only pushes blocks, it cannot fetch one).
FORK_TX_READABLE_STATUSES = {"valid-fork", "valid-headers"}

# Competing blocks whose transactions have already been resubmitted to our mempool.
_ADOPTED_FORK_BLOCKS = set()


def adopt_fork_txs(rpc, competitors):
    """Feed a competing chain's transactions into our own mempool so they ride into
    the next block we mine on OUR chain. The node does the real work: each tx is
    resubmitted with sendrawtransaction, which accepts whatever is valid against our
    chain (and getblocktemplate then includes it) and rejects the rest - the rival's
    coinbase and anything spending it, double-spends of inputs our block already
    spent, non-standard txs. Txs already in our mempool or our chain are skipped as
    already known. Only the gain is real: txs the rival miner saw that never reached
    us by relay. Each competing block is harvested once."""
    try:
        in_mempool = set(rpc("getrawmempool"))
    except Exception as e:
        log(f"  adopt-fork-txs: getrawmempool failed ({e}); skipping")
        return
    for t in competitors:
        if t["status"] not in FORK_TX_READABLE_STATUSES:
            continue
        # Walk the fork from its tip down to the first block on our active chain,
        # bounded by the reported branch length.
        h = t["hash"]
        for _ in range(max(1, t.get("branchlen", 1))):
            if h in _ADOPTED_FORK_BLOCKS:
                break
            try:
                hdr = rpc("getblockheader", [h])
                if hdr.get("confirmations", -1) >= 0:
                    break  # reached our chain: the fork point
                block = rpc("getblock", [h, 2])
            except Exception as e:
                log(f"  adopt-fork-txs: cannot read competing block {h[:16]}... ({e})")
                break
            _ADOPTED_FORK_BLOCKS.add(h)
            txs = block["tx"][1:]  # skip the rival coinbase
            adopted = known = 0
            rejected = []
            for tx in txs:
                if tx["txid"] in in_mempool:
                    known += 1
                    continue
                try:
                    # maxfeerate 0: no fee-rate cap - the fee is the sender's, and the
                    # rival already confirmed it, so refusing it only orphans them.
                    rpc("sendrawtransaction", [tx["hex"], 0])
                    adopted += 1
                    in_mempool.add(tx["txid"])
                except RuntimeError as e:
                    if "(-27)" in str(e):  # already in mempool / already in our chain
                        known += 1
                    else:
                        rejected.append((tx["txid"], str(e)))
                except OSError as e:
                    log(f"  adopt-fork-txs: bitcoind unreachable ({e}); stopping")
                    return
            log(
                f"  adopt-fork-txs: competing block h={block['height']} {h[:16]}... "
                f"({len(txs)} txs): adopted {adopted}, already known {known}, "
                f"rejected {len(rejected)}"
            )
            for txid, why in rejected[:5]:
                log(f"    rejected {txid[:16]}...: {why}")
            if len(rejected) > 5:
                log(f"    ... and {len(rejected) - 5} more")
            h = hdr.get("previousblockhash")
            if not h:
                break


def check_fork_contention(rpc, adopt=False):
    """Warn if our node holds a minority fork - a competing chain exists at or above
    our tip height that the node has not switched to. This is the case the reorg
    detector cannot see: at equal height/work the node keeps its own (first-seen)
    tip, so a block we mined can be orphaned from the NETWORK's view while our node
    still reports it confirmed and we keep mining a doomed private continuation on it.
    A longer competitor will eventually trigger a real reorg (caught by
    note_tip_change); this surfaces the contention before that. Deduplicated: it logs
    only when the contested state changes, so a steady fork does not flood the log.
    With adopt=True the competitors' transactions are also resubmitted to our mempool
    (adopt_fork_txs), so they ride into our next block."""
    global _LAST_FORK_STATE
    try:
        tips = rpc("getchaintips")
    except Exception:
        return
    active = next((t for t in tips if t["status"] == "active"), None)
    if active is None:
        return
    # Only tips that could actually contest ours: an "invalid" tip is one the node
    # has rejected outright, and it will never switch to it, so it is not contention.
    competitors = [
        t
        for t in tips
        if t["status"] in CONTENDING_TIP_STATUSES and t["height"] >= active["height"]
    ]
    state = (active["hash"], frozenset(t["hash"] for t in competitors))
    if state == _LAST_FORK_STATE:
        return  # unchanged since the last warning (or last all-clear)
    _LAST_FORK_STATE = state
    if not competitors:
        return  # no contention at the tip; nothing to say
    ours = any(h == active["hash"] for _, h in MINED_BLOCKS)
    log(
        f"CONTESTED TIP: height {active['height']} ({active['hash'][:16]}...) is one of "
        f"{len(competitors) + 1} chains at this height; your node holds its own by "
        f"first-seen"
        + (" and that tip is a block WE mined" if ours else "")
    )
    for t in competitors:
        log(f"  competing: h={t['height']} {t['hash'][:16]}... {t['status']} branchlen={t['branchlen']}")
    log("  a longer competitor will reorg us here; until then the network may be ignoring our chain")
    if adopt:
        adopt_fork_txs(rpc, competitors)


def note_tip_change(rpc, prev, where):
    """Log a tip change, distinguishing a normal extension (someone mined the next
    block on the chain we were building on) from a reorg (a competing chain replaced
    blocks at or below our height - which is what orphans a block we just mined). On a
    reorg it names the depth and flags any of our own blocks that were orphaned."""
    try:
        old = rpc("getblockheader", [prev])
        new_tip_hash = rpc("getbestblockhash")
        new_tip = rpc("getblockheader", [new_tip_hash])
    except Exception:
        log(f"tip moved ({where}); abandoning")
        return
    if old.get("confirmations", -1) >= 0:
        # The block we were building on is still on the active chain: a plain advance.
        log(f"tip advanced to {new_tip['height']} ({new_tip_hash[:16]}...); re-templating ({where})")
        return
    # Our parent was orphaned: a reorg. Report it and flag any of our own lost blocks.
    log(
        f"REORG ({where}): the block we were building on (height {old['height']}, "
        f"{prev[:16]}...) was orphaned; new tip is {new_tip['height']} ({new_tip_hash[:16]}...)"
    )
    for height, h in MINED_BLOCKS:
        try:
            if rpc("getblockheader", [h]).get("confirmations", 0) < 0:
                log(f"  !! OUR block at height {height} ({h[:16]}...) was ORPHANED by this reorg")
        except Exception:
            pass


def mine_one(rpc, args, chain, work_check=None, our_txids=()):
    """Mine one block on the current tip. Returns True on accept, False on a
    submitblock reject, or None if it stood down because work_check() went false
    (the watched tx confirmed elsewhere) at a re-template point. work_check is
    None outside watch-mempool mode, so mine_one then persists until it mines.
    our_txids are the transactions we are mining FOR (the pending wallet txs, or the
    --watch list); a block that loses a same-height race is pushed to peers only if
    the winner fails to carry one of them."""
    while True:
        if work_check is not None and not work_check():
            log("pending work cleared (confirmed elsewhere) - standing down")
            return None
        tmpl = rpc("getblocktemplate", [{"rules": ["segwit"]}])
        prev = tmpl["previousblockhash"]
        bits = tmpl["bits"]
        target = bits_to_target(bits)
        ntime = tmpl["curtime"]
        min_target = bits_to_target(MIN_DIFF_BITS)

        if chain in ("test", "testnet4") and target < min_target:
            # Real testnet difficulty is out of CPU reach; take the 20-minute
            # exception. ntime is fixed here (parent + 20m01s), so the whole header
            # is determined during the wait - which is what lets us pre-grind.
            prev_time = rpc("getblockheader", [prev])["time"]
            ntime = max(prev_time + 20 * 60 + 1, tmpl["mintime"])
            bits = MIN_DIFF_BITS
            target = min_target

        # Earliest real time at which a block stamped `ntime` clears the 2h future
        # cap (with the safety margin). For an open window / regtest this is already
        # in the past, so there is no hold.
        submit_time = ntime - MAX_FUTURE_SECS + args.future_margin

        payout = rpc("validateaddress", [args.address])
        if not payout.get("isvalid"):
            sys.exit(f"invalid address for this chain: {args.address}")
        for w in args.watch:
            mark = "included" if w in {t["txid"] for t in tmpl["transactions"]} else "NOT in template"
            log(f"watch {w[:16]}...: {mark}")

        result = mine_template(
            rpc, args, prev, ntime, bits, target, submit_time, tmpl, payout, our_txids
        )
        if result in ("tipmoved", "racelost"):
            continue  # re-template on the new tip (work_check re-runs at the top)
        return result  # True (accepted) or False (rejected)


def mine_template(rpc, args, prev, ntime, bits, target, submit_time, tmpl, payout, our_txids=()):
    """Grind a solution for one fixed (prev, ntime) header, then submit it - holding
    it back until `submit_time` if the min-diff window has not opened yet, which is
    what pre-grinds the block during the wait so it broadcasts the instant the window
    opens. The mempool keeps moving during a hold, so while one is in hand the hold
    re-templates and re-grinds whenever the tx set changes (same prev/ntime/bits -
    only the merkle side of the header differs), keeping the earlier solution as the
    fallback if a re-grind is unfinished at the window: freshness costs otherwise-idle
    CPU, never the race. Returns True/False from submitblock, "tipmoved" if the tip
    changed (during a grind or the hold), or "racelost" if the block was valid but a
    rival's block at the same height reached the node first; in both of the latter
    cases the caller should re-template.

    On a nonce-space sweep with no solution it re-rolls the coinbase extranonce for a
    fresh 2^32 search rather than bumping ntime, so `submit_time` stays put."""
    height = tmpl["height"]
    payout_script = bytes.fromhex(payout["scriptPubKey"])
    bits_le = bytes.fromhex(bits)[::-1]
    ntime_le = struct.pack("<I", ntime)
    tag = getattr(args, "coinbase_tag", "").encode()

    hold = submit_time - time.time()
    if hold > 0:
        log(
            f"height {height}: window opens in {hold/60:.1f} min; pre-grinding now "
            f"({len(tmpl['transactions'])} txs, {tmpl['coinbasevalue']/1e8:.8f} to {args.address})"
        )
    else:
        log(
            f"mining height {height}: {len(tmpl['transactions'])} txs, "
            f"{tmpl['coinbasevalue']/1e8:.8f} to {args.address}, bits {bits}"
        )

    ctx = mp.get_context("spawn")
    t0 = time.time()
    last_progress = 0.0

    def grind_template(t, deadline):
        """Sweep nonce spaces (fresh extranonce each) over template t's tx set until a
        solution, a tip move, or the deadline. Returns ("found", held) with held =
        (nonce, prefix, tail12, cb_ser, txs) - the tx list rides along so the block is
        assembled from the exact set ground into the merkle root - or
        ("tipmoved", None) / ("deadline", None)."""
        nonlocal last_progress
        txs = t["transactions"]
        reversed_txids = [bytes.fromhex(x["txid"])[::-1] for x in txs]
        commitment = t.get("default_witness_commitment")
        commit_bytes = bytes.fromhex(commitment) if commitment else None
        expected = (1 << 256) // target
        while True:
            t0_g = time.time()  # per sweep: the progress counter resets with each extranonce re-roll
            cb_txid, cb_ser = build_coinbase(
                height, t["coinbasevalue"], payout_script, os.urandom(8), commit_bytes, tag
            )
            root = merkle_root([cb_txid] + reversed_txids)
            prefix = struct.pack("<i", t["version"]) + bytes.fromhex(prev)[::-1] + root
            tail12 = prefix[64:] + ntime_le + bits_le
            found = ctx.Queue()
            progress = ctx.Value("Q", 0)
            stop = ctx.Event()
            workers = [
                ctx.Process(
                    target=grind,
                    args=(prefix[:64], tail12, target, i, args.jobs, found, progress, stop),
                    daemon=True,
                )
                for i in range(args.jobs)
            ]
            for w in workers:
                w.start()

            def stand_down():
                stop.set()
                for w in workers:
                    w.join(timeout=2)

            nonce = None
            exhausted = 0
            while nonce is None and exhausted < args.jobs:
                try:
                    got = found.get(timeout=2)
                    if got == -1:
                        exhausted += 1
                    else:
                        nonce = got
                except Exception:
                    pass
                el = time.time() - t0_g
                rate = progress.value / el if el > 0 else 0
                if rate and (TTY or time.time() - last_progress >= 30):
                    log(f"  {el:6.0f}s  {rate/1e6:6.2f} MH/s  ~{expected/rate/60:5.1f} min/block", inplace=True)
                    last_progress = time.time()
                if deadline is not None and time.time() >= deadline:
                    stand_down()
                    return ("deadline", None)
                if rpc("getbestblockhash") != prev:
                    stand_down()
                    note_tip_change(rpc, prev, "during grind")
                    return ("tipmoved", None)
            stand_down()
            if nonce is not None:
                return ("found", (nonce, prefix, tail12, cb_ser, txs))
            log("nonce space swept with no solution; re-rolling the coinbase")

    # --- grind the template we were handed
    status, held = grind_template(tmpl, None)
    if status == "tipmoved":
        return "tipmoved"

    # --- hold: solution in hand, wait out the future-time cap before broadcasting;
    # while enough hold remains, chase the moving mempool with replacement grinds
    if submit_time - time.time() > 0:
        log(f"solution found after {time.time()-t0:.0f}s; holding it until the window opens")
    last_hold = 0.0
    while time.time() < submit_time:
        if rpc("getbestblockhash") != prev:
            note_tip_change(rpc, prev, "while holding the solution")
            return "tipmoved"
        remaining = submit_time - time.time()
        if remaining > HOLD_REFRESH_MIN_SECS:
            fresh = rpc("getblocktemplate", [{"rules": ["segwit"]}])
            if fresh["previousblockhash"] != prev:
                note_tip_change(rpc, prev, "while holding the solution")
                return "tipmoved"
            if {x["txid"] for x in fresh["transactions"]} != {x["txid"] for x in held[4]}:
                log(
                    f"  mempool moved ({len(held[4])} -> {len(fresh['transactions'])} txs); "
                    f"re-grinding a fresh block (fallback stays in hand)"
                )
                status, refreshed = grind_template(fresh, submit_time - 2)
                if status == "tipmoved":
                    return "tipmoved"
                if status == "found":
                    held = refreshed
                    log(f"  refreshed solution in hand ({len(held[4])} txs)")
                continue
        if TTY or time.time() - last_hold >= 30:
            log(f"  holding; submitting in {remaining/60:.1f} min at window open", inplace=True)
            last_hold = time.time()
        time.sleep(min(15, max(0.2, submit_time - time.time())))

    # --- submit the instant the window is open
    nonce, prefix, tail12, cb_ser, txs = held
    header = tail12_header(prefix, tail12, nonce)
    block = header + varint(len(txs) + 1) + cb_ser + b"".join(bytes.fromhex(t["data"]) for t in txs)
    block_hex = block.hex()
    res = rpc("submitblock", [block_hex])
    bhash = sha256d(header)[::-1].hex()
    if res is None:
        log(f"block ACCEPTED at height {height}: {bhash}")
        MINED_BLOCKS.append((height, bhash))
        if getattr(args, "broadcast_peers", 0) > 0:
            broadcast_to_peers(rpc, args, block_hex)
        check_fork_contention(rpc, adopt=getattr(args, "adopt_fork_txs", False))
        return True
    if res == "inconclusive":
        # Core's answer when the block is valid and stored but was not connected:
        # the node already held a block at this height (a rival's, arriving in the
        # same instant) and keeps it by first-seen. Not a build problem.
        log(f"block VALID but lost the same-height race at {height}: {bhash}")
        handle_race_lost(rpc, args, height, txs, block_hex, our_txids)
        return "racelost"
    log(f"submitblock rejected: {res} (block {bhash})")
    return False


def handle_race_lost(rpc, args, height, txs, block_hex, our_txids):
    """Decide whether a race-lost block is worth contesting. The rival's block won
    first-seen on OUR node, but the race that matters is which chain reaches the
    real-difficulty miners first, and pushing ours directly to peers can still win
    that. We contest only when there is something to gain: one of the transactions we
    are mining for is in our block and NOT in the winner's. If the winner already
    confirms them, the rival did our job and fighting it would only fork the network
    for nothing."""
    ours_in_block = {t["txid"] for t in txs} & set(our_txids)
    if not ours_in_block:
        log("  none of our transactions are in it; not contesting the winner")
        return
    try:
        winner = rpc("getblock", [rpc("getblockhash", [height]), 1])
    except Exception as e:
        log(f"  cannot read the winning block at {height} ({e}); not contesting")
        return
    missing = ours_in_block - set(winner["tx"])
    if not missing:
        log(
            f"  the winning block {winner['hash'][:16]}... already confirms our "
            f"{len(ours_in_block)} tx(es); not contesting"
        )
        return
    log(
        f"  the winning block {winner['hash'][:16]}... lacks {len(missing)} of our tx(es): "
        + ", ".join(t[:16] + "..." for t in sorted(missing))
    )
    if getattr(args, "broadcast_peers", 0) > 0:
        log("  pushing our block to peers so the wider network can pick it instead")
        broadcast_to_peers(rpc, args, block_hex)
    else:
        log("  (--broadcast-peers is off; nothing more to do)")


def broadcast_to_peers(rpc, args, block_hex):
    """Fan the just-accepted block out to many peers directly over P2P, so it enters
    the network from more origins than the node's own handful of connections - the
    propagation half of winning a same-height tie. Best-effort and non-fatal: an
    import or network failure only forfeits the extra reach, never the mined block."""
    try:
        import btc_p2p_push
    except Exception as e:
        log(f"  p2p-push unavailable ({e}); relying on the node's own relay")
        return
    try:
        btc_p2p_push.broadcast_block(
            block_hex, rpc, network=args.network, count=args.broadcast_peers, log=log
        )
    except Exception as e:
        log(f"  p2p-push failed ({e}); the node's own relay still carries the block")


def tail12_header(prefix, tail12, nonce):
    # prefix = version+prev+merkle (68 bytes); tail12 = merkle[-4:]+time+bits.
    return prefix[:64] + tail12 + struct.pack("<I", nonce)


def pending_wallet_txids(node, rose, depth=1):
    """Txids the wallet needs a block mined for: ones it considers unconfirmed AND
    that the node still holds in its mempool. The mempool intersection is what makes
    this correct across the sync lag: once we mine, the txid leaves the node's mempool
    immediately, so we do not re-mine while rose is still catching up and reporting it
    at 0 confirmations. With depth > 1, txids confirmed shallower than depth count as
    work too, so the caller keeps extending its own chain until a competing
    same-height block can no longer orphan the confirmation away (confirmations are
    rose's view of the node's active chain, so depth reached by anyone's blocks -
    ours or a competitor's - stands the miner down)."""
    try:
        txs = rose("listtransactions", ["*", 100])
    except Exception as e:
        log(f"  rose unreachable ({e}); will retry")
        return set()
    unconfirmed = {t["txid"] for t in txs if t.get("confirmations", 0) == 0}
    shallow = {t["txid"] for t in txs if 0 < t.get("confirmations", 0) < depth}
    if unconfirmed:
        try:
            unconfirmed &= set(node("getrawmempool"))
        except OSError as e:
            log(f"  bitcoind unreachable ({e}); will retry")
            return set()
    return unconfirmed | shallow


def watch_mempool(node, rose, args, chain):
    log(
        f"watch-mempool: polling rose ({args.rose_url}) every {args.poll}s; mining "
        f"mempool-inclusive blocks when a wallet tx is waiting"
        + (f", to {args.blocks} confirmations" if args.blocks > 1 else "")
        + (f", at most one per {args.cadence}s" if args.cadence else "")
    )
    last_mined = 0.0
    while True:
        # Surface a minority-fork state that developed since we mined (a competing
        # block arrived after our accept). Deduplicated, so a steady fork is quiet.
        check_fork_contention(node, adopt=args.adopt_fork_txs)
        pending = pending_wallet_txids(node, rose, args.blocks)
        if not pending:
            time.sleep(args.poll)
            continue
        since = time.time() - last_mined
        if args.cadence and since < args.cadence:
            wait = args.cadence - since
            log(
                f"  {len(pending)} wallet tx(es) pending; cadence floor keeps the next "
                f"block {wait/60:.1f} min away"
            )
            time.sleep(min(args.poll, wait))
            continue
        log(f"  {len(pending)} wallet tx(es) pending:")
        for t in sorted(pending):
            log(f"    {t}")
        # Stand down cleanly if the tx confirms elsewhere while we wait on the window.
        try:
            r = mine_one(
                node,
                args,
                chain,
                work_check=lambda: bool(pending_wallet_txids(node, rose, args.blocks)),
                our_txids=pending,
            )
        except OSError as e:
            # A bitcoind restart (container recreate, upgrade) drops the RPC socket
            # mid-mine; that is an outage, not a build problem - keep the service alive.
            log(f"  bitcoind RPC failed mid-mine ({e}); retrying in {args.poll}s")
            time.sleep(args.poll)
            continue
        if r is True:
            last_mined = time.time()
            time.sleep(1)  # let rose see the new block before the next poll
        elif r is False:
            # A reject means a build problem; back off instead of hot-spinning on it.
            log(f"  backing off {args.poll}s after a submitblock rejection")
            time.sleep(args.poll)
        else:
            time.sleep(1)  # stood down (tip moved / work cleared); re-evaluate promptly


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", default="http://127.0.0.1:48332", help="bitcoind JSON-RPC URL")
    ap.add_argument("--user", default="btc")
    ap.add_argument("--password", default="btc")
    ap.add_argument(
        "--address",
        help="payout address for the coinbase (default: fetch a fresh one from rose via getnewaddress)",
    )
    ap.add_argument(
        "--blocks",
        type=int,
        default=1,
        help="how many blocks to mine; with --watch-mempool, the confirmation depth to "
        "mine pending wallet txs to (a lone block loses a same-height tie to a "
        "competing miner; depth is what makes a confirmation stick)",
    )
    ap.add_argument("--watch", action="append", default=[], help="txid to report on (repeatable)")
    ap.add_argument(
        "--coinbase-tag",
        default="",
        help="short string appended to the coinbase scriptSig (the conventional miner "
        "signature; shows in explorers). Max 75 bytes",
    )
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument(
        "--broadcast-peers",
        type=int,
        default=0,
        help="on an accepted block, also push it directly over P2P to this many peers "
        "(addresses from the node's own pool), so it enters the network from more "
        "origins than the node's ~10 connections and wins the same-height propagation "
        "race. A block that loses that race on our own node is pushed too, but only "
        "if the winning block lacks one of the transactions we are mining for. "
        "0 = off (rely on the node's relay); 30 is a good start for a public testnet",
    )
    ap.add_argument(
        "--adopt-fork-txs",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="when a competing block appears at our height, resubmit its transactions "
        "to our own mempool so they ride into the next block we mine (the node "
        "validates them; conflicts and the rival coinbase are skipped). Default on",
    )
    ap.add_argument("--bench", action="store_true", help="benchmark the hash loop and exit")
    ap.add_argument(
        "--watch-mempool",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="run continuously; mine mempool-inclusive blocks whenever an unconfirmed "
        "wallet tx (per rose) is in the node's mempool, until it reaches --blocks "
        "confirmations. Default on; --no-watch-mempool mines --blocks blocks on the "
        "current tip and exits",
    )
    ap.add_argument("--rose-url", default="http://127.0.0.1:48232", help="rose RPC to poll (watch-mempool)")
    ap.add_argument("--rose-user", default="btc")
    ap.add_argument(
        "--rose-password",
        default=os.environ.get("ROSE_RPC_PASSWORD", ""),
        help="rose RPC password (or set ROSE_RPC_PASSWORD)",
    )
    ap.add_argument("--poll", type=int, default=15, help="seconds between watch-mempool polls")
    ap.add_argument(
        "--future-margin",
        type=int,
        default=FUTURE_MARGIN_SECS,
        help="seconds to stay under the 2h future-time cap before starting to hash a "
        "min-diff block (default 60). Lower = start sooner and win the open-window race "
        "more often; too low risks peers rejecting the block as too-far-in-future. 0 "
        "hashes the instant the window opens (aggressive)",
    )
    ap.add_argument(
        "--cadence",
        type=int,
        default=0,
        help="minimum seconds between blocks we mine (0 = rely on testnet's 20-min rule; "
        "set a floor for testnet3, where storms can drop difficulty to 1)",
    )
    args = ap.parse_args()

    if len(args.coinbase_tag.encode()) > 75:
        sys.exit("--coinbase-tag too long (max 75 bytes)")
    if args.bench:
        bench()
        return

    node = Rpc(args.url, args.user, args.password)
    info = node("getblockchaininfo")
    chain = info["chain"]
    args.network = chain  # the node's own name for the chain, for the P2P magic bytes
    if chain == "main":
        sys.exit("refusing to CPU-mine mainnet")
    if args.broadcast_peers and chain == "regtest":
        log("--broadcast-peers is a public-network feature; ignoring it on regtest")
        args.broadcast_peers = 0

    # rose is needed to watch the mempool, and to fetch a payout address when --address
    # is omitted - both talk to the same rose, so build one handle for either.
    rose = None
    if args.watch_mempool or not args.address:
        if not args.rose_password:
            why = "--watch-mempool" if args.watch_mempool else "fetching a payout address (or pass --address)"
            sys.exit(f"need the rose RPC password (--rose-password or ROSE_RPC_PASSWORD) for {why}")
        rose = Rpc(args.rose_url, args.rose_user, args.rose_password)

    if not args.address:
        try:
            args.address = rose("getnewaddress")
        except Exception as e:
            sys.exit(f"could not fetch a payout address from rose ({args.rose_url}): {e}")
        log(f"payout address (fresh from rose): {args.address}")

    if args.watch_mempool:
        log(f"chain {chain}, tip {info['blocks']}, watch-mempool with {args.jobs} workers")
        watch_mempool(node, rose, args, chain)
        return

    log(f"chain {chain}, tip {info['blocks']}, mining {args.blocks} block(s) with {args.jobs} workers")
    mined = 0
    while mined < args.blocks:
        result = mine_one(node, args, chain, our_txids=set(args.watch))
        if result is True:
            mined += 1
        elif result is False:
            # A submitblock reject means the block was built wrong; retrying the same
            # construction just hot-spins, so stop rather than loop forever.
            sys.exit(1)


if __name__ == "__main__":
    main()
