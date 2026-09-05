#!/usr/bin/env python3
"""Generate the shipped per-day birthday table for the Bitcoin kyoto backend.

`zecd init` on a kyoto wallet is offline, so a `--birthday` date (or a height below the
shipped scan floor) used to resolve to nothing better than SegWit activation, and the
first sync had to scan headers from 2017 before it could anchor at the true height. The
table this script writes gives init an offline answer: for every UTC day since SegWit
activation, the height and hash of the first block whose header time is at or after that
day's midnight. `src/btc/birthdays.rs` reads it (`include_bytes!`) and turns a date or a
height into a `(height, hash)` scan anchor, exactly what a bitcoind-backed init records.

The table is read from a trusted node's headers over JSON-RPC (batched, ~2 requests per
2000 blocks). The last entries are cut `--confirmations` blocks below the node's tip so
nothing the binary ships can reorg out - an anchor is trusted verbatim by the first scan
and nothing clears a bad one.

Format (all little-endian):
    u32  first_day        days since the unix epoch of entry 0's UTC midnight
    u32  count            number of entries, one per consecutive day
    then `count` entries of:
    u32  height           the first block with header time >= that day's midnight
    [32] hash             the block's hash, consensus (internal) byte order

Usage (the mainnet node this host runs, cookie auth via docker):
    BITCOIND_RPC_AUTH="$(docker exec deploy-bitcoind-1 cat /root/.bitcoin/.cookie)" \\
        scripts/btc-birthday-table.py --out src/btc/birthdays-main.bin

Re-running against a newer tip appends days; earlier entries never change (each is a
buried block), so a regenerated table is a strict extension of the shipped one - verify
with `--check-against <old.bin>`.
"""

import argparse
import base64
import json
import os
import struct
import sys
import urllib.request
from datetime import datetime, timezone

SEGWIT_ACTIVATION = 481_824  # the first block a BIP 84 output can exist in
DAY = 86_400


def rpc_batch(url, auth, calls):
    body = json.dumps(
        [
            {"jsonrpc": "1.0", "id": i, "method": m, "params": p}
            for i, (m, p) in enumerate(calls)
        ]
    ).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "text/plain")
    req.add_header(
        "Authorization", "Basic " + base64.b64encode(auth.encode()).decode()
    )
    with urllib.request.urlopen(req, timeout=300) as resp:
        results = json.load(resp)
    out = [None] * len(calls)
    for r in results:
        if r.get("error"):
            raise SystemExit(f"rpc error: {r['error']}")
        out[r["id"]] = r["result"]
    return out


def fetch_headers(url, auth, lo, hi, batch):
    """Yield (height, time, hash_hex) for heights lo..=hi in order."""
    for start in range(lo, hi + 1, batch):
        heights = list(range(start, min(start + batch, hi + 1)))
        hashes = rpc_batch(url, auth, [("getblockhash", [h]) for h in heights])
        headers = rpc_batch(url, auth, [("getblockheader", [h, True]) for h in hashes])
        for h, hdr in zip(heights, headers):
            assert hdr["height"] == h
            yield h, hdr["time"], hdr["hash"]
        print(f"  headers to {heights[-1]}", file=sys.stderr, end="\r")


def read_table(path):
    data = open(path, "rb").read()
    first_day, count = struct.unpack_from("<II", data, 0)
    entries = []
    for i in range(count):
        height, = struct.unpack_from("<I", data, 8 + i * 36)
        raw = data[12 + i * 36 : 12 + i * 36 + 32]
        entries.append((height, raw[::-1].hex()))
    return first_day, entries


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rpc-url", default="http://127.0.0.1:8332/")
    ap.add_argument(
        "--rpc-auth",
        default=os.environ.get("BITCOIND_RPC_AUTH"),
        help="user:password (or the node's .cookie contents); default $BITCOIND_RPC_AUTH",
    )
    ap.add_argument("--out", required=True, help="table file to write")
    ap.add_argument(
        "--confirmations",
        type=int,
        default=1000,
        help="entries must sit at least this far below the tip (default 1000)",
    )
    ap.add_argument("--batch", type=int, default=2000)
    ap.add_argument(
        "--check-against",
        metavar="OLD.bin",
        help="require the new table to be a strict extension of this one",
    )
    args = ap.parse_args()
    if not args.rpc_auth:
        raise SystemExit("--rpc-auth or $BITCOIND_RPC_AUTH is required")

    tip, chain = rpc_batch(
        args.rpc_url, args.rpc_auth, [("getblockcount", []), ("getblockchaininfo", [])]
    )
    if chain["chain"] != "main":
        raise SystemExit(f"the node is on chain {chain['chain']!r}; this table is mainnet's")
    hi = tip - args.confirmations
    print(f"tip {tip}, reading headers {SEGWIT_ACTIVATION}..{hi}", file=sys.stderr)

    # Entry 0 is the first full UTC day after activation: the activation day's own first
    # block predates 481824, and init already clamps every earlier date to that floor.
    activation_time = fetch_headers(args.rpc_url, args.rpc_auth, SEGWIT_ACTIVATION, SEGWIT_ACTIVATION, 1)
    (_, t0, _), = list(activation_time)
    first_day = t0 // DAY + 1
    next_midnight = first_day * DAY
    entries = []
    for height, time, hash_hex in fetch_headers(args.rpc_url, args.rpc_auth, SEGWIT_ACTIVATION, hi, args.batch):
        # Header times are not monotonic; "first block at or after midnight" is defined
        # by the first height that crosses it, which makes the table monotonic in height.
        while time >= next_midnight:
            entries.append((height, hash_hex))
            next_midnight += DAY
    print(file=sys.stderr)
    if not entries:
        raise SystemExit("no complete day below the confirmation cut")

    if args.check_against:
        old_first, old_entries = read_table(args.check_against)
        if old_first != first_day:
            raise SystemExit(f"first day differs: old {old_first}, new {first_day}")
        if entries[: len(old_entries)] != old_entries:
            raise SystemExit("the new table does not extend the old one entry for entry")
        print(f"extends {args.check_against} by {len(entries) - len(old_entries)} days", file=sys.stderr)

    with open(args.out, "wb") as f:
        f.write(struct.pack("<II", first_day, len(entries)))
        for height, hash_hex in entries:
            f.write(struct.pack("<I", height))
            f.write(bytes.fromhex(hash_hex)[::-1])
    fmt = lambda d: datetime.fromtimestamp(d * DAY, timezone.utc).date()
    print(
        f"wrote {args.out}: {len(entries)} days, {fmt(first_day)} (height {entries[0][0]}) "
        f"to {fmt(first_day + len(entries) - 1)} (height {entries[-1][0]}), "
        f"{len(entries) * 36 + 8} bytes",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
