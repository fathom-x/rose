#!/usr/bin/env python3
"""Watch a Bitcoin node and one or more zecd wallets through live reorgs.

Testnet4 contests CPU-mined tips daily, and `scripts/btc-miner.py` mines a lone
min-difficulty block for every unconfirmed wallet transaction - exactly the block a
competing miner orphans. This script is the observer for that: every `--poll` seconds it
reads the node's best block and `getchaintips`, and each wallet's `getwalletinfo` plus
`gettransaction` for every transaction it has seen, and logs

  * REORG: the node's active tip moved to a block that does not extend the previous one
    (the previous best is no longer at its height), with the depth;
  * FORK: a new `valid-fork` tip in `getchaintips` (a competing branch the node has
    fully validated and rejected - the orphaned side of a reorg);
  * WALLET: each wallet's synced height/hash against the node's, and whether it is
    converged;
  * TX MOVED / TX UNCONFIRMED / TX GONE: a wallet transaction whose block changed, that
    fell back to 0 confirmations, or that the wallet no longer returns - the evidence a
    reorg reached the wallet's own history;
  * SEND: with `--send-every N` minutes, a small self-payment from the first wallet to
    its own fresh address, so most of the blocks the local miner produces carry a wallet
    transaction (the miner mines on the wallet's unconfirmed transactions). Refused on
    mainnet (`--allow-mainnet` overrides), priced at an explicit `--fee-rate` (never a
    wallet estimate), and skipped while the balance is under `--min-balance`.

Stdlib only. Wallet RPCs are zecd's; the node's are Bitcoin Core's. Output is one line
per event, timestamped, to stdout (tee it to a file for a day).

    ZECD_RPC_PASSWORD=... python3 scripts/btc-reorg-watch.py \\
        --node http://btc:btc@127.0.0.1:48332 \\
        --wallet bitcoind=http://btc:$ZECD_RPC_PASSWORD@172.17.0.1:48232 \\
        --wallet kyoto=http://btc:$ZECD_RPC_PASSWORD@127.0.0.1:48233 \\
        --send-every 30
"""

import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse


def rpc(url, method, params):
    u = urlparse(url)
    target = f"{u.scheme}://{u.hostname}:{u.port}{u.path or '/'}"
    body = json.dumps({"jsonrpc": "1.0", "id": "w", "method": method, "params": params}).encode()
    req = urllib.request.Request(target, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if u.username:
        cred = f"{u.username}:{u.password or ''}"
        req.add_header("Authorization", "Basic " + base64.b64encode(cred.encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            out = json.load(resp)
    except urllib.error.HTTPError as e:
        try:
            out = json.load(e)
        except Exception:
            raise RuntimeError(f"{method}: HTTP {e.code}") from None
    if out.get("error"):
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(kind, msg):
    print(f"{now()} {kind:<14} {msg}", flush=True)


class Wallet:
    def __init__(self, label, url):
        self.label = label
        self.url = url
        self.txs = {}  # txid -> (blockhash, confirmations)
        self.last = None  # (height, hash, connected)

    def poll(self, node_height, node_hash):
        try:
            wi = rpc(self.url, "getwalletinfo", [])
        except Exception as e:
            log("WALLET", f"[{self.label}] unreachable: {e}")
            return
        lp = wi.get("lastprocessedblock") or {}
        height, h = lp.get("height"), lp.get("hash")
        connected = wi.get("upstream_connected")
        converged = h == node_hash
        state = (height, h, connected)
        if state != self.last:
            log(
                "WALLET",
                f"[{self.label}] height={height} hash={str(h)[-12:]} "
                f"node={node_height}/{node_hash[-12:]} converged={converged} "
                f"connected={connected} pending={wi.get('unconfirmed_balance')} "
                f"balance={wi.get('balance')}",
            )
            self.last = state
        try:
            entries = rpc(self.url, "listtransactions", ["*", 50])
        except Exception as e:
            log("WALLET", f"[{self.label}] listtransactions failed: {e}")
            return
        seen = set()
        for e in entries:
            txid = e["txid"]
            if txid in seen:
                continue
            seen.add(txid)
            bh, conf = e.get("blockhash"), e.get("confirmations", 0)
            prev = self.txs.get(txid)
            if prev is None:
                log("TX NEW", f"[{self.label}] {txid[:16]} conf={conf} block={str(bh)[-12:] if bh else None}")
            elif prev[0] != bh:
                if bh is None:
                    log("TX UNCONFIRMED", f"[{self.label}] {txid[:16]} fell out of {prev[0][-12:]} (was {prev[1]} conf)")
                elif prev[0] is None:
                    log("TX CONFIRMED", f"[{self.label}] {txid[:16]} into {bh[-12:]}")
                else:
                    log("TX MOVED", f"[{self.label}] {txid[:16]} {prev[0][-12:]} -> {bh[-12:]} (reorged)")
            self.txs[txid] = (bh, conf)
        for txid in list(self.txs):
            if txid not in seen and self.txs[txid] is not None:
                # Not in the last 50 entries: check it still resolves.
                try:
                    rpc(self.url, "gettransaction", [txid])
                except RuntimeError as e:
                    if "-5" in str(e) or "non-wallet" in str(e):
                        log("TX GONE", f"[{self.label}] {txid[:16]} is no longer a wallet transaction")
                        self.txs[txid] = None


def self_send(wallet, amount, fee_rate, min_balance):
    """One self-payment, priced explicitly and floored on balance.

    Every send carries an explicit `fee_rate` (Core's tenth `sendtoaddress` argument, sat/vB):
    a wallet-estimated rate follows the mempool, and a busy testnet mempool priced the
    watcher's 2026-09-11 sends at hundreds of sat/vB until the spender was empty. The
    balance floor is the other half of that: the watcher stops paying before the wallet
    runs dry, so it never spends what a reorg test was meant to observe.
    """
    try:
        balance = float(rpc(wallet.url, "getbalance", []))
        if balance < min_balance:
            log("SEND", f"[{wallet.label}] skipped: balance {balance} is below --min-balance {min_balance}")
            return
        addr = rpc(wallet.url, "getnewaddress", [])
        # address, amount, comment, comment_to, subtractfeefromamount, replaceable,
        # conf_target, estimate_mode, avoid_reuse, fee_rate - the estimation pair stays
        # null (zecd refuses it alongside fee_rate, as Core does).
        txid = rpc(wallet.url, "sendtoaddress", [addr, amount, "", "", False, None, None, None, None, fee_rate])
        log("SEND", f"[{wallet.label}] {amount} to own {addr[-10:]} at {fee_rate} sat/vB: {txid}")
    except Exception as e:
        log("SEND", f"[{wallet.label}] failed: {e}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--node", required=True, help="bitcoind RPC URL with credentials")
    ap.add_argument("--wallet", action="append", default=[], metavar="LABEL=URL", help="zecd wallet RPC URL (repeatable)")
    ap.add_argument("--poll", type=int, default=20, help="seconds between polls")
    ap.add_argument("--send-every", type=int, default=0, help="minutes between self-payments from the first wallet (0 = never)")
    ap.add_argument("--send-amount", type=float, default=0.0001)
    ap.add_argument("--fee-rate", type=float, default=1.0, help="explicit sat/vB for every self-payment, never a wallet estimate (default 1)")
    ap.add_argument("--min-balance", type=float, default=0.001, help="skip the self-payment while the first wallet's balance is below this (BTC)")
    ap.add_argument("--allow-mainnet", action="store_true", help="permit --send-every against a mainnet node (refused otherwise: this loop spends real money)")
    args = ap.parse_args()
    if args.send_every:
        # The send loop exists to feed a testnet miner; on mainnet it is a slow drain of real
        # funds. Read the node's chain once, before the first payment, and refuse it.
        chain = rpc(args.node, "getblockchaininfo", []).get("chain")
        if chain == "main" and not args.allow_mainnet:
            sys.exit(f"--send-every against a mainnet node (chain={chain!r}) is refused; pass --allow-mainnet to override")
        if args.fee_rate <= 0:
            sys.exit("--fee-rate must be a positive sat/vB")
    wallets = []
    for spec in args.wallet:
        label, _, url = spec.partition("=")
        wallets.append(Wallet(label, url))

    known_forks = set()
    prev_best = None  # (height, hash)
    last_send = 0.0
    log("START", f"node={urlparse(args.node).hostname}:{urlparse(args.node).port} wallets={[w.label for w in wallets]}")
    while True:
        try:
            height = rpc(args.node, "getblockcount", [])
            best = rpc(args.node, "getbestblockhash", [])
            if prev_best is not None and best != prev_best[1]:
                ph, phash = prev_best
                still = None
                try:
                    still = rpc(args.node, "getblockhash", [ph])
                except Exception:
                    pass
                if still != phash:
                    log("REORG", f"tip {ph}/{phash[-12:]} replaced; now {height}/{best[-12:]} (depth >= {ph - min(ph, height) + 1})")
                else:
                    log("BLOCK", f"{height} {best[-12:]}")
            elif prev_best is None:
                log("BLOCK", f"{height} {best[-12:]}")
            prev_best = (height, best)
            for tip in rpc(args.node, "getchaintips", []):
                key = (tip["height"], tip["hash"])
                if tip["status"] == "valid-fork" and key not in known_forks:
                    known_forks.add(key)
                    if len(known_forks) > 1:
                        log("FORK", f"valid-fork at {tip['height']} len={tip['branchlen']} {tip['hash'][-12:]}")
            for w in wallets:
                w.poll(height, best)
            if args.send_every and wallets and time.time() - last_send >= args.send_every * 60:
                self_send(wallets[0], args.send_amount, args.fee_rate, args.min_balance)
                last_send = time.time()
        except Exception as e:
            log("ERROR", str(e))
        time.sleep(args.poll)


if __name__ == "__main__":
    main()
