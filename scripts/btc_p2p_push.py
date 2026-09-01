#!/usr/bin/env python3
"""Push a mined block straight into the P2P network from many origins at once.

A node relays a new block only to its handful of connected peers, so a CPU block
that ties a better-connected miner at the same height loses the propagation race -
the competitor's block reaches most nodes first, and a first-seen node neither
switches to nor relays the loser (see btc-miner's notes). This module opens direct
P2P connections to a fan-out of peers (addresses pulled from the local node's own
gossiped address pool) and announces + serves the block to all of them in parallel,
so the block enters the network from dozens of first-hop origins the instant it is
mined - the way a well-connected miner's does. Valid-block relay, nothing more.

Stdlib only. testnet4 by default; pass the magic for another network.
"""

import concurrent.futures
import hashlib
import io
import socket
import struct
import threading
import time

# Network magic (pchMessageStart). testnet4 is BIP94's 0x1c163f28.
MAGIC = {
    "testnet4": bytes.fromhex("1c163f28"),
    "test": bytes.fromhex("0b110907"),  # testnet3
    "main": bytes.fromhex("f9beb4d9"),
    "regtest": bytes.fromhex("fabfb5da"),
}
MSG_BLOCK = 2
PROTOCOL_VERSION = 70016


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _msg(magic, cmd, payload):
    return magic + cmd.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + dsha(payload)[:4] + payload


def _varint(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def _netaddr():
    return struct.pack("<Q", 0) + b"\0" * 10 + b"\xff\xff" + b"\0" * 4 + struct.pack(">H", 0)


def _version_payload(start_height):
    return (
        struct.pack("<iQq", PROTOCOL_VERSION, 0, int(time.time()))
        + _netaddr()
        + _netaddr()
        + struct.pack("<Q", int.from_bytes(hashlib.sha256(str(time.time()).encode()).digest()[:8], "little"))
        + bytes([len(b"/samaritan-push:0.1/")])
        + b"/samaritan-push:0.1/"
        + struct.pack("<i", start_height)
        + b"\x00"  # relay = false; we announce a block, we don't want their tx stream
    )


class _Framer:
    """Reads length-prefixed P2P messages off one socket."""

    def __init__(self, sock):
        self.s = sock
        self.buf = b""

    def read(self):
        while len(self.buf) < 24:
            self._fill()
        ln = struct.unpack("<I", self.buf[16:20])[0]
        while len(self.buf) < 24 + ln:
            self._fill()
        cmd = self.buf[4:16].rstrip(b"\0").decode(errors="replace")
        payload = self.buf[24 : 24 + ln]
        self.buf = self.buf[24 + ln :]
        return cmd, payload

    def _fill(self):
        chunk = self.s.recv(65536)
        if not chunk:
            raise ConnectionError("peer closed")
        self.buf += chunk


def _getdata_wants(payload, blockhash_le):
    """True if a getdata payload requests our block."""
    f = io.BytesIO(payload)
    n = f.read(1)
    if not n:
        return False
    count = n[0]  # tiny getdata; a single announced inv never needs a wide varint
    for _ in range(count):
        entry = f.read(36)
        if len(entry) < 36:
            break
        if entry[4:36] == blockhash_le:
            return True
    return False


def _push_one(addr, port, magic, block, blockhash_le, start_height, timeout):
    """Handshake one peer, announce the block by inv, serve it on getdata, and also
    send it unsolicited as a fallback. Returns True if the block bytes were sent."""
    header_inv = _msg(magic, "inv", _varint(1) + struct.pack("<I", MSG_BLOCK) + blockhash_le)
    block_msg = _msg(magic, "block", block)
    # A dead NAT'd address should fail fast and free the worker for another peer; a
    # reachable node answers the TCP SYN in well under 3s.
    s = socket.create_connection((addr, port), 3)
    # Short per-read timeout so a quiet peer never pins us for the whole window; the
    # deadline below bounds the total, and a read timeout just re-checks it.
    s.settimeout(2)
    try:
        fr = _Framer(s)
        s.sendall(_msg(magic, "version", _version_payload(start_height)))
        handshaked = False
        sent_block = False
        deadline = time.time() + timeout
        grace_until = None  # once handshaked, how long we wait for a getdata before pushing
        while time.time() < deadline and not sent_block:
            try:
                cmd, payload = fr.read()
            except socket.timeout:
                cmd, payload = None, b""
            if cmd == "version":
                s.sendall(_msg(magic, "verack", b""))
            elif cmd == "verack":
                handshaked = True
                grace_until = time.time() + 2
                s.sendall(header_inv)
            elif cmd == "ping":
                s.sendall(_msg(magic, "pong", payload))
            elif cmd == "getdata" and _getdata_wants(payload, blockhash_le):
                s.sendall(block_msg)
                sent_block = True
            elif cmd == "getheaders" and handshaked:
                # Peer is catching up; hand it the block directly rather than headers.
                s.sendall(block_msg)
                sent_block = True
            # No getdata after the grace window (the peer may already hold the header,
            # or ignore the inv): push it unsolicited. Core processes a valid
            # unrequested block that extends the tip.
            if handshaked and not sent_block and time.time() >= grace_until:
                s.sendall(block_msg)
                sent_block = True
        return sent_block
    finally:
        try:
            s.close()
        except OSError:
            pass


# DNS seeds resolve to always-up, well-connected infrastructure nodes - the highest-
# value first hops into the relay core. Standard P2P port per network.
DNS_SEEDS = {
    "testnet4": (["seed.testnet4.bitcoin.sprovoost.nl", "seed.testnet4.wiz.biz"], 48333),
    "test": (["seed.tbtc.petertodd.org", "seed.testnet.bitcoin.sprovoost.nl"], 18333),
}


def _seed_addresses(network):
    hosts, port = DNS_SEEDS.get(network, ([], 0))
    out = []
    for host in hosts:
        try:
            for info in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP):
                out.append((info[4][0], port))
        except OSError:
            pass
    return out


def peer_addresses(node_rpc, want, network="testnet4"):
    """Target list, best-first: the node's currently-connected peers (guaranteed
    reachable) and the DNS-seed infrastructure nodes ahead of the gossip pool (mostly
    unreachable NAT'd nodes). Delivering to the reachable/core set is what actually
    lands the block in the network fast."""
    front, seen = [], set()

    def add(addr, port):
        key = (addr, int(port))
        if addr and port and key not in seen:
            seen.add(key)
            front.append(key)

    try:
        for pi in node_rpc("getpeerinfo"):
            a = pi.get("addr", "")
            if a.rsplit(":", 1)[0].count(".") == 3 or a.startswith("["):  # ipv4 or [ipv6]
                host, _, port = a.rpartition(":")
                add(host.strip("[]"), int(port) if port.isdigit() else 0)
    except Exception:
        pass
    for addr, port in _seed_addresses(network):
        add(addr, port)
    try:
        for a in node_rpc("getnodeaddresses", [max(want * 4, 64)]):
            if a.get("network") in ("ipv4", "ipv6"):
                add(a.get("address"), a.get("port"))
    except Exception:
        pass
    return [(a, p) for a, p in front if p]


def broadcast_block(
    block_hex, node_rpc, network="testnet4", count=30, timeout=6, deadline_secs=25, log=print
):
    """Fan the block out until it is SERVED to `count` reachable peers (not merely
    attempted at `count` addresses - most gossiped addresses are unreachable NAT'd
    nodes, so a fixed attempt list delivers to only a handful). Attempts a large pool
    in parallel, counting successes, and stops on `count` deliveries or `deadline_secs`.
    Best-effort: every per-peer failure is swallowed. Returns (served, attempted)."""
    magic = MAGIC.get(network)
    if magic is None:
        log(f"  p2p-push: no magic for network {network!r}; skipping")
        return (0, 0)
    block = bytes.fromhex(block_hex)
    blockhash_le = dsha(block[:80])
    start_height = 0  # peers do not gate an inv/block on our advertised height
    # Pull a wide pool: at the ~5-10% reachability of gossiped addresses, serving
    # `count` peers means attempting many times that.
    pool = peer_addresses(node_rpc, count * 20, network)
    if not pool:
        log("  p2p-push: no peer addresses from the node; skipping")
        return (0, 0)
    log(f"  p2p-push: delivering to up to {count} peers (pool of {len(pool)}, {deadline_secs}s budget)")
    stop = threading.Event()

    def attempt(addr, port):
        if stop.is_set():
            return False
        try:
            return _push_one(addr, port, magic, block, blockhash_le, start_height, timeout)
        except Exception:
            return False

    served = attempted = 0
    hard_deadline = time.time() + deadline_secs
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        futs = {ex.submit(attempt, a, pt): (a, pt) for a, pt in pool}
        for fut in concurrent.futures.as_completed(futs):
            attempted += 1
            try:
                if fut.result():
                    served += 1
            except Exception:
                pass
            if served >= count or time.time() >= hard_deadline:
                stop.set()  # short-circuit not-yet-started attempts
                break
    log(f"  p2p-push: served the block to {served} peers ({attempted} attempted)")
    return (served, attempted)
