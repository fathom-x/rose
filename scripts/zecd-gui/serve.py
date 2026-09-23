#!/usr/bin/env python3
"""Tiny same-origin dev UI server for zecd's Bitcoin wallet RPC.

zecd speaks bitcoind's RPC dialect on purpose: HTTP Basic auth, no CORS headers. A
browser page therefore cannot call it cross-origin, and the RPC password has no
business living in browser JS. This server closes both gaps the way every bitcoind
dashboard does: it serves the static page AND forwards POST /rpc to zecd with the
credentials injected server-side, so the page and the RPC share one origin.

Stdlib only, no dependencies. Every value can come from a zecd config file (default:
deploy/zecd.btc-testnet4.toml) OR from the environment, so the image can run with no
config mounted at all. Each is resolved flag > env > config > default: the user via
--rpc-user / ZECD_RPC_USER / [rpc] user, and the password via ZECD_RPC_PASSWORD /
[rpc] password (no flag - a secret has no business on a command line), matching the
precedence zecd itself gives ZECD_RPC_PASSWORD over the file. When --conf points at a
file that is not present, it is skipped rather than an error. The two config-derived
values the page actually uses - the network (picks the BTC/tBTC unit) and the backend
(picks the fee source) - then come from ZECD_NETWORK and ZECD_BACKEND (kyoto|bitcoind);
the fee-preview tiers fall back to their per-network defaults.

The upstream address is likewise separable from the credentials. --rpc-url (env:
ZECD_RPC_URL) gives the whole base URL - correct for reaching a host zecd from a
container or a compose sibling by service name, where the config's own 127.0.0.1
[rpc] bind is the container's own loopback. When it is unset the base URL is composed
from parts: --rpc-host / ZECD_RPC_HOST (a bare hostname - e.g. an orchestrator service
reference that cannot have a scheme string-composed onto it), --rpc-port / ZECD_RPC_PORT,
and --rpc-scheme / ZECD_RPC_SCHEME (default http), each falling back to [rpc] bind/port.

Usage, from the repository root:

    python3 scripts/zecd-gui/serve.py                      # testnet4 stack defaults
    python3 scripts/zecd-gui/serve.py --conf deploy/zecd.btc-testnet3.toml --port 8081
    python3 scripts/zecd-gui/serve.py --wallet btc         # route via /wallet/<name>

    # from a container, against a zecd on the host (macOS/Windows Docker Desktop)
    python3 scripts/zecd-gui/serve.py --rpc-url http://host.docker.internal:48242

    # no config mounted: user, password and upstream all from the environment
    ZECD_RPC_USER=view ZECD_RPC_PASSWORD=... ZECD_RPC_HOST=zecd-btc ZECD_RPC_PORT=18232 \
        python3 scripts/zecd-gui/serve.py

Then open http://127.0.0.1:8080/.
"""

import argparse
import base64
import http.server
import json
import math
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from decimal import Decimal
from pathlib import Path

UI_DIR = Path(__file__).resolve().parent

# How often --reload polls the server's own source files for a change (mtime). Polling
# rather than inotify because it needs no dependency and works across a Docker bind mount
# from any host filesystem, and a one-second delay on a code edit costs nothing.
RELOAD_POLL_SECS = 1.0


def watch_and_reexec(paths, interval=RELOAD_POLL_SECS):
    """Re-exec this process when any of `paths` changes on disk (--reload).

    The page itself needs nothing: index.html is read from disk on every request, so an
    edit is live on the next refresh. This is for the server: a change to serve.py
    replaces the whole process with a fresh one running the new code, via execv, so the
    PID (and so the container) stays the same and a compose restart policy never sees a
    stop. The listening socket does not survive the exec (Python sockets are
    non-inheritable) and the new process rebinds the port; SO_REUSEADDR keeps that from
    failing on the lingering TIME_WAIT connections.
    """
    def stamp():
        return tuple(p.stat().st_mtime_ns if p.exists() else None for p in paths)

    def run():
        last = stamp()
        while True:
            time.sleep(interval)
            try:
                now = stamp()
            except OSError:
                continue
            if now != last:
                changed = [p.name for p, a, b in zip(paths, last, now) if a != b]
                print(f"reload: {', '.join(changed)} changed; restarting", flush=True)
                os.execv(sys.executable, [sys.executable, *sys.argv])

    threading.Thread(target=run, name="reload", daemon=True).start()


def read_config(conf_path):
    """Parse a zecd.toml into a {section: {key: value}} dict.

    Uses tomllib when available (Python 3.11+); otherwise a line-based fallback
    that understands the flat key = value shape these deploy configs use (the
    macOS system python is 3.9, so the fallback matters).
    """
    text = Path(conf_path).read_text()
    try:
        import tomllib

        return tomllib.loads(text)
    except ModuleNotFoundError:
        data = {}
        section = None
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            m = re.match(r"^\[(.+)\]$", line)
            if m:
                section = m.group(1)
                data.setdefault(section, {})
                continue
            m = re.match(r'^(\w+)\s*=\s*(?:"([^"]*)"|(\d+))$', line)
            if m and section is not None:
                data[section][m.group(1)] = m.group(2) if m.group(2) is not None else int(m.group(3))
        return data


def load_config(conf_path):
    """(config dict, label) for `conf_path`, tolerating a missing file.

    The image bakes no config and can run purely from environment variables (user, password,
    host, port), so a `--conf` that isn't mounted is not an error - it just means every value
    comes from the environment and the config-derived extras (the fee-preview tiers, the info
    panel's network/backend labels) fall back to their defaults. A config that IS present is
    read as before. The label is what the banner and /info report as the config source.
    """
    if conf_path and Path(conf_path).exists():
        return read_config(conf_path), os.path.basename(conf_path)
    return {}, "(none)"


# The built-in per-network endpoints of each HTTP fee tier, mirroring src/btc/fees.rs. A
# network absent from a table has no public instance of that source, so the tier is skipped -
# note Blockstream runs mainnet and testnet3 only, so an `esplora` tier on testnet4 is inert
# here for exactly the reason it is inert in the wallet.
FEE_ENDPOINTS = {
    "mempool_space": {
        "main": "https://mempool.space/api/v1/fees/recommended",
        "mainnet": "https://mempool.space/api/v1/fees/recommended",
        "test": "https://mempool.space/testnet/api/v1/fees/recommended",
        "testnet3": "https://mempool.space/testnet/api/v1/fees/recommended",
        "testnet4": "https://mempool.space/testnet4/api/v1/fees/recommended",
    },
    "esplora": {
        "main": "https://blockstream.info/api/fee-estimates",
        "mainnet": "https://blockstream.info/api/fee-estimates",
        "test": "https://blockstream.info/testnet/api/fee-estimates",
        "testnet3": "https://blockstream.info/testnet/api/fee-estimates",
    },
}

DEFAULT_FEE_SOURCES = ["mempool_space", "esplora", "peer_median"]

# What every fee source is allowed to say, in sat/vB - src/btc/fees.rs's SANITY_CEILING.
FEE_SANITY_CEILING_SAT_PER_VB = 2000


def wallet_fee_rate(value):
    """An oracle's sat/vB as the whole-sat rate zecd would actually pay, or ValueError.

    Mirrors `btc::fees::rate_from_sat_per_vb` exactly, because the page now PREFILLS the
    send form with this number and passes it as sendtoaddress's explicit `fee_rate` - so any
    difference here is a difference in what gets paid. Non-finite or negative is a broken
    source; anything over the sanity ceiling is refused rather than paid; and the result is
    rounded UP, so Esplora's sub-1 sat/vB quiet-market floats become 1 rather than a zero no
    peer would relay (and that zecd itself refuses as an explicit fee_rate).
    """
    value = float(value)
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"nonsensical fee rate {value}")
    if value > FEE_SANITY_CEILING_SAT_PER_VB:
        raise ValueError(f"{value} sat/vB is above the {FEE_SANITY_CEILING_SAT_PER_VB} sat/vB sanity ceiling")
    sat_per_vb = math.ceil(value)
    if sat_per_vb == 0:
        raise ValueError("zero fee rate")
    return sat_per_vb


def kyoto_fee_tiers(config, net):
    """The config's HTTP fee tiers as ordered (source, url) pairs.

    Mirrors `btc::fees::oracle_chain`: [fees] sources in order, each at its override or its
    built-in per-network endpoint, skipping any with neither. `peer_median` is dropped here
    because it is not an HTTP source - the page cannot query kyoto's peers, it can only name
    the fallback - so an empty result means the preview has nothing to show, not that the
    wallet cannot price a send.
    """
    fees = config.get("fees", {})
    overrides = {
        "mempool_space": fees.get("mempool_space_url"),
        "esplora": fees.get("esplora_url"),
    }
    tiers = []
    for source in fees.get("sources", DEFAULT_FEE_SOURCES):
        if source == "peer_median":
            continue
        url = (overrides.get(source) or "").strip() or FEE_ENDPOINTS.get(source, {}).get(net)
        if url:
            tiers.append((source, url))
    return tuple(tiers)


# The RPC methods index.html calls - the whole surface the proxy forwards. Everything else
# is refused before the credentials are attached: the page needs nothing more, and a proxy
# that forwarded any method would hand the wallet's full RPC (sendmany, sendrawtransaction,
# abandontransaction) to whatever could reach this port.
ALLOWED_METHODS = frozenset({
    "getbalances",
    "getbestblockhash",
    "getblockcount",
    "getnewaddress",
    "getwalletinfo",
    "listdescriptors",
    "listreceivedbyaddress",
    "listtransactions",
    "listunspent",
    "sendtoaddress",
})


def rpc_error(code, message):
    return json.dumps({"result": None, "error": {"code": code, "message": message}, "id": None}).encode()


def request_is_same_origin(headers):
    """Whether a browser request came from this server's own page.

    The proxy injects the wallet credentials, so the page's origin is the only one that may
    drive it: a page on any other site that could POST here would spend the wallet with the
    operator's cookie-less session doing nothing to stop it. Browsers label every request
    with `Sec-Fetch-Site` (same-origin / same-site / cross-site / none) and cross-origin
    ones with `Origin`; a request carrying neither is a non-browser client (curl, a script)
    on the operator's own machine, which has no cross-site problem to solve.
    """
    site = headers.get("Sec-Fetch-Site")
    if site is not None and site not in ("same-origin", "none"):
        return False
    origin = headers.get("Origin")
    if origin is not None:
        host = headers.get("Host", "")
        if origin.lower() not in (f"http://{host}".lower(), f"https://{host}".lower()):
            return False
    return True


class Handler(http.server.BaseHTTPRequestHandler):
    # Filled in by main() before the server starts.
    upstream_url = None
    auth_header = None
    bitcoind_url = None  # None if no [bitcoind] creds were found
    bitcoind_auth = None
    backend = "bitcoind"  # "bitcoind" | "kyoto", from the config
    fee_tiers = ()  # ordered (source, url) HTTP fee tiers, mirroring [fees] (set by main)
    info_json = b"{}"  # which config this proxy is serving (set by main)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = (UI_DIR / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/feerate":
            self.serve_feerate()
        elif self.path == "/info":
            self.relay(200, self.info_json)
        else:
            self.send_error(404)

    def serve_feerate(self):
        """zecd's Bitcoin engine exposes no fee-estimate RPC, so mirror where the wallet
        gets its rate: the bitcoind backend uses bitcoind's estimatesmartfee, and the
        kyoto backend uses mempool.space (then a recent-block median it derives from
        peers). Query whichever matches this config's backend so the page shows the rate
        the wallet would actually use."""
        if self.backend == "kyoto":
            return self.serve_feerate_kyoto()
        if not self.bitcoind_url:
            return self.relay(200, json.dumps({"error": "no [bitcoind] credentials in config"}).encode())
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": "estimatesmartfee", "params": [6]}).encode()
        req = urllib.request.Request(
            self.bitcoind_url, data=body,
            headers={"Content-Type": "application/json", "Authorization": self.bitcoind_auth},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                r = json.loads(resp.read())
        except (urllib.error.HTTPError, OSError, ValueError) as e:
            return self.relay(200, json.dumps({"error": f"bitcoind unreachable: {e}"}).encode())
        result = (r or {}).get("result") or {}
        if result.get("feerate"):
            # BTC/kvB -> whole sat/vB, ceiling-divided and floored at 1, exactly as zecd's
            # bitcoind path does (btc/chain.rs::estimate_fee_rate_blocking) - the page passes
            # this number back as the send's explicit fee_rate, so it must be the same number.
            # Decimal via repr so 0.00001 does not become 999.9999 sat/kvB on the way.
            sat_per_kvb = int(Decimal(repr(result["feerate"])) * 100_000_000)
            sat_per_vb = max(1, -(-sat_per_kvb // 1000))
            out = {"sat_per_vb": sat_per_vb, "source": "estimatesmartfee", "blocks": result.get("blocks")}
        else:
            out = {"sat_per_vb": 1.0, "source": "fallback"}  # test-network floor
        self.relay(200, json.dumps(out).encode())

    def serve_feerate_kyoto(self):
        """A kyoto wallet walks the [fees] oracle chain at send time (src/btc/fees.rs): each
        HTTP tier in turn, then a peer-derived recent-block median. The page can't see the
        peer path, but it can walk the same HTTP tiers, in the same order, at the same
        endpoints this config resolves - the closest honest preview of what a kyoto send
        would cost. If they're all unreachable, say so and name the fallback the wallet uses
        instead."""
        attempts = []
        for source, url in self.fee_tiers:
            try:
                with urllib.request.urlopen(url, timeout=10) as resp:
                    body = json.loads(resp.read())
            except (urllib.error.HTTPError, OSError, ValueError) as e:
                attempts.append(f"{source} ({e})")
                continue
            # Both tiers are read at the ~6-block target zecd reads them at (hourFee, and
            # Esplora's "6" key), so the preview matches the send rather than a faster,
            # pricier number.
            raw = body.get("hourFee") if source == "mempool_space" else body.get("6")
            if raw is None:
                attempts.append(f"{source} (no 6-block estimate)")
                continue
            try:
                sat = wallet_fee_rate(raw)
            except (TypeError, ValueError) as e:
                attempts.append(f"{source} ({e})")
                continue
            out = {"sat_per_vb": sat, "source": f"{source} ({url})"}
            if attempts:
                out["note"] = "fell back past " + ", ".join(attempts)
            return self.relay(200, json.dumps(out).encode())
        tried = "; ".join(attempts) if attempts else "no HTTP fee source configured for this network"
        self.relay(200, json.dumps(
            {"note": f"{tried}; kyoto falls back to a recent-block median"}).encode())

    def do_POST(self):
        if self.path != "/rpc":
            self.send_error(404)
            return
        if not request_is_same_origin(self.headers):
            self.log_error("refused a cross-origin /rpc request (Origin=%s Sec-Fetch-Site=%s)",
                           self.headers.get("Origin"), self.headers.get("Sec-Fetch-Site"))
            return self.relay(403, rpc_error(-32600, "cross-origin requests are refused"))
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        # One request at a time, and only the methods the page uses; a batch or an unlisted
        # method is refused with the shape the page already understands (zecd's own
        # method-not-found), and never reaches the wallet.
        try:
            call = json.loads(body)
        except ValueError:
            return self.relay(400, rpc_error(-32700, "Parse error"))
        method = call.get("method") if isinstance(call, dict) else None
        if not isinstance(method, str) or method not in ALLOWED_METHODS:
            self.log_error("refused /rpc method %r", method if isinstance(call, dict) else "<batch>")
            return self.relay(403, rpc_error(-32601, "Method not allowed through this proxy"))
        req = urllib.request.Request(
            self.upstream_url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": self.auth_header,
            },
            method="POST",
        )
        # zecd maps JSON-RPC errors onto non-2xx HTTP statuses (404 for unknown
        # methods, 500 for most errors) with a JSON body; pass both through
        # verbatim so the page sees exactly what a direct client would.
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                self.relay(resp.status, resp.read())
        except urllib.error.HTTPError as e:
            self.relay(e.code, e.read())
        except OSError as e:
            self.relay(
                502,
                json.dumps(
                    {"result": None, "error": {"code": -1, "message": f"zecd unreachable: {e}"}, "id": None}
                ).encode(),
            )

    def relay(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_request(self, code="-", size="-"):
        # Successful requests stay off the terminal (the page is the operator's view);
        # anything the proxy or zecd refused is logged, since a refusal that leaves no
        # trace is how a misconfigured or probed proxy goes unnoticed.
        try:
            failed = int(code) >= 400
        except (TypeError, ValueError):
            failed = True
        if failed:
            super().log_request(code, size)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--conf", default="deploy/zecd.btc-testnet4.toml", help="zecd config to read [rpc] from")
    ap.add_argument("--bind", default="127.0.0.1", help="address to serve the UI on")
    ap.add_argument("--port", type=int, default=8080, help="port to serve the UI on")
    ap.add_argument("--wallet", default="", help="route RPCs via /wallet/<name> (empty = default wallet)")
    ap.add_argument(
        "--rpc-user",
        default="",
        help="zecd RPC username, overriding [rpc] user from the config. Env: ZECD_RPC_USER. "
             "(The password has no flag - it is a secret; set it via ZECD_RPC_PASSWORD or the "
             "config.)",
    )
    ap.add_argument(
        "--rpc-url",
        default="",
        help="zecd JSON-RPC base URL, overriding [rpc] bind/port from the config (e.g. "
             "http://host.docker.internal:48242 to reach a host zecd from a container, or "
             "http://zecd:18232 for a compose sibling). Credentials still come from the "
             "config/env. Env: ZECD_RPC_URL",
    )
    ap.add_argument(
        "--rpc-host",
        default="",
        help="zecd RPC host, used to compose the base URL when --rpc-url/ZECD_RPC_URL is unset. "
             "Takes a bare hostname (e.g. an orchestrator's service reference that cannot have a "
             "scheme composed onto it). Env: ZECD_RPC_HOST",
    )
    ap.add_argument(
        "--rpc-port",
        default="",
        help="zecd RPC port for the composed base URL (with --rpc-host). Env: ZECD_RPC_PORT",
    )
    ap.add_argument(
        "--rpc-scheme",
        default="",
        help="scheme for the composed base URL (with --rpc-host); default http. Env: ZECD_RPC_SCHEME",
    )
    ap.add_argument(
        "--bitcoind-url",
        default="http://127.0.0.1:48332",
        help="bitcoind JSON-RPC for the fee estimate (default testnet4 48332; uses [bitcoind] creds)",
    )
    ap.add_argument(
        "--reload",
        action="store_true",
        help="development: re-exec this server when its source changes (index.html is "
             "always read per request); pair with a bind mount of the source directory",
    )
    args = ap.parse_args()

    sys.stdout.reconfigure(line_buffering=True)  # banner shows when piped to a service log

    # The config is optional: the image bakes none and can run purely from the environment.
    # A present config still supplies [rpc] and the fee/info extras; an absent one just means
    # every value below falls back to its env var (or default).
    config, conf_label = load_config(args.conf)
    rpc = config.get("rpc", {})

    # Precedence for each value: explicit flag, then env, then the config, then a default -
    # matching how zecd itself lets ZECD_RPC_PASSWORD win over the file. The password keeps its
    # env-over-file rule and has no flag (a secret has no business on a command line).
    user = args.rpc_user or os.environ.get("ZECD_RPC_USER") or rpc.get("user", "")
    password = os.environ.get("ZECD_RPC_PASSWORD") or rpc.get("password", "")
    if not user or not password:
        sys.exit("no RPC credentials: set ZECD_RPC_USER and ZECD_RPC_PASSWORD (or [rpc] "
                 f"user/password in a mounted --conf; this run read {conf_label})")
    # The shipped configs carry a placeholder that zecd itself refuses to start on (every
    # network), so a proxy holding it can only ever fail auth: say so up front, the same way.
    if password.strip().lower() == "change-me":
        sys.exit("[rpc] password is still the CHANGE-ME placeholder; zecd refuses to start on "
                 "it - set ZECD_RPC_PASSWORD to the password the daemon runs with")

    # Where zecd listens. --rpc-url (or ZECD_RPC_URL) gives the whole base URL; otherwise it is
    # composed from host/port/scheme parts, each with the same flag > env > config > default
    # precedence. The parts exist for callers that have only a bare hostname to hand in - e.g. an
    # orchestrator service reference that cannot have a scheme/port string-composed onto it in the
    # deployment blueprint - so ZECD_RPC_HOST takes that reference and ZECD_RPC_PORT/SCHEME the
    # literals. The config's own [rpc] bind/port is the fallback (right when the proxy runs beside
    # the daemon; wrong from a container, where 127.0.0.1 is the container's own loopback).
    base = args.rpc_url or os.environ.get("ZECD_RPC_URL")
    if not base:
        host = args.rpc_host or os.environ.get("ZECD_RPC_HOST") or rpc.get("bind", "127.0.0.1")
        port = args.rpc_port or os.environ.get("ZECD_RPC_PORT") or rpc.get("port", 8232)
        scheme = (args.rpc_scheme or os.environ.get("ZECD_RPC_SCHEME") or "http").rstrip(":/")
        base = f"{scheme}://{host}:{port}"
    path = f"/wallet/{args.wallet}" if args.wallet else "/"
    Handler.upstream_url = base.rstrip("/") + path
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    Handler.auth_header = f"Basic {token}"

    # Optional: the fee estimate comes straight from bitcoind (zecd exposes none),
    # using the [bitcoind] user/password in the same config. Skipped if absent.
    bd = config.get("bitcoind", {})
    if bd.get("rpc_user") and bd.get("rpc_password"):
        Handler.bitcoind_url = args.bitcoind_url
        bd_token = base64.b64encode(f"{bd['rpc_user']}:{bd['rpc_password']}".encode()).decode()
        Handler.bitcoind_auth = f"Basic {bd_token}"

    # Which configuration the page is looking at, so it can say so. These feed the header AND
    # two behaviours in index.html: the network picks the unit label (BTC on mainnet, else tBTC)
    # and the backend picks the fee-rate source. Neither is exposed by a Bitcoin-wallet RPC, so
    # when no config is mounted they come from ZECD_NETWORK / ZECD_BACKEND instead - the same
    # values the config would have supplied. Precedence: env, then the config, then a default.
    wallet_name = args.wallet or config.get("default_wallet", "default")
    wallet_cfg = config.get("wallets", {}).get(wallet_name) or config.get(f"wallets.{wallet_name}") or {}
    srv = wallet_cfg.get("server") or bd.get("server")
    # Backend: read from the wallet's `server` token (nested under tomllib, flat
    # "wallets.<name>" under the fallback parser), else the global [bitcoind] server, else the
    # built-in default - unless ZECD_BACKEND overrides it (kyoto|bitcoind; anything else ignored).
    backend_env = (os.environ.get("ZECD_BACKEND") or "").strip().lower()
    if backend_env in ("kyoto", "bitcoind"):
        backend = backend_env
    else:
        backend = "kyoto" if (srv or "").lower().startswith("kyoto") else "bitcoind"
    net = os.environ.get("ZECD_NETWORK") or config.get("btc_testnet") or config.get("network") or "?"
    Handler.backend = backend
    Handler.fee_tiers = kyoto_fee_tiers(config, net)
    Handler.info_json = json.dumps({
        "conf": conf_label,
        "network": net,
        "wallet": wallet_name,
        "backend": backend,
        "server": srv or (f"{backend} (env)" if backend_env in ("kyoto", "bitcoind") else "bitcoind (default)"),
    }).encode()

    server = http.server.ThreadingHTTPServer((args.bind, args.port), Handler)
    if args.reload:
        watch_and_reexec(sorted(UI_DIR.glob("*.py")))
        print(f"reload: watching {UI_DIR} (index.html is read per request; a .py change re-execs)")
    print(f"UI:   http://{args.bind}:{args.port}/")
    cred_src = "environment" if os.environ.get("ZECD_RPC_PASSWORD") else conf_label
    print(f"zecd: {Handler.upstream_url}  (user={user!r}, credentials from {cred_src})")
    if backend == "kyoto":
        # The chain zecd would walk, annotated where this page differs from it: it can query
        # the HTTP oracles but not kyoto's peers, and a source with no instance on this
        # network is one zecd skips too.
        live = {source for source, _ in Handler.fee_tiers}
        def label(source):
            if source in live:
                return source
            if source == "peer_median":
                return "peer_median (no HTTP preview)"
            return f"{source} (skipped: no instance for {net})"
        chain = " -> ".join(
            label(source)
            for source in config.get("fees", {}).get("sources", DEFAULT_FEE_SOURCES)
        )
        print(f"fee:  {chain or '(no sources)'}  (the [fees] chain zecd walks at send time)")
    else:
        print(f"fee:  {Handler.bitcoind_url or '(no [bitcoind] creds; fee estimate disabled)'}")
    print(f"cfg:  {conf_label}  net={net}  wallet={wallet_name}  backend={backend}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
