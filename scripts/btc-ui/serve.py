#!/usr/bin/env python3
"""Tiny same-origin dev UI server for zecd's Bitcoin wallet RPC.

zecd speaks bitcoind's RPC dialect on purpose: HTTP Basic auth, no CORS headers. A
browser page therefore cannot call it cross-origin, and the RPC password has no
business living in browser JS. This server closes both gaps the way every bitcoind
dashboard does: it serves the static page AND forwards POST /rpc to zecd with the
credentials injected server-side, so the page and the RPC share one origin.

Stdlib only, no dependencies. Credentials and the upstream port are read from the
zecd config file itself (default: deploy/zecd.btc-testnet4.toml), so there is no
second copy of the password to keep in sync; ZECD_RPC_PASSWORD in the environment
wins over the file, with the same precedence zecd gives it.

Usage, from the repository root:

    python3 scripts/btc-ui/serve.py                      # testnet4 stack defaults
    python3 scripts/btc-ui/serve.py --conf deploy/zecd.btc-testnet3.toml --port 8081
    python3 scripts/btc-ui/serve.py --wallet btc         # route via /wallet/<name>

Then open http://127.0.0.1:8080/.
"""

import argparse
import base64
import http.server
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

UI_DIR = Path(__file__).resolve().parent


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


def read_rpc_config(conf_path):
    """The [rpc] bind/port/user/password zecd exposes its own RPC on."""
    rpc = read_config(conf_path).get("rpc", {})
    return {
        "bind": rpc.get("bind", "127.0.0.1"),
        "port": rpc.get("port", 8232),
        "user": rpc.get("user", ""),
        "password": rpc.get("password", ""),
    }


class Handler(http.server.BaseHTTPRequestHandler):
    # Filled in by main() before the server starts.
    upstream_url = None
    auth_header = None
    bitcoind_url = None  # None if no [bitcoind] creds were found
    bitcoind_auth = None
    backend = "bitcoind"  # "bitcoind" | "kyoto", from the config
    mempool_base = None  # mempool.space base URL for this network, for a kyoto estimate
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
            sat_per_vb = round(result["feerate"] * 1e5, 3)
            out = {"sat_per_vb": sat_per_vb, "source": "estimatesmartfee", "blocks": result.get("blocks")}
        else:
            out = {"sat_per_vb": 1.0, "source": "fallback"}  # test-network floor
        self.relay(200, json.dumps(out).encode())

    def serve_feerate_kyoto(self):
        """A kyoto wallet prices from mempool.space first (btc/fees.rs), then a peer-derived
        recent-block median. The page can't see the peer path, but it can query the same
        mempool.space instance the wallet prefers - the closest honest preview of what a
        kyoto send would cost. If it's unreachable, say so and name the block-median fallback
        the wallet uses instead."""
        if not self.mempool_base:
            return self.relay(200, json.dumps(
                {"note": "kyoto prices at send time from mempool.space + recent-block medians"}).encode())
        url = self.mempool_base + "/api/v1/fees/recommended"
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                f = json.loads(resp.read())
        except (urllib.error.HTTPError, OSError, ValueError) as e:
            return self.relay(200, json.dumps(
                {"note": f"mempool.space unreachable ({e}); kyoto falls back to a recent-block median"}).encode())
        # hourFee is the ~6-block/~1-hour target zecd's kyoto path actually reads
        # (src/btc/fees.rs), so preview that field, not the faster (pricier) ones.
        sat = f.get("hourFee") or f.get("halfHourFee") or f.get("minimumFee")
        self.relay(200, json.dumps({"sat_per_vb": sat, "source": "mempool.space hourFee"}).encode())

    def do_POST(self):
        if self.path != "/rpc":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
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

    def log_message(self, fmt, *args):
        pass  # keep the terminal quiet; errors surface in the page


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--conf", default="deploy/zecd.btc-testnet4.toml", help="zecd config to read [rpc] from")
    ap.add_argument("--bind", default="127.0.0.1", help="address to serve the UI on")
    ap.add_argument("--port", type=int, default=8080, help="port to serve the UI on")
    ap.add_argument("--wallet", default="", help="route RPCs via /wallet/<name> (empty = default wallet)")
    ap.add_argument(
        "--bitcoind-url",
        default="http://127.0.0.1:48332",
        help="bitcoind JSON-RPC for the fee estimate (default testnet4 48332; uses [bitcoind] creds)",
    )
    args = ap.parse_args()

    sys.stdout.reconfigure(line_buffering=True)  # banner shows when piped to a service log
    rpc = read_rpc_config(args.conf)
    # Same precedence as zecd itself: ZECD_RPC_PASSWORD wins over [rpc] password in the
    # file, so a daemon started with the env var and a config carrying only CHANGE-ME
    # shares the one credential with this proxy.
    password = os.environ.get("ZECD_RPC_PASSWORD") or rpc["password"]
    if not rpc["user"] or not password:
        sys.exit(f"no RPC password: set ZECD_RPC_PASSWORD or [rpc] password in {args.conf}")
    path = f"/wallet/{args.wallet}" if args.wallet else "/"
    Handler.upstream_url = f"http://{rpc['bind']}:{rpc['port']}{path}"
    token = base64.b64encode(f"{rpc['user']}:{password}".encode()).decode()
    Handler.auth_header = f"Basic {token}"

    config = read_config(args.conf)

    # Optional: the fee estimate comes straight from bitcoind (zecd exposes none),
    # using the [bitcoind] user/password in the same config. Skipped if absent.
    bd = config.get("bitcoind", {})
    if bd.get("rpc_user") and bd.get("rpc_password"):
        Handler.bitcoind_url = args.bitcoind_url
        bd_token = base64.b64encode(f"{bd['rpc_user']}:{bd['rpc_password']}".encode()).decode()
        Handler.bitcoind_auth = f"Basic {bd_token}"

    # Which configuration the page is looking at, so it can say so. The backend is read
    # from the wallet's `server` token (nested under tomllib, flat "wallets.<name>" under
    # the fallback parser), else the global [bitcoind] server, else the built-in default.
    wallet_name = args.wallet or config.get("default_wallet", "default")
    wallet_cfg = config.get("wallets", {}).get(wallet_name) or config.get(f"wallets.{wallet_name}") or {}
    srv = wallet_cfg.get("server") or bd.get("server")
    backend = "kyoto" if (srv or "").lower().startswith("kyoto") else "bitcoind"
    net = config.get("btc_testnet") or config.get("network") or "?"
    Handler.backend = backend
    # mempool.space instance per network, for the kyoto fee estimate (kyoto's own source).
    Handler.mempool_base = {
        "testnet4": "https://mempool.space/testnet4",
        "testnet3": "https://mempool.space/testnet",
        "test": "https://mempool.space/testnet",
        "mainnet": "https://mempool.space",
        "main": "https://mempool.space",
    }.get(net)
    Handler.info_json = json.dumps({
        "conf": os.path.basename(args.conf),
        "network": net,
        "wallet": wallet_name,
        "backend": backend,
        "server": srv or "bitcoind (default)",
    }).encode()

    server = http.server.ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"UI:   http://{args.bind}:{args.port}/")
    print(f"zecd: {Handler.upstream_url}  (credentials from {args.conf})")
    print(f"fee:  {Handler.bitcoind_url or '(no [bitcoind] creds; fee estimate disabled)'}")
    print(f"cfg:  {os.path.basename(args.conf)}  net={net}  wallet={wallet_name}  backend={backend}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
