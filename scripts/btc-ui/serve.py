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


def read_rpc_config(conf_path):
    """Extract [rpc] bind/port/user/password from a zecd.toml.

    Uses tomllib when available (Python 3.11+); otherwise a line-based fallback
    that understands the flat key = value shape these deploy configs use (the
    macOS system python is 3.9, so the fallback matters).
    """
    text = Path(conf_path).read_text()
    try:
        import tomllib

        rpc = tomllib.loads(text).get("rpc", {})
    except ModuleNotFoundError:
        rpc = {}
        section = None
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            m = re.match(r"^\[(.+)\]$", line)
            if m:
                section = m.group(1)
                continue
            if section != "rpc":
                continue
            m = re.match(r'^(\w+)\s*=\s*(?:"([^"]*)"|(\d+))$', line)
            if m:
                rpc[m.group(1)] = m.group(2) if m.group(2) is not None else int(m.group(3))
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

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = (UI_DIR / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

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
    args = ap.parse_args()

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

    server = http.server.ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"UI:   http://{args.bind}:{args.port}/")
    print(f"zecd: {Handler.upstream_url}  (credentials from {args.conf})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
