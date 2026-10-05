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
values the page shows - the network (picks the BTC/tBTC unit) and the backend - then come
from ZECD_NETWORK and ZECD_BACKEND (kyoto|bitcoind). The fee estimate is zecd's own
`estimatesmartfee`, forwarded like any other call, so there is no fee logic here to keep
in step with the wallet.

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

    # a zecd inside a Caution enclave: every call rides an attested STEVE session
    ZECD_RPC_USER=btc ZECD_RPC_PASSWORD=... python3 scripts/zecd-gui/serve.py \
        --conf <deployment>/zecd.toml --rpc-url http://<enclave-ip>/ \
        --steve-pcrs <deployment>/.caution/trusted_hashes.json

Then open http://127.0.0.1:8080/.

Enclave mode (--steve-pcrs / ZECD_STEVE_PCRS): the enclave's RPC answers only through
STEVE, the attested end-to-end channel, so the proxy hands each call to `steve-cli`
(--steve-cli / ZECD_STEVE_CLI, default on PATH) with the PCR file the deployment's
runner committed; steve-cli verifies the enclave's attestation against it, opens a
session, sends the one request and prints the answer. About a second per call, which a
dashboard tolerates; a session per call is what the one-request CLI offers, and nothing
here keeps a key. The credentials still go in an Authorization header, inside the
encrypted channel.
"""

import argparse
import base64
import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
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
    comes from the environment and the config-derived extras (the info panel's network/backend
    labels) fall back to their defaults. A config that IS present is
    read as before. The label is what the banner and /info report as the config source.
    """
    if conf_path and Path(conf_path).exists():
        return read_config(conf_path), os.path.basename(conf_path)
    return {}, "(none)"


# The RPC methods index.html calls - the whole surface the proxy forwards. Everything else
# is refused before the credentials are attached: the page needs nothing more, and a proxy
# that forwarded any method would hand the wallet's full RPC (sendrawtransaction, the
# runtime wallet management, anything added later) to whatever could reach this port.
ALLOWED_METHODS = frozenset({
    "abandontransaction",
    "bumpfee",
    "estimatesmartfee",
    "getbalances",
    "getbestblockhash",
    "getblockcount",
    "getnewaddress",
    "getwalletinfo",
    "listdescriptors",
    "listreceivedbyaddress",
    "listtransactions",
    "listunspent",
    "sendmany",
    "sendtoaddress",
})


def machine_name(flag):
    """The name of the machine this proxy runs on, for the page header: the --machine flag,
    else ZECD_GUI_MACHINE, else the hostname. A container on a bridge network has a random
    container id for a hostname, which names nothing an operator would recognise, so the
    compose stacks pass ZECD_GUI_MACHINE through from deploy/.env; a host-network container
    (the mainnet stack) already sees the host's own name."""
    name = (flag or os.environ.get("ZECD_GUI_MACHINE") or "").strip()
    if name:
        return name
    host = socket.gethostname()
    if Path("/.dockerenv").exists() and re.fullmatch(r"[0-9a-f]{12}", host):
        return f"container {host} (set ZECD_GUI_MACHINE to name the host)"
    return host


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
    steve = None  # (steve-cli path, trusted-hashes file) in enclave mode, else None
    info_json = b"{}"  # which config this proxy is serving (set by main)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = (UI_DIR / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/info":
            self.relay(200, self.info_json)
        else:
            self.send_error(404)

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
        if self.steve:
            return self.relay_via_steve(body)
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

    def relay_via_steve(self, body):
        """One attested request through steve-cli. It prints the response body alone (no
        status line), so a JSON answer is relayed as 200 whatever zecd's HTTP status was -
        the page reads the JSON-RPC error object, not the status - and anything else is a
        502 naming steve-cli's complaint (a PCR mismatch, an unreachable enclave)."""
        cli, pcrs = self.steve
        try:
            out = subprocess.run(
                [cli, "--pcrs", pcrs, "-H", f"Authorization: {self.auth_header}",
                 "--json", body.decode("utf-8", "replace"), self.upstream_url],
                capture_output=True, timeout=120, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            return self.relay(502, rpc_error(-1, f"steve-cli failed to run: {e}"))
        answer = out.stdout.strip()
        try:
            json.loads(answer)
        except ValueError:
            # steve-cli's stderr starts with its trust verdict ("PCR trust: Pinned"), which is
            # not the failure; the complaint, if any, follows it. No complaint and no body is
            # zecd answering 401: the credentials, not the enclave.
            detail = [l for l in out.stderr.decode("utf-8", "replace").splitlines()
                      if l.strip() and not l.startswith("PCR trust:")]
            why = detail[-1] if detail else "the enclave answered with no body (credentials refused?)"
            self.log_error("steve-cli gave no JSON answer: %s", why)
            return self.relay(502, rpc_error(-1, f"enclave call failed: {why}"))
        self.relay(200, answer)

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
        "--machine",
        default="",
        help="the name the page header shows for the machine this proxy runs on (default: "
             "ZECD_GUI_MACHINE, else the hostname)",
    )
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
        "--steve-pcrs",
        default="",
        help="enclave mode: the deployment's trusted-hashes file (PCRs); every call then goes "
             "through steve-cli's attested session to --rpc-url. Env: ZECD_STEVE_PCRS",
    )
    ap.add_argument(
        "--steve-cli",
        default="",
        help="path to steve-cli for --steve-pcrs; default: steve-cli on PATH. Env: ZECD_STEVE_CLI",
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
        default="",
        help="ignored; kept so existing deployments still start. The fee estimate now comes "
             "from zecd's own estimatesmartfee, which is what a send uses",
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
    pcrs = args.steve_pcrs or os.environ.get("ZECD_STEVE_PCRS", "")
    if pcrs:
        if not os.path.isfile(pcrs):
            sys.exit(f"--steve-pcrs: no such file: {pcrs}")
        cli = args.steve_cli or os.environ.get("ZECD_STEVE_CLI", "") or shutil.which("steve-cli")
        if not cli or not os.path.isfile(cli):
            sys.exit("--steve-pcrs needs steve-cli (on PATH, --steve-cli, or ZECD_STEVE_CLI)")
        Handler.steve = (cli, pcrs)

    bd = config.get("bitcoind", {})

    # Which configuration the page is looking at, so it can say so. These feed the header, and
    # the network picks the unit label (BTC on mainnet, else tBTC). Neither is exposed by a
    # Bitcoin-wallet RPC, so
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
    Handler.info_json = json.dumps({
        "conf": conf_label,
        "machine": machine_name(args.machine),
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
    print("fee:  zecd's estimatesmartfee through /rpc (the same estimate a send uses)")
    print(f"cfg:  {conf_label}  net={net}  wallet={wallet_name}  backend={backend}  "
          f"machine={machine_name(args.machine)}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
