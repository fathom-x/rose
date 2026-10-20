# rose Bitcoin UI - Docker Guide

This containerizes the lightweight Python dev server that proxies RPC requests to rose with server-side credential handling.

## Read this first: rose itself does not run in a container here

The `zecd` release images published up to 0.7.0 (`ghcr.io/zecrocks/zecd`) were built
**without** the `bitcoin` cargo feature, so they refuse `coin = "bitcoin"` at config
resolution and reject `[bitcoind]` as an unknown field. The images built from this tree and
from the public `fathom-x/rose` tree carry both engines (`ROSE_CARGO_FEATURES` defaults to
`--features mimalloc-secure,bitcoin`). The recipes below predate that and still run **rose on
the host** from your own `cargo build --release --features bitcoin`, with only the UI
containerised; a containerised daemon works the same way once pointed at a current image.

## Config file, or pure environment

`serve.py` can take every value from a mounted rose config, from the environment, or a mix -
each is resolved **flag > env > config > default**. So the image needs no config mounted at
all: point `--conf` at a path that isn't there and it is skipped (not an error), and the only
config-derived extras that fall away are the info panel's network/backend labels. The fee
estimate needs no config: the page asks rose's own `estimatesmartfee` through the proxy.

| Value | Flag | Env | Config |
|---|---|---|---|
| RPC user | `--rpc-user` | `ROSE_RPC_USER` | `[rpc] user` |
| RPC password | *(none - it's a secret)* | `ROSE_RPC_PASSWORD` | `[rpc] password` |
| Upstream URL (whole) | `--rpc-url` | `ROSE_RPC_URL` | - |
| Upstream host | `--rpc-host` | `ROSE_RPC_HOST` | `[rpc] bind` |
| Upstream port | `--rpc-port` | `ROSE_RPC_PORT` | `[rpc] port` |
| Upstream scheme | `--rpc-scheme` | `ROSE_RPC_SCHEME` | *(default `http`)* |

Env-only, nothing mounted:

```bash
docker run --rm -p 127.0.0.1:8080:8080 \
  -e ROSE_RPC_USER=view \
  -e ROSE_RPC_PASSWORD \
  -e ROSE_RPC_HOST=rose-btc \
  -e ROSE_RPC_PORT=18232 \
  -e ROSE_NETWORK=main \
  -e ROSE_BACKEND=kyoto \
  "$GUI_IMAGE" --bind 0.0.0.0
```

(`ROSE_NETWORK`/`ROSE_BACKEND` are optional - they only set the info panel's network/backend
labels and the BTC/tBTC unit; the RPC works without them.)

`ROSE_RPC_HOST`/`PORT`/`SCHEME` exist for callers that only have a **bare hostname** to hand in -
e.g. an orchestrator service reference (`fromService`) that can't have `http://` or a port
string-composed onto it in the deployment blueprint. Pass the reference as `ROSE_RPC_HOST` and
the port/scheme as literals; the proxy assembles `scheme://host:port`. When `ROSE_RPC_URL` (or
`--rpc-url`) is set it wins and the parts are ignored.

## The address problem, and `--rpc-url`

When you *do* mount a config, `serve.py` reads credentials *and* the upstream address from it.
The credentials travel into a container fine; the address does not. `[rpc] bind` is `127.0.0.1`,
which inside a container is the container's own loopback, so an unmodified run reaches
nothing and every call returns 502.

`--rpc-url` (env: `ROSE_RPC_URL`) overrides the address alone, keeping the config's
credentials (or compose the address from `ROSE_RPC_HOST`/`PORT`/`SCHEME` as above). Two
consequences worth knowing before you use `--rpc-url`:

- **The host must listen past loopback.** A container reaches the host on the bridge
  interface, not `127.0.0.1`. On a laptop, `--rpcbind 0.0.0.0` publishes the RPC to your LAN
  behind the RPC password - fine for valueless testnet coins. On an internet-facing server,
  bind the docker bridge gateway alone, which is what `host.docker.internal` resolves to:
  `--rpcbind 172.17.0.1` (confirm with
  `docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}'`). Neither shape is
  for mainnet.
- **`host.docker.internal` needs help on Linux.** Docker Desktop (macOS/Windows) provides it;
  elsewhere add `extra_hosts: ["host.docker.internal:host-gateway"]`, as the compose stacks do.

## Quick Start

### Preferred: the network compose stacks

`deploy/docker-compose.btc-testnet{3,4}.yml` already carry a `rose-gui` service wired this
way, and each carries its own comments on the config and port it expects. Prefer them over a
bare `docker run`.

```bash
# start rose on the host, reachable from the container
# The configs ship a CHANGE-ME placeholder that rose refuses to start on, so the password
# lives in the environment: once in deploy/.env for compose, once for the host daemon.
echo "ROSE_RPC_PASSWORD=$(openssl rand -base64 24)" > deploy/.env    # gitignored
export ROSE_RPC_PASSWORD=$(sed -n 's/^ROSE_RPC_PASSWORD=//p' deploy/.env)
# (the config names the datadir, ./data-btc-testnet4 relative to the repo root)
./target/release/rose --conf deploy/rose.btc-testnet4.toml --rpcbind 0.0.0.0

docker compose -f deploy/docker-compose.btc-testnet4.yml up -d
```

Then open http://127.0.0.1:8080/

### Mainnet: host network, nothing published

`deploy/docker-compose.btc-mainnet.yml` runs the UI on the **host network** instead. The
mainnet config binds rose's RPC to `127.0.0.1:8232`, and on the host network the container
reaches that address as-is, so there is no `--rpc-url`, no `host.docker.internal`, and no
`--rpcbind` past loopback on the daemon: the spend surface never leaves loopback. The UI
binds `127.0.0.1:8081` on the host (8081 so it can run beside the testnet4 stack's GUI on
8080; on the host network there is no port mapping to separate them); front it with a
reverse proxy for TLS and auth if it must be reachable remotely. Linux only.

```bash
cp deploy/.env.mainnet.example deploy/.env && $EDITOR deploy/.env    # one variable
export ROSE_RPC_PASSWORD=$(sed -n 's/^ROSE_RPC_PASSWORD=//p' deploy/.env)
./target/release/rose --conf deploy/rose.btc-mainnet.toml init --wallet btc   # once; record the mnemonic
./target/release/rose --conf deploy/rose.btc-mainnet.toml
docker compose -f deploy/docker-compose.btc-mainnet.yml up -d rose-gui
```

To keep the seed off the dashboard host entirely, run the UI against a **watch-only**
wallet: `rose export-xpub --wallet btc` on the spender, `rose init --xpub <key>` where the
dashboard runs. The page reads `getwalletinfo.private_keys_enabled`, announces the
watch-only wallet at the top, and disables its send form.

### The published image

The `Docker GUI` workflow (`.github/workflows/docker-gui.yml`) publishes this dashboard to GHCR
(multi-arch amd64+arm64), so you can pull it instead of building. Three ways to trigger it:
a `gui-v*` tag (e.g. `git tag gui-v0.0.0-test <sha> && git push origin gui-v0.0.0-test`)
publishes just the GUI and works from any branch; a real `v*` release tag ships it alongside a
release; and once the workflow is on the default branch, Actions -> Docker GUI -> Run workflow
(give it a version) does it on demand. The name is the main image's name with a `-gui` suffix, derived from the repository
the workflow runs in: `ghcr.io/fathom-x/rose-gui` from this tree. Use a
version tag, not a moving `latest` (none is published). Point `$GUI_IMAGE` at whichever applies
and the commands below run unchanged:

```bash
GUI_IMAGE=ghcr.io/fathom-x/rose-gui:<version>
docker pull "$GUI_IMAGE"
```

Everything below that says `rose-gui` (a locally-built tag) works the same against the pulled
image - substitute `"$GUI_IMAGE"`. The compose stacks still build from
`scripts/rose-gui/Dockerfile` (the same Dockerfile the image is published from) so their
`--reload` dev mount keeps working; to pull instead, replace a stack's `build:` block with
`image: <that name>:<version>`.

### One-off container against a host rose

Publish the port on loopback (`-p 127.0.0.1:8080:8080`, as below and as the compose stacks
do), never on every interface: the proxy holds the wallet's RPC credentials and forwards
`sendtoaddress`, `sendmany`, `bumpfee` and `abandontransaction`, so an interface-wide publish
hands the spend surface to the whole LAN. The
proxy itself refuses cross-origin browser requests and any method the page does not use,
but neither is a substitute for not exposing it.

```bash
# either pull the published image ($GUI_IMAGE from "The published image" above)...
docker run --rm -p 127.0.0.1:8080:8080 \
  -e ROSE_RPC_PASSWORD \
  -v $(pwd)/deploy:/config:ro \
  --add-host host.docker.internal:host-gateway \
  "$GUI_IMAGE" \
  --conf /config/rose.btc-testnet4-kyoto.toml \
  --bind 0.0.0.0 \
  --rpc-url http://host.docker.internal:48242

# ...or build it locally
cd scripts/rose-gui
docker build -t rose-gui .
docker run --rm -p 127.0.0.1:8080:8080 \
  -e ROSE_RPC_PASSWORD \
  -v $(pwd)/../../deploy:/config:ro \
  --add-host host.docker.internal:host-gateway \
  rose-gui \
  --conf /config/rose.btc-testnet4-kyoto.toml \
  --bind 0.0.0.0 \
  --rpc-url http://host.docker.internal:48242
```

### No container at all

The server is stdlib-only, so for local testing this is the shortest path and sidesteps the
address problem entirely:

```bash
ROSE_RPC_PASSWORD=... python3 scripts/rose-gui/serve.py --conf deploy/rose.btc-testnet4-kyoto.toml
```

## Configuration

### Environment Variables

See the resolution table under "Config file, or pure environment" above for how these layer
with the flags and the config.

- `ROSE_RPC_PASSWORD` - The RPC password. Effectively required: the shipped configs carry a
  `CHANGE-ME` placeholder that rose refuses to start on (every network) and that `serve.py`
  refuses for the same reason, so the daemon and the proxy each take the real value from this
  variable. It wins over `[rpc] password` in the file.
- `ROSE_RPC_USER` - The RPC username, overriding `[rpc] user`. Lets the image run with no
  config mounted (e.g. `view` for a watch-only wallet).
- `ROSE_RPC_URL` - The whole upstream base URL, overriding the composed one; wins over the
  host/port/scheme parts below.
- `ROSE_RPC_HOST` / `ROSE_RPC_PORT` / `ROSE_RPC_SCHEME` - Compose the upstream URL from parts
  when `ROSE_RPC_URL` is unset. `HOST` takes a bare hostname (an orchestrator service reference
  that can't have a scheme composed onto it); `SCHEME` defaults to `http`. They fall back to
  `[rpc] bind`/`port` from the config.
- `ROSE_NETWORK` - The network label for the info panel (`main`/`test`/`testnet3`/`testnet4`).
  Only cosmetic-ish: the page picks its unit from it (`BTC` on `main`/`mainnet`, else
  `tBTC`). Set it when running env-only, since no
  Bitcoin-wallet RPC reports the network; falls back to `[btc_testnet]`/`network` from the config.
- `ROSE_BACKEND` - `kyoto` or `bitcoind`, the chain backend the info panel shows. Set it env-only;
  falls back to detecting `kyoto` from the config's `server` token.
- `ROSE_GUI_MACHINE` - the name the page header shows for the machine the UI runs on (also
  `--machine`). Defaults to the hostname, which is the host's own name under host networking
  (the mainnet stack) but a random container id on a bridge network, so the testnet stacks
  pass it through from `deploy/.env`. The config file the proxy read is on the header's
  tooltip.

### Command-line Arguments

Pass arguments via the docker `CMD`:

```bash
docker run rose-gui \
  --conf /config/rose.btc-testnet3.toml \
  --port 8080 \
  --wallet btc
```

Full options:
- `--conf PATH` - rose config file (default: `/config/rose.btc-testnet4.toml`); skipped, not an
  error, when the path isn't present, so the image can run env-only
- `--bind ADDR` - Server bind address (default: `0.0.0.0` in container)
- `--port PORT` - Server port (default: `8080`)
- `--wallet NAME` - Route RPC via `/wallet/<name>` (default: default wallet)
- `--machine NAME` - the machine name the page header shows (env: `ROSE_GUI_MACHINE`; default: the hostname)
- `--rpc-user NAME` - rose RPC username, overriding `[rpc] user` (env: `ROSE_RPC_USER`)
- `--rpc-url URL` - whole rose JSON-RPC base URL, overriding the config's `[rpc]` bind/port (env: `ROSE_RPC_URL`)
- `--rpc-host HOST` / `--rpc-port PORT` / `--rpc-scheme SCHEME` - compose the base URL from parts
  when `--rpc-url` is unset (env: `ROSE_RPC_HOST`/`ROSE_RPC_PORT`/`ROSE_RPC_SCHEME`; scheme default `http`)
- `--bitcoind-url URL` - ignored, accepted so older deployments still start. The fee estimate
  is rose's own `estimatesmartfee` (the estimate a send would use), not a separate bitcoind call

## Networking

Whatever the topology, the rule is the same: credentials come from the config or the env, and
the upstream address from `--rpc-url` (or the `ROSE_RPC_HOST`/`PORT`/`SCHEME` parts, or the
config's `[rpc]` bind/port).

| Where rose runs | Address | Also needed |
|---|---|---|
| Host, UI in a container | `--rpc-url http://host.docker.internal:<rpc port>` | rose `--rpcbind 0.0.0.0`; `--add-host host.docker.internal:host-gateway` on Linux |
| A container on the same network | `--rpc-url http://<service name>:<rpc port>` | both on one Docker network; needs a `--features bitcoin` image (none published) |
| An orchestrator service ref (bare hostname) | `ROSE_RPC_HOST=<ref> ROSE_RPC_PORT=<port>` | no config mount needed; also set `ROSE_RPC_USER`/`ROSE_RPC_PASSWORD` |
| Host, UI also on the host | omit it | nothing - the config's `127.0.0.1` is already right |
| Host, UI in a container on the host network (mainnet) | omit it | `network_mode: host`, UI `--bind 127.0.0.1`; rose stays on loopback |

## Development

**Both compose stacks mount this directory over the image's `/app` and pass `--reload`**, so
an edit is live without a rebuild: `index.html` is read from disk on every request (reload
the page), and a change to `serve.py` makes the server re-exec itself in place (the
container's PID 1 survives, so compose sees no restart; the log says `reload: serve.py
changed; restarting`). The image still carries its own copy of both files, so a deployment
that must not track the checkout drops the mount and the flag and gets the shipped build.

A rebuild is only needed when the `Dockerfile` itself changes:

```bash
docker build -t rose-gui .
docker run --rm -p 127.0.0.1:8080:8080 \
  -v $(pwd)/../../deploy:/config:ro \
  --add-host host.docker.internal:host-gateway \
  rose-gui --bind 0.0.0.0 --rpc-url http://host.docker.internal:48232
```

Or rebuild through the stack that owns the service:

```bash
docker compose -f deploy/docker-compose.btc-testnet4.yml up -d --build rose-gui
```

For a fast edit loop, skip the image entirely and run `serve.py` directly - it has no
dependencies, so there is nothing to install.

## Troubleshooting

### "rose unreachable"

- Check that rose is running: `docker ps` or local `ps aux | grep rose`
- Verify the RPC password: `echo $ROSE_RPC_PASSWORD`
- Test the connection: `curl -u "btc:$ROSE_RPC_PASSWORD" http://localhost:48242/` (the kyoto config's port and user)

### "no RPC password" / "still the CHANGE-ME placeholder"

- Set the `ROSE_RPC_PASSWORD` environment variable to the password the host rose runs with
  (compose reads it from `deploy/.env`; the daemon needs it in its own environment)

### "fee estimate: none"

- rose had no estimate for the chosen target (a fresh regtest chain, or a test network whose
  node estimator has no usable data). A send without a fee rate then pays rose's 1 sat/vB
  test-network fallback, and is refused on mainnet: type a rate, or pick another target

### Port already in use

```bash
# Use a different port
docker run -p 127.0.0.1:9000:8080 rose-gui
# Then open http://127.0.0.1:9000/
```

## Production Notes

- This image runs as non-root user `rose-ui` (UID 1000) for security
- Credentials are passed via environment variables (not baked into the image)
- Use `--bind 0.0.0.0` in containers, but consider a reverse proxy (nginx, traefik) in production
- Mount the config as read-only (`:ro`) to prevent accidental modification
- On mainnet prefer `network_mode: host` with the UI bound to loopback over publishing the
  daemon's RPC past `127.0.0.1` (the mainnet compose file does this), and consider pointing
  the UI at a watch-only wallet so the dashboard host holds no seed
