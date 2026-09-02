# zecd Bitcoin UI - Docker Guide

This containerizes the lightweight Python dev server that proxies RPC requests to zecd with server-side credential handling.

## Read this first: zecd itself does not run in a container here

The published `ghcr.io/zecrocks/zecd:latest` image is built **without** the `bitcoin` cargo
feature (both Dockerfiles pass only `--features mimalloc-secure`), so it refuses
`coin = "bitcoin"` at config resolution and rejects `[bitcoind]` as an unknown field. A
containerised zecd for a Bitcoin wallet needs an image built from source with
`--features bitcoin`; none is shipped. So in every recipe below, **zecd runs on the host**
from your own `cargo build --release --features bitcoin` and only the UI is containerised.

## The address problem, and `--rpc-url`

`serve.py` reads credentials *and* the upstream address from the mounted zecd config. The
credentials travel into a container fine; the address does not. `[rpc] bind` is `127.0.0.1`,
which inside a container is the container's own loopback, so an unmodified run reaches
nothing and every call returns 502.

`--rpc-url` (env: `ZECD_RPC_URL`) overrides the address alone, keeping the config's
credentials. Two consequences worth knowing before you use it:

- **The host must listen past loopback.** A container reaches the host on the bridge
  interface, not `127.0.0.1`, so start zecd with `--rpcbind 0.0.0.0`. That publishes its RPC
  to your LAN behind only the dev password - fine for valueless testnet coins, not for
  mainnet.
- **`host.docker.internal` needs help on Linux.** Docker Desktop (macOS/Windows) provides it;
  elsewhere add `extra_hosts: ["host.docker.internal:host-gateway"]`, as the compose stacks do.

## Quick Start

### Preferred: the network compose stacks

`deploy/docker-compose.btc-testnet{3,4}.yml` already carry a `zecd-gui` service wired this
way, and each carries its own comments on the config and port it expects. Prefer them over a
bare `docker run`.

```bash
# start zecd on the host, reachable from the container
# The configs ship a CHANGE-ME placeholder that zecd refuses to start on, so the password
# lives in the environment: once in deploy/.env for compose, once for the host daemon.
echo "ZECD_RPC_PASSWORD=$(openssl rand -base64 24)" > deploy/.env    # gitignored
export ZECD_RPC_PASSWORD=$(sed -n 's/^ZECD_RPC_PASSWORD=//p' deploy/.env)
# (the config names the datadir, ./data-btc-testnet4 relative to the repo root)
./target/release/zecd --conf deploy/zecd.btc-testnet4.toml --rpcbind 0.0.0.0

docker compose -f deploy/docker-compose.btc-testnet4.yml up -d
```

Then open http://127.0.0.1:8080/

### One-off container against a host zecd

```bash
cd scripts/zecd-gui
docker build -t zecd-gui .
docker run --rm -p 8080:8080 \
  -e ZECD_RPC_PASSWORD \
  -v $(pwd)/../../deploy:/config:ro \
  --add-host host.docker.internal:host-gateway \
  zecd-gui \
  --conf /config/zecd.btc-testnet4-kyoto.toml \
  --bind 0.0.0.0 \
  --rpc-url http://host.docker.internal:48242
```

### No container at all

The server is stdlib-only, so for local testing this is the shortest path and sidesteps the
address problem entirely:

```bash
ZECD_RPC_PASSWORD=... python3 scripts/zecd-gui/serve.py --conf deploy/zecd.btc-testnet4-kyoto.toml
```

## Configuration

### Environment Variables

- `ZECD_RPC_PASSWORD` - The RPC password. Effectively required: the shipped configs carry a
  `CHANGE-ME` placeholder that zecd refuses to start on (every network) and that `serve.py`
  refuses for the same reason, so the daemon and the proxy each take the real value from this
  variable. It wins over `[rpc] password` in the file.

### Command-line Arguments

Pass arguments via the docker `CMD`:

```bash
docker run zecd-gui \
  --conf /config/zecd.btc-testnet3.toml \
  --port 8080 \
  --wallet btc \
  --bitcoind-url http://127.0.0.1:48332
```

Full options:
- `--conf PATH` - zecd config file (default: `/config/zecd.btc-testnet4.toml`)
- `--bind ADDR` - Server bind address (default: `0.0.0.0` in container)
- `--port PORT` - Server port (default: `8080`)
- `--wallet NAME` - Route RPC via `/wallet/<name>` (default: default wallet)
- `--rpc-url URL` - zecd JSON-RPC address, overriding the config's `[rpc]` bind/port (env: `ZECD_RPC_URL`)
- `--bitcoind-url URL` - bitcoind RPC for fee estimates (default: `http://127.0.0.1:48332`)

## Networking

Whatever the topology, the rule is the same: the config supplies the credentials and
`--rpc-url` supplies the address.

| Where zecd runs | `--rpc-url` | Also needed |
|---|---|---|
| Host, UI in a container | `http://host.docker.internal:<rpc port>` | zecd `--rpcbind 0.0.0.0`; `--add-host host.docker.internal:host-gateway` on Linux |
| A container on the same network | `http://<service name>:<rpc port>` | both on one Docker network; needs a `--features bitcoin` image (none published) |
| Host, UI also on the host | omit it | nothing - the config's `127.0.0.1` is already right |

## Development

To rebuild after editing `serve.py` or `index.html`:

```bash
docker build -t zecd-gui .
docker run --rm -p 8080:8080 \
  -v $(pwd)/../../deploy:/config:ro \
  --add-host host.docker.internal:host-gateway \
  zecd-gui --bind 0.0.0.0 --rpc-url http://host.docker.internal:48232
```

Or rebuild through the stack that owns the service:

```bash
docker compose -f deploy/docker-compose.btc-testnet4.yml up -d --build zecd-gui
```

For a fast edit loop, skip the image entirely and run `serve.py` directly - it has no
dependencies, so there is nothing to install.

## Troubleshooting

### "zecd unreachable"

- Check that zecd is running: `docker ps` or local `ps aux | grep zecd`
- Verify the RPC password: `echo $ZECD_RPC_PASSWORD`
- Test the connection: `curl -u "btc:$ZECD_RPC_PASSWORD" http://localhost:48242/` (the kyoto config's port and user)

### "no RPC password" / "still the CHANGE-ME placeholder"

- Set the `ZECD_RPC_PASSWORD` environment variable to the password the host zecd runs with
  (compose reads it from `deploy/.env`; the daemon needs it in its own environment)

### "no [bitcoind] credentials"

- Fee estimates require bitcoind credentials in the config
- This is optional; the UI will still work without them

### Port already in use

```bash
# Use a different port
docker run -p 9000:8080 zecd-gui
# Then open http://127.0.0.1:9000/
```

## Production Notes

- This image runs as non-root user `zecd-ui` (UID 1000) for security
- Credentials are passed via environment variables (not baked into the image)
- Use `--bind 0.0.0.0` in containers, but consider a reverse proxy (nginx, traefik) in production
- Mount the config as read-only (`:ro`) to prevent accidental modification
