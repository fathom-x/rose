# The zecd wallet dashboard (scripts/zecd-gui): a stdlib-only same-origin proxy in front of
# zecd's RPC. Published to GHCR as `<repo>-gui` by the Release workflow's `docker-gui` job
# (multi-arch, semver-tagged), so it can be pulled like the main zecd image instead of built
# locally. The compose stacks also build it from this same Dockerfile, so the pulled image and
# a compose-built one are identical.
FROM python:3.12-slim

# Pick up the base image's security updates. The GUI has no dependencies of its own to
# install - it is stdlib Python - so this is the only apt work.
RUN apt-get update && apt-get upgrade -y && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only what's needed: the Python server and HTML UI.
COPY serve.py index.html ./

# Run as a non-root user.
RUN useradd -m -u 1000 zecd-ui
USER zecd-ui

# Liveness via the server's own /info endpoint. urllib, not curl: the slim image has no curl,
# so a compose-level curl healthcheck would only ever report unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/info', timeout=3)" || exit 1

# The default UI port.
EXPOSE 8080

# Default: serve testnet4, read config from /config/zecd.btc-testnet4.toml. Two ways to run:
#   - mount a config:  docker run ... -e ZECD_RPC_PASSWORD=... -v /path:/config ... --conf ... --rpc-url ...
#   - no config (env): docker run ... -e ZECD_RPC_USER=view -e ZECD_RPC_PASSWORD=... \
#                        -e ZECD_RPC_HOST=zecd-btc -e ZECD_RPC_PORT=18232 \
#                        [-e ZECD_NETWORK=main -e ZECD_BACKEND=kyoto for the info panel] ...
# A --conf path that isn't mounted is skipped, not an error - see serve.py's header.
ENTRYPOINT ["python3", "serve.py"]
CMD ["--conf", "/config/zecd.btc-testnet4.toml", "--bind", "0.0.0.0", "--port", "8080"]
