FROM python:3.12-slim

WORKDIR /app

# Copy only what's needed: the Python server and HTML UI
COPY serve.py .
COPY index.html .

# Create a non-root user for security
RUN useradd -m -u 1000 zecd-ui

USER zecd-ui

# Expose the default UI port
EXPOSE 8080

# Default: serve testnet4, read config from /config/zecd.btc-testnet4.toml
# Override via: docker run ... -e ZECD_RPC_PASSWORD=... -v /path/to/config:/config
ENTRYPOINT ["python3", "serve.py"]
CMD ["--conf", "/config/zecd.btc-testnet4.toml", "--bind", "0.0.0.0", "--port", "8080"]
