#
# Seren MCP Server - Production Dockerfile
#
# Build: docker build -f docker/mcp.Dockerfile -t seren-mcp .
# Run:   docker run -p 8080:8080 seren-mcp
#

# ---------- Builder ----------
FROM rust:latest AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY openapi ./openapi
COPY api ./api
COPY cli ./cli
COPY mcp ./mcp

# Build the unified CLI binary with hosted telemetry support
RUN cargo build --release --package seren-cli --features telemetry

# ---------- Runtime ----------
FROM debian:trixie-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 seren && \
    chown -R seren:seren /app

# Copy binary from builder
COPY --from=builder /app/target/release/seren /usr/local/bin/seren

USER seren

ENV PORT=8080
ENV RUST_LOG=seren_mcp=info,tower_http=info

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:${PORT}/readyz || exit 1

CMD ["seren", "mcp", "start:server"]
