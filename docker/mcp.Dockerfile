#
# Seren MCP Server - Production Dockerfile
# Multi-stage build for minimal final image
#
# Build: docker build -f docker/mcp.Dockerfile -t seren-mcp .
# Run:   docker run -p 8080:8080 seren-mcp
#

# ---------- Builder: compile Rust binary ----------
FROM rust:1.83-slim-trixie AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY api ./api
COPY cli ./cli
COPY mcp ./mcp

# Build release binary with telemetry feature for hosted deployment
RUN cargo build --release --package seren-mcp --features telemetry

# ---------- Runner: minimal runtime image ----------
FROM debian:trixie-slim AS runner

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3t64 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false seren

# Copy binary from builder
COPY --from=builder /app/target/release/seren-mcp /usr/local/bin/seren-mcp

# Use non-root user
USER seren

# Default port for HTTP mode
ENV PORT=8080
ENV RUST_LOG=seren_mcp=info,tower_http=info

EXPOSE 8080

# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD curl -sf http://localhost:${PORT}/health || exit 1

# Default to OAuth mode for hosted deployment
CMD ["seren-mcp", "start:oauth"]
