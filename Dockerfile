# Stage 1: Build the Rust Backend
FROM rust:1.82-slim as builder

# Install system dependencies for RocksDB and Rust compilation
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libclang-dev \
    make \
    g++ \
    libssl-dev \
    pkg-config

WORKDIR /usr/src/sicbox

# Copy the entire monorepo to have access to backend/ and frontend/
COPY . .

# Build the backend in release mode
RUN cd backend && cargo build --release

# Stage 2: Final Runtime Image
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

# Dedicated non-root user; static UID/GID for predictable volume ownership.
RUN groupadd -r -g 1001 appuser && useradd -r -u 1001 -g appuser -s /bin/false appuser

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /usr/src/sicbox/backend/target/release/sicbox .

# Pre-create directories and assign ownership so the named volumes
# (app_socket_dir, app_data) are initialised with the correct owner when
# first mounted.  Without this, Docker initialises them as root:root and
# the non-root process cannot write to them.
RUN mkdir -p /app/data/ledger /var/run/app \
 && chown -R appuser:appuser /app /var/run/app

USER appuser

# The engine will listen on the Unix Domain Socket specified by ENV
CMD ["./sicbox"]
