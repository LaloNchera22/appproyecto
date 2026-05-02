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

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /usr/src/sicbox/backend/target/release/sicbox .

# Create directory for the immutable ledger (RocksDB)
RUN mkdir -p /app/data/ledger

# The engine will listen on the Unix Domain Socket specified by ENV
CMD ["./sicbox"]
