FROM rust:1.96-slim-bookworm AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release --no-default-features

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --home-dir /var/lib/docmost-mcp --uid 10001 docmost-mcp
COPY --from=builder /build/target/release/docmost-mcp /usr/local/bin/docmost-mcp
USER 10001:10001
ENV DOCMOST_MCP_BIND=0.0.0.0:8787
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/docmost-mcp"]
