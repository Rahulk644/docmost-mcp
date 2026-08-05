# Contributing

The default build is headless and serves authenticated Streamable HTTP.

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --release
```

Legacy interactive stdio authentication opens the system browser. HTTP
deployments should use environment-injected Docmost credentials.

Keep the upstream provenance in `UPSTREAM.md` current when importing changes.
Do not reintroduce install-time binary downloads without cryptographic checksum
verification and a pinned release provenance chain.
