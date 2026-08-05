# Upstream provenance

The application core was forked from:

- Repository: `https://github.com/wisflux/docmost-local-mcp`
- Commit: `0bb296068227c9d2eb4e83731806867c2b0b98f6`
- Upstream version: `0.9.2`
- License: MIT

Local hardening in version 1.0.0 adds authenticated MCP Streamable HTTP, current
`rmcp` 3.1.0 transport support, host/origin validation, headless environment-based
Docmost authentication, default-deny writes, per-call mutation confirmation,
metadata-only mutation auditing, keychain-first credential storage, Docker
packaging, and Codex plugin metadata.

The upstream npm launcher and its install-time binary download path are not included.
