# Docmost MCP (authenticated HTTP)

This is a workspace-local Codex plugin and hardened fork of
[`wisflux/docmost-local-mcp`](https://github.com/wisflux/docmost-local-mcp). It exposes
20 Docmost tools over MCP Streamable HTTP while keeping the MCP gateway token and
Docmost credentials out of the plugin manifest.

It is not an official Docmost project. Docmost's official MCP endpoint remains an
Enterprise feature; this server is intended for self-hosted/Community deployments
that need a separately operated MCP bridge.

## Security defaults

- HTTP binds to `127.0.0.1:8787` unless explicitly changed.
- `/mcp` requires a Bearer token of at least 32 bytes.
- Host and Origin allowlists are enforced by the official Rust MCP SDK.
- `/health` is public and returns only service status.
- Mutating tools are disabled unless `DOCMOST_MCP_ENABLE_WRITES=true`.
- Every mutation also requires `confirm: true` in that individual tool call.
- Mutation metadata is appended to a mode-`0600` JSONL audit log; page and comment
  bodies are never logged.
- Docmost credentials come from environment variables or the OS keychain. The
  encrypted-file credential fallback is opt-in.

## Start locally

Rust 1.88 or newer is required.

```bash
cd "/Users/rahulkhatri/PREP Documentation/docmost-mcp"
export DOCMOST_BASE_URL="https://docs.example.com"
export DOCMOST_API_TOKEN="your-docmost-api-token"
export DOCMOST_MCP_BEARER_TOKEN="$(openssl rand -hex 32)"
cargo run --locked --release
```

For Docmost Community Edition, which may not provide API tokens, use a dedicated
least-privilege Docmost account instead:

```bash
export DOCMOST_EMAIL="mcp-service-account@example.com"
export DOCMOST_PASSWORD="use-a-secret-manager"
```

Do not set both authentication modes. The API token takes precedence when present.

Check the server:

```bash
curl http://127.0.0.1:8787/health
curl -i http://127.0.0.1:8787/mcp
```

The second request should return `401 Unauthorized` without the Bearer token.

The included `.mcp.json` makes Codex connect to
`http://127.0.0.1:8787/mcp` and read the MCP Bearer token from
`DOCMOST_MCP_BEARER_TOKEN`.

## Docker

```bash
cp .env.example .env
# Generate the MCP token; do not leave DOCMOST_MCP_BEARER_TOKEN empty.
# Edit .env with the generated token and real Docmost credentials, then:
docker compose -f docker-compose.example.yml up --build
```

The Compose example publishes only to the host loopback interface. For a remote
deployment, terminate TLS in a reverse proxy, bind deliberately, and set exact
`DOCMOST_MCP_ALLOWED_HOSTS` and `DOCMOST_MCP_ALLOWED_ORIGINS` values. Never expose
plain HTTP or use wildcard allowlists on an untrusted network.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `DOCMOST_BASE_URL` | required | Docmost origin, such as `https://docs.example.com` |
| `DOCMOST_API_TOKEN` | — | Preferred Docmost API token |
| `DOCMOST_EMAIL`, `DOCMOST_PASSWORD` | — | CE fallback; both must be set |
| `DOCMOST_MCP_BEARER_TOKEN` | required | Secret used by clients to authenticate to `/mcp` |
| `DOCMOST_MCP_BIND` | `127.0.0.1:8787` | HTTP listen address |
| `DOCMOST_MCP_ALLOWED_HOSTS` | loopback host/port values | Comma-separated Host allowlist |
| `DOCMOST_MCP_ALLOWED_ORIGINS` | loopback origins | Comma-separated browser Origin allowlist |
| `DOCMOST_MCP_ENABLE_WRITES` | `false` | Enables mutation calls; calls still require `confirm: true` |
| `DOCMOST_MCP_AUDIT_LOG` | `~/.docmost-local-mcp/mutations.jsonl` | Mutation audit file |
| `DOCMOST_ALLOW_FILE_CREDENTIALS` | `false` | Opts into encrypted-file credential fallback |

The legacy stdio transport remains available for development with
`--transport stdio`; its first-time interactive login opens the system browser.
HTTP is the default.

## Tool surface

Read tools: list/search spaces and pages, fetch pages/comments/current user, and
list workspace members.

Write tools: create/update/duplicate/copy/move pages, create/update spaces, and
create/update comments. See [docs/write-tools.md](docs/write-tools.md) for the
guardrails and confirmation contract.

## Verification

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
python3 /Users/rahulkhatri/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py .
```

See [UPSTREAM.md](UPSTREAM.md) for provenance and [SECURITY.md](SECURITY.md) for
deployment boundaries.
