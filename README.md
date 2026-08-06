# Docmost MCP

[![CI](https://github.com/Rahulk644/docmost-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Rahulk644/docmost-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An MCP server that lets AI agents read and manage a [Docmost](https://docmost.com)
workspace — search, read, create, and organise pages, spaces and comments — over
authenticated **MCP Streamable HTTP**.

Docmost's own MCP endpoint is an **Enterprise** feature. This is an independent
server built for **self-hosted and Community** deployments that want agent access
without an enterprise licence. It is not affiliated with Docmost.

**Security is the point of this project**: writes are off by default, the gateway
token and your Docmost credentials never live in a client manifest, and the HTTP
surface authenticates every request.

## Works with any MCP client

MCP is one protocol, so this is **one server** — not a different build per client.
Only the config file differs.

| Client | Config |
| --- | --- |
| Claude Code | `claude mcp add --transport http docmost http://127.0.0.1:8787/mcp --header "Authorization: Bearer $DOCMOST_MCP_BEARER_TOKEN"` |
| Claude Desktop | add an `mcpServers` entry pointing at `http://127.0.0.1:8787/mcp` |
| Codex | uses the bundled [`.codex-plugin/plugin.json`](.codex-plugin/plugin.json) → [`.mcp.json`](.mcp.json) |
| Cursor | `.cursor/mcp.json`, same URL and header |

The bearer token is read from the `DOCMOST_MCP_BEARER_TOKEN` environment variable
rather than written into any manifest, so the manifests are safe to commit.

## Quick start

Rust 1.88 or newer.

```bash
git clone https://github.com/Rahulk644/docmost-mcp.git
cd docmost-mcp

export DOCMOST_BASE_URL="https://docs.example.com"
export DOCMOST_API_TOKEN="your-docmost-api-token"
export DOCMOST_MCP_BEARER_TOKEN="$(openssl rand -hex 32)"

cargo run --locked --release
```

Docmost **Community Edition** may not issue API tokens. Use a dedicated,
least-privilege Docmost account instead:

```bash
export DOCMOST_EMAIL="mcp-service-account@example.com"
export DOCMOST_PASSWORD="use-a-secret-manager"
```

Do not set both modes — the API token wins when present.

Verify:

```bash
curl http://127.0.0.1:8787/health
curl -i http://127.0.0.1:8787/mcp   # expect 401 without the Bearer token
```

## Tools

All tools are prefixed `docmost_` so they never collide with other MCP servers
loaded alongside this one.

**Read** — `docmost_list_spaces`, `docmost_get_space`, `docmost_search_docs`,
`docmost_search_pages`, `docmost_get_page`, `docmost_list_pages`,
`docmost_list_child_pages`, `docmost_get_comments`,
`docmost_list_workspace_members`, `docmost_get_current_user`

**Write** — `docmost_create_page`, `docmost_update_page`, `docmost_duplicate_page`,
`docmost_copy_page_to_space`, `docmost_move_page`, `docmost_move_page_to_space`,
`docmost_create_space`, `docmost_update_space`, `docmost_create_comment`,
`docmost_update_comment`

Write tools are gated twice — see [docs/write-tools.md](docs/write-tools.md) for the
confirmation contract.

### Pagination

List tools accept `limit` and `cursor`, and their output states how many results
were shown, the total when the server reports one, and **the exact cursor to pass
next**. Where the server gives no signal either way, the output says the next page
is *unknown* rather than guessing — so an agent never concludes it has everything
when it hasn't, and never pages forever off a bad inference.

## Security defaults

- Binds to `127.0.0.1:8787` unless changed.
- `/mcp` requires a Bearer token of at least 32 bytes; comparison is constant-time,
  and obvious placeholder tokens are rejected outright.
- Host and Origin allowlists are enforced (DNS-rebinding protection).
- `/health` is public and returns only service status.
- **Mutating tools are disabled** unless `DOCMOST_MCP_ENABLE_WRITES=true`, *and*
  every mutation additionally requires `confirm: true` in that individual call.
- Mutation *metadata* is appended to a mode-`0600` JSONL audit log. Page and comment
  bodies are never logged.
- Credentials come from environment variables or the OS keychain. The
  encrypted-file fallback is opt-in.

See [SECURITY.md](SECURITY.md) for deployment boundaries and how to report issues.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `DOCMOST_BASE_URL` | required | Docmost origin, e.g. `https://docs.example.com` |
| `DOCMOST_API_TOKEN` | — | Preferred Docmost API token |
| `DOCMOST_EMAIL`, `DOCMOST_PASSWORD` | — | Community-edition fallback; both must be set |
| `DOCMOST_MCP_BEARER_TOKEN` | required | Secret clients use to authenticate to `/mcp` |
| `DOCMOST_MCP_BIND` | `127.0.0.1:8787` | HTTP listen address |
| `DOCMOST_MCP_ALLOWED_HOSTS` | loopback | Comma-separated Host allowlist |
| `DOCMOST_MCP_ALLOWED_ORIGINS` | loopback | Comma-separated browser Origin allowlist |
| `DOCMOST_MCP_ENABLE_WRITES` | `false` | Enables mutations; calls still require `confirm: true` |
| `DOCMOST_MCP_AUDIT_LOG` | `~/.docmost-local-mcp/mutations.jsonl` | Mutation audit file |
| `DOCMOST_ALLOW_FILE_CREDENTIALS` | `false` | Opts into the encrypted-file credential fallback |

> The on-disk state directory is still `~/.docmost-local-mcp/`, retained from before
> this project was renamed so existing credentials and audit logs are not orphaned.

A stdio transport is available for local development via `--transport stdio`; its
first-run interactive login opens the system browser. HTTP is the default.

## Docker

```bash
cp .env.example .env
# Generate a token — never leave DOCMOST_MCP_BEARER_TOKEN empty:
#   openssl rand -hex 32
docker compose -f docker-compose.example.yml up --build
```

The example Compose file publishes to the host loopback interface only. For a
remote deployment: terminate TLS in a reverse proxy, bind deliberately, and set
exact `DOCMOST_MCP_ALLOWED_HOSTS` / `DOCMOST_MCP_ALLOWED_ORIGINS`. Never expose
plain HTTP or wildcard allowlists on an untrusted network.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

CI runs all three on every push and pull request, plus a dependency-advisory audit.
Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Credits

The application core began as a fork of
[`wisflux/docmost-local-mcp`](https://github.com/wisflux/docmost-local-mcp) (MIT).
This project has since diverged substantially — authenticated Streamable HTTP on
`rmcp` 3.1.0, host/origin validation, headless environment-based authentication,
default-deny writes with per-call confirmation, mutation auditing, keychain-first
credential storage, prefixed tools, pagination metadata, Docker packaging, and CI.
The upstream npm launcher and its install-time binary download are deliberately not
carried over; this builds from source instead.

[UPSTREAM.md](UPSTREAM.md) records the exact upstream commit. See
[CHANGELOG.md](CHANGELOG.md) for what changed since.

## License

[MIT](LICENSE).
