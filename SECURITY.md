# Security policy and deployment boundary

The MCP gateway Bearer token and the Docmost credential are different secrets.
Use independent high-entropy values and rotate them independently.

## Supported boundary

The default configuration is for a single machine: loopback HTTP, exact Host and
Origin allowlists, and a local Codex client. If traffic leaves the machine, put the
server behind an HTTPS reverse proxy or private authenticated overlay network. The
Rust process intentionally does not terminate TLS.

Use a dedicated Docmost account with the smallest space permissions needed. Keep
writes disabled unless an operator needs them. MCP clients must show the exact
mutation to the user before sending `confirm: true`.

## Secret handling

- Never commit `.env`; it is ignored by Git.
- Prefer a secret manager or container orchestrator secret injection.
- Prefer `DOCMOST_API_TOKEN` when your Docmost edition supports it.
- Email/password authentication does not persist the password when supplied via
  environment variables.
- OS-keychain persistence is preferred for interactive stdio mode. File fallback
  requires `DOCMOST_ALLOW_FILE_CREDENTIALS=true`.

The audit log records timestamp, operation, target identifier, and status only.
It deliberately excludes page content, comment content, passwords, and tokens.

## Reporting

This is a local fork rather than an upstream-supported release. Treat findings in
the upstream logic separately from findings in the HTTP/plugin hardening layer.
