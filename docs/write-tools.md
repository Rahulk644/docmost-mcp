# Write-tool safety contract

The server exposes ten mutation tools: `docmost_create_page`, `docmost_update_page`,
`docmost_duplicate_page`, `docmost_copy_page_to_space`, `docmost_move_page`, `docmost_move_page_to_space`,
`docmost_create_space`, `docmost_update_space`, `docmost_create_comment`, and `docmost_update_comment`.

All ten are default-deny. A mutation reaches Docmost only when both conditions are
true:

1. The operator starts the server with `DOCMOST_MCP_ENABLE_WRITES=true`.
2. The individual tool call includes `confirm: true` after the user reviews the
   exact target and proposed change.

Example:

```json
{
  "confirm": true,
  "space_id": "018f...uuid",
  "title": "Release Notes",
  "markdown": "- First stable release"
}
```

Before dispatch, the server writes an `authorized` metadata event to its audit
log. If that preflight audit cannot be written, the mutation is blocked. It then
records `succeeded` or `failed`; an outcome-log failure is reported to server logs
without falsely retrying a mutation that may already have completed.

Audit entries contain only timestamp, tool name, target ID/slug, and status. They
never contain Markdown bodies, passwords, or tokens.

Docmost permissions remain authoritative. Use a service account that can modify
only the spaces this MCP server is meant to manage.
