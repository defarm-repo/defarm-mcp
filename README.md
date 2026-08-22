# @defarm/mcp

MCP server for [DeFarm](https://defarm.net) — lets an AI agent **seal, open, verify and ingest**
verifiable agri-traceability data by description, no code required. Built on
[`@defarm/sdk`](https://github.com/defarm-repo/defarm-sdk-ts): sealed fields are encrypted
client-side and the DeFarm server is **structurally blind** to them.

> Open source (MIT) for the same reason the SDK is: don't trust DeFarm — audit the client.

## Security posture (the part to read first)

- **Credentials never flow through the model.** Auth is server configuration (environment
  variables below). There is no login tool; no tool accepts a password, API key, or key
  material — and the test suite enforces that.
- **Private keys never leave the local keystore.** No tool returns private material; the agent
  sees ids and fingerprints only.
- **Safe defaults are inherited from the SDK**: sealing is private and self-addressed unless
  explicitly addressed; the crypto suite is fixed, never a choice.

## Setup

```jsonc
// e.g. Claude Desktop / Claude Code MCP config
{
  "mcpServers": {
    "defarm": {
      "command": "npx",
      "args": ["-y", "github:defarm-repo/defarm-mcp"],
      "env": {
        "DEFARM_GATEWAY": "<your test-environment gateway>",
        "DEFARM_EMAIL": "<workspace login>",
        "DEFARM_PASSWORD": "<workspace password>",
        "DEFARM_API_KEY": "<partner key, only if the agent should ingest>",
        "DEFARM_KEYSTORE": "~/.defarm/keys.json"
      }
    }
  }
}
```

Point `DEFARM_GATEWAY` at a **test environment** first; production is an explicit decision.

## Tools

| Tool | What it does |
|---|---|
| `defarm_whoami` | user + workspace of the configured credentials |
| `defarm_ensure_keys` | generate (locally) + register the workspace key pairs — returns ids/fingerprints only |
| `defarm_export_recipient` | export this workspace's public recipient bundle for out-of-band sharing |
| `defarm_ingest` | partner ingestion, with `preview` dry-run |
| `defarm_seal` | seal a field for addressed recipients — DeFarm stays blind; bindings re-verified |
| `defarm_open` | decrypt a sealed field locally; authorship re-verified locally |
| `defarm_verify` | public verification (anchor, RFC3161, sealed commitments) — no account needed |
| `defarm_get_item` / `defarm_get_item_public` | membership-gated / public reads (uniform 404) |
| `defarm_resolve_identifier` | resolve by SISBOV/chip/… |

Blocked-on-backend operations (`grant`, `grantLink`, `revoke` — engines#584/#574) are NOT
exposed as tools: an agent should not see tools that always fail.

## Development

**Dependency:** `@defarm/sdk` via semver (`^0.2.0`) from npm — the SHA-pin era (and its
"pin follows the latest SDK squash" rule) ended with the 0.2.0 publish, as promised.


```bash
npm install
npm test        # tool-table contract tests (no network, fake gateway)
npm run build && DEFARM_GATEWAY=... node dist/index.js   # stdio server
```

## License

[MIT](LICENSE)
