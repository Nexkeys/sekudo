# sekudo-mcp (Node)

The Node/TypeScript build of [Sekudo](https://github.com/Nexkeys/sekudo), a
scope-gated DAST exploitation MCP server. Same 34 OWASP-mapped checks as the
Python edition, packaged so any MCP host can run it with `npx`, no clone, no
virtualenv, no pip.

## Add it in your IDE's connector form

For a host with an "Add connector" form (Local / STDIO), fill it in like this:

```
Name:      sekudo
Command:   npx
Arguments: -y sekudo-mcp@0.1.0
Environment variables (one per line):
  SEKUDO_AUTHORIZED=true
  SEKUDO_TARGETS=localhost,127.0.0.1
```

Click Add, enable the server, and the host gets four tools: `about`,
`list_checks`, `check_scope`, `scan`. Pin the version (`sekudo-mcp@0.1.0`) so a
future release never changes under you.

### Are the env vars optional?

Adding the server works without them, but **scanning does not**. `SEKUDO_AUTHORIZED`
and `SEKUDO_TARGETS` are how you declare your fence, and every user sets them to
their own hosts. Leave them out and the server still connects and `list_checks`
works, but `check_scope` reports `NOT READY` and `scan` refuses every target. So
treat those two as required. Everything else in the table below is optional and
has a sensible default.

Published on npm: https://www.npmjs.com/package/sekudo-mcp

## Or as raw MCP JSON

```json
{
  "mcpServers": {
    "sekudo": {
      "command": "npx",
      "args": ["-y", "sekudo-mcp@0.1.0"],
      "env": {
        "SEKUDO_AUTHORIZED": "true",
        "SEKUDO_TARGETS": "localhost,127.0.0.1"
      }
    }
  }
}
```

## Scope config (the fence)

Sekudo only tests hosts you declare. Configure it entirely through env vars, so
the connector form alone is enough:

| Variable | Meaning | Required | Default |
|---|---|---|---|
| `SEKUDO_AUTHORIZED` | Must be `true`. Your attestation that the targets are yours to test. | Yes, to scan | `false` |
| `SEKUDO_TARGETS` | Comma-separated allowlist. Exact host, `*.suffix`, or IPv4 CIDR. | Yes, to scan | (empty) |
| `SEKUDO_MAX_REQUESTS` | Per-scan request budget. | No | `2000` |
| `SEKUDO_RPS` | Requests per second ceiling. | No | `20` |
| `SEKUDO_ALLOW_PRIVATE` | Allow RFC1918 / loopback targets. | No | `true` |
| `SEKUDO_CONFIG` | Path to a JSON config instead of env vars (same keys, snake_case). | No | (unset) |
| `SEKUDO_REPORT_DIR` | Where scan reports are written. | No | `reports` |

Anything not in `SEKUDO_TARGETS` is refused.

Prefer a file over typing env vars each time? Copy
[`sekudo.config.example.json`](sekudo.config.example.json) to
`sekudo.config.json`, edit it, and set `SEKUDO_CONFIG` to its absolute path. That
one variable then replaces `SEKUDO_AUTHORIZED` and `SEKUDO_TARGETS`.

## Run from a local checkout (for development)

```bash
git clone https://github.com/Nexkeys/sekudo.git
cd sekudo/node
npm install
npm run build
node dist/index.js --selftest   # prints the 34 checks
```

Then point the connector at it:

```json
{
  "mcpServers": {
    "sekudo": {
      "command": "node",
      "args": ["/absolute/path/to/sekudo/node/dist/index.js"],
      "env": { "SEKUDO_AUTHORIZED": "true", "SEKUDO_TARGETS": "localhost" }
    }
  }
}
```

## Using it

Prompts the host model understands once connected:

> "Check if `localhost:3000` is in scope, then run a full sekudo scan and summarize the criticals."

> "Run only the injection and auth checks against `staging.myapp.com`."

`scan` writes a timestamped Markdown + JSON report to `SEKUDO_REPORT_DIR`.

## Maintainer: publishing to npm

```bash
cd node
npm login
npm publish --access public
```

`prepublishOnly` builds first. Bump `version` in `package.json` for each release
and keep the connector `Arguments` pinned to the new version.

## License

MIT. You are responsible for using Sekudo only against systems you are
authorized to test.
