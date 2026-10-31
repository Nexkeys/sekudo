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

> This only resolves once the package is published to npm. Until then, use the
> "run from the repo" option below.

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

| Variable | Meaning | Default |
|---|---|---|
| `SEKUDO_AUTHORIZED` | Must be `true`. Your attestation that the targets are yours to test. | `false` |
| `SEKUDO_TARGETS` | Comma-separated allowlist. Exact host, `*.suffix`, or IPv4 CIDR. | (empty) |
| `SEKUDO_MAX_REQUESTS` | Per-scan request budget. | `2000` |
| `SEKUDO_RPS` | Requests per second ceiling. | `20` |
| `SEKUDO_ALLOW_PRIVATE` | Allow RFC1918 / loopback targets. | `true` |
| `SEKUDO_CONFIG` | Optional path to a JSON config (same keys, snake_case). | (unset) |
| `SEKUDO_REPORT_DIR` | Where scan reports are written. | `reports` |

Anything not in `SEKUDO_TARGETS` is refused.

## Run from the repo (before npm publish)

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
