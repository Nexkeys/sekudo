# Sekudo

**An aggressive, scope-gated DAST exploitation engine, delivered as an MCP server.**

Sekudo hunts hard inside systems you own — recon, then 34 active checks mapped to
the **OWASP Top 10 (2021)** — and *proves* what it finds with benign
proof-of-concept instead of destroying the target. Drop it into any MCP-capable
coding host (Claude Code, Codex, OpenCode, Cursor, and others), point it at your
app or staging box, and get a prioritized, patch-ready report.

> Think of it as a pack of hyenas on a long leash: they bite deep and bring back
> exactly where and how they got in — but they only hunt inside **your** fence.

---

## Why it exists

Vibe-coded apps ship fast and leak often — exposed `.env` files, SQL injection in
a hand-rolled query, a login with no rate limit, a `.git` folder served to the
world. Sekudo is the MCP you install so the model in your IDE can *actually test*
your project the way an attacker would, and hand you the fixes.

## The leash (read this)

Sekudo is for testing systems **you own or are explicitly authorized to assess.**
That is enforced, not suggested:

- Every network-touching tool routes through a **scope gate**. A target must be
  listed in `sekudo.config.yaml → authorized_targets`, the operator must set
  `i_am_authorized: true`, and each run must pass `confirm=true`. Anything else is
  refused.
- PoCs are **non-destructive**: SQLi is proven by comparison/timing/error, not by
  dumping or dropping tables. Traversal reads well-known read-only files. XSS/SSTI
  use inert markers. Login testing is **bounded** (a tiny default-cred list, capped
  attempts) — it detects a missing lockout, it is not a credential-stuffer.
- No persistence, no backdoors, no data exfiltration, no lateral movement into
  third-party systems.

Testing systems you don't own is illegal (CFAA, UK CMA, and equivalents). The gate
is there to keep this a professional tool.

## Capabilities (34 checks)

| OWASP | Checks |
|---|---|
| **A01 Broken Access Control** | path traversal/LFI, CORS misconfig, open redirect, IDOR probing, admin-area exposure |
| **A02 Cryptographic Failures** | cleartext HTTP, missing HSTS, insecure cookie flags, secrets in URLs, secret/API-key leakage |
| **A03 Injection** | SQLi (error / boolean / time-blind), NoSQLi, reflected XSS, SSTI, OS command injection, CRLF/header injection |
| **A05 Misconfiguration** | missing security headers, directory listing, dangerous HTTP methods, verbose errors, debug/management endpoints, exposed sensitive files, `.git`/`.svn`, Swagger/OpenAPI, GraphQL introspection, backup archives |
| **A06 Vulnerable Components** | server/framework/version disclosure, exposed dependency manifests |
| **A07 Auth Failures** | default credentials, missing login rate-limit/lockout, JWT `alg=none`/weak-secret, session hygiene |
| **A10 SSRF** | SSRF-prone parameters (with OOB guidance) |

Run `sekudo --selftest` for the live, exact list.

## Architecture

```
MCP host (Claude Code / Codex / …)   ← the "brain": chains the tools
        │  stdio (MCP)
        ▼
  Sekudo MCP server  ──►  scope gate (the fence)
        │
        ├─ recon        surface mapping: crawl, forms, params, robots/sitemap
        ├─ checks/*     34 OWASP-mapped active checks (the claws)
        └─ report       JSON + Markdown "bite-by-bite" findings (the kill report)
```

No separate AI API key is needed — the model already running in your IDE drives
the tools. Sekudo is plain Python doing the network work.

## Install

```bash
git clone https://github.com/Nexkeys/sekudo.git
cd sekudo
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
sekudo --selftest        # verify the 34 checks load
```

## Configure scope

```bash
cp sekudo.config.example.yaml sekudo.config.yaml
# edit: set i_am_authorized: true and list YOUR hosts
```

## Add to your IDE (MCP)

Claude Code:

```bash
claude mcp add sekudo -- sekudo
```

…or paste the `sekudo` block from [`mcp-config.example.json`](mcp-config.example.json)
into your host's MCP config, setting `SEKUDO_CONFIG` to your config path.

## Use it

Once connected, the host model has these tools: `about`, `list_checks`,
`check_scope`, and `scan`. Typical prompts:

> "Check if `localhost:3000` is in scope, then run a full sekudo scan and summarize the criticals."

> "Run only the injection and auth checks against `staging.myapp.com`."

`scan` writes a timestamped Markdown + JSON report to `./reports/`.

### Example finding

```
## [CRITICAL] Error-based SQL injection in `id`  (✅ CONFIRMED)
- Check: inj.sqli.error
- OWASP: A03:2021 Injection
- Where it bit: https://staging.myapp.com/product?id=1

How & why
Injecting a single quote into `id` surfaced a database error, meaning user
input reaches a SQL query unparameterized.

Evidence (proof-of-concept)
payload: id=1'
DB error leaked: …'you have an error in your SQL syntax'…

Patch
Use parameterized queries / prepared statements; never concatenate input into SQL.
```

## Roadmap

- TypeScript/Node port (same tools, `npx` install)
- Out-of-band collector for confirming blind SSRF/XXE
- Authenticated scans (session/cookie injection)
- SARIF output for CI

## License

MIT — see [LICENSE](LICENSE). You are responsible for using Sekudo only against
systems you are authorized to test.
