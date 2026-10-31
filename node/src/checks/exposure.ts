// Exposure checks, leaked secrets, source control, API docs, backups.

import type { Finding } from "../report.js";
import type { CheckDef, ScanContext } from "../types.js";
import * as P from "../patterns.js";

function at(ctx: ScanContext, path: string): string {
  return new URL(path, ctx.baseUrl.endsWith("/") ? ctx.baseUrl : ctx.baseUrl + "/").toString();
}

export const checks: CheckDef[] = [
  {
    id: "exp.sensitive_files", name: "Exposed sensitive files", owasp: "A05:2021 Security Misconfiguration", category: "exposure",
    async fn(ctx) {
      const out: Finding[] = [];
      for (const path of P.SENSITIVE_PATHS) {
        const url = at(ctx, path);
        const r = await ctx.engine.get(url);
        if (r.status === 200 && r.text.length > 8 && !r.text.slice(0, 200).toLowerCase().includes("<html")) {
          const crit = path.startsWith(".env") || path.startsWith(".git") || path.startsWith("id_rsa");
          out.push({
            checkId: "exp.sensitive_files", title: `Sensitive file exposed: /${path}`,
            owasp: "A05:2021 Security Misconfiguration", severity: crit ? "critical" : "high", target: url,
            description: "A configuration, secret, or backup file is directly downloadable.",
            evidence: `/${path} produced 200 (${r.text.length} bytes), first line: ${JSON.stringify(r.text.split("\n")[0].slice(0, 80))}`,
            remediation: "Remove the file from webroot; block dotfiles/backups at the server; rotate any exposed secret.", confirmed: true,
          });
        }
      }
      return out;
    },
  },
  {
    id: "exp.secret_leakage", name: "Secrets / API keys in responses", owasp: "A02:2021 Cryptographic Failures", category: "exposure",
    async fn(ctx) {
      const out: Finding[] = [];
      const urls = [...new Set([ctx.baseUrl, ...ctx.endpoints.map((e) => e.url)])].slice(0, 30);
      for (const url of urls) {
        const r = await ctx.engine.get(url, { followRedirects: true });
        if (r.error || !r.text) continue;
        for (const [label, rx] of Object.entries(P.SECRET_PATTERNS)) {
          if (label === "JWT") continue;
          const m = rx.exec(r.text);
          if (m) {
            const frag = m[0];
            out.push({
              checkId: "exp.secret_leakage", title: `${label} leaked in response`,
              owasp: "A02:2021 Cryptographic Failures", severity: "critical", target: url,
              description: `A live-looking ${label} is embedded in a served response (page, JS bundle, or source map).`,
              evidence: `${label}: ${frag.slice(0, 6)}...${frag.slice(-4)} at ${url}`,
              remediation: "Remove the secret from client-delivered code; rotate it immediately; use a backend proxy.", confirmed: true,
            });
            break;
          }
        }
      }
      return out;
    },
  },
  {
    id: "exp.vcs", name: "Exposed version control (.git/.svn)", owasp: "A05:2021 Security Misconfiguration", category: "exposure",
    async fn(ctx) {
      const url = at(ctx, ".git/HEAD");
      const r = await ctx.engine.get(url);
      if (r.status === 200 && r.text.includes("ref:")) {
        return [{
          checkId: "exp.vcs", title: "Exposed .git repository",
          owasp: "A05:2021 Security Misconfiguration", severity: "critical", target: at(ctx, ".git/"),
          description: "The .git directory is web-accessible; full source history (and any secrets in it) can be reconstructed.",
          evidence: `/.git/HEAD produced 200: ${JSON.stringify(r.text.trim().slice(0, 40))}`,
          remediation: "Block access to .git; deploy build artifacts only, not the repo.", confirmed: true,
        }];
      }
      return [];
    },
  },
  {
    id: "exp.swagger", name: "Exposed API docs (Swagger/OpenAPI)", owasp: "A05:2021 Security Misconfiguration", category: "exposure",
    async fn(ctx) {
      for (const path of ["swagger.json", "openapi.json", "api-docs", "v2/api-docs", "swagger-ui.html", "api/swagger.json"]) {
        const url = at(ctx, path);
        const r = await ctx.engine.get(url);
        const t = r.text.toLowerCase();
        if (r.status === 200 && (t.includes("swagger") || t.includes("openapi") || r.text.includes('"paths"'))) {
          return [{
            checkId: "exp.swagger", title: `API specification exposed: /${path}`,
            owasp: "A05:2021 Security Misconfiguration", severity: "medium", target: url,
            description: "A full API spec is public, handing an attacker every endpoint, parameter, and schema.",
            evidence: `/${path} produced 200 with OpenAPI/Swagger content`,
            remediation: "Restrict API docs to non-production or authenticated users.", confirmed: true,
          }];
        }
      }
      return [];
    },
  },
  {
    id: "exp.graphql", name: "GraphQL introspection enabled", owasp: "A05:2021 Security Misconfiguration", category: "exposure",
    async fn(ctx) {
      const q = { query: "{__schema{queryType{name}}}" };
      for (const path of ["graphql", "api/graphql", "v1/graphql", "query"]) {
        const url = at(ctx, path);
        const r = await ctx.engine.request("POST", url, { json: q });
        if (r.status === 200 && r.text.includes("__schema") && r.text.includes("queryType")) {
          return [{
            checkId: "exp.graphql", title: `GraphQL introspection open at /${path}`,
            owasp: "A05:2021 Security Misconfiguration", severity: "medium", target: url,
            description: "Introspection exposes the full GraphQL schema, mapping every type, query, and mutation.",
            evidence: `introspection query at /${path} returned __schema`,
            remediation: "Disable introspection in production; enforce query depth/cost limits and authz.", confirmed: true,
          }];
        }
      }
      return [];
    },
  },
  {
    id: "exp.backup", name: "Exposed backup / archive files", owasp: "A05:2021 Security Misconfiguration", category: "exposure",
    async fn(ctx) {
      const out: Finding[] = [];
      const name = ctx.host.toLowerCase().replace(/[^a-z0-9]/g, "") || "site";
      for (const cand of [`${name}.zip`, `${name}.tar.gz`, "backup.tar.gz", "www.zip", "site.zip", "public_html.zip"]) {
        const url = at(ctx, cand);
        const r = await ctx.engine.get(url);
        const ctype = r.headers["content-type"] ?? "";
        if (r.status === 200 && (ctype.includes("zip") || ctype.includes("octet-stream") || ctype.includes("gzip"))) {
          out.push({
            checkId: "exp.backup", title: `Downloadable backup archive: /${cand}`,
            owasp: "A05:2021 Security Misconfiguration", severity: "high", target: url,
            description: "A site or source backup archive is publicly downloadable.",
            evidence: `/${cand} produced 200, content-type ${ctype}`,
            remediation: "Remove archives from webroot; store backups off the web server.", confirmed: true,
          });
        }
      }
      return out;
    },
  },
];
