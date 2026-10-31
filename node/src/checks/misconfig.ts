// A05:2021 Security Misconfiguration.

import type { Finding } from "../report.js";
import type { CheckDef, ScanContext } from "../types.js";
import * as P from "../patterns.js";

function at(ctx: ScanContext, path: string): string {
  return new URL(path, ctx.baseUrl.endsWith("/") ? ctx.baseUrl : ctx.baseUrl + "/").toString();
}

export const checks: CheckDef[] = [
  {
    id: "cfg.headers", name: "Missing security headers", owasp: "A05:2021 Security Misconfiguration", category: "misconfig",
    async fn(ctx) {
      const r = await ctx.engine.get(ctx.baseUrl, { followRedirects: true });
      if (r.error) return [];
      const missing = Object.entries(P.SECURITY_HEADERS).filter(([h]) => !(h in r.headers));
      if (missing.length === 0) return [];
      return [{
        checkId: "cfg.headers", title: `${missing.length} security headers missing`,
        owasp: "A05:2021 Security Misconfiguration", severity: missing.length >= 3 ? "medium" : "low", target: ctx.baseUrl,
        description: "Baseline hardening headers are absent, widening XSS/clickjacking/downgrade risk.",
        evidence: missing.map(([h, why]) => `- ${h}: ${why}`).join("\n"),
        remediation: "Set the missing headers at the app or edge.", confirmed: true,
      }];
    },
  },
  {
    id: "cfg.dirlisting", name: "Directory listing enabled", owasp: "A05:2021 Security Misconfiguration", category: "misconfig",
    async fn(ctx) {
      const out: Finding[] = [];
      for (const path of ["", "assets/", "uploads/", "static/", "files/", "images/"]) {
        const url = at(ctx, path);
        const r = await ctx.engine.get(url);
        if (r.status === 200 && (r.text.includes("Index of /") || r.text.includes("<title>Directory listing for"))) {
          out.push({
            checkId: "cfg.dirlisting", title: `Directory listing exposed at /${path}`,
            owasp: "A05:2021 Security Misconfiguration", severity: "medium", target: url,
            description: "The server renders an auto-index, exposing file names and structure.",
            evidence: `'Index of' page served at /${path}`,
            remediation: "Disable autoindex (Options -Indexes / autoindex off).", confirmed: true,
          });
        }
      }
      return out;
    },
  },
  {
    id: "cfg.methods", name: "Dangerous HTTP methods enabled", owasp: "A05:2021 Security Misconfiguration", category: "misconfig",
    async fn(ctx) {
      const out: Finding[] = [];
      for (const method of P.DANGEROUS_METHODS) {
        const r = await ctx.engine.request(method, ctx.baseUrl);
        if (r.status && ![0, 405, 501, 403, 400].includes(r.status)) {
          out.push({
            checkId: "cfg.methods", title: `HTTP ${method} accepted`,
            owasp: "A05:2021 Security Misconfiguration", severity: ["PUT", "DELETE"].includes(method) ? "high" : "low", target: ctx.baseUrl,
            description: `The server accepted ${method} (status ${r.status}); PUT/DELETE can allow writes, TRACE enables XST.`,
            evidence: `${method} ${ctx.baseUrl} produced ${r.status}`,
            remediation: "Restrict methods to those each endpoint needs.", confirmed: true,
          });
        }
      }
      return out;
    },
  },
  {
    id: "cfg.verbose_errors", name: "Verbose error / stack trace disclosure", owasp: "A05:2021 Security Misconfiguration", category: "misconfig",
    async fn(ctx) {
      const probe = at(ctx, "sekudo-nonexistent-%27%22%3C");
      const r = await ctx.engine.get(probe);
      const sigs = ["Traceback (most recent call last)", "Exception in thread", "at java.",
        "System.NullReferenceException", "stack trace:", "Whoops, looks like", "Warning: include", "Fatal error:"];
      const hit = sigs.find((s) => r.text.toLowerCase().includes(s.toLowerCase()));
      if (hit) {
        return [{
          checkId: "cfg.verbose_errors", title: "Verbose error pages leak internals",
          owasp: "A05:2021 Security Misconfiguration", severity: "medium", target: probe,
          description: "An error response exposed a stack trace or framework internals useful to an attacker.",
          evidence: `error signature: ${JSON.stringify(hit)}`,
          remediation: "Return generic errors in production; log details server-side only.", confirmed: true,
        }];
      }
      return [];
    },
  },
  {
    id: "cfg.debug_endpoints", name: "Exposed debug / management endpoints", owasp: "A05:2021 Security Misconfiguration", category: "misconfig",
    async fn(ctx) {
      const out: Finding[] = [];
      for (const path of ["actuator", "actuator/env", "actuator/health", "server-status", "debug", "__debug__", "phpinfo.php", "info.php"]) {
        const url = at(ctx, path);
        const r = await ctx.engine.get(url);
        if (r.status === 200 && r.text.length > 50) {
          out.push({
            checkId: "cfg.debug_endpoints", title: `Debug/management endpoint exposed: /${path}`,
            owasp: "A05:2021 Security Misconfiguration", severity: "high", target: url,
            description: "A diagnostic/management endpoint is reachable and may leak config, env vars, or metrics.",
            evidence: `/${path} produced 200 (${r.text.length} bytes)`,
            remediation: "Disable or authenticate management endpoints; never expose them publicly.", confirmed: true,
          });
        }
      }
      return out;
    },
  },
];
