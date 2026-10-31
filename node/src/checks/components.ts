// A06:2021 Vulnerable & Outdated Components, fingerprinting & version banners.

import type { Finding } from "../report.js";
import type { CheckDef, ScanContext } from "../types.js";

const VERSION_RE = /[A-Za-z][A-Za-z0-9_-]+[/ ]\d+\.\d+(?:\.\d+)?/;

function at(ctx: ScanContext, path: string): string {
  return new URL(path, ctx.baseUrl.endsWith("/") ? ctx.baseUrl : ctx.baseUrl + "/").toString();
}

export const checks: CheckDef[] = [
  {
    id: "comp.fingerprint", name: "Technology/version disclosure", owasp: "A06:2021 Vulnerable Components", category: "components",
    async fn(ctx) {
      const r = await ctx.engine.get(ctx.baseUrl, { followRedirects: true });
      if (r.error) return [];
      const disclosed: Record<string, string> = {};
      for (const h of ["server", "x-powered-by", "x-aspnet-version", "x-generator"]) {
        if (h in r.headers) disclosed[h] = r.headers[h];
      }
      const m = r.text.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i);
      if (m) disclosed["meta-generator"] = m[1];
      if (Object.keys(disclosed).length === 0) return [];
      const versioned = Object.values(disclosed).some((v) => VERSION_RE.test(v));
      return [{
        checkId: "comp.fingerprint", title: "Server/framework versions disclosed",
        owasp: "A06:2021 Vulnerable Components", severity: versioned ? "low" : "info", target: ctx.baseUrl,
        description: "Response headers or meta reveal software and versions, letting an attacker look up known CVEs for the exact build.",
        evidence: Object.entries(disclosed).map(([k, v]) => `${k}: ${v}`).join("; "),
        remediation: "Suppress version banners; track components against a CVE feed and patch.", confirmed: true,
      }];
    },
  },
  {
    id: "comp.manifest", name: "Exposed dependency manifests", owasp: "A06:2021 Vulnerable Components", category: "components",
    async fn(ctx) {
      const out: Finding[] = [];
      for (const path of ["package.json", "composer.json", "composer.lock", "requirements.txt", "Gemfile.lock", "yarn.lock", "package-lock.json", "pom.xml"]) {
        const url = at(ctx, path);
        const r = await ctx.engine.get(url);
        const t = r.text.toLowerCase();
        if (r.status === 200 && r.text && ["dependencies", "require", "==", "resolved", "<dependency>"].some((x) => t.includes(x))) {
          out.push({
            checkId: "comp.manifest", title: `Dependency manifest exposed: /${path}`,
            owasp: "A06:2021 Vulnerable Components", severity: "medium", target: url,
            description: "A dependency manifest or lockfile is public, exposing exact versions to match against CVEs.",
            evidence: `/${path} produced 200 with dependency content`,
            remediation: "Do not serve manifests from webroot.", confirmed: true,
          });
        }
      }
      return out;
    },
  },
];
