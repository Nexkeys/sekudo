// A01:2021 Broken Access Control + A10:2021 SSRF.

import type { Finding } from "../report.js";
import type { CheckDef, ScanContext } from "../types.js";
import { setParam } from "../util.js";
import * as P from "../patterns.js";

export const checks: CheckDef[] = [
  {
    id: "ac.cors", name: "Permissive CORS", owasp: "A01:2021 Broken Access Control", category: "access_control",
    async fn(ctx) {
      const evil = "https://sekudo-evil.example";
      const r = await ctx.engine.get(ctx.baseUrl, { headers: { Origin: evil }, followRedirects: true });
      const acao = r.headers["access-control-allow-origin"] ?? "";
      const acac = (r.headers["access-control-allow-credentials"] ?? "").toLowerCase();
      if (acao === evil || (acao === "*" && acac === "true")) {
        return [{
          checkId: "ac.cors", title: "Dangerous CORS configuration",
          owasp: "A01:2021 Broken Access Control", severity: acac === "true" ? "high" : "medium", target: ctx.baseUrl,
          description: "The server reflects an arbitrary Origin (and/or allows credentials with wildcard), letting other sites read responses.",
          evidence: `Origin: ${evil} produced ACAO: ${JSON.stringify(acao)}, ACAC: ${JSON.stringify(acac)}`,
          remediation: "Allowlist exact trusted origins; never reflect Origin with credentials.", confirmed: true,
        }];
      }
      return [];
    },
  },
  {
    id: "ac.open_redirect", name: "Open redirect", owasp: "A01:2021 Broken Access Control", category: "access_control",
    async fn(ctx) {
      const out: Finding[] = [];
      const seen = new Set<string>();
      for (const ep of ctx.endpoints) {
        const cands = ep.params.filter((p) => P.OPEN_REDIRECT_PARAMS.includes(p.toLowerCase()));
        const list = cands.length ? cands : ep.url === ctx.baseUrl ? P.OPEN_REDIRECT_PARAMS : [];
        for (const param of list) {
          const key = ep.url + "|" + param;
          if (seen.has(key)) continue;
          seen.add(key);
          const r = await ctx.engine.get(setParam(ep.url, param, P.OPEN_REDIRECT_TARGET));
          const loc = r.headers["location"] ?? "";
          if ([301, 302, 303, 307, 308].includes(r.status) && loc.startsWith(P.OPEN_REDIRECT_TARGET)) {
            out.push({
              checkId: "ac.open_redirect", title: `Open redirect via \`${param}\``,
              owasp: "A01:2021 Broken Access Control", severity: "medium", target: ep.url,
              description: `\`${param}\` redirects to an attacker-supplied absolute URL, useful for phishing or OAuth token theft.`,
              evidence: `${param}=${P.OPEN_REDIRECT_TARGET} produced ${r.status} Location: ${loc}`,
              remediation: "Redirect only to relative paths or an allowlist of hosts.", confirmed: true,
            });
          }
        }
      }
      return out;
    },
  },
  {
    id: "ac.ssrf", name: "SSRF-prone parameters", owasp: "A10:2021 SSRF", category: "access_control",
    async fn(ctx) {
      const out: Finding[] = [];
      for (const ep of ctx.endpoints) {
        for (const param of ep.params) {
          if (P.SSRF_PARAMS.includes(param.toLowerCase())) {
            out.push({
              checkId: "ac.ssrf", title: `Potential SSRF sink \`${param}\``,
              owasp: "A10:2021 SSRF", severity: "medium", target: ep.url,
              description: `\`${param}\` looks like it fetches a URL server-side. Confirm with an out-of-band callback; if it reaches internal metadata (169.254.169.254) it is critical.`,
              evidence: `URL-fetching parameter \`${param}\` at ${ep.url}`,
              remediation: "Allowlist destinations; block internal IP ranges and metadata endpoints.", confirmed: false,
            });
          }
        }
      }
      return out;
    },
  },
  {
    id: "ac.idor", name: "IDOR / object reference probing", owasp: "A01:2021 Broken Access Control", category: "access_control",
    async fn(ctx) {
      const out: Finding[] = [];
      const idParams = ["id", "user", "user_id", "uid", "account", "order", "doc", "file"];
      const numeric: Array<[string, string]> = [];
      for (const ep of ctx.endpoints) for (const p of ep.params) if (idParams.includes(p.toLowerCase())) numeric.push([ep.url, p]);
      for (const [url, param] of numeric.slice(0, 10)) {
        const a = await ctx.engine.get(setParam(url, param, "1"));
        const b = await ctx.engine.get(setParam(url, param, "2"));
        if (a.status === 200 && b.status === 200 && a.text && b.text && a.text !== b.text) {
          out.push({
            checkId: "ac.idor", title: `Possible IDOR on \`${param}\``,
            owasp: "A01:2021 Broken Access Control", severity: "high", target: url,
            description: `Changing \`${param}\` returned different object content with no auth challenge. Verify these objects belong to different owners.`,
            evidence: `${param}=1 and ${param}=2 both 200 with differing bodies`,
            remediation: "Enforce per-object authorization server-side (ownership checks), not just authentication.", confirmed: false,
          });
        }
      }
      return out;
    },
  },
];
