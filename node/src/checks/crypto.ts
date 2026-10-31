// A02:2021 Cryptographic Failures (transport & data-in-transit hygiene).

import type { Finding } from "../report.js";
import type { CheckDef, ScanContext } from "../types.js";

export const checks: CheckDef[] = [
  {
    id: "crypto.cleartext", name: "Cleartext HTTP (no TLS)", owasp: "A02:2021 Cryptographic Failures", category: "crypto",
    async fn(ctx) {
      const u = new URL(ctx.baseUrl);
      if (u.protocol === "https:") {
        const httpUrl = "http://" + u.host;
        const r = await ctx.engine.get(httpUrl);
        if (r.status === 200 && !("location" in r.headers)) {
          return [{
            checkId: "crypto.cleartext", title: "Site served over plaintext HTTP",
            owasp: "A02:2021 Cryptographic Failures", severity: "high", target: httpUrl,
            description: "The HTTP endpoint serves content instead of redirecting to HTTPS; traffic is interceptable.",
            evidence: `${httpUrl} produced 200 with no redirect to HTTPS`,
            remediation: "Force HTTPS; 301-redirect all HTTP to HTTPS and set HSTS.", confirmed: true,
          }];
        }
        return [];
      }
      return [{
        checkId: "crypto.cleartext", title: "Target is HTTP-only",
        owasp: "A02:2021 Cryptographic Failures", severity: "high", target: ctx.baseUrl,
        description: "The target was reached over plaintext HTTP; all traffic including credentials is exposed.",
        evidence: `scheme = http for ${ctx.baseUrl}`,
        remediation: "Deploy TLS and redirect HTTP to HTTPS.", confirmed: true,
      }];
    },
  },
  {
    id: "crypto.hsts", name: "Missing HSTS", owasp: "A02:2021 Cryptographic Failures", category: "crypto",
    async fn(ctx) {
      if (new URL(ctx.baseUrl).protocol !== "https:") return [];
      const r = await ctx.engine.get(ctx.baseUrl, { followRedirects: true });
      if (!r.error && !("strict-transport-security" in r.headers)) {
        return [{
          checkId: "crypto.hsts", title: "HSTS not enabled",
          owasp: "A02:2021 Cryptographic Failures", severity: "low", target: ctx.baseUrl,
          description: "Without HSTS, browsers can be downgraded to HTTP by an active attacker.",
          evidence: "no Strict-Transport-Security response header",
          remediation: "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.", confirmed: true,
        }];
      }
      return [];
    },
  },
  {
    id: "crypto.cookie_flags", name: "Insecure session cookie flags", owasp: "A02:2021 Cryptographic Failures", category: "crypto",
    async fn(ctx) {
      const r = await ctx.engine.get(ctx.baseUrl, { followRedirects: true });
      const raw = r.headers["set-cookie"];
      if (!raw) return [];
      const low = raw.toLowerCase();
      const missing: string[] = [];
      if (!low.includes("secure")) missing.push("Secure");
      if (!low.includes("httponly")) missing.push("HttpOnly");
      if (!low.includes("samesite")) missing.push("SameSite");
      if (missing.length === 0) return [];
      return [{
        checkId: "crypto.cookie_flags", title: `Cookie missing ${missing.join(", ")}`,
        owasp: "A02:2021 Cryptographic Failures", severity: "medium", target: ctx.baseUrl,
        description: "A session/auth cookie lacks protective flags, enabling theft via JS or plaintext transport.",
        evidence: `Set-Cookie missing: ${missing.join(", ")}`,
        remediation: "Set Secure; HttpOnly; SameSite=Lax/Strict on session cookies.", confirmed: true,
      }];
    },
  },
  {
    id: "crypto.secrets_in_url", name: "Sensitive data in URL", owasp: "A02:2021 Cryptographic Failures", category: "crypto",
    async fn(ctx) {
      const out: Finding[] = [];
      const risky = ["token", "apikey", "api_key", "password", "passwd", "secret", "sessionid", "auth"];
      for (const ep of ctx.endpoints) {
        for (const param of ep.params) {
          if (risky.includes(param.toLowerCase())) {
            out.push({
              checkId: "crypto.secrets_in_url", title: `Secret-like parameter \`${param}\` in URL`,
              owasp: "A02:2021 Cryptographic Failures", severity: "medium", target: ep.url,
              description: "Secrets in query strings land in server logs, browser history, and Referer headers.",
              evidence: `parameter \`${param}\` carried in the URL at ${ep.url}`,
              remediation: "Move secrets to headers or POST bodies; never place them in URLs.", confirmed: false,
            });
          }
        }
      }
      return out;
    },
  },
];
