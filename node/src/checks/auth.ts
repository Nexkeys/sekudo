// A07:2021 Identification & Authentication Failures.
// Login testing is deliberately bounded: a tiny default-cred list and capped
// attempts to detect a missing lockout. It is not a credential-stuffing engine.

import type { Finding } from "../report.js";
import type { CheckDef, Endpoint, ScanContext } from "../types.js";
import * as P from "../patterns.js";

const LOGIN_HINTS = ["login", "signin", "sign-in", "auth", "session", "account/login", "admin"];
const ERROR_HINTS = ["invalid", "incorrect", "wrong", "failed", "denied", "try again"];

function findLogin(ctx: ScanContext): Endpoint | null {
  for (const ep of ctx.endpoints) {
    const names = new Set(ep.params.map((p) => p.toLowerCase()));
    if ((names.has("password") || names.has("passwd")) && ["user", "username", "email", "login"].some((k) => names.has(k))) return ep;
  }
  for (const ep of ctx.endpoints) if (LOGIN_HINTS.some((h) => ep.url.toLowerCase().includes(h))) return ep;
  return null;
}

function credFields(ep: Endpoint): [string, string] {
  const names = new Map(ep.params.map((p) => [p.toLowerCase(), p]));
  const user = ["username", "user", "email", "login"].map((k) => names.get(k)).find(Boolean) ?? "username";
  const pwd = ["password", "passwd", "pass"].map((k) => names.get(k)).find(Boolean) ?? "password";
  return [user, pwd];
}

function at(ctx: ScanContext, path: string): string {
  return new URL(path, ctx.baseUrl.endsWith("/") ? ctx.baseUrl : ctx.baseUrl + "/").toString();
}

export const checks: CheckDef[] = [
  {
    id: "auth.default_creds", name: "Default / weak credentials accepted", owasp: "A07:2021 Auth Failures", category: "auth",
    async fn(ctx) {
      const ep = findLogin(ctx);
      if (!ep || ep.params.length === 0) return [];
      const [userF, pwdF] = credFields(ep);
      const baseline = await ctx.engine.request(ep.method, ep.url, { data: { [userF]: "sekudo_nouser_zzz", [pwdF]: "sekudo_nopass_zzz" } });
      for (const [u, pw] of P.DEFAULT_CREDS) {
        const r = await ctx.engine.request(ep.method, ep.url, { data: { [userF]: u, [pwdF]: pw } });
        const looksOk = (r.status === 301 || r.status === 302 || "set-cookie" in r.headers) && !ERROR_HINTS.some((e) => r.text.toLowerCase().includes(e));
        const differs = r.status !== baseline.status || Math.abs(r.text.length - baseline.text.length) > 80;
        if (looksOk && differs) {
          return [{
            checkId: "auth.default_creds", title: `Default credentials accepted (${u}/****)`,
            owasp: "A07:2021 Auth Failures", severity: "critical", target: ep.url,
            description: "A common default credential pair appears to authenticate successfully.",
            evidence: `login as ${u} produced status ${r.status}, session cookie set, no error text`,
            remediation: "Remove default accounts; enforce strong unique passwords and MFA.", confirmed: true,
          }];
        }
      }
      return [];
    },
  },
  {
    id: "auth.login_rate_limit", name: "No login rate-limiting / lockout", owasp: "A07:2021 Auth Failures", category: "auth",
    async fn(ctx) {
      const ep = findLogin(ctx);
      if (!ep || ep.params.length === 0) return [];
      const [userF, pwdF] = credFields(ep);
      const statuses: number[] = [];
      for (let i = 0; i < 6; i++) {
        const r = await ctx.engine.request(ep.method, ep.url, { data: { [userF]: "sekudo_user", [pwdF]: "wrong" + i } });
        statuses.push(r.status);
        if (r.status === 429) return [];
      }
      if (statuses.every((s) => s !== 429 && s !== 0)) {
        return [{
          checkId: "auth.login_rate_limit", title: "Login endpoint lacks rate-limiting",
          owasp: "A07:2021 Auth Failures", severity: "medium", target: ep.url,
          description: "Six rapid failed logins drew no throttling or lockout (no 429), enabling brute-force.",
          evidence: `6 failed attempts, statuses=${JSON.stringify(statuses)}, no 429/lockout`,
          remediation: "Add per-account and per-IP throttling, lockout/backoff, and CAPTCHA/MFA.", confirmed: true,
        }];
      }
      return [];
    },
  },
  {
    id: "auth.jwt_alg_none", name: "JWT alg=none acceptance", owasp: "A07:2021 Auth Failures", category: "auth",
    async fn(ctx) {
      const r = await ctx.engine.get(ctx.baseUrl, { followRedirects: true });
      const hay = (r.headers["set-cookie"] ?? "") + " " + r.text;
      const m = P.SECRET_PATTERNS["JWT"].exec(hay);
      if (!m) return [];
      return [{
        checkId: "auth.jwt_alg_none", title: "JWT present, test alg=none / weak secret",
        owasp: "A07:2021 Auth Failures", severity: "medium", target: ctx.baseUrl,
        description: "A JWT is in use. Forge a token with header alg=none (and try a weak HMAC secret). If the server accepts either, authentication is fully bypassable.",
        evidence: `JWT observed: ${m[0].slice(0, 24)}... (replay with alg=none to confirm)`,
        remediation: "Pin the expected algorithm server-side; reject 'none'; use a strong rotated secret.", confirmed: false,
      }];
    },
  },
  {
    id: "auth.admin_exposed", name: "Admin interface reachable without auth", owasp: "A01:2021 Broken Access Control", category: "auth",
    async fn(ctx) {
      const out: Finding[] = [];
      for (const path of ["admin", "administrator", "wp-admin", "admin/dashboard", "manage", "console"]) {
        const url = at(ctx, path);
        const r = await ctx.engine.get(url);
        if (r.status === 200 && ["dashboard", "admin", "logout", "settings"].some((k) => r.text.toLowerCase().includes(k))) {
          out.push({
            checkId: "auth.admin_exposed", title: `Admin area served without auth: /${path}`,
            owasp: "A01:2021 Broken Access Control", severity: "high", target: url,
            description: "An admin/management page returned 200 with admin UI and no redirect to login.",
            evidence: `/${path} produced 200 with admin-looking content, no auth redirect`,
            remediation: "Gate admin routes behind authentication and authorization; deny by default.", confirmed: false,
          });
        }
      }
      return out;
    },
  },
];
