// A03:2021 Injection, SQLi, NoSQLi, XSS, SSTI, command injection, traversal, CRLF.
// All PoCs are benign: markers, comparisons, or bounded timing. None dump or drop.

import type { Finding } from "../report.js";
import type { CheckDef, Endpoint, ScanContext } from "../types.js";
import type { SekudoResponse } from "../http.js";
import { setParam } from "../util.js";
import * as P from "../patterns.js";

async function send(ctx: ScanContext, ep: Endpoint, param: string, value: string): Promise<SekudoResponse> {
  if (ep.method === "POST") {
    const data: Record<string, string> = {};
    for (const p of ep.params) data[p] = p === param ? value : "1";
    return ctx.engine.request("POST", ep.url, { data });
  }
  return ctx.engine.get(setParam(ep.url, param, value));
}

function* targets(ctx: ScanContext): Generator<[Endpoint, string]> {
  for (const ep of ctx.endpoints) for (const p of ep.params ?? []) yield [ep, p];
}

export const checks: CheckDef[] = [
  {
    id: "inj.sqli.error", name: "SQL injection (error-based)", owasp: "A03:2021 Injection", category: "injection",
    async fn(ctx) {
      const out: Finding[] = [];
      for (const [ep, param] of targets(ctx)) {
        const r = await send(ctx, ep, param, "1" + P.SQLI_ERROR_PROBE);
        const m = r.text && P.SQL_ERROR_RE.exec(r.text);
        if (m) {
          out.push({
            checkId: "inj.sqli.error", title: `Error-based SQL injection in \`${param}\``,
            owasp: "A03:2021 Injection", severity: "critical", target: ep.url,
            description: `Injecting a single quote into \`${param}\` surfaced a database error, meaning user input reaches a SQL query unparameterized.`,
            evidence: `payload: ${param}=1'\nDB error leaked: ...${JSON.stringify(m[0])}...`,
            remediation: "Use parameterized queries / prepared statements; never concatenate input into SQL.",
            references: ["https://owasp.org/www-community/attacks/SQL_Injection"], confirmed: true,
          });
        }
      }
      return out;
    },
  },
  {
    id: "inj.sqli.boolean", name: "SQL injection (boolean-based)", owasp: "A03:2021 Injection", category: "injection",
    async fn(ctx) {
      const out: Finding[] = [];
      for (const [ep, param] of targets(ctx)) {
        const t = await send(ctx, ep, param, "1" + P.SQLI_BOOLEAN_TRUE);
        const f = await send(ctx, ep, param, "1" + P.SQLI_BOOLEAN_FALSE);
        if (t.status === 200 && f.status && Math.abs(t.text.length - f.text.length) > 60) {
          out.push({
            checkId: "inj.sqli.boolean", title: `Boolean-based blind SQLi in \`${param}\``,
            owasp: "A03:2021 Injection", severity: "critical", target: ep.url,
            description: `A TRUE vs FALSE SQL condition in \`${param}\` produced materially different responses, so the query honours injected logic.`,
            evidence: `TRUE len=${t.text.length} vs FALSE len=${f.text.length} (delta>60 bytes)`,
            remediation: "Parameterize queries; validate/whitelist input types.", confirmed: true,
          });
        }
      }
      return out;
    },
  },
  {
    id: "inj.sqli.time", name: "SQL injection (time-based blind)", owasp: "A03:2021 Injection", category: "injection",
    async fn(ctx) {
      const out: Finding[] = [];
      for (const [ep, param] of targets(ctx)) {
        const base = await send(ctx, ep, param, "1");
        for (const payload of P.SQLI_TIME_PROBES) {
          const r = await send(ctx, ep, param, "1" + payload);
          if (r.elapsedMs > P.SQLI_TIME_THRESHOLD_MS && r.elapsedMs > base.elapsedMs + 2000) {
            out.push({
              checkId: "inj.sqli.time", title: `Time-based blind SQLi in \`${param}\``,
              owasp: "A03:2021 Injection", severity: "critical", target: ep.url,
              description: `A bounded SQL sleep injected into \`${param}\` delayed the response, proving execution of injected SQL.`,
              evidence: `payload: ${payload}\nbaseline=${base.elapsedMs}ms delayed=${r.elapsedMs}ms`,
              remediation: "Parameterize queries. A sleeping DB means arbitrary SQL executes.", confirmed: true,
            });
            break;
          }
        }
      }
      return out;
    },
  },
  {
    id: "inj.nosqli", name: "NoSQL injection", owasp: "A03:2021 Injection", category: "injection",
    async fn(ctx) {
      const out: Finding[] = [];
      for (const [ep, param] of targets(ctx)) {
        const base = await send(ctx, ep, param, "sekudo_nomatch_zzz");
        for (const payload of P.NOSQLI_PAYLOADS) {
          const r = await send(ctx, ep, param, payload);
          if (r.status === 200 && base.status === 200 && r.text.length > base.text.length + 60) {
            out.push({
              checkId: "inj.nosqli", title: `Possible NoSQL injection in \`${param}\``,
              owasp: "A03:2021 Injection", severity: "high", target: ep.url,
              description: `A Mongo-style operator payload in \`${param}\` returned more data than a non-matching value, so operator injection is likely.`,
              evidence: `payload: ${param}=${payload}\nresponse grew ${base.text.length} to ${r.text.length} bytes`,
              remediation: "Cast/validate input types; reject objects where scalars are expected.", confirmed: false,
            });
            break;
          }
        }
      }
      return out;
    },
  },
  {
    id: "inj.xss.reflected", name: "Reflected XSS", owasp: "A03:2021 Injection", category: "injection",
    async fn(ctx) {
      const out: Finding[] = [];
      for (const [ep, param] of targets(ctx)) {
        for (const probe of P.XSS_PROBES) {
          const r = await send(ctx, ep, param, probe);
          if (r.text.includes(probe) && (r.headers["content-type"] ?? "").includes("text/html")) {
            out.push({
              checkId: "inj.xss.reflected", title: `Reflected XSS in \`${param}\``,
              owasp: "A03:2021 Injection", severity: "high", target: ep.url,
              description: `Input in \`${param}\` is reflected into HTML unescaped, so an attacker-controlled script marker renders verbatim.`,
              evidence: `marker ${P.XSS_MARKER} reflected unescaped into HTML body`,
              remediation: "Context-encode output; set a strict CSP; prefer framework auto-escaping.",
              references: ["https://owasp.org/www-community/attacks/xss/"], confirmed: true,
            });
            break;
          }
        }
      }
      return out;
    },
  },
  {
    id: "inj.ssti", name: "Server-side template injection", owasp: "A03:2021 Injection", category: "injection",
    async fn(ctx) {
      const out: Finding[] = [];
      for (const [ep, param] of targets(ctx)) {
        for (const [probe, expect] of Object.entries(P.SSTI_PROBES)) {
          const r = await send(ctx, ep, param, probe);
          if (r.text.includes(expect)) {
            out.push({
              checkId: "inj.ssti", title: `Server-side template injection in \`${param}\``,
              owasp: "A03:2021 Injection", severity: "critical", target: ep.url,
              description: `\`${param}\` evaluated a template expression (73*73 to ${expect}), which commonly escalates to remote code execution.`,
              evidence: `payload: ${probe} produced output containing ${expect}`,
              remediation: "Never pass user input into template source; use sandboxed logic-less templates.", confirmed: true,
            });
            break;
          }
        }
      }
      return out;
    },
  },
  {
    id: "inj.cmdi", name: "OS command injection", owasp: "A03:2021 Injection", category: "injection",
    async fn(ctx) {
      const out: Finding[] = [];
      for (const [ep, param] of targets(ctx)) {
        for (const probe of P.CMDI_PROBES) {
          const r = await send(ctx, ep, param, "1" + probe);
          if (r.text.includes(P.CMDI_MARKER)) {
            out.push({
              checkId: "inj.cmdi", title: `OS command injection in \`${param}\``,
              owasp: "A03:2021 Injection", severity: "critical", target: ep.url,
              description: `A shell echo injected via \`${param}\` executed, so the app passes input to a system shell.`,
              evidence: `payload: ${probe} echoed back marker ${P.CMDI_MARKER}`,
              remediation: "Avoid shells; use argument arrays/APIs; strictly validate input.", confirmed: true,
            });
            break;
          }
        }
      }
      return out;
    },
  },
  {
    id: "inj.traversal", name: "Path traversal / LFI", owasp: "A01:2021 Broken Access Control", category: "injection",
    async fn(ctx) {
      const out: Finding[] = [];
      for (const [ep, param] of targets(ctx)) {
        for (const [payload, sig] of P.TRAVERSAL_PROBES) {
          const r = await send(ctx, ep, param, payload);
          if (r.text && sig.test(r.text)) {
            out.push({
              checkId: "inj.traversal", title: `Path traversal via \`${param}\``,
              owasp: "A01:2021 Broken Access Control", severity: "high", target: ep.url,
              description: `\`${param}\` read a file outside the web root, so the parameter is used in a filesystem path without canonicalization.`,
              evidence: `payload: ${payload} matched a well-known read-only system file`,
              remediation: "Resolve and confine paths to an allowlisted base dir; reject '..'.", confirmed: true,
            });
            break;
          }
        }
      }
      return out;
    },
  },
  {
    id: "inj.crlf", name: "CRLF / header injection", owasp: "A03:2021 Injection", category: "injection",
    async fn(ctx) {
      const out: Finding[] = [];
      for (const [ep, param] of targets(ctx)) {
        const r = await send(ctx, ep, param, "1%0d%0aSekudo-CRLF:%201");
        if ("sekudo-crlf" in r.headers) {
          out.push({
            checkId: "inj.crlf", title: `CRLF / response-header injection in \`${param}\``,
            owasp: "A03:2021 Injection", severity: "medium", target: ep.url,
            description: `\`${param}\` let an injected CRLF add a response header.`,
            evidence: "injected header 'Sekudo-CRLF' appeared in the response",
            remediation: "Strip CR/LF from values placed in headers; use framework header APIs.", confirmed: true,
          });
        }
      }
      return out;
    },
  },
];
