"""A03:2021 Injection, SQLi, NoSQLi, XSS, SSTI, command injection, traversal, CRLF.

All PoCs are benign: they prove the injection point with markers, comparisons or
bounded timing. None dump, drop, or mutate data.
"""

from __future__ import annotations

from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from . import ScanContext, register
from ..http import Response
from ..report import Finding, Severity
from .. import patterns as P


def _with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    q = parse_qs(parsed.query)
    q[param] = [value]
    new_q = urlencode({k: v[0] for k, v in q.items()})
    return urlunparse(parsed._replace(query=new_q))


async def _send(ctx: ScanContext, ep, param: str, value: str) -> Response:
    if ep.method == "POST":
        data = {p: ("1" if p != param else value) for p in ep.params}
        return await ctx.engine.request("POST", ep.url, data=data)
    return await ctx.engine.get(_with_param(ep.url, param, value))


def _targets(ctx: ScanContext):
    for ep in ctx.endpoints:
        for param in (ep.params or []):
            yield ep, param


@register("inj.sqli.error", "SQL injection (error-based)", "A03:2021 Injection", "injection")
async def sqli_error(ctx: ScanContext) -> list[Finding]:
    out = []
    for ep, param in _targets(ctx):
        r = await _send(ctx, ep, param, "1" + P.SQLI_ERROR_PROBE)
        if r.text and P.SQL_ERROR_RE.search(r.text):
            m = P.SQL_ERROR_RE.search(r.text)
            out.append(Finding(
                check_id="inj.sqli.error", title=f"Error-based SQL injection in `{param}`",
                owasp="A03:2021 Injection", severity=Severity.CRITICAL, target=ep.url,
                description=(f"Injecting a single quote into `{param}` surfaced a database "
                             f"error, meaning user input reaches a SQL query unparameterized."),
                evidence=f"payload: {param}=1'\nDB error leaked: …{m.group(0)!r}…",
                remediation="Use parameterized queries / prepared statements; never concatenate input into SQL.",
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                confirmed=True,
            ))
    return out


@register("inj.sqli.boolean", "SQL injection (boolean-based)", "A03:2021 Injection", "injection")
async def sqli_boolean(ctx: ScanContext) -> list[Finding]:
    out = []
    for ep, param in _targets(ctx):
        t = await _send(ctx, ep, param, "1" + P.SQLI_BOOLEAN_TRUE)
        f = await _send(ctx, ep, param, "1" + P.SQLI_BOOLEAN_FALSE)
        if t.status and f.status and t.status == 200 and abs(len(t.text) - len(f.text)) > 60:
            out.append(Finding(
                check_id="inj.sqli.boolean", title=f"Boolean-based blind SQLi in `{param}`",
                owasp="A03:2021 Injection", severity=Severity.CRITICAL, target=ep.url,
                description=(f"A TRUE vs FALSE SQL condition in `{param}` produced materially "
                             f"different responses, the query honours injected logic."),
                evidence=f"TRUE len={len(t.text)} vs FALSE len={len(f.text)} (delta>60 bytes)",
                remediation="Parameterize queries; validate/whitelist input types.",
                confirmed=True,
            ))
    return out


@register("inj.sqli.time", "SQL injection (time-based blind)", "A03:2021 Injection", "injection")
async def sqli_time(ctx: ScanContext) -> list[Finding]:
    out = []
    for ep, param in _targets(ctx):
        base = await _send(ctx, ep, param, "1")
        for payload in P.SQLI_TIME_PROBES:
            r = await _send(ctx, ep, param, "1" + payload)
            if r.elapsed_ms > P.SQLI_TIME_THRESHOLD_MS and r.elapsed_ms > base.elapsed_ms + 2000:
                out.append(Finding(
                    check_id="inj.sqli.time", title=f"Time-based blind SQLi in `{param}`",
                    owasp="A03:2021 Injection", severity=Severity.CRITICAL, target=ep.url,
                    description=(f"A bounded SQL sleep injected into `{param}` delayed the "
                                 f"response, proving query execution of injected SQL."),
                    evidence=f"payload: {payload}\nbaseline={base.elapsed_ms:.0f}ms delayed={r.elapsed_ms:.0f}ms",
                    remediation="Parameterize queries. A sleeping DB means arbitrary SQL executes.",
                    confirmed=True,
                ))
                break
    return out


@register("inj.nosqli", "NoSQL injection", "A03:2021 Injection", "injection")
async def nosqli(ctx: ScanContext) -> list[Finding]:
    out = []
    for ep, param in _targets(ctx):
        base = await _send(ctx, ep, param, "sekudo_nomatch_zzz")
        for payload in P.NOSQLI_PAYLOADS:
            r = await _send(ctx, ep, param, payload)
            if r.status == 200 and base.status == 200 and len(r.text) > len(base.text) + 60:
                out.append(Finding(
                    check_id="inj.nosqli", title=f"Possible NoSQL injection in `{param}`",
                    owasp="A03:2021 Injection", severity=Severity.HIGH, target=ep.url,
                    description=(f"A Mongo-style operator payload in `{param}` returned more "
                                 f"data than a non-matching value, operator injection likely."),
                    evidence=f"payload: {param}={payload}\nresponse grew {len(base.text)}→{len(r.text)} bytes",
                    remediation="Cast/validate input types; reject objects where scalars are expected.",
                    confirmed=False,
                ))
                break
    return out


@register("inj.xss.reflected", "Reflected XSS", "A03:2021 Injection", "injection")
async def xss_reflected(ctx: ScanContext) -> list[Finding]:
    out = []
    for ep, param in _targets(ctx):
        for probe in P.XSS_PROBES:
            r = await _send(ctx, ep, param, probe)
            if r.text and probe in r.text and "text/html" in r.headers.get("content-type", ""):
                out.append(Finding(
                    check_id="inj.xss.reflected", title=f"Reflected XSS in `{param}`",
                    owasp="A03:2021 Injection", severity=Severity.HIGH, target=ep.url,
                    description=(f"Input in `{param}` is reflected into HTML unescaped, so an "
                                 f"attacker-controlled script marker renders verbatim."),
                    evidence=f"marker {P.XSS_MARKER} reflected unescaped into HTML body",
                    remediation="Context-encode output; set a strict CSP; prefer framework auto-escaping.",
                    references=["https://owasp.org/www-community/attacks/xss/"],
                    confirmed=True,
                ))
                break
    return out


@register("inj.ssti", "Server-side template injection", "A03:2021 Injection", "injection")
async def ssti(ctx: ScanContext) -> list[Finding]:
    out = []
    for ep, param in _targets(ctx):
        for probe, expect in P.SSTI_PROBES.items():
            r = await _send(ctx, ep, param, probe)
            if r.text and expect in r.text:
                out.append(Finding(
                    check_id="inj.ssti", title=f"Server-side template injection in `{param}`",
                    owasp="A03:2021 Injection", severity=Severity.CRITICAL, target=ep.url,
                    description=(f"`{param}` evaluated a template expression (73*73→{expect}), "
                                 f"which commonly escalates to remote code execution."),
                    evidence=f"payload: {probe} → output contained {expect}",
                    remediation="Never pass user input into template source; use sandboxed logic-less templates.",
                    confirmed=True,
                ))
                break
    return out


@register("inj.cmdi", "OS command injection", "A03:2021 Injection", "injection")
async def cmdi(ctx: ScanContext) -> list[Finding]:
    out = []
    for ep, param in _targets(ctx):
        for probe in P.CMDI_PROBES:
            r = await _send(ctx, ep, param, "1" + probe)
            if r.text and P.CMDI_MARKER in r.text:
                out.append(Finding(
                    check_id="inj.cmdi", title=f"OS command injection in `{param}`",
                    owasp="A03:2021 Injection", severity=Severity.CRITICAL, target=ep.url,
                    description=(f"A shell echo injected via `{param}` executed, the app passes "
                                 f"input to a system shell."),
                    evidence=f"payload: {probe} → marker {P.CMDI_MARKER} echoed back",
                    remediation="Avoid shells; use argument arrays/APIs; strictly validate input.",
                    confirmed=True,
                ))
                break
    return out


@register("inj.traversal", "Path traversal / LFI", "A01:2021 Broken Access Control", "injection")
async def traversal(ctx: ScanContext) -> list[Finding]:
    out = []
    for ep, param in _targets(ctx):
        for payload, sig in P.TRAVERSAL_PROBES:
            r = await _send(ctx, ep, param, payload)
            if r.text and sig.search(r.text):
                out.append(Finding(
                    check_id="inj.traversal", title=f"Path traversal via `{param}`",
                    owasp="A01:2021 Broken Access Control", severity=Severity.HIGH, target=ep.url,
                    description=(f"`{param}` read a file outside the web root, the parameter is "
                                 f"used in a filesystem path without canonicalization."),
                    evidence=f"payload: {payload} → matched well-known read-only system file",
                    remediation="Resolve+confine paths to an allowlisted base dir; reject '..'.",
                    confirmed=True,
                ))
                break
    return out


@register("inj.crlf", "CRLF / header injection", "A03:2021 Injection", "injection")
async def crlf(ctx: ScanContext) -> list[Finding]:
    out = []
    marker = "Sekudo-CRLF: 1"
    for ep, param in _targets(ctx):
        r = await _send(ctx, ep, param, "1%0d%0a" + marker.replace(" ", "%20"))
        if "sekudo-crlf" in {k.lower() for k in r.headers}:
            out.append(Finding(
                check_id="inj.crlf", title=f"CRLF / response-header injection in `{param}`",
                owasp="A03:2021 Injection", severity=Severity.MEDIUM, target=ep.url,
                description=f"`{param}` let an injected CRLF add a response header.",
                evidence="injected header 'Sekudo-CRLF' appeared in the response",
                remediation="Strip CR/LF from values placed in headers; use framework header APIs.",
                confirmed=True,
            ))
    return out
