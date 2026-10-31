"""A01:2021 Broken Access Control + A10:2021 SSRF (open redirect / SSRF params)."""

from __future__ import annotations

from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from . import ScanContext, register
from ..report import Finding, Severity
from .. import patterns as P


def _set_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url if "://" in url else "https://" + url)
    q = parse_qs(parsed.query)
    q[param] = [value]
    return urlunparse(parsed._replace(query=urlencode({k: v[0] for k, v in q.items()})))


@register("ac.cors", "Permissive CORS", "A01:2021 Broken Access Control", "access_control")
async def cors(ctx: ScanContext) -> list[Finding]:
    evil = "https://sekudo-evil.example"
    r = await ctx.engine.get(ctx.base_url, headers={"Origin": evil}, follow_redirects=True)
    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "").lower()
    if acao == evil or (acao == "*" and acac == "true"):
        return [Finding(
            check_id="ac.cors", title="Dangerous CORS configuration",
            owasp="A01:2021 Broken Access Control",
            severity=Severity.HIGH if acac == "true" else Severity.MEDIUM, target=ctx.base_url,
            description="The server reflects an arbitrary Origin (and/or allows credentials with wildcard), letting other sites read responses.",
            evidence=f"Origin: {evil} → ACAO: {acao!r}, ACAC: {acac!r}",
            remediation="Allowlist exact trusted origins; never reflect Origin with credentials.", confirmed=True,
        )]
    return []


@register("ac.open_redirect", "Open redirect", "A01:2021 Broken Access Control", "access_control")
async def open_redirect(ctx: ScanContext) -> list[Finding]:
    out = []
    seen = set()
    for ep in ctx.endpoints:
        cands = [p for p in ep.params if p.lower() in P.OPEN_REDIRECT_PARAMS] or (
            P.OPEN_REDIRECT_PARAMS if ep.url == ctx.base_url else [])
        for param in cands:
            key = (ep.url, param)
            if key in seen:
                continue
            seen.add(key)
            u = _set_param(ep.url, param, P.OPEN_REDIRECT_TARGET)
            r = await ctx.engine.get(u)
            loc = r.headers.get("location", "")
            if r.status in (301, 302, 303, 307, 308) and loc.startswith(P.OPEN_REDIRECT_TARGET):
                out.append(Finding(
                    check_id="ac.open_redirect", title=f"Open redirect via `{param}`",
                    owasp="A01:2021 Broken Access Control", severity=Severity.MEDIUM, target=ep.url,
                    description=f"`{param}` redirects to an attacker-supplied absolute URL, useful for phishing/oauth theft.",
                    evidence=f"{param}={P.OPEN_REDIRECT_TARGET} → {r.status} Location: {loc}",
                    remediation="Redirect only to relative paths or an allowlist of hosts.", confirmed=True,
                ))
    return out


@register("ac.ssrf", "SSRF-prone parameters", "A10:2021 SSRF", "access_control")
async def ssrf(ctx: ScanContext) -> list[Finding]:
    out = []
    for ep in ctx.endpoints:
        for param in ep.params:
            if param.lower() in P.SSRF_PARAMS:
                # Advisory: confirming blind SSRF needs an out-of-band collector.
                out.append(Finding(
                    check_id="ac.ssrf", title=f"Potential SSRF sink `{param}`",
                    owasp="A10:2021 SSRF", severity=Severity.MEDIUM, target=ep.url,
                    description=(f"`{param}` looks like it fetches a URL server-side. Confirm with an "
                                 f"out-of-band callback; if it hits internal metadata (169.254.169.254) it is critical."),
                    evidence=f"URL-fetching parameter `{param}` at {ep.url}",
                    remediation="Allowlist destinations; block internal IP ranges and metadata endpoints.", confirmed=False,
                ))
    return out


@register("ac.idor", "IDOR / object reference probing", "A01:2021 Broken Access Control", "access_control")
async def idor(ctx: ScanContext) -> list[Finding]:
    out = []
    numeric = [(ep, p) for ep in ctx.endpoints for p in ep.params
               if p.lower() in ("id", "user", "user_id", "uid", "account", "order", "doc", "file")]
    for ep, param in numeric[:10]:
        a = await ctx.engine.get(_set_param(ep.url, param, "1"))
        b = await ctx.engine.get(_set_param(ep.url, param, "2"))
        if a.status == 200 and b.status == 200 and a.text and b.text and a.text != b.text:
            out.append(Finding(
                check_id="ac.idor", title=f"Possible IDOR on `{param}`",
                owasp="A01:2021 Broken Access Control", severity=Severity.HIGH, target=ep.url,
                description=(f"Changing `{param}` returned different object content with no auth challenge, "
                             f"verify these objects belong to different owners."),
                evidence=f"{param}=1 and {param}=2 both 200 with differing bodies",
                remediation="Enforce per-object authorization server-side (ownership checks), not just auth.", confirmed=False,
            ))
    return out
