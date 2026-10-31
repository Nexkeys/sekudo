"""A05:2021 Security Misconfiguration."""

from __future__ import annotations

from urllib.parse import urljoin

from . import ScanContext, register
from ..report import Finding, Severity
from .. import patterns as P


@register("cfg.headers", "Missing security headers", "A05:2021 Security Misconfiguration", "misconfig")
async def headers(ctx: ScanContext) -> list[Finding]:
    r = await ctx.engine.get(ctx.base_url, follow_redirects=True)
    if r.error:
        return []
    missing = [(h, why) for h, why in P.SECURITY_HEADERS.items() if h not in r.headers]
    if not missing:
        return []
    sev = Severity.MEDIUM if len(missing) >= 3 else Severity.LOW
    body = "\n".join(f"- {h}: {why}" for h, why in missing)
    return [Finding(
        check_id="cfg.headers", title=f"{len(missing)} security headers missing",
        owasp="A05:2021 Security Misconfiguration", severity=sev, target=ctx.base_url,
        description="Baseline hardening headers are absent, widening XSS/clickjacking/downgrade risk.",
        evidence=body, remediation="Set the missing headers at the app or edge.", confirmed=True,
    )]


@register("cfg.dirlisting", "Directory listing enabled", "A05:2021 Security Misconfiguration", "misconfig")
async def dirlisting(ctx: ScanContext) -> list[Finding]:
    out = []
    for path in ("/", "/assets/", "/uploads/", "/static/", "/files/", "/images/"):
        r = await ctx.engine.get(urljoin(ctx.base_url, path))
        if r.status == 200 and ("Index of /" in r.text or "<title>Directory listing for" in r.text):
            out.append(Finding(
                check_id="cfg.dirlisting", title=f"Directory listing exposed at {path}",
                owasp="A05:2021 Security Misconfiguration", severity=Severity.MEDIUM,
                target=urljoin(ctx.base_url, path),
                description="The server renders an auto-index, exposing file names and structure.",
                evidence=f"'Index of' page served at {path}",
                remediation="Disable autoindex (e.g. `Options -Indexes` / `autoindex off`).",
                confirmed=True,
            ))
    return out


@register("cfg.methods", "Dangerous HTTP methods enabled", "A05:2021 Security Misconfiguration", "misconfig")
async def methods(ctx: ScanContext) -> list[Finding]:
    out = []
    for method in P.DANGEROUS_METHODS:
        r = await ctx.engine.request(method, ctx.base_url)
        if r.status and r.status not in (0, 405, 501, 403, 400):
            out.append(Finding(
                check_id="cfg.methods", title=f"HTTP {method} accepted",
                owasp="A05:2021 Security Misconfiguration",
                severity=Severity.HIGH if method in ("PUT", "DELETE") else Severity.LOW,
                target=ctx.base_url,
                description=f"The server accepted {method} (status {r.status}); PUT/DELETE can allow writes, TRACE enables XST.",
                evidence=f"{method} {ctx.base_url} → {r.status}",
                remediation="Restrict methods to those each endpoint needs.", confirmed=True,
            ))
    return out


@register("cfg.verbose_errors", "Verbose error / stack trace disclosure", "A05:2021 Security Misconfiguration", "misconfig")
async def verbose_errors(ctx: ScanContext) -> list[Finding]:
    probe = urljoin(ctx.base_url, "/sekudo-nonexistent-%27%22%3C")
    r = await ctx.engine.get(probe)
    sigs = ["Traceback (most recent call last)", "Exception in thread", "at java.",
            "System.NullReferenceException", "stack trace:", "Whoops, looks like",
            "Warning: include", "Fatal error:"]
    hit = next((s for s in sigs if s.lower() in r.text.lower()), None)
    if hit:
        return [Finding(
            check_id="cfg.verbose_errors", title="Verbose error pages leak internals",
            owasp="A05:2021 Security Misconfiguration", severity=Severity.MEDIUM, target=probe,
            description="An error response exposed a stack trace / framework internals useful to an attacker.",
            evidence=f"error signature: {hit!r}",
            remediation="Return generic errors in production; log details server-side only.",
            confirmed=True,
        )]
    return []


@register("cfg.debug_endpoints", "Exposed debug / management endpoints", "A05:2021 Security Misconfiguration", "misconfig")
async def debug_endpoints(ctx: ScanContext) -> list[Finding]:
    out = []
    for path in ("actuator", "actuator/env", "actuator/health", "server-status",
                 "debug", "__debug__", "phpinfo.php", "info.php"):
        r = await ctx.engine.get(urljoin(ctx.base_url, "/" + path))
        if r.status == 200 and len(r.text) > 50:
            out.append(Finding(
                check_id="cfg.debug_endpoints", title=f"Debug/management endpoint exposed: /{path}",
                owasp="A05:2021 Security Misconfiguration", severity=Severity.HIGH,
                target=urljoin(ctx.base_url, "/" + path),
                description="A diagnostic/management endpoint is reachable and may leak config, env vars or metrics.",
                evidence=f"/{path} → 200 ({len(r.text)} bytes)",
                remediation="Disable or authenticate management endpoints; never expose them publicly.",
                confirmed=True,
            ))
    return out
