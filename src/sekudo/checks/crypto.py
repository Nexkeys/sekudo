"""A02:2021 Cryptographic Failures (transport & data-in-transit hygiene)."""

from __future__ import annotations

from urllib.parse import urlparse

from . import ScanContext, register
from ..report import Finding, Severity


@register("crypto.cleartext", "Cleartext HTTP (no TLS)", "A02:2021 Cryptographic Failures", "crypto")
async def cleartext(ctx: ScanContext) -> list[Finding]:
    if urlparse(ctx.base_url).scheme == "https":
        # Does the http:// version serve content instead of redirecting?
        http_url = "http://" + urlparse(ctx.base_url).netloc
        r = await ctx.engine.get(http_url)
        if r.status == 200 and "location" not in r.headers:
            return [Finding(
                check_id="crypto.cleartext", title="Site served over plaintext HTTP",
                owasp="A02:2021 Cryptographic Failures", severity=Severity.HIGH, target=http_url,
                description="The HTTP endpoint serves content instead of redirecting to HTTPS; traffic is interceptable.",
                evidence=f"{http_url} → 200 with no redirect to HTTPS",
                remediation="Force HTTPS; 301-redirect all HTTP to HTTPS and set HSTS.", confirmed=True,
            )]
        return []
    return [Finding(
        check_id="crypto.cleartext", title="Target is HTTP-only",
        owasp="A02:2021 Cryptographic Failures", severity=Severity.HIGH, target=ctx.base_url,
        description="The target was reached over plaintext HTTP; all traffic (incl. creds) is exposed.",
        evidence=f"scheme = http for {ctx.base_url}",
        remediation="Deploy TLS and redirect HTTP→HTTPS.", confirmed=True,
    )]


@register("crypto.hsts", "Missing HSTS", "A02:2021 Cryptographic Failures", "crypto")
async def hsts(ctx: ScanContext) -> list[Finding]:
    if urlparse(ctx.base_url).scheme != "https":
        return []
    r = await ctx.engine.get(ctx.base_url, follow_redirects=True)
    if not r.error and "strict-transport-security" not in r.headers:
        return [Finding(
            check_id="crypto.hsts", title="HSTS not enabled",
            owasp="A02:2021 Cryptographic Failures", severity=Severity.LOW, target=ctx.base_url,
            description="Without HSTS, browsers can be downgraded to HTTP by an active attacker.",
            evidence="no Strict-Transport-Security response header",
            remediation="Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.", confirmed=True,
        )]
    return []


@register("crypto.cookie_flags", "Insecure session cookie flags", "A02:2021 Cryptographic Failures", "crypto")
async def cookie_flags(ctx: ScanContext) -> list[Finding]:
    r = await ctx.engine.get(ctx.base_url, follow_redirects=True)
    out = []
    for raw in r.headers.get("set-cookie", "").split("\n"):
        if not raw.strip():
            continue
        low = raw.lower()
        name = raw.split("=", 1)[0].strip()
        missing = [f for f, k in (("Secure", "secure"), ("HttpOnly", "httponly")) if k not in low]
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            out.append(Finding(
                check_id="crypto.cookie_flags", title=f"Cookie `{name}` missing {', '.join(missing)}",
                owasp="A02:2021 Cryptographic Failures", severity=Severity.MEDIUM, target=ctx.base_url,
                description="A session/auth cookie lacks protective flags, enabling theft via JS or plaintext.",
                evidence=f"Set-Cookie: {raw[:80]}…  (missing: {', '.join(missing)})",
                remediation="Set Secure; HttpOnly; SameSite=Lax/Strict on session cookies.", confirmed=True,
            ))
    return out


@register("crypto.secrets_in_url", "Sensitive data in URL", "A02:2021 Cryptographic Failures", "crypto")
async def secrets_in_url(ctx: ScanContext) -> list[Finding]:
    out = []
    risky = ("token", "apikey", "api_key", "password", "passwd", "secret", "sessionid", "auth")
    for ep in ctx.endpoints:
        for param in ep.params:
            if param.lower() in risky:
                out.append(Finding(
                    check_id="crypto.secrets_in_url", title=f"Secret-like parameter `{param}` in URL",
                    owasp="A02:2021 Cryptographic Failures", severity=Severity.MEDIUM, target=ep.url,
                    description="Secrets in query strings land in logs, history, and Referer headers.",
                    evidence=f"parameter `{param}` carried in the URL at {ep.url}",
                    remediation="Move secrets to headers/POST bodies; never place them in URLs.", confirmed=False,
                ))
    return out
