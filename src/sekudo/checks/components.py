"""A06:2021 Vulnerable & Outdated Components, fingerprinting & version banners."""

from __future__ import annotations

import re

from . import ScanContext, register
from ..report import Finding, Severity

_VERSION_RE = re.compile(r"([A-Za-z][A-Za-z0-9_\-]+)[/ ](\d+\.\d+(?:\.\d+)?)")


@register("comp.fingerprint", "Technology/version disclosure", "A06:2021 Vulnerable Components", "components")
async def fingerprint(ctx: ScanContext) -> list[Finding]:
    r = await ctx.engine.get(ctx.base_url, follow_redirects=True)
    if r.error:
        return []
    disclosed = {}
    for h in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        if h in r.headers:
            disclosed[h] = r.headers[h]
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', r.text, re.I)
    if m:
        disclosed["meta-generator"] = m.group(1)
    if not disclosed:
        return []
    versioned = any(_VERSION_RE.search(v) for v in disclosed.values())
    return [Finding(
        check_id="comp.fingerprint", title="Server/framework versions disclosed",
        owasp="A06:2021 Vulnerable Components",
        severity=Severity.LOW if versioned else Severity.INFO, target=ctx.base_url,
        description=("Response headers/meta reveal software and versions, letting an attacker look up "
                     "known CVEs for the exact build."),
        evidence="; ".join(f"{k}: {v}" for k, v in disclosed.items()),
        remediation="Suppress version banners; track components against a CVE feed and patch.", confirmed=True,
    )]


@register("comp.manifest", "Exposed dependency manifests", "A06:2021 Vulnerable Components", "components")
async def manifest(ctx: ScanContext) -> list[Finding]:
    from urllib.parse import urljoin
    out = []
    for path in ("package.json", "composer.json", "composer.lock", "requirements.txt",
                 "Gemfile.lock", "yarn.lock", "package-lock.json", "pom.xml"):
        r = await ctx.engine.get(urljoin(ctx.base_url, "/" + path))
        if r.status == 200 and r.text and any(
            t in r.text.lower() for t in ("dependencies", "require", "==", "resolved", "<dependency>")):
            out.append(Finding(
                check_id="comp.manifest", title=f"Dependency manifest exposed: /{path}",
                owasp="A06:2021 Vulnerable Components", severity=Severity.MEDIUM,
                target=urljoin(ctx.base_url, "/" + path),
                description="A dependency manifest/lockfile is public, exposing exact versions to match against CVEs.",
                evidence=f"/{path} → 200 with dependency content",
                remediation="Do not serve manifests from webroot.", confirmed=True,
            ))
    return out
