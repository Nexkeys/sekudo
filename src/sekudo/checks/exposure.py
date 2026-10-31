"""Exposure checks, leaked secrets, source control, API docs, backups.

Spans A01 (access control), A02 (crypto/secret exposure) and A05 (misconfig).
"""

from __future__ import annotations

from urllib.parse import urljoin

from . import ScanContext, register
from ..report import Finding, Severity
from .. import patterns as P


@register("exp.sensitive_files", "Exposed sensitive files", "A05:2021 Security Misconfiguration", "exposure")
async def sensitive_files(ctx: ScanContext) -> list[Finding]:
    out = []
    for path in P.SENSITIVE_PATHS:
        r = await ctx.engine.get(urljoin(ctx.base_url, "/" + path))
        if r.status == 200 and r.text and len(r.text) > 8 and "<html" not in r.text[:200].lower():
            out.append(Finding(
                check_id="exp.sensitive_files", title=f"Sensitive file exposed: /{path}",
                owasp="A05:2021 Security Misconfiguration",
                severity=Severity.CRITICAL if path.startswith((".env", ".git", "id_rsa")) else Severity.HIGH,
                target=urljoin(ctx.base_url, "/" + path),
                description="A configuration/secret/backup file is directly downloadable.",
                evidence=f"/{path} → 200 ({len(r.text)} bytes), first line: {r.text.splitlines()[0][:80]!r}",
                remediation="Remove the file from webroot; block dotfiles/backups at the server; rotate any exposed secret.",
                confirmed=True,
            ))
    return out


@register("exp.secret_leakage", "Secrets / API keys in responses", "A02:2021 Cryptographic Failures", "exposure")
async def secret_leakage(ctx: ScanContext) -> list[Finding]:
    out = []
    urls = {ctx.base_url} | {ep.url for ep in ctx.endpoints}
    for url in list(urls)[:30]:
        r = await ctx.engine.get(url, follow_redirects=True)
        if r.error or not r.text:
            continue
        for label, rx in P.SECRET_PATTERNS.items():
            if label == "JWT":
                continue  # handled by auth.jwt_alg_none
            m = rx.search(r.text)
            if m:
                frag = m.group(0)
                out.append(Finding(
                    check_id="exp.secret_leakage", title=f"{label} leaked in response",
                    owasp="A02:2021 Cryptographic Failures", severity=Severity.CRITICAL, target=url,
                    description=f"A live-looking {label} is embedded in a served response (page/JS/source map).",
                    evidence=f"{label}: {frag[:6]}…{frag[-4:]} at {url}",
                    remediation="Remove the secret from client-delivered code; rotate it immediately; use a backend proxy.",
                    confirmed=True,
                ))
                break
    return out


@register("exp.vcs", "Exposed version control (.git/.svn)", "A05:2021 Security Misconfiguration", "exposure")
async def vcs(ctx: ScanContext) -> list[Finding]:
    r = await ctx.engine.get(urljoin(ctx.base_url, "/.git/HEAD"))
    if r.status == 200 and "ref:" in r.text:
        return [Finding(
            check_id="exp.vcs", title="Exposed .git repository",
            owasp="A05:2021 Security Misconfiguration", severity=Severity.CRITICAL,
            target=urljoin(ctx.base_url, "/.git/"),
            description="The .git directory is web-accessible; full source history (and secrets in it) can be reconstructed.",
            evidence=f"/.git/HEAD → 200: {r.text.strip()[:40]!r}",
            remediation="Block access to .git; deploy build artifacts only, not the repo.", confirmed=True,
        )]
    return []


@register("exp.swagger", "Exposed API docs (Swagger/OpenAPI)", "A05:2021 Security Misconfiguration", "exposure")
async def swagger(ctx: ScanContext) -> list[Finding]:
    out = []
    for path in ("swagger.json", "openapi.json", "api-docs", "v2/api-docs", "swagger-ui.html", "api/swagger.json"):
        r = await ctx.engine.get(urljoin(ctx.base_url, "/" + path))
        if r.status == 200 and ("swagger" in r.text.lower() or "openapi" in r.text.lower() or "\"paths\"" in r.text):
            out.append(Finding(
                check_id="exp.swagger", title=f"API specification exposed: /{path}",
                owasp="A05:2021 Security Misconfiguration", severity=Severity.MEDIUM,
                target=urljoin(ctx.base_url, "/" + path),
                description="A full API spec is public, handing an attacker every endpoint, parameter and schema.",
                evidence=f"/{path} → 200 with OpenAPI/Swagger content",
                remediation="Restrict API docs to non-prod or authenticated users.", confirmed=True,
            ))
            break
    return out


@register("exp.graphql", "GraphQL introspection enabled", "A05:2021 Security Misconfiguration", "exposure")
async def graphql(ctx: ScanContext) -> list[Finding]:
    q = {"query": "{__schema{queryType{name}}}"}
    for path in ("/graphql", "/api/graphql", "/v1/graphql", "/query"):
        r = await ctx.engine.request("POST", urljoin(ctx.base_url, path), json=q)
        if r.status == 200 and "__schema" in r.text and "queryType" in r.text:
            return [Finding(
                check_id="exp.graphql", title=f"GraphQL introspection open at {path}",
                owasp="A05:2021 Security Misconfiguration", severity=Severity.MEDIUM,
                target=urljoin(ctx.base_url, path),
                description="Introspection exposes the full GraphQL schema, mapping every type, query and mutation.",
                evidence=f"introspection query at {path} returned __schema",
                remediation="Disable introspection in production; enforce query depth/cost limits + authz.", confirmed=True,
            )]
    return []


@register("exp.backup", "Exposed backup / archive files", "A05:2021 Security Misconfiguration", "exposure")
async def backup(ctx: ScanContext) -> list[Finding]:
    out = []
    import re
    name = re.sub(r"[^a-z0-9]", "", ctx.host.lower()) or "site"
    for cand in (f"{name}.zip", f"{name}.tar.gz", "backup.tar.gz", "www.zip", "site.zip", "public_html.zip"):
        r = await ctx.engine.get(urljoin(ctx.base_url, "/" + cand))
        ctype = r.headers.get("content-type", "")
        if r.status == 200 and ("zip" in ctype or "octet-stream" in ctype or "gzip" in ctype):
            out.append(Finding(
                check_id="exp.backup", title=f"Downloadable backup archive: /{cand}",
                owasp="A05:2021 Security Misconfiguration", severity=Severity.HIGH,
                target=urljoin(ctx.base_url, "/" + cand),
                description="A site/source backup archive is publicly downloadable.",
                evidence=f"/{cand} → 200, content-type {ctype}",
                remediation="Remove archives from webroot; store backups off the web server.", confirmed=True,
            ))
    return out
