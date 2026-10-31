"""A07:2021 Identification & Authentication Failures.

Login testing here is deliberately *bounded*: a fixed, tiny set of default-cred
pairs and a capped number of attempts to detect a missing lockout. This proves
the weakness without becoming a credential-stuffing engine.
"""

from __future__ import annotations

import base64
import json
from urllib.parse import urljoin

from . import ScanContext, Endpoint, register
from ..report import Finding, Severity
from .. import patterns as P

LOGIN_HINTS = ("login", "signin", "sign-in", "auth", "session", "account/login", "admin")
ERROR_HINTS = ("invalid", "incorrect", "wrong", "failed", "denied", "try again")


def _find_login(ctx: ScanContext) -> Endpoint | None:
    for ep in ctx.endpoints:
        names = {p.lower() for p in ep.params}
        if ("password" in names or "passwd" in names) and any(
            k in names for k in ("user", "username", "email", "login")):
            return ep
    for ep in ctx.endpoints:
        if any(h in ep.url.lower() for h in LOGIN_HINTS):
            return ep
    return None


def _creds_fields(ep: Endpoint) -> tuple[str, str]:
    names = {p.lower(): p for p in ep.params}
    user = next((names[k] for k in ("username", "user", "email", "login") if k in names), "username")
    pwd = next((names[k] for k in ("password", "passwd", "pass") if k in names), "password")
    return user, pwd


@register("auth.default_creds", "Default / weak credentials accepted", "A07:2021 Auth Failures", "auth")
async def default_creds(ctx: ScanContext) -> list[Finding]:
    ep = _find_login(ctx)
    if ep is None or not ep.params:
        return []
    user_f, pwd_f = _creds_fields(ep)
    baseline = await ctx.engine.request(ep.method, ep.url,
                                        data={user_f: "sekudo_nouser_zzz", pwd_f: "sekudo_nopass_zzz"})
    for u, pw in P.DEFAULT_CREDS:
        r = await ctx.engine.request(ep.method, ep.url, data={user_f: u, pwd_f: pw})
        looks_ok = (r.status in (301, 302) or "set-cookie" in r.headers) and not any(
            e in r.text.lower() for e in ERROR_HINTS)
        differs = r.status != baseline.status or abs(len(r.text) - len(baseline.text)) > 80
        if looks_ok and differs:
            return [Finding(
                check_id="auth.default_creds", title=f"Default credentials accepted ({u}/****)",
                owasp="A07:2021 Auth Failures", severity=Severity.CRITICAL, target=ep.url,
                description="A common default credential pair appears to authenticate successfully.",
                evidence=f"login as {u} → status {r.status}, session cookie set, no error text",
                remediation="Remove default accounts; enforce strong unique passwords + MFA.", confirmed=True,
            )]
    return []


@register("auth.login_rate_limit", "No login rate-limiting / lockout", "A07:2021 Auth Failures", "auth")
async def login_rate_limit(ctx: ScanContext) -> list[Finding]:
    ep = _find_login(ctx)
    if ep is None or not ep.params:
        return []
    user_f, pwd_f = _creds_fields(ep)
    statuses = []
    for i in range(6):  # bounded, enough to see a lockout, not to stuff
        r = await ctx.engine.request(ep.method, ep.url,
                                     data={user_f: "sekudo_user", pwd_f: f"wrong{i}"})
        statuses.append(r.status)
        if r.status == 429:
            return []  # lockout kicked in, good
    if all(s not in (429, 0) for s in statuses):
        return [Finding(
            check_id="auth.login_rate_limit", title="Login endpoint lacks rate-limiting",
            owasp="A07:2021 Auth Failures", severity=Severity.MEDIUM, target=ep.url,
            description="Six rapid failed logins drew no throttling/lockout (no 429), enabling brute-force.",
            evidence=f"6 failed attempts, statuses={statuses}, no 429/lockout",
            remediation="Add per-account+IP throttling, lockout/backoff, and CAPTCHA/MFA.", confirmed=True,
        )]
    return []


def _find_jwts(ctx: ScanContext) -> list[str]:
    return list(getattr(ctx, "_jwts", []))


@register("auth.jwt_alg_none", "JWT alg=none acceptance", "A07:2021 Auth Failures", "auth")
async def jwt_alg_none(ctx: ScanContext) -> list[Finding]:
    r = await ctx.engine.get(ctx.base_url, follow_redirects=True)
    tokens = P.SECRET_PATTERNS["JWT"].findall(r.headers.get("set-cookie", "") + " " + r.text)
    if not tokens:
        return []
    return [Finding(
        check_id="auth.jwt_alg_none", title="JWT present, test alg=none / weak secret",
        owasp="A07:2021 Auth Failures", severity=Severity.MEDIUM, target=ctx.base_url,
        description=("A JWT is in use. Forge a token with header alg=none (and try a weak HMAC secret). "
                     "If the server accepts either, authentication is fully bypassable."),
        evidence=f"JWT observed: {tokens[0][:24]}…  (manually replay with alg=none to confirm)",
        remediation="Pin the expected algorithm server-side; reject 'none'; use a strong rotated secret.", confirmed=False,
    )]


@register("auth.admin_exposed", "Admin interface reachable without auth", "A01:2021 Broken Access Control", "auth")
async def admin_exposed(ctx: ScanContext) -> list[Finding]:
    out = []
    for path in ("admin", "administrator", "wp-admin", "admin/dashboard", "manage", "console"):
        r = await ctx.engine.get(urljoin(ctx.base_url, "/" + path), follow_redirects=False)
        if r.status == 200 and any(k in r.text.lower() for k in ("dashboard", "admin", "logout", "settings")):
            out.append(Finding(
                check_id="auth.admin_exposed", title=f"Admin area served without auth: /{path}",
                owasp="A01:2021 Broken Access Control", severity=Severity.HIGH,
                target=urljoin(ctx.base_url, "/" + path),
                description="An admin/management page returned a 200 with admin UI and no redirect to login.",
                evidence=f"/{path} → 200 with admin-looking content, no auth redirect",
                remediation="Gate admin routes behind authentication + authorization; deny by default.", confirmed=False,
            ))
    return out
