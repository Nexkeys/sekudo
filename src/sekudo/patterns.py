"""Payloads and detection patterns.

Payloads here are chosen to *prove* a flaw with a benign marker, not to damage.
SQLi payloads read/compare; they never DROP, DELETE, or dump wholesale. The XSS
and SSTI markers are inert canaries. Traversal reads well-known read-only files.
"""

from __future__ import annotations

import re

# --- SQL injection ---------------------------------------------------------
SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning:\s+mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"psql:\s+error",
    r"sqlite3?::",
    r"sqlite_error",
    r"ora-\d{5}",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"syntax error at or near",
]
SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_SIGNATURES), re.I)

# Benign boolean pair: TRUE page should differ from FALSE page.
SQLI_BOOLEAN_TRUE = "' AND '1'='1"
SQLI_BOOLEAN_FALSE = "' AND '1'='2"
SQLI_ERROR_PROBE = "'"
# Time-based: a short, bounded sleep to prove execution without hammering.
SQLI_TIME_PROBES = [
    "' AND SLEEP(3)-- -",            # MySQL
    "';SELECT pg_sleep(3)-- -",      # Postgres
    "' WAITFOR DELAY '0:0:3'-- -",   # MSSQL
]
SQLI_TIME_THRESHOLD_MS = 2800

# --- NoSQL injection -------------------------------------------------------
NOSQLI_PAYLOADS = ['{"$ne": null}', '{"$gt": ""}', "[$ne]=1"]

# --- XSS (reflection) ------------------------------------------------------
XSS_MARKER = "sekudoXSS9f3a"
XSS_PROBES = [
    f"<{XSS_MARKER}>",
    f"\"'><{XSS_MARKER}>",
]

# --- SSTI ------------------------------------------------------------------
# 7*7 markers; if 49 (or 49-equivalent) reflects, template eval happened.
SSTI_PROBES = {
    "{{73*73}}": "5329",
    "${73*73}": "5329",
    "#{73*73}": "5329",
    "<%= 73*73 %>": "5329",
}

# --- Path traversal (read-only well-known files) ---------------------------
TRAVERSAL_PROBES = [
    ("../../../../etc/passwd", re.compile(r"root:.*:0:0:")),
    ("..%2f..%2f..%2f..%2fetc%2fpasswd", re.compile(r"root:.*:0:0:")),
    ("../../../../windows/win.ini", re.compile(r"\[fonts\]|\[extensions\]", re.I)),
]

# --- Command injection (benign echo marker via sleep/echo) -----------------
CMDI_MARKER = "sekudoCMD7b2e"
CMDI_PROBES = [f";echo {CMDI_MARKER}", f"|echo {CMDI_MARKER}", f"`echo {CMDI_MARKER}`"]

# --- Open redirect ---------------------------------------------------------
OPEN_REDIRECT_TARGET = "https://sekudo.example/redirect-canary"
OPEN_REDIRECT_PARAMS = ["url", "next", "redirect", "redirect_uri", "return", "returnUrl", "dest", "destination", "continue"]

# --- SSRF (callback marker; blind detection is advisory without a collector)
SSRF_PARAMS = ["url", "uri", "path", "dest", "domain", "callback", "webhook", "feed", "src", "target"]

# --- Secret / API key leakage ---------------------------------------------
SECRET_PATTERNS: dict[str, re.Pattern] = {
    "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Access Key": re.compile(r"(?i)aws(.{0,20})?(secret|private).{0,3}['\"=:\s]([0-9a-zA-Z/+]{40})"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Google OAuth Token": re.compile(r"ya29\.[0-9A-Za-z\-_]+"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
    "Slack Webhook": re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+"),
    "Stripe Live Secret": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "Stripe Restricted": re.compile(r"rk_live_[0-9a-zA-Z]{24,}"),
    "GitHub Token": re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"),
    "GitLab PAT": re.compile(r"glpat-[0-9A-Za-z\-_]{20,}"),
    "Private Key Block": re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "Twilio SID": re.compile(r"AC[0-9a-fA-F]{32}"),
    "SendGrid Key": re.compile(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"),
    "Mailgun Key": re.compile(r"key-[0-9a-f]{32}"),
    "Generic Bearer Secret": re.compile(r"(?i)(api[_-]?key|secret|token|passwd|password)['\"=:\s]{1,4}['\"]?[0-9a-zA-Z\-_]{16,}"),
}

# Files/paths worth probing for exposure (all read-only GETs).
SENSITIVE_PATHS = [
    ".env", ".env.local", ".env.production",
    ".git/config", ".git/HEAD",
    ".svn/entries", ".hg/hgrc",
    "config.php.bak", "config.json", "settings.py",
    "wp-config.php.bak", "web.config", "appsettings.json",
    "backup.zip", "backup.sql", "db.sql", "dump.sql",
    "docker-compose.yml", "Dockerfile",
    "phpinfo.php", "info.php",
    ".DS_Store", "id_rsa", ".npmrc", ".dockercfg",
    "swagger.json", "openapi.json", "api-docs",
    "actuator", "actuator/env", "actuator/health",
    "server-status", "debug", "__debug__",
]

# Security headers every app should set.
SECURITY_HEADERS = {
    "content-security-policy": "Define a CSP to constrain script/style/connect sources.",
    "strict-transport-security": "Send HSTS so browsers refuse downgrade to HTTP.",
    "x-content-type-options": "Set `nosniff` to stop MIME sniffing.",
    "x-frame-options": "Set DENY/SAMEORIGIN (or CSP frame-ancestors) to stop clickjacking.",
    "referrer-policy": "Set a restrictive referrer policy to avoid leaking URLs.",
    "permissions-policy": "Restrict powerful browser features you do not use.",
}

# Default credential pairs to test ONLY against the operator's own admin forms.
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("root", "root"), ("root", "toor"), ("administrator", "administrator"),
    ("test", "test"), ("guest", "guest"),
]

# Dangerous HTTP methods to probe for.
DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]

# Common unauthenticated data-store ports (host-level exposure checks).
DATASTORE_PORTS = {
    "MongoDB": 27017, "Redis": 6379, "Elasticsearch": 9200,
    "PostgreSQL": 5432, "MySQL": 3306, "CouchDB": 5984, "Memcached": 11211,
}
