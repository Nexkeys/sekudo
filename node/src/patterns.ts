// Payloads and detection patterns.
//
// Payloads here prove a flaw with a benign marker, not to damage. SQLi payloads
// read/compare/time; they never DROP, DELETE, or dump wholesale. XSS and SSTI
// markers are inert. Traversal reads well-known read-only files.

export const SQL_ERROR_RE = new RegExp(
  [
    "you have an error in your sql syntax",
    "warning:\\s+mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query\\(\\)",
    "psql:\\s+error",
    "sqlite3?::",
    "sqlite_error",
    "ora-\\d{5}",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "syntax error at or near",
  ].join("|"),
  "i",
);

export const SQLI_BOOLEAN_TRUE = "' AND '1'='1";
export const SQLI_BOOLEAN_FALSE = "' AND '1'='2";
export const SQLI_ERROR_PROBE = "'";
export const SQLI_TIME_PROBES = [
  "' AND SLEEP(3)-- -",
  "';SELECT pg_sleep(3)-- -",
  "' WAITFOR DELAY '0:0:3'-- -",
];
export const SQLI_TIME_THRESHOLD_MS = 2800;

export const NOSQLI_PAYLOADS = ['{"$ne": null}', '{"$gt": ""}', "[$ne]=1"];

export const XSS_MARKER = "sekudoXSS9f3a";
export const XSS_PROBES = [`<${XSS_MARKER}>`, `"'><${XSS_MARKER}>`];

export const SSTI_PROBES: Record<string, string> = {
  "{{73*73}}": "5329",
  "${73*73}": "5329",
  "#{73*73}": "5329",
  "<%= 73*73 %>": "5329",
};

export const TRAVERSAL_PROBES: Array<[string, RegExp]> = [
  ["../../../../etc/passwd", /root:.*:0:0:/],
  ["..%2f..%2f..%2f..%2fetc%2fpasswd", /root:.*:0:0:/],
  ["../../../../windows/win.ini", /\[fonts\]|\[extensions\]/i],
];

export const CMDI_MARKER = "sekudoCMD7b2e";
export const CMDI_PROBES = [`;echo ${CMDI_MARKER}`, `|echo ${CMDI_MARKER}`, `\`echo ${CMDI_MARKER}\``];

export const OPEN_REDIRECT_TARGET = "https://sekudo.example/redirect-canary";
export const OPEN_REDIRECT_PARAMS = [
  "url", "next", "redirect", "redirect_uri", "return", "returnurl", "dest", "destination", "continue",
];

export const SSRF_PARAMS = [
  "url", "uri", "path", "dest", "domain", "callback", "webhook", "feed", "src", "target",
];

export const SECRET_PATTERNS: Record<string, RegExp> = {
  "AWS Access Key ID": /AKIA[0-9A-Z]{16}/,
  "AWS Secret Access Key": /aws(.{0,20})?(secret|private).{0,3}['"=:\s]([0-9a-zA-Z/+]{40})/i,
  "Google API Key": /AIza[0-9A-Za-z\-_]{35}/,
  "Google OAuth Token": /ya29\.[0-9A-Za-z\-_]+/,
  "Slack Token": /xox[baprs]-[0-9A-Za-z-]{10,48}/,
  "Slack Webhook": /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]+\/B[0-9A-Z]+\/[0-9A-Za-z]+/,
  "Stripe Live Secret": /sk_live_[0-9a-zA-Z]{24,}/,
  "Stripe Restricted": /rk_live_[0-9a-zA-Z]{24,}/,
  "GitHub Token": /gh[pousr]_[0-9A-Za-z]{36,}/,
  "GitLab PAT": /glpat-[0-9A-Za-z\-_]{20,}/,
  "Private Key Block": /-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----/,
  "JWT": /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
  "Twilio SID": /AC[0-9a-fA-F]{32}/,
  "SendGrid Key": /SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}/,
  "Mailgun Key": /key-[0-9a-f]{32}/,
  "Generic Bearer Secret": /(api[_-]?key|secret|token|passwd|password)['"=:\s]{1,4}['"]?[0-9a-zA-Z\-_]{16,}/i,
};

export const SENSITIVE_PATHS = [
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
];

export const SECURITY_HEADERS: Record<string, string> = {
  "content-security-policy": "Define a CSP to constrain script/style/connect sources.",
  "strict-transport-security": "Send HSTS so browsers refuse downgrade to HTTP.",
  "x-content-type-options": "Set nosniff to stop MIME sniffing.",
  "x-frame-options": "Set DENY/SAMEORIGIN (or CSP frame-ancestors) to stop clickjacking.",
  "referrer-policy": "Set a restrictive referrer policy to avoid leaking URLs.",
  "permissions-policy": "Restrict powerful browser features you do not use.",
};

export const DEFAULT_CREDS: Array<[string, string]> = [
  ["admin", "admin"], ["admin", "password"], ["admin", "admin123"],
  ["root", "root"], ["root", "toor"], ["administrator", "administrator"],
  ["test", "test"], ["guest", "guest"],
];

export const DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"];
