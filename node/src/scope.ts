// Scope gate, the fence.
//
// Every tool that touches a target routes through authorize(). A target is only
// in scope when: the operator attested authorization (SEKUDO_AUTHORIZED=true or
// config i_am_authorized), the host matches the allowlist, and the run passed
// confirm=true. Config comes from env vars (so an MCP connector entry alone is
// enough) or an optional JSON file at SEKUDO_CONFIG.

import { readFileSync, existsSync } from "node:fs";

export class ScopeError extends Error {}

export interface Config {
  iAmAuthorized: boolean;
  authorizedTargets: string[];
  maxRequestsPerScan: number;
  requestsPerSecond: number;
  allowPrivateRanges: boolean;
  source: string;
}

function parseBool(v: string | undefined): boolean {
  return !!v && ["1", "true", "yes", "on"].includes(v.trim().toLowerCase());
}

export function loadConfig(): Config {
  // Optional JSON file overlay.
  let fileData: Record<string, unknown> = {};
  let source = "env";
  const path = process.env.SEKUDO_CONFIG;
  if (path && existsSync(path)) {
    try {
      fileData = JSON.parse(readFileSync(path, "utf-8"));
      source = path;
    } catch (e) {
      throw new ScopeError(`SEKUDO_CONFIG at ${path} is not valid JSON: ${(e as Error).message}`);
    }
  }

  const envTargets = (process.env.SEKUDO_TARGETS ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const fileTargets = Array.isArray(fileData.authorized_targets)
    ? (fileData.authorized_targets as string[]).map((s) => String(s).trim().toLowerCase())
    : [];

  return {
    iAmAuthorized: parseBool(process.env.SEKUDO_AUTHORIZED) || fileData.i_am_authorized === true,
    authorizedTargets: [...new Set([...envTargets, ...fileTargets])],
    maxRequestsPerScan: Number(process.env.SEKUDO_MAX_REQUESTS ?? fileData.max_requests_per_scan ?? 2000),
    requestsPerSecond: Number(process.env.SEKUDO_RPS ?? fileData.requests_per_second ?? 20),
    allowPrivateRanges:
      process.env.SEKUDO_ALLOW_PRIVATE !== undefined
        ? parseBool(process.env.SEKUDO_ALLOW_PRIVATE)
        : fileData.allow_private_ranges !== false,
    source,
  };
}

function hostOf(target: string): string {
  const t = target.includes("://") ? target : "http://" + target;
  let host = "";
  try {
    host = new URL(t).hostname.toLowerCase();
  } catch {
    host = "";
  }
  if (!host) throw new ScopeError(`Could not parse a host from target: ${JSON.stringify(target)}`);
  return host;
}

function ipToInt(ip: string): number | null {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function hostMatches(host: string, pattern: string): boolean {
  pattern = pattern.trim().toLowerCase();
  if (pattern.startsWith("*.")) {
    const base = pattern.slice(2);
    return host === base || host.endsWith("." + base);
  }
  if (pattern.includes("/")) {
    const [net, bitsRaw] = pattern.split("/");
    const bits = Number(bitsRaw);
    const h = ipToInt(host);
    const n = ipToInt(net);
    if (h === null || n === null || !(bits >= 0 && bits <= 32)) return false;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (h & mask) === (n & mask);
  }
  return host === pattern;
}

export function authorize(target: string, confirm: boolean, cfg: Config): string {
  if (!cfg.iAmAuthorized) {
    throw new ScopeError(
      "Refused: not authorized. Set SEKUDO_AUTHORIZED=true (or i_am_authorized: true) to attest " +
        "that the listed targets are yours to test.",
    );
  }
  if (!confirm) {
    throw new ScopeError("Refused: this run was not confirmed. Pass confirm=true against an in-scope target.");
  }
  const host = hostOf(target);
  if (cfg.authorizedTargets.length === 0) {
    throw new ScopeError("Refused: no authorized targets. Set SEKUDO_TARGETS to the hosts you may test.");
  }
  for (const pattern of cfg.authorizedTargets) {
    if (hostMatches(host, pattern)) return host;
  }
  throw new ScopeError(
    `Refused: ${JSON.stringify(host)} is not in the allowlist. Sekudo will not touch targets outside ` +
      "your declared scope. Add it only if you own it or are authorized to test it.",
  );
}
