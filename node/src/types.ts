// Shared types for checks, kept separate to avoid import cycles.

import type { Finding } from "./report.js";
import type { HttpEngine } from "./http.js";

export interface Endpoint {
  url: string;
  method: string; // "GET" | "POST"
  params: string[];
}

export interface ScanContext {
  baseUrl: string;
  host: string;
  engine: HttpEngine;
  endpoints: Endpoint[];
  notes: Record<string, unknown>;
}

export type CheckFn = (ctx: ScanContext) => Promise<Finding[]>;

export interface CheckDef {
  id: string;
  name: string;
  owasp: string;
  category: string;
  fn: CheckFn;
}
