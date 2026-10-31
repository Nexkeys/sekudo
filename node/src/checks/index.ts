// Check registry + runner. Modules export their checks statically (no cycle).

import type { Finding } from "../report.js";
import type { CheckDef, ScanContext } from "../types.js";
import { BudgetExceeded } from "../http.js";

import { checks as injection } from "./injection.js";
import { checks as accessControl } from "./accessControl.js";
import { checks as crypto } from "./crypto.js";
import { checks as misconfig } from "./misconfig.js";
import { checks as auth } from "./auth.js";
import { checks as exposure } from "./exposure.js";
import { checks as components } from "./components.js";

const ALL: CheckDef[] = [
  ...injection,
  ...accessControl,
  ...crypto,
  ...misconfig,
  ...auth,
  ...exposure,
  ...components,
];

// Guard against accidental duplicate ids.
const _ids = new Set<string>();
for (const c of ALL) {
  if (_ids.has(c.id)) throw new Error(`duplicate check id: ${c.id}`);
  _ids.add(c.id);
}

export function catalog(): CheckDef[] {
  return [...ALL].sort((a, b) => a.id.localeCompare(b.id));
}

export async function runSelected(
  ctx: ScanContext,
  opts: { categories?: string[]; checkIds?: string[] } = {},
): Promise<Finding[]> {
  const selected = catalog().filter((c) => {
    if (opts.checkIds && !opts.checkIds.includes(c.id)) return false;
    if (opts.categories && !opts.categories.includes(c.category)) return false;
    return true;
  });
  const findings: Finding[] = [];
  const errors: Record<string, string> = {};
  for (const c of selected) {
    try {
      findings.push(...(await c.fn(ctx)));
    } catch (e) {
      if (e instanceof BudgetExceeded) break; // safety stop
      errors[c.id] = `${(e as Error).name}: ${(e as Error).message}`;
    }
  }
  if (Object.keys(errors).length) ctx.notes.checkErrors = errors;
  return findings;
}
