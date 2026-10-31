// Sekudo MCP server (Node/TypeScript).
//
// Exposes the scanner to any MCP host (Claude Code, Cursor, Codex, etc.) over
// stdio. The host model orchestrates; these tools do the network work. Every
// target-touching tool routes through the scope gate first.

import { mkdirSync, writeFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { catalog, runSelected } from "./checks/index.js";
import { HttpEngine } from "./http.js";
import { contextForTarget, crawl } from "./recon.js";
import { ScanReport, nowIso } from "./report.js";
import { authorize, loadConfig, ScopeError } from "./scope.js";

const VERSION = "0.1.0";

function textResult(text: string) {
  return { content: [{ type: "text" as const, text }] };
}

async function runScan(
  target: string,
  categories: string[] | undefined,
  checkIds: string[] | undefined,
  maxPages: number,
): Promise<ScanReport> {
  const cfg = loadConfig();
  authorize(target, true, cfg); // throws if out of scope
  const engine = new HttpEngine(cfg.maxRequestsPerScan, cfg.requestsPerSecond);
  const started = nowIso();
  const ctx = contextForTarget(target, engine);
  await crawl(ctx, maxPages);
  const findings = await runSelected(ctx, { categories, checkIds });
  return new ScanReport(target, started, nowIso(), engine.requestsMade, findings);
}

function saveReport(report: ScanReport): string {
  const dir = process.env.SEKUDO_REPORT_DIR ?? "reports";
  mkdirSync(dir, { recursive: true });
  const stamp = report.finishedAt.replace(/[:-]/g, "");
  const safe = report.target.replace(/:\/\//g, "_").replace(/[/:]/g, "_");
  const md = `${dir}/${safe}_${stamp}.sekudo.md`;
  const js = `${dir}/${safe}_${stamp}.sekudo.json`;
  writeFileSync(md, report.toMarkdown(), "utf-8");
  writeFileSync(js, report.toJSON(), "utf-8");
  return `${md}  |  ${js}`;
}

export function buildServer(): McpServer {
  const server = new McpServer({ name: "sekudo", version: VERSION });

  server.tool("about", "What Sekudo is, and the rules it operates under.", {}, async () =>
    textResult(
      `Sekudo v${VERSION}, a scope-gated DAST exploitation engine over MCP.\n\n` +
        "It hunts hard (recon + 34 active OWASP-mapped checks) and PROVES findings with benign " +
        "proof-of-concept. It only tests targets you declare you own or are authorized to assess " +
        "(SEKUDO_TARGETS + SEKUDO_AUTHORIZED=true, or a SEKUDO_CONFIG file). It will not attack " +
        "out-of-scope hosts, dump or destroy data, drop persistence, or disable the host model's " +
        "judgment. Start with check_scope, then scan.",
    ),
  );

  server.tool("list_checks", "List every available check, grouped by OWASP Top 10 category.", {}, async () => {
    const byOwasp = new Map<string, string[]>();
    for (const c of catalog()) {
      if (!byOwasp.has(c.owasp)) byOwasp.set(c.owasp, []);
      byOwasp.get(c.owasp)!.push(`  - ${c.id}: ${c.name}`);
    }
    const lines = [`Sekudo check catalog (${catalog().length} checks):`, ""];
    for (const owasp of [...byOwasp.keys()].sort()) {
      lines.push(owasp, ...byOwasp.get(owasp)!.sort(), "");
    }
    return textResult(lines.join("\n"));
  });

  server.tool(
    "check_scope",
    "Report whether a target is in the operator's authorized scope. Makes no requests.",
    { target: z.string().describe("URL or host to check against the allowlist") },
    async ({ target }) => {
      let cfg;
      try {
        cfg = loadConfig();
      } catch (e) {
        return textResult(`NOT READY: ${(e as Error).message}`);
      }
      try {
        const host = authorize(target, true, cfg);
        return textResult(`IN SCOPE: ${host} matches the allowlist (source: ${cfg.source}). Safe to scan.`);
      } catch (e) {
        return textResult(`OUT OF SCOPE: ${(e as Error).message}`);
      }
    },
  );

  server.tool(
    "scan",
    "Run a scan against an in-scope target. Requires confirm=true. Returns a Markdown report.",
    {
      target: z.string().describe("URL or host. MUST be in the allowlist (SEKUDO_TARGETS)."),
      confirm: z.boolean().default(false).describe("Must be true to run, an explicit per-run acknowledgement."),
      categories: z
        .array(z.string())
        .optional()
        .describe('Optional filter, e.g. ["injection","auth"]. Omit for all.'),
      checkIds: z.array(z.string()).optional().describe('Optional exact check ids, e.g. ["inj.sqli.error"].'),
      maxPages: z.number().int().positive().default(25).describe("Crawl budget for surface mapping."),
    },
    async ({ target, confirm, categories, checkIds, maxPages }) => {
      try {
        const cfg = loadConfig();
        authorize(target, confirm, cfg);
      } catch (e) {
        return textResult(`REFUSED (scope gate): ${(e as Error).message}`);
      }
      const report = await runScan(target, categories, checkIds, maxPages);
      let footer = "";
      try {
        footer = `\n\n_Saved: ${saveReport(report)}_`;
      } catch (e) {
        footer = `\n\n_(could not save report files: ${(e as Error).message})_`;
      }
      return textResult(report.toMarkdown() + footer);
    },
  );

  return server;
}

export async function runServer(): Promise<void> {
  const server = buildServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
