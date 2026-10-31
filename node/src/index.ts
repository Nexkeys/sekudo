#!/usr/bin/env node
// Entry point: `sekudo-mcp` starts the MCP server over stdio.
// `sekudo-mcp --selftest` prints the registered checks and exits.

import { catalog } from "./checks/index.js";

async function main(): Promise<void> {
  if (process.argv.includes("--selftest")) {
    const cs = catalog();
    console.log(`sekudo selftest: ${cs.length} checks registered`);
    for (const c of cs) {
      console.log(`  ${c.id.padEnd(24)} ${c.owasp.padEnd(40)} ${c.name}`);
    }
    return;
  }
  const { runServer } = await import("./server.js");
  await runServer();
}

main().catch((e) => {
  console.error(`sekudo fatal: ${e?.stack ?? e}`);
  process.exit(1);
});
