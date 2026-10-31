// Findings model + report rendering.
//
// Every bite comes back as a Finding: where it bit, how, why, the benign proof,
// and the patch. Findings render to JSON (machine) and Markdown (human).

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export const SEV_RANK: Record<Severity, number> = {
  info: 0, low: 1, medium: 2, high: 3, critical: 4,
};

export interface Finding {
  checkId: string;
  title: string;
  owasp: string;
  severity: Severity;
  target: string;
  description: string;
  evidence: string;
  remediation: string;
  references?: string[];
  confirmed: boolean;
}

export function nowIso(): string {
  return new Date().toISOString().replace(/\.\d+Z$/, "Z");
}

export class ScanReport {
  constructor(
    public target: string,
    public startedAt: string,
    public finishedAt: string,
    public requestsMade: number,
    public findings: Finding[],
  ) {}

  sorted(): Finding[] {
    return [...this.findings].sort((a, b) => {
      const s = SEV_RANK[b.severity] - SEV_RANK[a.severity];
      if (s !== 0) return s;
      const c = Number(a.confirmed) - Number(b.confirmed);
      if (c !== 0) return -c;
      return a.checkId.localeCompare(b.checkId);
    });
  }

  counts(): Record<Severity, number> {
    const out: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
    for (const f of this.findings) out[f.severity] += 1;
    return out;
  }

  toJSON(): string {
    return JSON.stringify(
      {
        target: this.target,
        startedAt: this.startedAt,
        finishedAt: this.finishedAt,
        requestsMade: this.requestsMade,
        counts: this.counts(),
        findings: this.sorted(),
      },
      null,
      2,
    );
  }

  toMarkdown(): string {
    const c = this.counts();
    const lines: string[] = [
      `# Sekudo report, ${this.target}`,
      "",
      `- Started: ${this.startedAt}`,
      `- Finished: ${this.finishedAt}`,
      `- Requests made: ${this.requestsMade}`,
      `- Findings: **${c.critical} critical**, ${c.high} high, ${c.medium} medium, ${c.low} low, ${c.info} info`,
      "",
      "---",
      "",
    ];
    if (this.findings.length === 0) {
      lines.push(
        "No findings. Either the target is tight, or the budget ran out before deeper checks, raise it and re-run.",
      );
      return lines.join("\n");
    }
    for (const f of this.sorted()) {
      const badge = f.confirmed ? "CONFIRMED" : "INDICATED";
      lines.push(
        `## [${f.severity.toUpperCase()}] ${f.title}  (${badge})`,
        "",
        `- **Check:** \`${f.checkId}\``,
        `- **OWASP:** ${f.owasp}`,
        `- **Where it bit:** ${f.target}`,
        "",
        `**How & why**  \n${f.description}`,
        "",
        `**Evidence (proof-of-concept)**  \n\`\`\`\n${f.evidence}\n\`\`\``,
        "",
        `**Patch**  \n${f.remediation}`,
        "",
      );
      if (f.references && f.references.length) {
        lines.push("**References**  \n" + f.references.map((r) => `- ${r}`).join("\n"), "");
      }
      lines.push("---", "");
    }
    return lines.join("\n");
  }
}
