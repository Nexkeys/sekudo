"""Findings model + report rendering.

Every bite the hyena takes comes back as a Finding: where it bit, how, why it
matters, the evidence that proves it, and the patch. Findings render to both
JSON (machine) and Markdown (the human bite-by-bite report).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


@dataclass
class Finding:
    check_id: str
    title: str
    owasp: str              # e.g. "A03:2021 Injection"
    severity: Severity
    target: str             # the URL/endpoint where it bit
    description: str        # how & why
    evidence: str           # the proof-of-concept result (benign)
    remediation: str        # the patch
    references: list[str] = field(default_factory=list)
    confirmed: bool = False  # True when a PoC proved it, False when only indicated

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanReport:
    target: str
    started_at: str
    finished_at: str
    requests_made: int
    findings: list[Finding] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, not f.confirmed, f.check_id))

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def to_json(self) -> str:
        return json.dumps(
            {
                "target": self.target,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "requests_made": self.requests_made,
                "counts": self.counts(),
                "findings": [f.to_dict() for f in self.sorted_findings()],
            },
            indent=2,
        )

    def to_markdown(self) -> str:
        c = self.counts()
        lines = [
            f"# Sekudo report, {self.target}",
            "",
            f"- Started: {self.started_at}",
            f"- Finished: {self.finished_at}",
            f"- Requests made: {self.requests_made}",
            f"- Findings: **{c['critical']} critical**, {c['high']} high, "
            f"{c['medium']} medium, {c['low']} low, {c['info']} info",
            "",
            "---",
            "",
        ]
        if not self.findings:
            lines.append("No findings. Either the target is tight, or the budget "
                         "ran out before deeper checks, raise it and re-run.")
            return "\n".join(lines)
        for f in self.sorted_findings():
            badge = "✅ CONFIRMED" if f.confirmed else "⚠️ INDICATED"
            lines += [
                f"## [{f.severity.value.upper()}] {f.title}  ({badge})",
                "",
                f"- **Check:** `{f.check_id}`",
                f"- **OWASP:** {f.owasp}",
                f"- **Where it bit:** {f.target}",
                "",
                f"**How & why**  \n{f.description}",
                "",
                f"**Evidence (proof-of-concept)**  \n```\n{f.evidence}\n```",
                "",
                f"**Patch**  \n{f.remediation}",
                "",
            ]
            if f.references:
                lines.append("**References**  \n" + "\n".join(f"- {r}" for r in f.references))
                lines.append("")
            lines.append("---")
            lines.append("")
        return "\n".join(lines)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
