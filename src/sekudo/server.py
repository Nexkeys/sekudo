"""Sekudo MCP server.

Exposes the scanner to any MCP-capable model host (Claude Code, Codex, etc.).
The host model orchestrates; Sekudo's tools do the actual network work. Every
tool that touches a target routes through the scope gate first.
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from . import __version__
from .checks import ScanContext, catalog, run_selected
from .http import HttpEngine
from .recon import crawl
from .report import ScanReport, now_iso
from .scope import Config, ScopeError, authorize

mcp = FastMCP("sekudo")


@mcp.tool()
def about() -> str:
    """What Sekudo is, and the rules it operates under."""
    return (
        f"Sekudo v{__version__} — a scope-gated DAST exploitation engine exposed over MCP.\n\n"
        "It hunts hard (recon + 34 active OWASP-mapped checks) and PROVES findings with benign "
        "proof-of-concept. It only tests targets you declare you own or are authorized to assess, "
        "in sekudo.config.yaml. It will not: attack out-of-scope hosts, dump or destroy data, drop "
        "persistence/backdoors, or disable the host model's own judgment. Start with `check_scope`, "
        "then `scan`."
    )


@mcp.tool()
def list_checks() -> str:
    """List every available check, grouped by OWASP Top 10 category."""
    by_owasp: dict[str, list[str]] = {}
    for c in catalog():
        by_owasp.setdefault(c.owasp, []).append(f"  - {c.id}: {c.name}")
    lines = [f"Sekudo check catalog ({len(catalog())} checks):", ""]
    for owasp in sorted(by_owasp):
        lines.append(owasp)
        lines.extend(sorted(by_owasp[owasp]))
        lines.append("")
    return "\n".join(lines)


@mcp.tool()
def check_scope(target: str) -> str:
    """Report whether `target` is in the operator's authorized scope — makes no requests."""
    try:
        cfg = Config.load()
    except ScopeError as e:
        return f"NOT READY: {e}"
    try:
        host = authorize(target, confirm=True, config=cfg)
        return f"IN SCOPE: {host} matches authorized_targets in {cfg.source}. Safe to scan."
    except ScopeError as e:
        return f"OUT OF SCOPE: {e}"


async def _run_scan(target: str, categories, check_ids, max_pages: int) -> ScanReport:
    cfg = Config.load()
    authorize(target, confirm=True, config=cfg)  # raises if out of scope
    engine = HttpEngine(cfg.max_requests_per_scan, cfg.requests_per_second)
    started = now_iso()
    try:
        ctx = ScanContext.for_target(target, engine)
        await crawl(ctx, max_pages=max_pages)
        findings = await run_selected(ctx, categories=categories, check_ids=check_ids)
    finally:
        await engine.aclose()
    report = ScanReport(
        target=target, started_at=started, finished_at=now_iso(),
        requests_made=engine.requests_made, findings=findings,
    )
    return report


def _save(report: ScanReport) -> tuple[str, str]:
    out_dir = Path(os.environ.get("SEKUDO_REPORT_DIR", "reports"))
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = report.finished_at.replace(":", "").replace("-", "")
    safe = report.target.replace("://", "_").replace("/", "_").replace(":", "_")
    md = out_dir / f"{safe}_{stamp}.sekudo.md"
    js = out_dir / f"{safe}_{stamp}.sekudo.json"
    md.write_text(report.to_markdown(), encoding="utf-8")
    js.write_text(report.to_json(), encoding="utf-8")
    return str(md), str(js)


@mcp.tool()
async def scan(
    target: str,
    confirm: bool = False,
    categories: list[str] | None = None,
    check_ids: list[str] | None = None,
    max_pages: int = 25,
) -> str:
    """Run a full scan against an in-scope target.

    Args:
        target: URL or host to test. MUST be in sekudo.config.yaml authorized_targets.
        confirm: Must be true to run — an explicit per-run acknowledgement.
        categories: Optional filter, e.g. ["injection","auth"]. Omit for all.
        check_ids: Optional exact check ids, e.g. ["inj.sqli.error"]. Omit for all.
        max_pages: Crawl budget for surface mapping (default 25).

    Returns the Markdown report and the paths of the saved report files.
    """
    try:
        cfg = Config.load()
        authorize(target, confirm=confirm, config=cfg)
    except ScopeError as e:
        return f"REFUSED (scope gate): {e}"

    report = await _run_scan(target, categories, check_ids, max_pages)
    try:
        md_path, js_path = _save(report)
        footer = f"\n\n_Saved: {md_path}  |  {js_path}_"
    except Exception as e:  # noqa: BLE001
        footer = f"\n\n_(could not save report files: {e})_"
    return report.to_markdown() + footer


def run() -> None:
    mcp.run()
