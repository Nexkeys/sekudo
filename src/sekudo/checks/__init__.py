"""Check registry + scan context + runner.

Each check is an async function registered with metadata. The runner executes
the selected checks against a shared ScanContext, isolating failures so one
dead check never aborts the hunt.
"""

from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field
from typing import Awaitable, Callable
from urllib.parse import urlparse

from ..http import BudgetExceeded, HttpEngine
from ..report import Finding


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)


@dataclass
class ScanContext:
    base_url: str
    host: str
    engine: HttpEngine
    endpoints: list[Endpoint] = field(default_factory=list)
    notes: dict = field(default_factory=dict)

    @classmethod
    def for_target(cls, target: str, engine: HttpEngine) -> "ScanContext":
        t = target if "://" in target else "https://" + target
        parsed = urlparse(t)
        host = parsed.hostname or ""
        base = f"{parsed.scheme}://{parsed.netloc}"
        ctx = cls(base_url=base, host=host, engine=engine)
        start = t if parsed.path and parsed.path != "/" else base
        ctx.endpoints.append(Endpoint(url=start, params=_params_of(t)))
        return ctx


def _params_of(url: str) -> list[str]:
    from urllib.parse import parse_qs
    q = urlparse(url).query
    return list(parse_qs(q).keys())


CheckFn = Callable[[ScanContext], Awaitable[list[Finding]]]


@dataclass
class CheckDef:
    id: str
    name: str
    owasp: str
    category: str
    fn: CheckFn


_REGISTRY: dict[str, CheckDef] = {}


def register(id: str, name: str, owasp: str, category: str):
    def deco(fn: CheckFn) -> CheckFn:
        if id in _REGISTRY:
            raise ValueError(f"duplicate check id: {id}")
        _REGISTRY[id] = CheckDef(id=id, name=name, owasp=owasp, category=category, fn=fn)
        return fn
    return deco


def _ensure_loaded() -> None:
    # Import every submodule so their @register decorators run.
    pkg = importlib.import_module(__name__)
    for mod in pkgutil.iter_modules(pkg.__path__):
        if mod.name != "__init__":
            importlib.import_module(f"{__name__}.{mod.name}")


def catalog() -> list[CheckDef]:
    _ensure_loaded()
    return sorted(_REGISTRY.values(), key=lambda c: c.id)


async def run_selected(
    ctx: ScanContext,
    categories: list[str] | None = None,
    check_ids: list[str] | None = None,
) -> list[Finding]:
    _ensure_loaded()
    selected = []
    for c in _REGISTRY.values():
        if check_ids and c.id not in check_ids:
            continue
        if categories and c.category not in categories:
            continue
        selected.append(c)
    findings: list[Finding] = []
    for c in sorted(selected, key=lambda c: c.id):
        try:
            findings.extend(await c.fn(ctx))
        except BudgetExceeded:
            break  # safety stop — return what we have
        except Exception as exc:  # noqa: BLE001 — a dead check must not kill the scan
            ctx.notes.setdefault("check_errors", {})[c.id] = f"{type(exc).__name__}: {exc}"
    return findings
