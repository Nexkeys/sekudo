"""Scope gate, the fence.

Every tool that touches a network target routes through `authorize()`. A target
is only in scope when ALL of the following hold:

  1. The operator config exists and sets `i_am_authorized: true` (an explicit,
     human-set attestation that they own or are permitted to test the listed
     targets).
  2. The target host matches an entry in `authorized_targets`.
  3. The caller passed `confirm=True` for this run.

This is deliberate and non-negotiable: Sekudo is a tool for testing systems you
control. It is not a facility for attacking third parties, and the gate refuses
anything it cannot tie to the operator's own declaration.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml

CONFIG_ENV = "SEKUDO_CONFIG"
DEFAULT_CONFIG_NAMES = ("sekudo.config.yaml", "sekudo.config.yml")


class ScopeError(Exception):
    """Raised when a target is out of scope or authorization is missing."""


@dataclass
class Config:
    i_am_authorized: bool = False
    authorized_targets: list[str] = field(default_factory=list)
    max_requests_per_scan: int = 2000
    requests_per_second: float = 20.0
    allow_private_ranges: bool = True  # own lab hosts are usually private
    source: str | None = None

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "Config":
        candidate = _resolve_config_path(path)
        if candidate is None:
            raise ScopeError(
                "No sekudo config found. Create sekudo.config.yaml (see "
                "sekudo.config.example.yaml) and set i_am_authorized: true with "
                "your authorized_targets before scanning."
            )
        data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
        cfg = cls(
            i_am_authorized=bool(data.get("i_am_authorized", False)),
            authorized_targets=[str(t).strip().lower() for t in data.get("authorized_targets", [])],
            max_requests_per_scan=int(data.get("max_requests_per_scan", 2000)),
            requests_per_second=float(data.get("requests_per_second", 20.0)),
            allow_private_ranges=bool(data.get("allow_private_ranges", True)),
            source=str(candidate),
        )
        return cfg


def _resolve_config_path(path: str | os.PathLike | None) -> Path | None:
    if path:
        p = Path(path)
        return p if p.is_file() else None
    env = os.environ.get(CONFIG_ENV)
    if env and Path(env).is_file():
        return Path(env)
    for name in DEFAULT_CONFIG_NAMES:
        p = Path.cwd() / name
        if p.is_file():
            return p
    return None


def _host_of(target: str) -> str:
    t = target.strip()
    if "://" not in t:
        t = "http://" + t
    host = (urlparse(t).hostname or "").lower()
    if not host:
        raise ScopeError(f"Could not parse a host from target: {target!r}")
    return host


def _host_matches(host: str, pattern: str) -> bool:
    """Exact host, suffix wildcard (*.example.com), or CIDR match."""
    pattern = pattern.strip().lower()
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    # CIDR / IP range support for lab networks
    if "/" in pattern:
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False
    return host == pattern


def authorize(target: str, confirm: bool, config: Config | None = None) -> str:
    """Return the validated host or raise ScopeError.

    This is the single choke point. Do not bypass it.
    """
    cfg = config or Config.load()
    if not cfg.i_am_authorized:
        raise ScopeError(
            "Refused: config has i_am_authorized: false. Sekudo only tests "
            "targets you own or are explicitly permitted to assess. Set this to "
            "true to attest that the listed targets are yours."
        )
    if not confirm:
        raise ScopeError(
            "Refused: this run was not confirmed. Pass confirm=true to proceed "
            "against an in-scope target."
        )
    host = _host_of(target)
    if not cfg.authorized_targets:
        raise ScopeError("Refused: authorized_targets is empty. Add the hosts you may test.")
    for pattern in cfg.authorized_targets:
        if _host_matches(host, pattern):
            return host
    raise ScopeError(
        f"Refused: {host!r} is not in authorized_targets. Sekudo will not touch "
        f"targets outside your declared scope. Add it to the allowlist only if "
        f"you own it or are authorized to test it."
    )
