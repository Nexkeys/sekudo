"""Bounded, rate-limited HTTP engine.

Aggressive by default (fast, parallel, thorough) but never unbounded: every scan
shares a request budget and a token-bucket rate limiter so Sekudo stresses a
target you own without turning into a denial-of-service cannon. The operator can
raise the ceilings in config for their own lab.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

import httpx

USER_AGENT = "sekudo/0.1 (+https://github.com/Nexkeys/sekudo; authorized-testing-only)"


class BudgetExceeded(Exception):
    """Raised when a scan hits its request budget, a safety stop, not an error."""


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    text: str
    elapsed_ms: float
    error: str | None = None


class _TokenBucket:
    def __init__(self, rate_per_sec: float):
        self.rate = max(0.1, rate_per_sec)
        self._tokens = self.rate
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def take(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self._tokens = min(self.rate, self._tokens + (now - self._last) * self.rate)
            self._last = now
            if self._tokens < 1:
                wait = (1 - self._tokens) / self.rate
                await asyncio.sleep(wait)
                self._tokens = 0
            else:
                self._tokens -= 1


class HttpEngine:
    def __init__(self, max_requests: int, rps: float, timeout: float = 10.0):
        self.max_requests = max_requests
        self._count = 0
        self._bucket = _TokenBucket(rps)
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            verify=False, # testing targets often use self-signed certs in lab
            headers={"User-Agent": USER_AGENT},
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )

    @property
    def requests_made(self) -> int:
        return self._count

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        data=None,
        json=None,
        headers: dict | None = None,
        follow_redirects: bool = False,
    ) -> Response:
        if self._count >= self.max_requests:
            raise BudgetExceeded(
                f"Request budget of {self.max_requests} reached, stopping this scan. "
                f"Raise max_requests_per_scan in config for a bigger run."
            )
        await self._bucket.take()
        self._count += 1
        start = time.monotonic()
        try:
            resp = await self._client.request(
                method, url, params=params, data=data, json=json,
                headers=headers, follow_redirects=follow_redirects,
            )
            body = resp.text if len(resp.content) < 2_000_000 else resp.text[:2_000_000]
            return Response(
                url=str(resp.url),
                status=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                text=body,
                elapsed_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as exc:  # noqa: BLE001, surface network errors as data
            return Response(
                url=url, status=0, headers={}, text="",
                elapsed_ms=(time.monotonic() - start) * 1000, error=f"{type(exc).__name__}: {exc}",
            )

    async def get(self, url: str, **kw) -> Response:
        return await self.request("GET", url, **kw)

    async def aclose(self) -> None:
        await self._client.aclose()
