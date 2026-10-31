"""Surface mapping, find the attack surface before hunting it.

Crawls same-host pages (bounded), extracts links, form actions and their input
names, and reads robots.txt / sitemap.xml for more paths. Populates
ctx.endpoints with URLs and their parameters so injection checks have real
places to bite.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, parse_qs

from .checks import Endpoint, ScanContext

_HREF_RE = re.compile(r"""<a[^>]+href=["']([^"'#]+)["']""", re.I)
_FORM_RE = re.compile(r"""<form[^>]*>(.*?)</form>""", re.I | re.S)
_ACTION_RE = re.compile(r"""action=["']([^"']*)["']""", re.I)
_METHOD_RE = re.compile(r"""method=["']([^"']*)["']""", re.I)
_INPUT_RE = re.compile(r"""<(?:input|textarea|select)[^>]+name=["']([^"']+)["']""", re.I)


def _same_host(url: str, host: str) -> bool:
    return (urlparse(url).hostname or "") == host


async def crawl(ctx: ScanContext, max_pages: int = 25) -> list[str]:
    seen: set[str] = set()
    queue: list[str] = [ctx.base_url]
    known_params: dict[str, set[str]] = {}
    forms: list[Endpoint] = []

    # seed with common well-known locations
    for extra in ("/robots.txt", "/sitemap.xml"):
        queue.append(urljoin(ctx.base_url, extra))

    while queue and len(seen) < max_pages:
        url = queue.pop(0)
        if url in seen or not _same_host(url, ctx.host):
            continue
        seen.add(url)
        resp = await ctx.engine.get(url, follow_redirects=True)
        if resp.error or not resp.text:
            continue

        # robots / sitemap path extraction
        if url.endswith("robots.txt"):
            for m in re.findall(r"(?:Allow|Disallow|Sitemap):\s*(\S+)", resp.text, re.I):
                queue.append(urljoin(ctx.base_url, m))
            continue
        if url.endswith(".xml"):
            for loc in re.findall(r"<loc>([^<]+)</loc>", resp.text, re.I):
                queue.append(loc.strip())
            continue

        # links
        for href in _HREF_RE.findall(resp.text):
            nxt = urljoin(url, href)
            if _same_host(nxt, ctx.host):
                base = nxt.split("#")[0]
                q = parse_qs(urlparse(base).query)
                if q:
                    key = base.split("?")[0]
                    known_params.setdefault(key, set()).update(q.keys())
                if base not in seen:
                    queue.append(base)

        # forms
        for body in _FORM_RE.findall(resp.text):
            action_m = _ACTION_RE.search(body)
            action = urljoin(url, action_m.group(1)) if action_m else url
            if not _same_host(action, ctx.host):
                continue
            method = (_METHOD_RE.search(body).group(1).upper()
                      if _METHOD_RE.search(body) else "GET")
            names = _INPUT_RE.findall(body)
            forms.append(Endpoint(url=action, method=method, params=names))

    # rebuild ctx.endpoints: parameterized URLs + forms, deduped
    endpoints: dict[tuple, Endpoint] = {}
    for url in seen:
        q = parse_qs(urlparse(url).query)
        key = (url.split("?")[0], "GET")
        params = set(q.keys()) | known_params.get(url.split("?")[0], set())
        if key in endpoints:
            endpoints[key].params = list(set(endpoints[key].params) | params)
        else:
            endpoints[key] = Endpoint(url=url.split("?")[0], method="GET", params=list(params))
    for f in forms:
        key = (f.url, f.method)
        if key in endpoints:
            endpoints[key].params = list(set(endpoints[key].params) | set(f.params))
        else:
            endpoints[key] = f

    ctx.endpoints = list(endpoints.values())
    ctx.notes["pages_crawled"] = len(seen)
    ctx.notes["endpoints_found"] = len(ctx.endpoints)
    return sorted(seen)
