// Surface mapping, find the attack surface before hunting it.
//
// Crawls same-host pages (bounded), extracts links, form actions and their input
// names, and reads robots.txt / sitemap.xml. Populates ctx.endpoints so injection
// checks have real places to bite.

import type { HttpEngine } from "./http.js";
import type { Endpoint, ScanContext } from "./types.js";
import { sameHost, stripQuery } from "./util.js";

export function contextForTarget(target: string, engine: HttpEngine): ScanContext {
  const t = target.includes("://") ? target : "https://" + target;
  const u = new URL(t);
  const base = `${u.protocol}//${u.host}`;
  const start = u.pathname && u.pathname !== "/" ? t : base;
  return {
    baseUrl: base,
    host: u.hostname.toLowerCase(),
    engine,
    endpoints: [{ url: stripQuery(start), method: "GET", params: [...u.searchParams.keys()] }],
    notes: {},
  };
}

const HREF_RE = /<a[^>]+href=["']([^"'#]+)["']/gi;
const FORM_RE = /<form[^>]*>([\s\S]*?)<\/form>/gi;
const ACTION_RE = /action=["']([^"']*)["']/i;
const METHOD_RE = /method=["']([^"']*)["']/i;
const INPUT_RE = /<(?:input|textarea|select)[^>]+name=["']([^"']+)["']/gi;

export async function crawl(ctx: ScanContext, maxPages = 25): Promise<string[]> {
  const seen = new Set<string>();
  const queue: string[] = [ctx.baseUrl, ctx.baseUrl + "/robots.txt", ctx.baseUrl + "/sitemap.xml"];
  const knownParams = new Map<string, Set<string>>();
  const forms: Endpoint[] = [];

  while (queue.length && seen.size < maxPages) {
    const url = queue.shift()!;
    if (seen.has(url) || !sameHost(url, ctx.host)) continue;
    seen.add(url);
    const resp = await ctx.engine.get(url, { followRedirects: true });
    if (resp.error || !resp.text) continue;

    if (url.endsWith("robots.txt")) {
      for (const m of resp.text.matchAll(/(?:Allow|Disallow|Sitemap):\s*(\S+)/gi)) {
        try {
          queue.push(new URL(m[1], ctx.baseUrl).toString());
        } catch {
          /* ignore */
        }
      }
      continue;
    }
    if (url.endsWith(".xml")) {
      for (const m of resp.text.matchAll(/<loc>([^<]+)<\/loc>/gi)) queue.push(m[1].trim());
      continue;
    }

    for (const m of resp.text.matchAll(HREF_RE)) {
      let next: string;
      try {
        next = new URL(m[1], url).toString();
      } catch {
        continue;
      }
      if (!sameHost(next, ctx.host)) continue;
      const base = stripQuery(next);
      const q = [...new URL(next).searchParams.keys()];
      if (q.length) {
        if (!knownParams.has(base)) knownParams.set(base, new Set());
        q.forEach((k) => knownParams.get(base)!.add(k));
      }
      if (!seen.has(base)) queue.push(base);
    }

    for (const fm of resp.text.matchAll(FORM_RE)) {
      const body = fm[1];
      const actionM = body.match(ACTION_RE);
      let action: string;
      try {
        action = new URL(actionM ? actionM[1] : url, url).toString();
      } catch {
        continue;
      }
      if (!sameHost(action, ctx.host)) continue;
      const methodM = body.match(METHOD_RE);
      const method = methodM ? methodM[1].toUpperCase() : "GET";
      const names = [...body.matchAll(INPUT_RE)].map((x) => x[1]);
      forms.push({ url: stripQuery(action), method, params: names });
    }
  }

  const endpoints = new Map<string, Endpoint>();
  for (const url of seen) {
    const base = stripQuery(url);
    const key = base + "|GET";
    const params = new Set<string>([...new URL(url).searchParams.keys(), ...(knownParams.get(base) ?? [])]);
    if (endpoints.has(key)) {
      params.forEach((p) => endpoints.get(key)!.params.push(p));
    } else {
      endpoints.set(key, { url: base, method: "GET", params: [...params] });
    }
  }
  for (const f of forms) {
    const key = f.url + "|" + f.method;
    if (endpoints.has(key)) {
      const merged = new Set([...endpoints.get(key)!.params, ...f.params]);
      endpoints.get(key)!.params = [...merged];
    } else {
      endpoints.set(key, f);
    }
  }
  for (const ep of endpoints.values()) ep.params = [...new Set(ep.params)];

  ctx.endpoints = [...endpoints.values()];
  ctx.notes.pagesCrawled = seen.size;
  ctx.notes.endpointsFound = ctx.endpoints.length;
  return [...seen].sort();
}
