// Bounded, rate-limited HTTP engine.
//
// Aggressive (fast, parallel, thorough) but never unbounded: a shared request
// budget plus a token-bucket limiter keep Sekudo from turning into a DoS cannon.

export const USER_AGENT = "sekudo/0.1 (+https://github.com/Nexkeys/sekudo; authorized-testing-only)";

export class BudgetExceeded extends Error {}

export interface SekudoResponse {
  url: string;
  status: number;
  headers: Record<string, string>;
  text: string;
  elapsedMs: number;
  error?: string;
}

class TokenBucket {
  private tokens: number;
  private last: number;
  constructor(private rate: number) {
    this.rate = Math.max(0.1, rate);
    this.tokens = this.rate;
    this.last = Date.now();
  }
  async take(): Promise<void> {
    const now = Date.now();
    this.tokens = Math.min(this.rate, this.tokens + ((now - this.last) / 1000) * this.rate);
    this.last = now;
    if (this.tokens < 1) {
      const waitMs = ((1 - this.tokens) / this.rate) * 1000;
      await new Promise((r) => setTimeout(r, waitMs));
      this.tokens = 0;
    } else {
      this.tokens -= 1;
    }
  }
}

export interface RequestOpts {
  params?: Record<string, string>;
  data?: Record<string, string>;
  json?: unknown;
  headers?: Record<string, string>;
  followRedirects?: boolean;
}

export class HttpEngine {
  private count = 0;
  private bucket: TokenBucket;
  constructor(
    private maxRequests: number,
    rps: number,
    private timeoutMs = 10000,
  ) {
    this.bucket = new TokenBucket(rps);
  }

  get requestsMade(): number {
    return this.count;
  }

  async request(method: string, url: string, opts: RequestOpts = {}): Promise<SekudoResponse> {
    if (this.count >= this.maxRequests) {
      throw new BudgetExceeded(
        `Request budget of ${this.maxRequests} reached, stopping this scan. Raise SEKUDO_MAX_REQUESTS for a bigger run.`,
      );
    }
    await this.bucket.take();
    this.count += 1;

    let full = url;
    if (opts.params) {
      const u = new URL(url);
      for (const [k, v] of Object.entries(opts.params)) u.searchParams.set(k, v);
      full = u.toString();
    }

    const headers: Record<string, string> = { "User-Agent": USER_AGENT, ...(opts.headers ?? {}) };
    let body: string | undefined;
    if (opts.json !== undefined) {
      body = JSON.stringify(opts.json);
      headers["Content-Type"] = "application/json";
    } else if (opts.data) {
      body = new URLSearchParams(opts.data).toString();
      headers["Content-Type"] = "application/x-www-form-urlencoded";
    }

    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), this.timeoutMs);
    const start = Date.now();
    try {
      const resp = await fetch(full, {
        method,
        headers,
        body,
        redirect: opts.followRedirects ? "follow" : "manual",
        signal: ctl.signal,
      });
      let text = "";
      try {
        text = await resp.text();
      } catch {
        text = "";
      }
      if (text.length > 2_000_000) text = text.slice(0, 2_000_000);
      const hdrs: Record<string, string> = {};
      resp.headers.forEach((v, k) => (hdrs[k.toLowerCase()] = v));
      return { url: resp.url || full, status: resp.status, headers: hdrs, text, elapsedMs: Date.now() - start };
    } catch (e) {
      return {
        url: full,
        status: 0,
        headers: {},
        text: "",
        elapsedMs: Date.now() - start,
        error: `${(e as Error).name}: ${(e as Error).message}`,
      };
    } finally {
      clearTimeout(timer);
    }
  }

  get(url: string, opts: RequestOpts = {}): Promise<SekudoResponse> {
    return this.request("GET", url, opts);
  }
}
