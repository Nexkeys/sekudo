// Small URL helpers shared by checks.

export function setParam(url: string, param: string, value: string): string {
  const u = new URL(url.includes("://") ? url : "https://" + url);
  u.searchParams.set(param, value);
  return u.toString();
}

export function paramsOf(url: string): string[] {
  try {
    return [...new URL(url).searchParams.keys()];
  } catch {
    return [];
  }
}

export function sameHost(url: string, host: string): boolean {
  try {
    return new URL(url).hostname.toLowerCase() === host;
  } catch {
    return false;
  }
}

export function stripQuery(url: string): string {
  return url.split("?")[0].split("#")[0];
}
