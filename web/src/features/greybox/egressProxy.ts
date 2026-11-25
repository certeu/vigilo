// Pure helpers for opt-in grey-box egress proxies: validation mirroring the backend,
// host matching, payload building and failure-message mapping.
import type { EgressProxy, EgressProxyWrite } from "./types";

export const DIRECT_HINT =
  "If a browser can reach this host, it may require a proxy (PAC/WPAD); an administrator can configure an egress proxy.";

/** http(s)://host:port only: a port is required, no path, query, fragment or userinfo. */
export function validateProxyUrl(raw: string): string | null {
  const v = raw.trim();
  if (!v) return "Enter the proxy URL, e.g. http://proxy.example.org:3128";
  if (/\s/.test(v)) return "The URL must not contain spaces.";
  if (!/^https?:\/\//i.test(v)) return "The URL must start with http:// or https://.";
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    return "This is not a valid URL.";
  }
  if (u.username || u.password || /^https?:\/\/[^/]*@/i.test(v)) {
    return "Do not put credentials in the URL; use the username and password fields.";
  }
  if (!u.hostname) return "The URL needs a host.";
  // `new URL` hides an explicit default port (e.g. :80), so check the raw text too.
  if (!u.port && !/^https?:\/\/(\[[^\]]+\]|[^/:?#]+):\d+/i.test(v)) return "The URL needs an explicit port, e.g. :3128.";
  if (u.search || u.hash || /[?#]/.test(v)) return "The URL must not contain a query or fragment.";
  if (u.pathname !== "/" && u.pathname !== "") return "The URL must not contain a path.";
  return null;
}

const HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;

export function validateAllowedHost(raw: string): string | null {
  const h = raw.trim().toLowerCase();
  if (!h) return "Empty host.";
  if (h === "*" || h === "*.") return `"${raw.trim()}" would match every host; use an exact host or "*.suffix".`;
  if (h.includes("*") && !(h.startsWith("*.") && !h.slice(2).includes("*"))) {
    return `"${raw.trim()}": a wildcard is only allowed as a leading "*.".`;
  }
  const bare = h.startsWith("*.") ? h.slice(2) : h;
  if (!bare.includes(".") && h.startsWith("*.")) return `"${raw.trim()}" is too broad; use a full domain such as *.example.org.`;
  if (/[/:\s@]/.test(bare) && !/^\[[0-9a-f:]+\]$/.test(bare)) return `"${raw.trim()}" must be a host name only (no scheme, port or path).`;
  if (!HOST_RE.test(bare) && !/^\[[0-9a-f:]+\]$/.test(bare)) return `"${raw.trim()}" is not a valid host.`;
  return null;
}

/** Split a free-text list (newlines, commas, spaces) into lower-cased unique hosts. */
export function parseHosts(text: string): string[] {
  const out: string[] = [];
  for (const p of text.split(/[\s,;]+/)) {
    const h = p.trim().toLowerCase();
    if (h && !out.includes(h)) out.push(h);
  }
  return out;
}

export interface ProxyFormValues {
  name: string;
  url: string;
  username: string;
  password: string;
  hostsText: string;
  enabled: boolean;
}

export function validateProxyForm(v: ProxyFormValues): Partial<Record<"name" | "url" | "hosts" | "username", string>> {
  const errs: Partial<Record<"name" | "url" | "hosts" | "username", string>> = {};
  if (!v.name.trim()) errs.name = "Enter a name.";
  else if (v.name.trim().length > 200) errs.name = "The name is too long (max 200).";
  const u = validateProxyUrl(v.url);
  if (u) errs.url = u;
  const hosts = parseHosts(v.hostsText);
  if (hosts.length === 0) errs.hosts = "Add at least one allowed host.";
  else {
    const bad = hosts.map(validateAllowedHost).find(Boolean);
    if (bad) errs.hosts = bad;
  }
  if (v.password && !v.username.trim()) errs.username = "A password needs a username.";
  return errs;
}

/**
 * Create sends everything. Edit sends credentials only when typed: both blank keeps the
 * stored ones (the API never returns them); `clearCredentials` sends empty strings.
 */
export function buildProxyPayload(v: ProxyFormValues, editing: boolean, clearCredentials = false): EgressProxyWrite {
  const body: EgressProxyWrite = {
    name: v.name.trim(),
    url: v.url.trim(),
    allowed_hosts: parseHosts(v.hostsText),
    enabled: v.enabled,
  };
  if (clearCredentials && editing) {
    body.username = "";
    body.password = "";
  } else {
    if (v.username.trim()) body.username = v.username.trim();
    if (v.password) body.password = v.password;
  }
  return body;
}

/** Exact host or "*.suffix" (matches subdomains, not the apex), case-insensitive. */
export function hostMatches(host: string, patterns: string[]): boolean {
  const h = host.trim().toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  if (!h) return false;
  return patterns.some((raw) => {
    const p = raw.trim().toLowerCase();
    if (p.startsWith("*.")) return h.endsWith(p.slice(1)) && h.length > p.length - 1;
    return h === p;
  });
}

export function hostOfUrl(raw: string): string | null {
  try {
    const u = new URL(raw.trim());
    return u.hostname ? u.hostname.toLowerCase() : null;
  } catch {
    return null;
  }
}

export type AvailableProxy = Pick<EgressProxy, "id" | "name" | "allowed_hosts">;

export function proxyChoices(baseUrl: string, proxies: AvailableProxy[], selectedId: string) {
  const host = hostOfUrl(baseUrl);
  return proxies.map((p) => ({
    ...p,
    // Unknown host (no URL yet): do not claim a mismatch.
    matches: host === null ? true : hostMatches(host, p.allowed_hosts),
    selected: p.id === selectedId,
  }));
}

export type EgressFailureKind = "proxy_unreachable" | "proxy_refused" | "direct_unreachable" | "other";

const DIRECT_FAIL = /connection refused|econnrefused|connect(ion)? (error|failed|timed out|timeout)|timed out|timeout|unreachable|name or service not known|nodename|dns|no route|could not resolve|cannot resolve/i;

/**
 * Map a preflight `blocked_reason` / run `error_summary` / end_reason to the distinct
 * proxy messages. Accepts machine codes and free text; null when it is not network-path related.
 */
export function classifyEgressFailure(text: string | null | undefined, viaProxy: boolean): EgressFailureKind | null {
  const t = (text ?? "").trim();
  if (!t) return null;
  if (/proxy[_ ]unreachable|proxy[^.\n]*(unreachable|connection (refused|failed)|could not connect|cannot connect|timed out|timeout|dns)/i.test(t)) return "proxy_unreachable";
  if (/target[_ ]refused|proxy[_ ]refused|refused[^.\n]*via (the )?proxy|via (the )?proxy[^.\n]*(refus|denied|forbidden|403|502|503)|proxy[^.\n]*(refused (the )?(target|connection to the target)|denied|forbidden|407|tunnel)/i.test(t)) return "proxy_refused";
  if (!viaProxy && DIRECT_FAIL.test(t)) return "direct_unreachable";
  return null;
}

export interface EgressFailure {
  kind: EgressFailureKind;
  message: string;
  /** Show the hint with an admin link / "ask an administrator" tail. */
  showProxyHint: boolean;
}

export function egressFailure(
  text: string | null | undefined,
  viaProxy: boolean,
  proxyName?: string | null,
): EgressFailure | null {
  const kind = classifyEgressFailure(text, viaProxy);
  if (!kind) return null;
  const via = proxyName ? `the egress proxy "${proxyName}"` : "the egress proxy";
  switch (kind) {
    case "proxy_unreachable":
      return { kind, showProxyHint: false, message: `Vigilo could not reach ${via}. Check the proxy URL and that the proxy is running; the target itself was not contacted.` };
    case "proxy_refused":
      return { kind, showProxyHint: false, message: `${via[0].toUpperCase()}${via.slice(1)} was reachable but refused to connect to the target. The proxy may not allow this destination or may require different credentials.` };
    case "direct_unreachable":
      return { kind, showProxyHint: true, message: DIRECT_HINT };
    default:
      return null;
  }
}
