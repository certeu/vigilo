import type { FindingClass, FindingStatus, FindingSummary, Severity } from "../types";

export const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
export const STATUS_ORDER: readonly FindingStatus[] = ["verified", "candidate", "rejected"];
export const STATUS_LABEL: Record<FindingStatus, string> = {
  verified: "Verified",
  candidate: "Candidate",
  rejected: "Rejected",
};

export type SortKey = "severity" | "title" | "asset" | "check" | "status" | "evidence" | "defenses";
export type SortDir = "asc" | "desc";
export interface Sort {
  key: SortKey;
  dir: SortDir;
}
export interface FindingFilter {
  severity: Severity | null;
  status: FindingStatus | null;
}

/** Most severe first by default; a finding the engine rejected sinks to the bottom. */
export const DEFAULT_SORT: Sort = { key: "severity", dir: "desc" };

const rank = <T extends string>(order: readonly T[], v: T): number => {
  const i = order.indexOf(v);
  return i < 0 ? order.length : i;
};

export const findingAsset = (f: FindingSummary): string => f.affected_asset?.label ?? "";
export const defenseCount = (f: FindingSummary): number => f.defense_count ?? 0;

/** Natural ascending value for each column; "severity ascending" means least severe first. */
function compareBy(key: SortKey, a: FindingSummary, b: FindingSummary): number {
  switch (key) {
    case "severity":
      return rank(SEVERITY_ORDER, b.severity) - rank(SEVERITY_ORDER, a.severity);
    case "status":
      return rank(STATUS_ORDER, b.status) - rank(STATUS_ORDER, a.status);
    case "title":
      return a.title.localeCompare(b.title);
    case "asset":
      return findingAsset(a).localeCompare(findingAsset(b));
    case "check":
      return a.check_id.localeCompare(b.check_id);
    case "evidence":
      return a.evidence_count - b.evidence_count;
    case "defenses":
      return defenseCount(a) - defenseCount(b);
  }
}

/** Stable, non-mutating. Ties fall back to severity (most severe first), then title. */
export function sortFindings(items: readonly FindingSummary[], sort: Sort = DEFAULT_SORT): FindingSummary[] {
  const sign = sort.dir === "asc" ? 1 : -1;
  return items
    .map((f, i) => ({ f, i }))
    .sort((x, y) => {
      const c = compareBy(sort.key, x.f, y.f) * sign;
      if (c) return c;
      const s = rank(SEVERITY_ORDER, x.f.severity) - rank(SEVERITY_ORDER, y.f.severity);
      if (s) return s;
      return x.f.title.localeCompare(y.f.title) || x.i - y.i;
    })
    .map((x) => x.f);
}

export function filterFindings(items: readonly FindingSummary[], flt: FindingFilter): FindingSummary[] {
  return items.filter((f) => (!flt.severity || f.severity === flt.severity) && (!flt.status || f.status === flt.status));
}

/** Clicking a header: same column flips direction; a new column starts at its natural default. */
export function nextSort(cur: Sort, key: SortKey): Sort {
  if (cur.key === key) return { key, dir: cur.dir === "asc" ? "desc" : "asc" };
  return { key, dir: key === "severity" || key === "evidence" || key === "defenses" ? "desc" : "asc" };
}

/** Counts per severity over the unfiltered list, for the filter labels. */
export function countBy<K extends string>(items: readonly FindingSummary[], pick: (f: FindingSummary) => K): Partial<Record<K, number>> {
  const out: Partial<Record<K, number>> = {};
  for (const f of items) out[pick(f)] = (out[pick(f)] ?? 0) + 1;
  return out;
}

/** Events that mean the findings list may have changed (finding.created, finding.verified, ...). */
export const FINDING_EVENTS = "finding.*";

/** Run URL params for "Show in graph": the Graph tab reads ?node=<graph node id>. */
export function graphLinkParams(current: URLSearchParams, nodeId: string): URLSearchParams {
  const next = new URLSearchParams(current);
  next.set("tab", "exploration");
  next.set("node", nodeId);
  next.delete("finding");
  next.delete("open");
  return next;
}

/** Run URL params for the Defenses tab filtered to one finding. */
export function defensesLinkParams(current: URLSearchParams, findingId: string): URLSearchParams {
  const next = new URLSearchParams(current);
  next.set("tab", "defenses");
  next.set("finding", findingId);
  next.delete("node");
  next.delete("open");
  return next;
}

// ---------------------------------------------------------------- finding classes
// Mirrors the server (findclass.section_of): a missing header is never presented as
// a vulnerability, and an unverified vulnerability is "likely", not "confirmed".

export const CLASS_ORDER: readonly FindingClass[] = ["vulnerability", "misconfiguration", "hardening", "informational"];
export const CLASS_LABEL: Record<FindingClass, string> = {
  vulnerability: "Vulnerability",
  misconfiguration: "Misconfiguration",
  hardening: "Hardening",
  informational: "Informational",
};

export type FindingSectionKey =
  | "confirmed_vulnerability" | "likely_vulnerability" | "misconfiguration" | "hardening" | "informational" | "rejected";

export const SECTION_LABEL: Record<FindingSectionKey, string> = {
  confirmed_vulnerability: "Confirmed vulnerabilities",
  likely_vulnerability: "Likely vulnerabilities (require verification)",
  misconfiguration: "Security misconfigurations",
  hardening: "Hardening recommendations",
  informational: "Informational observations",
  rejected: "Rejected (not reproduced)",
};

const SECTION_ORDER: readonly FindingSectionKey[] = [
  "confirmed_vulnerability", "likely_vulnerability", "misconfiguration", "hardening", "informational", "rejected",
];

export const findingClass = (f: FindingSummary): FindingClass => f.finding_class ?? "vulnerability";

export function sectionOf(f: FindingSummary): FindingSectionKey {
  if (f.status === "rejected") return "rejected";
  const c = findingClass(f);
  if (c === "vulnerability") return f.status === "verified" ? "confirmed_vulnerability" : "likely_vulnerability";
  return c;
}

/** Already-sorted findings, grouped into the report's sections (order preserved). */
export function groupFindings(items: readonly FindingSummary[]): { key: FindingSectionKey; label: string; items: FindingSummary[] }[] {
  const by = new Map<FindingSectionKey, FindingSummary[]>();
  for (const f of items) {
    const k = sectionOf(f);
    by.set(k, [...(by.get(k) ?? []), f]);
  }
  return SECTION_ORDER.filter((k) => by.has(k)).map((k) => ({ key: k, label: SECTION_LABEL[k], items: by.get(k)! }));
}
