// Pure helpers of the Defenses tab: grouping, filters, empty-state selection.
import { RUN_TERMINAL, type Defense, type DefenseDownloadFormat, type DefenseFormat, type DefenseKind, type RunStatus, type Severity } from "../types";

export const KIND_LABEL: Record<DefenseKind, string> = {
  waf_rule: "WAF rule",
  detection_rule: "Detection rule",
  config: "Configuration",
  hardening: "Hardening",
};
export const FORMAT_LABEL: Record<DefenseFormat, string> = {
  modsecurity: "ModSecurity",
  sigma: "Sigma",
  nginx: "nginx",
  apache: "Apache",
  text: "Text",
};
export const DEFENSE_KINDS = Object.keys(KIND_LABEL) as DefenseKind[];
export const DEFENSE_FORMATS = Object.keys(FORMAT_LABEL) as DefenseFormat[];
/** Formats the download endpoint takes (no "text"). */
export const DOWNLOAD_FORMATS: readonly Exclude<DefenseDownloadFormat, "all">[] = ["modsecurity", "sigma", "nginx", "apache"];

/** Network-wide recommendation: about an asset's surface, not derived from one finding. */
export function isAssetScoped(d: Pick<Defense, "scope" | "finding_id" | "asset_id">): boolean {
  return d.scope === "asset" || (d.scope === undefined && !d.finding_id && !!d.asset_id);
}

export interface DefenseFilters {
  finding?: string | null;
  asset?: string | null;
  kind?: DefenseKind | null;
  format?: DefenseFormat | null;
}

export function filterDefenses(items: readonly Defense[], f: DefenseFilters): Defense[] {
  return items.filter((d) => (!f.finding || d.finding_id === f.finding || !!d.finding_ids?.includes(f.finding)) && (!f.asset || d.asset_id === f.asset) && (!f.kind || d.kind === f.kind) && (!f.format || d.format === f.format));
}

export interface FindingMeta {
  title: string;
  severity: Severity | null;
}

export interface DefenseGroup {
  findingId: string;
  title: string;
  severity: Severity | null;
  defenses: Defense[];
}

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const shortId = (id: string) => (id.length > 12 ? `${id.slice(0, 8)}…` : id);

/** Group by finding: most severe first, then title; within a group by kind, format, title. */
export function groupByFinding(items: readonly Defense[], findings: ReadonlyMap<string, FindingMeta>): DefenseGroup[] {
  const by = new Map<string, Defense[]>();
  for (const d of items) {
    if (isAssetScoped(d)) continue;
    const k = d.finding_id ?? "";
    (by.get(k) ?? by.set(k, []).get(k)!).push(d);
  }
  const groups = [...by].map(([findingId, defenses]): DefenseGroup => {
    const m = findings.get(findingId);
    return {
      findingId,
      title: m?.title || `Finding ${shortId(findingId)}`,
      severity: m?.severity ?? null,
      defenses: [...defenses].sort(
        (a, b) => a.kind.localeCompare(b.kind) || a.format.localeCompare(b.format) || a.title.localeCompare(b.title) || a.id.localeCompare(b.id),
      ),
    };
  });
  return groups.sort(
    (a, b) => (SEV_RANK[a.severity ?? ""] ?? 5) - (SEV_RANK[b.severity ?? ""] ?? 5) || a.title.localeCompare(b.title) || a.findingId.localeCompare(b.findingId),
  );
}

/** What the network-wide grouping needs to know about an asset (from the asset graph). */
export interface AssetMeta {
  label: string;
  kind: string;
  parent_id: string | null;
}

export interface ServiceGroup {
  /** Service (or host) id; "" for recommendations about the whole target. */
  assetId: string;
  title: string;
  kind: string;
  defenses: Defense[];
}

const KIND_RANK: Record<string, number> = { host: 0, service: 1 };

/** The service an asset belongs to (walking up parents); the topmost known asset when there is none. */
export function owningServiceId(assetId: string, assets: ReadonlyMap<string, AssetMeta>): string | null {
  let cur: string | null = assetId;
  let top: string | null = null;
  for (let i = 0; cur && i < 8; i++) {
    const a = assets.get(cur);
    if (!a) break;
    top = cur;
    if (a.kind === "service") return cur;
    cur = a.parent_id;
  }
  return top;
}

/** Group network-wide (scope "asset") defenses by service; unresolved ones go to a "Whole target" group, last. */
export function groupByService(items: readonly Defense[], assets: ReadonlyMap<string, AssetMeta>): ServiceGroup[] {
  const by = new Map<string, Defense[]>();
  for (const d of items) {
    if (!isAssetScoped(d)) continue;
    const k = (d.asset_id && owningServiceId(d.asset_id, assets)) || "";
    (by.get(k) ?? by.set(k, []).get(k)!).push(d);
  }
  const groups = [...by].map(([assetId, defenses]): ServiceGroup => {
    const a = assets.get(assetId);
    return {
      assetId,
      title: assetId ? (a?.label ?? `Asset ${shortId(assetId)}`) : "Whole target",
      kind: a?.kind ?? (assetId ? "asset" : "target"),
      defenses: [...defenses].sort(
        (x, y) => x.kind.localeCompare(y.kind) || x.format.localeCompare(y.format) || x.title.localeCompare(y.title) || x.id.localeCompare(y.id),
      ),
    };
  });
  return groups.sort((a, b) => Number(!a.assetId) - Number(!b.assetId) || (KIND_RANK[a.kind] ?? 2) - (KIND_RANK[b.kind] ?? 2) || a.title.localeCompare(b.title) || a.assetId.localeCompare(b.assetId));
}

/** Download formats that have at least one rule (plus "all" when there is any). */
/**
 * Download buttons for the set the server will actually return: by default the
 * download excludes rules of unverified (candidate) findings, so a format that only
 * has unverified rules must not get a button (it would 404) unless the user opts in.
 */
export function availableDownloads(items: readonly Defense[], includeUnverified = false): DefenseDownloadFormat[] {
  const pool = includeUnverified ? items : items.filter((d) => d.status !== "unverified");
  const have = new Set(pool.map((d) => d.format));
  const out: DefenseDownloadFormat[] = DOWNLOAD_FORMATS.filter((f) => have.has(f));
  return out.length || pool.length ? [...out, "all"] : [];
}

/** How many rules the default (verified-only) download leaves out. */
export function unverifiedCount(items: readonly Defense[]): number {
  return items.filter((d) => d.status === "unverified").length;
}

export type DefensesEmpty = "active" | "failed" | "no_findings" | "none_generated" | "filtered";

/**
 * Why the list is empty, or null when there is something to show. `total` is the
 * unfiltered count, `shown` the count after filters, `findingCount` candidate + verified.
 */
export function defensesEmptyState(o: { runStatus: RunStatus; total: number; shown: number; findingCount: number | null }): DefensesEmpty | null {
  if (o.shown > 0) return null;
  if (o.total > 0) return "filtered";
  if (!RUN_TERMINAL.has(o.runStatus)) return "active";
  if (o.runStatus !== "succeeded") return "failed";
  if (o.findingCount === 0) return "no_findings";
  return "none_generated";
}

export const EMPTY_COPY: Record<DefensesEmpty, { title: string; body: string }> = {
  active: { title: "Defenses are generated when the run finishes", body: "Detection and WAF suggestions appear here once the run has completed and the report is built." },
  failed: { title: "No defenses for this run", body: "Defensive suggestions are only generated for runs that finish successfully. This run failed or was cancelled." },
  no_findings: { title: "No findings, no defenses", body: "The run did not report any finding, so there is nothing to defend against." },
  none_generated: { title: "No defenses were generated", body: "This run has findings, but none of them produced a detection or WAF suggestion." },
  filtered: { title: "No defenses match these filters", body: "Clear the filters to see every suggestion." },
};

/** Should an incoming event refresh the list? Only once the run is terminal. */
export function shouldRefreshDefenses(runStatus: string | null, eventKind: string): boolean {
  return !!runStatus && RUN_TERMINAL.has(runStatus as RunStatus) && (eventKind.startsWith("defense.") || eventKind === "report.ready");
}
