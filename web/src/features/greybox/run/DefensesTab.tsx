import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowDownTrayIcon, ClipboardDocumentIcon, ShieldCheckIcon } from "@heroicons/react/24/outline";
import { EmptyState, ErrorState, humanizeError, SeverityChip, SkeletonRows } from "../../../components/ui";
import { greyboxApi } from "../api";
import { fetchExplorationGraph } from "../graph/api";
import { fetchAssetGraph } from "../network/useAssetGraph";
import type { Defense, DefenseDownloadFormat, DefenseFormat, DefenseKind, RunStatus, Severity } from "../types";
import {
  availableDownloads, defensesEmptyState, EMPTY_COPY, filterDefenses, FORMAT_LABEL, groupByFinding, groupByService,
  isAssetScoped, KIND_LABEL, type AssetMeta, type FindingMeta, unverifiedCount } from "./defensesModel";
import { useDefenses } from "./useDefenses";

/** Finding title and severity come from the exploration graph (the Findings tab is not built yet). */
function useFindingMeta(runId: string, runStatus: string, count: number): ReadonlyMap<string, FindingMeta> {
  const [meta, setMeta] = useState<ReadonlyMap<string, FindingMeta>>(new Map());
  useEffect(() => {
    if (count === 0) return;
    let alive = true;
    fetchExplorationGraph(runId, 0, 5000)
      .then((g) => {
        if (!alive) return;
        const m = new Map<string, FindingMeta>();
        for (const n of g.nodes) {
          if (n.kind !== "finding") continue;
          const sev = (n.severity ?? n.data?.severity) as Severity | null | undefined;
          for (const id of new Set([n.finding_id, n.id])) if (id) m.set(id, { title: n.label, severity: sev ?? null });
        }
        setMeta(m);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [runId, runStatus, count]);
  return meta;
}

/** Labels and parents of assets, so network-wide rules can be grouped by service. Only fetched when there are any. */
function useAssetMeta(runId: string, runStatus: string, count: number): ReadonlyMap<string, AssetMeta> {
  const [meta, setMeta] = useState<ReadonlyMap<string, AssetMeta>>(new Map());
  useEffect(() => {
    if (count === 0) return;
    let alive = true;
    fetchAssetGraph(runId, 0, 5000)
      .then((g) => {
        if (!alive) return;
        setMeta(new Map(g.nodes.map((n) => [n.id, { label: n.label, kind: n.kind, parent_id: n.parent_id }])));
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [runId, runStatus, count]);
  return meta;
}

/** Rule text is untrusted: always a text child of <pre>, never HTML. */
export function CopyableRule({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState<"ok" | "err" | null>(null);
  const copy = () =>
    navigator.clipboard
      ?.writeText(text)
      .then(() => setCopied("ok"), () => setCopied("err"))
      .finally(() => setTimeout(() => setCopied(null), 2000)) ?? setCopied("err");
  return (
    <div className="relative">
      <button type="button" className="btn-ghost absolute right-1.5 top-1.5 !px-2 !py-0.5 text-xs" onClick={copy} aria-label={`Copy ${label}`}>
        <ClipboardDocumentIcon className="h-3.5 w-3.5" aria-hidden="true" />
        {copied === "ok" ? "Copied" : copied === "err" ? "Copy failed" : "Copy"}
      </button>
      <pre className="mono max-h-72 overflow-auto whitespace-pre-wrap break-words rounded border border-line bg-canvas p-2.5 pr-20 text-xs text-ink">{text}</pre>
      <span role="status" className="sr-only">{copied === "ok" ? "Copied to clipboard" : ""}</span>
    </div>
  );
}

export function DefenseChips({ d }: { d: Pick<Defense, "kind" | "format" | "status"> }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <span className="rounded border border-teal-600/40 bg-teal-50 px-1.5 py-px text-[11px] font-medium text-teal-800">{KIND_LABEL[d.kind] ?? d.kind}</span>
      <span className="mono rounded border border-line px-1.5 py-px text-[11px] text-slate">{FORMAT_LABEL[d.format] ?? d.format}</span>
      {d.status === "unverified" && (
        <span className="rounded border border-dashed border-teal-600/50 px-1.5 py-px text-[11px] text-teal-700" title="Not checked against the target. Test before deploying.">
          unverified
        </span>
      )}
    </span>
  );
}

function Select<T extends string>({ label, value, options, onChange }: { label: string; value: T | ""; options: Record<T, string>; onChange: (v: T | "") => void }) {
  return (
    <label className="flex items-center gap-1.5 text-sm text-slate">
      {label}
      <select className="rounded border border-line bg-surface px-2 py-1 text-sm text-ink" value={value} onChange={(e) => onChange(e.target.value as T | "")}>
        <option value="">All</option>
        {(Object.keys(options) as T[]).map((k) => (
          <option key={k} value={k}>{options[k]}</option>
        ))}
      </select>
    </label>
  );
}

function DefenseItem({ d }: { d: Defense }) {
  return (
    <li className="space-y-2 px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="break-words text-sm font-medium text-ink">{d.title}</span>
        <DefenseChips d={d} />
      </div>
      {d.rationale && <p className="whitespace-pre-wrap break-words text-[13px] text-slate">{d.rationale}</p>}
      <CopyableRule text={d.content} label={d.title} />
    </li>
  );
}

export function DefensesTab({ runId, runStatus, findingCount }: { runId: string; runStatus: RunStatus; findingCount: number | null }) {
  const { items, loading, error, refresh } = useDefenses(runId, runStatus);
  const [params, setParams] = useSearchParams();
  const finding = params.get("finding");
  const [kind, setKind] = useState<DefenseKind | "">("");
  const [format, setFormat] = useState<DefenseFormat | "">("");
  const [dlError, setDlError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const meta = useFindingMeta(runId, runStatus, items.length);
  const networkWide = useMemo(() => items.filter(isAssetScoped).length, [items]);
  const assetMeta = useAssetMeta(runId, runStatus, networkWide);

  const shown = useMemo(() => filterDefenses(items, { finding, kind: kind || null, format: format || null }), [items, finding, kind, format]);
  const groups = useMemo(() => groupByFinding(shown, meta), [shown, meta]);
  const serviceGroups = useMemo(() => groupByService(shown, assetMeta), [shown, assetMeta]);
  const [includeUnverified, setIncludeUnverified] = useState(false);
  const unverified = useMemo(() => unverifiedCount(items), [items]);
  const downloads = useMemo(() => availableDownloads(items, includeUnverified), [items, includeUnverified]);
  const empty = defensesEmptyState({ runStatus, total: items.length, shown: shown.length, findingCount });
  const filtering = !!(finding || kind || format);
  const clear = () => {
    setKind("");
    setFormat("");
    if (finding) {
      const next = new URLSearchParams(params);
      next.delete("finding");
      setParams(next, { replace: true });
    }
  };

  const download = async (f: DefenseDownloadFormat) => {
    setDlError(null);
    setBusy(f);
    try {
      await greyboxApi.downloadDefenses(runId, f, includeUnverified);
    } catch (e) {
      setDlError(e instanceof Error ? e.message : "Download failed");
    } finally {
      setBusy(null);
    }
  };

  if (loading) return <SkeletonRows rows={4} />;
  if (error && items.length === 0) {
    return <ErrorState icon={ShieldCheckIcon} title="Could not load defenses" message={humanizeError(new Error(error))} onRetry={refresh} />;
  }

  return (
    <div className="space-y-4">
      {items.length > 0 && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <Select label="Kind" value={kind} options={KIND_LABEL} onChange={setKind} />
          <Select label="Format" value={format} options={FORMAT_LABEL} onChange={setFormat} />
          {finding && (
            <span className="rounded border border-teal-600/40 bg-teal-50 px-2 py-0.5 text-xs text-teal-800">
              Finding: {meta.get(finding)?.title ?? `${finding.slice(0, 8)}…`}
            </span>
          )}
          {filtering && <button type="button" className="text-sm text-accent hover:underline" onClick={clear}>Clear filters</button>}
          <span className="ml-auto flex flex-wrap items-center gap-1.5">
            <span className="text-xs text-slate">Download</span>
            {unverified > 0 && (
              <label className="mr-1 inline-flex items-center gap-1 text-xs text-slate" title="Rules for candidate findings that were not verified are left out of downloads unless you include them.">
                <input type="checkbox" checked={includeUnverified} onChange={(e) => setIncludeUnverified(e.target.checked)} />
                Include unverified ({unverified})
              </label>
            )}
            {downloads.length === 0 && unverified > 0 && (
              <span className="text-xs text-slate">Only unverified rules: include them to download</span>
            )}
            {downloads.map((f) => (
              <button key={f} type="button" className="btn-ghost !px-2 !py-1 text-xs" disabled={busy !== null} onClick={() => void download(f)}>
                <ArrowDownTrayIcon className="h-3.5 w-3.5" aria-hidden="true" />
                {f === "all" ? "All (zip)" : FORMAT_LABEL[f]}
              </button>
            ))}
          </span>
        </div>
      )}
      {dlError && <p role="alert" className="text-sm text-severity-critical">{dlError}</p>}
      <p className="text-xs text-slate">
        Suggested rules are derived from what this run observed on the target. Review and test them before deploying.
      </p>

      {empty ? (
        <EmptyState
          icon={ShieldCheckIcon}
          title={EMPTY_COPY[empty].title}
          action={empty === "filtered" ? <button type="button" className="btn-ghost" onClick={clear}>Clear filters</button> : undefined}
        >
          {EMPTY_COPY[empty].body}
        </EmptyState>
      ) : (
        <>
          {serviceGroups.length > 0 && (
            <section aria-labelledby="def-network" className="space-y-3">
              <div>
                <h2 id="def-network" className="font-display text-base font-semibold text-ink">Network-wide</h2>
                <p className="text-xs text-slate">Recommendations about a service's overall surface (headers, cookies, CORS, exposed paths), grouped by service.</p>
              </div>
              {serviceGroups.map((g) => (
                <section key={g.assetId || "target"} aria-label={`Network-wide defenses for ${g.title}`} className="rounded-lg border border-line bg-surface">
                  <header className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-2.5">
                    <span className="rounded border border-teal-600/40 bg-teal-50 px-1.5 py-px text-[11px] font-medium capitalize text-teal-800">{g.kind}</span>
                    <h3 className="mono min-w-0 break-all text-sm font-semibold text-ink">{g.title}</h3>
                    <span className="text-xs text-slate">{g.defenses.length} {g.defenses.length === 1 ? "suggestion" : "suggestions"}</span>
                    {g.assetId && <Link to={`?tab=network&asset=${encodeURIComponent(g.assetId)}`} className="ml-auto text-xs text-accent hover:underline">View on the network map</Link>}
                  </header>
                  <ul className="divide-y divide-line">
                    {g.defenses.map((d) => <DefenseItem key={d.id} d={d} />)}
                  </ul>
                </section>
              ))}
            </section>
          )}
          {groups.length > 0 && (
            <section aria-labelledby="def-findings" className="space-y-3">
              {serviceGroups.length > 0 && (
                <div>
                  <h2 id="def-findings" className="font-display text-base font-semibold text-ink">Per finding</h2>
                  <p className="text-xs text-slate">Rules derived from a single finding.</p>
                </div>
              )}
              {groups.map((g) => (
                <section key={g.findingId} aria-label={`Defenses for ${g.title}`} className="rounded-lg border border-line bg-surface">
                  <header className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-2.5">
                    {g.severity && <SeverityChip severity={g.severity} />}
                    <h3 className="min-w-0 break-words text-sm font-semibold text-ink">{g.title}</h3>
                    <span className="text-xs text-slate">{g.defenses.length} {g.defenses.length === 1 ? "suggestion" : "suggestions"}</span>
                  </header>
                  <ul className="divide-y divide-line">
                    {g.defenses.map((d) => <DefenseItem key={d.id} d={d} />)}
                  </ul>
                </section>
              ))}
            </section>
          )}
        </>
      )}
    </div>
  );
}
