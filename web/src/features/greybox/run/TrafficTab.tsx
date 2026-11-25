// HTTP Traffic tab: captured exchanges of the run.
// URL: ?tab=traffic&exchange=<id> opens the detail; &work_order=<id> / &finding=<id> pre-filter.
// Shown only when capture is available; otherwise an explicit "not available" state.
import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { EmptyState, ErrorState, SkeletonRows } from "../../../components/ui";
import { ExchangeDetail } from "../traffic/ExchangeDetail";
import { TrafficList } from "../traffic/TrafficList";
import {
  BODY_STORE_CAP_KB, clientFilter, DEFAULT_TRAFFIC_FILTERS, filtersFromParams, foldStatic, foldSummary, METHODS, parseExchangeParam,
  STATUS_CLASS_LABEL, STATUS_CLASSES, type StatusClass, type TrafficFilters,
} from "../traffic/trafficModel";
import { useTraffic } from "../traffic/useTraffic";

export function CaptureStrip({ viaProxy = false }: { viaProxy?: boolean } = {}) {
  // TODO(backend): the API does not expose the body cap; this is the documented BODY_STORE_CAP.
  return (
    <p className="rounded-md border border-line bg-surface px-3 py-2 text-xs text-slate" role="note">
      Captured: request/response metadata and bodies up to {BODY_STORE_CAP_KB} KB; credentials and sensitive parameters are redacted; binary bodies are not stored.{viaProxy && " Requests of this run are sent via the egress proxy."}
    </p>
  );
}

const selectedId = (p: URLSearchParams) => parseExchangeParam(p.get("exchange"));

export function TrafficTab({ runId, viaProxy = false }: { runId: string; viaProxy?: boolean }) {
  const [params, setParams] = useSearchParams();
  const [filters, setFilters] = useState<TrafficFilters>(() => filtersFromParams(params));
  const selected = parseExchangeParam(params.get("exchange"));
  const t = useTraffic(runId, filters);
  const visible = useMemo(() => clientFilter(t.rows, filters), [t.rows, filters]);
  // Static assets (chunks, css, fonts, images) fold into one group per host and prefix.
  // An explicit path prefix filter means the analyst asked for them: nothing is folded then.
  const [showStatic, setShowStatic] = useState(false);
  const [openGroups, setOpenGroups] = useState<ReadonlySet<string>>(() => new Set());
  const toggleGroup = useCallback((key: string) => setOpenGroups((s) => {
    const n = new Set(s);
    if (!n.delete(key)) n.add(key);
    return n;
  }), []);
  const items = useMemo(
    () => foldStatic(visible, { showStatic: showStatic || !!filters.pathPrefix.trim(), expanded: openGroups, reveal: selectedId(params) }),
    [visible, showStatic, filters.pathPrefix, openGroups, params],
  );
  const folded = useMemo(() => foldSummary(items), [items]);

  // Work order / finding links arriving while the tab is open.
  const wo = params.get("work_order") ?? params.get("work_order_id") ?? "";
  const fi = params.get("finding") ?? params.get("finding_id") ?? "";
  useEffect(() => {
    setFilters((f) => (f.workOrderId === wo && f.findingId === fi ? f : { ...f, workOrderId: wo, findingId: fi }));
  }, [wo, fi]);

  const set = <K extends keyof TrafficFilters>(k: K, v: TrafficFilters[K]) => setFilters((f) => ({ ...f, [k]: v }));
  const select = useCallback((id: number | null) => {
    const next = new URLSearchParams(params);
    if (id == null) next.delete("exchange");
    else next.set("exchange", String(id));
    setParams(next, { replace: true });
  }, [params, setParams]);
  const clearScope = () => {
    const next = new URLSearchParams(params);
    for (const k of ["work_order", "work_order_id", "finding", "finding_id"]) next.delete(k);
    setParams(next, { replace: true });
  };
  const active = JSON.stringify(filters) !== JSON.stringify(DEFAULT_TRAFFIC_FILTERS);

  if (t.status === "unavailable") {
    return (
      <div className="space-y-3">
        <EmptyState title="Traffic capture is not available for this run">
          HTTP exchanges are only shown when they were safely captured and redacted. Nothing is shown here rather than showing partial or unredacted data.
        </EmptyState>
        {selected != null && <p className="text-xs text-slate">Exchange #{selected} cannot be shown.</p>}
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <CaptureStrip viaProxy={viaProxy} />

      <form className="flex flex-wrap items-end gap-2 text-xs" role="search" aria-label="Traffic filters" onSubmit={(e) => e.preventDefault()}>
        <label className="grid gap-0.5">Method
          <select className="input py-1" value={filters.method} onChange={(e) => set("method", e.target.value)}>
            <option value="">Any</option>
            {METHODS.map((m) => <option key={m}>{m}</option>)}
          </select>
        </label>
        <label className="grid gap-0.5">Status
          <select className="input py-1" value={filters.statusClass} onChange={(e) => set("statusClass", e.target.value as StatusClass)}>
            {STATUS_CLASSES.map((c) => <option key={c} value={c}>{STATUS_CLASS_LABEL[c]}</option>)}
          </select>
        </label>
        <label className="grid gap-0.5">Host
          <input className="input py-1" value={filters.host} onChange={(e) => set("host", e.target.value)} placeholder="exact host" />
        </label>
        <label className="grid gap-0.5">Path prefix
          <input className="input py-1" value={filters.pathPrefix} onChange={(e) => set("pathPrefix", e.target.value)} placeholder="/api/" />
        </label>
        <label className="flex items-center gap-1.5 pb-1.5"><input type="checkbox" checked={filters.blockedOnly} onChange={(e) => set("blockedOnly", e.target.checked)} /> Blocked only</label>
        <label className="flex items-center gap-1.5 pb-1.5" title="Scripts, stylesheets, fonts and images that answered normally are folded into one group per host and prefix"><input type="checkbox" checked={showStatic} onChange={(e) => setShowStatic(e.target.checked)} /> Show static assets</label>
        <label className="flex items-center gap-1.5 pb-1.5"><input type="checkbox" checked={filters.hasFindings} onChange={(e) => set("hasFindings", e.target.checked)} /> Has findings</label>
        {active && (
          <button type="button" className="btn-ghost py-1" onClick={() => { setFilters(DEFAULT_TRAFFIC_FILTERS); clearScope(); }}>Clear filters</button>
        )}
      </form>
      {(filters.workOrderId || filters.findingId) && (
        <p className="text-xs text-slate">
          Showing only traffic of {filters.workOrderId && <>work order <span className="mono">{filters.workOrderId.slice(0, 8)}</span></>}
          {filters.workOrderId && filters.findingId && " and "}
          {filters.findingId && <>finding <span className="mono">{filters.findingId.slice(0, 8)}</span></>}.
        </p>
      )}

      {t.status === "loading" && <SkeletonRows rows={8} />}
      {t.status === "error" && <ErrorState title="Could not load traffic" message={t.error ?? undefined} onRetry={t.reload} />}
      {t.status === "ready" && (
        <div className={`grid items-start gap-4 ${selected != null ? "xl:grid-cols-[minmax(0,1fr)_28rem]" : ""}`}>
          <div className="min-w-0">
            {visible.length === 0 && !t.hasMore ? (
              <EmptyState title={active ? "No exchanges match these filters" : "No HTTP traffic captured yet"}>
                {active ? "Try clearing a filter." : "Requests appear here as the run sends them."}
              </EmptyState>
            ) : (
              <TrafficList rows={items} selectedId={selected} hasMore={t.hasMore} loadingMore={t.loadingMore} onSelect={select} onLoadMore={t.loadMore} onToggleGroup={toggleGroup} />
            )}
            <p className="mt-1.5 text-xs text-slate" role="status">
              {(visible.length - (folded?.files ?? 0)).toLocaleString()} shown{folded ? `, ${folded.files.toLocaleString()} static file${folded.files === 1 ? "" : "s"} in ${folded.groups} group${folded.groups === 1 ? "" : "s"} folded` : ""}{t.hasMore ? " (more load as you scroll)" : ""}
              {t.error && <span className="ml-2 text-severity-critical">{t.error}</span>}
            </p>
          </div>
          {selected != null && <ExchangeDetail runId={runId} exchangeId={selected} onClose={() => select(null)} />}
        </div>
      )}
      {t.status !== "ready" && selected != null && <ExchangeDetail runId={runId} exchangeId={selected} onClose={() => select(null)} />}
    </div>
  );
}
