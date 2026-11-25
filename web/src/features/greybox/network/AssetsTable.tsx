// Accessible alternative to the canvas: every asset as a filterable table.
import { useMemo, useState } from "react";
import type { AssetKind, AssetNode } from "../types";
import { groupLabel } from "../assetClass";
import { assetVisual, displayService, endpointMethod, endpointPath, filterAssets, hiddenStaticIds, NO_ASSET_FILTERS, owningService, parentMap, serviceSurface, staticGroups, VISUAL_STYLE, type AssetFilters, type AssetGraphState, type AssetStateFilter } from "./model";
import { RiskBadge } from "./SurfacePanel";

const PAGE = 200;
const KIND_LABEL: Record<AssetKind | "all", string> = { all: "All kinds", host: "Hosts", service: "Services", endpoint: "Endpoints", parameter: "Parameters", defense: "Defenses" };
const STATE_LABEL: Record<AssetStateFilter, string> = {
  all: "Any state", finding: "Has findings", tested: "Tested", in_scope: "In scope", untested: "In scope, untested", out_of_scope: "Out of scope",
};

export function assetTitle(n: AssetNode): string {
  if (n.kind === "endpoint") return `${endpointMethod(n) ? `${endpointMethod(n)} ` : ""}${endpointPath(n)}`;
  return n.kind === "service" ? displayService(n.label) : n.label;
}

export function AssetsTable({ graph, selected, onOpen, showStatic = false }: { graph: AssetGraphState; selected: string | null; onOpen: (id: string) => void; showStatic?: boolean }) {
  const [filters, setFilters] = useState<AssetFilters>(NO_ASSET_FILTERS);
  const [limit, setLimit] = useState(PAGE);
  const parents = useMemo(() => parentMap(graph), [graph]);
  const rows = useMemo(() => filterAssets(graph.nodes.values(), { ...filters, showStatic }), [graph.nodes, filters, showStatic]);
  const hiddenGroups = useMemo(() => (showStatic ? [] : staticGroups(graph.nodes.values())), [graph.nodes, showStatic]);
  const hiddenFiles = hiddenGroups.reduce((n, g) => n + g.files, 0);
  const set = (p: Partial<AssetFilters>) => {
    setFilters((f) => ({ ...f, ...p }));
    setLimit(PAGE);
  };
  const filtering = filters.kind !== "all" || filters.state !== "all" || !!filters.query;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-line px-3 py-2 text-[13px]" role="group" aria-label="Asset filters">
        <label className="flex items-center gap-1.5 text-slate">
          Kind
          <select className="rounded border border-line bg-surface px-2 py-1 text-ink" value={filters.kind} onChange={(e) => set({ kind: e.target.value as AssetFilters["kind"] })}>
            {(Object.keys(KIND_LABEL) as (AssetKind | "all")[]).map((k) => <option key={k} value={k}>{KIND_LABEL[k]}</option>)}
          </select>
        </label>
        <label className="flex items-center gap-1.5 text-slate">
          State
          <select className="rounded border border-line bg-surface px-2 py-1 text-ink" value={filters.state} onChange={(e) => set({ state: e.target.value as AssetStateFilter })}>
            {(Object.keys(STATE_LABEL) as AssetStateFilter[]).map((k) => <option key={k} value={k}>{STATE_LABEL[k]}</option>)}
          </select>
        </label>
        <label className="flex items-center gap-1.5 text-slate">
          Search
          <input type="search" className="w-52 rounded border border-line bg-surface px-2 py-1 text-ink" value={filters.query} onChange={(e) => set({ query: e.target.value })} placeholder="path, host, parameter" />
        </label>
        {filtering && <button type="button" className="text-accent hover:underline" onClick={() => { setFilters(NO_ASSET_FILTERS); setLimit(PAGE); }}>Clear filters</button>}
        <span className="ml-auto tabular-nums text-slate" role="status">{rows.length} of {graph.nodes.size - (showStatic ? 0 : hiddenStaticCount(graph))} assets</span>
      </div>
      {hiddenFiles > 0 && (
        <p className="border-b border-line bg-canvas px-3 py-1.5 text-xs text-slate" role="note">
          {hiddenFiles} static asset{hiddenFiles === 1 ? "" : "s"} hidden:{" "}
          {hiddenGroups.slice(0, 4).map((g) => groupLabel(g.prefix, g.files, g.bytes)).join("; ")}
          {hiddenGroups.length > 4 ? `; ${hiddenGroups.length - 4} more groups` : ""}. Use “Show static assets” to list them.
        </p>
      )}
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full text-left text-[13px]">
          <caption className="sr-only">Assets discovered by the run</caption>
          <thead className="sticky top-0 bg-canvas text-xs text-slate">
            <tr>
              <th scope="col" className="px-3 py-1.5 font-medium">Kind</th>
              <th scope="col" className="px-3 py-1.5 font-medium">Asset</th>
              <th scope="col" className="px-3 py-1.5 font-medium">Service</th>
              <th scope="col" className="px-3 py-1.5 font-medium">State</th>
              <th scope="col" className="px-3 py-1.5 text-right font-medium">Findings</th>
              <th scope="col" className="px-3 py-1.5 font-medium">Risk</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, limit).map((n) => {
              const v = VISUAL_STYLE[assetVisual(n)];
              const svc = n.kind === "service" ? null : owningService(n.id, graph.nodes, parents);
              return (
                <tr key={n.id} className={`border-t border-line ${selected === n.id ? "bg-accent/5" : ""}`}>
                  <td className="px-3 py-1.5 capitalize text-slate">{n.kind}</td>
                  <td className="max-w-[26rem] px-3 py-1.5">
                    <button type="button" className="mono max-w-full break-all text-left text-[12.5px] text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent" onClick={() => onOpen(n.id)}>
                      {assetTitle(n)}
                    </button>
                  </td>
                  <td className="max-w-[14rem] truncate px-3 py-1.5 text-slate" title={svc?.label}>{svc ? displayService(svc.label) : ""}</td>
                  <td className="px-3 py-1.5">
                    <span className={`inline-flex items-center gap-1 rounded border px-1.5 text-[12px] font-semibold ${v.chip}`}><span aria-hidden="true">{v.glyph}</span>{v.label}</span>
                  </td>
                  <td className="px-3 py-1.5 text-right tabular-nums">{n.finding_count || ""}</td>
                  <td className="px-3 py-1.5">{n.kind === "service" && <RiskBadge score={serviceSurface(n.data)?.riskScore ?? null} />}</td>
                </tr>
              );
            })}
            {rows.length === 0 && <tr><td colSpan={6} className="px-3 py-6 text-center text-slate">No assets match these filters.</td></tr>}
          </tbody>
        </table>
        {rows.length > limit && (
          <div className="p-3 text-center">
            <button type="button" className="btn-ghost" onClick={() => setLimit((l) => l + PAGE)}>Show {Math.min(PAGE, rows.length - limit)} more</button>
          </div>
        )}
      </div>
    </div>
  );
}

function hiddenStaticCount(graph: AssetGraphState): number {
  return hiddenStaticIds(graph.nodes.values()).size;
}
