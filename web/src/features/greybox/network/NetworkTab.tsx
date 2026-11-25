// Body of the run workspace's Network tab: live asset graph (map or table), coverage,
// per-service surface panel and the asset drawer. `?asset=<id>` selects an asset.
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { ArrowPathIcon, Squares2X2Icon, TableCellsIcon } from "@heroicons/react/20/solid";
import { EmptyState, ErrorBoundary, ErrorState, Skeleton } from "../../../components/ui";
import { RUN_TERMINAL, type RunStatus } from "../types";
import { useRunEvents, useRunLiveStatusOptional } from "../run/RunLiveContext";
import type { StreamState } from "../events";
import { AssetDrawer } from "./AssetDrawer";
import { AssetsTable, assetTitle } from "./AssetsTable";
import { CoverageBar } from "./CoverageBar";
import { displayService, kindCounts, owningService, parentMap, VISUAL_STYLE, type AssetVisual } from "./model";
import { SurfacePanel } from "./SurfacePanel";
import { useAssetGraph, type UseAssetGraphOptions } from "./useAssetGraph";

const NetworkMap = lazy(() => import("./NetworkMap"));

/** Safety refetch while the stream is live; 3 s fallback otherwise (same policy as the exploration graph). */
export const NETWORK_SAFETY_POLL_MS = 30_000;
export const NETWORK_FALLBACK_POLL_MS = 3_000;
export const networkPollMs = (streamLive: boolean) => (streamLive ? NETWORK_SAFETY_POLL_MS : NETWORK_FALLBACK_POLL_MS);

function Toggle({ pressed, onClick, children, title }: { pressed: boolean; onClick: () => void; children: ReactNode; title?: string }) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      title={title}
      onClick={onClick}
      className={`inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
        pressed ? "border-accent/40 bg-accent/10 text-accent" : "border-line bg-surface text-slate hover:text-ink"
      }`}
    >
      {children}
    </button>
  );
}

const LIVE: Record<StreamState, { label: string; dot: string }> = {
  live: { label: "Live", dot: "bg-emerald-600" },
  connecting: { label: "Connecting…", dot: "bg-severity-medium" },
  reconnecting: { label: "Reconnecting…", dot: "bg-severity-medium" },
  disconnected: { label: "Polling", dot: "bg-severity-critical" },
  finished: { label: "Run finished", dot: "bg-slate/50" },
};

function Legend() {
  const states = Object.keys(VISUAL_STYLE) as AssetVisual[];
  return (
    <ul className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-line px-3 py-1.5 text-[12px] text-slate" aria-label="Legend">
      {states.map((k) => (
        <li key={k} className="flex items-center gap-1.5" title={VISUAL_STYLE[k].description}>
          <span aria-hidden="true" className="inline-block h-3 w-3 rounded-sm" style={{ border: `2px ${k === "out_of_scope" ? "dashed" : "solid"} ${VISUAL_STYLE[k].fill}` }} />
          {VISUAL_STYLE[k].label}
        </li>
      ))}
      <li className="flex items-center gap-1.5" title="A suggested rule that protects this asset (see the Defenses tab).">
        <span aria-hidden="true" className="inline-block h-3 w-3 rounded-sm border-2 border-teal-600 bg-teal-50" />
        Defense (protects)
      </li>
    </ul>
  );
}

export interface NetworkTabProps {
  runId: string;
  runStatus: RunStatus;
  /** Injected for tests. */
  options?: UseAssetGraphOptions;
}

export function NetworkTab({ runId, runStatus, options }: NetworkTabProps) {
  const active = !RUN_TERMINAL.has(runStatus);
  const live = useRunLiveStatusOptional();
  const ctl = useAssetGraph(runId, { active, pollMs: networkPollMs(!!live?.isLive), ...options });
  const { graph, status, error, refresh, requestRefresh, updatedAt } = ctl;

  // Live: graph.updated carries asset counts, surface.updated a changed surface; both
  // trigger the debounced (1 s) delta fetch. Terminal run events fetch the final state.
  useRunEvents(["graph.updated", "surface.updated"], () => requestRefresh());
  const settle = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (settle.current) clearTimeout(settle.current); }, []);
  const finalFetch = useCallback(() => {
    void refresh();
    if (settle.current) clearTimeout(settle.current);
    settle.current = setTimeout(() => void refresh(), 1_500);
  }, [refresh]);
  useRunEvents(["run.completed", "run.failed", "run.cancelled"], finalFetch);
  const wasActive = useRef(active);
  useEffect(() => {
    if (wasActive.current && !active) finalFetch();
    wasActive.current = active;
  }, [active, finalFetch]);

  const [params, setParams] = useSearchParams();
  const assetParam = params.get("asset");
  const [mode, setMode] = useState<"map" | "table">("map");
  const [showLinks, setShowLinks] = useState(false);
  const [showStatic, setShowStatic] = useState(false);
  const [follow, setFollow] = useState(false);
  const [fitNonce, setFitNonce] = useState(0);
  const [centerOn, setCenterOn] = useState<{ id: string; nonce: number } | null>(null);
  const nonce = useRef(0);
  const [surfaceService, setSurfaceService] = useState<string | null>(null);

  const setAssetParam = useCallback(
    (id: string | null) => {
      setParams(
        (prev) => {
          const p = new URLSearchParams(prev);
          if (id) p.set("asset", id);
          else p.delete("asset");
          return p;
        },
        { replace: true },
      );
    },
    [setParams],
  );
  const parents = useMemo(() => parentMap(graph), [graph]);
  const open = useCallback(
    (id: string) => {
      setAssetParam(id);
      const svc = owningService(id, graph.nodes, parents);
      if (svc) setSurfaceService(svc.id);
    },
    [setAssetParam, graph.nodes, parents],
  );
  const openAndCentre = useCallback(
    (id: string) => {
      open(id);
      setCenterOn({ id, nonce: ++nonce.current });
    },
    [open],
  );

  // Deep link ?asset=<id>: centre once per id when the asset is loaded.
  const handled = useRef<string | null>(null);
  useEffect(() => {
    if (!assetParam || assetParam === handled.current || !graph.nodes.has(assetParam)) return;
    handled.current = assetParam;
    const svc = owningService(assetParam, graph.nodes, parents);
    if (svc) setSurfaceService(svc.id);
    setCenterOn({ id: assetParam, nonce: ++nonce.current });
  }, [assetParam, graph.nodes, parents]);

  const services = useMemo(() => [...graph.nodes.values()].filter((n) => n.kind === "service").sort((a, b) => a.label.localeCompare(b.label)), [graph.nodes]);
  const surfaceNode = (surfaceService && graph.nodes.get(surfaceService)) || services[0] || null;
  const selectedNode = assetParam ? graph.nodes.get(assetParam) ?? null : null;
  const counts = useMemo(() => kindCounts(graph.nodes.values()), [graph.nodes]);
  const ls = live?.state ?? null;
  const li = ls ? LIVE[ls] : { label: "Live", dot: "bg-emerald-600" };
  const time = updatedAt ? new Date(updatedAt).toISOString().slice(11, 19) : null;

  if (status === "loading" && !graph.loaded) return <div role="status" aria-label="Loading the network map"><Skeleton className="h-[28rem] w-full" /></div>;
  if (status === "error" && !graph.loaded) {
    return <ErrorState title="Could not load the network map" message={error ?? "The asset graph is not available."} onRetry={() => void refresh()} />;
  }
  if (graph.nodes.size === 0 && graph.loaded) {
    return (
      <EmptyState title={active ? "No assets discovered yet" : "No assets were recorded"}>
        {active ? "The network picture builds up here, live, as the run explores the target." : "This run did not record any host, service or endpoint."}
      </EmptyState>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 rounded-lg border border-line bg-surface px-3 py-2.5">
        <CoverageBar graph={graph} />
        <p className="text-[13px] tabular-nums text-slate">
          {counts.host} host{counts.host === 1 ? "" : "s"} · {counts.service} service{counts.service === 1 ? "" : "s"} · {counts.endpoint} endpoint{counts.endpoint === 1 ? "" : "s"}{counts.staticAssets > 0 ? ` (+ ${counts.staticAssets} static asset${counts.staticAssets === 1 ? "" : "s"})` : ""} · {counts.parameter} parameter{counts.parameter === 1 ? "" : "s"}
          {counts.defense > 0 ? ` · ${counts.defense} defense${counts.defense === 1 ? "" : "s"}` : ""}
        </p>
      </div>

      <div className="flex h-[max(520px,calc(100vh-22rem))] w-full flex-col overflow-hidden rounded-lg border border-line bg-surface">
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
          <div className="flex overflow-hidden rounded-md border border-line" role="group" aria-label="View">
            {([["map", "Map", Squares2X2Icon], ["table", "Table", TableCellsIcon]] as const).map(([k, label, Icon]) => (
              <button
                key={k}
                type="button"
                aria-pressed={mode === k}
                onClick={() => setMode(k)}
                className={`flex items-center gap-1 px-2.5 py-1 text-xs font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent ${mode === k ? "bg-ink text-white" : "bg-surface text-slate hover:text-ink"}`}
              >
                <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                {label}
              </button>
            ))}
          </div>
          {counts.staticAssets > 0 && (
            <Toggle pressed={showStatic} onClick={() => setShowStatic((v) => !v)} title="Static assets (scripts, stylesheets, fonts, images) are folded into one group per prefix; show them individually">
              Show static assets ({counts.staticAssets})
            </Toggle>
          )}
          {mode === "map" && (
            <Toggle pressed={showLinks} onClick={() => setShowLinks((v) => !v)} title="Draw links_to and redirects_to between endpoints">
              Show links and redirects
            </Toggle>
          )}
          <div className="ml-auto flex items-center gap-2 text-xs text-slate">
            {mode === "map" && (
              <>
                <button type="button" className="rounded px-1.5 py-1 hover:bg-canvas hover:text-ink" onClick={() => setFitNonce((n) => n + 1)}>Fit to view</button>
                {active && <Toggle pressed={follow} onClick={() => setFollow((v) => !v)} title="Pan to the newest asset as the run discovers things">Follow activity</Toggle>}
              </>
            )}
            {active && (
              <span className="inline-flex items-center gap-1" role="status" title="Updates arrive as events; a delta is fetched within about 1 s.">
                <span className={`h-1.5 w-1.5 rounded-full ${li.dot}`} aria-hidden="true" /> {li.label}{time ? ` · ${time}Z` : ""}
              </span>
            )}
            <button type="button" className="rounded p-1 hover:bg-canvas hover:text-ink" onClick={() => void refresh()} aria-label="Refresh the network map" title="Refresh">
              <ArrowPathIcon className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
        </div>
        <Legend />
        {graph.truncated && (
          <p role="status" className="border-b border-severity-medium/30 bg-amber-50 px-3 py-1.5 text-xs text-severity-medium">
            The asset graph is truncated ({Object.entries(graph.truncatedByKind).map(([k, n]) => `${n} ${k}s`).join(", ") || "some assets"} not loaded). The map shows what was returned.
          </p>
        )}
        {error && graph.loaded && (
          <p role="status" className="border-b border-severity-medium/30 bg-amber-50 px-3 py-1.5 text-xs text-severity-medium">
            Could not refresh: {error}. Showing the last data.{" "}
            <button type="button" className="font-medium text-accent hover:underline" onClick={() => void refresh()}>Retry</button>
          </p>
        )}
        <div className="relative min-h-0 flex-1">
          {mode === "table" ? (
            <AssetsTable graph={graph} selected={assetParam} onOpen={openAndCentre} showStatic={showStatic} />
          ) : (
            <ErrorBoundary label="the network map">
              <Suspense fallback={<div role="status" className="flex h-full items-center justify-center text-sm text-slate">Loading the map…</div>}>
                <NetworkMap graph={graph} selected={assetParam} onOpen={open} showSecondary={showLinks} showStatic={showStatic} followActivity={follow} centerOn={centerOn} fitNonce={fitNonce} />
              </Suspense>
            </ErrorBoundary>
          )}
        </div>
      </div>

      <section aria-labelledby="surface-h" className="rounded-lg border border-line bg-surface p-4">
        <div className="mb-3 flex flex-wrap items-center gap-3">
          <h2 id="surface-h" className="font-display text-base font-semibold text-ink">Surface</h2>
          {services.length > 1 && (
            <label className="flex items-center gap-1.5 text-[13px] text-slate">
              Service
              <select className="max-w-xs rounded border border-line bg-surface px-2 py-1 text-ink" value={surfaceNode?.id ?? ""} onChange={(e) => setSurfaceService(e.target.value)}>
                {services.map((s) => <option key={s.id} value={s.id}>{displayService(s.label)}</option>)}
              </select>
            </label>
          )}
          {surfaceNode && services.length === 1 && <span className="mono text-[13px] text-slate">{assetTitle(surfaceNode)}</span>}
          {surfaceNode && <button type="button" className="ml-auto text-[13px] text-accent hover:underline" onClick={() => open(surfaceNode.id)}>Open details</button>}
        </div>
        {surfaceNode ? <SurfacePanel service={surfaceNode} /> : <p className="text-[13px] text-slate">No service has been identified yet.</p>}
      </section>

      {selectedNode && <AssetDrawer runId={runId} asset={selectedNode} onClose={() => setAssetParam(null)} />}
      {assetParam && !selectedNode && graph.loaded && (
        <p role="status" className="text-[13px] text-slate">Asset {assetParam} is not in this run's asset graph.</p>
      )}
    </div>
  );
}
