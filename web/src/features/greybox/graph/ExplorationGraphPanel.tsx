// Entry point for the workspace's Exploration tab. Stays in the main bundle and
// is tiny: React Flow, dagre and the graph CSS load on demand with the lazy chunk.
import { lazy, Suspense, useEffect, useRef } from "react";
import { ErrorBoundary } from "../../../components/ui";
import { RUN_TERMINAL, type RunStatus } from "../types";
import type { ExplorationGraphProps } from "./ExplorationGraph";
import { useExplorationGraph, type ExplorationGraphController, type UseExplorationGraphOptions } from "./useExplorationGraph";
import { useRunEvents, useRunLiveStatusOptional } from "../run/RunLiveContext";
import type { StreamState } from "../events";

/** Safety refetch while the stream is live (graph.updated events do the real work). */
export const GRAPH_SAFETY_POLL_MS = 30_000;
/** Fallback poll while the stream is not live. */
export const GRAPH_FALLBACK_POLL_MS = 3_000;

/** Poll interval policy: 30 s safety net when the stream is live, 3 s fallback otherwise. */
export function graphPollMs(streamLive: boolean): number {
  return streamLive ? GRAPH_SAFETY_POLL_MS : GRAPH_FALLBACK_POLL_MS;
}

/**
 * Event-driven refresh: `graph.updated` triggers the controller's debounced (1 s) delta
 * fetch (skipped when the event's version is not newer than the loaded one); a terminal
 * run event triggers a final one. Returns the stream state for the graph's indicator.
 */
export function useLiveGraphRefresh(controller: ExplorationGraphController): { liveState: StreamState | null; streamLive: boolean } {
  const live = useRunLiveStatusOptional();
  const { requestRefresh } = controller;
  const version = useRef(controller.graph.version);
  version.current = controller.graph.version;
  useRunEvents("graph.updated", (e) => {
    const v = (e.data as { version?: unknown } | null)?.version;
    if (typeof v === "number" && v <= version.current) return;
    requestRefresh();
  });
  // Terminal run events: fetch the final delta NOW (not debounced), then once more shortly
  // after in case the last graph writes land just behind the event.
  const { refresh } = controller;
  const settle = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (settle.current) clearTimeout(settle.current); }, []);
  useRunEvents(["run.completed", "run.failed", "run.cancelled"], () => {
    void refresh();
    if (settle.current) clearTimeout(settle.current);
    settle.current = setTimeout(() => void refresh(), 1_500);
  });
  return { liveState: live?.state ?? null, streamLive: !!live?.isLive };
}

const ExplorationGraph = lazy(() => import("./ExplorationGraph"));

function Loading() {
  return (
    <div role="status" aria-live="polite" className="flex h-full min-h-[320px] items-center justify-center text-sm text-slate">
      Loading the graph view…
    </div>
  );
}

/** Lazy graph view for a controller you own (e.g. shared with the live event stream). */
export function LazyExplorationGraph(props: ExplorationGraphProps) {
  return (
    <ErrorBoundary label="the exploration graph">
      <Suspense fallback={<Loading />}>
        <ExplorationGraph {...props} />
      </Suspense>
    </ErrorBoundary>
  );
}

/** Self-contained tab: loads the run's graph and renders it. */
export function ExplorationGraphPanel({
  runId,
  runActive = false,
  options,
  ...rest
}: Omit<ExplorationGraphProps, "controller"> & { runId: string; options?: UseExplorationGraphOptions }) {
  const live = useRunLiveStatusOptional();
  const controller = useExplorationGraph(runId, { active: runActive, pollMs: graphPollMs(!!live?.isLive), ...options });
  const { liveState } = useLiveGraphRefresh(controller);
  return <LazyExplorationGraph controller={controller} runActive={runActive} liveState={liveState} {...rest} />;
}

/** True when RunRead.graph_version moved past both the last value seen and the loaded graph. */
export function graphVersionAdvanced(graphVersion: number | undefined, lastSeen: number | undefined, loadedVersion: number): boolean {
  return graphVersion !== undefined && graphVersion > loadedVersion && (lastSeen === undefined || graphVersion > lastSeen);
}

export interface ExplorationTabProps extends Omit<ExplorationGraphProps, "controller" | "runActive"> {
  runId: string;
  runStatus: RunStatus;
  graphVersion?: number;
  /** Injected for tests. */
  options?: UseExplorationGraphOptions;
}

/**
 * Body of the run workspace's Exploration tab (re-exported by run/ExplorationTabSlot).
 * `graphVersion` (from RunRead) is a cheap change signal: when it increases past the
 * loaded version, fetch the delta now.
 */
export function ExplorationTab({ runId, runStatus, graphVersion, options, ...links }: ExplorationTabProps) {
  const active = !RUN_TERMINAL.has(runStatus);
  const live = useRunLiveStatusOptional();
  const controller = useExplorationGraph(runId, { active, pollMs: graphPollMs(!!live?.isLive), ...options });
  const { liveState } = useLiveGraphRefresh(controller);
  const { graph, refresh } = controller;
  const lastSeen = useRef<number | undefined>(graphVersion);
  useEffect(() => {
    const advanced = graphVersionAdvanced(graphVersion, lastSeen.current, graph.version);
    if (graphVersion !== undefined) lastSeen.current = graphVersion;
    if (graph.loaded && advanced) void refresh();
  }, [graphVersion, graph.loaded, graph.version, refresh]);
  // The run just turned terminal (status from RunRead, possibly before/without the event): final delta.
  const wasActive = useRef(active);
  useEffect(() => {
    if (wasActive.current && !active) {
      void refresh();
      const t = setTimeout(() => void refresh(), 1_500);
      wasActive.current = active;
      return () => clearTimeout(t);
    }
    wasActive.current = active;
  }, [active, refresh]);
  return <LazyExplorationGraph controller={controller} runActive={active} liveState={liveState} {...links} />;
}
