// Snapshot-then-deltas loader for the exploration graph.
// Loads the bounded snapshot (since_version=0), then merges deltas
// (since_version=<local version>). `graph.updated` events from the run stream call
// `requestRefresh()` (see ExplorationGraphPanel.useLiveGraphRefresh); the timer
// (`pollMs`) is a 30 s safety net while the stream is live and a 3 s fallback otherwise.
import { useCallback, useEffect, useRef, useState } from "react";
import { EMPTY_GRAPH, expireMarks, mergeGraph, type GraphState } from "./model";
import { fetchExplorationGraph, GRAPH_DEFAULT_LIMIT, type ExplorationGraphFetcher } from "./api";
import type { ExplorationGraphResponse } from "./types";

export type GraphLoadStatus = "loading" | "ready" | "error";

export interface UseExplorationGraphOptions {
  /** Run is active (queued … cancelling): enables the safety refetch timer. */
  active?: boolean;
  /** Refetch interval while active and visible: a 30 s safety net once SSE exists. */
  pollMs?: number;
  /** Debounce of `requestRefresh()`: 1 s after `graph.updated`. */
  debounceMs?: number;
  limit?: number;
  /** How long new / changed nodes stay highlighted. */
  highlightMs?: number;
  /** Injected for the dev preview and tests. */
  fetcher?: ExplorationGraphFetcher;
}

export interface ExplorationGraphController {
  graph: GraphState;
  status: GraphLoadStatus;
  error: string | null;
  /** Client time of the last successful merge. */
  updatedAt: number | null;
  /** Fetches the delta now (coalesces with an in-flight request). */
  refresh: () => Promise<void>;
  /** Coalesced refresh (fires `debounceMs` after the first call of a burst), for `graph.updated` events. */
  requestRefresh: () => void;
  /** Merge a response obtained elsewhere (e.g. pushed by a stream). */
  applyDelta: (resp: ExplorationGraphResponse) => void;
  /** Drop local state and reload the snapshot. */
  reload: () => Promise<void>;
}

export function useExplorationGraph(runId: string, opts: UseExplorationGraphOptions = {}): ExplorationGraphController {
  const {
    active = false,
    pollMs = 30_000,
    debounceMs = 1_000,
    limit = GRAPH_DEFAULT_LIMIT,
    highlightMs = 6_000,
    fetcher = fetchExplorationGraph,
  } = opts;
  const [graph, setGraph] = useState<GraphState>(EMPTY_GRAPH);
  const [status, setStatus] = useState<GraphLoadStatus>("loading");
  const [error, setError] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);

  const graphRef = useRef(graph);
  graphRef.current = graph;
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;
  const inflight = useRef<Promise<void> | null>(null);
  const again = useRef(false);
  const abort = useRef<AbortController | null>(null);
  const debounce = useRef<ReturnType<typeof setTimeout> | null>(null);
  const alive = useRef(true);

  const applyDelta = useCallback((resp: ExplorationGraphResponse) => {
    const next = mergeGraph(graphRef.current, resp, Date.now()).state;
    graphRef.current = next;
    setGraph(next);
    setUpdatedAt(Date.now());
  }, []);

  const fetchOnce = useCallback(async () => {
    const ctrl = new AbortController();
    abort.current = ctrl;
    try {
      const since = graphRef.current.loaded ? graphRef.current.version : 0;
      const resp = await fetcherRef.current(runId, since, limit, ctrl.signal);
      if (!alive.current || ctrl.signal.aborted) return;
      applyDelta(resp);
      setStatus("ready");
      setError(null);
    } catch (e) {
      if (!alive.current || ctrl.signal.aborted) return;
      setError(e instanceof Error ? e.message : String(e));
      // Keep showing what we have; only a failed first load is a hard error.
      setStatus(graphRef.current.loaded ? "ready" : "error");
    }
  }, [runId, limit, applyDelta]);

  const refresh = useCallback(async () => {
    if (inflight.current) {
      again.current = true;
      return inflight.current;
    }
    const run = async () => {
      do {
        again.current = false;
        await fetchOnce();
      } while (again.current && alive.current);
    };
    inflight.current = run().finally(() => {
      inflight.current = null;
    });
    return inflight.current;
  }, [fetchOnce]);

  // Coalescing with a bounded wait: a burst of graph.updated events (up to 2/s) yields one
  // fetch ~debounceMs after the FIRST one. A resetting debounce would starve while events
  // keep arriving faster than the delay.
  const requestRefresh = useCallback(() => {
    if (debounce.current) return;
    debounce.current = setTimeout(() => {
      debounce.current = null;
      void refresh();
    }, debounceMs);
  }, [refresh, debounceMs]);

  const reload = useCallback(async () => {
    abort.current?.abort();
    inflight.current = null;
    graphRef.current = EMPTY_GRAPH;
    setGraph(EMPTY_GRAPH);
    setStatus("loading");
    await refresh();
  }, [refresh]);

  // Initial snapshot, and reset when the run changes.
  useEffect(() => {
    alive.current = true;
    graphRef.current = EMPTY_GRAPH;
    setGraph(EMPTY_GRAPH);
    setStatus("loading");
    setError(null);
    void refresh();
    return () => {
      alive.current = false;
      abort.current?.abort();
      if (debounce.current) clearTimeout(debounce.current);
    };
  }, [runId, refresh]);

  // Safety refetch while the run is active and the tab is visible.
  useEffect(() => {
    if (!active || pollMs <= 0) return;
    const t = setInterval(() => {
      if (document.visibilityState === "visible") void refresh();
    }, pollMs);
    const onVisible = () => {
      if (document.visibilityState === "visible") void refresh();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      clearInterval(t);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [active, pollMs, refresh]);

  // Expire "new" / "changed" highlights.
  useEffect(() => {
    if (!graph.fresh.size && !graph.changed.size) return;
    const t = setTimeout(() => {
      const next = expireMarks(graphRef.current, Date.now(), highlightMs);
      if (next !== graphRef.current) {
        graphRef.current = next;
        setGraph(next);
      }
    }, 1_000);
    return () => clearTimeout(t);
  }, [graph, highlightMs]);

  return { graph, status, error, updatedAt, refresh, requestRefresh, applyDelta, reload };
}
