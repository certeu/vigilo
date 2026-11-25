// Snapshot-then-deltas loader for the asset graph (same approach as
// graph/useExplorationGraph.ts: since_version=0 first, then since_version=<local version>;
// responses are upserts and out-of-order ones are ignored). Event-driven refreshes are
// debounced with a bounded wait (first event of a burst + debounceMs); a 30 s timer is the
// safety net while the stream is live, 3 s otherwise.
import { useCallback, useEffect, useRef, useState } from "react";
import { greyboxApi } from "../api";
import type { AssetGraphResponse } from "../types";
import { EMPTY_ASSET_GRAPH, expireAssetMarks, mergeAssetGraph, type AssetGraphState } from "./model";

export type AssetGraphFetcher = (runId: string, sinceVersion: number, limit: number, signal?: AbortSignal) => Promise<AssetGraphResponse>;
export const fetchAssetGraph: AssetGraphFetcher = (runId, since, limit, signal) => greyboxApi.assetGraph(runId, since, limit, signal);

export type AssetLoadStatus = "loading" | "ready" | "error";

export interface UseAssetGraphOptions {
  active?: boolean;
  pollMs?: number;
  debounceMs?: number;
  limit?: number;
  highlightMs?: number;
  fetcher?: AssetGraphFetcher;
}

export interface AssetGraphController {
  graph: AssetGraphState;
  status: AssetLoadStatus;
  error: string | null;
  updatedAt: number | null;
  refresh: () => Promise<void>;
  requestRefresh: () => void;
}

export function useAssetGraph(runId: string, opts: UseAssetGraphOptions = {}): AssetGraphController {
  const { active = false, pollMs = 30_000, debounceMs = 1_000, limit = 5000, highlightMs = 6_000, fetcher = fetchAssetGraph } = opts;
  const [graph, setGraph] = useState<AssetGraphState>(EMPTY_ASSET_GRAPH);
  const [status, setStatus] = useState<AssetLoadStatus>("loading");
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

  const fetchOnce = useCallback(async () => {
    const ctrl = new AbortController();
    abort.current = ctrl;
    try {
      const since = graphRef.current.loaded ? graphRef.current.version : 0;
      const resp = await fetcherRef.current(runId, since, limit, ctrl.signal);
      if (!alive.current || ctrl.signal.aborted) return;
      const next = mergeAssetGraph(graphRef.current, resp, Date.now()).state;
      graphRef.current = next;
      setGraph(next);
      setUpdatedAt(Date.now());
      setStatus("ready");
      setError(null);
    } catch (e) {
      if (!alive.current || ctrl.signal.aborted) return;
      setError(e instanceof Error ? e.message : String(e));
      setStatus(graphRef.current.loaded ? "ready" : "error");
    }
  }, [runId, limit]);

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

  const requestRefresh = useCallback(() => {
    if (debounce.current) return;
    debounce.current = setTimeout(() => {
      debounce.current = null;
      void refresh();
    }, debounceMs);
  }, [refresh, debounceMs]);

  useEffect(() => {
    alive.current = true;
    graphRef.current = EMPTY_ASSET_GRAPH;
    setGraph(EMPTY_ASSET_GRAPH);
    setStatus("loading");
    setError(null);
    void refresh();
    return () => {
      alive.current = false;
      abort.current?.abort();
      if (debounce.current) {
        clearTimeout(debounce.current);
        debounce.current = null;
      }
    };
  }, [runId, refresh]);

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

  useEffect(() => {
    if (!graph.fresh.size && !graph.changed.size) return;
    const t = setTimeout(() => {
      const next = expireAssetMarks(graphRef.current, Date.now(), highlightMs);
      if (next !== graphRef.current) {
        graphRef.current = next;
        setGraph(next);
      }
    }, 1_000);
    return () => clearTimeout(t);
  }, [graph, highlightMs]);

  return { graph, status, error, updatedAt, refresh, requestRefresh };
}
