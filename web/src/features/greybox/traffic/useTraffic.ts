import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "../../../api/client";
import { greyboxApi } from "../api";
import type { Exchange, ExchangeSummary } from "../types";
import { useRunEvents } from "../run/RunLiveContext";
import { filtersToQuery, lastId, mergeRows, serverKey, type TrafficFilters } from "./trafficModel";

const PAGE = 100;

export type TrafficStatus = "loading" | "ready" | "unavailable" | "error";

export interface TrafficState {
  rows: ExchangeSummary[];
  status: TrafficStatus;
  error: string | null;
  hasMore: boolean;
  loadingMore: boolean;
  loadMore: () => void;
  reload: () => void;
}

/**
 * Exchanges of a run, ascending by id. Pages come from `after_id`; while the run is live,
 * http.exchange / scope.blocked events trigger a fetch of just the rows after the last id
 * (never a full refetch). A 404 or capture != "enabled" is reported as "unavailable".
 */
export function useTraffic(runId: string, filters: TrafficFilters): TrafficState {
  const [rows, setRows] = useState<ExchangeSummary[]>([]);
  const [status, setStatus] = useState<TrafficStatus>("loading");
  const [error, setError] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const gen = useRef(0);
  const rowsRef = useRef<ExchangeSummary[]>([]);
  const busy = useRef(false);
  const dirty = useRef(false);
  const hasMoreRef = useRef(false);
  const filtersRef = useRef(filters);
  filtersRef.current = filters;
  const key = serverKey(filters);

  const apply = (next: ExchangeSummary[], more: boolean) => {
    rowsRef.current = next;
    hasMoreRef.current = more;
    setRows(next);
    setHasMore(more);
  };

  const fetchPage = useCallback(async (reset: boolean) => {
    if (!runId) return;
    if (busy.current && !reset) {
      dirty.current = true;
      return;
    }
    const mine = reset ? ++gen.current : gen.current;
    busy.current = true;
    if (reset) {
      rowsRef.current = [];
      setStatus("loading");
      setError(null);
    } else setLoadingMore(true);
    try {
      const r = await greyboxApi.traffic(runId, filtersToQuery(filtersRef.current, { limit: PAGE, after_id: reset ? undefined : lastId(rowsRef.current) }));
      if (mine !== gen.current) return;
      if (r.capture !== "enabled") {
        setStatus("unavailable");
        return;
      }
      apply(reset ? mergeRows([], r.items) : mergeRows(rowsRef.current, r.items), r.next_after_id != null);
      setStatus("ready");
    } catch (e) {
      if (mine !== gen.current) return;
      if (e instanceof ApiError && e.status === 404) setStatus("unavailable");
      else {
        setError(e instanceof Error ? e.message : "Could not load traffic");
        if (reset) setStatus("error");
      }
    } finally {
      if (mine === gen.current) {
        busy.current = false;
        setLoadingMore(false);
        if (dirty.current) {
          dirty.current = false;
          if (!hasMoreRef.current) void fetchPage(false);
        }
      }
    }
  }, [runId]);

  useEffect(() => {
    busy.current = false;
    dirty.current = false;
    void fetchPage(true);
    return () => {
      gen.current++;
    };
  }, [fetchPage, key]);

  // New exchanges while live: only when the loaded list reaches the end (else scrolling loads them).
  useRunEvents(["http.exchange", "scope.blocked"], () => {
    if (status === "ready" && !hasMoreRef.current) void fetchPage(false);
  });

  const loadMore = useCallback(() => {
    if (hasMoreRef.current && !busy.current) void fetchPage(false);
  }, [fetchPage]);
  const reload = useCallback(() => void fetchPage(true), [fetchPage]);

  return { rows, status, error, hasMore, loadingMore, loadMore, reload };
}

export interface ExchangeDetailState {
  exchange: Exchange | null;
  loading: boolean;
  /** "missing" = 404 */
  error: "missing" | string | null;
}

export function useExchange(runId: string, id: number | null): ExchangeDetailState {
  const [state, setState] = useState<ExchangeDetailState>({ exchange: null, loading: false, error: null });
  useEffect(() => {
    if (id == null) {
      setState({ exchange: null, loading: false, error: null });
      return;
    }
    let live = true;
    setState({ exchange: null, loading: true, error: null });
    greyboxApi
      .exchange(runId, id)
      .then((exchange) => live && setState({ exchange, loading: false, error: null }))
      .catch((e) => live && setState({ exchange: null, loading: false, error: e instanceof ApiError && e.status === 404 ? "missing" : e instanceof Error ? e.message : "Could not load the exchange" }));
    return () => {
      live = false;
    };
  }, [runId, id]);
  return state;
}
