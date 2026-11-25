import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "../../../api/client";
import { greyboxApi } from "../api";
import { RUN_TERMINAL, type RunRead } from "../types";
import { useRunEvents, useRunLiveStatusOptional } from "./RunLiveContext";

/** Fallback poll while the event stream is not live. */
export const RUN_POLL_MS = 3000;
/** Safety refetch while the stream is live (events trigger the real refreshes). */
export const RUN_SAFETY_POLL_MS = 30_000;
/** Coalescing delays for event-driven refreshes. */
export const RUN_EVENT_REFRESH_MS = 250;
export const RUN_COUNTER_REFRESH_MS = 1000;

export type RunConnection =
  /** Polling and the last request succeeded. */
  | "live"
  /** One or two consecutive failures: still retrying. */
  | "reconnecting"
  /** Three or more consecutive failures. Still retrying, but say so honestly. */
  | "disconnected"
  /** Terminal run: polling stopped. */
  | "finished";

export interface RunState {
  run: RunRead | null;
  /** Most recent load error (cleared by the next success). */
  loadError: { status: number; message: string } | null;
  /** 404: not found, no access, or grey-box disabled. Polling stops. */
  notFound: boolean;
  /** Consecutive failed polls. */
  fails: number;
  connection: RunConnection;
  /** "stream" while the SSE stream is live (events trigger refreshes), else "poll". */
  transport: "stream" | "poll";
  lastUpdated: number | null;
  refresh: () => Promise<void>;
  /** Replace the run with a fresher copy (e.g. the cancel response). */
  setRun: (r: RunRead) => void;
}

/**
 * GET /greybox/runs/{id}. While the run event stream is live (RunLiveContext) the run is
 * refetched on run.* / finding.* events (250 ms coalescing) and, for counters, on
 * graph.updated (1 s), with a 30 s safety poll. When the stream is not live (or there is
 * no provider) it falls back to the 3 s poll of the white-box RunDetail page.
 * Polling pauses while the tab is hidden and resumes (with an immediate fetch) when shown.
 */
export function useRun(id: string): RunState {
  const [run, setRunState] = useState<RunRead | null>(null);
  const [loadError, setLoadError] = useState<RunState["loadError"]>(null);
  const [fails, setFails] = useState(0);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const alive = useRef(true);
  const inFlight = useRef(false);
  const live = useRunLiveStatusOptional();
  const streaming = !!live?.isLive;

  const setRun = useCallback((r: RunRead) => {
    setRunState(r);
    setLastUpdated(Date.now());
  }, []);

  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    try {
      const r = await greyboxApi.run(id);
      if (!alive.current) return;
      setRun(r);
      setLoadError(null);
      setFails(0);
    } catch (e) {
      if (!alive.current) return;
      const status = e instanceof ApiError ? e.status : 0;
      // Before the first success a 404 is final (see notFound); otherwise keep retrying.
      setFails((n) => n + 1);
      setLoadError({ status, message: e instanceof Error ? e.message : "Failed to load run" });
    } finally {
      inFlight.current = false;
    }
  }, [id, setRun]);

  useEffect(() => {
    alive.current = true;
    setRunState(null);
    setLoadError(null);
    setFails(0);
    void refresh();
    return () => {
      alive.current = false;
    };
  }, [refresh]);

  const terminal = run ? RUN_TERMINAL.has(run.status) : false;
  const notFound = !run && (loadError?.status === 404 || loadError?.status === 401);

  // Event-driven refresh: coalesce bursts into one fetch.
  const timers = useRef<Record<string, ReturnType<typeof setTimeout> | undefined>>({});
  const schedule = useCallback(
    (key: string, ms: number) => {
      if (timers.current[key]) return;
      timers.current[key] = setTimeout(() => {
        timers.current[key] = undefined;
        void refresh();
      }, ms);
    },
    [refresh],
  );
  useEffect(() => {
    const t = timers.current;
    return () => {
      for (const k of Object.keys(t)) if (t[k]) clearTimeout(t[k]);
    };
  }, [id]);
  useRunEvents(["run.*", "finding.*", "report.*"], () => schedule("e", RUN_EVENT_REFRESH_MS));
  useRunEvents("graph.updated", () => schedule("c", RUN_COUNTER_REFRESH_MS));

  useEffect(() => {
    if (terminal || notFound) return;
    const t = setInterval(() => {
      if (!document.hidden) void refresh();
    }, streaming ? RUN_SAFETY_POLL_MS : RUN_POLL_MS);
    const onVis = () => !document.hidden && void refresh();
    document.addEventListener("visibilitychange", onVis);
    return () => {
      clearInterval(t);
      document.removeEventListener("visibilitychange", onVis);
    };
  }, [terminal, notFound, refresh, streaming]);

  const connection: RunConnection = terminal
    ? "finished"
    : fails >= 3
      ? "disconnected"
      : fails > 0
        ? "reconnecting"
        : "live";

  return { run, loadError, notFound, fails, connection, transport: streaming ? "stream" : "poll", lastUpdated, refresh, setRun };
}
