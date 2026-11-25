// Run-scoped live context: ONE event stream per run workspace (RunWorkspace mounts the
// provider). Everything that needs live data reads it from here instead of opening its
// own connection: the graph, the run header, the Live Activity tab, the run chat.
//
// API (all from this file)
//   <RunLiveProvider runId>            mount once per run workspace
//   useRunLive(): RunLive              full value incl. `events`; re-renders on every flushed
//                                      batch (<= 20/s), so use it only where the list is shown
//   useRunLiveStatus(): RunLiveStatus  everything except events/lastSeq; re-renders only when
//   useRunLiveStatusOptional()         the connection state changes. Prefer it (+ subscribe).
//                                      The Optional form returns null outside the provider
//                                      (graph dev preview, tests); the others throw.
//   useRunEvents(match, cb)            subscribe for the component's lifetime (recommended)
//
//   RunLive.events        ascending GreyboxEvent[] (history tail + live), deduped by seq,
//                         bounded to 20 000 (oldest dropped; loadOlder() refetches)
//   RunLive.state         "connecting" | "live" | "reconnecting" | "disconnected" | "finished"
//   RunLive.isLive        state === "live": the stream is delivering, so polling can relax
//   RunLive.lastSeq       highest applied seq
//   RunLive.runStatus     run status from history / the stream's `end` frame (or null)
//   RunLive.subscribe(match, cb) -> unsubscribe
//       match: "hint.added" (exact kind) | "hint.*" (prefix) | ["a.b","c.*"] | (e) => boolean
//       cb(event) is called once per newly applied event, in seq order, outside React
//       render, for the history tail (when subscribed before it arrives), live events and
//       gap backfill; not for older pages. Subscribers added later should seed from
//       `events` (e.g. events.filter(e => e.kind.startsWith("hint."))) and then use
//       subscribe for increments. Callbacks must not throw (errors are swallowed).
//   RunLive.loadOlder()   prepend the previous page of history
//   RunLive.reconnect()   retry now
//
// Event text (summary, data) is redacted plain text: render it as text, never as HTML.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, type ReactNode } from "react";
import { compileMatch, type EventMatch, type GreyboxEvent, type StreamState } from "../events";
import { useEventStream, type EventStreamResult } from "../useEventStream";

export interface RunLiveStatus {
  runId: string;
  state: StreamState;
  isLive: boolean;
  runStatus: string | null;
  hasMoreBefore: boolean;
  error: string | null;
  subscribe: (match: EventMatch, cb: (e: GreyboxEvent) => void) => () => void;
  loadOlder: EventStreamResult["loadOlder"];
  reconnect: () => void;
}

export interface RunLive extends RunLiveStatus {
  events: readonly GreyboxEvent[];
  lastSeq: number;
}

const StatusCtx = createContext<RunLiveStatus | null>(null);
const EventsCtx = createContext<{ events: readonly GreyboxEvent[]; lastSeq: number }>({ events: [], lastSeq: 0 });

export function RunLiveProvider({ runId, children, enabled = true }: { runId: string; children: ReactNode; enabled?: boolean }) {
  const subs = useRef(new Set<{ test: (e: GreyboxEvent) => boolean; cb: (e: GreyboxEvent) => void }>());

  const onBatch = useCallback((batch: GreyboxEvent[]) => {
    if (!subs.current.size) return;
    for (const e of batch) {
      for (const s of [...subs.current]) {
        try {
          if (s.test(e)) s.cb(e);
        } catch {
          /* a faulty subscriber must not break the stream */
        }
      }
    }
  }, []);

  const stream = useEventStream(runId, { enabled, onBatch });

  const subscribe = useCallback<RunLiveStatus["subscribe"]>((match, cb) => {
    const entry = { test: compileMatch(match), cb };
    subs.current.add(entry);
    return () => {
      subs.current.delete(entry);
    };
  }, []);

  const { events, state, lastSeq, runStatus, hasMoreBefore, error, loadOlder, reconnect } = stream;
  const status = useMemo<RunLiveStatus>(
    () => ({
      runId, state, isLive: state === "live", runStatus, hasMoreBefore, error, subscribe, loadOlder, reconnect,
    }),
    [runId, state, runStatus, hasMoreBefore, error, subscribe, loadOlder, reconnect],
  );
  const evs = useMemo(() => ({ events, lastSeq }), [events, lastSeq]);
  return (
    <StatusCtx.Provider value={status}>
      <EventsCtx.Provider value={evs}>{children}</EventsCtx.Provider>
    </StatusCtx.Provider>
  );
}

export function useRunLiveStatusOptional(): RunLiveStatus | null {
  return useContext(StatusCtx);
}

export function useRunLiveStatus(): RunLiveStatus {
  const v = useContext(StatusCtx);
  if (!v) throw new Error("useRunLiveStatus must be used inside <RunLiveProvider>");
  return v;
}

export function useRunLive(): RunLive {
  const status = useRunLiveStatus();
  const evs = useContext(EventsCtx);
  return useMemo(() => ({ ...status, ...evs }), [status, evs]);
}

export function useRunEvents(match: EventMatch, cb: (e: GreyboxEvent) => void): void {
  const live = useRunLiveStatusOptional();
  const cbRef = useRef(cb);
  cbRef.current = cb;
  const subscribe = live?.subscribe;
  const key = typeof match === "function" ? match : typeof match === "string" ? match : match.join("|");
  const matchRef = useRef(match);
  matchRef.current = match;
  useEffect(() => {
    if (!subscribe) return;
    return subscribe(matchRef.current, (e) => cbRef.current(e));
  }, [subscribe, key]);
}
