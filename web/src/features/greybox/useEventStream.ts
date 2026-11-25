// Live event stream for one grey-box run.
//
//  1. GET /greybox/runs/{id}/events (tail) -> history + last_seq cursor.
//  2. fetch() GET .../events/stream?after=<last_seq> with the Bearer header (native
//     EventSource cannot send headers) and `Last-Event-ID`, parsed by ./sse.
//  3. Dedupe by seq (anything <= highest applied is dropped), flush to React every 50 ms.
//  4. States: connecting | live | reconnecting | disconnected | finished.
//  5. Reconnect with exponential backoff + jitter (1 s .. 30 s) and immediately on
//     `online` / `visibilitychange`. The server closes cleanly every 15 min: same path.
//  6. 401: clear the token and go to /login, like request(). 404/403/422 are final.
//  7. Gap (stream seq > highest + 1): backfill with ?after_seq= before applying.
//
// The protocol lives in the framework-free `EventStreamClient` (unit-tested with a fake
// fetch); `useEventStream` is the thin React binding. Components should not call the
// hook themselves: use RunLiveContext, which owns one stream per run workspace.
import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, getToken as defaultGetToken, setToken } from "../../api/client";
import {
  isGreyboxEvent, isTerminalRunStatus,
  type EventsPage, type GreyboxEvent, type StreamState,
} from "./events";
import { SseParser } from "./sse";

export const BACKOFF_BASE_MS = 1_000;
export const BACKOFF_MAX_MS = 30_000;
export const FLUSH_MS = 50;
export const HISTORY_LIMIT = 500;
/** In-memory ring bound: the oldest events are dropped (and loadOlder() can refetch them). */
export const MAX_EVENTS = 20_000;
/** Consecutive failures before "reconnecting" is reported as "disconnected" (still retrying). */
export const DISCONNECTED_AFTER = 3;
/** The server sends a `: ping` comment after 15 s without data. No bytes at all
 * for this long means the connection is dead even if the response never ended (e.g. a dev
 * proxy that keeps the client side open after the upstream died): abort and reconnect. */
export const STALL_TIMEOUT_MS = 40_000;

/** attempt 0 -> ~1 s, doubling, capped at 30 s; +0..20 % jitter, never above the cap. */
export function backoffDelay(attempt: number, rand: () => number = Math.random): number {
  const exp = Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** Math.max(0, attempt));
  return Math.min(BACKOFF_MAX_MS, Math.round(exp * (1 + 0.2 * rand())));
}

export interface StreamMeta {
  runStatus: string | null;
  lastSeq: number;
  hasMoreBefore?: boolean;
}

export interface EventStreamClientOptions {
  runId: string;
  /** Receives every newly applied event, ascending by seq (history tail, live, backfill). */
  onEvents: (batch: GreyboxEvent[]) => void;
  onState: (s: StreamState) => void;
  onMeta?: (m: StreamMeta) => void;
  onError?: (message: string | null) => void;
  onUnauthorized?: () => void;
  fetchImpl?: typeof fetch;
  getToken?: () => string | null;
  historyLimit?: number;
  flushMs?: number;
  rand?: () => number;
  /** Liveness watchdog for the open stream (default STALL_TIMEOUT_MS). */
  stallTimeoutMs?: number;
}

const FATAL = new Set([401, 403, 404, 422]);

export class EventStreamClient {
  private o: EventStreamClientOptions;
  private highest = 0;
  private stopped = true;
  private finished = false;
  private historyLoaded = false;
  private attempt = 0;
  private gen = 0;
  private state: StreamState = "connecting";
  private abort: AbortController | null = null;
  private pending: GreyboxEvent[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  private wakeSleep: (() => void) | null = null;
  private sleepTimer: ReturnType<typeof setTimeout> | null = null;
  private runStatus: string | null = null;
  private listening = false;

  constructor(opts: EventStreamClientOptions) {
    this.o = opts;
  }

  get lastSeq(): number {
    return this.highest;
  }

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    this.finished = false;
    this.attempt = 0;
    this.setState(this.historyLoaded ? "reconnecting" : "connecting");
    this.listen(true);
    const gen = ++this.gen;
    void this.loop(gen);
  }

  stop(): void {
    this.stopped = true;
    this.gen++;
    this.listen(false);
    this.abort?.abort();
    this.wake();
    this.flush();
  }

  /** Skip any backoff wait and try now (online / tab visible / user action). */
  wake(): void {
    if (this.sleepTimer) clearTimeout(this.sleepTimer);
    this.sleepTimer = null;
    const w = this.wakeSleep;
    this.wakeSleep = null;
    w?.();
  }

  /** Manual retry after a final failure (404/401 stop the loop). */
  retry(): void {
    if (!this.stopped && this.state !== "disconnected") return this.wake();
    this.stopped = true;
    this.start();
  }

  /** Older page for scrolling back: the latest `limit` events with seq < beforeSeq. */
  async loadOlder(beforeSeq: number, limit = this.o.historyLimit ?? HISTORY_LIMIT): Promise<EventsPage> {
    return this.getPage(`before_seq=${beforeSeq}&limit=${limit}`);
  }

  // ---------------------------------------------------------------- internals

  private onWake = () => {
    if (typeof document !== "undefined" && document.visibilityState === "hidden") return;
    if (this.state === "reconnecting" || this.state === "disconnected") this.wake();
  };

  private listen(on: boolean): void {
    if (typeof window === "undefined" || on === this.listening) return;
    this.listening = on;
    const f = on ? "addEventListener" : "removeEventListener";
    window[f]("online", this.onWake);
    document[f]("visibilitychange", this.onWake);
  }

  private setState(s: StreamState): void {
    if (this.state === s && s !== "connecting") return;
    this.state = s;
    this.o.onState(s);
  }

  private async loop(gen: number): Promise<void> {
    const live = () => !this.stopped && gen === this.gen;
    while (live()) {
      const ctrl = new AbortController();
      this.abort = ctrl;
      try {
        if (!this.historyLoaded) await this.loadHistory(ctrl.signal);
        if (!live()) return;
        if (this.finished) return;
        await this.consume(ctrl.signal);
        if (!live() || this.finished) return;
        this.o.onError?.(null);
      } catch (e) {
        if (!live()) return;
        const status = e instanceof ApiError ? e.status : 0;
        if (FATAL.has(status)) {
          this.o.onError?.(e instanceof Error ? e.message : String(e));
          this.flush();
          this.setState("disconnected");
          this.stopped = true;
          this.listen(false);
          return;
        }
        this.o.onError?.(e instanceof Error ? e.message : String(e));
        this.attempt++;
      }
      this.flush();
      this.setState(this.attempt >= DISCONNECTED_AFTER ? "disconnected" : "reconnecting");
      await this.sleep(backoffDelay(this.attempt, this.o.rand));
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      this.wakeSleep = resolve;
      this.sleepTimer = setTimeout(() => this.wake(), ms);
    });
  }

  private headers(extra?: Record<string, string>): Headers {
    const h = new Headers(extra);
    const token = (this.o.getToken ?? defaultGetToken)();
    if (token) h.set("Authorization", `Bearer ${token}`);
    return h;
  }

  private async http(path: string, signal: AbortSignal | undefined, extra?: Record<string, string>): Promise<Response> {
    const f = this.o.fetchImpl ?? fetch;
    const resp = await f(`/api/greybox/runs/${encodeURIComponent(this.o.runId)}${path}`, {
      headers: this.headers(extra),
      signal,
      cache: "no-store",
    });
    if (resp.status === 401) {
      setTokenSafe();
      this.o.onUnauthorized?.();
      throw new ApiError(401, "Unauthorized");
    }
    if (!resp.ok) throw new ApiError(resp.status, resp.statusText || `HTTP ${resp.status}`);
    return resp;
  }

  private async getPage(query: string, signal?: AbortSignal): Promise<EventsPage> {
    const resp = await this.http(`/events?${query}`, signal, { Accept: "application/json" });
    return (await resp.json()) as EventsPage;
  }

  private async loadHistory(signal: AbortSignal): Promise<void> {
    const page = await this.getPage(`limit=${this.o.historyLimit ?? HISTORY_LIMIT}`, signal);
    const items = (page.items ?? []).filter(isGreyboxEvent);
    for (const e of items) this.accept(e);
    this.highest = Math.max(this.highest, page.last_seq ?? 0);
    this.historyLoaded = true;
    this.runStatus = page.run_status ?? null;
    this.flush();
    this.o.onMeta?.({ runStatus: this.runStatus, lastSeq: this.highest, hasMoreBefore: page.has_more_before });
    if (isTerminalRunStatus(this.runStatus) && !page.has_more_after) this.finish();
  }

  private finish(status?: string): void {
    this.finished = true;
    if (status) this.runStatus = status;
    this.flush();
    this.o.onMeta?.({ runStatus: this.runStatus, lastSeq: this.highest });
    this.setState("finished");
    this.abort?.abort();
  }

  private async consume(signal: AbortSignal): Promise<void> {
    const extra: Record<string, string> = { Accept: "text/event-stream" };
    if (this.highest > 0) extra["Last-Event-ID"] = String(this.highest);
    const resp = await this.http(`/events/stream?after=${this.highest}`, signal, extra);
    if (!resp.body) throw new Error("Streaming is not supported by this browser or proxy");
    this.attempt = 0;
    this.setState("live");
    this.o.onError?.(null);
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    const parser = new SseParser();
    // Watchdog: any bytes (events or pings) re-arm it; silence cancels the read so the
    // loop reconnects with Last-Event-ID instead of showing "Live" on a dead stream.
    let stalled = false;
    let watchdog: ReturnType<typeof setTimeout> | null = null;
    const arm = () => {
      if (watchdog) clearTimeout(watchdog);
      watchdog = setTimeout(() => {
        stalled = true;
        reader.cancel().catch(() => {});
      }, this.o.stallTimeoutMs ?? STALL_TIMEOUT_MS);
    };
    arm();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (stalled) throw new Error("The live connection stalled; reconnecting");
        if (done) break;
        arm();
        const batch: GreyboxEvent[] = [];
        let end: { status?: string; last_seq?: number } | null = null;
        for (const item of parser.push(decoder.decode(value, { stream: true }))) {
          if (item.type !== "message") continue;
          let parsed: unknown;
          try {
            parsed = JSON.parse(item.data);
          } catch {
            continue; // malformed frame: skip, never crash the stream
          }
          if (item.event === "end") end = (parsed ?? {}) as { status?: string; last_seq?: number };
          else if (isGreyboxEvent(parsed)) batch.push(parsed);
        }
        if (batch.length) await this.ingest(batch, signal);
        if (end) {
          if (typeof end.last_seq === "number" && end.last_seq > this.highest) await this.backfill(signal);
          this.finish(end.status);
          return;
        }
      }
    } finally {
      if (watchdog) clearTimeout(watchdog);
      reader.cancel().catch(() => {});
    }
  }

  private async ingest(batch: GreyboxEvent[], signal: AbortSignal): Promise<void> {
    for (const e of batch) {
      if (e.seq <= this.highest) continue;
      if (e.seq > this.highest + 1) await this.backfill(signal);
      this.accept(e);
    }
  }

  private async backfill(signal: AbortSignal): Promise<void> {
    for (;;) {
      const page = await this.getPage(`after_seq=${this.highest}&limit=1000`, signal);
      const items = (page.items ?? []).filter(isGreyboxEvent);
      for (const e of items) this.accept(e);
      if (!page.has_more_after || items.length === 0) return;
    }
  }

  private accept(e: GreyboxEvent): void {
    if (e.seq <= this.highest) return;
    this.highest = Math.max(this.highest, e.seq);
    this.pending.push(e);
    if (!this.flushTimer) this.flushTimer = setTimeout(() => this.flush(), this.o.flushMs ?? FLUSH_MS);
  }

  private flush(): void {
    if (this.flushTimer) clearTimeout(this.flushTimer);
    this.flushTimer = null;
    if (!this.pending.length) return;
    const batch = this.pending;
    this.pending = [];
    this.o.onEvents(batch);
    this.o.onMeta?.({ runStatus: this.runStatus, lastSeq: this.highest });
  }
}

function setTokenSafe(): void {
  try {
    setToken(null);
  } catch {
    /* no localStorage (tests) */
  }
}

// ------------------------------------------------------------------ React binding

export interface UseEventStreamOptions {
  enabled?: boolean;
  maxEvents?: number;
  historyLimit?: number;
  /** Called with each flushed batch of newly applied events (not older pages). */
  onBatch?: (batch: GreyboxEvent[]) => void;
}

export interface EventStreamResult {
  /** Ascending by seq, contiguous from the oldest loaded event. */
  events: readonly GreyboxEvent[];
  state: StreamState;
  runStatus: string | null;
  lastSeq: number;
  hasMoreBefore: boolean;
  error: string | null;
  /** Prepend the previous page. Resolves false when nothing older exists. */
  loadOlder: () => Promise<boolean>;
  /** Retry now (also resumes after a final 404/401 stop). */
  reconnect: () => void;
}

const goToLogin = () => {
  if (typeof window !== "undefined" && window.location.pathname !== "/login") window.location.assign("/login");
};

/** Adds events keeping the list ascending/unique and bounded; pure, for tests. */
export function appendCapped(prev: readonly GreyboxEvent[], batch: readonly GreyboxEvent[], max: number): { events: GreyboxEvent[]; trimmed: boolean } {
  const last = prev.length ? prev[prev.length - 1].seq : 0;
  const fresh = batch.filter((e) => e.seq > last);
  const all = fresh.length ? prev.concat(fresh) : (prev as GreyboxEvent[]);
  if (all.length <= max) return { events: all, trimmed: false };
  return { events: all.slice(all.length - max), trimmed: true };
}

export function prependOlder(prev: readonly GreyboxEvent[], older: readonly GreyboxEvent[]): GreyboxEvent[] {
  const first = prev.length ? prev[0].seq : Infinity;
  const add = older.filter((e) => e.seq < first);
  return add.length ? add.concat(prev) : (prev as GreyboxEvent[]);
}

export function useEventStream(runId: string, opts: UseEventStreamOptions = {}): EventStreamResult {
  const { enabled = true, maxEvents = MAX_EVENTS, historyLimit = HISTORY_LIMIT } = opts;
  const [events, setEvents] = useState<readonly GreyboxEvent[]>([]);
  const [state, setState] = useState<StreamState>("connecting");
  const [runStatus, setRunStatus] = useState<string | null>(null);
  const [hasMoreBefore, setHasMoreBefore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastSeq, setLastSeq] = useState(0);
  const clientRef = useRef<EventStreamClient | null>(null);
  const eventsRef = useRef(events);
  eventsRef.current = events;
  const onBatchRef = useRef(opts.onBatch);
  onBatchRef.current = opts.onBatch;
  const olderBusy = useRef(false);

  useEffect(() => {
    setEvents([]);
    setRunStatus(null);
    setHasMoreBefore(false);
    setError(null);
    setLastSeq(0);
    if (!enabled || !runId) {
      setState("disconnected");
      return;
    }
    setState("connecting");
    const client = new EventStreamClient({
      runId,
      historyLimit,
      onEvents: (batch) => {
        setEvents((prev) => {
          const r = appendCapped(prev, batch, maxEvents);
          if (r.trimmed) setHasMoreBefore(true);
          return r.events;
        });
        onBatchRef.current?.(batch);
      },
      onState: setState,
      onMeta: (m) => {
        setRunStatus(m.runStatus);
        setLastSeq(m.lastSeq);
        if (m.hasMoreBefore !== undefined) setHasMoreBefore(m.hasMoreBefore);
      },
      onError: setError,
      onUnauthorized: goToLogin,
    });
    clientRef.current = client;
    client.start();
    return () => {
      client.stop();
      clientRef.current = null;
    };
  }, [runId, enabled, historyLimit, maxEvents]);

  const loadOlder = useCallback(async () => {
    const client = clientRef.current;
    const first = eventsRef.current[0]?.seq;
    if (!client || olderBusy.current || first === undefined || first <= 1) return false;
    olderBusy.current = true;
    try {
      const page = await client.loadOlder(first);
      const items = (page.items ?? []).filter(isGreyboxEvent);
      setEvents((prev) => prependOlder(prev, items));
      setHasMoreBefore(page.has_more_before);
      return items.length > 0;
    } catch {
      return false;
    } finally {
      olderBusy.current = false;
    }
  }, []);

  const reconnect = useCallback(() => clientRef.current?.retry(), []);

  return { events, state, runStatus, lastSeq, hasMoreBefore, error, loadOlder, reconnect };
}
