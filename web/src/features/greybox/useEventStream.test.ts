import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../../api/client";
import { compileMatch, type EventsPage, type GreyboxEvent } from "./events";
import { appendCapped, backoffDelay, EventStreamClient, prependOlder } from "./useEventStream";

const ev = (seq: number, kind = "tool.started"): GreyboxEvent => ({
  seq, run_id: "r", ts: "2026-11-20T10:00:00.123456Z", kind, level: "info", source: "agent",
  agent_id: null, agent_name: null, work_order_id: null, tool_call_id: null, summary: `e${seq}`,
  status: "ok", duration_ms: null, refs: {}, data: {},
});
const frame = (e: GreyboxEvent) => `id: ${e.seq}\nevent: event\ndata: ${JSON.stringify(e)}\n\n`;
const page = (items: GreyboxEvent[], over: Partial<EventsPage> = {}): EventsPage => ({
  items, last_seq: (items.length ? items[items.length - 1].seq : 0), has_more_before: false, has_more_after: false, run_status: "running", ...over,
});
const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });
const sse = (chunks: string[], close = true) => {
  const enc = new TextEncoder();
  return new Response(
    new ReadableStream({
      start(c) {
        for (const ch of chunks) c.enqueue(enc.encode(ch));
        if (close) c.close();
      },
    }),
    { status: 200, headers: { "Content-Type": "text/event-stream" } },
  );
};

interface Call { url: string; headers: Headers }
function harness(handler: (url: string, n: number) => Response | Promise<Response>, extra: { stallTimeoutMs?: number } = {}) {
  const calls: Call[] = [];
  const batches: GreyboxEvent[][] = [];
  const states: string[] = [];
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    calls.push({ url, headers: new Headers(init?.headers) });
    return handler(url, calls.length);
  }) as unknown as typeof fetch;
  const client = new EventStreamClient({
    runId: "r1", fetchImpl, getToken: () => "tok", flushMs: 5, rand: () => 0, ...extra,
    onEvents: (b) => batches.push(b), onState: (s) => states.push(s),
  });
  return { client, calls, batches, states, seqs: () => batches.flat().map((e) => e.seq) };
}
const last = <T,>(a: T[]): T | undefined => a[a.length - 1];
const until = async (f: () => boolean) => {
  for (let i = 0; i < 200 && !f(); i++) await new Promise((r) => setTimeout(r, 5));
  expect(f()).toBe(true);
};

describe("backoffDelay", () => {
  it("doubles from 1 s, caps at 30 s, adds at most 20% jitter", () => {
    expect([0, 1, 2, 3].map((a) => backoffDelay(a, () => 0))).toEqual([1000, 2000, 4000, 8000]);
    expect(backoffDelay(10, () => 0)).toBe(30_000);
    expect(backoffDelay(10, () => 1)).toBe(30_000);
    expect(backoffDelay(0, () => 1)).toBe(1200);
  });
});

describe("list helpers", () => {
  it("appendCapped dedupes, bounds and flags trimming; prependOlder skips known seqs", () => {
    const a = appendCapped([ev(1), ev(2)], [ev(2), ev(3), ev(4)], 3);
    expect(a.events.map((e) => e.seq)).toEqual([2, 3, 4]);
    expect(a.trimmed).toBe(true);
    expect(prependOlder([ev(5), ev(6)], [ev(3), ev(4), ev(5)]).map((e) => e.seq)).toEqual([3, 4, 5, 6]);
  });
});

describe("compileMatch", () => {
  it("matches exact kinds, prefix wildcards, lists and predicates", () => {
    expect(compileMatch("hint.added")(ev(1, "hint.added"))).toBe(true);
    expect(compileMatch("hint.added")(ev(1, "hint.addressed"))).toBe(false);
    expect(compileMatch("hint.*")(ev(1, "hint.rejected"))).toBe(true);
    expect(compileMatch("hint.*")(ev(1, "hints.x"))).toBe(false);
    expect(compileMatch(["run.*", "graph.updated"])(ev(1, "graph.updated"))).toBe(true);
    expect(compileMatch((e) => e.seq > 2)(ev(3))).toBe(true);
  });
});

describe("EventStreamClient", () => {
  beforeEach(() => vi.stubGlobal("localStorage", { removeItem() {}, getItem: () => null, setItem() {} }));
  afterEach(() => vi.unstubAllGlobals());

  it("loads the history tail, then streams after last_seq with Bearer + Last-Event-ID, deduping by seq", async () => {
    const h = harness((url) =>
      url.includes("/events/stream")
        ? sse([frame(ev(2)), ": ping\n\n", frame(ev(3)), frame(ev(3)), frame(ev(1)), `event: end\ndata: {"status":"succeeded","last_seq":3}\n\n`])
        : json(page([ev(1), ev(2)], { last_seq: 2 })),
    );
    h.client.start();
    await until(() => last(h.states) === "finished");
    expect(h.seqs()).toEqual([1, 2, 3]);
    expect(h.calls[0].url).toBe("/api/greybox/runs/r1/events?limit=500");
    expect(h.calls[1].url).toBe("/api/greybox/runs/r1/events/stream?after=2");
    expect(h.calls[1].headers.get("Authorization")).toBe("Bearer tok");
    expect(h.calls[1].headers.get("Last-Event-ID")).toBe("2");
    expect(h.states).toContain("live");
    h.client.stop();
  });

  it("does not open the stream when history already shows a terminal run", async () => {
    const h = harness(() => json(page([ev(1)], { run_status: "succeeded" })));
    h.client.start();
    await until(() => last(h.states) === "finished");
    expect(h.calls).toHaveLength(1);
    h.client.stop();
  });

  it("backfills a gap with ?after_seq= before applying the out-of-order event", async () => {
    const h = harness((url) => {
      if (url.includes("/events/stream")) return sse([frame(ev(5)), `event: end\ndata: {"status":"failed","last_seq":5}\n\n`]);
      if (url.includes("after_seq=1")) return json(page([ev(2), ev(3), ev(4)]));
      return json(page([ev(1)], { last_seq: 1 }));
    });
    h.client.start();
    await until(() => last(h.states) === "finished");
    expect(h.seqs()).toEqual([1, 2, 3, 4, 5]);
    expect(h.calls.some((c) => c.url.includes("events?after_seq=1&limit=1000"))).toBe(true);
    h.client.stop();
  });

  it("reconnects after a dropped stream, resuming from the highest seq", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"], shouldAdvanceTime: true });
    let streams = 0;
    const h = harness((url) => {
      if (!url.includes("/events/stream")) return json(page([ev(1)], { last_seq: 1 }));
      streams++;
      if (streams === 1) return sse([frame(ev(2))]); // closes without `end`
      return sse([frame(ev(3)), `event: end\ndata: {"status":"succeeded","last_seq":3}\n\n`]);
    });
    h.client.start();
    await vi.advanceTimersByTimeAsync(3000);
    await vi.waitFor(() => expect(last(h.states)).toBe("finished"));
    expect(h.seqs()).toEqual([1, 2, 3]);
    expect(h.states).toContain("reconnecting");
    const second = h.calls.filter((c) => c.url.includes("/events/stream"))[1];
    expect(second.url).toContain("after=2");
    expect(second.headers.get("Last-Event-ID")).toBe("2");
    h.client.stop();
    vi.useRealTimers();
  });

  it("reconnects when an open stream goes silent (no events, no pings) past the stall timeout", async () => {
    // E2E finding: through the vite dev proxy the response never ends after the API dies,
    // so without a watchdog the UI stayed "Live" forever and never resumed.
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"], shouldAdvanceTime: true });
    let streams = 0;
    const h = harness((url) => {
      if (!url.includes("/events/stream")) return json(page([ev(1)], { last_seq: 1 }));
      streams++;
      if (streams === 1) return sse([frame(ev(2))], false); // stays open, then silence
      return sse([frame(ev(3)), `event: end\ndata: {"status":"succeeded","last_seq":3}\n\n`]);
    }, { stallTimeoutMs: 200 });
    h.client.start();
    await vi.advanceTimersByTimeAsync(150);
    expect(last(h.states)).toBe("live"); // pings/events within the window keep it live
    await vi.advanceTimersByTimeAsync(3000);
    await vi.waitFor(() => expect(last(h.states)).toBe("finished"));
    expect(h.seqs()).toEqual([1, 2, 3]);
    expect(h.states).toContain("reconnecting");
    const second = h.calls.filter((c) => c.url.includes("/events/stream"))[1];
    expect(second.headers.get("Last-Event-ID")).toBe("2");
    h.client.stop();
    vi.useRealTimers();
  });

  it("keeps a stream alive while pings arrive within the stall timeout", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"], shouldAdvanceTime: true });
    const enc = new TextEncoder();
    let ctrl: ReadableStreamDefaultController<Uint8Array> | null = null;
    const h = harness((url) => {
      if (!url.includes("/events/stream")) return json(page([ev(1)], { last_seq: 1 }));
      return new Response(new ReadableStream<Uint8Array>({ start(c) { ctrl = c; } }), { status: 200 });
    }, { stallTimeoutMs: 200 });
    h.client.start();
    for (let i = 0; i < 6; i++) {
      await vi.advanceTimersByTimeAsync(150);
      ctrl!.enqueue(enc.encode(": ping\n\n"));
    }
    expect(h.calls.filter((c) => c.url.includes("/events/stream"))).toHaveLength(1);
    expect(h.states).not.toContain("reconnecting");
    h.client.stop();
    vi.useRealTimers();
  });

  it("treats 401 as final: clears the token path, notifies, and stops retrying", async () => {
    const calls: string[] = [];
    let unauthorized = 0;
    const states: string[] = [];
    const client = new EventStreamClient({
      runId: "r1", getToken: () => "tok",
      fetchImpl: (async (url: string) => (calls.push(url), new Response("", { status: 401 }))) as unknown as typeof fetch,
      onEvents: () => {}, onState: (s) => states.push(s), onUnauthorized: () => unauthorized++,
    });
    client.start();
    await until(() => last(states) === "disconnected");
    expect(unauthorized).toBe(1);
    expect(calls).toHaveLength(1);
    client.stop();
  });

  it("treats 404 as final and exposes the ApiError status via state", async () => {
    const h = harness(() => new Response("", { status: 404, statusText: "Not Found" }));
    h.client.start();
    await until(() => last(h.states) === "disconnected");
    expect(h.calls).toHaveLength(1);
    expect(new ApiError(404, "x").status).toBe(404);
    h.client.stop();
  });

  it("loadOlder requests before_seq", async () => {
    const h = harness(() => json(page([ev(1), ev(2)], { has_more_before: false })));
    const p = await h.client.loadOlder(3, 200);
    expect(h.calls[0].url).toBe("/api/greybox/runs/r1/events?before_seq=3&limit=200");
    expect(p.items).toHaveLength(2);
  });
});
