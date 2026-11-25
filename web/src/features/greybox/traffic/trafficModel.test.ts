import { describe, expect, it } from "vitest";
import type { Exchange, ExchangeSummary } from "../types";
import {
  blockSentence, buildCurl, clientFilter, foldStatic, foldSummary, isFoldedStaticExchange, DEFAULT_TRAFFIC_FILTERS, eventExchangeId, filtersFromParams, filtersToQuery,
  hostPort, isRedacted, mergeRows, parseExchangeParam, prettyJson, serverKey, statusClass, statusColor,
} from "./trafficModel";

const row = (id: number, o: Partial<ExchangeSummary> = {}): ExchangeSummary => ({
  id, ts: "2026-01-01T00:00:00Z", method: "GET", scheme: "https", host: "a.test", port: 443, path: "/", status_code: 200,
  duration_ms: 5, content_type: null, response_size: 1, tool: "http_probe", agent_id: null, agent_name: null, work_order_id: null,
  blocked: false, block_reason: null, error: null, redirect_hop: 0, finding_ids: [], ...o,
});

describe("filters", () => {
  it("builds the query from server-side filters only", () => {
    const q = filtersToQuery({ ...DEFAULT_TRAFFIC_FILTERS, method: "POST", host: " A.Test ", pathPrefix: "/api", blockedOnly: true, statusClass: "4xx", hasFindings: true, findingId: "f1" }, { limit: 500, after_id: 7 });
    expect(q).toEqual({ method: "POST", host: "a.test", path_prefix: "/api", blocked: true, finding_id: "f1", limit: 200, after_id: 7 });
  });
  it("client-only filters do not change the server key", () => {
    expect(serverKey({ ...DEFAULT_TRAFFIC_FILTERS, statusClass: "5xx" })).toBe(serverKey(DEFAULT_TRAFFIC_FILTERS));
  });
  it("filters by status class and findings client-side", () => {
    const rows = [row(1), row(2, { status_code: 404 }), row(3, { status_code: null }), row(4, { finding_ids: ["x"] })];
    expect(clientFilter(rows, { ...DEFAULT_TRAFFIC_FILTERS, statusClass: "4xx" }).map((r) => r.id)).toEqual([2]);
    expect(clientFilter(rows, { ...DEFAULT_TRAFFIC_FILTERS, statusClass: "none" }).map((r) => r.id)).toEqual([3]);
    expect(clientFilter(rows, { ...DEFAULT_TRAFFIC_FILTERS, hasFindings: true }).map((r) => r.id)).toEqual([4]);
  });
  it("reads work order and finding from URL params", () => {
    const f = filtersFromParams(new URLSearchParams("tab=traffic&work_order=w1&finding=f2"));
    expect(f.workOrderId).toBe("w1");
    expect(f.findingId).toBe("f2");
    expect(parseExchangeParam("12")).toBe(12);
    expect(parseExchangeParam("1e3")).toBeNull();
  });
});

describe("status", () => {
  it("classifies and colours", () => {
    expect(statusClass(204)).toBe("2xx");
    expect(statusClass(302)).toBe("3xx");
    expect(statusClass(503)).toBe("5xx");
    expect(statusClass(null)).toBe("none");
    expect(statusColor(200)).toContain("emerald");
    expect(statusColor(500)).toContain("critical");
    expect(statusColor(null)).toContain("slate");
  });
  it("formats host:port without default ports", () => {
    expect(hostPort(row(1))).toBe("a.test");
    expect(hostPort(row(1, { port: 8443 }))).toBe("a.test:8443");
    expect(hostPort(row(1, { host: null }))).toBe("—");
  });
});

describe("mergeRows", () => {
  it("dedupes by id and keeps ascending order", () => {
    const a = [row(1), row(2)];
    expect(mergeRows(a, [row(2), row(3)]).map((r) => r.id)).toEqual([1, 2, 3]);
    expect(mergeRows(a, [row(2)])).toBe(a);
    expect(mergeRows(a, [row(5), row(4)]).map((r) => r.id)).toEqual([1, 2, 4, 5]);
  });
  it("reads the exchange id of live events", () => {
    expect(eventExchangeId({ data: { exchange_id: 9 } })).toBe(9);
    expect(eventExchangeId({ data: {}, refs: { exchange_ids: [4] } })).toBe(4);
    expect(eventExchangeId({ data: {} })).toBeNull();
  });
});

describe("reason sentences", () => {
  it("reuses scope sentences and explains ip denials", () => {
    expect(blockSentence("host_not_allowed")).toBe("Blocked by scope policy: that host is outside the authorised scope");
    expect(blockSentence("ip_denied:loopback")).toContain("loopback");
    expect(blockSentence(null)).toMatch(/^Blocked by scope policy: /);
  });
});

describe("curl", () => {
  const x: Pick<Exchange, "method" | "url" | "request"> = {
    method: "POST", url: "https://a.test/x?token=***&q=it's",
    request: { headers: [["Cookie", "sid=***"], ["Host", "a.test"], ["Content-Type", "application/json"]], body: '{"pw":"***"}', body_truncated: false, body_omitted_reason: null },
  };
  it("keeps redaction as placeholders and says so", () => {
    const c = buildCurl(x);
    expect(c).toContain("<REDACTED>");
    expect(c).not.toContain("***");
    expect(c).toContain("# Redacted values are kept");
    expect(c).toContain("-H 'Cookie: sid=<REDACTED>'");
    expect(c).not.toContain("Host:");
    expect(c).toContain(`'\\''`); // single quote escaped
  });
  it("detects redaction and pretty-prints only valid JSON", () => {
    expect(isRedacted("Bearer ***")).toBe(true);
    expect(prettyJson('{"a":1}')).toBe('{\n  "a": 1\n}');
    expect(prettyJson('{"a":')).toBeNull();
  });
});


describe("static asset folding", () => {
  const chunk = (id: number, o: Partial<ExchangeSummary> = {}) => row(id, { path: `/_next/static/chunks/${id}.js`, content_type: "application/javascript", response_size: 1000, ...o });
  const rows = [
    row(1, { path: "/", content_type: "text/html" }),
    chunk(2), chunk(3),
    row(4, { path: "/api/notebooks", content_type: "application/json" }),
    chunk(5),
    row(6, { path: "/_next/static/media/f.woff2", content_type: "font/woff2", response_size: 500 }),
    row(7, { path: "/favicon.ico", content_type: "image/x-icon" }),
    row(8, { host: "cdn.thirdparty.test", port: null, scheme: "https", path: "/_next/static/chunks/x.js" }),
  ];
  const none = new Set<string>();
  it("folds into one group per host and prefix, placed at the first member, with count and size", () => {
    const items = foldStatic(rows, { showStatic: false, expanded: none });
    expect(items.map((i) => (i.type === "group" ? `G:${i.label}` : `x${i.x.id}`))).toEqual([
      "x1",
      "G:a.test/_next/static — 4 files, 3.4 KB",
      "x4",
      "G:a.test/ (root files) — 1 file, 1 B",
      "G:cdn.thirdparty.test/_next/static — 1 file, 1 B",
    ]);
    expect(foldSummary(items)).toEqual({ files: 6, groups: 3 });
  });
  it("shows everything flat with showStatic, and members under an expanded group", () => {
    expect(foldStatic(rows, { showStatic: true, expanded: none })).toHaveLength(rows.length);
    const open = foldStatic(rows, { showStatic: false, expanded: new Set(["a.test|/_next/static"]) });
    expect(open.filter((i) => i.type === "exchange" && i.nested).map((i) => (i as { x: ExchangeSummary }).x.id)).toEqual([2, 3, 5, 6]);
    expect(foldSummary(open)).toEqual({ files: 2, groups: 2 });
  });
  it("reveals the group of the open exchange", () => {
    const items = foldStatic(rows, { showStatic: false, expanded: none, reveal: 3 });
    expect(items.filter((i) => i.type === "exchange" && i.nested)).toHaveLength(4);
  });
  it("never folds blocked, failed, 4xx/5xx, no-response or finding-linked requests", () => {
    for (const o of [{ blocked: true }, { error: "timeout" }, { status_code: 404 }, { status_code: 500 }, { status_code: null }, { finding_ids: ["f"] }]) {
      expect(isFoldedStaticExchange(chunk(9, o))).toBe(false);
    }
    expect(isFoldedStaticExchange(chunk(9, { status_code: 304 }))).toBe(true);
    expect(isFoldedStaticExchange(row(9, { path: "/login", content_type: "text/html" }))).toBe(false);
  });
});
