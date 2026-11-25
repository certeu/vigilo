import { describe, expect, it } from "vitest";
import type { AssetEdge, AssetGraphResponse, AssetNode } from "../types";
import {
  assetVisual, AUTO_COLLAPSE_ENDPOINTS, clusterId, coverageFraction, coverageSummary, deriveNetworkView, EMPTY_ASSET_GRAPH, endpointPath,
  endpointSurface, expireAssetMarks, filterAssets, mergeAssetGraph, parentMap, pathPrefix, riskLevel, serviceSurface, type ViewOptions,
  displayService, hiddenStaticIds, isFoldedStatic, kindCounts, staticClusterId, staticGroups,
} from "./model";
import { layoutNetwork } from "./layout";

const node = (id: string, kind: AssetNode["kind"], o: Partial<AssetNode> = {}): AssetNode => ({
  id, kind, key: id, label: id, parent_id: null, state: "in_scope", in_scope: true, tested: false, finding_count: 0, data: {}, version: 1, ...o,
});
const edge = (src: string, dst: string, rel: AssetEdge["rel"], version = 1): AssetEdge => ({ id: `${src}>${rel}>${dst}`, src, dst, rel, version });
const resp = (o: Partial<AssetGraphResponse>): AssetGraphResponse => ({
  version: 1, since_version: 0, full: true, truncated: false, nodes: [], edges: [], coverage: null, ...o,
});
const OPTS: ViewOptions = { showSecondary: false, clusterOverrides: new Map(), expandedParams: new Set(), showDefenses: true };

describe("delta merge", () => {
  it("loads a snapshot without marking anything fresh, then marks new and changed assets from deltas", () => {
    const a = mergeAssetGraph(EMPTY_ASSET_GRAPH, resp({ version: 3, nodes: [node("h", "host"), node("s", "service", { parent_id: "h" })] }), 1000);
    expect(a.state.loaded).toBe(true);
    expect(a.state.fresh.size).toBe(0);
    const b = mergeAssetGraph(
      a.state,
      resp({ version: 5, since_version: 3, full: false, nodes: [node("e", "endpoint", { parent_id: "s", version: 5 }), node("s", "service", { parent_id: "h", tested: true, version: 4 })] }),
      2000,
    );
    expect(b.state.nodes.size).toBe(3);
    expect(b.state.fresh.get("e")).toBe(2000);
    expect(b.state.changed.get("s")).toBe(2000);
    expect(b.state.version).toBe(5);
  });
  it("is an upsert: an older copy never overwrites a newer one, and stale responses are ignored", () => {
    const a = mergeAssetGraph(EMPTY_ASSET_GRAPH, resp({ version: 9, nodes: [node("e", "endpoint", { version: 9, tested: true })] }), 0).state;
    const stale = mergeAssetGraph(a, resp({ version: 4, full: false, nodes: [node("e", "endpoint", { version: 4, tested: false })] }), 1);
    expect(stale.state).toBe(a);
    const mixed = mergeAssetGraph(a, resp({ version: 10, full: false, nodes: [node("e", "endpoint", { version: 2 })] }), 1).state;
    expect(mixed.nodes.get("e")!.tested).toBe(true);
  });
  it("flags a changed surface, keeps the latest coverage and expires marks", () => {
    const first = mergeAssetGraph(EMPTY_ASSET_GRAPH, resp({ nodes: [node("s", "service", { data: { surface: { risk_score: 10 } } })], coverage: { in_scope_endpoints: 4, tested_endpoints: 1 } }), 0).state;
    const next = mergeAssetGraph(first, resp({ version: 2, full: false, nodes: [node("s", "service", { version: 2, data: { surface: { risk_score: 40 } } })] }), 100).state;
    expect(next.changed.has("s")).toBe(true);
    expect(next.coverage).toEqual({ in_scope_endpoints: 4, tested_endpoints: 1 });
    expect(expireAssetMarks(next, 100 + 6000, 6000).changed.size).toBe(0);
    expect(expireAssetMarks(next, 200, 6000)).toBe(next);
  });
  it("a full re-sync replaces the set unless the server truncated", () => {
    const a = mergeAssetGraph(EMPTY_ASSET_GRAPH, resp({ nodes: [node("x", "host"), node("y", "host")] }), 0).state;
    expect(mergeAssetGraph(a, resp({ version: 2, nodes: [node("x", "host", { version: 2 })] }), 1).state.nodes.size).toBe(1);
    expect(mergeAssetGraph(a, resp({ version: 2, truncated: true, truncated_by_kind: { endpoint: 3 }, nodes: [node("x", "host", { version: 2 })] }), 1).state.nodes.size).toBe(2);
  });
});

describe("coverage maths", () => {
  it("is tested over in-scope, clamped, and null with nothing in scope", () => {
    expect(coverageFraction(0, 0)).toBeNull();
    expect(coverageFraction(8, 2)).toBe(0.25);
    expect(coverageFraction(2, 5)).toBe(1);
  });
  it("prefers the server's numbers, else counts in-scope endpoints locally", () => {
    const nodes = new Map([
      ["e1", node("e1", "endpoint", { tested: true })],
      ["e2", node("e2", "endpoint")],
      ["e3", node("e3", "endpoint", { in_scope: false, tested: true })],
      ["s", node("s", "service", { tested: true })],
    ]);
    const local = coverageSummary({ coverage: null, nodes });
    expect([local.inScope, local.tested, local.percent, local.source]).toEqual([2, 1, 50, "local"]);
    const server = coverageSummary({ coverage: { in_scope_endpoints: 10, tested_endpoints: 3, definition: "D" }, nodes });
    expect([server.inScope, server.tested, server.percent, server.definition, server.source]).toEqual([10, 3, 30, "D", "server"]);
    expect(coverageSummary({ coverage: null, nodes: new Map() }).percent).toBeNull();
  });
});

describe("asset visual state", () => {
  it("out of scope beats everything; findings beat tested beats in scope", () => {
    expect(assetVisual({ in_scope: false, tested: true, finding_count: 2 })).toBe("out_of_scope");
    expect(assetVisual({ in_scope: true, tested: true, finding_count: 2 })).toBe("finding");
    expect(assetVisual({ in_scope: true, tested: true, finding_count: 0 })).toBe("tested");
    expect(assetVisual({ in_scope: true, tested: false, finding_count: 0 })).toBe("in_scope");
  });
});

describe("surface mapping", () => {
  const data = {
    surface: {
      server: "nginx/1.18.0",
      technologies: ["PHP 7.4"],
      security_headers: { present: ["x-frame-options"], missing: ["content-security-policy", "referrer-policy", "x-content-type-options"] },
      cookie_flags: { sid: { secure: false, httponly: true, samesite: null }, ok: { secure: true, httponly: true, samesite: "lax" } },
      cors: { reflects_origin: true, allows_credentials: true },
      redirects: { count: 3, external_blocked: 1 },
      tls: { https: true, hsts: false },
      endpoints: { total: 20, tested: 12, with_findings: 2, auth_like: 1, sensitive: 3 },
      sensitive_paths: [{ path: "/.git/config", reason: "git repository", served: true }],
      risk_score: 72,
      risk_factors: [{ id: "cors", points: 20, detail: "origin reflected with credentials" }],
    },
  };
  it("maps every block and the risk level", () => {
    const s = serviceSurface(data)!;
    expect(s.headers).toMatchObject({ presentCount: 1, missingCount: 3, total: 4, ratio: 0.25 });
    expect(s.cookies.map((c) => [c.name, c.issues])).toEqual([["sid", ["no Secure flag", "no SameSite"]], ["ok", []]]);
    expect(s.cors).toMatchObject({ risky: true });
    expect(s.tls).toBe("HTTPS, HSTS missing");
    expect(s.endpoints).toEqual({ total: 20, static: 0, tested: 12, withFindings: 2, authLike: 1, sensitive: 3 });
    expect([s.riskScore, s.riskLevel]).toEqual([72, "high"]);
    expect(s.sensitivePaths[0].path).toBe("/.git/config");
  });
  it("explains the score from the API's factors, else from the signals", () => {
    expect(serviceSurface(data)!.explanation).toEqual(["origin reflected with credentials (+20)"]);
    const noFactors = serviceSurface({ surface: { ...data.surface, risk_factors: undefined } })!;
    expect(noFactors.explanation.some((x) => x.includes("3 of 4 security headers missing"))).toBe(true);
    expect(noFactors.explanation.some((x) => x.includes("CORS reflects"))).toBe(true);
  });
  it("ignores the Secure flag on plain http and tolerates absent or partial surfaces", () => {
    const http = serviceSurface({ surface: { tls: { https: false }, cookie_flags: { a: { secure: false, httponly: true, samesite: "lax" } } } })!;
    expect(http.cookies[0].issues).toEqual([]);
    expect(http.explanation).toContain("The service is plain http (no TLS)");
    expect(serviceSurface({})).toBeNull();
    expect(serviceSurface({ surface: {} })!.riskScore).toBeNull();
    expect(riskLevel(10)).toBe("low");
    expect(riskLevel(50)).toBe("medium");
    expect(riskLevel(null)).toBeNull();
  });
  it("maps endpoint surfaces (sensitive is a reason string)", () => {
    expect(endpointSurface({ surface: { status_codes: [200, 404], content_types: ["text/html"], methods: ["GET"], has_form: true, password_form: true, params: 2, sensitive: "git repository" } })).toEqual({
      statusCodes: ["200", "404"], contentTypes: ["text/html"], methods: ["GET"], hasForm: true, passwordForm: true, params: 2, sensitive: "git repository", size: null,
    });
    expect(endpointSurface({ surface: { sensitive: null } })!.sensitive).toBeNull();
  });
});

describe("paths and clusters", () => {
  it("extracts paths from urls, labels with methods and keys", () => {
    expect(endpointPath(node("x", "endpoint", { label: "GET /api/users?id=1" }))).toBe("/api/users");
    expect(endpointPath(node("x", "endpoint", { label: "?", key: "https://h.example:443/static/app.js" }))).toBe("/static/app.js");
    expect(endpointPath(node("x", "endpoint", { label: "/", key: "https://h:80/" }))).toBe("/");
    expect(pathPrefix("/api/v1/users")).toBe("/api");
    expect(pathPrefix("/")).toBe("/");
  });
});

function tree(nEndpoints: number, prefix = "/api") {
  const nodes: AssetNode[] = [node("h", "host", { version: 1 }), node("s", "service", { parent_id: "h", version: 2 })];
  for (let i = 0; i < nEndpoints; i++) {
    const id = `e${i}`;
    nodes.push(node(id, "endpoint", { parent_id: "s", label: `GET ${prefix}/r${i}`, version: 10 + i, tested: i % 2 === 0, finding_count: i === 1 ? 1 : 0 }));
  }
  return { nodes: new Map(nodes.map((n) => [n.id, n])), edges: new Map<string, AssetEdge>() };
}

describe("derived view", () => {
  it("builds host > service > endpoints with parent links (parent_id or contains edges)", () => {
    const g = tree(2, "/x");
    const e = new Map([[`c`, edge("s", "e0", "contains")]]);
    const p = parentMap({ nodes: new Map([...g.nodes, ["orphan", node("orphan", "endpoint")]]), edges: e });
    expect(p.get("e0")).toBe("s");
    expect(p.has("orphan")).toBe(false);
    const v = deriveNetworkView(g, OPTS);
    expect(v.nodes.map((n) => n.kind)).toEqual(["host", "service", "endpoint", "endpoint"]);
  });
  it("groups 4+ endpoints sharing a prefix into a cluster, expanded while the map is small", () => {
    const v = deriveNetworkView(tree(6), OPTS);
    const c = v.nodes.find((n) => n.kind === "cluster")!;
    expect(c.cluster).toMatchObject({ prefix: "/api", total: 6, tested: 3, findings: 1, expanded: true });
    expect(v.nodes.filter((n) => n.kind === "endpoint")).toHaveLength(6);
    expect(deriveNetworkView(tree(3), OPTS).nodes.some((n) => n.kind === "cluster")).toBe(false);
  });
  it("collapses clusters by default above the threshold and the override / reveal expands them", () => {
    const g = tree(AUTO_COLLAPSE_ENDPOINTS + 5);
    const v = deriveNetworkView(g, OPTS);
    expect(v.nodes.filter((n) => n.kind === "endpoint")).toHaveLength(0);
    expect(v.hiddenEndpoints).toBe(AUTO_COLLAPSE_ENDPOINTS + 5);
    const cid = clusterId("s", "/api");
    expect(deriveNetworkView(g, { ...OPTS, clusterOverrides: new Map([[cid, true]]) }).nodes.filter((n) => n.kind === "endpoint")).toHaveLength(AUTO_COLLAPSE_ENDPOINTS + 5);
    expect(deriveNetworkView(g, { ...OPTS, reveal: new Set(["e3"]) }).nodes.some((n) => n.id === "e3")).toBe(true);
    expect(deriveNetworkView(tree(6), { ...OPTS, clusterOverrides: new Map([[cid, false]]) }).nodes.some((n) => n.id === "e1")).toBe(false);
  });
  it("hides parameters until expanded, with a count", () => {
    const g = tree(1, "/x");
    g.nodes.set("p1", node("p1", "parameter", { parent_id: "e0" }));
    g.nodes.set("p2", node("p2", "parameter", { parent_id: "e0" }));
    const collapsed = deriveNetworkView(g, OPTS);
    expect(collapsed.nodes.some((n) => n.kind === "parameter")).toBe(false);
    expect(collapsed.nodes.find((n) => n.id === "e0")!.params).toEqual({ count: 2, expanded: false });
    const open = deriveNetworkView(g, { ...OPTS, expandedParams: new Set(["e0"]) });
    expect(open.nodes.filter((n) => n.kind === "parameter")).toHaveLength(2);
    expect(open.edges.some((e) => e.rel === "has_param")).toBe(true);
  });
  it("draws links_to / redirects_to only when asked, re-routed to the cluster when an endpoint is folded", () => {
    const g = tree(AUTO_COLLAPSE_ENDPOINTS + 1);
    g.nodes.set("e-root", node("e-root", "endpoint", { parent_id: "s", label: "GET /", version: 5 }));
    g.edges.set("l", edge("e-root", "e7", "links_to"));
    expect(deriveNetworkView(g, OPTS).edges.some((e) => e.secondary)).toBe(false);
    const v = deriveNetworkView(g, { ...OPTS, showSecondary: true });
    const sec = v.edges.filter((e) => e.secondary);
    expect(sec).toHaveLength(1);
    expect(sec[0].dst).toBe(clusterId("s", "/api"));
  });
  it("attaches defenses through protects edges, also to a folded endpoint's cluster", () => {
    const g = tree(AUTO_COLLAPSE_ENDPOINTS + 1);
    g.nodes.set("d1", node("d1", "defense", { label: "Add CSP" }));
    g.nodes.set("d2", node("d2", "defense", { label: "Block .git" }));
    g.edges.set("p1", edge("d1", "s", "protects"));
    g.edges.set("p2", edge("d2", "e3", "protects"));
    const v = deriveNetworkView(g, OPTS);
    expect(v.nodes.filter((n) => n.kind === "defense").map((n) => [n.id, n.protects])).toEqual([["d1", "s"], ["d2", clusterId("s", "/api")]]);
    expect(deriveNetworkView(g, { ...OPTS, showDefenses: false }).nodes.some((n) => n.kind === "defense")).toBe(false);
  });
});

describe("layout", () => {
  const big = () => deriveNetworkView(tree(12), OPTS);
  it("places columns left to right and never overlaps cards", () => {
    const g = tree(12);
    g.nodes.set("p1", node("p1", "parameter", { parent_id: "e0" }));
    g.nodes.set("d1", node("d1", "defense"));
    g.nodes.set("d2", node("d2", "defense"));
    g.edges.set("a", edge("d1", "s", "protects"));
    g.edges.set("b", edge("d2", "e2", "protects"));
    const v = deriveNetworkView(g, { ...OPTS, expandedParams: new Set(["e0"]) });
    const { rects } = layoutNetwork(v);
    expect(rects.size).toBe(v.nodes.length);
    expect(rects.get("h")!.x).toBeLessThan(rects.get("s")!.x);
    expect(rects.get("s")!.x).toBeLessThan(rects.get("e0")!.x);
    expect(rects.get("e0")!.x).toBeLessThan(rects.get("p1")!.x);
    const list = [...rects.entries()];
    for (let i = 0; i < list.length; i++) {
      for (let j = i + 1; j < list.length; j++) {
        const [, a] = list[i];
        const [, b] = list[j];
        const overlap = a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
        expect(overlap, `${list[i][0]} vs ${list[j][0]}`).toBe(false);
      }
    }
  });
  it("is stable: a newly discovered endpoint leaves every earlier card where it was", () => {
    const before = layoutNetwork(big()).rects;
    const g = tree(12);
    g.nodes.set("late", node("late", "endpoint", { parent_id: "s", label: "GET /api/zzz", version: 999 }));
    g.nodes.set("h2", node("h2", "host", { version: 1000 }));
    const after = layoutNetwork(deriveNetworkView(g, OPTS)).rects;
    for (const [id, r] of before) expect(after.get(id), id).toEqual(r);
  });
  it("keeps a 250-endpoint map compact when clusters are collapsed", () => {
    const g = tree(250);
    const collapsed = layoutNetwork(deriveNetworkView(g, OPTS));
    const open = layoutNetwork(deriveNetworkView(g, { ...OPTS, clusterOverrides: new Map([[clusterId("s", "/api"), true]]) }));
    expect(collapsed.rects.size).toBeLessThan(5);
    expect(open.height).toBeGreaterThan(collapsed.height * 10);
  });
});

describe("table filters", () => {
  const nodes = [
    node("h", "host", { label: "10.0.0.1" }),
    node("e1", "endpoint", { label: "GET /login", tested: true, finding_count: 1 }),
    node("e2", "endpoint", { label: "GET /about" }),
    node("e3", "endpoint", { label: "GET /ext", in_scope: false }),
  ];
  it("filters by kind, state and text, most findings first", () => {
    const f = (o: Partial<Parameters<typeof filterAssets>[1]>) => filterAssets(nodes, { kind: "all", state: "all", query: "", ...o }).map((n) => n.id);
    expect(f({})).toEqual(["h", "e1", "e2", "e3"]);
    expect(f({ kind: "endpoint", state: "finding" })).toEqual(["e1"]);
    expect(f({ state: "untested" })).toEqual(["h", "e2"]);
    expect(f({ state: "out_of_scope" })).toEqual(["e3"]);
    expect(f({ query: "ABOUT" })).toEqual(["e2"]);
  });
});


describe("static assets are folded", () => {
  function nextApp(nStatic = 30) {
    const nodes: AssetNode[] = [node("h", "host"), node("s", "service", { parent_id: "h" })];
    nodes.push(node("home", "endpoint", { parent_id: "s", key: "https://t:443/", label: "/", tested: true }));
    nodes.push(node("nb", "endpoint", { parent_id: "s", key: "https://t:443/notebooks", label: "/notebooks" }));
    for (let i = 0; i < nStatic; i++) {
      nodes.push(node(`c${i}`, "endpoint", { parent_id: "s", key: `https://t:443/_next/static/chunks/${i}.js`, label: `/_next/static/chunks/${i}.js`, data: { surface: { size: 1000 } } }));
    }
    nodes.push(node("fav", "endpoint", { parent_id: "s", key: "https://t:443/favicon.ico", label: "/favicon.ico" }));
    nodes.push(node("favq", "parameter", { parent_id: "fav", label: "favicon.0b3bf435.ico (query)" }));
    return { nodes: new Map(nodes.map((n) => [n.id, n])), edges: new Map<string, AssetEdge>() };
  }
  it("recognises folded statics but keeps out-of-scope ones and ones with findings visible", () => {
    expect(isFoldedStatic(node("a", "endpoint", { label: "/_next/static/a.js" }))).toBe(true);
    expect(isFoldedStatic(node("a", "endpoint", { label: "/_next/static/a.js", finding_count: 1 }))).toBe(false);
    expect(isFoldedStatic(node("a", "endpoint", { label: "/_next/static/a.js", in_scope: false }))).toBe(false);
    expect(isFoldedStatic(node("a", "endpoint", { label: "/notebooks" }))).toBe(false);
    expect(isFoldedStatic(node("a", "endpoint", { label: "/x", data: { surface: { class: "static" } } }))).toBe(true);
  });
  it("aggregates them into one collapsed group per prefix with the total size", () => {
    const v = deriveNetworkView(nextApp(), OPTS);
    const groups = v.nodes.filter((n) => n.kind === "cluster");
    expect(groups.map((g) => [g.id, g.cluster!.prefix, g.cluster!.total, g.cluster!.bytes, g.cluster!.expanded])).toEqual([
      [staticClusterId("s", "/_next/static"), "/_next/static", 30, 30000, false],
      [staticClusterId("s", "/"), "/", 1, null, false],
    ]);
    expect(v.nodes.filter((n) => n.kind === "endpoint").map((n) => n.id)).toEqual(["home", "nb"]);
    expect(v.nodes.some((n) => n.kind === "parameter")).toBe(false);
    expect(v.endpointCount).toBe(2);
    expect(v.hiddenEndpoints).toBe(31);
  });
  it("does not collapse the page clusters just because the build output is large", () => {
    expect(deriveNetworkView(nextApp(300), OPTS).endpointCount).toBeLessThan(AUTO_COLLAPSE_ENDPOINTS);
  });
  it("expands with showStatic or a per-group override, and a selected asset reveals its group", () => {
    const g = nextApp();
    const all = deriveNetworkView(g, { ...OPTS, showStatic: true });
    expect(all.nodes.filter((n) => n.kind === "endpoint")).toHaveLength(33);
    const one = deriveNetworkView(g, { ...OPTS, clusterOverrides: new Map([[staticClusterId("s", "/"), true]]) });
    expect(one.nodes.filter((n) => n.kind === "endpoint").map((n) => n.id)).toContain("fav");
    expect(one.nodes.filter((n) => n.kind === "endpoint")).toHaveLength(3);
    const rev = deriveNetworkView(g, { ...OPTS, reveal: new Set(["c3"]) });
    expect(rev.nodes.filter((n) => n.kind === "endpoint")).toHaveLength(32);
  });
  it("attaches a defense of a hidden static asset to its group", () => {
    const g = nextApp();
    g.nodes.set("d", node("d", "defense", { parent_id: null }));
    g.edges.set("p", edge("d", "c1", "protects"));
    const v = deriveNetworkView(g, OPTS);
    expect(v.nodes.find((n) => n.id === "d")!.protects).toBe(staticClusterId("s", "/_next/static"));
  });
  it("counts and coverage leave statics out; the table hides them unless asked", () => {
    const g = nextApp();
    const c = kindCounts(g.nodes.values());
    expect([c.endpoint, c.staticAssets, c.parameter]).toEqual([2, 31, 0]);
    expect(coverageSummary({ coverage: null, nodes: g.nodes })).toMatchObject({ inScope: 2, tested: 1 });
    expect(filterAssets(g.nodes.values(), NO_FILTERS).filter((n) => n.kind === "endpoint")).toHaveLength(2);
    expect(filterAssets(g.nodes.values(), { ...NO_FILTERS, showStatic: true }).filter((n) => n.kind === "endpoint")).toHaveLength(33);
    expect(hiddenStaticIds(g.nodes.values()).has("favq")).toBe(true);
    expect(staticGroups(g.nodes.values())).toEqual([{ prefix: "/_next/static", files: 30, bytes: 30000 }, { prefix: "/", files: 1, bytes: null }]);
  });
  it("shows a service without its default port", () => {
    expect(displayService("https://a.b:443")).toBe("https://a.b");
    expect(displayService("http://a.b:80")).toBe("http://a.b");
    expect(displayService("https://a.b:8443")).toBe("https://a.b:8443");
  });
});
const NO_FILTERS = { kind: "all", state: "all", query: "" } as const;
