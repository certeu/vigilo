import { describe, expect, it } from "vitest";
import { CATEGORY_STYLE, KIND_STYLE, REL_STYLE, statusCategory } from "../graph/encoding";
import { FEEDBACK_RELS } from "../graph/model";
import { incrementalLayout, layeredLayout, NODE_W } from "../graph/layout";
import { EDGE_RELS, NODE_KINDS, STATUSES_BY_KIND } from "../graph/types";
import { buildStoryRun } from "../graph/dev/syntheticRun";
import type { Defense } from "../types";
import { availableDownloads, unverifiedCount, defensesEmptyState, filterDefenses, groupByFinding, groupByService, isAssetScoped, owningServiceId, shouldRefreshDefenses, type AssetMeta, type FindingMeta } from "./defensesModel";

const def = (o: Partial<Defense> = {}): Defense => ({
  id: "d1", run_id: "r", finding_id: "f1", node_id: null, kind: "waf_rule", format: "modsecurity", title: "t", rationale: "",
  content: "SecRule", confidence: null, status: "proposed", created_at: "2026-01-01T00:00:00Z", ...o,
});

describe("grouping and filters", () => {
  const items = [
    def({ id: "a", finding_id: "f-low", format: "nginx", kind: "config" }),
    def({ id: "b", finding_id: "f-high" }),
    def({ id: "c", finding_id: "f-high", format: "sigma", kind: "detection_rule" }),
    def({ id: "d", finding_id: "f-unknown" }),
  ];
  const meta = new Map<string, FindingMeta>([
    ["f-low", { title: "Headers", severity: "low" }],
    ["f-high", { title: "XSS", severity: "high" }],
  ]);
  it("groups by finding, most severe first, unknown findings last with a short id", () => {
    const g = groupByFinding(items, meta);
    expect(g.map((x) => x.findingId)).toEqual(["f-high", "f-low", "f-unknown"]);
    expect(g[0].defenses.map((x) => x.id)).toEqual(["c", "b"]); // detection_rule < waf_rule
    expect(g[2].title).toBe("Finding f-unknown");
    expect(g[2].severity).toBeNull();
  });
  it("filters by finding, kind and format together", () => {
    expect(filterDefenses(items, {}).length).toBe(4);
    expect(filterDefenses(items, { finding: "f-high" }).map((x) => x.id)).toEqual(["b", "c"]);
    expect(filterDefenses(items, { kind: "config" }).map((x) => x.id)).toEqual(["a"]);
    expect(filterDefenses(items, { finding: "f-high", format: "sigma" }).map((x) => x.id)).toEqual(["c"]);
  });
  it("offers downloads only for formats present, plus all", () => {
    expect(availableDownloads(items)).toEqual(["modsecurity", "sigma", "nginx", "all"]);
    expect(availableDownloads([])).toEqual([]);
    expect(availableDownloads([def({ format: "text" })])).toEqual(["all"]);
  });

  it("offers downloads only for what the server returns: unverified rules need an explicit opt-in", () => {
    // The download endpoint excludes rules of unverified findings unless
    // include_unverified=true; a button for them would 404.
    const onlyUnverified = [def({ format: "nginx", status: "unverified" }), def({ format: "sigma", status: "unverified" })];
    expect(availableDownloads(onlyUnverified)).toEqual([]);
    expect(availableDownloads(onlyUnverified, true)).toEqual(["sigma", "nginx", "all"]);
    expect(unverifiedCount(onlyUnverified)).toBe(2);

    const mixed = [def({ format: "nginx" }), def({ format: "sigma", status: "unverified" })];
    expect(availableDownloads(mixed)).toEqual(["nginx", "all"]);
    expect(availableDownloads(mixed, true)).toEqual(["sigma", "nginx", "all"]);
  });
});

describe("empty state selection", () => {
  const o = { total: 0, shown: 0, findingCount: 2 };
  it("explains active, failed, no-findings, none-generated and filtered", () => {
    expect(defensesEmptyState({ ...o, runStatus: "running" })).toBe("active");
    expect(defensesEmptyState({ ...o, runStatus: "cancelling" })).toBe("active");
    expect(defensesEmptyState({ ...o, runStatus: "failed" })).toBe("failed");
    expect(defensesEmptyState({ ...o, runStatus: "cancelled" })).toBe("failed");
    expect(defensesEmptyState({ ...o, runStatus: "succeeded", findingCount: 0 })).toBe("no_findings");
    expect(defensesEmptyState({ ...o, runStatus: "succeeded" })).toBe("none_generated");
    expect(defensesEmptyState({ ...o, runStatus: "succeeded", total: 3 })).toBe("filtered");
    expect(defensesEmptyState({ ...o, runStatus: "succeeded", total: 3, shown: 1 })).toBeNull();
  });
  it("refreshes only after the run is terminal, on defense.* and report.ready", () => {
    expect(shouldRefreshDefenses("running", "defense.proposed")).toBe(false);
    expect(shouldRefreshDefenses(null, "report.ready")).toBe(false);
    expect(shouldRefreshDefenses("succeeded", "defense.proposed")).toBe(true);
    expect(shouldRefreshDefenses("succeeded", "report.ready")).toBe(true);
    expect(shouldRefreshDefenses("succeeded", "hint.added")).toBe(false);
  });
});

describe("defense graph vocabulary", () => {
  it("has a kind style, scoped statuses and the mitigates rel", () => {
    expect(NODE_KINDS).toContain("defense");
    expect(KIND_STYLE.defense.tile).toContain("teal");
    expect(STATUSES_BY_KIND.defense).toEqual(["proposed", "unverified"]);
    expect(EDGE_RELS).toContain("mitigates");
    expect(REL_STYLE.mitigates.dash).toBeUndefined();
    expect(FEEDBACK_RELS.has("mitigates")).toBe(true);
  });
  it("styles unverified defenses as muted and dashed", () => {
    expect(statusCategory("defense", "proposed")).toBe("defense_proposed");
    expect(statusCategory("defense", "unverified")).toBe("defense_unverified");
    expect(CATEGORY_STYLE.defense_unverified.border).toContain("dashed");
    expect(CATEGORY_STYLE.defense_proposed.border).not.toContain("dashed");
  });
  it("lays a defense out to the right of its finding", () => {
    const edges = [{ src: "d", dst: "f", rel: "mitigates" as const }, { src: "o", dst: "f", rel: "supports" as const }];
    const full = layeredLayout(["o", "f", "d"], edges);
    expect(full.get("d")!.x).toBeGreaterThan(full.get("f")!.x);
    const inc = incrementalLayout(["o", "f", "d"], edges, new Map([["o", { x: 0, y: 0 }], ["f", { x: 296, y: 0 }]]));
    expect(inc.get("d")!.x).toBeGreaterThanOrEqual(296 + NODE_W);
  });
  it("the synthetic story includes defenses linked to findings", () => {
    const run = buildStoryRun();
    const g = run.respond(run.v, 0, 5000);
    expect(g.nodes.filter((n) => n.kind === "defense").length).toBeGreaterThan(0);
    for (const e of g.edges.filter((x) => x.rel === "mitigates")) {
      expect(g.nodes.find((n) => n.id === e.dst)?.kind).toBe("finding");
    }
  });
});

describe("network-wide (asset-scoped) defenses", () => {
  const assets = new Map<string, AssetMeta>([
    ["h", { label: "10.0.0.5", kind: "host", parent_id: null }],
    ["s1", { label: "https://a.example:443", kind: "service", parent_id: "h" }],
    ["s2", { label: "http://b.example:80", kind: "service", parent_id: "h" }],
    ["e1", { label: "/login", kind: "endpoint", parent_id: "s1" }],
    ["p1", { label: "user (query)", kind: "parameter", parent_id: "e1" }],
  ]);
  const net = (o: Partial<Defense>) => def({ finding_id: null, scope: "asset", ...o });
  const items = [
    def({ id: "f1", finding_id: "fx" }),
    net({ id: "n1", asset_id: "s1", title: "B header" }),
    net({ id: "n2", asset_id: "e1", title: "A cookie", kind: "config", format: "nginx" }),
    net({ id: "n3", asset_id: "s2" }),
    net({ id: "n4", asset_id: "ghost" }),
    net({ id: "n5", asset_id: null }),
  ];

  it("classifies by scope, tolerating servers without the field", () => {
    expect(isAssetScoped(items[0])).toBe(false);
    expect(isAssetScoped(items[1])).toBe(true);
    expect(isAssetScoped(def({ scope: undefined, finding_id: null, asset_id: "s1" }))).toBe(true);
    expect(isAssetScoped(def({ scope: undefined }))).toBe(false);
  });
  it("keeps asset-scoped rules out of the per-finding groups", () => {
    expect(groupByFinding(items, new Map()).map((g) => g.findingId)).toEqual(["fx"]);
  });
  it("resolves the owning service of an endpoint or parameter, else the topmost known asset", () => {
    expect(owningServiceId("p1", assets)).toBe("s1");
    expect(owningServiceId("s2", assets)).toBe("s2");
    expect(owningServiceId("h", assets)).toBe("h");
    expect(owningServiceId("ghost", assets)).toBeNull();
  });
  it("groups by service, with unknown targets in a last 'Whole target' group", () => {
    const g = groupByService(items, assets);
    expect(g.map((x) => x.assetId)).toEqual(["s2", "s1", ""]); // by title
    expect(g[1].defenses.map((d) => d.id)).toEqual(["n2", "n1"]); // config < waf_rule; endpoint rule folds into its service
    expect(g[2].title).toBe("Whole target");
    expect(g[2].defenses.map((d) => d.id).sort()).toEqual(["n4", "n5"]);
  });
  it("filters by asset and by finding_ids", () => {
    expect(filterDefenses(items, { asset: "s1" }).map((d) => d.id)).toEqual(["n1"]);
    expect(filterDefenses([net({ id: "m", finding_ids: ["fx"] })], { finding: "fx" })).toHaveLength(1);
  });
});
