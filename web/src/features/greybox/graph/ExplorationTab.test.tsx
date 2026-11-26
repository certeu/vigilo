// The workspace has no DOM test environment (no jsdom / testing library), so the
// tab is tested through server rendering of its states plus the pure pieces it is
// built from: graph state merge (truncated_by_kind) and the graphVersion trigger.
import { describe, expect, it } from "vitest";
import { createElement } from "react";
import { renderToString } from "react-dom/server";
import ExplorationGraph from "./ExplorationGraph";
import { graphVersionAdvanced } from "./ExplorationGraphPanel";
import { EMPTY_GRAPH, mergeGraph } from "./model";
import type { ExplorationGraphController } from "./useExplorationGraph";
import type { ExplorationGraphResponse, ExplorationNode } from "./types";

const node = (id: string, kind: ExplorationNode["kind"]): ExplorationNode => ({
  id, kind, key: id, label: id, status: kind === "objective" ? "active" : "open",
  agent_id: null, work_order_id: null, finding_id: null, asset_id: null, event_seq: 1, data: {}, version: 1,
});

const resp = (over: Partial<ExplorationGraphResponse>): ExplorationGraphResponse => ({
  version: 1, since_version: 0, full: true, truncated: false, total_nodes: 0, total_edges: 0, nodes: [], edges: [], ...over,
});

function controller(over: Partial<ExplorationGraphController>): ExplorationGraphController {
  const noop = async () => {};
  return {
    graph: EMPTY_GRAPH, status: "loading", error: null, updatedAt: null,
    refresh: noop, requestRefresh: () => {}, applyDelta: () => {}, reload: noop, ...over,
  };
}
const html = (c: ExplorationGraphController, runActive = true) =>
  renderToString(createElement(ExplorationGraph, { controller: c, runActive }));

describe("Exploration tab states", () => {
  it("shows loading, then the empty state while the run is queued", () => {
    expect(html(controller({}))).toContain("Loading the exploration graph");
    const loaded = mergeGraph(EMPTY_GRAPH, resp({}), 0).state;
    const out = html(controller({ graph: loaded, status: "ready" }));
    expect(out).toContain("No graph data yet");
  });

  it("shows a failed first load with a Retry button", () => {
    const out = html(controller({ status: "error", error: "HTTP 500" }));
    expect(out).toContain("could not be loaded");
    expect(out).toContain("HTTP 500");
    expect(out).toContain("Retry");
  });

  it("names what a truncated response left out", () => {
    const state = mergeGraph(
      EMPTY_GRAPH,
      resp({ truncated: true, total_nodes: 40, nodes: [node("o", "objective")], truncated_by_kind: { action: 30, observation: 9 } }),
      0,
    ).state;
    expect(state.truncatedByKind).toEqual({ action: 30, observation: 9 });
    const out = html(controller({ graph: state, status: "ready" }));
    expect(out).toContain("Not shown");
    expect(out).toContain("30 actions");
    expect(out).toContain("9 observations");
  });

  it("clears the truncated kinds on a complete snapshot", () => {
    const t = mergeGraph(EMPTY_GRAPH, resp({ truncated: true, truncated_by_kind: { lead: 2 } }), 0).state;
    const full = mergeGraph(t, resp({ version: 2 }), 1).state;
    expect(full.truncatedByKind).toEqual({});
  });
});

describe("refresh on graphVersion", () => {
  it("fires only when graph_version increases past what is loaded and was seen", () => {
    expect(graphVersionAdvanced(undefined, undefined, 5)).toBe(false);
    expect(graphVersionAdvanced(5, 5, 5)).toBe(false);
    expect(graphVersionAdvanced(6, 5, 5)).toBe(true);
    expect(graphVersionAdvanced(6, 6, 5)).toBe(false); // already triggered for 6
    expect(graphVersionAdvanced(4, 3, 5)).toBe(false); // loaded graph already newer
  });
});
