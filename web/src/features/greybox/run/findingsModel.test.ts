import { describe, expect, it } from "vitest";
import type { FindingSummary } from "../types";
import {
  defensesLinkParams, filterFindings, graphLinkParams, nextSort, sortFindings,
} from "./findingsModel";

const f = (o: Partial<FindingSummary>): FindingSummary => ({
  id: "x", title: "T", severity: "low", status: "verified", confidence: "high", check_id: "c",
  affected_asset: null, agent_name: null, evidence_count: 0, created_at: "", updated_at: "", ...o,
});
const items = [
  f({ id: "a", title: "B low", severity: "low", evidence_count: 1 }),
  f({ id: "b", title: "A crit", severity: "critical", status: "candidate", evidence_count: 3, defense_count: 2 }),
  f({ id: "c", title: "C crit", severity: "critical", evidence_count: 2, affected_asset: { id: "1", kind: "endpoint", label: "/z" } }),
  f({ id: "d", title: "D med", severity: "medium", status: "rejected" }),
];
const ids = (xs: FindingSummary[]) => xs.map((x) => x.id).join("");

describe("sortFindings", () => {
  it("defaults to most severe first, ties by title", () => {
    expect(ids(sortFindings(items))).toBe("bcda");
  });
  it("severity ascending is least severe first", () => {
    expect(ids(sortFindings(items, { key: "severity", dir: "asc" }))).toBe("adbc");
  });
  it("sorts by evidence and defenses (missing defense_count is 0)", () => {
    expect(ids(sortFindings(items, { key: "evidence", dir: "desc" }))).toBe("bcad");
    expect(sortFindings(items, { key: "defenses", dir: "desc" })[0].id).toBe("b");
  });
  it("sorts by status with verified first when descending", () => {
    const r = sortFindings(items, { key: "status", dir: "desc" });
    expect(r[0].status).toBe("verified");
    expect(r[r.length - 1].status).toBe("rejected");
  });
  it("sorts by title and does not mutate", () => {
    const copy = [...items];
    expect(ids(sortFindings(items, { key: "title", dir: "asc" }))).toBe("bacd");
    expect(items).toEqual(copy);
  });
});

describe("filterFindings", () => {
  it("filters by severity and status together", () => {
    expect(ids(filterFindings(items, { severity: "critical", status: null }))).toBe("bc");
    expect(ids(filterFindings(items, { severity: "critical", status: "verified" }))).toBe("c");
    expect(filterFindings(items, { severity: null, status: null })).toHaveLength(4);
  });
});

describe("nextSort and links", () => {
  it("flips the direction on the same column, natural default on a new one", () => {
    expect(nextSort({ key: "severity", dir: "desc" }, "severity")).toEqual({ key: "severity", dir: "asc" });
    expect(nextSort({ key: "severity", dir: "desc" }, "title")).toEqual({ key: "title", dir: "asc" });
    expect(nextSort({ key: "title", dir: "asc" }, "evidence")).toEqual({ key: "evidence", dir: "desc" });
  });
  it("builds the graph and defenses links", () => {
    const base = new URLSearchParams("tab=findings&finding=f1");
    expect(graphLinkParams(base, "n1").toString()).toBe("tab=exploration&node=n1");
    expect(defensesLinkParams(new URLSearchParams("tab=findings&node=n"), "f2").toString()).toBe("tab=defenses&finding=f2");
  });
});
