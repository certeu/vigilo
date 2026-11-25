import { describe, expect, it } from "vitest";
import { checksByArea, isAvailable, skippedDetail, skippedSummary, unavailableIds, willBeSkipped } from "./checksAvailability";
import type { GreyboxCheck } from "./types";

const mk = (id: string, extra: Partial<GreyboxCheck> = {}): GreyboxCheck => ({
  id, title: id, description: "", default_enabled: true, requires_auth_testing: false, ...extra,
});

describe("checks availability", () => {
  const checks = [mk("a"), mk("b", { available: true }), mk("c", { available: false, unavailable_reason: "nope" })];
  it("treats a missing flag as available", () => {
    expect(isAvailable(checks[0])).toBe(true);
    expect(isAvailable(checks[1])).toBe(true);
    expect(isAvailable(checks[2])).toBe(false);
    expect([...unavailableIds(checks)]).toEqual(["c"]);
  });
  it("lists selected unavailable checks as skipped", () => {
    expect(willBeSkipped(["a", "c"], checks)).toEqual(["c"]);
    expect(willBeSkipped(["a"], checks)).toEqual([]);
  });
  it("summarises skipped checks", () => {
    expect(skippedSummary(undefined)).toBeNull();
    expect(skippedSummary([])).toBeNull();
    expect(skippedSummary([{ id: "x", reason: "r" }])).toBe("1 check not available in this build");
    expect(skippedSummary([{ id: "x", reason: "r" }, { id: "y", reason: "s" }])).toBe("2 checks not available in this build");
    expect(skippedDetail([{ id: "x", reason: "r" }])).toBe("x: r");
  });
  it("groups checks by the server's security area", () => {
    const grouped = checksByArea([
      mk("headers", { area: "Browser", evidence: "metadata" }),
      mk("cors", { area: "Origin", evidence: "origin proof" }),
      mk("cookies", { area: "Browser", evidence: "metadata" }),
    ]);
    expect(grouped.map((group) => group.area)).toEqual(["Browser", "Origin"]);
    expect(grouped[0].checks.map((check) => check.id)).toEqual(["headers", "cookies"]);
    expect(grouped[0].evidence).toBe("metadata");
  });
});
