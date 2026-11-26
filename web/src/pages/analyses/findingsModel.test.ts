import { describe, expect, it } from "vitest";
import { findingParts } from "./findingsModel";

describe("findingParts", () => {
  it("orders by severity, hides zeros and carries colour classes", () => {
    const parts = findingParts({ low: 4, critical: 0, high: 12, medium: 6, info: 0 });
    expect(parts.map((p) => [p.severity, p.count])).toEqual([["high", 12], ["medium", 6], ["low", 4]]);
    expect(parts[0].textClass).toBe("text-severity-high");
    expect(parts[0].title).toBe("12 high");
  });
  it("is empty without counts", () => {
    expect(findingParts({})).toEqual([]);
  });
});
