import { describe, expect, it } from "vitest";
import { formatDateMs, formatRelative, timeParts } from "./format";

const NOW = Date.parse("2026-05-01T12:00:00Z");
const ago = (s: number) => new Date(NOW - s * 1000).toISOString();

describe("formatRelative", () => {
  it("buckets by magnitude", () => {
    expect(formatRelative(ago(10), NOW)).toBe("just now");
    expect(formatRelative(ago(5 * 60), NOW)).toBe("5 min ago");
    expect(formatRelative(ago(3 * 3600), NOW)).toBe("3 h ago");
    expect(formatRelative(ago(2 * 86400), NOW)).toBe("2 d ago");
  });
  it("handles missing and invalid input", () => {
    expect(formatRelative(null, NOW)).toBe("—");
    expect(formatRelative("nope", NOW)).toBe("nope");
  });
  it("falls back to a date after 30 days", () => {
    expect(formatRelative(ago(90 * 86400), NOW)).not.toMatch(/ago/);
  });
});

describe("timeParts / formatDateMs", () => {
  it("returns the exact time as title", () => {
    const p = timeParts(ago(120), NOW);
    expect(p.text).toBe("2 min ago");
    expect(p.title).toBeTruthy();
    expect(timeParts(null).title).toBeUndefined();
  });
  it("keeps milliseconds", () => {
    expect(formatDateMs("2026-05-01T12:00:00.123Z")).toMatch(/\.123$/);
  });
});
