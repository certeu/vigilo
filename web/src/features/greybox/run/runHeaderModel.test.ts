import { describe, expect, it } from "vitest";
import type { RunRead } from "../types";
import { defaultTab, errorHead, outcomeLine, outcomeParts } from "./runHeaderModel";

const run = (o: Partial<RunRead>): RunRead =>
  ({
    status: "succeeded", end_reason: "completed", error_summary: null, phase: "reporting",
    findings: { candidate: 2, verified: 10, rejected: 1, by_severity: {} },
    ...o,
  }) as RunRead;

describe("defaultTab", () => {
  it("is Findings for terminal runs and Activity for active ones", () => {
    for (const s of ["succeeded", "failed", "cancelled"] as const) expect(defaultTab(s)).toBe("findings");
    for (const s of ["queued", "preparing", "running", "cancelling"] as const) expect(defaultTab(s)).toBe("activity");
  });
});

describe("outcomeLine", () => {
  it("is null while active", () => {
    expect(outcomeLine(run({ status: "running" }))).toBeNull();
  });
  it("summarises a completed run", () => {
    expect(outcomeLine(run({}))).toBe("Completed: 12 findings (10 verified)");
    expect(outcomeLine(run({ findings: { candidate: 0, verified: 1, rejected: 0, by_severity: {} } as never }))).toBe("Completed: 1 finding (1 verified)");
    expect(outcomeLine(run({ findings: { candidate: 0, verified: 0, rejected: 3, by_severity: {} } as never }))).toBe("Completed: no findings");
    expect(outcomeLine(run({ end_reason: "budget_requests" }))).toBe("Completed (stopped: request budget reached): 12 findings (10 verified)");
    expect(outcomeLine(run({ end_reason: "budget_time" }))).toBe("Completed (stopped: time budget reached): 12 findings (10 verified)");
    expect(outcomeLine(run({ end_reason: "budget_requests", findings: { candidate: 2, verified: 10, rejected: 0, by_severity: {} } as never })))
      .toBe("Completed (stopped: request budget reached): 12 findings (10 verified)");
  });
  it("shows the failure cause", () => {
    expect(outcomeLine(run({ status: "failed", end_reason: "error", error_summary: "Target unreachable: dns\nstack" }))).toBe("Failed: Target unreachable: dns");
    expect(outcomeLine(run({ status: "failed", end_reason: "lease_expired" }))).toBe("Failed: Worker lost contact (lease expired)");
  });
  it("names who cancelled and why when the API provides it", () => {
    expect(outcomeLine(run({ status: "cancelled" }))).toBe("Cancelled");
    expect(outcomeLine(run({ status: "cancelled", cancelled_by: "u1", cancel_reason: "wrong scope" }), () => "ana")).toBe("Cancelled by ana: wrong scope");
  });
});

describe("errorHead", () => {
  it("flags multi-line and long errors as truncated", () => {
    expect(errorHead("short")).toEqual({ head: "short", truncated: false });
    expect(errorHead("a\nb").truncated).toBe(true);
    const r = errorHead("x".repeat(300));
    expect(r.head.length).toBeLessThanOrEqual(110);
    expect(r.truncated).toBe(true);
  });
});

describe("outcomeParts", () => {
  it("uses a warning tone only for budget stops", () => {
    expect(outcomeParts(run({ end_reason: "budget_time" }))?.tone).toBe("warn");
    expect(outcomeParts(run({ end_reason: "budget_requests" }))?.tone).toBe("warn");
    expect(outcomeParts(run({}))?.tone).toBe("default");
    expect(outcomeParts(run({ status: "running" }))).toBeNull();
  });
  it("appends the skipped-checks note for completed runs", () => {
    const skipped = ["a", "b", "c", "d", "e"].map((id) => ({ id, reason: "r" }));
    const p = outcomeParts(run({ skipped_checks: skipped }));
    expect(p?.text).toBe("Completed: 12 findings (10 verified) · 5 checks not available in this build");
    expect(p?.note).toBe("5 checks not available in this build");
    expect(outcomeLine(run({ skipped_checks: [] }))).toBe("Completed: 12 findings (10 verified)");
    expect(outcomeLine(run({ status: "failed", error_summary: "x", skipped_checks: skipped }))).toBe("Failed: x");
  });
});
