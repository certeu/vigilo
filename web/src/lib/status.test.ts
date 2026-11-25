import { describe, expect, it } from "vitest";
import { statusLabel } from "./status";

describe("statusLabel", () => {
  it("maps known statuses to sentence case", () => {
    expect(statusLabel("succeeded")).toBe("Completed");
    expect(statusLabel("running")).toBe("Running");
    expect(statusLabel("cancelling")).toBe("Cancelling");
  });
  it("sentence-cases unknown statuses", () => {
    expect(statusLabel("waiting_for_input")).toBe("Waiting for input");
    expect(statusLabel(null)).toBe("—");
  });
});
