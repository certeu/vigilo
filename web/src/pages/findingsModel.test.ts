import { describe, expect, it } from "vitest";
import type { FindingSummary } from "../features/greybox/types";
import { canonicalIssues, verificationLabel } from "./findingsModel";

const finding = (id: string, title: string, extra: Record<string, unknown> = {}): FindingSummary => ({
  id, title, severity: "medium", status: "verified", confidence: "high", check_id: "dynamic", affected_asset: { id, kind: "endpoint", label: `/${id}` },
  agent_name: "Explorer", evidence_count: 1, created_at: "2026-01-01", updated_at: "2026-01-01", finding_class: "misconfiguration", ...extra,
});

describe("canonicalIssues", () => {
  it("adapts legacy findings without inventing semantic correlation", () => {
    const issues = canonicalIssues([finding("one", "Missing CSP"), finding("two", "Missing CSP")], "run", "Target");
    expect(issues).toHaveLength(2);
    expect(issues[0].affectedLocations[0].location).toBe("/one");
  });

  it("groups only an explicit canonical identity and preserves affected locations", () => {
    const issues = canonicalIssues([
      finding("one", "CORS route", { canonical_issue_id: "cors", affected_locations: [{ location: "/api", status: "confirmed_configuration", observation_count: 2 }] }),
      finding("two", "Shared CORS policy", { canonical_issue_id: "cors", affected_locations: [{ location: "/api/version", evidence: [{ excerpt: "proof" }] }] }),
    ], "run", "Target");
    expect(issues).toHaveLength(1);
    expect(issues[0].findingIds).toEqual(["one", "two"]);
    expect(issues[0].affectedLocations.map((location) => location.location)).toEqual(["/api", "/api/version"]);
    expect(issues[0].affectedLocationCount).toBe(2);
    expect(issues[0].observationCount).toBe(3);
  });

  it("does not duplicate canonical locations returned in every member detail", () => {
    const canonical = { location: { url: "/api", method: "GET" }, observation_status: "confirmed", impact_status: "verified", observation_count: 1, observations: [{ observation_id: "obs-1" }] };
    const issues = canonicalIssues([
      finding("one", "Root cause", { canonical_issue_id: "issue", affected_location_count: 1, affected_locations: [canonical] }),
      finding("two", "Root cause", { canonical_issue_id: "issue", affected_location_count: 1, affected_locations: [canonical] }),
    ], "run", "Target");
    expect(issues[0].affectedLocations).toHaveLength(1);
    expect(issues[0].affectedLocations[0].observationStatus).toBe("confirmed");
    expect(issues[0].affectedLocations[0].impactStatus).toBe("verified");
  });

  it("labels observation and impact verification distinctly", () => {
    expect(verificationLabel("verified", "hardening")).toBe("Confirmed observation");
    expect(verificationLabel("verified", "vulnerability")).toBe("Verified impact");
    expect(verificationLabel("confirmed_configuration", "misconfiguration")).toBe("Confirmed configuration weakness");
  });
});
