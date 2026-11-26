import { describe, expect, it } from "vitest";
import type { FindingSummary } from "../types";
import { groupFindings, sectionOf } from "./findingsModel";
import { parsePorts, parseTargets } from "../AssessmentModeEditor";

const f = (id: string, finding_class: FindingSummary["finding_class"], status: FindingSummary["status"]): FindingSummary => ({
  id, title: id, severity: "medium", status, confidence: "high", check_id: "x", affected_asset: null,
  agent_name: null, evidence_count: 1, created_at: "", updated_at: "", finding_class,
});

describe("finding classes", () => {
  it("never presents hardening or unverified issues as confirmed vulnerabilities", () => {
    expect(sectionOf(f("a", "vulnerability", "verified"))).toBe("confirmed_vulnerability");
    expect(sectionOf(f("b", "vulnerability", "candidate"))).toBe("likely_vulnerability");
    expect(sectionOf(f("c", "hardening", "verified"))).toBe("hardening");
    expect(sectionOf(f("d", "misconfiguration", "rejected"))).toBe("rejected");
    expect(sectionOf({ ...f("e", undefined, "verified") })).toBe("confirmed_vulnerability");
  });

  it("groups in report order and keeps the sort within a group", () => {
    const g = groupFindings([f("h1", "hardening", "verified"), f("v1", "vulnerability", "verified"),
      f("h2", "hardening", "verified"), f("m1", "misconfiguration", "verified")]);
    expect(g.map((x) => x.key)).toEqual(["confirmed_vulnerability", "misconfiguration", "hardening"]);
    expect(g[2].items.map((x) => x.id)).toEqual(["h1", "h2"]);
  });
});

describe("network scope parsing", () => {
  it("accepts ports, ranges, addresses and names as the server does", () => {
    expect(parsePorts("22, 80 8000-8010,,")).toEqual([22, 80, "8000-8010"]);
    expect(parseTargets("10.0.0.0/30\n db.lab.example , 10.0.1.5")).toEqual(["10.0.0.0/30", "db.lab.example", "10.0.1.5"]);
  });
});
