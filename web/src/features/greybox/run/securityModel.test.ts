import { describe, expect, it } from "vitest";
import { accessCell, entityName, summarise } from "./securityModel";
import type { SecurityModelView } from "../types";

const view: SecurityModelView = {
  identities: [{ identity: "dave", requests: 4, role: "member" }, { identity: "finn", requests: 3, role: null }],
  entities: [],
  relations: [],
  expectations: [
    { subject: "identity:dave", operation: "read", resource: "resource:cobalt", expected: "deny", basis: "observed_ui" },
    { subject: "role:member", operation: "read", resource: "resource_type:documents", expected: "allow", basis: "stated" },
  ],
  interfaces: [{ interface: "/api/projects/{id}", resource_type: "projects", access: { dave: { deny: 1 }, finn: { allow: 1 } } }],
  signals: [],
  unresolved: [{ kind: "no_expectation", detail: "x", resource_type: "documents" }],
  counts: {},
};

describe("security model view", () => {
  it("summarises expected vs assumed access and what is unresolved", () => {
    const s = summarise(view);
    expect(s).toMatchObject({ identities: 2, interfaces: 1, expectations: 2, assumptions: 1, unresolved: 1, empty: false });
    expect(summarise(null).empty).toBe(true);
  });
  it("formats access cells and entity names", () => {
    expect(accessCell({ allow: 2, deny: 1 })).toBe("2 / 1 / 0");
    expect(accessCell(undefined)).toBe("—");
    expect(entityName("resource_type:documents")).toBe("documents");
  });
});
