import { createElement } from "react";
import { renderToString } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import type { Credential } from "../../api/client";
import { TestAccountPicker } from "./NewGreyboxForm";

const accounts: Credential[] = Array.from({ length: 200 }, (_, index) => ({
  id: `account-${index}`,
  kind: "login_account",
  label: `Synthetic user ${index}`,
  gitlab_base_url: null,
  created_at: "2026-11-24T00:00:00Z",
  has_secret: true,
}));

describe("TestAccountPicker", () => {
  it("summarises and contains a large multi-account selection", () => {
    const html = renderToString(createElement(MemoryRouter, null, createElement(TestAccountPicker, {
      accounts,
      selected: ["account-4", "account-90"],
      onChange: () => undefined,
    })));
    expect(html.replace(/<!-- -->/g, "")).toContain("2 selected");
    expect(html).toContain("Search 200 test accounts");
    expect(html).toContain("max-h-56");
    expect(html).toContain("Synthetic user 199");
  });
});
