import { defineConfig } from "@playwright/test";

// Runs e2e against the DEPLOYED stack (Traefik/compose) via E2E_BASE_URL, with no
// dev webServer. Use for verifying the built UI image, not the dev server.
export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  use: {
    baseURL: process.env.E2E_BASE_URL || "http://localhost:8081",
    screenshot: "on",
    trace: "off",
  },
});
