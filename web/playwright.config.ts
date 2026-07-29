import { defineConfig } from "@playwright/test";

// E2E against a running dev server. Start the API (VIGILO_EXECUTION_ENGINE=fake,
// with a seeded admin) and `npm run dev` first, or let Playwright start the SPA.
export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  use: {
    baseURL: process.env.E2E_BASE_URL || "http://localhost:5173",
    screenshot: "on",
    trace: "on-first-retry",
  },
  webServer: {
    command: "npm run dev",
    url: "http://localhost:5173",
    reuseExistingServer: true,
    timeout: 60_000,
  },
});
