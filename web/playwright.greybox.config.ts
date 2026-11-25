import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { defineConfig } from "@playwright/test";

// Self-contained grey-box E2E: boots the synthetic target, the API (throwaway SQLite
// DB, in-process grey-box executor, mock white-box engine) and vite, then tears them
// all down. Run: `npm run test:e2e:greybox` (see e2e/greybox/README.md).
const API_PORT = Number(process.env.GB_API_PORT ?? 18580);
const TARGET_PORT = Number(process.env.GB_TARGET_PORT ?? 18581);
const UI_PORT = Number(process.env.GB_UI_PORT ?? 18590);

// The installed Playwright may want a newer Chromium than the one cached locally.
// Browsers are never downloaded here: point E2E_CHROMIUM at any Chromium binary.
// Default: the macOS Playwright cache of the current user.
const LOCAL_CHROMIUM = join(homedir(), "Library/Caches/ms-playwright/chromium_headless_shell-1243",
  "chrome-headless-shell-mac-arm64/chrome-headless-shell");
const chromium = process.env.E2E_CHROMIUM ?? (existsSync(LOCAL_CHROMIUM) ? LOCAL_CHROMIUM : undefined);

export default defineConfig({
  testDir: "./e2e/greybox",
  testMatch: /.*\.spec\.ts/,
  outputDir: "./test-results/greybox",
  timeout: 120_000,
  expect: { timeout: 15_000 },
  workers: 1,
  fullyParallel: false,
  retries: 0,
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report/greybox" }]],
  use: {
    baseURL: `http://127.0.0.1:${UI_PORT}`,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    acceptDownloads: true,
    launchOptions: chromium ? { executablePath: chromium } : {},
  },
  metadata: {
    apiUrl: `http://127.0.0.1:${API_PORT}`,
    targetUrl: `http://127.0.0.1:${TARGET_PORT}`,
  },
  webServer: [
    {
      command: `bash e2e/greybox/serve.sh target ${TARGET_PORT}`,
      url: `http://127.0.0.1:${TARGET_PORT}/robots.txt`,
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: `bash e2e/greybox/serve.sh api ${API_PORT}`,
      url: `http://127.0.0.1:${API_PORT}/health`,
      reuseExistingServer: false,
      timeout: 120_000,
    },
    {
      command: `npx vite --port ${UI_PORT} --host 127.0.0.1 --strictPort`,
      url: `http://127.0.0.1:${UI_PORT}/login`,
      env: { VIGILO_API_URL: `http://127.0.0.1:${API_PORT}` },
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
});
