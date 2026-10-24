import { defineConfig } from "@playwright/test";

// Serves the real binary (API + embedded UI). Build the UI first: npm run build.
// Locally you can reuse an installed Chrome: PW_CHANNEL=chrome npx playwright test
export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: "http://127.0.0.1:18080",
    channel: process.env.PW_CHANNEL || undefined,
    trace: "retain-on-failure",
  },
  webServer: {
    command: "go run ../cmd/cloudgraph serve --addr 127.0.0.1:18080 --db :memory:",
    url: "http://127.0.0.1:18080/api/health",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
