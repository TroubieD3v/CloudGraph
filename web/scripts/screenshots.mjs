// Regenerates the README screenshots against a running server:
//   cloudgraph serve --addr 127.0.0.1:18080 --db :memory:
//   PW_CHANNEL=chrome node scripts/screenshots.mjs
import { chromium } from "@playwright/test";

const base = process.env.CLOUDGRAPH_URL || "http://127.0.0.1:18080";
const out = new URL("../../docs/screenshots/", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");

const browser = await chromium.launch({ channel: process.env.PW_CHANNEL || undefined });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });

await page.goto(base);
await page.screenshot({ path: out + "welcome.png" });

await page.getByTestId("demo-insecure-kubernetes").click();
await page.getByTestId("stat-paths").waitFor();
await page.screenshot({ path: out + "overview.png" });

await page.getByRole("tab", { name: "Graph" }).click();
await page.getByLabel("Highlight path").selectOption({ index: 4 });
await page.locator(".react-flow__node").filter({ hasText: "web-sa" }).first().click();
await page.waitForTimeout(500);
await page.screenshot({ path: out + "graph.png" });

await page.getByRole("tab", { name: "What-if" }).click();
await page.getByLabel("Set automountServiceAccountToken: false on web").check();
await page.getByTestId("paths-after").filter({ hasText: "6" }).waitFor();
await page.getByRole("button", { name: "Export patch" }).click();
await page.getByTestId("patch").waitFor();
await page.screenshot({ path: out + "whatif.png" });

await browser.close();
console.log("screenshots written to", out);
