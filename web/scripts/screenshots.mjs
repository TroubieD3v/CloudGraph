// Regenerates the README screenshots and the frames of docs/screenshots/demo.gif.
//   cloudgraph serve --addr 127.0.0.1:18080 --db :memory:
//   PW_CHANNEL=chrome node scripts/screenshots.mjs
//   python scripts/make_gif.py          # needs Pillow; assembles the frames into demo.gif
import { mkdirSync, rmSync } from "node:fs";
import { chromium } from "@playwright/test";

const base = process.env.CLOUDGRAPH_URL || "http://127.0.0.1:18080";
const out = new URL("../../docs/screenshots/", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const framesDir = out + "frames/";
rmSync(framesDir, { recursive: true, force: true });
mkdirSync(framesDir, { recursive: true });

const browser = await chromium.launch({ channel: process.env.PW_CHANNEL || undefined });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });

let n = 0;
// hold = how many GIF ticks (0.1 s) the frame stays on screen
async function frame(hold) {
  await page.screenshot({ path: `${framesDir}${String(n++).padStart(3, "0")}-${hold}.png` });
}

await page.goto(base);
await page.screenshot({ path: out + "welcome.png" });
await frame(15);

await page.getByTestId("demo-insecure-kubernetes").click();
await page.getByTestId("stat-paths").waitFor();
await page.screenshot({ path: out + "overview.png" });
await frame(30);

await page.getByRole("tab", { name: "Graph" }).click();
await page.waitForTimeout(600);
await frame(12);
await page.getByLabel("Highlight path").selectOption({ index: 4 });
await page.waitForTimeout(600);
await frame(18);
await page.locator(".react-flow__node").filter({ hasText: "web-sa" }).first().click();
await page.waitForTimeout(600);
await page.screenshot({ path: out + "graph.png" });
await frame(30);

await page.getByRole("tab", { name: "What-if" }).click();
await page.getByTestId("fix").first().waitFor();
await page.waitForTimeout(800);
await frame(15);
await page.getByLabel("Set automountServiceAccountToken: false on web").check();
await page.getByTestId("paths-after").filter({ hasText: "6" }).waitFor();
await frame(25);
await page.getByRole("button", { name: "Export patch" }).click();
await page.getByTestId("patch").waitFor();
await page.screenshot({ path: out + "whatif.png" });
await frame(35);

await page.getByRole("tab", { name: "Diff" }).click();
await page.getByRole("button", { name: /Compare vulnerable vs hardened/ }).click();
await page.getByTestId("diff-result").waitFor();
await page.screenshot({ path: out + "diff.png" });
await frame(35);

await browser.close();
console.log("screenshots and frames written to", out);
