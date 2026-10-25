import { expect, test, type Page } from "@playwright/test";

async function analyse(page: Page, demo: string) {
  await page.goto("/");
  await page.getByTestId(`demo-${demo}`).click();
  await expect(page.getByTestId("stat-paths")).toBeVisible();
}

test("welcome screen offers the three demo projects", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByTestId("demo-vulnerable-ecommerce")).toBeVisible();
  await expect(page.getByTestId("demo-insecure-kubernetes")).toBeVisible();
  await expect(page.getByTestId("demo-hardened-infrastructure")).toBeVisible();
});

test("overview shows conditional attack paths with source references", async ({ page }) => {
  await analyse(page, "insecure-kubernetes");
  await expect(page.getByTestId("stat-paths")).toContainText("10");
  const first = page.getByTestId("path-card").first();
  await expect(first).toContainText("Conditional");
  await expect(first).toContainText("Static analysis");
  await expect(first).toContainText("Connections do not prove that exploitation is possible");

  // every step links back to a concrete file and line
  await first.getByRole("button", { name: /\.yaml:\d+/ }).first().click();
  const code = page.getByTestId("source-code");
  await expect(code).toBeVisible();
  await expect(code.locator(".hl")).toHaveCount(1);
  await page.keyboard.press("Escape");
  await expect(code).toBeHidden();
});

test("source viewer never shows secret values", async ({ page }) => {
  await analyse(page, "insecure-kubernetes");
  await page.getByRole("tab", { name: /Findings/ }).click();
  await page.getByPlaceholder(/Filter/).fill("CG-K8S-018");
  await page.getByTestId("finding").first().getByRole("button").first().click();
  const code = page.getByTestId("source-code");
  await expect(code).toContainText("SESSION_SECRET");
  await expect(code).toContainText("***MASKED***");
  await expect(code).not.toContainText("demo-not-a-real-secret");
});

test("graph highlights a selected path and explains edges", async ({ page }) => {
  await analyse(page, "insecure-kubernetes");
  await page.getByRole("tab", { name: "Graph" }).click();
  await expect(page.getByTestId("graph")).toBeVisible();
  await expect(page.locator(".react-flow__node").first()).toBeVisible();

  await page.getByLabel("Highlight path").selectOption({ index: 1 });
  await expect(page.locator(".rf-node.dim").first()).toBeVisible();

  await page.locator(".react-flow__node").filter({ hasText: "web-sa" }).first().click();
  const inspector = page.getByTestId("inspector");
  await expect(inspector).toContainText("ServiceAccount");
  await expect(inspector).toContainText("Outgoing");
  await expect(inspector).toContainText("Conditional");
});

test("findings can be filtered by severity", async ({ page }) => {
  await analyse(page, "insecure-kubernetes");
  await page.getByRole("tab", { name: /Findings/ }).click();
  await page.getByRole("button", { name: /^critical/ }).click();
  const rows = page.getByTestId("finding");
  await expect(rows).toHaveCount(3);
  for (const text of await rows.allInnerTexts()) expect(text.toLowerCase()).toContain("critical");
});

test("what-if simulator recomputes paths and exports a patch", async ({ page }) => {
  await analyse(page, "insecure-kubernetes");
  await page.getByRole("tab", { name: "What-if" }).click();
  await page.getByLabel("Set automountServiceAccountToken: false on web").check();
  await expect(page.getByTestId("paths-after")).toHaveText("6");
  await expect(page.getByTestId("sim-result")).toContainText("resolved 4");

  await page.getByRole("button", { name: "Export patch" }).click();
  const patch = page.getByTestId("patch");
  await expect(patch).toContainText("--- a/web.yaml");
  await expect(patch).toContainText("+      automountServiceAccountToken: false");
});

test("unknown tab reports missing information instead of inventing links", async ({ page }) => {
  await analyse(page, "insecure-kubernetes");
  await page.getByRole("tab", { name: /Unknown/ }).click();
  await expect(page.getByTestId("unknown").first()).toContainText("legacy-svc");
  await expect(page.getByText("instead of inventing a connection")).toBeVisible();
});

test("hardened infrastructure has no risk paths", async ({ page }) => {
  await analyse(page, "hardened-infrastructure");
  await expect(page.getByTestId("stat-paths")).toContainText("0");
  await expect(page.getByText("No attack paths found")).toBeVisible();
});

test("diff shows risk paths that disappeared", async ({ page }) => {
  await analyse(page, "hardened-infrastructure");
  await page.getByRole("tab", { name: "Diff" }).click();
  await page.getByRole("button", { name: /Compare vulnerable vs hardened/ }).click();
  const diff = page.getByTestId("diff-result");
  await expect(diff).toBeVisible();
  await expect(diff).toContainText("Risk paths");
  const paths = page.getByTestId("diff-paths");
  await expect(paths.locator(".minus").first()).toBeVisible();
  await expect(paths.locator(".plus")).toHaveCount(0);
});

test("uploaded compose file is analysed", async ({ page }) => {
  await page.goto("/");
  await page.getByTestId("file-input").setInputFiles({
    name: "docker-compose.yml",
    mimeType: "text/yaml",
    buffer: Buffer.from('services:\n  db:\n    image: postgres:16\n    ports: ["5432:5432"]\n'),
  });
  await expect(page.getByTestId("stat-paths")).toBeVisible();
  await page.getByRole("tab", { name: /Findings/ }).click();
  await expect(page.getByTestId("finding").first()).toContainText("CG-DC-007");
});

test("unsupported upload shows an error", async ({ page }) => {
  await page.goto("/");
  await page.getByTestId("file-input").setInputFiles({ name: "values.yaml", mimeType: "text/yaml", buffer: Buffer.from("replicaCount: 2\n") });
  await expect(page.locator(".error")).toContainText("no supported resources");
});

test("reports can be downloaded and analyses deleted", async ({ page }) => {
  await analyse(page, "vulnerable-ecommerce");
  const [download] = await Promise.all([page.waitForEvent("download"), page.getByTestId("exports").getByText("SARIF").click()]);
  expect(download.suggestedFilename()).toMatch(/\.sarif$/);
  const body = await (await download.createReadStream()).toArray();
  const sarif = JSON.parse(Buffer.concat(body).toString());
  expect(sarif.version).toBe("2.1.0");

  page.once("dialog", (d) => d.accept());
  await page.getByRole("button", { name: "Delete" }).click();
  await expect(page.getByTestId("demo-vulnerable-ecommerce")).toBeVisible();
});

test("what-if marks fixes as patchable or manual", async ({ page }) => {
  await analyse(page, "vulnerable-ecommerce");
  await page.getByRole("tab", { name: "What-if" }).click();
  await expect(page.getByTestId("fix").filter({ hasText: "patch: docker-compose.yml" }).first()).toBeVisible();
  await expect(page.getByTestId("fix").filter({ hasText: "manual change in Terraform" }).first()).toBeVisible();
});

test("overview states the search limits and their scope", async ({ page }) => {
  await analyse(page, "insecure-kubernetes");
  await expect(page.getByTestId("search-limits")).toHaveText(/· search complete · limited coverage$/);
  await expect(page.getByTestId("search-scope").first()).toContainText("network pivot");
  await page.getByTestId("coverage").locator("summary").click();
  await expect(page.getByTestId("coverage")).toContainText("network_reach");
  await expect(page.getByTestId("search-incomplete")).toHaveCount(0);
});

test("dark theme is the default and the toggle switches and remembers light", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  expect(bg).toBe("rgb(13, 14, 16)");
  await page.getByTestId("theme-toggle").click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  expect(await page.evaluate(() => getComputedStyle(document.body).backgroundColor)).toBe("rgb(211, 225, 248)");
  await page.getByTestId("theme-toggle").click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
});

test("secondary paths are compact and expand on demand", async ({ page }) => {
  await analyse(page, "insecure-kubernetes");
  const second = page.getByTestId("path-card").nth(1);
  await expect(second.locator(".route")).toBeVisible();
  await expect(second.locator(".steps")).toBeHidden();
  await second.locator("summary").click();
  await expect(second.locator(".steps")).toBeVisible();
});

test("show alternative paths lists the routes merged into a path", async ({ page }) => {
  const compose = [
    "services:",
    "  gateway: {image: 'nginx:1.27.2', ports: ['8080:80'], networks: [edge]}",
    "  app: {image: 'acme/app:1', networks: [edge, data]}",
    "  worker: {image: 'acme/worker:1', networks: [edge, data]}",
    "  db: {image: 'postgres:16.4', networks: [data]}",
    "networks: {edge: {}, data: {}}",
  ].join("\n");
  const res = await page.request.post("/api/analyses", {
    data: { name: "alternatives", files: [{ name: "docker-compose.yml", content: compose }], limits: { maxPivots: 3 } },
  });
  const { id } = await res.json();
  await page.goto("/");
  await page.getByLabel("Analysis history").selectOption(id);
  await expect(page.getByTestId("stat-paths")).toBeVisible();

  await expect(page.getByTestId("similar-routes").first()).toContainText("similar route");
  await expect(page.getByTestId("alternatives")).toHaveCount(0);
  await page.getByTestId("alt-toggle").check();
  await expect(page.getByTestId("alternatives").first()).toContainText("Alternative routes");
  await expect(page.getByTestId("similar-routes")).toHaveCount(0);
  await page.getByTestId("alt-toggle").uncheck();
  await expect(page.getByTestId("alternatives")).toHaveCount(0);
});
