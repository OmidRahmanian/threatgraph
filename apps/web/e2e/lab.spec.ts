import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const BUNDLE = join(__dirname, "../public/threatgraph-data/demo/v1");
const read = (rel: string) => JSON.parse(readFileSync(join(BUNDLE, rel), "utf8"));

test("overview shows computed stats with a synthetic badge", async ({ page }) => {
  const summary = read("summary.json");
  await page.goto("/threatgraph/");
  await expect(page.getByTestId("provenance-badge").first()).toHaveText("Synthetic demo");
  await expect(page.getByText("Synthetic demo — no real network data on this page")).toBeVisible();
  await expect(page.getByTestId("stat-events")).toContainText(`${summary.rejected_source_rows} malformed rows rejected`);
  // Unbuilt views are labeled, not dead links.
  await expect(page.getByText("Not built yet · Phase 4").first()).toBeVisible();
});

test("navigation from overview to the lab", async ({ page }) => {
  await page.goto("/threatgraph/");
  // Client-rendered stats appear only after hydration; clicking earlier can race the router.
  await expect(page.getByTestId("stat-events")).toBeVisible();
  await page.getByRole("link", { name: /Compare models/ }).click();
  await expect(page).toHaveURL(/\/threatgraph\/lab\/?$/);
  await expect(page.getByRole("heading", { name: "ML Experiment Lab" })).toBeVisible();
});

test("calibrated threshold reproduces the stored test operating point", async ({ page }) => {
  const models = read("models.json").models;
  const model = models[models.length - 1];
  const op = read(`models/${model.model_id}/metrics.json`).splits.test.operating_point;
  await page.goto("/threatgraph/lab/");
  await expect(page.getByTestId("metric-alerts")).toContainText(String(op.alerts));
  await expect(page.getByTestId("cm-tp")).toHaveText(String(op.known_positive_alerts));
});

test("threshold slider recomputes metrics and reset restores them", async ({ page }) => {
  await page.goto("/threatgraph/lab/");
  const alerts = page.getByTestId("metric-alerts");
  await expect(alerts).toBeVisible();
  const before = await alerts.locator("div").nth(1).innerText();
  const slider = page.getByTestId("threshold-slider");
  await slider.focus();
  for (let i = 0; i < 60; i++) await page.keyboard.press("ArrowRight");
  const after = await alerts.locator("div").nth(1).innerText();
  expect(Number(after.replace(/,/g, ""))).toBeGreaterThan(Number(before.replace(/,/g, "")));
  await page.getByRole("button", { name: "Reset to validation-calibrated threshold" }).click();
  await expect(alerts.locator("div").nth(1)).toHaveText(before);
});

test("selecting a ranked window shows evidence events", async ({ page }) => {
  await page.goto("/threatgraph/lab/");
  await page.getByRole("radio", { name: "All known red-team" }).click();
  await page.getByTestId("ranked-list").locator("button:not([disabled])").first().click();
  const explanation = page.getByTestId("explanation");
  await expect(explanation).toBeVisible();
  await expect(explanation.getByText("Known red-team").first()).toBeVisible();
  await expect(page.getByTestId("evidence-table").locator("tbody tr").first()).toBeVisible();
  await expect(explanation.getByText(/Explanation method/)).toBeVisible();
});

test("switching model and split keeps provenance labels", async ({ page }) => {
  await page.goto("/threatgraph/lab/");
  await page.getByRole("radio", { name: /M0/ }).click();
  await page.getByRole("radio", { name: "Validation" }).click();
  await expect(page.getByText("treat its numbers as optimistic")).toBeVisible();
  await expect(page.getByTestId("model-card")).toContainText("robust_z");
  await expect(page.getByTestId("provenance-badge").first()).toHaveText("Synthetic demo");
});

test("no horizontal page scroll", async ({ page }) => {
  for (const path of ["/threatgraph/", "/threatgraph/lab/"]) {
    await page.goto(path);
    await page.waitForLoadState("networkidle");
    const [sw, cw] = await page.evaluate(() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]);
    expect(sw, path).toBeLessThanOrEqual(cw);
  }
});

test("the lab shows the graph-feature ablation from stored metrics", async ({ page }) => {
  const ablation = read("models.json").ablations[0];
  await page.goto("/threatgraph/lab/");
  const table = page.getByTestId("ablation-table");
  await expect(table).toBeVisible();
  const test = ablation.splits.find((s: { split: string }) => s.split === "test");
  await expect(table.locator("tbody tr").nth(1)).toContainText(test.candidate.average_precision.toFixed(3));
});
