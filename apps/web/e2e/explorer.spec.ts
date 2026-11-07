import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const BUNDLE = join(__dirname, "../public/threatgraph-data/demo/v1");
const read = (rel: string) => JSON.parse(readFileSync(join(BUNDLE, rel), "utf8"));
const slug = (id: string) => id.replace(/[^A-Za-z0-9._-]/g, "_");

test("a known red-team window shows labeled edges backed by events", async ({ page }) => {
  await page.goto("/threatgraph/explorer/");
  await expect(page.getByTestId("provenance-badge").first()).toHaveText("Synthetic demo");
  await page.getByRole("radio", { name: "Red-team" }).click();
  await page.getByTestId("window-list").locator("button").first().click();
  await expect(page.getByTestId("graph-svg")).toBeVisible();
  const redteam = page.getByTestId("edge-redteam");
  await expect(redteam.first()).toBeVisible();
  await redteam.first().click();
  const evidence = page.getByTestId("edge-evidence");
  await expect(evidence).toBeVisible();
  await expect(evidence.getByTestId("edge-events").getByText("Known red-team").first()).toBeVisible();
});

test("edge counts match the exported graph and hop 2 is opt-in", async ({ page }) => {
  const index = read("graph/windows/test/index.json");
  const w = index.windows[0];
  const graph = read(`graph/windows/${slug(w.window_id)}.json`).graph;
  const hop1 = graph.edges.filter((e: { hop: number }) => e.hop === 1).length;
  await page.goto(`/threatgraph/explorer/?window=${encodeURIComponent(w.window_id)}`);
  await expect(page.getByTestId("edge-count")).toContainText(`${hop1} edges by this account`);
  await page.getByTestId("toggle-hop2").check();
  await expect(page.getByTestId("edge-count")).toContainText(`${graph.edges.length - hop1} by other accounts shown`);
});

test("selecting a computer opens its entity evidence", async ({ page }) => {
  await page.goto("/threatgraph/explorer/");
  await page.getByTestId("graph-node").first().click();
  await expect(page.getByTestId("entity-panel")).toBeVisible();
  await expect(page.getByTestId("entity-panel").getByText("Computer", { exact: true })).toBeVisible();
});
