import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const BUNDLE = join(__dirname, "../public/threatgraph-data/demo/v1");
const read = (rel: string) => JSON.parse(readFileSync(join(BUNDLE, rel), "utf8"));
const slug = (id: string) => id.replace(/[^A-Za-z0-9._-]/g, "_");

test("replay reveals alerts only after their windows close", async ({ page }) => {
  const index = read("incidents/index.json");
  const s = index.incidents.find((i: { split: string; detections: { status: string }[] }) =>
    i.split === "test" && i.detections.some((d) => d.status === "detected"),
  );
  const inc = read(`incidents/${slug(s.incident_id)}.json`);
  const detected = s.detections.find((d: { status: string }) => d.status === "detected");
  await page.goto(`/threatgraph/replay/?incident=${encodeURIComponent(s.incident_id)}`);
  await expect(page.getByTestId("writeup")).toContainText(String(s.n_labeled_events));
  // At the start nothing has been scored yet.
  await expect(page.getByTestId(`alert-${detected.model_id}`)).toHaveCount(0);
  await page.getByTestId("next").click();
  await expect(page.getByTestId("event-log").locator("tbody tr")).toHaveCount(1);
  await page.getByTestId("end").click();
  const alerted = inc.windows.filter((w: { scores: Record<string, { flagged: boolean }> }) => w.scores[detected.model_id].flagged).length;
  await expect(page.getByTestId(`alert-${detected.model_id}`)).toHaveCount(alerted);
  await expect(page.getByTestId("path-graph")).toBeVisible();
  await expect(page.getByTestId("detection-status")).toContainText("Model alert");
});

test("methodology reads its numbers from the bundle and links the downloads", async ({ page }) => {
  const meta = read("metadata.json");
  await page.goto("/threatgraph/methodology/");
  const splits = page.getByTestId("split-table").locator("tbody tr");
  await expect(splits).toHaveCount(meta.splits.length);
  await expect(page.getByTestId("stage-table")).toContainText("features");
  const links = page.getByTestId("downloads").getByRole("link");
  await expect(links.first()).toBeVisible();
  const href = await links.first().getAttribute("href");
  const res = await page.request.get(href!);
  expect(res.ok()).toBeTruthy();
  expect((await res.text()).startsWith("# Synthetic demo")).toBeTruthy();
});
