import { expect, test } from "@playwright/test";

// The public static build has no live API configured: the page must say so, show no
// research badge, and render no telemetry, numbers or charts.
test("live monitoring page in the public build shows that it is not enabled", async ({ page }) => {
  await page.goto("/threatgraph/live/");
  await expect(page.getByRole("heading", { name: "Live monitoring" })).toBeVisible();
  await expect(page.getByTestId("live-mode-badge")).toHaveText("Live monitoring · private");
  await expect(page.getByTestId("live-not-enabled")).toContainText("not enabled in this build");
  await expect(page.getByTestId("provenance-badge")).toHaveCount(0);
  await expect(page.getByTestId("agents-table")).toHaveCount(0);
  await expect(page.getByText("Live Monitoring Mode: private telemetry")).toBeVisible();
  const nav = page.getByRole("navigation", { name: "ThreatGraph sections" });
  await nav.getByRole("link", { name: "Experiment Lab" }).click();
  await expect(page.getByTestId("provenance-badge").first()).toHaveText("Synthetic demo");
});
