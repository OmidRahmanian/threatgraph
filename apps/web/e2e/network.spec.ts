import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const BUNDLE = join(__dirname, "../public/threatgraph-data/demo/v1");
const read = (rel: string) => JSON.parse(readFileSync(join(BUNDLE, rel), "utf8"));

interface Acct {
  node_id: string;
  label: string;
  n_known_redteam_windows: number;
  scores: Record<string, { n_alerts: number }>;
}

test("the map draws every mapped account and computer of the test split", async ({ page }) => {
  const net = read("network/test.json");
  await page.goto("/threatgraph/network/");
  await expect(page.getByTestId("provenance-badge").first()).toHaveText("Synthetic demo");
  await expect(page.getByTestId("map-svg")).toBeVisible();
  await expect(page.getByTestId("map-account")).toHaveCount(net.accounts.length);
  await expect(page.getByTestId("map-computer")).toHaveCount(net.computers.length);
  const redteam = net.accounts.filter((a: Acct) => a.n_known_redteam_windows > 0).length;
  await expect(page.getByTestId("map-redteam-marker")).toHaveCount(redteam);
  await expect(page.getByTestId("map-counts")).toContainText(`${net.accounts.length} accounts`);
  await expect(page.getByTestId("map-counts")).toContainText(`${redteam} with known red-team windows`);
});

test("filters recount from the payload: model, red-team only, single day", async ({ page }) => {
  const net = read("network/test.json");
  const models = read("models.json").models.map((m: { model_id: string }) => m.model_id);
  await page.goto("/threatgraph/network/");
  await expect(page.getByTestId("map-svg")).toBeVisible();
  for (const m of models) {
    await page.getByTestId("map-model").selectOption(m);
    const alerted = net.accounts.filter((a: Acct) => a.scores[m].n_alerts > 0).length;
    await expect(page.getByTestId("map-alert-ring")).toHaveCount(alerted);
  }
  await page.getByRole("radio", { name: "Red-team" }).click();
  const redteam = net.accounts.filter((a: Acct) => a.n_known_redteam_windows > 0).length;
  await expect(page.getByTestId("map-account")).toHaveCount(redteam);
  await expect(page.getByTestId("map-link-redteam").first()).toBeVisible();
  // A day with no red-team window empties the red-team filter rather than keeping stale labels.
  const rtDays = new Set<number>(
    net.accounts.flatMap((a: { windows: { day: number; known_redteam: boolean }[] }) =>
      a.windows.filter((w) => w.known_redteam).map((w) => w.day),
    ),
  );
  const quiet = (net.days as number[]).find((d) => !rtDays.has(d));
  if (quiet !== undefined) {
    await page.getByTestId("map-from").selectOption(String(quiet));
    await page.getByTestId("map-to").selectOption(String(quiet));
    await expect(page.getByTestId("map-empty")).toBeVisible();
  }
});

test("search selects a node; an account links to its hour and its incident", async ({ page }) => {
  const net = read("network/test.json");
  const incidents = read("incidents/index.json").incidents;
  const acct = net.accounts.find(
    (a: Acct) => a.n_known_redteam_windows > 0 && incidents.some((i: { principal_id: string }) => i.principal_id === a.node_id),
  ) as Acct;
  await page.goto("/threatgraph/network/");
  await page.getByTestId("map-search").fill(acct.label);
  await page.getByTestId("map-search-results").getByRole("button", { name: new RegExp(acct.label) }).first().click();
  const detail = page.getByTestId("map-account-detail");
  await expect(detail).toContainText(acct.label);
  await expect(detail.getByText("Known red-team").first()).toBeVisible();
  await expect(page.getByTestId("map-replay-link").first()).toBeVisible();
  await page.getByTestId("map-windows").getByRole("link").first().click();
  await expect(page).toHaveURL(/\/threatgraph\/explorer\/\?window=/);
  await expect(page.getByTestId("graph-svg")).toBeVisible();
  await page.getByTestId("to-network-map").click();
  await expect(page).toHaveURL(/\/threatgraph\/network\/\?.*node=/);
  await expect(page.getByTestId("map-account-detail")).toBeVisible();
});

test("selecting a computer lists its mapped accounts", async ({ page }) => {
  const net = read("network/test.json");
  const c = [...net.computers].sort((a, b) => b.n_accounts_shown - a.n_accounts_shown)[0];
  await page.goto("/threatgraph/network/");
  await page.getByTestId("map-search").fill(c.label);
  await page.getByTestId("map-search").press("Enter");
  await expect(page.getByTestId("map-computer-detail")).toContainText(c.label);
  await expect(page.getByTestId("map-computer-links").getByRole("button")).toHaveCount(c.n_accounts_shown);
  await expect(page.getByTestId("map-computer-links").getByRole("button").first()).toBeVisible();
});
