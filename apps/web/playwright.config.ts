import { defineConfig, devices } from "@playwright/test";

// E2E runs against the static export (`npm run build` → out/), served by Python's stdlib
// server so no extra dependency is needed. Requires the exported demo bundle in public/.
export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  fullyParallel: true,
  reporter: [["list"]],
  use: { baseURL: "http://localhost:4173", trace: "retain-on-failure" },
  webServer: {
    command: "python3 -m http.server 4173 --directory out",
    url: "http://localhost:4173/threatgraph/",
    reuseExistingServer: !process.env.CI,
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile", use: { ...devices["Pixel 7"] } },
  ],
});
