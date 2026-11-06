# End-to-end tests

The Playwright suite lives in [apps/web/e2e/](../../apps/web/e2e/) so it resolves the web
package's `node_modules`. Run it with `make e2e` (or `cd apps/web && npm run build && npx playwright test`).
