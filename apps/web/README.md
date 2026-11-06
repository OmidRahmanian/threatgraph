# ThreatGraph AI — web

Next.js 16 (App Router) + TypeScript + Tailwind v4 + Recharts, built as a static export.
See the [root README](../../README.md) for setup. Data is read from
`public/threatgraph-data/<dataset>/v1/` (produced by `scripts/export_demo.py`) or, when
`NEXT_PUBLIC_TG_API_BASE` is set, from the live API.

| Command | |
|---|---|
| `npm run dev` | dev server on :3000 → http://localhost:3000/threatgraph |
| `npm run build` | static export to `out/` |
| `npm test` | vitest (threshold math) |
| `npm run typecheck` | regenerate route types + `tsc` |
| `npx playwright test` | e2e on desktop + mobile against `out/` |
