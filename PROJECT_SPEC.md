# Project specification (condensed)

Condensed from the original engineering brief. The brief is authoritative for intent; this
file tracks scope and status.

## Goal

A research-quality portfolio project for Data Scientist / ML Engineer / Security Data Scientist
roles: explainable behavioral anomaly detection and threat investigation on the LANL 2015
cyber-security dataset (or a clearly labeled synthetic fixture). It should show engineering
depth, statistically rigorous evaluation, and honest presentation.

## Non-negotiables

1. An anomaly is not confirmed malicious activity. Model anomalies, red-team labels, and
   synthetic events are always visually and semantically distinct.
2. No fabricated incidents, traffic, metrics, comparisons, or business impact.
3. No leakage: causal features; fit on train; calibrate on validation; report on test.
4. Relative time only for LANL; no off-hours claims.
5. Red-team labels are incomplete; unlabeled ≠ benign. Metrics say so.
6. LANL data is user-downloaded via LANL's form, never committed, baked into images, or
   published raw.
7. Core analysis works offline with no LLM and no paid service.

## Phases

| Phase | Scope | Status |
|---|---|---|
| 0 | Inspect environment, plan, scaffold | Done |
| 1 | Synthetic fixture → typed parsing → causal features → M0 + M1 → persisted predictions and evaluation → API → overview + working Experiment Lab → tests | **Done** |
| 2 | LANL streaming import, DQ report, red-team matching, real-data evaluation | Importer, DQ report and join done (shared with Phase 1). **Not yet run on real files**; needs the user's download |
| 3 | Entity graph, graph/novelty features, explorer, bounded graph API, graph-feature ablation | Not started |
| 4 | Evidence-linked replay, model cards, incident write-ups, methodology page, deployment | Partly: model card in the Lab, CI and deploy docs. Replay and methodology page not started |
| 5 | Flows/DNS/proc, drift monitor, block-bootstrap CIs, supervised model, GNN | Not started (optional) |

## API contract (v1)

Implemented: `health`, `metadata`, `summary`, `models`, `models/{id}/metrics`,
`models/{id}/scores`, `models/{id}/predictions`, `models/{id}/explanations/{window_id}`,
`events`, `benchmarks`.
Planned (not registered, so they cannot be mistaken for working): `graph`,
`entities/{id}`, `incidents`, `incidents/{id}`, `drift`.

## Deviations from the suggested layout

- One Python distribution (`packages/threatgraph/{data,ml,serving}`) instead of separate
  `packages/data|ml|graph` projects, because the stages share schemas and config. `graph/` is
  added in Phase 3.
- Playwright specs live in `apps/web/e2e/` (they must resolve the web package's
  `node_modules`); `tests/e2e/README.md` points there.
- The scoring unit is a (source principal, 1-hour window), not a single event. Labels are
  event-level, so a window is a known positive if it contains a labeled event. See
  docs/modeling.md.
- `scripts/build_features.py` runs ingest first when no processed data exists, so the
  documented five-command workflow works. `scripts/ingest_lanl.py` is the explicit ingest
  entry point.
