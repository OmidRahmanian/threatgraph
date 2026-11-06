# Working agreements for agents and contributors

- **No invented numbers.** Every metric, count or chart in the UI or docs must come from
  pipeline output. Never type results into docs; regenerate them (`scripts/evaluate.py` writes
  `artifacts/<ds>/reports/evaluation.md`).
- **Label semantics.** Keep three categories distinct everywhere: model anomaly (score ≥ threshold),
  known red-team (matched to the red-team file), and synthetic data. Unlabeled ≠ benign.
- **Causality.** Features for a window may use only events with time < window end; per-principal
  baselines use strictly earlier windows. `tests/unit/test_features.py::test_features_are_causal_on_fixture`
  must keep passing. Labels never enter feature columns.
- **No test leakage.** Fit on `train`, calibrate thresholds on `validation`, report `test` once.
  If you change a model because of a number, the number must come from validation.
- **Time.** LANL time is relative seconds. Show "Day N · +s"; never calendar or clock time.
- **Data handling.** Never commit, bake into images, or export raw LANL files. Do not bypass
  LANL's data-use form. Public exports of real data must use `public_ids=True`.
- **Unbuilt features** are labeled as such in the UI (no dummy controls).
- **API/static parity.** Add payloads in `packages/threatgraph/serving/payloads.py` and use them from
  both the API and the exporter; `tests/integration/test_end_to_end.py` checks parity.
- Before finishing: `make lint typecheck test e2e`.
- Next.js 16 differs from older versions; consult `apps/web/node_modules/next/dist/docs/`.
