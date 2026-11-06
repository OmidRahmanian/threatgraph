# Evaluation

Current numbers live in generated files only:

- `artifacts/<dataset>/metrics.json`: the full metrics, which the website reads;
- `artifacts/<dataset>/reports/evaluation.md`: the comparison table, written by `scripts/evaluate.py`;
- `artifacts/<dataset>/reports/api_benchmark.json`: API latency (`make benchmark`).

They are not copied here, so this document cannot go stale.

## Protocol

| Split | Demo config (relative days) | Use |
|---|---|---|
| warm-up | [0, 2) | history only |
| train | [2, 8) | fit models (no labels) |
| validation | [8, 11) | calibrate the alert threshold; model-design checks |
| test | [11, 14) | reported once with the fixed threshold |

Windows go to a split by `window_start`. Boundaries align with window edges (the config
validates this). Known-positive windows and labeled events are counted per split in
`feature_manifest.json` and shown in the Lab. If a split has no positives, AP and recall are
reported as **not estimable** (`n/e`), never as 0.

## Metrics

| Metric | Meaning here |
|---|---|
| Average precision (AP) | ranking quality for known red-team windows; compare with *random-ranking AP* = prevalence |
| Precision@K | known red-team windows among the K highest scores |
| Known-label recall | share of documented red-team windows alerted at the threshold |
| Precision (lower bound) | known red-team alerts / all alerts, with unlabeled alerts counted as false |
| Alerts, alerts/day, alerts per 1,000 windows | analyst workload, valid even without negative labels |
| Detection latency | per account: first labeled event → end of the first alerted labeled window |
| ROC AUC | stored for completeness; not emphasized under extreme imbalance |

**Labeling assumption.** Precision, AP and the confusion matrix treat unlabeled windows as
negatives. Unlabeled windows may hold undocumented attacks (the synthetic fixture deliberately
leaves about 15% of successful attacker hops and all failed attempts unlabeled), so measured
precision is a lower bound. Recall measures only documented red-team activity.

## Threshold explorer correctness

The browser recomputes metrics from the persisted test score table:
`apps/web/src/lib/threshold.ts`, tested in `threshold.test.ts` against the same fixture as
the Python `threshold_counts` tests. The integration test checks that recomputing from the
exported table at the calibrated threshold reproduces the stored operating point. An e2e test
checks that the UI displays it.

## Known gaps

- **Uncertainty.** No confidence intervals yet. With fewer than 10 positive windows per
  split, model differences are noisy. Planned: block bootstrap over days or accounts, not
  independent windows.
- No graph-feature ablation yet (Phase 3).
- No drift monitor yet (Phase 5).
- Synthetic results show the pipeline works. They do not measure real-world detection
  performance.
