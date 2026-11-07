# Modeling

## Problem framing

Labels are rare (tens of red-team events among hundreds of thousands) and incomplete (the
red-team file documents *some* malicious authentications). So the primary models are
**unsupervised rankers** trained without labels. Labels are used only for evaluation. A score
answers "how unusual is this account-hour compared with the training period?", not "what is
the probability of compromise?".

## Scoring unit

`(source principal, 1-hour window)` with at least one non-LogOff authentication. An
account-hour matches how an analyst triages ("what was this account doing?") and makes
fan-out and novelty features meaningful. Labels are event-level, so a window is a known
positive if it contains at least one red-team-matched event. Per-event scoring is possible
later but would multiply alert volume without adding evidence.

## Models

All models implement `AnomalyModel` (`packages/threatgraph/ml/models.py`): `fit`, `score`,
`calibrate_threshold`, `predict`, `diagnostics`, `save`, `load`, and `metadata`. Saved
metadata includes the feature list, training window, hyperparameters, seed, library
versions, threshold policy, and artifact SHA-256.

### M0 · Robust z-score baseline

The score is the largest upward robust z-score among `n_fail`, `n_novel_dst`, `n_novel_edge`,
`z_events` and `z_distinct_dst`. The median and scale (MAD×1.4826, falling back to IQR, then
std, then 1, with a minimum scale of 1.0) are fit on the training split. Because the score
*is* the largest per-feature z, its explanation is exact.

Limitations: one global reference for every account, upward deviations only, no feature
interactions.

**Development disclosure.** The first M0 draft used raw volume features (`n_events`,
`n_fail`, `n_distinct_dst`, `n_novel_dst`, `max_burst`). Raw volume is dominated by
high-volume service accounts, which made it a straw-man baseline: validation AP was 0.005. It
was replaced with novelty and per-account-deviation features before the final evaluation
(validation AP 0.039). The choice was made on design grounds and checked on validation, but the
first draft's *test* numbers were also printed during development. The comparison is therefore
not perfectly blind; this note records that.

### M1 · Isolation Forest

scikit-learn `IsolationForest` (300 trees, `max_samples=256`, `random_state=42`, `n_jobs=1`
for determinism) on all 17 features after a monotone signed `log1p` transform, which tames
heavy-tailed counts. Trained on the training split without labels. The score is
`-score_samples(x)`.

**Explanations are proxies.** Isolation Forest has no faithful per-feature attribution. The
UI shows each feature's robust z versus the training median and labels it an *approximate
diagnostic*, not the model's reasoning.

### M3 · Isolation Forest + graph features

The same estimator, hyperparameters and seed as M1, with the `graph` feature group added
(`n_rare_dst`, `n_pivot_src`; see `docs/graph.md`). Because only the inputs differ, M1 vs M3 is
a clean ablation of the graph features. It is configured under `ablations:` in
`configs/models.yaml`, reported in `artifacts/<ds>/reports/evaluation.md` and shown in the Lab.

**Development disclosure.** The graph features were designed after the synthetic fixture,
whose campaigns pivot from host to host. They were checked on the demo while being written,
so the demo ablation is not blind. M0 and M1 were not changed: their metrics are identical
before and after the graph features were added (verified when M3 was introduced).

### M2 · supervised model: gated, not trained

A supervised model is trained only when the training split holds at least
`supervised_gate.min_positive_windows` known red-team windows from
`min_positive_accounts` accounts (30 and 5; fixed in `configs/models.yaml` before looking at
results). The demo has far fewer, so `metrics.json` records the decision and the reason
instead of a model. If real data passes the gate, the model must keep train and validation
positives disjoint in time, never using a random event-level split.

### Not implemented (Phase 5, optional)

- Flow, DNS and process logs: LANL publishes them, but they need the same user download and
  the synthetic fixture has none.
- A graph neural network benchmark: a heavy dependency for a comparison that a handful of
  labeled accounts cannot support.

## Threshold policy

`validation_alert_rate`: flag the top 1% of **validation** windows. Labels are not used, since
they are too few and too incomplete to tune against. Test metrics use that fixed threshold.
The Lab lets users explore other thresholds, but every number it shows is recomputed from the
stored test scores and is labeled as such.

## Leakage controls

- Features use events with time < window end. Baselines use strictly earlier windows
  (`shift(1)`), and novelty is defined by first occurrence. Leakage is tested by recomputing
  features on data truncated at a cutoff; the test fails if any earlier window changes. A
  mutation check confirmed it catches a future leak.
- Scalers and references are fit on train only. Thresholds come from validation only.
- Splits are chronological by window start, with explicit boundaries in the config.
  The first two days are warm-up (history only, never scored), because everything is "novel"
  at the start of any log.
