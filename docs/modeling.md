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

### Not yet implemented

- M2 (supervised, e.g. regularized logistic regression or XGBoost): only if the real-data
  split has enough positives. Train and validation positives would have to be disjoint in
  time, never a random event-level split.
- M3 (graph-derived): temporal degree shifts and neighborhood risk, plus an ablation of graph
  features. Phase 3.

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
