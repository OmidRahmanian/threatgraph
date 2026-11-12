# Modeling

## Problem framing

Labels are rare (tens of red-team events among hundreds of thousands) and incomplete (the
red-team file documents *some* malicious authentications). So the primary models are
**unsupervised rankers** trained without labels, and labels are used for evaluation. The one
exception, M2, is trained on training-split labels only and only when there are enough of them. A score
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

### M2 · Gradient boosting (supervised, gated)

`HistGradientBoostingClassifier` (scikit-learn) on the same inputs as M3, with balanced class
weights and fixed hyperparameters from `configs/models.yaml` (never tuned on validation or
test). It is fitted on the **training split's labels only**; `AnomalyModel.fit` refuses labels
for unsupervised models and requires them for supervised ones, and a test flips every
validation and test label and checks that M2's scores do not change.

Unlabeled windows count as negatives *for fitting* (the usual positive-unlabeled shortcut).
That biases M2 against undocumented attacker activity, which is why evaluation still treats
unlabeled windows as unknown, exactly as for the other models. Its score is a ranking, not a
calibrated probability.

M2 exists only when the training split holds at least `supervised_gate.min_positive_windows`
known red-team windows from `min_positive_accounts` accounts (30 and 5, fixed before looking
at results). The decision reads the feature manifest's label counts, never scores. On the
synthetic demo the training split has 8 such windows from 2 accounts, so M2 is **not trained
there**; `metrics.json` and the Lab say so. A test lowers the gate on the fixture to exercise
the full train, evaluate and serve path.

### M4 · Isolation Forest + graph + process features

M3's inputs plus the `process` group, computed from LANL's optional `proc.txt`
(`packages/threatgraph/data/process_features.py`): process starts, distinct programs, programs
the account never ran before, programs no other account had run before the window, hosts, and
starts within 5 minutes of a lateral logon to that host. Same estimator, hyperparameters and
seed as M3, so M3 vs M4 is a clean ablation.

When a dataset has no proc file, the process features are stored as null (never as zeros),
M4 is skipped, and the reason is recorded in `metrics.json` and shown in the Lab.

**Development disclosure and result.** The synthetic fixture was written so most red-team hops
start tools, but also with benign novelty: a software rollout on day 9.3 (validation period),
admin tools on every swept host, and new hires. On the demo M4 does **not** improve on M3
(test AP 0.199 vs 0.248, with overlapping bootstrap intervals): the benign new programs add as
much unusualness as the attacks. The features and fixture were not changed after seeing this.

### M5 · Isolation Forest + graph embeddings (lightweight GNN alternative)

M3's inputs plus two `graph_embedding` features (`packages/threatgraph/graph/embedding.py`).
For each relative day, a truncated SVD (16 dimensions, fixed seed) factorizes the account x
destination-computer graph of **all earlier days**; a window's features are the largest and
mean `1 - cosine` distance between the account and the computers it reached. The embedding for
day d uses only events before day d, so the features pass the same truncation causality test
as the others. Accounts or computers absent from the earlier graph contribute 0 (the novelty
features already count them). On the demo M5 and M3 are within noise (test AP 0.260 vs 0.248).

### Not implemented (optional)

- **A message-passing GNN.** It needs PyTorch (a large dependency) and labels for a
  supervised GNN that a handful of labeled accounts cannot support. M5 covers the
  graph-representation idea without it.
- **Flow and DNS logs.** LANL publishes them, but they record computers, not accounts, so they
  need a computer-to-account attribution step before they fit the account-hour unit.

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
