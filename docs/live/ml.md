# Behavioural model (live telemetry)

## Why a separate pipeline

The research models (M0, M1, M3) were built for LANL authentication windows. Web and SSH
telemetry from a personal server has different units, scales and semantics, so HTTP events are
never fed to them. The live model has its own features (`threatgraph/live/behavior.py`) and
reuses only generic pieces: robust scaling and the Isolation Forest setup.

## Unit and features

One row per (host, remote source, 5-minute bucket). The source is the client address as the
agent stored it (possibly truncated or hashed by the privacy policy).

| Feature | Description |
|---|---|
| `http_requests`, `http_distinct_paths` | request volume and breadth |
| `http_4xx_ratio`, `http_5xx_ratio`, `http_404_paths` | error behaviour |
| `http_sensitive`, `http_malformed`, `http_non_get` | sensitive-looking paths, non-HTTP payloads, unusual methods |
| `ssh_failures`, `ssh_successes`, `ssh_distinct_users`, `ssh_fail_ratio` | authentication behaviour |
| `new_source` | the source had no earlier activity on this host (new source-to-service relation) |
| `log_rate_change` | change versus the source's previous active bucket |

Novelty and rate change use only earlier buckets (causal), checked by a test.

## Training and thresholds

- Chronological: train on the oldest `train_days` (7) of real (non-simulated) telemetry,
  validate on the following `validation_days` (1). No overlap, no shuffling.
- Unsupervised: labels are never used for fitting.
- Threshold: the `1 - alert_rate` quantile of validation scores (default 0.2% of validation
  windows), so the expected alert volume is chosen up front rather than tuned on outcomes.
- Versioned: each model records its version hash, periods, window counts, seed, threshold
  policy and library versions in `models/live_behavior/report.json` next to the database.
  Same data and seed give the same version and threshold (tested).
- Retraining: every `retrain_hours` (24); until there are at least `min_train_windows`
  (500) training windows the report says `insufficient_history`, the model is not used, and
  the worker retries hourly.

## False-alert rate

Measured, never assumed: validation alerts are matched to resolved incidents for the same host
and source. Incidents resolved as `confirmed_malicious` count as true; `false_positive`,
`benign` or `expected_activity` count as false. With no matching verdicts the report states
that the false-alert rate is **unknown**, not zero. Verdicts measure the model; they are not
used to tune it.

## How findings are presented

Model findings are `unusual`, severity `info`, and dashboard-only by default. Evidence lists
the score, the threshold and the three features that deviate most from the training medians
(robust z-scores). These are approximate diagnostics, not the forest's internal reasons.
