# Data dictionary

## Source files (LANL format, header-less, comma-separated)

| File | Columns (in order) |
|---|---|
| `auth.txt.gz` | time, source user@domain, destination user@domain, source computer, destination computer, authentication type, logon type, authentication orientation, success/failure |
| `redteam.txt.gz` | time, user@domain, source computer, destination computer |

`time` is integer seconds from an arbitrary epoch: there is no calendar date and no known
clock time. `?` marks a missing value. Identifiers (`U123@DOM1`, `C17693`, `C17693$@DOM1`
for machine accounts) are de-identified pseudonyms, preserved verbatim.

Only `auth` and `redteam` are ingested so far. `flows`, `dns` and `proc` are planned (Phase 5).

## Validation rules (auth)

| Reject reason | Rule |
|---|---|
| `wrong_column_count` | not exactly 9 fields |
| `non_integer_time` / `negative_time` | time not a non-negative integer |
| `invalid_outcome` | outcome not in {Success, Fail, ?} |
| `missing_source_principal` | source user is `?` or empty |

Rows are never silently repaired. Every rejection is counted by reason in
`reports/data_quality.json`, with the first 10 examples. That report stays local and is never
exported.

## Internal auth event schema (`auth/day=*/part-*.parquet`)

| Column | Type | Notes |
|---|---|---|
| `event_id` | int64 | ordinal of the accepted row in source order; stable across time windows |
| `event_family` | str | `auth` |
| `event_time_seconds` | int64 | relative seconds |
| `day` | int32 (partition) | `event_time_seconds // 86400` |
| `src_principal`, `dst_principal` | str? | `user@domain`, verbatim |
| `src_computer`, `dst_computer` | str? | verbatim |
| `auth_type`, `logon_type`, `auth_orientation`, `outcome` | str? | `?` → null |
| `dataset_mode` | str | `synthetic` or `lanl` (provenance) |

The schema is OCSF-*inspired* (event family, actor/target, provenance). It is not validated
against OCSF, and no OCSF compliance is claimed.

## Labels (`labels.parquet`)

| Column | Notes |
|---|---|
| `event_id` | labeled auth event |
| `label_source` | `synthetic_redteam` or `lanl_redteam` |
| `redteam_record_id` | first red-team record with this key |
| `match_multiplicity` | number of auth events sharing the key (> 1 means ambiguous; all are labeled) |

Match key: `(time, principal, src_computer, dst_computer)`. By default the principal is the
auth **source** principal (`redteam.user_field` in config). Unmatched red-team keys are
reported. An auth event without a match is **unlabeled**, not benign.

## Window features (`features/windows.parquet`)

Scoring unit: `(src_principal, window_start)` with `window_seconds = 3600`, scored at
`window_end`. Machine accounts (`…$@…`), `ANONYMOUS…` and LogOff events are excluded from
per-principal features. They still count toward global computer-edge novelty.

| Feature | Definition |
|---|---|
| `n_events` | non-LogOff auth events in the window |
| `n_fail` | failures |
| `fail_ratio` | `n_fail / n_events` |
| `n_distinct_dst` | distinct destination computers (fan-out) |
| `n_distinct_src` | distinct source computers |
| `n_remote` | events with `src_computer ≠ dst_computer` |
| `n_novel_dst` | destinations this principal had never used before (first observation falls in this window) |
| `novel_dst_ratio` | `n_novel_dst / n_distinct_dst` |
| `n_novel_src` | first-seen source computers for this principal |
| `n_novel_edge` | computer→computer pairs observed for the first time by anyone, via this principal's events |
| `n_novel_auth_type` | first use of an authentication type by this principal |
| `n_post_fail_success` | successes whose previous event on the same (principal, destination) was a failure |
| `ntlm_ratio` | share of NTLM events |
| `max_burst` | max events in any 5-minute sub-window |
| `z_events`, `z_distinct_dst` | `(x − mean) / (std + 1)` over the principal's previous ≤ 24 active windows; 0 with no history |
| `log_prior_windows` | `log(1 + #earlier active windows)` (cold start indicator) |

Identifier columns (`window_id`, `src_principal`, `window_start`, `window_end`, `day`, `split`)
and label columns (`label`, `n_labeled_events`, `first_labeled_event_seconds`) are kept
separate from the feature list. Labels are never model inputs.

## Predictions (`artifacts/<ds>/predictions.parquet`)

The ID and label columns plus `score__<model_id>` for every window in train, validation and
test. Higher scores mean more anomalous.
