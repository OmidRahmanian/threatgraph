# Architecture

## Data flow

```
raw text (.txt.gz, LANL format)
   │  pyarrow incremental CSV reader, gzip streamed, block_size bounded
   ▼
validate (Polars) ── rejects → data-quality report (reasons + first 10 examples)
   │  `?`/"" → null · event_id = accepted-row ordinal in file order · time window filter
   ▼
data/processed/<ds>/auth/day=NNNNN/part-*.parquet      (zstd, hive-partitioned by relative day)
data/processed/<ds>/redteam.parquet
data/processed/<ds>/labels.parquet                      (event_id → red-team record, multiplicity)
data/processed/<ds>/reports/data_quality.json           (counts, missingness, duplicates, distincts)
   │
   ▼  build_window_features (Polars, time chunks with carried state)
data/processed/<ds>/features/windows.parquet            (one row per principal × window)
data/processed/<ds>/features/feature_manifest.json
   │
   ├─▶ build graph (same chunks)
   │   data/processed/<ds>/graph/edges/*.parquet         (window × account × src → dst)
   │   data/processed/<ds>/graph/{entities,links}.parquet
   │
   ▼  train (fit on train split; calibrate on validation)
artifacts/<ds>/models/<model_id>/{model.joblib, metadata.json}
artifacts/<ds>/predictions.parquet                      (scores for train/validation/test)
   │
   ▼  evaluate
artifacts/<ds>/metrics.json · reports/evaluation.md · runs/<stage>.json (time, peak RSS, hash)
   │
   ├─▶ FastAPI  (apps/api)       GET /api/v1/...    builds payloads on request
   └─▶ export   (scripts/export_demo.py)            same payload builders → static JSON
                                                     apps/web/public/threatgraph-data/<ds>/v1/
                                                          │
                                                          ▼
                                       Next.js static site (client-side fetch; API optional)
```

## Why these choices

- **Batch first, serve small.** Heavy work (parsing, features, training) happens offline. The
  public site only reads a static bundle (capped at 12 MB, 1 MB per file, fetched lazily per
  page), so it never trains or scans raw data.
- **pyarrow streaming + Polars.** Ingest memory is bounded by the block size, not the file size.
  The real `auth.txt.gz` is about 7 GB compressed and roughly 1 billion rows. When the file is
  time-sorted and the window has an end, ingest stops early.
- **Chunked features and graph.** Features and graph tables are built in time chunks
  (`features.chunk_seconds`). First-seen sets, last outcomes and recent arrivals are carried
  between chunks, so output does not depend on chunk size and peak memory follows one chunk
  plus the window table (`docs/real_data.md`).
- **Precomputed graph tables.** Graph queries read a per-window edge table sorted by time
  instead of raw events, so a bounded subgraph query takes tens of milliseconds on the demo.
- **DuckDB** computes whole-table statistics (distincts, duplicates) over the Parquet files
  with a memory cap, so they never load into Python memory.
- **One payload layer** (`serving/payloads.py`) feeds both the API and the static export. An
  integration test asserts that API responses equal the exported JSON.
- **Stale inputs are refused.** Each stage records a fingerprint of the config sections its
  output depends on, plus its upstream stage's fingerprint (`pipeline.fingerprint_inputs`).
  Training, evaluation, the API and the exporter refuse inputs built under a different
  configuration and name the changed section (for example, editing the split days requires
  re-running features, because the split column is computed there). Settings that cannot
  change outputs, such as chunk and block sizes, are left out. Replacing raw files without
  changing the config is not detected, so re-run ingest after that.
- **Static export** lets the site be dropped into any existing personal website, optionally
  under a sub-path. Setting `NEXT_PUBLIC_TG_API_BASE` switches it to the live API with no
  code change.

## Reproducibility

- The fixture is deterministic: a seeded numpy `Generator`, stable sorting, and gzip `mtime=0`.
  A unit test checks that the file hash is identical across runs.
- Every artifact records a config hash (dataset and model configs, key-order independent),
  library versions, seeds, and split boundaries.
- `event_id` is assigned before the time-window filter, so ids stay stable when the window
  changes.

## Resource profile (consumer workstation)

The `runs/*.json` and `benchmarks.json` files record wall time and peak RSS for each stage of the
last run, and the Overview page shows them. The demo pipeline needs well under 1 GB of memory and
no GPU.
For real LANL subsets, feature building is the memory-heavy stage, because novelty uses
first-seen times per (principal, host). Start with a window of a few days. Machine accounts are
excluded from per-principal features by default.

## Live Monitoring Mode

A second, separate data flow for telemetry from your own servers ([docs/live/](live/README.md)):

```
agent (stdlib only, on each server)          external probe (another machine)
  tail logs with rotation · /proc · systemd     HTTP checks · TLS expiry
  parse → privacy filters → batch               direct Telegram/SMTP alerts
        │ HTTPS, bearer token, gzip                    │ optional report (probe role)
        ▼                                              ▼
live-ingest   auth → source binding → size/rate limits → validation → INSERT OR IGNORE
        │
        ▼
SQLite (WAL)  events · agents · incidents · incident_events · notifications · sessions
        │
        ▼
live-worker   rules + behavioural model → incidents (dedup, escalation, auto-resolve)
              → notification outbox → Telegram / SMTP (retries) · retention · retraining
        │
        ▼
live-dashboard (/live-api, session auth) → /threatgraph/live (same-origin static page)
```

- **Modes do not mix.** Live code lives in `packages/threatgraph/live/` and
  `apps/live/threatgraph_live/`; the research API, payloads and static export are untouched
  and never read live data. Shared pieces: the robust scaling and Isolation Forest helpers,
  the website shell and design tokens.
- **Agent depends on nothing.** The agent, probe, parsers and notification channels use only
  the standard library (a test enforces it), so they run on any server with Python 3.11.
- **SQLite behind an interface.** `LiveStore` is the only storage access; a Postgres backend
  could replace it for several hosts with heavy traffic.
- **Deterministic first.** Rules decide incidents and severity; the model adds `info`
  findings; the optional LLM only writes advisory notes.
- **Missing data is explicit.** Intervals with no agent reporting are `null` in every API and
  drawn as gaps.
