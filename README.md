# ThreatGraph AI

Explainable behavioral anomaly detection on authentication logs, with a rigorous evaluation
lab, an interactive website, and a live monitoring mode for your own servers.

ThreatGraph AI has two clearly separated modes that share one codebase:

- **Research Mode.** Historical authentication events in the format of the **LANL
  Comprehensive, Multi-Source Cyber-Security Events** dataset (Kent, 2015). It builds causal
  per-account behavioral and graph features, scores each account-hour with a statistical
  baseline and two Isolation Forests (with and without graph features), evaluates them on a
  strict chronological split against red-team labels, and shows the results in a web app.
  You can move the alert threshold, see metrics recompute from the stored held-out scores,
  inspect the raw events behind any alert, explore which computers an alerted account moved
  between, and replay documented red-team incidents against each model's alerts.
- **Live Monitoring Mode.** A stdlib-only agent ships nginx, SSH/sudo, syslog, resource,
  systemd, Docker and file-integrity telemetry from your own Linux servers over authenticated
  TLS. Deterministic rules (plus an optional behavioural model) open deduplicated incidents
  with documented severity, Telegram and e-mail notifications go out with retries and
  cooldowns, an external probe catches whole-server outages, an optional local LLM writes
  evidence-cited investigation notes, and a private dashboard at `/threatgraph/live` shows it
  all. See [docs/live/](docs/live/README.md).

Live events, incidents and notifications never mix with research results.

> **Status.** Research Mode: working synthetic demo with model comparison, network map,
> incident replay, methodology page, drift monitor and bootstrap confidence intervals; real
> LANL mode is tested end to end on LANL-format fixtures but has **not** been run on the
> official files, and the Lab shows it as *pending*. Live Monitoring Mode: implemented and
> tested with simulated scenarios and local Telegram/SMTP stand-ins, and run locally in Docker
> with the real agent shipping a real nginx container's logs; it has **not** been deployed to
> a VPS or sent to a real Telegram chat or mailbox yet. See
> [What's implemented](#whats-implemented).

## Quick start

Prerequisites: Python ≥ 3.11 (3.12 tested) with [uv](https://docs.astral.sh/uv/), Node.js 24, npm.
No GPU, paid API or LLM is needed.

```bash
make setup     # .venv + editable install, npm ci
make demo      # fixture → ingest → features → graph → train → evaluate → export (~10 s)
make web       # http://localhost:3000/threatgraph  (reads the static export)
```

Run stage by stage instead:

```bash
python scripts/generate_demo_data.py --seed 42   # writes data/demo/raw/{auth,redteam}.txt.gz
python scripts/build_features.py --dataset demo  # ingests if needed, then builds features
python scripts/build_graph.py --dataset demo     # edge, entity and link tables
python scripts/train.py --dataset demo
python scripts/evaluate.py --dataset demo        # prints artifacts/demo/reports/evaluation.md
python scripts/export_demo.py --dataset demo     # → apps/web/public/threatgraph-data/demo/v1/
```

(Use `.venv/bin/python` or activate the venv.)

Live monitoring (simulated data on your machine; real deployment: [docs/deployment.md](docs/deployment.md#live-monitoring)):

```bash
export TG_LIVE_DB=data/live/live.db
.venv/bin/threatgraph-live simulate ssh_bruteforce && .venv/bin/threatgraph-live worker --once
docker compose --profile live up -d --build        # ingestion, dashboard API, worker, Caddy TLS
```

Run the live API and point the website at it:

```bash
make api                                                  # http://localhost:8000/api/docs
NEXT_PUBLIC_TG_API_BASE=http://localhost:8000/api/v1 make web
```

Tests and checks:

```bash
make test        # pytest (unit + integration) + vitest
make lint        # ruff check/format, eslint
make typecheck   # mypy + tsc
make e2e         # Playwright on desktop + mobile against the static build
make benchmark   # in-process API latency → artifacts/demo/reports/api_benchmark.json, then re-export
make docker      # read-only API + nginx in containers (see docs/deployment.md)
```

## Using the real LANL data

ThreatGraph never downloads LANL data for you.

1. Fill in LANL's data-use form at <https://csr.lanl.gov/data/cyber1/> and download
   `auth.txt.gz` and `redteam.txt.gz`.
2. Put them in `data/raw/lanl/`. That path is git-ignored and excluded from Docker builds, so
   never commit or redistribute the files.
3. `python scripts/ingest_lanl.py --inspect-redteam` prints red-team records per day and
   suggests a `time_window` and split days where validation and test both contain red-team
   records. Paste them into `configs/datasets.yaml`.
4. `python scripts/verify_lanl.py` checks the files (add `--full --sha256` for a complete
   pass), and `python scripts/run_pipeline.py --dataset lanl_smoke` runs the first four days
   as a throughput and memory check.
5. `python scripts/run_pipeline.py --dataset lanl`. Ingest streams the 7 GB file in bounded
   blocks and stops at the window end; features and graph run in one-hour chunks.
6. Build the site with `NEXT_PUBLIC_TG_DATASET=lanl`. In LANL mode the export replaces
   identifiers with salted aliases.

If the files are missing, the importer prints these instructions and the demo keeps working.
Details, the real-data-mode guarantees and a scale rehearsal: [docs/real_data.md](docs/real_data.md).

## What's implemented

| Area | Status |
|---|---|
| Deterministic LANL-format synthetic fixture (campaigns, benign look-alikes, incomplete labels, malformed rows) | ✅ |
| Streaming auth/red-team ingest, `?`→null, validation, data-quality report, day-partitioned Parquet | ✅ |
| Red-team composite-key join with duplicate/ambiguous/unmatched reporting | ✅ |
| Causal per-(account, hour) features with leakage test | ✅ |
| M0 robust z-score baseline, M1 Isolation Forest, common model interface, persisted artifacts | ✅ |
| Chronological train/validation/test; validation-calibrated threshold; AP, P@K, known-label recall, alert volume, latency | ✅ |
| Versioned read-only FastAPI (`/api/v1`), input bounds, rate limit, CORS, OpenAPI | ✅ |
| Static export with the same payloads (parity tested) | ✅ |
| Website: overview + ML Experiment Lab (threshold slider, PR curve, score distribution, ranked windows, evidence viewer, model card, ablation) | ✅ |
| Entity graph tables, bounded graph/entity API, graph features, M3 + M1-vs-M3 ablation | ✅ (ablation not blind on the demo) |
| Network map: alerted and red-team accounts with their computers, zoom/pan, search, model and day filters, links to hours and incidents | ✅ |
| Hour explorer: window list, directed graph, edge evidence, entity panel, table view | ✅ |
| Incident API, replay page (alerts revealed at window end), generated write-ups | ✅ implemented and tested on the synthetic demo |
| Methodology page, model cards (Markdown), comparison CSV, API latency in the site | ✅ implemented |
| Dockerfile and Compose stack (read-only API + nginx) | ✅ implemented and verified locally; see [deployment notes](docs/deployment.md#docker) |
| CI workflow: Python lint/types/tests, web build and browser tests | ✅ [passed on published `main`](https://github.com/OmidRahmanian/threatgraph/actions/runs/42347825810) |
| Docker smoke-test CI job | ✅ configured on this branch; its GitHub run is pending |
| Drift monitor (API and Experiment Lab) | ✅ implemented |
| Account cluster-bootstrap confidence intervals and paired model differences | ✅ implemented |
| Explanation faithfulness study (feature deletion test) | ✅ implemented |
| Supervised-model label-availability gate | ✅ implemented; decision and reason recorded in metrics.json |
| Trained supervised model (M2) | ⏳ optional, not implemented; the current demo has too few training labels |
| Flows/DNS/process log ingestion and features | ⏳ optional, not implemented |
| GNN benchmark | ⏳ optional, not implemented; see [modeling notes](docs/modeling.md) |
| Chunked features/graph, split suggestion, capped score tables, real-data-mode test, scale rehearsal | ✅ implemented; real LANL memory use remains unverified |
| Run on official LANL data | ⏳ importer implemented; actual evaluation awaits user-downloaded files |
| Raw-file integrity check (gzip completeness, columns, sorted time, sha256 vs last run), `lanl_smoke` window | ✅ implemented and tested on fixtures |
| Research dataset status (API, export, Lab panel): real LANL shown as pending until evaluated | ✅ |
| **Live:** stdlib-only agent (rotation-aware tailing, ack-based commits, bounded buffer, backoff, privacy filters), collectors for nginx, auth, syslog, metrics, systemd, Docker, file integrity | ✅ tested; run locally against a real nginx container |
| **Live:** authenticated TLS ingestion (per-agent tokens bound to source, limits, dedup), SQLite store with retention and backup | ✅ |
| **Live:** 21 deterministic rules, incidents with documented severity, dedup, escalation, auto-resolve, verdicts | ✅ tested on simulated scenarios |
| **Live:** behavioural Isolation Forest on a dedicated feature pipeline, chronological training, false-alert rate from verdicts | ✅ tested on simulated history; no real-traffic model yet |
| **Live:** Telegram and SMTP notifications with outbox, retries, cooldowns, recovery messages | ✅ tested against local stand-ins; real delivery unverified |
| **Live:** external probe with direct alerts; GitHub Actions template | ✅ probe tested; template not run |
| **Live:** optional Ollama investigation with prompt-injection and citation controls | ✅ tested with fake models; not run with a real model |
| **Live:** private dashboard `/threatgraph/live` (sign-in, health, availability, traffic, incidents, timeline) | ✅ checked in a browser on desktop and mobile |
| **Live:** Compose `live` profile, Caddy TLS, hardened containers, agent systemd unit, backups | ✅ verified locally (colima); not deployed to a VPS |

The linked CI run covers commit `ad6d4d8` on published `main`. It does not verify the newer
replay, research extensions or Docker CI job on this branch; those need a run after publishing
the current changes. Phase 4's replay and methodology features are implemented. Phase 5 is
partially implemented, with its completed research features and optional extensions listed
separately above.

## Architecture

```
data/demo/raw/*.txt.gz ─┐                          ┌─> artifacts/<ds>/models/*  metrics.json
data/raw/lanl/*.txt.gz ─┴─> ingest ─> features ─> train ─> evaluate ─┐
                          (Parquet,   (Parquet)   (scores)   (report) │
                           DQ report,  └─> graph (edges, entities) ───┤
                           labels)                                     ├─> FastAPI /api/v1/*
                                                                       └─> static JSON bundle ─> Next.js site
```

- `packages/threatgraph/`: Python library. `data/` covers ingest, schema, red-team join,
  features, split suggestion and the synthetic fixture. `graph/` builds and queries the entity
  graph. `ml/` holds the models and metrics. `serving/` holds the
  response schemas, the payload builders shared by the API and the export, and the exporter.
- `packages/threatgraph/live/`: Live Monitoring Mode (agent, parsers, privacy, store, rules,
  incidents, notifications, behavioural model, probe, LLM investigation).
- `apps/api/`: FastAPI app (read-only, research).
- `apps/live/`: live ingestion API, private dashboard API, worker and `threatgraph-live` CLI.
- `apps/web/`: Next.js App Router, TypeScript, Tailwind v4, Recharts. Built as a static export.
- `configs/`: dataset and model configs. Every artifact records their hash.
- `docs/`: [architecture](docs/architecture.md), [data dictionary](docs/data_dictionary.md),
  [modeling](docs/modeling.md), [evaluation](docs/evaluation.md),
  [limitations](docs/limitations.md), [deployment](docs/deployment.md),
  [model card](docs/model_card.md), [graph](docs/graph.md), [real data](docs/real_data.md),
  [live monitoring](docs/live/README.md).

Results are never typed into docs by hand. `scripts/evaluate.py` writes
`artifacts/<dataset>/reports/evaluation.md`, and the website reads the same `metrics.json`.
The exporter also writes `model_comparison.csv`, `model_cards/*.md` and
`incident_writeups.md` to `artifacts/<dataset>/reports/` and to the site's `downloads/`.

## Embedding in a personal website

The UI is a self-contained route segment (`/threatgraph`, `/threatgraph/lab`,
`/threatgraph/network`, `/threatgraph/explorer`, `/threatgraph/replay`, `/threatgraph/methodology`) built as static
files. Set `NEXT_PUBLIC_BASE_PATH=/projects` (for example), run `npm run build`, and copy
`apps/web/out/` to that path on your host. See [docs/deployment.md](docs/deployment.md).

## Data citation

A. D. Kent, "Comprehensive, Multi-Source Cyber-Security Events," Los Alamos National
Laboratory, 2015. doi:10.17021/1179829. Historical research data: not live threat
intelligence and not live website traffic.

## Troubleshooting

- **Website shows "Could not load data".** Run `make demo` to produce
  `apps/web/public/threatgraph-data/`.
- **`TS2344 ... does not satisfy the constraint`.** Run `npm run typecheck`, which first
  regenerates Next's route types.
- **API returns 503.** Artifacts are missing for `TG_DATASET`. Run the pipeline for that
  dataset.
- **Playwright cannot find a browser.** Run `cd apps/web && npx playwright install chromium`.
