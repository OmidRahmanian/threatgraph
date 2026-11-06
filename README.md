# ThreatGraph AI

Explainable behavioral anomaly detection on authentication logs, with a rigorous evaluation
lab and an interactive website.

ThreatGraph AI ingests authentication events in the format of the **LANL Comprehensive,
Multi-Source Cyber-Security Events** dataset (Kent, 2015). It builds causal per-account
behavioral features, scores each account-hour with a statistical baseline and an Isolation
Forest, evaluates both on a strict chronological split against red-team labels, and shows the
results in a web app. In the app you can move the alert threshold, see metrics recompute from the
stored held-out scores, and inspect the raw events behind any alert.

> **Status: Phase 1 (vertical slice) complete.** The demo runs on a **deterministic synthetic
> fixture** and is labeled *Synthetic demo* everywhere. Real LANL mode has a working importer
> but has **not** been run against the real files yet, so no real-data performance is claimed.
> Network explorer (Phase 3) and incident replay (Phase 4) are not built; the UI marks them
> that way. See [What's implemented](#whats-implemented).

## Quick start

Prerequisites: Python ≥ 3.11 (3.12 tested) with [uv](https://docs.astral.sh/uv/), Node.js 24, npm.
No GPU, paid API or LLM is needed.

```bash
make setup     # .venv + editable install, npm ci
make demo      # fixture → ingest → features → train → evaluate → export (~20 s)
make web       # http://localhost:3000/threatgraph  (reads the static export)
```

Run stage by stage instead:

```bash
python scripts/generate_demo_data.py --seed 42   # writes data/demo/raw/{auth,redteam}.txt.gz
python scripts/build_features.py --dataset demo  # ingests if needed, then builds features
python scripts/train.py --dataset demo
python scripts/evaluate.py --dataset demo        # prints artifacts/demo/reports/evaluation.md
python scripts/export_demo.py --dataset demo     # → apps/web/public/threatgraph-data/demo/v1/
```

(Use `.venv/bin/python` or activate the venv.)

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
make benchmark   # in-process API latency → artifacts/demo/reports/api_benchmark.json
```

## Using the real LANL data

ThreatGraph never downloads LANL data for you.

1. Fill in LANL's data-use form at <https://csr.lanl.gov/data/cyber1/> and download
   `auth.txt.gz` and `redteam.txt.gz`.
2. Put them in `data/raw/lanl/`. That path is git-ignored and excluded from Docker builds, so
   never commit or redistribute the files.
3. `python scripts/ingest_lanl.py --inspect-redteam` prints red-team records per day. Pick a
   `time_window` and split days in `configs/datasets.yaml` so validation and test both contain
   red-team records.
4. `python scripts/run_pipeline.py --dataset lanl`. Ingest streams the 7 GB file in bounded
   blocks and stops at the window end.
5. Build the site with `NEXT_PUBLIC_TG_DATASET=lanl`. In LANL mode the export replaces
   identifiers with salted aliases.

If the files are missing, the importer prints these instructions and the demo keeps working.

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
| Website: overview + ML Experiment Lab (threshold slider, PR curve, score distribution, ranked windows, evidence viewer, model card) | ✅ |
| CI workflow, Dockerfile/compose | ✅ written · ⚠️ Docker build not yet verified |
| Run on real LANL data | ⏳ importer ready, not yet run |
| Graph construction, explorer, graph features, ablation | ⏳ Phase 3 |
| Incident replay, methodology page | ⏳ Phase 4 |
| Flows/DNS/process, drift monitor, bootstrap CIs, supervised model | ⏳ Phase 5 (optional) |

## Architecture

```
data/demo/raw/*.txt.gz ─┐                          ┌─> artifacts/<ds>/models/*  metrics.json
data/raw/lanl/*.txt.gz ─┴─> ingest ─> features ─> train ─> evaluate ─┐
                          (Parquet,   (Parquet)   (scores)   (report) │
                           DQ report,                                  ├─> FastAPI /api/v1/*
                           labels)                                     └─> static JSON bundle ─> Next.js site
```

- `packages/threatgraph/`: Python library. `data/` covers ingest, schema, red-team join,
  features, and the synthetic fixture. `ml/` holds the models and metrics. `serving/` holds the
  response schemas, the payload builders shared by the API and the export, and the exporter.
- `apps/api/`: FastAPI app (read-only).
- `apps/web/`: Next.js App Router, TypeScript, Tailwind v4, Recharts. Built as a static export.
- `configs/`: dataset and model configs. Every artifact records their hash.
- `docs/`: [architecture](docs/architecture.md), [data dictionary](docs/data_dictionary.md),
  [modeling](docs/modeling.md), [evaluation](docs/evaluation.md),
  [limitations](docs/limitations.md), [deployment](docs/deployment.md),
  [model card](docs/model_card.md).

Results are never typed into docs by hand. `scripts/evaluate.py` writes
`artifacts/<dataset>/reports/evaluation.md`, and the website reads the same `metrics.json`.

## Embedding in a personal website

The UI is a self-contained route segment (`/threatgraph`, `/threatgraph/lab`) built as static
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
