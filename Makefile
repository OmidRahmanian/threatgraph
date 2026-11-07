PY ?= .venv/bin/python
DATASET ?= demo

.PHONY: setup demo pipeline api web web-build test lint typecheck e2e benchmark docker ci clean

setup:            ## Create the Python venv and install web dependencies
	uv venv --python 3.12 .venv
	uv pip install --python $(PY) -e ".[dev]"
	cd apps/web && npm ci

demo: pipeline    ## Generate the synthetic fixture and run every stage

pipeline:
	$(PY) scripts/run_pipeline.py --dataset $(DATASET) --seed 42

api:              ## Serve the read-only API on :8000 (docs at /api/docs)
	TG_DATASET=$(DATASET) $(PY) -m uvicorn threatgraph_api.main:app --port 8000 --reload

web:              ## Next.js dev server on :3000 (reads the static export by default)
	cd apps/web && npm run dev

web-build:
	cd apps/web && npm run build

test:             ## Python unit + integration tests, then frontend unit tests
	$(PY) -m pytest
	cd apps/web && npm test

lint:
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .
	cd apps/web && npm run lint

typecheck:
	$(PY) -m mypy
	cd apps/web && npm run typecheck

e2e: web-build    ## Playwright against the static export (run `make demo` first)
	cd apps/web && npx playwright test

benchmark:        ## API latency report, then re-export so the site shows it
	$(PY) scripts/benchmark_api.py --dataset $(DATASET)
	$(PY) scripts/export_demo.py --dataset $(DATASET)

docker: web-build  ## API + nginx in containers (run `make demo` first); ports via TG_API_PORT/TG_WEB_PORT
	docker compose up --build

ci: lint typecheck test e2e

clean:
	rm -rf data/processed/demo artifacts/demo data/demo/raw apps/web/public/threatgraph-data apps/web/out apps/web/.next
