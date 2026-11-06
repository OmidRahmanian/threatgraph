"""Measure in-process API latency for the main read endpoints.

    python scripts/benchmark_api.py --dataset demo --repeats 50

Uses FastAPI's TestClient (no network), so the numbers measure serialization and artifact
access, not network or server overhead. Results go to artifacts/<dataset>/reports/.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import time

from fastapi.testclient import TestClient

from threatgraph.config import load_dataset_config


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="demo")
    ap.add_argument("--repeats", type=int, default=50)
    args = ap.parse_args()
    os.environ["TG_DATASET"] = args.dataset
    os.environ["TG_RATE_LIMIT_PER_MINUTE"] = "1000000"
    from threatgraph_api.main import create_app

    cfg = load_dataset_config(args.dataset)
    results = {}
    with TestClient(create_app()) as client:
        model = client.get("/api/v1/models").json()["models"][-1]["model_id"]
        top = client.get(f"/api/v1/models/{model}/predictions?limit=1").json()["rows"][0][
            "window_id"
        ]
        routes = {
            "summary": "/api/v1/summary",
            "metrics": f"/api/v1/models/{model}/metrics",
            "scores_test": f"/api/v1/models/{model}/scores?split=test",
            "predictions": f"/api/v1/models/{model}/predictions?limit=50",
            "explanation": f"/api/v1/models/{model}/explanations/{top}",
            "events_page": "/api/v1/events?limit=100",
        }
        for name, url in routes.items():
            client.get(url)  # warm caches
            times = []
            for _ in range(args.repeats):
                t0 = time.perf_counter()
                r = client.get(url)
                times.append((time.perf_counter() - t0) * 1000)
                r.raise_for_status()
            times.sort()
            results[name] = {
                "url": url,
                "p50_ms": round(statistics.median(times), 2),
                "p95_ms": round(times[int(0.95 * (len(times) - 1))], 2),
                "response_bytes": len(r.content),
            }
    out = cfg.artifacts_path / "reports" / "api_benchmark.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps({"dataset": cfg.name, "repeats": args.repeats, "endpoints": results}, indent=2)
        + "\n"
    )
    for name, r in results.items():
        print(
            f"{name:12s} p50 {r['p50_ms']:8.2f} ms   p95 {r['p95_ms']:8.2f} ms   {r['response_bytes']:>9,} B"
        )
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
