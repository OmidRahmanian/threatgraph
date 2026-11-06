"""Static export of the public demo bundle.

The file layout mirrors the API routes under `/api/v1`, so the website can read either:

    metadata.json                          GET /api/v1/metadata
    summary.json                           GET /api/v1/summary
    models.json                            GET /api/v1/models
    benchmarks.json                        GET /api/v1/benchmarks
    models/{id}/metrics.json               GET /api/v1/models/{id}/metrics
    models/{id}/scores/{split}.json        GET /api/v1/models/{id}/scores?split=
    models/{id}/predictions/{split}.json   GET /api/v1/models/{id}/predictions?split=&limit=100
    models/{id}/explanations/{split}.json  bundle of GET /api/v1/models/{id}/explanations/{window}
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from threatgraph.pipeline import EVAL_SPLITS
from threatgraph.serving.payloads import ServingContext

EXPORT_PREDICTION_LIMIT = 100
MAX_BUNDLE_BYTES = 5 * 1024 * 1024  # public payload budget


def _write(path: Path, payload: BaseModel) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = payload.model_dump_json()
    path.write_text(data)
    return len(data.encode())


def export_bundle(ctx: ServingContext, out_dir: Path) -> dict[str, Any]:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    sizes: dict[str, int] = {}

    def put(rel: str, payload: BaseModel) -> None:
        sizes[rel] = _write(out_dir / rel, payload)

    put("metadata.json", ctx.metadata())
    put("summary.json", ctx.summary())
    put("models.json", ctx.model_list())
    for model_id in ctx.mcfg.models:
        put(f"models/{model_id}/metrics.json", ctx.model_metrics(model_id))
        for split in EVAL_SPLITS:
            put(f"models/{model_id}/scores/{split}.json", ctx.score_table(model_id, split))
            put(
                f"models/{model_id}/predictions/{split}.json",
                ctx.predictions_page(model_id, split, None, EXPORT_PREDICTION_LIMIT),
            )
        put(f"models/{model_id}/explanations/test.json", ctx.explanation_bundle(model_id, "test"))
    total = sum(sizes.values())
    put("benchmarks.json", ctx.benchmarks(export_payload_bytes=total))
    total = sum(sizes.values())
    if total > MAX_BUNDLE_BYTES:
        raise RuntimeError(
            f"export bundle is {total} bytes, over the {MAX_BUNDLE_BYTES} byte budget"
        )
    return {"out_dir": str(out_dir), "files": sizes, "total_bytes": total}
