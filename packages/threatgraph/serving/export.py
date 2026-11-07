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
    graph/windows/{split}/index.json       GET /api/v1/graph/windows?split=
    graph/windows/{slug}.json              GET /api/v1/graph/windows/{window_id}
    entities/{slug}.json                   GET /api/v1/entities/{entity_id}

`slug` is the id with every character outside [A-Za-z0-9._-] replaced by "_"
(apps/web/src/lib/data.ts uses the same rule). Only entities that appear in an exported
window graph at hop 0 or 1 are written; hop-2 entity details need the live API.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from threatgraph.pipeline import EVAL_SPLITS
from threatgraph.serving.payloads import ServingContext

EXPORT_PREDICTION_LIMIT = 100
# Public payload budget. Pages fetch files lazily, so the per-file cap is what a visitor waits
# for; the total bounds what a deployment ships.
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024


def static_slug(window_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", window_id)


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
    index = ctx.graph_window_index("test")
    put("graph/windows/test/index.json", index)
    entity_ids: set[str] = set()
    slugs: dict[str, str] = {}
    for w in index.windows:
        slug = static_slug(w.window_id)
        if slugs.setdefault(slug, w.window_id) != w.window_id:
            raise RuntimeError(f"static slug collision: {w.window_id} vs {slugs[slug]}")
        gw = ctx.graph_window(w.window_id)
        put(f"graph/windows/{slug}.json", gw)
        entity_ids.update(n.node_id for n in gw.graph.nodes if n.hop <= 1)
        entity_ids.update(p.principal_id for p in gw.graph.principals if p.hop <= 1)
    for e in sorted(entity_ids):
        slug = static_slug(e)
        if slugs.setdefault(slug, e) != e:
            raise RuntimeError(f"static slug collision: {e} vs {slugs[slug]}")
        put(f"entities/{slug}.json", ctx.entity(e))
    total = sum(sizes.values())
    put("benchmarks.json", ctx.benchmarks(export_payload_bytes=total))
    total = sum(sizes.values())
    big = {k: v for k, v in sizes.items() if v > MAX_FILE_BYTES}
    if big:
        raise RuntimeError(f"export files over the {MAX_FILE_BYTES} byte per-file cap: {big}")
    if total > MAX_BUNDLE_BYTES:
        raise RuntimeError(
            f"export bundle is {total} bytes, over the {MAX_BUNDLE_BYTES} byte budget"
        )
    return {"out_dir": str(out_dir), "files": sizes, "total_bytes": total}
