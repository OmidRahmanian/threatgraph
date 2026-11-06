"""Fixture -> ingest -> features -> train -> evaluate -> export -> API, in a temp directory."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import polars as pl
import pytest
from fastapi.testclient import TestClient

from tests.conftest import make_cfg, write_datasets_yaml
from threatgraph import pipeline
from threatgraph.config import load_models_config
from threatgraph.data.synthetic import SyntheticSpec, generate_fixture
from threatgraph.ml.metrics import threshold_counts
from threatgraph.serving.export import export_bundle
from threatgraph.serving.payloads import ServingContext
from threatgraph_api.main import Settings, create_app

M1 = "m1_isolation_forest"


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory):
    root = tmp_path_factory.mktemp("e2e")
    cfg = make_cfg(root)
    mcfg = load_models_config()
    generate_fixture(cfg.raw_path, SyntheticSpec(seed=42))
    pipeline.run_ingest(cfg)
    pipeline.run_features(cfg)
    pipeline.run_train(cfg, mcfg)
    pipeline.run_evaluate(cfg, mcfg)
    ctx = ServingContext(cfg, mcfg, public_ids=True)
    bundle = export_bundle(ctx, root / "export")
    settings = Settings()
    settings.datasets_config = str(write_datasets_yaml(root / "datasets.yaml", cfg))
    settings.dataset = cfg.name
    with TestClient(create_app(settings)) as client:
        yield cfg, mcfg, ctx, bundle, client


def test_quality_report_records_injected_issues(built) -> None:
    cfg, *_ = built
    q = json.loads(pipeline.quality_report_path(cfg).read_text())
    assert q["auth"]["rows_rejected"] == 5
    assert q["label_join"]["keys_unmatched"] == 1
    assert q["label_join"]["keys_ambiguous"] == 1
    assert q["redteam"]["duplicate_records_in_window"] == 1


def test_chronological_splits_and_no_test_leakage(built) -> None:
    cfg, mcfg, *_ = built
    preds = pl.read_parquet(pipeline.predictions_path(cfg))
    bounds = cfg.splits.boundaries_seconds()
    for split in ("train", "validation", "test"):
        part = preds.filter(pl.col("split") == split)
        lo, hi = bounds[split]
        assert part["window_start"].min() >= lo and part["window_start"].max() < hi
        assert part["label"].sum() > 0, f"{split} must contain known positives in the demo"
    for model_id in mcfg.models:
        meta = json.loads((pipeline.model_dir(cfg, model_id) / "metadata.json").read_text())
        assert meta["train_info"]["labels_used"] is False
        assert meta["train_info"]["n_train_rows"] == preds.filter(pl.col("split") == "train").height
        assert meta["threshold_policy"]["calibrated_on"] == "validation"


def test_score_table_reproduces_stored_operating_point(built) -> None:
    """What the browser slider does: recompute metrics from persisted scores."""
    _, mcfg, ctx, *_ = built
    for model_id in mcfg.models:
        table = ctx.score_table(model_id, "test")
        y = np.array([r[2] for r in table.rows])
        s = np.array([r[1] for r in table.rows])
        stored = ctx.model_metrics(model_id).splits["test"].operating_point
        recomputed = threshold_counts(y, s, table.calibrated_threshold)
        # Scores are rounded to 6 decimals in the table; counts must still agree.
        assert recomputed["alerts"] == stored.alerts
        assert recomputed["known_positive_alerts"] == stored.known_positive_alerts


def test_api_matches_static_export(built) -> None:
    *_, bundle, client = built
    out = Path(bundle["out_dir"])
    routes = {
        "metadata.json": "/api/v1/metadata",
        "summary.json": "/api/v1/summary",
        "models.json": "/api/v1/models",
        f"models/{M1}/metrics.json": f"/api/v1/models/{M1}/metrics",
        f"models/{M1}/scores/test.json": f"/api/v1/models/{M1}/scores?split=test",
        f"models/{M1}/predictions/test.json": f"/api/v1/models/{M1}/predictions?split=test&limit=100",
    }
    for rel, url in routes.items():
        r = client.get(url)
        assert r.status_code == 200, url
        assert r.json() == json.loads((out / rel).read_text()), rel
    assert bundle["total_bytes"] < 5 * 1024 * 1024


def test_every_payload_is_labeled_synthetic(built) -> None:
    *_, bundle, _ = built
    for rel in bundle["files"]:
        data = json.loads((Path(bundle["out_dir"]) / rel).read_text())
        assert data["provenance"]["mode_label"] == "Synthetic demo", rel
        assert data["provenance"]["is_synthetic"] is True


def test_explanations_are_grounded_in_window_events(built) -> None:
    _, _, ctx, bundle, client = built
    exp_bundle = json.loads(
        (Path(bundle["out_dir"]) / f"models/{M1}/explanations/test.json").read_text()
    )
    known = [e for e in exp_bundle["explanations"].values() if e["label"] == "known_redteam"]
    assert known, "export must include every known red-team test window"
    labeled_ids = ctx.labeled_event_ids
    for e in exp_bundle["explanations"].values():
        assert e["evidence_events"], e["window_id"]
        for ev in e["evidence_events"]:
            assert ev["src_principal"] == e["principal"]
            assert e["window_start"] <= ev["event_time_seconds"] < e["window_end"]
            assert ev["known_redteam"] == (ev["event_id"] in labeled_ids)
        if e["label"] == "known_redteam":
            assert any(ev["known_redteam"] for ev in e["evidence_events"])
    # API explanation for the same window is identical to the exported one.
    wid = known[0]["window_id"]
    assert (
        client.get(f"/api/v1/models/{M1}/explanations/{wid}").json()
        == exp_bundle["explanations"][wid]
    )


def test_api_validation_and_errors(built) -> None:
    *_, client = built
    assert client.get("/api/v1/health").json()["status"] == "ok"
    assert client.get("/api/v1/models/unknown_model/metrics").status_code == 404
    assert client.get(f"/api/v1/models/{M1}/predictions?limit=5000").status_code == 422
    assert client.get(f"/api/v1/models/{M1}/predictions?split=train").status_code == 422
    assert client.get(f"/api/v1/models/{M1}/explanations/w:U0@DOM1:3600").status_code == 404
    assert client.get("/api/v1/events?start=10&end=5").status_code == 422
    page1 = client.get("/api/v1/events?limit=3").json()
    page2 = client.get(f"/api/v1/events?limit=3&cursor={page1['next_cursor']}").json()
    ids = [r["event_id"] for r in page1["rows"] + page2["rows"]]
    assert ids == sorted(ids) and len(set(ids)) == 6
    r = client.get("/api/v1/summary")
    assert "max-age" in r.headers["cache-control"]
    assert client.post("/api/v1/summary").status_code == 405
