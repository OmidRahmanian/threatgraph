"""Supervised M2 (when the gate permits), model skipping without process logs, and the
graph-embedding features. Synthetic fixture only."""

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
from threatgraph.ml.models import IsolationForestModel, SupervisedGBMModel
from threatgraph.serving.payloads import ServingContext
from threatgraph_api.main import Settings, create_app

M2, M4, M5 = "m2_supervised_gbm", "m4_isolation_forest_process", "m5_isolation_forest_embedding"


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory):
    """No proc log configured, and a gate low enough for the demo's training labels."""
    root = tmp_path_factory.mktemp("ext")
    cfg = make_cfg(root, files={"auth": "auth.txt.gz", "redteam": "redteam.txt.gz"})
    generate_fixture(cfg.raw_path, SyntheticSpec(seed=42))
    mcfg = load_models_config().model_copy(
        update={
            "supervised_gate": load_models_config().supervised_gate.model_copy(
                update={"min_positive_windows": 1, "min_positive_accounts": 1}
            )
        }
    )
    pipeline.run_ingest(cfg)
    pipeline.run_features(cfg)
    pipeline.run_graph(cfg)
    pipeline.run_train(cfg, mcfg)
    metrics = pipeline.run_evaluate(cfg, mcfg)
    return root, cfg, mcfg, metrics


def test_models_without_inputs_are_skipped_with_a_reason(built) -> None:
    _, cfg, mcfg, metrics = built
    active, skipped = pipeline.active_models(cfg, mcfg)
    assert M4 not in active.models and "proc.txt.gz" in skipped[M4]
    assert "process_features" not in active.ablations
    assert {m: v["reason"] for m, v in metrics["skipped_models"].items()} == skipped
    assert M4 not in metrics["models"] and M5 in metrics["models"]
    manifest = json.loads(pipeline.feature_manifest_path(cfg).read_text())
    assert manifest["process_log"] is False and "n_proc_start" in manifest["unavailable_features"]


def test_supervised_model_trains_only_on_training_labels(built) -> None:
    _, cfg, _mcfg, metrics = built
    assert metrics["supervised_model"]["trained"] is True
    meta = json.loads((pipeline.model_dir(cfg, M2) / "metadata.json").read_text())
    feats = pl.read_parquet(pipeline.features_path(cfg))
    train_pos = int(feats.filter(pl.col("split") == "train")["label"].sum())
    assert meta["train_info"]["labels_used"] is True
    assert meta["train_info"]["n_positive_train_windows"] == train_pos
    assert meta["threshold_policy"]["calibrated_on"] == "validation"
    for m in ("m1_isolation_forest", "m3_isolation_forest_graph", M5):
        info = json.loads((pipeline.model_dir(cfg, m) / "metadata.json").read_text())["train_info"]
        assert info["labels_used"] is False
    assert {"validation", "test"} <= set(metrics["models"][M2]["splits"])


def test_validation_and_test_labels_cannot_change_m2(built, tmp_path: Path) -> None:
    _root, cfg, mcfg, _ = built
    before = pl.read_parquet(pipeline.predictions_path(cfg))[f"score__{M2}"].to_numpy()
    path = pipeline.features_path(cfg)
    original = pl.read_parquet(path)
    flipped = original.with_columns(
        pl.when(pl.col("split").is_in(["validation", "test"]))
        .then(1 - pl.col("label"))
        .otherwise(pl.col("label"))
        .alias("label")
    )
    try:
        flipped.write_parquet(path)
        pipeline.run_train(cfg, mcfg)
        after = pl.read_parquet(pipeline.predictions_path(cfg))[f"score__{M2}"].to_numpy()
    finally:
        original.write_parquet(path)
        pipeline.run_train(cfg, mcfg)
    np.testing.assert_array_equal(before, after)


def test_serving_and_api_follow_the_active_model_set(built) -> None:
    root, cfg, mcfg, _ = built
    ctx = ServingContext(
        cfg, load_models_config().model_copy(update={"supervised_gate": mcfg.supervised_gate})
    )
    ids = [m.model_id for m in ctx.model_list().models]
    assert M2 in ids and M4 not in ids
    assert all(not f.name.startswith("n_proc") for f in ctx.metadata().features)
    settings = Settings()
    settings.datasets_config = str(write_datasets_yaml(root / "datasets.yaml", cfg))
    settings.dataset = cfg.name
    # The API with the repository's gate (30/5) refuses these artifacts as stale rather than
    # silently serving a different model set.
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/v1/health").json()["status"] == "degraded"


def test_label_rules_are_enforced_by_the_model_classes() -> None:
    X = np.random.default_rng(0).normal(size=(50, 3))
    y = np.r_[np.ones(10), np.zeros(40)].astype(int)
    with pytest.raises(ValueError):
        IsolationForestModel("m", "M", ["n_events", "n_fail", "fail_ratio"], {}).fit(X, y=y)
    with pytest.raises(ValueError):
        SupervisedGBMModel("m", "M", ["n_events", "n_fail", "fail_ratio"], {}).fit(X)
    m = SupervisedGBMModel("m", "M", ["n_events", "n_fail", "fail_ratio"], {"max_iter": 20}).fit(
        X, y=y
    )
    s = m.score(X)
    assert s.shape == (50,) and np.all((s >= 0) & (s <= 1))


def test_embedding_features_exist_and_are_bounded(built) -> None:
    _, cfg, *_ = built
    feats = pl.read_parquet(pipeline.features_path(cfg))
    for c in ("emb_dst_surprise_max", "emb_dst_surprise_mean"):
        assert feats[c].null_count() == 0
        assert feats[c].min() >= -1e-9 and feats[c].max() <= 2 + 1e-9  # 1 - cosine
    first_day = feats.filter(pl.col("day") == feats["day"].min())
    assert first_day["emb_dst_surprise_max"].max() == 0.0  # no earlier graph on day 0
    assert (feats["emb_dst_surprise_max"] >= feats["emb_dst_surprise_mean"] - 1e-12).all()
