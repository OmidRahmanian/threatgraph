"""Pipeline stages. Each stage reads the previous stage's outputs from disk, so stages can be
run independently (scripts/*.py) or together (scripts/run_pipeline.py)."""

from __future__ import annotations

import json
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl

from threatgraph.config import (
    DAY_SECONDS,
    DatasetConfig,
    ModelsConfig,
    config_hash,
)
from threatgraph.data.features import FEATURE_DESCRIPTIONS, build_window_features, split_summary
from threatgraph.data.ingest import auth_glob, ingest_auth, ingest_redteam, write_json
from threatgraph.data.redteam import match_redteam
from threatgraph.ml.metrics import EVALUATION_ASSUMPTIONS, detection_latency, evaluate_scores
from threatgraph.ml.models import AnomalyModel, build_model
from threatgraph.provenance import PIPELINE_VERSION, label_source, provenance_block
from threatgraph.versions import library_versions, peak_rss_mb

EVAL_SPLITS = ("validation", "test")


class MissingInputError(RuntimeError):
    """Raised when a stage's inputs do not exist yet (with an actionable message)."""


# ----------------------------------------------------------------------------- paths
def features_path(cfg: DatasetConfig) -> Path:
    return cfg.processed_path / "features" / "windows.parquet"


def labels_path(cfg: DatasetConfig) -> Path:
    return cfg.processed_path / "labels.parquet"


def quality_report_path(cfg: DatasetConfig) -> Path:
    return cfg.processed_path / "reports" / "data_quality.json"


def predictions_path(cfg: DatasetConfig) -> Path:
    return cfg.artifacts_path / "predictions.parquet"


def metrics_path(cfg: DatasetConfig) -> Path:
    return cfg.artifacts_path / "metrics.json"


def model_dir(cfg: DatasetConfig, model_id: str) -> Path:
    return cfg.artifacts_path / "models" / model_id


def scan_auth(cfg: DatasetConfig) -> pl.LazyFrame:
    return pl.scan_parquet(auth_glob(cfg.processed_path), hive_partitioning=True)


def require(path: Path, hint: str) -> Path:
    if not path.exists():
        raise MissingInputError(f"missing {path}. {hint}")
    return path


# ----------------------------------------------------------------------------- run log
@contextmanager
def stage_run(cfg: DatasetConfig, name: str, mcfg: ModelsConfig | None = None):
    """Record wall time, peak memory and config hash for a stage."""
    record: dict[str, Any] = {
        "stage": name,
        "dataset": cfg.name,
        "mode": cfg.mode,
        "config_hash": config_hash(cfg, *([mcfg] if mcfg else [])),
        "started_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "pipeline_version": PIPELINE_VERSION,
    }
    started = time.perf_counter()
    yield record
    record["seconds"] = round(time.perf_counter() - started, 3)
    record["peak_rss_mb"] = peak_rss_mb()
    record["library_versions"] = library_versions()
    write_json(cfg.artifacts_path / "runs" / f"{name}.json", record)


# ----------------------------------------------------------------------------- stages
def run_ingest(cfg: DatasetConfig) -> dict[str, Any]:
    with stage_run(cfg, "ingest") as rec:
        out = cfg.processed_path
        auth_report = ingest_auth(cfg, out)
        redteam, rt_report = ingest_redteam(cfg, out)
        labels, join_report = match_redteam(
            scan_auth(cfg),
            redteam,
            user_field=cfg.redteam.user_field,
            label_source=label_source(cfg.mode),
        )
        labels.write_parquet(labels_path(cfg))
        report = {
            "dataset": cfg.name,
            "mode": cfg.mode,
            "config_hash": config_hash(cfg),
            "time_window": cfg.time_window.model_dump(),
            "auth": auth_report,
            "redteam": rt_report,
            "label_join": join_report,
        }
        write_json(quality_report_path(cfg), report)
        rec["rows_accepted"] = auth_report["rows_accepted"]
        rec["rows_per_second"] = auth_report["rows_per_second"]
    return report


def run_features(cfg: DatasetConfig) -> dict[str, Any]:
    require(
        labels_path(cfg), "Run scripts/build_features.py after ingesting (scripts/ingest_lanl.py)."
    )
    with stage_run(cfg, "features") as rec:
        labels = pl.read_parquet(labels_path(cfg))
        feats = build_window_features(scan_auth(cfg), labels, cfg)
        path = features_path(cfg)
        path.parent.mkdir(parents=True, exist_ok=True)
        feats.write_parquet(path)
        manifest = {
            "dataset": cfg.name,
            "config_hash": config_hash(cfg),
            "scoring_unit": "(src_principal, window)",
            "window_seconds": cfg.features.window_seconds,
            "burst_seconds": cfg.features.burst_seconds,
            "baseline_windows": cfg.features.baseline_windows,
            "principals": cfg.features.principals,
            "n_rows": feats.height,
            "features": FEATURE_DESCRIPTIONS,
            "splits": split_summary(feats),
            "split_boundaries_seconds": cfg.splits.boundaries_seconds(),
        }
        write_json(path.parent / "feature_manifest.json", manifest)
        rec["n_windows"] = feats.height
    return manifest


def _matrix(df: pl.DataFrame, features: list[str]) -> np.ndarray:
    return df.select(pl.col(f).cast(pl.Float64) for f in features).to_numpy()


def run_train(cfg: DatasetConfig, mcfg: ModelsConfig) -> dict[str, Any]:
    require(features_path(cfg), "Run scripts/build_features.py first.")
    with stage_run(cfg, "train", mcfg) as rec:
        feats = pl.read_parquet(features_path(cfg))
        scored = feats.filter(pl.col("split").is_in(["train", "validation", "test"]))
        train = scored.filter(pl.col("split") == "train")
        val = scored.filter(pl.col("split") == "validation")
        if train.is_empty() or val.is_empty():
            raise MissingInputError(
                "train or validation split is empty; check split days in configs/datasets.yaml"
            )
        bounds = cfg.splits.boundaries_seconds()
        preds = scored.select(
            "window_id",
            "src_principal",
            "window_start",
            "window_end",
            "day",
            "split",
            "label",
            "n_labeled_events",
            "first_labeled_event_seconds",
        )
        summaries = {}
        for model_id, spec in mcfg.models.items():
            feature_list = mcfg.features_for(model_id)
            model = build_model(model_id, spec, feature_list)
            model.fit(
                _matrix(train, feature_list),
                train_info={
                    "train_split": "train",
                    "train_window_seconds": list(bounds["train"]),
                    "labels_used": False,
                    "seed": cfg.seed,
                    "dataset": cfg.name,
                    "dataset_mode": cfg.mode,
                    "feature_set": mcfg.feature_set,
                    "config_hash": config_hash(cfg, mcfg),
                },
            )
            model.calibrate_threshold(
                model.score(_matrix(val, feature_list)), mcfg.threshold_policy
            )
            started = time.perf_counter()
            scores = model.score(_matrix(scored, feature_list))
            per_1k = 1000 * (time.perf_counter() - started) / max(len(scores), 1)
            model.train_info["score_ms_per_1000_windows"] = round(per_1k * 1000, 3)
            preds = preds.with_columns(pl.Series(f"score__{model_id}", scores))
            summaries[model_id] = model.save(model_dir(cfg, model_id))
        preds.write_parquet(predictions_path(cfg))
        rec["models"] = list(summaries)
    return summaries


def load_models(cfg: DatasetConfig, mcfg: ModelsConfig) -> dict[str, AnomalyModel]:
    return {
        m: AnomalyModel.load(require(model_dir(cfg, m), "Run scripts/train.py first."))
        for m in mcfg.models
    }


def run_evaluate(cfg: DatasetConfig, mcfg: ModelsConfig) -> dict[str, Any]:
    require(predictions_path(cfg), "Run scripts/train.py first.")
    with stage_run(cfg, "evaluate", mcfg):
        preds = pl.read_parquet(predictions_path(cfg))
        models = load_models(cfg, mcfg)
        bounds = cfg.splits.boundaries_seconds()
        result: dict[str, Any] = {
            "provenance": provenance_block(cfg.name, cfg.mode, config_hash(cfg, mcfg)),
            "evaluation_assumptions": EVALUATION_ASSUMPTIONS,
            "split_boundaries_seconds": {s: list(bounds[s]) for s in ("train", *EVAL_SPLITS)},
            "models": {},
        }
        for model_id, model in models.items():
            assert model.threshold is not None
            per_split = {}
            for split in EVAL_SPLITS:
                part = preds.filter(pl.col("split") == split)
                y = part["label"].to_numpy().astype(int)
                s = part[f"score__{model_id}"].to_numpy()
                lo, hi = bounds[split]
                m = evaluate_scores(y, s, model.threshold, n_days=(hi - lo) / DAY_SECONDS)
                m["detection_latency"] = detection_latency(
                    part["src_principal"].to_numpy(),
                    y,
                    s >= model.threshold,
                    part["window_end"].to_numpy(),
                    part["first_labeled_event_seconds"].fill_null(-1).to_numpy(),
                )
                m["n_labeled_events"] = int(part["n_labeled_events"].sum())
                per_split[split] = m
            result["models"][model_id] = {
                "display_name": model.display_name,
                "kind": model.kind,
                "threshold": model.threshold,
                "splits": per_split,
            }
        write_json(metrics_path(cfg), result)
        write_benchmark_report(cfg, result)
    return result


def write_benchmark_report(cfg: DatasetConfig, metrics: dict[str, Any]) -> Path:
    """Markdown comparison table generated from metrics.json (never typed by hand)."""
    prov = metrics["provenance"]
    lines = [
        f"# Evaluation report — {cfg.name} ({prov['mode_label']})",
        "",
        f"Config hash `{prov['config_hash']}` · pipeline {prov['pipeline_version']}. "
        "Generated by `scripts/evaluate.py`; do not edit by hand.",
        "",
        "| Model | Split | Windows | Known-positive windows | AP | Random-ranking AP | P@10 | "
        "Alerts @ threshold | Known-label recall | Precision (lower bound) |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    def fmt(v: Any, digits: int = 3) -> str:
        return "n/e" if v is None else (f"{v:.{digits}f}" if isinstance(v, float) else str(v))

    for m in metrics["models"].values():
        for split, s in m["splits"].items():
            op = s["operating_point"]
            p10 = next(p for p in s["precision_at_k"] if p["k"] == 10)
            lines.append(
                f"| {m['display_name']} | {split} | {s['n_windows']} | {s['n_positive_windows']} | "
                f"{fmt(s['average_precision'])} | {fmt(s['random_ranking_average_precision'])} | "
                f"{fmt(p10['precision'])} | {op['alerts']} | {fmt(op['known_label_recall'])} | "
                f"{fmt(op['precision_lower_bound'])} |"
            )
    lines += ["", "n/e = not estimable (no known positives in the split).", ""]
    lines += [f"- {a}" for a in metrics["evaluation_assumptions"]]
    path = cfg.artifacts_path / "reports" / "evaluation.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")
    return path


def load_run_records(cfg: DatasetConfig) -> dict[str, Any]:
    out = {}
    for p in sorted((cfg.artifacts_path / "runs").glob("*.json")):
        out[p.stem] = json.loads(p.read_text())
    return out
