"""Pipeline stages. Each stage reads the previous stage's outputs from disk, so stages can be
run independently (scripts/*.py) or together (scripts/run_pipeline.py)."""

from __future__ import annotations

import itertools
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
from threatgraph.graph.build import build_edge_table, build_entity_tables
from threatgraph.ml.drift import drift_report
from threatgraph.ml.faithfulness import deletion_test
from threatgraph.ml.metrics import EVALUATION_ASSUMPTIONS, detection_latency, evaluate_scores
from threatgraph.ml.models import AnomalyModel, build_model
from threatgraph.ml.uncertainty import account_bootstrap
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


def graph_dir(cfg: DatasetConfig) -> Path:
    return cfg.processed_path / "graph"


def predictions_path(cfg: DatasetConfig) -> Path:
    return cfg.artifacts_path / "predictions.parquet"


def metrics_path(cfg: DatasetConfig) -> Path:
    return cfg.artifacts_path / "metrics.json"


def drift_path(cfg: DatasetConfig) -> Path:
    return cfg.artifacts_path / "drift.json"


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
            "principal_scope": cfg.features.principals,
            "n_rows": feats.height,
            "features": FEATURE_DESCRIPTIONS,
            "splits": split_summary(feats),
            "split_boundaries_seconds": cfg.splits.boundaries_seconds(),
        }
        write_json(path.parent / "feature_manifest.json", manifest)
        rec["n_windows"] = feats.height
    return manifest


def run_graph(cfg: DatasetConfig) -> dict[str, Any]:
    require(labels_path(cfg), "Run scripts/ingest_lanl.py (or run_pipeline.py) first.")
    with stage_run(cfg, "graph") as rec:
        out = graph_dir(cfg)
        labels = pl.read_parquet(labels_path(cfg))
        edges = build_edge_table(scan_auth(cfg), labels, cfg, out)
        entities = build_entity_tables(out)
        manifest = {
            "dataset": cfg.name,
            "config_hash": config_hash(cfg),
            "scope": "non-LogOff events of in-scope principals with both computers recorded",
            "principal_scope": cfg.features.principals,
            "edge_unit": "(window, principal, source computer, destination computer)",
            "window_seconds": cfg.features.window_seconds,
            **edges,
            **entities,
            "graph_config": cfg.graph.model_dump(),
        }
        write_json(out / "graph_manifest.json", manifest)
        rec["edge_rows"] = edges["edge_rows"]
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
        # Phase 5: uncertainty, explanation faithfulness, supervised gate, drift.
        pairs = [(ab.baseline, ab.candidate) for ab in mcfg.ablations.values()]
        ids = list(models)
        pairs += [(a, b) for a, b in itertools.pairwise(ids) if (a, b) not in pairs]
        u = mcfg.uncertainty
        for split in EVAL_SPLITS:
            part = preds.filter(pl.col("split") == split)
            boot = account_bootstrap(
                part["src_principal"].to_numpy(),
                part["label"].to_numpy().astype(int),
                {mid: part[f"score__{mid}"].to_numpy() for mid in models},
                {mid: float(models[mid].threshold) for mid in models},  # type: ignore[arg-type]
                pairs,
                n_boot=u.n_boot,
                seed=u.seed,
                level=u.level,
            )
            for mid in models:
                result["models"][mid]["splits"][split]["uncertainty"] = boot["models"][mid]
            result.setdefault("uncertainty", {})[split] = {
                k: v for k, v in boot.items() if k != "models"
            }
        feats = pl.read_parquet(features_path(cfg))
        test = feats.join(
            preds.select("window_id", *[f"score__{mid}" for mid in models]), on="window_id"
        )
        test = test.filter(pl.col("split") == "test")
        for mid, model in models.items():
            alerted = test.filter(pl.col(f"score__{mid}") >= model.threshold)
            result["models"][mid]["explanation_faithfulness"] = deletion_test(
                model, _matrix(alerted, model.features), seed=cfg.seed
            )
        train = preds.filter(pl.col("split") == "train")
        gate = mcfg.supervised_gate
        n_pos = int(train["label"].sum())
        n_acc = train.filter(pl.col("label") == 1)["src_principal"].n_unique()
        ok = n_pos >= gate.min_positive_windows and n_acc >= gate.min_positive_accounts
        result["supervised_model"] = {
            "trained": False,
            "labels_permit": ok,
            "train_positive_windows": n_pos,
            "train_positive_accounts": n_acc,
            "required": gate.model_dump(),
            "reason": (
                f"The training split has {n_pos} known red-team windows from {n_acc} accounts; "
                f"a supervised model needs at least {gate.min_positive_windows} from "
                f"{gate.min_positive_accounts}."
                if not ok
                else "Labels would permit a supervised model; none is configured yet."
            ),
        }
        scored = feats.join(
            preds.select("window_id", *[f"score__{mid}" for mid in models]), on="window_id"
        ).filter(pl.col("split").is_in(["train", *EVAL_SPLITS]))
        write_json(
            drift_path(cfg),
            {
                "provenance": result["provenance"],
                **drift_report(
                    scored,
                    mcfg.features,
                    {mid: float(models[mid].threshold) for mid in models},  # type: ignore[arg-type]
                    mcfg.threshold_policy.alert_rate,
                    expected={
                        "log_prior_windows": "counts an account's past windows, so it grows "
                        "over time by design; models that use it see later periods shift."
                    },
                ),
            },
        )
        write_json(metrics_path(cfg), result)
        write_benchmark_report(cfg, result, mcfg)
    return result


def write_benchmark_report(
    cfg: DatasetConfig, metrics: dict[str, Any], mcfg: ModelsConfig | None = None
) -> Path:
    """Markdown comparison table generated from metrics.json (never typed by hand)."""
    prov = metrics["provenance"]
    lines = [
        f"# Evaluation report — {cfg.name} ({prov['mode_label']})",
        "",
        f"Config hash `{prov['config_hash']}` · pipeline {prov['pipeline_version']}. "
        "Generated by `scripts/evaluate.py`; do not edit by hand.",
        "",
        "| Model | Split | Windows | Known-positive windows | AP | AP 95% CI | Random-ranking AP | "
        "P@10 | Alerts @ threshold | Known-label recall | Precision (lower bound) |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    def fmt(v: Any, digits: int = 3) -> str:
        return "n/e" if v is None else (f"{v:.{digits}f}" if isinstance(v, float) else str(v))

    def ci(iv: dict[str, Any] | None) -> str:
        if not iv or iv.get("low") is None:
            return "n/e"
        return f"[{iv['low']:.3f}, {iv['high']:.3f}]"

    for m in metrics["models"].values():
        for split, s in m["splits"].items():
            op = s["operating_point"]
            p10 = next(p for p in s["precision_at_k"] if p["k"] == 10)
            lines.append(
                f"| {m['display_name']} | {split} | {s['n_windows']} | {s['n_positive_windows']} | "
                f"{fmt(s['average_precision'])} | "
                f"{ci((s.get('uncertainty') or {}).get('average_precision'))} | "
                f"{fmt(s['random_ranking_average_precision'])} | "
                f"{fmt(p10['precision'])} | {op['alerts']} | {fmt(op['known_label_recall'])} | "
                f"{fmt(op['precision_lower_bound'])} |"
            )
    lines += ["", "n/e = not estimable (no known positives in the split).", ""]
    for split, u in metrics.get("uncertainty", {}).items():
        lines.append(
            f"CIs ({split}): {u['method']}, {u['n_boot']} resamples of {u['n_accounts']} accounts "
            f"({u['n_positive_accounts']} with known red-team activity), seed {u['seed']}."
        )
    lines.append("")
    for ab in (mcfg.ablations if mcfg else {}).values():
        base, cand = metrics["models"][ab.baseline], metrics["models"][ab.candidate]
        added = sorted(set(mcfg.features_for(ab.candidate)) - set(mcfg.features_for(ab.baseline)))  # type: ignore[union-attr]
        lines += [
            f"## {ab.title}",
            "",
            f"Features added in the candidate: {', '.join(f'`{f}`' for f in added) or 'none'}.",
            "",
            "| Split | AP baseline | AP candidate | Δ AP | Δ AP 95% CI | Candidate better in | "
            "Recall baseline | Recall candidate |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for split in EVAL_SPLITS:
            b, c = base["splits"][split], cand["splits"][split]
            ap_b, ap_c = b["average_precision"], c["average_precision"]
            delta = None if ap_b is None or ap_c is None else ap_c - ap_b
            pair: dict[str, Any] = next(
                (
                    x
                    for x in metrics.get("uncertainty", {}).get(split, {}).get("pairs", [])
                    if x["baseline"] == ab.baseline and x["candidate"] == ab.candidate
                ),
                {},
            )
            better = pair.get("share_candidate_better")
            lines.append(
                f"| {split} | {fmt(ap_b)} | {fmt(ap_c)} | {fmt(delta)} | "
                f"{ci(pair.get('average_precision_delta'))} | "
                f"{'n/e' if better is None else f'{better:.0%} of resamples'} | "
                f"{fmt(b['operating_point']['known_label_recall'])} | "
                f"{fmt(c['operating_point']['known_label_recall'])} |"
            )
        lines += ["", ab.note.strip(), ""]
    faith = [
        (m, v["explanation_faithfulness"])
        for m, v in metrics["models"].items()
        if "explanation_faithfulness" in v
    ]
    if faith:
        lines += [
            "## Explanation faithfulness (deletion test, test alerts)",
            "",
            "Reset the explanation's top-k features to training medians and re-score; compare with "
            "resetting k random features.",
            "",
            "| Model | Alerts | k | Score drop (top-k) | Score drop (random k) | Below threshold (top-k) | "
            "Below threshold (random k) |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        for m, f in faith:
            for r in f["results"]:
                lines.append(
                    f"| {metrics['models'][m]['display_name']} | {f['n_alerts']} | {r['k']} | "
                    f"{r['mean_score_drop_top']:.4f} | {r['mean_score_drop_random']:.4f} | "
                    f"{r['below_threshold_share_top']:.0%} | {r['below_threshold_share_random']:.0%} |"
                )
        lines.append("")
    if "supervised_model" in metrics:
        lines += ["## Supervised model", "", metrics["supervised_model"]["reason"], ""]
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
