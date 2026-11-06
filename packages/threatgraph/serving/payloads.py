"""Build v1 API payloads from pipeline artifacts.

Both the FastAPI app and `scripts/export_demo.py` call these functions, so the live API and
the static JSON bundle are identical by construction.
"""

from __future__ import annotations

import hashlib
import json
from functools import cached_property
from typing import Any

import numpy as np
import polars as pl

from threatgraph.config import DAY_SECONDS, DatasetConfig, ModelsConfig
from threatgraph.data.features import FEATURE_DESCRIPTIONS, scoped_events
from threatgraph.ml.models import AnomalyModel
from threatgraph.pipeline import (
    EVAL_SPLITS,
    features_path,
    labels_path,
    load_models,
    load_run_records,
    metrics_path,
    predictions_path,
    quality_report_path,
    require,
    scan_auth,
)
from threatgraph.provenance import LABEL_SEMANTICS
from threatgraph.serving import schemas as S

TIME_SEMANTICS = (
    "LANL-format time is relative seconds from an arbitrary epoch. It is shown as "
    "'Day N + seconds'; no calendar date or clock time is implied."
)
SCORING_UNIT = (
    "One row per (source principal, time window) with at least one non-LogOff authentication. "
    "The score is produced at the window end using only events up to that time."
)
MODEL_DESCRIPTIONS = {
    "robust_z": (
        "Largest upward robust z-score among a few interpretable features (failures, novelty "
        "and per-principal deviation). Medians and scales are fit on the training split."
    ),
    "isolation_forest": (
        "Unsupervised Isolation Forest over all window features, trained on the training split "
        "without labels. Its score ranks unusualness; it is not a probability of compromise."
    ),
}
IMPLEMENTED_VIEWS = ["overview", "lab"]
MAX_EVIDENCE = 40


class NotFoundError(KeyError):
    pass


class ServingContext:
    """Read-only view over one dataset's artifacts.

    `public_ids=True` replaces real-data identifiers with salted aliases (never applied to
    synthetic data, whose identifiers are invented).
    """

    def __init__(self, cfg: DatasetConfig, mcfg: ModelsConfig, *, public_ids: bool = False):
        self.cfg = cfg
        self.mcfg = mcfg
        self.alias_ids = public_ids and cfg.mode == "lanl"
        hint = f"Run `python scripts/run_pipeline.py --dataset {cfg.name}` first."
        for p in (
            quality_report_path(cfg),
            features_path(cfg),
            predictions_path(cfg),
            metrics_path(cfg),
        ):
            require(p, hint)

    # ------------------------------------------------------------------ cached inputs
    @cached_property
    def quality(self) -> dict[str, Any]:
        return json.loads(quality_report_path(self.cfg).read_text())

    @cached_property
    def metrics(self) -> dict[str, Any]:
        return json.loads(metrics_path(self.cfg).read_text())

    @cached_property
    def feature_manifest(self) -> dict[str, Any]:
        return json.loads((features_path(self.cfg).parent / "feature_manifest.json").read_text())

    @cached_property
    def predictions(self) -> pl.DataFrame:
        return pl.read_parquet(predictions_path(self.cfg))

    @cached_property
    def features(self) -> pl.DataFrame:
        return pl.read_parquet(features_path(self.cfg))

    @cached_property
    def labeled_event_ids(self) -> set[int]:
        return set(pl.read_parquet(labels_path(self.cfg))["event_id"].to_list())

    @cached_property
    def models(self) -> dict[str, AnomalyModel]:
        return load_models(self.cfg, self.mcfg)

    @cached_property
    def model_meta(self) -> dict[str, dict[str, Any]]:
        out = {}
        for m in self.mcfg.models:
            path = self.cfg.artifacts_path / "models" / m / "metadata.json"
            out[m] = json.loads(path.read_text())
        return out

    @cached_property
    def provenance(self) -> S.Provenance:
        return S.Provenance(**self.metrics["provenance"])

    @cached_property
    def _salt(self) -> str:
        path = self.cfg.processed_path / ".export_salt"  # local only; never exported
        if not path.exists():
            path.write_text(hashlib.sha256(np.random.default_rng().bytes(32)).hexdigest())
        return path.read_text().strip()

    @cached_property
    def _alias_map(self) -> dict[str, str]:
        return {self.alias(p) or p: p for p in self.predictions["src_principal"].unique().to_list()}

    # ------------------------------------------------------------------ identifiers
    def alias(self, ident: str | None) -> str | None:
        if ident is None or not self.alias_ids:
            return ident
        return "X" + hashlib.sha256((self._salt + ident).encode()).hexdigest()[:10]

    def window_id(self, principal: str, window_start: int) -> str:
        return f"w:{self.alias(principal)}:{window_start}"

    def resolve_window(self, window_id: str) -> tuple[str, int]:
        prefix, _, rest = window_id.partition(":")
        who, _, start = rest.rpartition(":")
        if prefix != "w" or not who or not start.isdigit():
            raise NotFoundError(window_id)
        principal = self._alias_map.get(who) if self.alias_ids else who
        if principal is None:
            raise NotFoundError(window_id)
        return principal, int(start)

    def _model(self, model_id: str) -> AnomalyModel:
        if model_id not in self.mcfg.models:
            raise NotFoundError(model_id)
        return self.models[model_id]

    def _split_days(self, split: str) -> float:
        lo, hi = self.cfg.splits.boundaries_seconds()[split]
        return (hi - lo) / DAY_SECONDS

    # ------------------------------------------------------------------ payloads
    def metadata(self) -> S.Metadata:
        auth = self.quality["auth"]
        bounds = self.cfg.splits.boundaries_seconds()
        splits = []
        for s in self.feature_manifest["splits"]:
            if s["split"] not in bounds:
                continue
            lo, hi = bounds[s["split"]]
            splits.append(S.SplitInfo(**{**s, "start_seconds": lo, "end_seconds": hi}))
        return S.Metadata(
            provenance=self.provenance,
            time_start_seconds=auth["time_min_seconds"],
            time_end_seconds=auth["time_max_seconds"],
            n_days=auth["days_covered"],
            time_semantics=TIME_SEMANTICS,
            scoring_unit=SCORING_UNIT,
            window_seconds=self.cfg.features.window_seconds,
            label_semantics=LABEL_SEMANTICS,
            splits=splits,
            feature_set=self.mcfg.feature_set,
            features=[
                S.FeatureInfo(name=k, description=v) for k, v in FEATURE_DESCRIPTIONS.items()
            ],
            model_ids=list(self.mcfg.models),
            implemented_views=IMPLEMENTED_VIEWS,
        )

    def summary(self) -> S.Summary:
        q = self.quality
        scored = self.predictions
        flagged = []
        for m, info in self.metrics["models"].items():
            op = info["splits"]["test"]["operating_point"]
            flagged.append(
                S.FlaggedCount(
                    model_id=m, split="test", threshold=info["threshold"], alerts=op["alerts"]
                )
            )
        return S.Summary(
            provenance=self.provenance,
            processed_auth_events=q["auth"]["rows_accepted"],
            rejected_source_rows=q["auth"]["rows_rejected"],
            distinct_principals=q["auth"]["distinct"]["src_principal"],
            distinct_computers=q["auth"]["distinct"]["computers_total"],
            scored_windows=scored.height,
            redteam_records_in_window=q["redteam"]["records_in_time_window"],
            labeled_redteam_events=q["label_join"]["auth_events_labeled"],
            known_positive_windows=int(scored["label"].sum()),
            flagged_windows=flagged,
            model_versions={m: meta["artifact_sha256"][:12] for m, meta in self.model_meta.items()},
        )

    def model_list(self) -> S.ModelList:
        out = []
        for m, meta in self.model_meta.items():
            headline = []
            for split in EVAL_SPLITS:
                s = self.metrics["models"][m]["splits"][split]
                op = s["operating_point"]
                headline.append(
                    S.HeadlineMetrics(
                        split=split,
                        average_precision=s["average_precision"],
                        random_ranking_average_precision=s["random_ranking_average_precision"],
                        precision_at_10=next(
                            p["precision"] for p in s["precision_at_k"] if p["k"] == 10
                        ),
                        alerts=op["alerts"],
                        known_label_recall=op["known_label_recall"],
                        precision_lower_bound=op["precision_lower_bound"],
                    )
                )
            out.append(
                S.ModelInfo(
                    model_id=m,
                    display_name=meta["display_name"],
                    kind=meta["kind"],
                    description=MODEL_DESCRIPTIONS[meta["kind"]],
                    features=meta["features"],
                    hyperparameters=meta["hyperparameters"],
                    threshold=meta["threshold"],
                    threshold_policy=meta["threshold_policy"],
                    train_info=meta["train_info"],
                    explanation_method=meta["explanation_method"],
                    explanation_caveat=meta["explanation_caveat"],
                    artifact_sha256=meta["artifact_sha256"],
                    library_versions=meta["library_versions"],
                    headline=headline,
                )
            )
        return S.ModelList(provenance=self.provenance, models=out)

    def model_metrics(self, model_id: str) -> S.ModelMetrics:
        self._model(model_id)
        m = self.metrics["models"][model_id]
        splits = {}
        for split, s in m["splits"].items():
            lat = [{**r, "principal": self.alias(r["principal"])} for r in s["detection_latency"]]
            splits[split] = S.SplitMetrics(**{**s, "detection_latency": lat})
        return S.ModelMetrics(
            provenance=self.provenance,
            model_id=model_id,
            display_name=m["display_name"],
            threshold=m["threshold"],
            evaluation_assumptions=self.metrics["evaluation_assumptions"],
            split_boundaries_seconds=self.metrics["split_boundaries_seconds"],
            splits=splits,
        )

    def score_table(self, model_id: str, split: str) -> S.ScoreTable:
        model = self._model(model_id)
        if split not in EVAL_SPLITS:
            raise NotFoundError(split)
        part = self.predictions.filter(pl.col("split") == split).sort(
            "window_start", "src_principal"
        )
        col = f"score__{model_id}"
        rows = [
            (self.window_id(p, ws), round(float(sc), 6), int(lab))
            for p, ws, sc, lab in part.select(
                "src_principal", "window_start", col, "label"
            ).iter_rows()
        ]
        assert model.threshold is not None
        return S.ScoreTable(
            provenance=self.provenance,
            model_id=model_id,
            split=split,
            n_days=self._split_days(split),
            calibrated_threshold=model.threshold,
            rows=rows,
        )

    def predictions_page(
        self, model_id: str, split: str, threshold: float | None, limit: int, offset: int = 0
    ) -> S.PredictionPage:
        model = self._model(model_id)
        if split not in EVAL_SPLITS:
            raise NotFoundError(split)
        assert model.threshold is not None
        t = model.threshold if threshold is None else threshold
        col = f"score__{model_id}"
        part = self.predictions.filter(pl.col("split") == split)
        ranked = part.with_columns(
            pl.col(col).rank("ordinal", descending=True).cast(pl.Int64).alias("_rank")
        ).sort("_rank")
        flagged = ranked.filter(pl.col(col) >= t)
        page = flagged.slice(offset, limit)
        rows = [
            S.PredictionRow(
                window_id=self.window_id(r["src_principal"], r["window_start"]),
                principal=self.alias(r["src_principal"]) or "",
                window_start=r["window_start"],
                window_end=r["window_end"],
                day=r["day"],
                score=float(r[col]),
                rank=r["_rank"],
                known_redteam=bool(r["label"]),
                n_labeled_events=r["n_labeled_events"],
                flagged=True,
            )
            for r in page.iter_rows(named=True)
        ]
        return S.PredictionPage(
            provenance=self.provenance,
            model_id=model_id,
            split=split,
            threshold=t,
            total_flagged=flagged.height,
            offset=offset,
            rows=rows,
        )

    def _event_rows(self, df: pl.DataFrame, used_ids: set[int]) -> list[S.AuthEvent]:
        labeled = self.labeled_event_ids
        return [
            S.AuthEvent(
                event_id=r["event_id"],
                event_time_seconds=r["event_time_seconds"],
                day=r["event_time_seconds"] // DAY_SECONDS,
                src_principal=self.alias(r["src_principal"]),
                dst_principal=self.alias(r["dst_principal"]),
                src_computer=self.alias(r["src_computer"]),
                dst_computer=self.alias(r["dst_computer"]),
                auth_type=r["auth_type"],
                logon_type=r["logon_type"],
                auth_orientation=r["auth_orientation"],
                outcome=r["outcome"],
                known_redteam=r["event_id"] in labeled,
                used_in_features=r["event_id"] in used_ids,
            )
            for r in df.iter_rows(named=True)
        ]

    def explanation(self, model_id: str, window_id: str) -> S.Explanation:
        model = self._model(model_id)
        principal, start = self.resolve_window(window_id)
        row = self.features.filter(
            (pl.col("src_principal") == principal) & (pl.col("window_start") == start)
        )
        if row.is_empty() or row["split"][0] not in ("train", *EVAL_SPLITS):
            raise NotFoundError(window_id)
        r = row.row(0, named=True)
        x = np.array([float(r[f]) for f in model.features])
        score = float(model.score(x[None, :])[0])
        assert model.threshold is not None
        end = start + self.cfg.features.window_seconds
        window_events = (
            scan_auth(self.cfg)
            .filter(
                (pl.col("src_principal") == principal)
                & (pl.col("event_time_seconds") >= start)
                & (pl.col("event_time_seconds") < end)
            )
            .sort("event_time_seconds", "event_id")
            .collect()
        )
        used = set(scoped_events(window_events.lazy(), self.cfg).collect()["event_id"].to_list())
        # Show labeled events first so evidence for a known red-team window is never truncated away.
        ordered = window_events.with_columns(
            pl.col("event_id").is_in(list(self.labeled_event_ids)).alias("_lab")
        ).sort(["_lab", "event_time_seconds", "event_id"], descending=[True, False, False])
        shown = ordered.head(MAX_EVIDENCE).sort("event_time_seconds", "event_id").drop("_lab")
        return S.Explanation(
            provenance=self.provenance,
            model_id=model_id,
            window_id=window_id,
            principal=self.alias(principal) or "",
            split=r["split"],
            window_start=start,
            window_end=end,
            score=score,
            threshold=model.threshold,
            flagged=score >= model.threshold,
            label="known_redteam" if r["label"] else "unlabeled",
            n_labeled_events=r["n_labeled_events"],
            method=model.explanation_method,
            caveat=model.explanation_caveat,
            diagnostics=[S.FeatureDiagnostic(**d) for d in model.diagnostics(x)],
            feature_values={f: float(r[f]) for f in FEATURE_DESCRIPTIONS},
            n_events_in_window=window_events.height,
            evidence_events=self._event_rows(shown, used),
            evidence_truncated=window_events.height > MAX_EVIDENCE,
        )

    def explanation_bundle(self, model_id: str, split: str, top_n: int = 40) -> S.ExplanationBundle:
        """Top-N scored windows plus every known red-team window of the split (static export)."""
        col = f"score__{model_id}"
        part = self.predictions.filter(pl.col("split") == split)
        top = part.sort([col, "window_start"], descending=[True, False]).head(top_n)
        chosen = pl.concat([top, part.filter(pl.col("label") == 1)]).unique(
            subset="window_id", keep="first", maintain_order=True
        )
        expl = {}
        for p, ws in chosen.select("src_principal", "window_start").iter_rows():
            wid = self.window_id(p, ws)
            expl[wid] = self.explanation(model_id, wid)
        return S.ExplanationBundle(
            provenance=self.provenance,
            model_id=model_id,
            split=split,
            selection=f"top {top_n} windows by score plus all known red-team windows in the split",
            explanations=expl,
        )

    def events_page(
        self,
        start: int | None,
        end: int | None,
        principal: str | None,
        limit: int,
        cursor: int | None,
    ) -> S.EventPage:
        lf = scan_auth(self.cfg)
        if start is not None:
            lf = lf.filter(pl.col("event_time_seconds") >= start)
        if end is not None:
            lf = lf.filter(pl.col("event_time_seconds") < end)
        if principal is not None:
            real = self._alias_map.get(principal, None) if self.alias_ids else principal
            lf = lf.filter(pl.col("src_principal") == real)
        if cursor is not None:
            lf = lf.filter(pl.col("event_id") > cursor)
        df = lf.sort("event_id").head(limit + 1).collect()
        nxt = int(df["event_id"][limit - 1]) if df.height > limit else None
        df = df.head(limit)
        used = set(scoped_events(df.lazy(), self.cfg).collect()["event_id"].to_list())
        return S.EventPage(
            provenance=self.provenance, rows=self._event_rows(df, used), next_cursor=nxt
        )

    def benchmarks(self, export_payload_bytes: int | None = None) -> S.Benchmarks:
        runs = load_run_records(self.cfg)
        sizes = {
            "features_parquet": features_path(self.cfg).stat().st_size,
            "predictions_parquet": predictions_path(self.cfg).stat().st_size,
            "auth_parquet_total": sum(
                p.stat().st_size for p in (self.cfg.processed_path / "auth").rglob("*.parquet")
            ),
        }
        stages = {
            k: {kk: v[kk] for kk in ("seconds", "peak_rss_mb", "config_hash") if kk in v}
            | {kk: v[kk] for kk in ("rows_accepted", "n_windows") if kk in v}
            for k, v in runs.items()
        }
        lib = next(iter(runs.values()))["library_versions"] if runs else {}
        return S.Benchmarks(
            provenance=self.provenance,
            stages=stages,
            ingest_rows_per_second=runs.get("ingest", {}).get("rows_per_second"),
            processed_bytes=sizes,
            export_payload_bytes=export_payload_bytes,
            library_versions=lib,
        )
