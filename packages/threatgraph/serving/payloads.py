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
from threatgraph.graph.build import edges_glob
from threatgraph.graph.query import EntityType, subgraph
from threatgraph.ml.models import AnomalyModel
from threatgraph.pipeline import (
    EVAL_SPLITS,
    features_path,
    graph_dir,
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
IMPLEMENTED_VIEWS = ["overview", "lab", "explorer"]
MAX_EVIDENCE = 40
# Per-split cap on exported/served score rows (real LANL splits can hold hundreds of thousands).
SCORE_TABLE_MAX_ROWS = 10_000
EXPLANATION_TOP_N = 40
ENTITY_TOP_LINKS = 8
ENTITY_TOP_WINDOWS = 3
GRAPH_SEMANTICS = (
    "Nodes are computers. A directed edge means the account authenticated from the source "
    "computer to the destination computer, in the direction LANL records it. Edges aggregate "
    "non-LogOff events of in-scope accounts (machine accounts excluded by default) per window. "
    "Hop 2 adds other accounts' edges on hop-1 computers, except through hubs. Graph structure "
    "is context for an analyst, not evidence of compromise."
)
TRUNCATION_ORDER = (
    "hop, then edges first observed in the range, then failures, then event count "
    "(red-team labels are not used to choose what is shown)"
)
ENTITY_SCOPE = (
    "Counts cover the processed time window and the graph scope: non-LogOff events of in-scope "
    "accounts with both computers recorded."
)


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
            graph_dir(cfg) / "graph_manifest.json",
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

    @cached_property
    def graph_edges(self) -> pl.LazyFrame:
        return pl.scan_parquet(edges_glob(graph_dir(self.cfg)))

    @cached_property
    def entities(self) -> pl.DataFrame:
        return pl.read_parquet(graph_dir(self.cfg) / "entities.parquet")

    @cached_property
    def _entity_lookup(self) -> dict[str, tuple[EntityType, str]]:
        return {
            self.entity_id(t, k): (t, k)
            for t, k in self.entities.select("entity_type", "entity_key").iter_rows()
        }

    @cached_property
    def _ranked(self) -> pl.DataFrame:
        """Evaluated windows with each model's rank inside its split (1 = highest score)."""
        parts = []
        for split in EVAL_SPLITS:
            part = self.predictions.filter(pl.col("split") == split)
            parts.append(
                part.with_columns(
                    pl.col(f"score__{m}")
                    .rank("ordinal", descending=True)
                    .cast(pl.Int64)
                    .alias(f"rank__{m}")
                    for m in self.mcfg.models
                )
            )
        return pl.concat(parts)

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

    def entity_id(self, entity_type: str, key: str) -> str:
        return f"{entity_type}:{self.alias(key)}"

    def resolve_entity(self, entity_id: str) -> tuple[EntityType, str]:
        hit = self._entity_lookup.get(entity_id)
        if hit is None:
            raise NotFoundError(entity_id)
        return hit

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

    def _headline(self, model_id: str) -> list[S.HeadlineMetrics]:
        headline = []
        for split in EVAL_SPLITS:
            s = self.metrics["models"][model_id]["splits"][split]
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
        return headline

    def ablations(self) -> list[S.Ablation]:
        out = []
        for ab_id, ab in self.mcfg.ablations.items():
            base_f = self.mcfg.features_for(ab.baseline)
            cand_f = self.mcfg.features_for(ab.candidate)
            base_h, cand_h = self._headline(ab.baseline), self._headline(ab.candidate)
            splits = []
            for b, c in zip(base_h, cand_h, strict=True):
                ap_b, ap_c = b.average_precision, c.average_precision
                splits.append(
                    S.AblationSplit(
                        split=b.split,
                        n_positive_windows=self.metrics["models"][ab.baseline]["splits"][b.split][
                            "n_positive_windows"
                        ],
                        baseline=b,
                        candidate=c,
                        average_precision_delta=None
                        if ap_b is None or ap_c is None
                        else ap_c - ap_b,
                    )
                )
            out.append(
                S.Ablation(
                    ablation_id=ab_id,
                    title=ab.title,
                    baseline=ab.baseline,
                    candidate=ab.candidate,
                    added_features=[f for f in cand_f if f not in base_f],
                    removed_features=[f for f in base_f if f not in cand_f],
                    note=ab.note.strip(),
                    splits=splits,
                )
            )
        return out

    def model_list(self) -> S.ModelList:
        out = []
        for m, meta in self.model_meta.items():
            headline = self._headline(m)
            out.append(
                S.ModelInfo(
                    model_id=m,
                    display_name=meta["display_name"],
                    kind=meta["kind"],
                    description=(
                        self.mcfg.models[m].description or MODEL_DESCRIPTIONS[meta["kind"]]
                    )
                    .strip()
                    .replace("\n", " "),
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
        return S.ModelList(provenance=self.provenance, models=out, ablations=self.ablations())

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
        kept, exact_above = part, None
        if part.height > SCORE_TABLE_MAX_ROWS:
            # Keep every row scoring strictly above the (cap+1)-th score, so no tie is split.
            exact_above = float(part[col].sort(descending=True)[SCORE_TABLE_MAX_ROWS])
            kept = part.filter(pl.col(col) > exact_above)
        rows = [
            (self.window_id(p, ws), round(float(sc), 6), int(lab))
            for p, ws, sc, lab in kept.select(
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
            n_rows_total=part.height,
            n_known_positive_total=int(part["label"].sum()),
            truncated=exact_above is not None,
            exact_above=exact_above,
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

    def explanation_bundle(
        self, model_id: str, split: str, top_n: int = EXPLANATION_TOP_N
    ) -> S.ExplanationBundle:
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

    # ------------------------------------------------------------------ graph
    def _edge_events(self, ids: list[int], start: int, end: int) -> dict[int, S.EdgeEvent]:
        if not ids:
            return {}
        df = (
            scan_auth(self.cfg)
            .filter(
                pl.col("day").is_between(start // DAY_SECONDS, (end - 1) // DAY_SECONDS)
                & pl.col("event_id").is_in(sorted(set(ids)))
            )
            .collect()
        )
        labeled = self.labeled_event_ids
        return {
            r["event_id"]: S.EdgeEvent(
                event_id=r["event_id"],
                event_time_seconds=r["event_time_seconds"],
                auth_type=r["auth_type"],
                logon_type=r["logon_type"],
                auth_orientation=r["auth_orientation"],
                outcome=r["outcome"],
                known_redteam=r["event_id"] in labeled,
            )
            for r in df.iter_rows(named=True)
        }

    def subgraph(
        self, entity_id: str, start: int, end: int, hops: int, max_edges: int
    ) -> S.Subgraph:
        focus_type, key = self.resolve_entity(entity_id)
        g = self.cfg.graph
        w = self.cfg.features.window_seconds
        res = subgraph(
            self.graph_edges,
            focus_type=focus_type,
            focus_key=key,
            start=start,
            end=end,
            window_seconds=w,
            hops=hops,
            max_edges=max_edges,
            hub_max_principals=g.hub_max_principals,
            sample_limit=2 * g.sample_events_per_edge,
        )
        lo = start // w * w
        ids = [i for lst in res.edges["sample_event_ids"].to_list() for i in lst]
        events = self._edge_events(ids, lo, end)
        computer = lambda c: self.entity_id("computer", c)  # noqa: E731
        edges = []
        for r in res.edges.iter_rows(named=True):
            sample = sorted(
                (events[i] for i in r["sample_event_ids"] if i in events),
                key=lambda e: (not e.known_redteam, e.event_time_seconds, e.event_id),
            )[: g.sample_events_per_edge]
            p, src, dst = r["src_principal"], r["src_computer"], r["dst_computer"]
            edges.append(
                S.GraphEdge(
                    edge_id=f"e:{self.alias(p)}:{self.alias(src)}:{self.alias(dst)}",
                    principal=self.alias(p) or "",
                    principal_id=self.entity_id("principal", p),
                    source=computer(src),
                    target=computer(dst),
                    hop=r["hop"],
                    n_events=r["n_events"],
                    n_success=r["n_success"],
                    n_fail=r["n_fail"],
                    n_known_redteam=r["n_known_redteam"],
                    n_windows=r["n_windows"],
                    first_event_seconds=r["first_t"],
                    last_event_seconds=r["last_t"],
                    auth_types=r["auth_types"],
                    edge_first_seen_seconds=r["edge_first_seen_seconds"],
                    first_observed_in_range=r["first_observed_in_range"],
                    is_local=r["is_local"],
                    sample_events=sample,
                )
            )
        nodes = [
            S.GraphNode(
                node_id=computer(r["computer"]),
                label=self.alias(r["computer"]) or "",
                hop=r["hop"],
                n_principals_in_range=r["n_principals_in_range"],
                is_hub=r["is_hub"],
                expanded=r["expanded"],
            )
            for r in res.nodes.iter_rows(named=True)
        ]
        principals = [
            S.GraphPrincipal(
                principal_id=self.entity_id("principal", r["src_principal"]),
                label=self.alias(r["src_principal"]) or "",
                hop=r["hop"],
                n_edges=r["n_edges"],
                n_events=r["n_events"],
                n_known_redteam=r["n_known_redteam"],
            )
            for r in res.edges.group_by("src_principal")
            .agg(
                pl.col("hop").min(),
                pl.len().alias("n_edges"),
                pl.col("n_events").sum(),
                pl.col("n_known_redteam").sum(),
            )
            .sort(["hop", "n_events", "src_principal"], descending=[False, True, False])
            .iter_rows(named=True)
        ]
        return S.Subgraph(
            provenance=self.provenance,
            focus=entity_id,
            start_seconds=lo,
            end_seconds=end,
            hops=hops,
            max_edges=max_edges,
            hub_max_principals=g.hub_max_principals,
            n_edges_total=res.n_edges_total,
            truncated=res.truncated,
            truncation_order=TRUNCATION_ORDER,
            semantics=GRAPH_SEMANTICS,
            nodes=nodes,
            edges=edges,
            principals=principals,
        )

    def _window_summary(self, row: dict[str, Any]) -> S.GraphWindowSummary:
        scores = {}
        for m, model in self.models.items():
            assert model.threshold is not None
            sc = float(row[f"score__{m}"])
            scores[m] = S.WindowScore(
                score=sc,
                threshold=model.threshold,
                flagged=sc >= model.threshold,
                rank=row[f"rank__{m}"],
            )
        p = row["src_principal"]
        return S.GraphWindowSummary(
            window_id=self.window_id(p, row["window_start"]),
            principal=self.alias(p) or "",
            principal_id=self.entity_id("principal", p),
            split=row["split"],
            window_start=row["window_start"],
            window_end=row["window_end"],
            day=row["day"],
            label="known_redteam" if row["label"] else "unlabeled",
            n_labeled_events=row["n_labeled_events"],
            scores=scores,
        )

    def graph_window_index(self, split: str, top_n: int = EXPLANATION_TOP_N) -> S.GraphWindowIndex:
        """The windows the static explorer precomputes: each model's top N plus known red-team."""
        if split not in EVAL_SPLITS:
            raise NotFoundError(split)
        part = self._ranked.filter(pl.col("split") == split)
        rank_cols = [f"rank__{m}" for m in self.mcfg.models]
        chosen = part.filter(
            pl.any_horizontal(pl.col(c) <= top_n for c in rank_cols) | (pl.col("label") == 1)
        ).sort(pl.min_horizontal(rank_cols), "window_start", "src_principal")
        return S.GraphWindowIndex(
            provenance=self.provenance,
            split=split,
            selection=f"top {top_n} windows of each model plus all known red-team windows in the split",
            windows=[self._window_summary(r) for r in chosen.iter_rows(named=True)],
        )

    def graph_window(self, window_id: str) -> S.GraphWindow:
        principal, start = self.resolve_window(window_id)
        row = self._ranked.filter(
            (pl.col("src_principal") == principal) & (pl.col("window_start") == start)
        )
        if row.is_empty():
            raise NotFoundError(window_id)
        summary = self._window_summary(row.row(0, named=True))
        graph = self.subgraph(
            summary.principal_id,
            summary.window_start,
            summary.window_end,
            hops=2,
            max_edges=self.cfg.graph.export_max_edges,
        )
        return S.GraphWindow(provenance=self.provenance, window=summary, graph=graph)

    def entity(self, entity_id: str) -> S.EntityDetail:
        etype, key = self.resolve_entity(entity_id)
        row = self.entities.filter(
            (pl.col("entity_type") == etype) & (pl.col("entity_key") == key)
        ).row(0, named=True)
        links = pl.scan_parquet(graph_dir(self.cfg) / "links.parquet")
        if etype == "computer":
            mine, other_col, other_type = (
                links.filter(pl.col("computer") == key),
                "src_principal",
                "principal",
            )
        else:
            mine, other_col, other_type = (
                links.filter(pl.col("src_principal") == key),
                "computer",
                "computer",
            )
        mine_df = mine.collect()
        top = mine_df.sort(["n_events", other_col], descending=[True, False]).head(ENTITY_TOP_LINKS)
        top_links = [
            S.EntityLink(
                entity_id=self.entity_id(other_type, r[other_col]),
                label=self.alias(r[other_col]) or "",
                n_events=r["n_events"],
                n_known_redteam=r["n_known_redteam"],
                first_seen_seconds=r["first_t"],
                last_seen_seconds=r["last_t"],
            )
            for r in top.iter_rows(named=True)
        ]
        extra: dict[str, Any] = {}
        if etype == "principal":
            mine_w = self.features.filter(pl.col("src_principal") == key)
            extra["windows_by_split"] = [
                S.SplitWindows(split=sp, n_windows=n, n_known_positive_windows=int(k))
                for sp, n, k in mine_w.group_by("split")
                .agg(pl.len(), pl.col("label").sum())
                .sort("split")
                .iter_rows()
            ]
            ranked = self._ranked.filter(
                (pl.col("src_principal") == key) & (pl.col("split") == "test")
            )
            model_windows = []
            for m, model in self.models.items():
                assert model.threshold is not None
                col = f"score__{m}"
                top_w = ranked.sort([col, "window_start"], descending=[True, False]).head(
                    ENTITY_TOP_WINDOWS
                )
                model_windows.append(
                    S.EntityModelWindows(
                        model_id=m,
                        display_name=model.display_name,
                        split="test",
                        n_windows=ranked.height,
                        alerts=int((ranked[col] >= model.threshold).sum()),
                        top_windows=[
                            S.EntityWindow(
                                window_id=self.window_id(key, r["window_start"]),
                                window_start=r["window_start"],
                                score=float(r[col]),
                                flagged=float(r[col]) >= model.threshold,
                                known_redteam=bool(r["label"]),
                            )
                            for r in top_w.iter_rows(named=True)
                        ],
                    )
                )
            extra["model_windows"] = model_windows
            for f in ("n_active_windows", "n_distinct_src_computers", "n_distinct_dst_computers"):
                extra[f] = row[f]
        else:
            for f in ("n_distinct_principals", "in_degree", "out_degree", "n_local_events"):
                extra[f] = row[f]
        return S.EntityDetail(
            provenance=self.provenance,
            entity_id=entity_id,
            entity_type=etype,
            label=self.alias(key) or "",
            scope=ENTITY_SCOPE,
            first_seen_seconds=row["first_seen_seconds"],
            last_seen_seconds=row["last_seen_seconds"],
            n_events=row["n_events"],
            n_fail=row["n_fail"],
            n_known_redteam_events=row["n_known_redteam_events"],
            top_links=top_links,
            n_links_total=mine_df.height,
            **extra,
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
