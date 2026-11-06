"""Causal behavioral features per (source principal, fixed time window).

Scoring unit
    One row per (src_principal, window_start) in which the principal had at least one
    non-LogOff authentication event. The row's *prediction time* is the window end
    (window_start + window_seconds); every feature uses only events with
    event_time_seconds < window end, and the per-principal baselines use only strictly
    earlier windows.

Novelty
    A (principal, destination computer) pair is "novel" in the window that contains its
    first observation in the processed data. Because first occurrence depends only on the
    past, novelty is causal. The warm-up split exists so that the first days, where
    everything is novel, are used only as history and never scored.

Cold start
    `log_prior_windows` encodes how much history a principal has. Rolling baselines with no
    history yield z = 0 (no evidence of deviation) rather than an imputed mean.
"""

from __future__ import annotations

from typing import Any

import polars as pl

from threatgraph.config import DatasetConfig

FEATURE_DESCRIPTIONS: dict[str, str] = {
    "n_events": "Authentication events (excluding LogOff) by the principal in the window",
    "n_fail": "Failed authentication events in the window",
    "fail_ratio": "Failed / total authentication events in the window",
    "n_distinct_dst": "Distinct destination computers contacted in the window (fan-out)",
    "n_distinct_src": "Distinct source computers the principal authenticated from",
    "n_remote": "Events whose destination computer differs from the source computer",
    "n_novel_dst": "Destination computers this principal had never authenticated to before",
    "novel_dst_ratio": "Share of the window's distinct destinations that were novel",
    "n_novel_src": "Source computers this principal had never authenticated from before",
    "n_novel_edge": "Source→destination computer pairs never observed before (any principal)",
    "n_novel_auth_type": "Authentication types this principal used for the first time",
    "n_post_fail_success": "Successes immediately following a failure on the same destination",
    "ntlm_ratio": "Share of events using NTLM",
    "max_burst": "Maximum events in any burst sub-window (default 5 minutes) of the window",
    "z_events": "Deviation of n_events from the principal's trailing baseline (prior windows)",
    "z_distinct_dst": "Deviation of fan-out from the principal's trailing baseline",
    "log_prior_windows": "log(1 + number of earlier active windows) — history / cold start",
}

ID_COLUMNS = ["window_id", "src_principal", "window_start", "window_end", "day", "split"]
LABEL_COLUMNS = ["n_labeled_events", "label"]
TIME_COLUMNS = ["first_event_seconds", "last_event_seconds", "first_labeled_event_seconds"]


def _is_user_principal() -> pl.Expr:
    p = pl.col("src_principal")
    return (
        p.is_not_null() & ~p.str.contains(r"\$@", literal=False) & ~p.str.starts_with("ANONYMOUS")
    )


def scoped_events(auth: pl.LazyFrame, cfg: DatasetConfig) -> pl.LazyFrame:
    """Events eligible for per-principal features (LogOff and machine accounts excluded)."""
    lf = auth.filter(pl.col("auth_orientation").fill_null("") != "LogOff")
    if cfg.features.principals == "users_only":
        lf = lf.filter(_is_user_principal())
    return lf


def build_window_features(
    auth: pl.LazyFrame,
    labels: pl.DataFrame,
    cfg: DatasetConfig,
) -> pl.DataFrame:
    """Compute the feature table. `auth` must follow the internal auth schema."""
    w = cfg.features.window_seconds
    burst = cfg.features.burst_seconds
    k = cfg.features.baseline_windows

    # Global computer-edge novelty uses every event, including machine accounts.
    edge_first = (
        auth.filter(pl.col("src_computer").is_not_null() & pl.col("dst_computer").is_not_null())
        .group_by("src_computer", "dst_computer")
        .agg(pl.col("event_time_seconds").min().alias("first_t"))
    )

    ev = (
        scoped_events(auth, cfg)
        .with_columns((pl.col("event_time_seconds") // w * w).alias("window_start"))
        .sort("event_time_seconds", "event_id")
    )

    def first_seen(cols: list[str], name: str) -> pl.LazyFrame:
        return (
            ev.filter(pl.all_horizontal(pl.col(c).is_not_null() for c in cols))
            .group_by(["src_principal", *cols])
            .agg(pl.col("window_start").min().alias("window_start"))
            .group_by("src_principal", "window_start")
            .agg(pl.len().alias(name))
        )

    novel_dst = first_seen(["dst_computer"], "n_novel_dst")
    novel_src = first_seen(["src_computer"], "n_novel_src")
    novel_auth = first_seen(["auth_type"], "n_novel_auth_type")

    # A novel edge counts toward the window of the principal event that realises its first
    # observation (machine-account first observations count toward no principal window).
    novel_edge = (
        ev.join(edge_first, on=["src_computer", "dst_computer"], how="inner")
        .filter(pl.col("event_time_seconds") == pl.col("first_t"))
        .group_by("src_principal", "window_start")
        .agg(pl.struct("src_computer", "dst_computer").n_unique().alias("n_novel_edge"))
    )

    post_fail = (
        ev.with_columns(
            pl.col("outcome").shift(1).over("src_principal", "dst_computer").alias("_prev")
        )
        .filter((pl.col("outcome") == "Success") & (pl.col("_prev") == "Fail"))
        .group_by("src_principal", "window_start")
        .agg(pl.len().alias("n_post_fail_success"))
    )

    bursts = (
        ev.group_by("src_principal", "window_start", pl.col("event_time_seconds") // burst)
        .agg(pl.len().alias("_n"))
        .group_by("src_principal", "window_start")
        .agg(pl.col("_n").max().alias("max_burst"))
    )

    label_ev = labels.lazy().select("event_id").with_columns(pl.lit(1).alias("_lab"))
    base = (
        ev.join(label_ev, on="event_id", how="left")
        .group_by("src_principal", "window_start")
        .agg(
            pl.len().alias("n_events"),
            (pl.col("outcome") == "Fail").sum().alias("n_fail"),
            pl.col("dst_computer").drop_nulls().n_unique().alias("n_distinct_dst"),
            pl.col("src_computer").drop_nulls().n_unique().alias("n_distinct_src"),
            (pl.col("src_computer") != pl.col("dst_computer")).sum().alias("n_remote"),
            (pl.col("auth_type") == "NTLM").sum().alias("_n_ntlm"),
            pl.col("_lab").sum().alias("n_labeled_events"),
            pl.col("event_time_seconds").min().alias("first_event_seconds"),
            pl.col("event_time_seconds").max().alias("last_event_seconds"),
            pl.col("event_time_seconds")
            .filter(pl.col("_lab") == 1)
            .min()
            .alias("first_labeled_event_seconds"),
        )
    )

    keys = ["src_principal", "window_start"]
    df = base
    for part in (novel_dst, novel_src, novel_auth, novel_edge, post_fail, bursts):
        df = df.join(part, on=keys, how="left")

    int_fill = [
        "n_novel_dst",
        "n_novel_src",
        "n_novel_auth_type",
        "n_novel_edge",
        "n_post_fail_success",
        "n_labeled_events",
    ]
    df = (
        df.with_columns(pl.col(c).fill_null(0).cast(pl.Int64) for c in int_fill)
        .with_columns(
            pl.col(c).cast(pl.Int64)
            for c in (
                "n_events",
                "n_fail",
                "n_distinct_dst",
                "n_distinct_src",
                "n_remote",
                "max_burst",
            )
        )
        .with_columns(
            (pl.col("n_fail") / pl.col("n_events")).alias("fail_ratio"),
            (pl.col("_n_ntlm") / pl.col("n_events")).alias("ntlm_ratio"),
            pl.when(pl.col("n_distinct_dst") > 0)
            .then(pl.col("n_novel_dst") / pl.col("n_distinct_dst"))
            .otherwise(0.0)
            .alias("novel_dst_ratio"),
        )
        .sort("src_principal", "window_start")
    )

    # Trailing per-principal baselines over the previous `k` active windows (shift(1) makes
    # them strictly causal: the current window never contributes to its own baseline).
    # The +1 in the denominator keeps z bounded for principals with near-constant history.
    def z(col: str, name: str) -> pl.Expr:
        prev = pl.col(col).cast(pl.Float64).shift(1)
        mean = prev.rolling_mean(k, min_samples=1)
        std = prev.rolling_std(k, min_samples=2).fill_null(0.0)
        return ((pl.col(col) - mean) / (std + 1.0)).fill_null(0.0).over("src_principal").alias(name)

    df = df.with_columns(
        z("n_events", "z_events"),
        z("n_distinct_dst", "z_distinct_dst"),
        (pl.int_range(pl.len()).over("src_principal").cast(pl.Float64) + 1)
        .log()
        .alias("log_prior_windows"),
    )

    splits = cfg.splits.boundaries_seconds()
    split_expr = pl.lit(None, dtype=pl.String)
    for name, (lo, hi) in reversed(splits.items()):
        split_expr = (
            pl.when((pl.col("window_start") >= lo) & (pl.col("window_start") < hi))
            .then(pl.lit(name))
            .otherwise(split_expr)
        )
    out = (
        df.with_columns(
            (pl.col("window_start") + w).alias("window_end"),
            (pl.col("window_start") // 86_400).cast(pl.Int32).alias("day"),
            split_expr.fill_null("out_of_range").alias("split"),
            (pl.col("n_labeled_events") > 0).cast(pl.Int8).alias("label"),
            pl.format("w:{}:{}", pl.col("src_principal"), pl.col("window_start")).alias(
                "window_id"
            ),
        )
        .select(*ID_COLUMNS, *FEATURE_DESCRIPTIONS, *LABEL_COLUMNS, *TIME_COLUMNS)
        .sort("window_start", "src_principal")
        .collect()
    )
    return out


def split_summary(features: pl.DataFrame) -> list[dict[str, Any]]:
    rows = (
        features.group_by("split")
        .agg(
            pl.len().alias("n_windows"),
            pl.col("label").sum().alias("n_positive_windows"),
            pl.col("n_labeled_events").sum().alias("n_labeled_events"),
            pl.col("src_principal").n_unique().alias("n_principals"),
            pl.col("window_start").min().alias("start_seconds"),
            pl.col("window_end").max().alias("end_seconds"),
        )
        .to_dicts()
    )
    order = {"warmup": 0, "train": 1, "validation": 2, "test": 3, "out_of_range": 4}
    return sorted(rows, key=lambda r: order.get(r["split"], 9))
