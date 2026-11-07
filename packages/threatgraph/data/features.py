"""Causal behavioral and graph features per (source principal, fixed time window).

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

Graph features
    `n_rare_dst` counts destinations that no *other* in-scope principal had authenticated to
    before the window. `n_pivot_src` counts source computers the principal authenticated
    from after reaching them itself as a remote destination (a two-hop path A→B, B→C) within
    `pivot_lookback_seconds`. Both use only earlier events.

Bounded memory
    Events are processed in time chunks (`features.chunk_seconds`). Everything that crosses a
    chunk boundary (first-seen sets, the last outcome per destination, recent arrivals) is
    carried as explicit state, so the output is identical for any chunk size
    (tests/unit/test_features.py checks this) and peak memory follows one chunk.

Cold start
    `log_prior_windows` encodes how much history a principal has. Rolling baselines with no
    history yield z = 0 (no evidence of deviation) rather than an imputed mean.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import polars as pl

from threatgraph.config import DAY_SECONDS, DatasetConfig

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
    "n_rare_dst": "Destinations in the window that no other account had authenticated to before",
    "n_pivot_src": "Source computers the account had itself reached as a remote destination "
    "shortly before (two-hop path)",
}

ID_COLUMNS = ["window_id", "src_principal", "window_start", "window_end", "day", "split"]
LABEL_COLUMNS = ["n_labeled_events", "label"]
TIME_COLUMNS = ["first_event_seconds", "last_event_seconds", "first_labeled_event_seconds"]
EVENT_COLUMNS = [
    "event_id",
    "event_time_seconds",
    "src_principal",
    "src_computer",
    "dst_computer",
    "auth_type",
    "outcome",
]

P = "src_principal"
KEYS = [P, "window_start"]


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


def time_chunks(auth: pl.LazyFrame, chunk_seconds: int) -> list[tuple[int, int]]:
    """Half-open [start, end) ranges aligned to `chunk_seconds` that cover every event."""
    lo, hi = (
        auth.select(
            pl.col("event_time_seconds").min().alias("lo"),
            pl.col("event_time_seconds").max().alias("hi"),
        )
        .collect()
        .row(0)
    )
    if lo is None:
        return []
    first = lo // chunk_seconds * chunk_seconds
    return [(s, s + chunk_seconds) for s in range(first, hi + 1, chunk_seconds)]


def chunk_of(auth: pl.LazyFrame, start: int, end: int) -> pl.LazyFrame:
    """Events in [start, end). Also filters the hive `day` partition so whole days are skipped."""
    lf = auth.filter((pl.col("event_time_seconds") >= start) & (pl.col("event_time_seconds") < end))
    if "day" in auth.collect_schema().names():
        lf = lf.filter(pl.col("day").is_between(start // DAY_SECONDS, (end - 1) // DAY_SECONDS))
    return lf


def _empty(schema: dict[str, Any]) -> pl.DataFrame:
    return pl.DataFrame(schema=schema)


@dataclass
class _State:
    """Everything a chunk needs to know about earlier chunks."""

    seen_dst: pl.DataFrame = field(
        default_factory=lambda: _empty(
            {P: pl.String, "dst_computer": pl.String, "first_ws": pl.Int64}
        )
    )
    seen_src: pl.DataFrame = field(
        default_factory=lambda: _empty({P: pl.String, "src_computer": pl.String})
    )
    seen_auth: pl.DataFrame = field(
        default_factory=lambda: _empty({P: pl.String, "auth_type": pl.String})
    )
    seen_edge: pl.DataFrame = field(
        default_factory=lambda: _empty({"src_computer": pl.String, "dst_computer": pl.String})
    )
    last_outcome: pl.DataFrame = field(
        default_factory=lambda: _empty(
            {P: pl.String, "dst_computer": pl.String, "_carry": pl.String}
        )
    )
    last_arrival: pl.DataFrame = field(
        default_factory=lambda: _empty({P: pl.String, "computer": pl.String, "t_arr": pl.Int64})
    )


def _novel(
    ev: pl.DataFrame, seen: pl.DataFrame, col: str, name: str
) -> tuple[pl.DataFrame, pl.DataFrame]:
    """(per-window counts of first observations, the newly seen keys with their window)."""
    firsts = ev.filter(pl.col(col).is_not_null()).group_by(P, col).agg(pl.col("window_start").min())
    new = firsts.join(seen.select(P, col), on=[P, col], how="anti")
    counts = new.group_by(KEYS).agg(pl.len().alias(name))
    return counts, new


def _chunk_features(
    chunk_all: pl.LazyFrame,
    labels: pl.DataFrame,
    cfg: DatasetConfig,
    st: _State,
    chunk_end: int,
) -> pl.DataFrame | None:
    w = cfg.features.window_seconds
    burst = cfg.features.burst_seconds
    lookback = cfg.features.pivot_lookback_seconds

    # Global computer-edge novelty uses every event, including machine accounts and LogOff.
    edges = (
        chunk_all.filter(
            pl.col("src_computer").is_not_null() & pl.col("dst_computer").is_not_null()
        )
        .group_by("src_computer", "dst_computer")
        .agg(pl.col("event_time_seconds").min().alias("first_t"))
        .collect()
    )
    new_edges = edges.join(st.seen_edge, on=["src_computer", "dst_computer"], how="anti")
    st.seen_edge = pl.concat([st.seen_edge, new_edges.select("src_computer", "dst_computer")])

    ev = (
        scoped_events(chunk_all, cfg)
        .select(EVENT_COLUMNS)
        .with_columns((pl.col("event_time_seconds") // w * w).alias("window_start"))
        .sort("event_time_seconds", "event_id")
        .collect()
    )
    if ev.is_empty():
        return None

    novel_dst, new_dst = _novel(ev, st.seen_dst, "dst_computer", "n_novel_dst")
    novel_src, new_src = _novel(ev, st.seen_src, "src_computer", "n_novel_src")
    novel_auth, new_auth = _novel(ev, st.seen_auth, "auth_type", "n_novel_auth_type")
    st.seen_dst = pl.concat([st.seen_dst, new_dst.rename({"window_start": "first_ws"})])
    st.seen_src = pl.concat([st.seen_src, new_src.select(P, "src_computer")])
    st.seen_auth = pl.concat([st.seen_auth, new_auth.select(P, "auth_type")])

    # A novel edge counts toward the window of the principal event that realises its first
    # observation (machine-account first observations count toward no principal window).
    novel_edge = (
        ev.join(new_edges, on=["src_computer", "dst_computer"], how="inner")
        .filter(pl.col("event_time_seconds") == pl.col("first_t"))
        .group_by(KEYS)
        .agg(pl.struct("src_computer", "dst_computer").n_unique().alias("n_novel_edge"))
    )

    # The previous outcome on the same (principal, destination), continuing across chunks.
    grp = [P, "dst_computer"]
    with_prev = ev.with_columns(
        pl.col("outcome").shift(1).over(grp).alias("_prev"),
        (pl.int_range(pl.len()).over(grp) == 0).alias("_first"),
    ).join(st.last_outcome, on=grp, how="left", nulls_equal=True)
    post_fail = (
        with_prev.with_columns(
            pl.when(pl.col("_first"))
            .then(pl.col("_carry"))
            .otherwise(pl.col("_prev"))
            .alias("_prev")
        )
        .filter((pl.col("outcome") == "Success") & (pl.col("_prev") == "Fail"))
        .group_by(KEYS)
        .agg(pl.len().alias("n_post_fail_success"))
    )
    st.last_outcome = pl.concat(
        [
            st.last_outcome,
            ev.group_by(grp, maintain_order=True).agg(pl.col("outcome").last().alias("_carry")),
        ]
    ).unique(subset=grp, keep="last", maintain_order=True)

    bursts = (
        ev.group_by(P, "window_start", pl.col("event_time_seconds") // burst)
        .agg(pl.len().alias("_n"))
        .group_by(KEYS)
        .agg(pl.col("_n").max().alias("max_burst"))
    )

    # Rare destinations: how many *other* principals had first reached the destination
    # before this window starts (strictly earlier windows only).
    triples = (
        ev.filter(pl.col("dst_computer").is_not_null())
        .select(P, "window_start", "dst_computer")
        .unique()
    )
    popularity = (
        st.seen_dst.filter(pl.col("dst_computer").is_in(triples["dst_computer"].unique().implode()))
        .group_by("dst_computer", "first_ws")
        .agg(pl.len().alias("n"))
        .sort("dst_computer", "first_ws")
        .with_columns(pl.col("n").cum_sum().over("dst_computer").alias("n_before"))
        .sort("first_ws")
    )
    rare = (
        triples.sort("window_start")
        .join_asof(
            popularity.select("dst_computer", "first_ws", "n_before"),
            left_on="window_start",
            right_on="first_ws",
            by="dst_computer",
            strategy="backward",
            allow_exact_matches=False,
            check_sortedness=False,  # both sides are sorted explicitly above
        )
        .join(st.seen_dst.rename({"first_ws": "_own_first"}), on=[P, "dst_computer"], how="left")
        .with_columns(
            (
                pl.col("n_before").fill_null(0)
                - (pl.col("_own_first") < pl.col("window_start")).cast(pl.Int64)
            ).alias("_others")
        )
        .group_by(KEYS)
        .agg((pl.col("_others") == 0).sum().cast(pl.Int64).alias("n_rare_dst"))
    )

    # Pivots: a remote authentication *from* a computer the principal had itself reached as a
    # remote destination at an earlier time (within the lookback).
    remote = ev.filter(
        pl.col("src_computer").is_not_null()
        & pl.col("dst_computer").is_not_null()
        & (pl.col("src_computer") != pl.col("dst_computer"))
    )
    arrivals = pl.concat(
        [
            st.last_arrival,
            remote.select(
                P,
                pl.col("dst_computer").alias("computer"),
                pl.col("event_time_seconds").alias("t_arr"),
            ),
        ]
    ).sort("t_arr")
    pivots = (
        remote.select(
            P, pl.col("src_computer").alias("computer"), "event_time_seconds", "window_start"
        )
        .sort("event_time_seconds")
        .join_asof(
            arrivals,
            left_on="event_time_seconds",
            right_on="t_arr",
            by=[P, "computer"],
            strategy="backward",
            allow_exact_matches=False,
            check_sortedness=False,  # both sides are sorted explicitly above
        )
        .filter(
            pl.col("t_arr").is_not_null()
            & (pl.col("event_time_seconds") - pl.col("t_arr") <= lookback)
        )
        .group_by(KEYS)
        .agg(pl.col("computer").n_unique().alias("n_pivot_src"))
    )
    st.last_arrival = (
        arrivals.group_by(P, "computer")
        .agg(pl.col("t_arr").max())
        .filter(pl.col("t_arr") >= chunk_end - lookback)
    )

    base = (
        ev.join(labels, on="event_id", how="left")
        .group_by(KEYS)
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
    df = base
    for part in (novel_dst, novel_src, novel_auth, novel_edge, post_fail, bursts, rare, pivots):
        df = df.join(part, on=KEYS, how="left")
    return df


def build_window_features(
    auth: pl.LazyFrame,
    labels: pl.DataFrame,
    cfg: DatasetConfig,
) -> pl.DataFrame:
    """Compute the feature table. `auth` must follow the internal auth schema."""
    w = cfg.features.window_seconds
    k = cfg.features.baseline_windows
    label_ev = labels.select("event_id").with_columns(pl.lit(1).alias("_lab"))

    st = _State()
    parts = []
    for start, end in time_chunks(auth, cfg.features.chunk_seconds):
        part = _chunk_features(chunk_of(auth, start, end), label_ev, cfg, st, end)
        if part is not None:
            parts.append(part)
    if not parts:
        raise ValueError("no in-scope authentication events to build features from")

    int_fill = [
        "n_novel_dst",
        "n_novel_src",
        "n_novel_auth_type",
        "n_novel_edge",
        "n_post_fail_success",
        "n_labeled_events",
        "n_rare_dst",
        "n_pivot_src",
    ]
    df = (
        pl.concat(parts)
        .lazy()
        .with_columns(pl.col(c).fill_null(0).cast(pl.Int64) for c in int_fill)
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
