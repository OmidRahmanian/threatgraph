"""Causal process features per (principal, window) from LANL-format `proc.txt` events.

Same scoring unit and causality rules as the authentication features: a window's features use
only process events with time < window end, novelty and rarity compare against strictly
earlier windows, and state crossing a time-chunk boundary is carried explicitly, so the output
does not depend on the chunk size (tests/unit/test_process_features.py checks this).

Features (only process *starts* count):

- `n_proc_start`: processes started by the principal in the window.
- `n_distinct_proc`: distinct process names started.
- `n_novel_proc`: process names this principal had never started before (on any computer).
- `n_rare_proc`: process names no *other* principal (machine accounts included) had started
  before the window.
- `n_proc_hosts`: distinct computers on which the principal started processes.
- `n_proc_after_remote`: starts on a computer within `PROC_AFTER_REMOTE_SECONDS` after the
  principal authenticated to that computer from a different computer (activity right after a
  lateral logon).

Windows exist only where the principal had authentication activity (the scoring unit is set
by the auth log); process activity in other windows is not scored.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import polars as pl

from threatgraph.config import DatasetConfig
from threatgraph.data.features import (
    KEYS,
    PROCESS_FEATURES,
    P,
    _is_user_principal,
    chunk_of,
    scoped_events,
)

PROC_AFTER_REMOTE_SECONDS = 300


@dataclass
class _ProcState:
    seen_any: pl.DataFrame = (
        field(  # first window each (principal, process) was seen, all principals
            default_factory=lambda: pl.DataFrame(
                schema={"principal": pl.String, "process": pl.String, "first_ws": pl.Int64}
            )
        )
    )
    last_arrival: pl.DataFrame = field(
        default_factory=lambda: pl.DataFrame(
            schema={P: pl.String, "computer": pl.String, "t_arr": pl.Int64}
        )
    )


def _chunk(
    proc_chunk: pl.LazyFrame,
    auth_chunk: pl.LazyFrame,
    cfg: DatasetConfig,
    st: _ProcState,
    chunk_end: int,
) -> pl.DataFrame | None:
    w = cfg.features.window_seconds
    starts = (
        proc_chunk.filter(pl.col("action") == "Start")
        .select("event_time_seconds", "principal", "computer", "process")
        .with_columns((pl.col("event_time_seconds") // w * w).alias("window_start"))
        .collect()
    )
    # Arrivals by lateral logon (scoped auth events between two different computers).
    remote = (
        scoped_events(auth_chunk, cfg)
        .filter(
            (pl.col("outcome") == "Success")
            & pl.col("src_computer").is_not_null()
            & pl.col("dst_computer").is_not_null()
            & (pl.col("src_computer") != pl.col("dst_computer"))
        )
        .select(
            P, pl.col("dst_computer").alias("computer"), pl.col("event_time_seconds").alias("t_arr")
        )
        .collect()
    )
    arrivals = pl.concat([st.last_arrival, remote]).sort("t_arr")
    st.last_arrival = (
        arrivals.group_by(P, "computer")
        .agg(pl.col("t_arr").max())
        .filter(pl.col("t_arr") >= chunk_end - PROC_AFTER_REMOTE_SECONDS)
    )
    if starts.is_empty():
        return None

    # First observation of each (principal, process) in this chunk, against carried state.
    firsts = starts.group_by("principal", "process").agg(
        pl.col("window_start").min().alias("first_ws")
    )
    new = firsts.join(
        st.seen_any.select("principal", "process"), on=["principal", "process"], how="anti"
    )
    prior = st.seen_any
    st.seen_any = pl.concat([st.seen_any, new])

    scoped = starts.rename({"principal": P}).filter(
        _is_user_principal() if cfg.features.principals == "users_only" else pl.lit(True)
    )
    if scoped.is_empty():
        return None
    novel = (
        new.rename({"principal": P})
        .join(scoped.select(P).unique(), on=P, how="semi")
        .group_by(P, pl.col("first_ws").alias("window_start"))
        .agg(pl.len().alias("n_novel_proc"))
    )

    # Rarity: distinct *other* principals whose first start of the process came in an earlier
    # window (carried state plus earlier windows of this chunk).
    pairs = scoped.select(P, "window_start", "process").unique()
    seen_all = pl.concat([prior, new])
    popularity = (
        seen_all.filter(pl.col("process").is_in(pairs["process"].unique().implode()))
        .group_by("process", "first_ws")
        .agg(pl.len().alias("n"))
        .sort("process", "first_ws")
        .with_columns(pl.col("n").cum_sum().over("process").alias("n_before"))
        .sort("first_ws")
    )
    rare = (
        pairs.sort("window_start")
        .join_asof(
            popularity.select("process", "first_ws", "n_before"),
            left_on="window_start",
            right_on="first_ws",
            by="process",
            strategy="backward",
            allow_exact_matches=False,
            check_sortedness=False,
        )
        .join(
            seen_all.rename({"principal": P, "first_ws": "_own_first"}),
            on=[P, "process"],
            how="left",
        )
        .with_columns(
            (
                pl.col("n_before").fill_null(0)
                - (pl.col("_own_first") < pl.col("window_start")).cast(pl.Int64)
            ).alias("_others")
        )
        .group_by(KEYS)
        .agg((pl.col("_others") == 0).sum().cast(pl.Int64).alias("n_rare_proc"))
    )

    after_remote = (
        scoped.filter(pl.col("computer").is_not_null())
        .sort("event_time_seconds")
        .join_asof(
            arrivals,
            left_on="event_time_seconds",
            right_on="t_arr",
            by=[P, "computer"],
            strategy="backward",
            check_sortedness=False,
        )
        .filter(
            pl.col("t_arr").is_not_null()
            & (pl.col("event_time_seconds") - pl.col("t_arr") <= PROC_AFTER_REMOTE_SECONDS)
        )
        .group_by(KEYS)
        .agg(pl.len().alias("n_proc_after_remote"))
    )

    base = scoped.group_by(KEYS).agg(
        pl.len().alias("n_proc_start"),
        pl.col("process").n_unique().alias("n_distinct_proc"),
        pl.col("computer").drop_nulls().n_unique().alias("n_proc_hosts"),
    )
    out = base
    for part in (novel, rare, after_remote):
        out = out.join(part, on=KEYS, how="left")
    return out


def build_process_features(
    proc: pl.LazyFrame, auth: pl.LazyFrame, cfg: DatasetConfig, chunks: list[tuple[int, int]]
) -> pl.DataFrame:
    """Process features for every (principal, window) with process starts, over `chunks`."""
    st = _ProcState()
    parts = []
    for start, end in chunks:
        part = _chunk(chunk_of(proc, start, end), chunk_of(auth, start, end), cfg, st, end)
        if part is not None:
            parts.append(part)
    cols = list(PROCESS_FEATURES)
    if not parts:
        return pl.DataFrame(
            schema={P: pl.String, "window_start": pl.Int64, **dict.fromkeys(cols, pl.Int64)}
        )
    return pl.concat(parts, how="diagonal").with_columns(
        pl.col(c).fill_null(0).cast(pl.Int64) for c in cols
    )
