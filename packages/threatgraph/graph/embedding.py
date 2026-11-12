"""Causal graph-embedding features (a lightweight alternative to a GNN benchmark).

Each relative day, the account × destination-computer graph of *all earlier days* (log-scaled
authentication counts, LogOff and machine accounts excluded) is factorized with a truncated
SVD (scikit-learn, CPU only, fixed seed). Accounts and computers that tend to connect get
similar vectors. A window's features then measure how far the computers the account reached
lie from the account's own position in that earlier graph:

- `emb_dst_surprise_max`: largest 1 - cosine(account, destination) over the window's
  destinations that existed in the earlier graph;
- `emb_dst_surprise_mean`: the mean of the same quantity.

The embedding for day d uses only events before day d starts, so the features are causal.
Accounts or computers absent from the earlier graph contribute nothing here (the novelty
features already count them), and both features are 0 when nothing is comparable.

This is not a message-passing GNN: it needs no PyTorch or GPU, and it is deterministic. A real
GNN benchmark remains an optional, unimplemented extension (docs/modeling.md).
"""

from __future__ import annotations

import numpy as np
import polars as pl
import scipy.sparse as sp
from sklearn.decomposition import TruncatedSVD

from threatgraph.config import DAY_SECONDS, DatasetConfig
from threatgraph.data.features import EMBEDDING_FEATURES, KEYS, P, scoped_events

EMBEDDING_DIM = 16


def _embed(counts: pl.DataFrame, seed: int) -> tuple[dict[str, np.ndarray], dict[str, np.ndarray]]:
    accounts = counts[P].unique().sort().to_list()
    computers = counts["dst_computer"].unique().sort().to_list()
    if len(accounts) < 3 or len(computers) < 3:
        return {}, {}
    ai = {a: i for i, a in enumerate(accounts)}
    ci = {c: i for i, c in enumerate(computers)}
    m = sp.csr_matrix(
        (
            np.log1p(counts["n"].to_numpy().astype(float)),
            ([ai[a] for a in counts[P]], [ci[c] for c in counts["dst_computer"]]),
        ),
        shape=(len(accounts), len(computers)),
    )
    k = min(EMBEDDING_DIM, min(m.shape) - 1)
    svd = TruncatedSVD(n_components=k, algorithm="randomized", n_iter=7, random_state=seed)
    u = svd.fit_transform(m)  # accounts: U * S
    v = svd.components_.T * svd.singular_values_  # computers: V * S
    norm = lambda x: x / np.maximum(np.linalg.norm(x, axis=1, keepdims=True), 1e-12)  # noqa: E731
    u, v = norm(u), norm(v)
    return {a: u[i] for a, i in ai.items()}, {c: v[i] for c, i in ci.items()}


def build_embedding_features(auth: pl.LazyFrame, cfg: DatasetConfig) -> pl.DataFrame:
    w = cfg.features.window_seconds
    ev = scoped_events(auth, cfg).filter(pl.col("dst_computer").is_not_null())
    days = (
        ev.select((pl.col("event_time_seconds") // DAY_SECONDS).alias("d"))
        .unique()
        .sort("d")
        .collect()["d"]
        .to_list()
    )
    history = pl.DataFrame(schema={P: pl.String, "dst_computer": pl.String, "n": pl.Int64})
    rows = []
    for d in days:
        lo, hi = d * DAY_SECONDS, (d + 1) * DAY_SECONDS
        day_ev = ev.filter(
            (pl.col("event_time_seconds") >= lo) & (pl.col("event_time_seconds") < hi)
        )
        acc, comp = _embed(history, cfg.seed) if history.height else ({}, {})
        triples = (
            day_ev.select(
                P, "dst_computer", (pl.col("event_time_seconds") // w * w).alias("window_start")
            )
            .unique()
            .collect()
        )
        for (principal, ws), grp in triples.group_by([P, "window_start"]):
            a = acc.get(str(principal))
            dists = (
                [
                    1.0 - float(a @ comp[c])
                    for c in sorted(grp["dst_computer"].to_list())
                    if c in comp
                ]
                if a is not None
                else []
            )
            rows.append(
                (
                    principal,
                    ws,
                    max(dists) if dists else 0.0,
                    float(np.mean(dists)) if dists else 0.0,
                )
            )
        today = day_ev.group_by(P, "dst_computer").agg(pl.len().cast(pl.Int64).alias("n")).collect()
        history = (
            pl.concat([history, today])
            .group_by(P, "dst_computer")
            .agg(pl.col("n").sum())
            .sort(P, "dst_computer")
        )
    out = pl.DataFrame(
        rows,
        schema={
            P: pl.String,
            "window_start": pl.Int64,
            **dict.fromkeys(EMBEDDING_FEATURES, pl.Float64),
        },
        orient="row",
    )
    return out.sort(KEYS)
