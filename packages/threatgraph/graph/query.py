"""Bounded subgraph queries over the per-window edge table.

A query names a focus entity (a principal or a computer) and a time range. Hop 1 is the
focus entity's own edges. Hop 2 adds other principals' edges that touch hop-1 computers,
except through hubs: computers used by more than `hub_max_principals` principals in the range
(domain controllers, file servers), which would connect everyone to everyone. Results are
capped at `max_edges` with a stated order, and `truncated` says when the cap applied.

Truncation order: hop, then edges first observed inside the range, then failures, then event
count. Red-team labels are *not* used to choose what is shown, so the view does not favor
labeled activity; labels are only displayed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import polars as pl

EntityType = Literal["principal", "computer"]
EDGE_ID = ["src_principal", "src_computer", "dst_computer"]


@dataclass
class SubgraphResult:
    edges: pl.DataFrame  # one row per (principal, src, dst) aggregated over the range
    nodes: pl.DataFrame  # one row per computer
    n_edges_total: int
    truncated: bool


def _aggregate(lf: pl.LazyFrame, hop: int, start: int, sample_limit: int) -> pl.LazyFrame:
    return (
        lf.group_by(EDGE_ID)
        .agg(
            pl.col("n_events").sum(),
            pl.col("n_success").sum(),
            pl.col("n_fail").sum(),
            pl.col("n_known_redteam").sum(),
            pl.col("first_t").min(),
            pl.col("last_t").max(),
            pl.col("window_start").n_unique().cast(pl.Int64).alias("n_windows"),
            pl.col("auth_types").explode().drop_nulls().unique().sort().alias("auth_types"),
            pl.col("edge_first_seen_seconds").min(),
            # Hours with labeled events first, so a labeled sample is never cut off here.
            pl.col("sample_event_ids")
            .sort_by(["n_known_redteam", "window_start"], descending=[True, False])
            .explode()
            .head(sample_limit)
            .alias("sample_event_ids"),
        )
        .with_columns(
            pl.lit(hop).cast(pl.Int8).alias("hop"),
            (pl.col("edge_first_seen_seconds") >= start).alias("first_observed_in_range"),
            (pl.col("src_computer") == pl.col("dst_computer")).alias("is_local"),
        )
    )


def subgraph(
    edges: pl.LazyFrame,
    *,
    focus_type: EntityType,
    focus_key: str,
    start: int,
    end: int,
    window_seconds: int,
    hops: int = 1,
    max_edges: int = 60,
    hub_max_principals: int = 15,
    sample_limit: int = 6,
) -> SubgraphResult:
    lo = start // window_seconds * window_seconds
    rng = edges.filter((pl.col("window_start") >= lo) & (pl.col("window_start") < end))
    if focus_type == "principal":
        own = pl.col("src_principal") == focus_key
    else:
        own = (pl.col("src_computer") == focus_key) | (pl.col("dst_computer") == focus_key)
    hop1 = _aggregate(rng.filter(own), 1, lo, sample_limit).collect()
    computers = set(hop1["src_computer"]) | set(hop1["dst_computer"])
    if focus_type == "computer":
        computers.add(focus_key)

    def principal_counts(nodes: set[str]) -> dict[str, int]:
        if not nodes:
            return {}
        touch = pl.concat(
            [
                rng.select(pl.col("src_computer").alias("c"), "src_principal"),
                rng.select(pl.col("dst_computer").alias("c"), "src_principal"),
            ]
        ).filter(pl.col("c").is_in(sorted(nodes)))
        rows = touch.group_by("c").agg(pl.col("src_principal").n_unique()).collect().rows()
        return dict(rows)

    counts = principal_counts(computers)
    expand: set[str] = set()
    parts = [hop1]
    if hops >= 2:
        expand = {c for c in computers if counts.get(c, 0) <= hub_max_principals}
        if focus_type == "computer":
            expand.discard(focus_key)  # its own edges are already hop 1
        if expand:
            ids = sorted(expand)
            touches = pl.col("src_computer").is_in(ids) | pl.col("dst_computer").is_in(ids)
            parts.append(_aggregate(rng.filter(touches & ~own), 2, lo, sample_limit).collect())
    all_edges = pl.concat(parts)
    ranked = all_edges.sort(
        ["hop", "first_observed_in_range", "n_fail", "n_events", *EDGE_ID],
        descending=[False, True, True, True, False, False, False],
    )
    kept = ranked.head(max_edges)

    node_ids = set(kept["src_computer"]) | set(kept["dst_computer"])
    if focus_type == "computer":
        node_ids.add(focus_key)
    counts.update(principal_counts(node_ids - set(counts)))
    hop1_nodes = set(hop1["src_computer"]) | set(hop1["dst_computer"])
    nodes = pl.DataFrame(
        {
            "computer": sorted(node_ids),
            "hop": [
                0
                if (focus_type == "computer" and c == focus_key)
                else (1 if c in hop1_nodes else 2)
                for c in sorted(node_ids)
            ],
            "n_principals_in_range": [counts.get(c, 0) for c in sorted(node_ids)],
            "is_hub": [counts.get(c, 0) > hub_max_principals for c in sorted(node_ids)],
            "expanded": [
                hops >= 2 and (c in expand or (focus_type == "computer" and c == focus_key))
                for c in sorted(node_ids)
            ],
        },
        schema={
            "computer": pl.String,
            "hop": pl.Int8,
            "n_principals_in_range": pl.Int64,
            "is_hub": pl.Boolean,
            "expanded": pl.Boolean,
        },
    )
    return SubgraphResult(
        edges=kept,
        nodes=nodes,
        n_edges_total=all_edges.height,
        truncated=kept.height < all_edges.height,
    )
