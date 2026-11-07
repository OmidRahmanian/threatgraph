"""Entity graph tables built from processed authentication events.

Nodes are principals and computers. A directed edge is one principal authenticating from a
source computer to a destination computer; LANL's columns give the direction, and it is never
symmetrised. Edges are aggregated per time window into `edges/*.parquet` (sorted by window, so
time-range queries read only the row groups they need), which keeps graph queries bounded
without scanning raw events.

Scope matches the features: LogOff events and (by default) machine accounts are excluded, as
are events without both computers. `edge_first_seen_seconds` is the first time the computer
pair was observed in the processed data by *any* event, the same definition as the
`n_novel_edge` feature.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import polars as pl

from threatgraph.config import DatasetConfig
from threatgraph.data.features import chunk_of, scoped_events, time_chunks

PAIR = ["src_computer", "dst_computer"]
EDGE_KEY = ["window_start", "src_principal", "src_computer", "dst_computer"]


def edges_glob(graph_dir: Path) -> str:
    return str(graph_dir / "edges" / "*.parquet")


def build_edge_table(
    auth: pl.LazyFrame, labels: pl.DataFrame, cfg: DatasetConfig, graph_dir: Path
) -> dict[str, Any]:
    """Write the per-window edge table in chunks. Returns counts for the graph manifest."""
    w = cfg.features.window_seconds
    k = cfg.graph.sample_events_per_edge
    edge_dir = graph_dir / "edges"
    edge_dir.mkdir(parents=True, exist_ok=True)
    for old in edge_dir.glob("*.parquet"):
        old.unlink()
    label_ev = labels.select("event_id").with_columns(pl.lit(1).alias("_lab"))
    seen = pl.DataFrame(
        schema={
            "src_computer": pl.String,
            "dst_computer": pl.String,
            "edge_first_seen_seconds": pl.Int64,
        }
    )
    n_rows = n_events = dropped = 0
    for i, (start, end) in enumerate(time_chunks(auth, cfg.features.chunk_seconds)):
        chunk = chunk_of(auth, start, end)
        firsts = (
            chunk.filter(
                pl.col("src_computer").is_not_null() & pl.col("dst_computer").is_not_null()
            )
            .group_by(PAIR)
            .agg(pl.col("event_time_seconds").min().alias("edge_first_seen_seconds"))
            .collect()
        )
        seen = pl.concat([seen, firsts.join(seen, on=PAIR, how="anti")])
        ev = (
            scoped_events(chunk, cfg)
            .select(
                "event_id", "event_time_seconds", "src_principal", *PAIR, "auth_type", "outcome"
            )
            .collect()
        )
        complete = ev.filter(
            pl.col("src_computer").is_not_null() & pl.col("dst_computer").is_not_null()
        )
        dropped += ev.height - complete.height
        if complete.is_empty():
            continue
        edges = (
            complete.join(label_ev, on="event_id", how="left")
            .with_columns(
                pl.col("_lab").fill_null(0),
                (pl.col("event_time_seconds") // w * w).alias("window_start"),
            )
            .group_by(EDGE_KEY)
            .agg(
                pl.len().cast(pl.Int64).alias("n_events"),
                (pl.col("outcome") == "Success").sum().cast(pl.Int64).alias("n_success"),
                (pl.col("outcome") == "Fail").sum().cast(pl.Int64).alias("n_fail"),
                pl.col("_lab").sum().cast(pl.Int64).alias("n_known_redteam"),
                pl.col("event_time_seconds").min().alias("first_t"),
                pl.col("event_time_seconds").max().alias("last_t"),
                pl.col("auth_type").drop_nulls().unique().sort().alias("auth_types"),
                # Labeled events first, then earliest, so evidence for a labeled edge survives.
                pl.col("event_id")
                .sort_by(
                    ["_lab", "event_time_seconds", "event_id"], descending=[True, False, False]
                )
                .head(k)
                .alias("sample_event_ids"),
            )
            .join(seen, on=PAIR, how="left")
            .sort(EDGE_KEY)
        )
        edges.write_parquet(
            edge_dir / f"part-{i:05d}.parquet", compression="zstd", row_group_size=50_000
        )
        n_rows += edges.height
        n_events += complete.height
    return {"edge_rows": n_rows, "events_in_graph": n_events, "events_missing_a_computer": dropped}


def build_entity_tables(graph_dir: Path) -> dict[str, Any]:
    """Per-entity summaries and (computer, principal) links, both from the edge table."""
    edges = pl.scan_parquet(edges_glob(graph_dir))
    principals = (
        edges.group_by("src_principal")
        .agg(
            pl.col("first_t").min().alias("first_seen_seconds"),
            pl.col("last_t").max().alias("last_seen_seconds"),
            pl.col("n_events").sum(),
            pl.col("n_fail").sum(),
            pl.col("n_known_redteam").sum().alias("n_known_redteam_events"),
            pl.col("window_start").n_unique().cast(pl.Int64).alias("n_active_windows"),
            pl.col("src_computer").n_unique().cast(pl.Int64).alias("n_distinct_src_computers"),
            pl.col("dst_computer").n_unique().cast(pl.Int64).alias("n_distinct_dst_computers"),
        )
        .rename({"src_principal": "entity_key"})
        .with_columns(pl.lit("principal").alias("entity_type"))
    )
    remote = pl.col("src_computer") != pl.col("dst_computer")
    # One row per (computer, edge-row) incidence; a local logon (src == dst) counts once.
    incid = pl.concat(
        [
            edges.select(pl.col("src_computer").alias("computer"), pl.all()),
            edges.filter(remote).select(pl.col("dst_computer").alias("computer"), pl.all()),
        ]
    )
    computers = (
        incid.group_by("computer")
        .agg(
            pl.col("first_t").min().alias("first_seen_seconds"),
            pl.col("last_t").max().alias("last_seen_seconds"),
            pl.col("n_events").sum(),
            pl.col("n_fail").sum(),
            pl.col("n_known_redteam").sum().alias("n_known_redteam_events"),
            pl.col("src_principal").n_unique().cast(pl.Int64).alias("n_distinct_principals"),
            pl.col("src_computer")
            .filter(remote & (pl.col("dst_computer") == pl.col("computer")))
            .n_unique()
            .cast(pl.Int64)
            .alias("in_degree"),
            pl.col("dst_computer")
            .filter(remote & (pl.col("src_computer") == pl.col("computer")))
            .n_unique()
            .cast(pl.Int64)
            .alias("out_degree"),
            pl.col("n_events").filter(~remote).sum().cast(pl.Int64).alias("n_local_events"),
        )
        .rename({"computer": "entity_key"})
        .with_columns(pl.lit("computer").alias("entity_type"))
    )
    entities = (
        pl.concat([principals, computers], how="diagonal_relaxed")
        .sort("entity_type", "entity_key")
        .collect()
    )
    entities.write_parquet(graph_dir / "entities.parquet")
    links = (
        incid.group_by("computer", "src_principal")
        .agg(
            pl.col("n_events").sum(),
            pl.col("n_known_redteam").sum(),
            pl.col("first_t").min(),
            pl.col("last_t").max(),
        )
        .sort("computer", "src_principal")
        .collect()
    )
    links.write_parquet(graph_dir / "links.parquet", row_group_size=50_000)
    return {
        "principals": int((entities["entity_type"] == "principal").sum()),
        "computers": int((entities["entity_type"] == "computer").sum()),
        "computer_principal_links": links.height,
    }
