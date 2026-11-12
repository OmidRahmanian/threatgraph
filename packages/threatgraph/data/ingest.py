"""Streaming, bounded-memory ingestion of LANL-format auth and red-team files.

The source files are read with pyarrow's incremental CSV reader (one block at a time, gzip
decoded on the fly), validated with Polars, and written as day-partitioned Parquet. Peak
memory is governed by `ingest.block_size_bytes`, not by file size.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import duckdb
import polars as pl
import pyarrow as pa
import pyarrow.csv as pacsv

from threatgraph.config import DAY_SECONDS, DatasetConfig
from threatgraph.data.schema import (
    AUTH_EVENT_SCHEMA,
    AUTH_OUTCOMES,
    AUTH_SOURCE_COLUMNS,
    MISSING_TOKEN,
    PROC_ACTIONS,
    PROC_EVENT_SCHEMA,
    PROC_SOURCE_COLUMNS,
    REDTEAM_SCHEMA,
    REDTEAM_SOURCE_COLUMNS,
)

MAX_EXAMPLES = 10


@dataclass
class RejectLog:
    counts: Counter[str] = field(default_factory=Counter)
    examples: list[dict[str, str]] = field(default_factory=list)

    def add(self, reason: str, text: str, n: int = 1) -> None:
        self.counts[reason] += n
        if len(self.examples) < MAX_EXAMPLES:
            self.examples.append({"reason": reason, "text": text[:200]})

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def iter_csv_batches(
    path: Path, columns: Sequence[str], block_size: int, rejects: RejectLog
) -> Iterator[pl.DataFrame]:
    """Yield raw string-typed batches; rows with the wrong column count go to `rejects`."""

    def on_invalid(row: Any) -> str:
        rejects.add("wrong_column_count", row.text or "")
        return "skip"

    compression = "gzip" if path.suffix == ".gz" else None
    stream = pa.input_stream(str(path), compression=compression)
    reader = pacsv.open_csv(
        stream,
        read_options=pacsv.ReadOptions(
            column_names=list(columns), block_size=block_size, use_threads=False
        ),
        parse_options=pacsv.ParseOptions(quote_char=False, invalid_row_handler=on_invalid),
        convert_options=pacsv.ConvertOptions(
            column_types={c: pa.string() for c in columns}, strings_can_be_null=False
        ),
    )
    for batch in reader:
        if batch.num_rows:
            yield pl.from_arrow(pa.Table.from_batches([batch]))  # type: ignore[misc]


def _null_missing(df: pl.DataFrame, cols: Sequence[str]) -> pl.DataFrame:
    """`?` (LANL's missing marker) and empty strings become explicit nulls."""
    return df.with_columns(
        pl.when(pl.col(c).is_in([MISSING_TOKEN, ""])).then(None).otherwise(pl.col(c)).alias(c)
        for c in cols
    )


def validate_auth_batch(raw: pl.DataFrame, rejects: RejectLog) -> pl.DataFrame:
    """Type-check one raw batch. Returns accepted rows (with `time` cast) in input order."""
    df = raw.with_columns(pl.col("time").str.strip_chars().cast(pl.Int64, strict=False).alias("_t"))
    reason = (
        pl.when(pl.col("_t").is_null())
        .then(pl.lit("non_integer_time"))
        .when(pl.col("_t") < 0)
        .then(pl.lit("negative_time"))
        .when(~pl.col("outcome").is_in([*AUTH_OUTCOMES, MISSING_TOKEN]))
        .then(pl.lit("invalid_outcome"))
        .when(pl.col("src_principal").is_in([MISSING_TOKEN, ""]))
        .then(pl.lit("missing_source_principal"))
        .otherwise(None)
    )
    df = df.with_columns(reason.alias("_reason"))
    bad = df.filter(pl.col("_reason").is_not_null())
    for r in bad.iter_rows(named=True):
        text = ",".join(str(r[c]) for c in AUTH_SOURCE_COLUMNS)
        rejects.add(r["_reason"], text)
    good = df.filter(pl.col("_reason").is_null()).drop("time", "_reason").rename({"_t": "time"})
    return _null_missing(good, [c for c in AUTH_SOURCE_COLUMNS if c != "time"])


def to_internal_auth(df: pl.DataFrame, first_event_id: int, mode: str) -> pl.DataFrame:
    n = df.height
    return df.select(
        pl.Series("event_id", range(first_event_id, first_event_id + n), dtype=pl.Int64),
        pl.lit("auth").alias("event_family"),
        pl.col("time").alias("event_time_seconds"),
        (pl.col("time") // DAY_SECONDS).cast(pl.Int32).alias("day"),
        *[pl.col(c) for c in AUTH_SOURCE_COLUMNS[1:]],
        pl.lit(mode).alias("dataset_mode"),
    ).cast(AUTH_EVENT_SCHEMA)  # type: ignore[arg-type]


def _file_info(path: Path, with_hash: bool) -> dict[str, Any]:
    info: dict[str, Any] = {"name": path.name, "size_bytes": path.stat().st_size}
    if with_hash:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        info["sha256"] = h.hexdigest()
    return info


def ingest_auth(cfg: DatasetConfig, out_dir: Path) -> dict[str, Any]:
    src = cfg.raw_file("auth")
    if not src.exists():
        raise FileNotFoundError(src)
    auth_dir = out_dir / "auth"
    if auth_dir.exists():
        for p in sorted(auth_dir.rglob("*.parquet")):
            p.unlink()
    rejects = RejectLog()
    window = cfg.time_window
    rows_read = accepted = outside = 0
    missing: Counter[str] = Counter()
    started = time.perf_counter()
    next_id = 0
    stopped_early = False
    for batch_idx, raw in enumerate(
        iter_csv_batches(src, AUTH_SOURCE_COLUMNS, cfg.ingest.block_size_bytes, rejects)
    ):
        rows_read += raw.height
        good = validate_auth_batch(raw, rejects)
        # event_id is assigned before the time-window filter so ids are stable across windows.
        events = to_internal_auth(good, next_id, cfg.mode)
        next_id += good.height
        in_window = events.filter(
            (pl.col("event_time_seconds") >= window.start_seconds)
            & (
                pl.lit(True)
                if window.end_seconds is None
                else pl.col("event_time_seconds") <= window.end_seconds
            )
        )
        outside += events.height - in_window.height
        if in_window.height:
            for c in AUTH_SOURCE_COLUMNS[1:]:
                missing[c] += in_window[c].null_count()
            for (day,), part in in_window.partition_by(
                "day", as_dict=True, maintain_order=True
            ).items():
                d = auth_dir / f"day={int(day):05d}"
                d.mkdir(parents=True, exist_ok=True)
                part.drop("day").write_parquet(
                    d / f"part-{batch_idx:06d}.parquet", compression="zstd"
                )
            accepted += in_window.height
        if (
            cfg.ingest.assume_sorted
            and window.end_seconds is not None
            and events.height
            and events["event_time_seconds"].min() > window.end_seconds  # type: ignore[operator]
        ):
            stopped_early = True
            break
    elapsed = time.perf_counter() - started

    stats = _auth_table_stats(auth_dir) if accepted else {}
    return {
        "source_file": _file_info(src, cfg.ingest.hash_source_files),
        "rows_read": rows_read + rejects.counts["wrong_column_count"],
        "rows_rejected": rejects.total,
        "rejected_by_reason": dict(sorted(rejects.counts.items())),
        "rejection_examples": rejects.examples,
        "rows_outside_time_window": outside,
        "rows_accepted": accepted,
        "stopped_early_at_window_end": stopped_early,
        "missing_by_column": {c: missing[c] for c in AUTH_SOURCE_COLUMNS[1:]},
        "ingest_seconds": round(elapsed, 3),
        "rows_per_second": round((rows_read / elapsed) if elapsed else 0.0, 1),
        **stats,
    }


def auth_glob(processed: Path) -> str:
    return str(processed / "auth" / "**" / "*.parquet")


def _auth_table_stats(auth_dir: Path) -> dict[str, Any]:
    glob = str(auth_dir / "**" / "*.parquet")
    con = duckdb.connect()
    # Bounded memory: DuckDB spills the DISTINCT counts to disk next to the processed data.
    con.execute("SET memory_limit='2GB'")
    con.execute(f"SET temp_directory='{auth_dir.parent / '.duckdb_tmp'}'")
    src = f"read_parquet('{glob}', hive_partitioning=true)"
    row = con.execute(
        f"""
        SELECT count(*), min(event_time_seconds), max(event_time_seconds),
               count(DISTINCT src_principal), count(DISTINCT dst_principal),
               count(DISTINCT src_computer), count(DISTINCT dst_computer),
               count(DISTINCT day)
        FROM {src}
        """
    ).fetchone()
    assert row is not None
    cols = ", ".join(AUTH_SOURCE_COLUMNS[1:])
    distinct_rows = con.execute(
        f"SELECT count(*) FROM (SELECT DISTINCT event_time_seconds, {cols} FROM {src})"
    ).fetchone()
    computers = con.execute(
        f"SELECT count(*) FROM (SELECT src_computer c FROM {src} UNION SELECT dst_computer FROM {src}) "
        "WHERE c IS NOT NULL"
    ).fetchone()
    by_family = con.execute(
        f"SELECT auth_orientation, count(*) FROM {src} GROUP BY 1 ORDER BY 2 DESC"
    ).fetchall()
    con.close()
    assert distinct_rows is not None and computers is not None
    return {
        "time_min_seconds": row[1],
        "time_max_seconds": row[2],
        "days_covered": row[7],
        "duplicate_rows": row[0] - distinct_rows[0],
        "distinct": {
            "src_principal": row[3],
            "dst_principal": row[4],
            "src_computer": row[5],
            "dst_computer": row[6],
            "computers_total": computers[0],
        },
        "rows_by_orientation": {str(k): v for k, v in by_family},
    }


def proc_glob(processed: Path) -> str:
    return str(processed / "proc" / "**" / "*.parquet")


def ingest_proc(cfg: DatasetConfig, out_dir: Path) -> dict[str, Any]:
    """Stream the optional LANL `proc.txt` file (process start/end) into day partitions.

    Same guarantees as the auth importer: bounded memory, every rejected row counted with its
    reason, the configured time window, and an early stop past the window end when the file is
    time-sorted.
    """
    src = cfg.raw_file("proc")
    if not src.exists():
        raise FileNotFoundError(src)
    proc_dir = out_dir / "proc"
    if proc_dir.exists():
        for p in sorted(proc_dir.rglob("*.parquet")):
            p.unlink()
    rejects = RejectLog()
    window = cfg.time_window
    rows_read = accepted = outside = 0
    missing: Counter[str] = Counter()
    started = time.perf_counter()
    stopped_early = False
    for batch_idx, raw in enumerate(
        iter_csv_batches(src, PROC_SOURCE_COLUMNS, cfg.ingest.block_size_bytes, rejects)
    ):
        rows_read += raw.height
        df = raw.with_columns(
            pl.col("time").str.strip_chars().cast(pl.Int64, strict=False).alias("_t")
        )
        reason = (
            pl.when(pl.col("_t").is_null())
            .then(pl.lit("non_integer_time"))
            .when(pl.col("_t") < 0)
            .then(pl.lit("negative_time"))
            .when(~pl.col("action").is_in(list(PROC_ACTIONS)))
            .then(pl.lit("invalid_action"))
            .when(pl.col("principal").is_in([MISSING_TOKEN, ""]))
            .then(pl.lit("missing_principal"))
            .when(pl.col("process").is_in([MISSING_TOKEN, ""]))
            .then(pl.lit("missing_process"))
            .otherwise(None)
        )
        df = df.with_columns(reason.alias("_reason"))
        for r in df.filter(pl.col("_reason").is_not_null()).iter_rows(named=True):
            rejects.add(r["_reason"], ",".join(str(r[c]) for c in PROC_SOURCE_COLUMNS))
        good = (
            _null_missing(df.filter(pl.col("_reason").is_null()), ["computer"])
            .select(
                pl.col("_t").alias("event_time_seconds"),
                (pl.col("_t") // DAY_SECONDS).cast(pl.Int32).alias("day"),
                "principal",
                "computer",
                "process",
                "action",
            )
            .cast(PROC_EVENT_SCHEMA)  # type: ignore[arg-type]
        )
        in_window = good.filter(
            (pl.col("event_time_seconds") >= window.start_seconds)
            & (
                pl.lit(True)
                if window.end_seconds is None
                else pl.col("event_time_seconds") <= window.end_seconds
            )
        )
        outside += good.height - in_window.height
        if in_window.height:
            missing["computer"] += in_window["computer"].null_count()
            for (day,), part in in_window.partition_by(
                "day", as_dict=True, maintain_order=True
            ).items():
                d = proc_dir / f"day={int(day):05d}"
                d.mkdir(parents=True, exist_ok=True)
                part.drop("day").write_parquet(
                    d / f"part-{batch_idx:06d}.parquet", compression="zstd"
                )
            accepted += in_window.height
        if (
            cfg.ingest.assume_sorted
            and window.end_seconds is not None
            and good.height
            and good["event_time_seconds"].min() > window.end_seconds  # type: ignore[operator]
        ):
            stopped_early = True
            break
    elapsed = time.perf_counter() - started
    stats: dict[str, Any] = {}
    if accepted:
        con = duckdb.connect()
        row = con.execute(
            "SELECT min(event_time_seconds), max(event_time_seconds), count(DISTINCT principal), "
            "count(DISTINCT computer), count(DISTINCT process), "
            "count(*) FILTER (WHERE action = 'Start') "
            f"FROM read_parquet('{proc_glob(out_dir)}', hive_partitioning=true)"
        ).fetchone()
        con.close()
        assert row is not None
        stats = {
            "time_min_seconds": row[0],
            "time_max_seconds": row[1],
            "distinct": {"principal": row[2], "computer": row[3], "process": row[4]},
            "starts": row[5],
        }
    return {
        "source_file": _file_info(src, cfg.ingest.hash_source_files),
        "rows_read": rows_read + rejects.counts["wrong_column_count"],
        "rows_rejected": rejects.total,
        "rejected_by_reason": dict(sorted(rejects.counts.items())),
        "rejection_examples": rejects.examples,
        "rows_outside_time_window": outside,
        "rows_accepted": accepted,
        "stopped_early_at_window_end": stopped_early,
        "missing_by_column": dict(missing),
        "ingest_seconds": round(elapsed, 3),
        "rows_per_second": round((rows_read / elapsed) if elapsed else 0.0, 1),
        **stats,
    }


def ingest_redteam(cfg: DatasetConfig, out_dir: Path) -> tuple[pl.DataFrame, dict[str, Any]]:
    src = cfg.raw_file("redteam")
    if not src.exists():
        raise FileNotFoundError(src)
    rejects = RejectLog()
    frames = list(iter_csv_batches(src, REDTEAM_SOURCE_COLUMNS, 1 << 20, rejects))
    raw = (
        pl.concat(frames)
        if frames
        else pl.DataFrame(schema=dict.fromkeys(REDTEAM_SOURCE_COLUMNS, pl.String))
    )
    df = raw.with_columns(pl.col("time").str.strip_chars().cast(pl.Int64, strict=False).alias("_t"))
    for r in df.filter(pl.col("_t").is_null() | (pl.col("_t") < 0)).iter_rows(named=True):
        rejects.add("non_integer_time", ",".join(str(r[c]) for c in REDTEAM_SOURCE_COLUMNS))
    df = _null_missing(
        df.filter(pl.col("_t").is_not_null() & (pl.col("_t") >= 0)),
        REDTEAM_SOURCE_COLUMNS[1:],
    )
    rt = df.select(
        pl.int_range(pl.len(), dtype=pl.Int64).alias("redteam_record_id"),
        pl.col("_t").alias("event_time_seconds"),
        "principal",
        "src_computer",
        "dst_computer",
    ).cast(REDTEAM_SCHEMA)  # type: ignore[arg-type]
    w = cfg.time_window
    in_window = rt.filter(
        (pl.col("event_time_seconds") >= w.start_seconds)
        & (pl.lit(True) if w.end_seconds is None else pl.col("event_time_seconds") <= w.end_seconds)
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    in_window.write_parquet(out_dir / "redteam.parquet")
    key = ["event_time_seconds", "principal", "src_computer", "dst_computer"]
    report = {
        "source_file": _file_info(src, cfg.ingest.hash_source_files),
        "records_total": rt.height,
        "records_rejected": rejects.total,
        "rejected_by_reason": dict(rejects.counts),
        "records_in_time_window": in_window.height,
        "duplicate_records_in_window": in_window.height - in_window.unique(subset=key).height,
        "distinct_principals_in_window": in_window["principal"].n_unique(),
        "records_by_day": {
            str(k): v
            for k, v in rt.group_by((pl.col("event_time_seconds") // DAY_SECONDS).alias("d"))
            .len()
            .sort("d")
            .iter_rows()
        },
    }
    return in_window, report


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=False, default=str) + "\n")
