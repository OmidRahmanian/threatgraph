"""Integrity checks for raw source files, run before trusting any real-data result.

`quick` mode reads only the first lines: is the file gzip, does every sampled row have the
expected number of columns, are sampled times integers and non-decreasing? `full` mode streams
the whole file once (bounded memory), which also proves the gzip stream is complete, counts
rows and checks time order everywhere. With `sha256=True` the compressed bytes are hashed and
compared with the hash recorded by the previous verification, so a replaced or truncated
download is detected before it silently changes results.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as pacsv

from threatgraph.config import DatasetConfig
from threatgraph.data.schema import AUTH_SOURCE_COLUMNS, REDTEAM_SOURCE_COLUMNS

COLUMNS = {"auth": AUTH_SOURCE_COLUMNS, "redteam": REDTEAM_SOURCE_COLUMNS}
QUICK_LINES = 10_000


def integrity_report_path(cfg: DatasetConfig) -> Path:
    return cfg.processed_path / "reports" / "source_integrity.json"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def _quick(path: Path, n_cols: int) -> dict[str, Any]:
    bad_cols = bad_time = out_of_order = n = 0
    prev: int | None = None
    first = last = None
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            n += 1
            parts = line.rstrip("\n").split(",")
            if len(parts) != n_cols:
                bad_cols += 1
            else:
                try:
                    t = int(parts[0])
                except ValueError:
                    bad_time += 1
                else:
                    first = t if first is None else first
                    last = t
                    if prev is not None and t < prev:
                        out_of_order += 1
                    prev = t
            if n >= QUICK_LINES:
                break
    return {
        "sampled_rows": n,
        "wrong_column_count": bad_cols,
        "non_integer_time": bad_time,
        "time_decreases": out_of_order,
        "first_time_seconds": first,
        "last_sampled_time_seconds": last,
    }


def _full(path: Path, columns: list[str], block_size: int) -> dict[str, Any]:
    """Stream every row of the time column; memory is bounded by `block_size`."""
    bad = 0

    def on_invalid(_: Any) -> str:
        nonlocal bad
        bad += 1
        return "skip"

    stream = pa.input_stream(str(path), compression="gzip" if path.suffix == ".gz" else None)
    reader = pacsv.open_csv(
        stream,
        read_options=pacsv.ReadOptions(column_names=columns, block_size=block_size),
        parse_options=pacsv.ParseOptions(quote_char=False, invalid_row_handler=on_invalid),
        convert_options=pacsv.ConvertOptions(
            include_columns=["time"], column_types={"time": pa.string()}
        ),
    )
    rows = decreases = non_int = 0
    first = prev = None
    for batch in reader:
        if not batch.num_rows:
            continue
        raw = batch.column(0)
        is_int = pc.match_substring_regex(raw, r"^\s*[0-9]+\s*$")
        ints = pc.cast(pc.utf8_trim_whitespace(pc.filter(raw, is_int)), pa.int64())
        rows += batch.num_rows
        non_int += batch.num_rows - len(ints)
        if len(ints) == 0:
            continue
        arr = ints.to_numpy(zero_copy_only=False)
        if prev is not None and arr[0] < prev:
            decreases += 1
        decreases += int((arr[1:] < arr[:-1]).sum())
        first = int(arr[0]) if first is None else first
        prev = int(arr[-1])
    return {
        "rows": rows,
        "wrong_column_count": bad,
        "non_integer_time": non_int,
        "time_decreases": decreases,
        "first_time_seconds": first,
        "last_time_seconds": prev,
        "gzip_stream_complete": True,
    }


def verify_raw(cfg: DatasetConfig, *, full: bool = False, sha256: bool = False) -> dict[str, Any]:
    """Check each raw file and write data/processed/<ds>/reports/source_integrity.json."""
    out = integrity_report_path(cfg)
    previous = json.loads(out.read_text()) if out.exists() else {}
    files: dict[str, Any] = {}
    ok = True
    for kind in ("auth", "redteam"):
        path = cfg.raw_file(kind)
        info: dict[str, Any] = {"name": path.name, "present": path.exists()}
        if not path.exists():
            files[kind] = info
            ok = False
            continue
        started = time.perf_counter()
        info["size_bytes"] = path.stat().st_size
        cols = list(COLUMNS[kind])
        try:
            info["check"] = (
                _full(path, cols, cfg.ingest.block_size_bytes) if full else _quick(path, len(cols))
            )
        except (OSError, EOFError, pa.ArrowInvalid) as exc:
            info["error"] = f"{type(exc).__name__}: {exc}"
            ok = False
        if sha256:
            info["sha256"] = _sha256(path)
            before = previous.get("files", {}).get(kind, {}).get("sha256")
            info["sha256_matches_previous"] = None if before is None else before == info["sha256"]
            if before is not None and before != info["sha256"]:
                ok = False
        info["seconds"] = round(time.perf_counter() - started, 3)
        chk = info.get("check", {})
        if chk.get("wrong_column_count") or chk.get("non_integer_time"):
            info["warning"] = "malformed rows found; ingest rejects them and reports each reason"
        if chk.get("time_decreases"):
            info["warning"] = (
                "time is not sorted; set ingest.assume_sorted: false for this dataset, "
                "otherwise ingest may stop early at the time-window end"
            )
            ok = False
        files[kind] = info
    report = {
        "dataset": cfg.name,
        "mode": "full" if full else "quick",
        "verified_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "ok": ok,
        "files": files,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n")
    return report
