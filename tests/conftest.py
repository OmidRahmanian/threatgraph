from __future__ import annotations

import gzip
from collections.abc import Iterable
from pathlib import Path

import polars as pl
import pytest
import yaml

from threatgraph.config import DatasetConfig, load_dataset_config

AUTH_HEADERLESS = Iterable[str]


def write_gz(path: Path, lines: Iterable[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def make_cfg(tmp: Path, **overrides: object) -> DatasetConfig:
    """Demo config re-rooted into a temp directory."""
    base = load_dataset_config("demo").model_dump()
    base.update(
        raw_dir=str(tmp / "raw"),
        processed_dir=str(tmp / "processed"),
        artifacts_dir=str(tmp / "artifacts"),
    )
    base.update(overrides)
    return DatasetConfig(**base)


def write_datasets_yaml(path: Path, cfg: DatasetConfig) -> Path:
    data = cfg.model_dump(mode="json")
    name = data.pop("name")
    path.write_text(yaml.safe_dump({"datasets": {name: data}}))
    return path


def auth_frame(rows: list[tuple]) -> pl.LazyFrame:
    """Internal-schema auth events from compact tuples:
    (event_id, t, src_principal, src_computer, dst_computer, outcome[, auth_type, orientation])."""
    recs = []
    for r in rows:
        eid, t, user, src, dst, outcome, *rest = r
        auth_type = rest[0] if len(rest) > 0 else "Kerberos"
        orient = rest[1] if len(rest) > 1 else "LogOn"
        recs.append(
            {
                "event_id": eid,
                "event_family": "auth",
                "event_time_seconds": t,
                "day": t // 86_400,
                "src_principal": user,
                "dst_principal": user,
                "src_computer": src,
                "dst_computer": dst,
                "auth_type": auth_type,
                "logon_type": "Network",
                "auth_orientation": orient,
                "outcome": outcome,
                "dataset_mode": "synthetic",
            }
        )
    return pl.DataFrame(recs).lazy()


@pytest.fixture
def tmp_cfg(tmp_path: Path) -> DatasetConfig:
    return make_cfg(tmp_path)
