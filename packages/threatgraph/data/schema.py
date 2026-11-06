"""Source schemas (exactly as published by LANL) and the internal typed event schema."""

from __future__ import annotations

import polars as pl

MISSING_TOKEN = "?"

# Column order of the published, header-less files (https://csr.lanl.gov/data/cyber1/).
AUTH_SOURCE_COLUMNS: tuple[str, ...] = (
    "time",
    "src_principal",  # source user@domain
    "dst_principal",  # destination user@domain
    "src_computer",
    "dst_computer",
    "auth_type",
    "logon_type",
    "auth_orientation",
    "outcome",  # success/failure
)
REDTEAM_SOURCE_COLUMNS: tuple[str, ...] = ("time", "principal", "src_computer", "dst_computer")

AUTH_OUTCOMES = frozenset({"Success", "Fail"})

# Internal schema for authentication events written to Parquet.
AUTH_EVENT_SCHEMA: dict[str, pl.DataType] = {
    "event_id": pl.Int64(),  # ordinal of the accepted row in source-file order
    "event_family": pl.String(),
    "event_time_seconds": pl.Int64(),  # relative seconds from LANL's arbitrary epoch
    "day": pl.Int32(),
    "src_principal": pl.String(),
    "dst_principal": pl.String(),
    "src_computer": pl.String(),
    "dst_computer": pl.String(),
    "auth_type": pl.String(),
    "logon_type": pl.String(),
    "auth_orientation": pl.String(),
    "outcome": pl.String(),
    "dataset_mode": pl.String(),
}

REDTEAM_SCHEMA: dict[str, pl.DataType] = {
    "redteam_record_id": pl.Int64(),
    "event_time_seconds": pl.Int64(),
    "principal": pl.String(),
    "src_computer": pl.String(),
    "dst_computer": pl.String(),
}

LABEL_SCHEMA: dict[str, pl.DataType] = {
    "event_id": pl.Int64(),
    "label_source": pl.String(),
    "redteam_record_id": pl.Int64(),
    "match_multiplicity": pl.Int64(),  # auth events sharing this red-team key (>1 = ambiguous)
}
