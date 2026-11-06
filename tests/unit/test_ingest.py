from __future__ import annotations

import polars as pl

from tests.conftest import write_gz
from threatgraph.config import TimeWindow
from threatgraph.data.ingest import RejectLog, ingest_auth, ingest_redteam, validate_auth_batch
from threatgraph.pipeline import scan_auth

GOOD = [
    "1,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success",
    "2,C3$@DOM1,C3$@DOM1,C3,C9,?,?,TGS,Success",
    "3,U2@DOM1,SYSTEM@C2,C2,C2,Negotiate,Service,LogOn,Fail",
    "90000,U1@DOM1,U1@DOM1,C1,C5,NTLM,Network,LogOn,Success",
]
BAD = [
    "4,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network",  # too few columns
    "x5,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success",  # non-integer time
    "6,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Maybe",  # invalid outcome
    "7,?,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success",  # missing source principal
    "not a record",
]


def test_validate_rejects_with_reasons() -> None:
    raw = pl.DataFrame(
        [r.split(",") for r in [GOOD[0], BAD[1], BAD[2], BAD[3]]],
        schema=[
            "time",
            "src_principal",
            "dst_principal",
            "src_computer",
            "dst_computer",
            "auth_type",
            "logon_type",
            "auth_orientation",
            "outcome",
        ],
        orient="row",
    )
    rejects = RejectLog()
    good = validate_auth_batch(raw, rejects)
    assert good.height == 1
    assert dict(rejects.counts) == {
        "non_integer_time": 1,
        "invalid_outcome": 1,
        "missing_source_principal": 1,
    }


def test_ingest_parses_nulls_rejects_and_ids(tmp_cfg) -> None:
    write_gz(tmp_cfg.raw_file("auth"), [GOOD[0], BAD[0], GOOD[1], BAD[1], GOOD[2], BAD[4], GOOD[3]])
    report = ingest_auth(tmp_cfg, tmp_cfg.processed_path)
    assert report["rows_accepted"] == 4
    assert report["rows_rejected"] == 3
    assert report["rejected_by_reason"] == {"non_integer_time": 1, "wrong_column_count": 2}
    assert report["missing_by_column"]["auth_type"] == 1
    assert report["missing_by_column"]["logon_type"] == 1

    df = scan_auth(tmp_cfg).sort("event_id").collect()
    # `?` is an explicit null, never the literal string.
    machine = df.filter(pl.col("src_principal") == "C3$@DOM1").row(0, named=True)
    assert machine["auth_type"] is None and machine["logon_type"] is None
    assert (df["auth_type"] == "?").sum() == 0
    # Identifiers are preserved verbatim; ids follow accepted-row file order.
    assert df["event_id"].to_list() == [0, 1, 2, 3]
    assert df["src_principal"].to_list()[0] == "U1@DOM1"
    assert set(df["day"].to_list()) == {0, 1}
    assert report["distinct"]["computers_total"] == 5


def test_time_window_filter_keeps_stable_ids(tmp_cfg) -> None:
    write_gz(tmp_cfg.raw_file("auth"), GOOD)
    cfg = tmp_cfg.model_copy(update={"time_window": TimeWindow(start_seconds=2, end_seconds=10)})
    report = ingest_auth(cfg, cfg.processed_path)
    df = scan_auth(cfg).collect().sort("event_id")
    assert df["event_id"].to_list() == [1, 2]  # same ids as an unfiltered ingest
    assert report["rows_outside_time_window"] == 2


def test_duplicate_rows_are_counted_not_dropped(tmp_cfg) -> None:
    write_gz(tmp_cfg.raw_file("auth"), [GOOD[0], GOOD[0], GOOD[1]])
    report = ingest_auth(tmp_cfg, tmp_cfg.processed_path)
    assert report["rows_accepted"] == 3
    assert report["duplicate_rows"] == 1


def test_redteam_ingest_and_window(tmp_cfg) -> None:
    write_gz(
        tmp_cfg.raw_file("redteam"),
        ["5,U1@DOM1,C1,C2", "5,U1@DOM1,C1,C2", "bad,U1@DOM1,C1,C2", "999999,U9@DOM1,C1,C3"],
    )
    cfg = tmp_cfg.model_copy(update={"time_window": TimeWindow(start_seconds=0, end_seconds=1000)})
    rt, report = ingest_redteam(cfg, cfg.processed_path)
    assert rt.height == 2
    assert report["records_rejected"] == 1
    assert report["duplicate_records_in_window"] == 1
    assert report["records_by_day"] == {"0": 2, "11": 1}
