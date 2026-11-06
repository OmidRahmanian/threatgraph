from __future__ import annotations

import polars as pl

from tests.conftest import auth_frame
from threatgraph.data.redteam import match_redteam
from threatgraph.data.schema import REDTEAM_SCHEMA


def rt(rows: list[tuple[int, str, str, str]]) -> pl.DataFrame:
    return pl.DataFrame(
        [(i, *r) for i, r in enumerate(rows)],
        schema=list(REDTEAM_SCHEMA),
        orient="row",
    ).cast(REDTEAM_SCHEMA)


AUTH = auth_frame(
    [
        (0, 100, "U1@DOM1", "C1", "C2", "Success"),
        (1, 100, "U1@DOM1", "C1", "C2", "Success"),  # repeated line -> ambiguous key
        (2, 100, "U2@DOM1", "C1", "C2", "Success"),  # same time/computers, other user
        (3, 200, "U1@DOM1", "C2", "C3", "Success"),
        (4, 201, "U1@DOM1", "C2", "C4", "Success"),
    ]
)


def test_composite_key_join() -> None:
    labels, report = match_redteam(
        AUTH,
        rt(
            [
                (100, "U1@DOM1", "C1", "C2"),
                (200, "U1@DOM1", "C2", "C3"),
                (200, "U1@DOM1", "C2", "C3"),  # duplicate record
                (201, "U1@DOM1", "C2", "C9"),  # wrong destination -> unmatched
                (300, "U1@DOM1", "C2", "C3"),  # no event at that time -> unmatched
            ]
        ),
        user_field="source",
        label_source="synthetic_redteam",
    )
    assert labels["event_id"].to_list() == [0, 1, 3]  # never event 2 (different user)
    mult = dict(zip(labels["event_id"], labels["match_multiplicity"], strict=True))
    assert mult == {0: 2, 1: 2, 3: 1}
    assert report["distinct_keys"] == 4
    assert report["duplicate_records"] == 1
    assert report["keys_matched"] == 2
    assert report["keys_unmatched"] == 2
    assert report["keys_ambiguous"] == 1
    assert report["auth_events_labeled"] == 3
    assert set(labels["label_source"]) == {"synthetic_redteam"}


def test_destination_user_field() -> None:
    lf = AUTH.with_columns(
        pl.when(pl.col("event_id") == 4)
        .then(pl.lit("U7@DOM1"))
        .otherwise(pl.col("dst_principal"))
        .alias("dst_principal")
    )
    rec = rt([(201, "U7@DOM1", "C2", "C4")])
    src_labels, _ = match_redteam(lf, rec, user_field="source", label_source="x")
    dst_labels, _ = match_redteam(lf, rec, user_field="destination", label_source="x")
    assert src_labels.is_empty()
    assert dst_labels["event_id"].to_list() == [4]


def test_empty_redteam() -> None:
    labels, report = match_redteam(AUTH, rt([]), user_field="source", label_source="x")
    assert labels.is_empty() and report["keys_matched"] == 0
