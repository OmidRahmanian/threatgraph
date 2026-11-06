from __future__ import annotations

import polars as pl
import pytest
from polars.testing import assert_frame_equal

from tests.conftest import auth_frame
from threatgraph.config import DatasetConfig
from threatgraph.data.features import FEATURE_DESCRIPTIONS, build_window_features
from threatgraph.data.ingest import ingest_auth
from threatgraph.data.schema import LABEL_SCHEMA
from threatgraph.data.synthetic import SyntheticSpec, generate_fixture
from threatgraph.pipeline import scan_auth

H = 3600
NO_LABELS = pl.DataFrame(schema=LABEL_SCHEMA)


def feats(rows: list[tuple], cfg: DatasetConfig, labels: pl.DataFrame = NO_LABELS) -> pl.DataFrame:
    return build_window_features(auth_frame(rows), labels, cfg)


def row(df: pl.DataFrame, principal: str, start: int) -> dict:
    return df.filter(
        (pl.col("src_principal") == principal) & (pl.col("window_start") == start)
    ).row(0, named=True)


def test_counts_novelty_and_scope(tmp_cfg) -> None:
    df = feats(
        [
            (0, 10, "U1@DOM1", "C1", "C2", "Success"),
            (1, 20, "U1@DOM1", "C1", "C2", "Fail"),
            (2, 30, "U1@DOM1", "C1", "C2", "Success"),  # success right after failure
            (3, 40, "U1@DOM1", "C1", "C3", "Success", "NTLM"),
            (4, 50, "U1@DOM1", "C3", "C3", "Success", None, "LogOff"),  # excluded (LogOff)
            (5, 60, "C1$@DOM1", "C1", "C9", "Success"),  # excluded (machine account)
            (6, H + 5, "U1@DOM1", "C1", "C2", "Success"),  # known destination
            (7, H + 9, "U1@DOM1", "C1", "C4", "Success"),  # new destination
        ],
        tmp_cfg,
    )
    assert set(df["src_principal"]) == {"U1@DOM1"}
    w0, w1 = row(df, "U1@DOM1", 0), row(df, "U1@DOM1", H)
    assert w0["n_events"] == 4 and w0["n_fail"] == 1
    assert w0["fail_ratio"] == pytest.approx(0.25)
    assert w0["n_distinct_dst"] == 2 and w0["n_novel_dst"] == 2
    assert w0["n_post_fail_success"] == 1
    assert w0["ntlm_ratio"] == pytest.approx(0.25)
    assert w0["n_novel_auth_type"] == 2  # Kerberos and NTLM first seen
    assert w1["n_novel_dst"] == 1 and w1["novel_dst_ratio"] == pytest.approx(0.5)
    assert w1["n_novel_edge"] == 1  # C1->C4 never seen; C1->C2 seen in window 0
    assert w1["n_novel_auth_type"] == 0
    assert w0["log_prior_windows"] == pytest.approx(0.0)
    assert w1["log_prior_windows"] > 0
    assert w1["window_id"] == f"w:U1@DOM1:{H}"


def test_rolling_baseline_excludes_current_window(tmp_cfg) -> None:
    rows = []
    eid = 0
    for w, n in enumerate([2, 2, 2, 10]):
        for i in range(n):
            rows.append((eid, w * H + i, "U1@DOM1", "C1", "C2", "Success"))
            eid += 1
    df = feats(rows, tmp_cfg).sort("window_start")
    z = df["z_events"].to_list()
    assert z[0] == 0.0  # cold start: no history -> no evidence of deviation
    assert z[1] == pytest.approx(0.0)
    assert z[3] == pytest.approx((10 - 2) / (0 + 1))  # baseline uses prior windows only


def test_labels_and_splits(tmp_cfg) -> None:
    day = 86_400
    rows = [
        (0, 1 * day, "U1@DOM1", "C1", "C2", "Success"),
        (1, 3 * day, "U1@DOM1", "C1", "C2", "Success"),
        (2, 3 * day + 10, "U1@DOM1", "C1", "C3", "Success"),
        (3, 9 * day, "U1@DOM1", "C1", "C2", "Success"),
        (4, 12 * day, "U1@DOM1", "C1", "C2", "Success"),
    ]
    labels = pl.DataFrame(
        {
            "event_id": [2],
            "label_source": ["x"],
            "redteam_record_id": [0],
            "match_multiplicity": [1],
        }
    ).cast(LABEL_SCHEMA)
    df = feats(rows, tmp_cfg, labels).sort("window_start")
    assert df["split"].to_list() == ["warmup", "train", "validation", "test"]
    labeled = df.filter(pl.col("label") == 1)
    assert labeled.height == 1 and labeled["n_labeled_events"][0] == 1
    assert labeled["first_labeled_event_seconds"][0] == 3 * day + 10
    # Labels never leak into model features.
    assert "label" not in FEATURE_DESCRIPTIONS and "n_labeled_events" not in FEATURE_DESCRIPTIONS


def test_features_are_causal_on_fixture(tmp_path) -> None:
    """Features for windows ending before a cutoff must not change when later data is removed."""
    from tests.conftest import make_cfg

    cfg = make_cfg(tmp_path)
    generate_fixture(cfg.raw_path, SyntheticSpec(seed=7))
    ingest_auth(cfg, cfg.processed_path)
    full_auth = scan_auth(cfg).collect()
    cutoff = 6 * 86_400 + 5 * H
    full = build_window_features(full_auth.lazy(), NO_LABELS, cfg)
    truncated = build_window_features(
        full_auth.filter(pl.col("event_time_seconds") < cutoff).lazy(), NO_LABELS, cfg
    )
    cols = ["window_id", *FEATURE_DESCRIPTIONS]
    a = full.filter(pl.col("window_end") <= cutoff).select(cols).sort("window_id")
    b = truncated.filter(pl.col("window_end") <= cutoff).select(cols).sort("window_id")
    assert a.height > 1000
    assert_frame_equal(a, b)
