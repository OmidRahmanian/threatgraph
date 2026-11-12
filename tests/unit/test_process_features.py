"""Process features (LANL proc.txt): exact counts, causality and chunk-size invariance."""

from __future__ import annotations

from pathlib import Path

import polars as pl

from tests.conftest import auth_frame, make_cfg, write_gz
from threatgraph import pipeline
from threatgraph.data.features import PROCESS_FEATURES, build_window_features
from threatgraph.data.synthetic import SyntheticSpec, generate_fixture

H = 3600


def proc_frame(rows: list[tuple[int, str, str, str, str]]) -> pl.LazyFrame:
    return pl.DataFrame(
        [
            {
                "event_time_seconds": t,
                "day": t // 86_400,
                "principal": u,
                "computer": c,
                "process": p,
                "action": a,
            }
            for t, u, c, p, a in rows
        ]
    ).lazy()


def feats(auth_rows, proc_rows, cfg) -> pl.DataFrame:
    labels = pl.DataFrame(schema={"event_id": pl.Int64})
    return build_window_features(auth_frame(auth_rows), labels, cfg, proc_frame(proc_rows))


def test_counts_novelty_rarity_and_after_remote(tmp_cfg) -> None:
    auth = [
        (0, 10, "U1@DOM1", "C1", "C1", "Success"),
        (1, H + 10, "U1@DOM1", "C1", "C9", "Success"),  # lateral logon to C9
        (2, 20, "U2@DOM1", "C2", "C2", "Success"),
    ]
    proc = [
        (30, "U2@DOM1", "C2", "P1", "Start"),  # U2 runs P1 first
        (40, "U1@DOM1", "C1", "P1", "Start"),
        (50, "U1@DOM1", "C1", "P1", "End"),  # ends do not count
        (60, "U1@DOM1", "C1", "P2", "Start"),
        (H + 100, "U1@DOM1", "C9", "P7", "Start"),  # 90 s after the lateral logon
        (H + 900, "U1@DOM1", "C9", "P1", "Start"),  # too late for "after remote"
        (H + 950, "C9$@DOM1", "C9", "P3", "Start"),  # machine account: not scored
    ]
    df = (
        feats(auth, proc, tmp_cfg).filter(pl.col("src_principal") == "U1@DOM1").sort("window_start")
    )
    w0, w1 = df.row(0, named=True), df.row(1, named=True)
    assert (w0["n_proc_start"], w0["n_distinct_proc"], w0["n_novel_proc"]) == (2, 2, 2)
    # P1 was first started by U2 in the same window, not before it: still rare; P2 too.
    assert w0["n_rare_proc"] == 2 and w0["n_proc_after_remote"] == 0
    assert (w1["n_proc_start"], w1["n_novel_proc"], w1["n_proc_hosts"]) == (2, 1, 1)
    # In window 1, P1 had been started by another account (U2) earlier: not rare. P7 is.
    assert w1["n_rare_proc"] == 1
    assert w1["n_proc_after_remote"] == 1


def test_without_proc_log_features_are_null_not_zero(tmp_cfg) -> None:
    labels = pl.DataFrame(schema={"event_id": pl.Int64})
    df = build_window_features(
        auth_frame([(0, 10, "U1@DOM1", "C1", "C2", "Success")]), labels, tmp_cfg
    )
    for c in PROCESS_FEATURES:
        assert df[c].null_count() == df.height


def _fixture(tmp: Path):
    cfg = make_cfg(tmp)
    generate_fixture(cfg.raw_path, SyntheticSpec(seed=42))
    pipeline.run_ingest(cfg)
    labels = pl.read_parquet(pipeline.labels_path(cfg))
    return cfg, labels


def test_process_features_are_causal_and_chunk_invariant(tmp_path: Path) -> None:
    cfg, labels = _fixture(tmp_path)
    auth, proc = pipeline.scan_auth(cfg), pipeline.scan_proc(cfg)
    full = build_window_features(auth, labels, cfg, proc)
    assert full["n_proc_start"].sum() > 0 and full["n_novel_proc"].sum() > 0
    # Causality: truncating the logs after day 6 does not change any earlier window.
    cut = 6 * 86_400
    trunc = build_window_features(
        auth.filter(pl.col("event_time_seconds") < cut),
        labels,
        cfg,
        proc.filter(pl.col("event_time_seconds") < cut),
    )
    cols = ["window_id", *PROCESS_FEATURES, "emb_dst_surprise_max", "emb_dst_surprise_mean"]
    before = full.filter(pl.col("window_end") <= cut).select(cols).sort("window_id")
    assert before.equals(trunc.filter(pl.col("window_end") <= cut).select(cols).sort("window_id"))
    # Chunk size changes nothing.
    hourly = cfg.model_copy(
        update={"features": cfg.features.model_copy(update={"chunk_seconds": 3600})}
    )
    other = build_window_features(auth, labels, hourly, proc)
    assert full.select(cols).sort("window_id").equals(other.select(cols).sort("window_id"))


def test_proc_ingest_reports_rejections(tmp_path: Path) -> None:
    cfg = make_cfg(tmp_path)
    write_gz(cfg.raw_file("auth"), ["1,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success"])
    write_gz(cfg.raw_file("redteam"), ["1,U1@DOM1,C1,C2"])
    write_gz(
        cfg.raw_file("proc"),
        [
            "1,U1@DOM1,C1,P1,Start",
            "2,?,C1,P1,Start",
            "x,U1@DOM1,C1,P1,Start",
            "3,U1@DOM1,C1,P1,Stop",
            "4,U1@DOM1",
        ],
    )
    q = pipeline.run_ingest(cfg)["proc"]
    assert q["rows_accepted"] == 1 and q["rows_rejected"] == 4
    assert set(q["rejected_by_reason"]) == {
        "missing_principal",
        "non_integer_time",
        "invalid_action",
        "wrong_column_count",
    }
