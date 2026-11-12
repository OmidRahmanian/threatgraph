"""Raw-file integrity checks and research dataset status (pending vs evaluated)."""

from __future__ import annotations

from pathlib import Path

from tests.conftest import make_cfg, write_gz
from threatgraph.config import load_models_config
from threatgraph.data.integrity import verify_raw
from threatgraph.serving.datasets import dataset_status

AUTH = [
    "1,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success",
    "2,U2@DOM1,U2@DOM1,C2,C3,NTLM,Network,LogOn,Fail",
    "3,U3@DOM1,U3@DOM1,C3,C4,Kerberos,Network,LogOn,Success",
]
REDTEAM = ["2,U2@DOM1,C2,C3"]


def _files(tmp: Path, auth: list[str], redteam: list[str] = REDTEAM):
    cfg = make_cfg(tmp, files={"auth": "auth.txt.gz", "redteam": "redteam.txt.gz"})
    write_gz(cfg.raw_file("auth"), auth)
    write_gz(cfg.raw_file("redteam"), redteam)
    return cfg


def test_quick_and_full_checks_agree_on_clean_file(tmp_path: Path) -> None:
    cfg = _files(tmp_path, AUTH)
    quick = verify_raw(cfg)
    full = verify_raw(cfg, full=True)
    assert quick["ok"] and full["ok"]
    assert quick["files"]["auth"]["check"]["sampled_rows"] == 3
    assert full["files"]["auth"]["check"]["rows"] == 3
    assert full["files"]["auth"]["check"]["last_time_seconds"] == 3


def test_unsorted_time_fails_verification(tmp_path: Path) -> None:
    cfg = _files(tmp_path, [AUTH[1], AUTH[0], AUTH[2]])
    rep = verify_raw(cfg, full=True)
    assert not rep["ok"]
    assert rep["files"]["auth"]["check"]["time_decreases"] == 1
    assert "assume_sorted" in rep["files"]["auth"]["warning"]


def test_malformed_rows_are_counted(tmp_path: Path) -> None:
    cfg = _files(
        tmp_path, [*AUTH, "x,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success", "4,a,b"]
    )
    rep = verify_raw(cfg, full=True)
    chk = rep["files"]["auth"]["check"]
    assert chk["non_integer_time"] == 1 and chk["wrong_column_count"] == 1


def test_truncated_gzip_is_detected(tmp_path: Path) -> None:
    cfg = _files(tmp_path, AUTH * 2000)
    path = cfg.raw_file("auth")
    path.write_bytes(path.read_bytes()[:-40])  # cut off the end of the gzip stream
    rep = verify_raw(cfg, full=True)
    assert not rep["ok"] and "error" in rep["files"]["auth"]


def test_replaced_file_changes_hash(tmp_path: Path) -> None:
    cfg = _files(tmp_path, AUTH)
    first = verify_raw(cfg, sha256=True)
    assert first["files"]["auth"]["sha256_matches_previous"] is None
    assert verify_raw(cfg, sha256=True)["files"]["auth"]["sha256_matches_previous"] is True
    write_gz(cfg.raw_file("auth"), AUTH[:2])
    changed = verify_raw(cfg, sha256=True)
    assert changed["files"]["auth"]["sha256_matches_previous"] is False and not changed["ok"]


def test_missing_files_are_pending_not_evaluated(tmp_path: Path) -> None:
    cfg = make_cfg(tmp_path, mode="lanl")
    st = dataset_status(cfg, load_models_config())
    assert st.status == "files_missing"
    assert st.models == [] and st.rows_accepted is None


def test_present_but_unprocessed_files_are_pending(tmp_path: Path) -> None:
    cfg = _files(tmp_path, AUTH)
    st = dataset_status(cfg, load_models_config())
    assert st.status == "not_processed" and st.models == []
