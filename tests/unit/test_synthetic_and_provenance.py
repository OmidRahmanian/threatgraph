from __future__ import annotations

import gzip

from threatgraph.data.schema import AUTH_SOURCE_COLUMNS, REDTEAM_SOURCE_COLUMNS
from threatgraph.data.synthetic import SyntheticSpec, generate_fixture
from threatgraph.provenance import mode_label, provenance_block


def test_fixture_is_deterministic(tmp_path) -> None:
    a = generate_fixture(tmp_path / "a", SyntheticSpec(seed=11))
    b = generate_fixture(tmp_path / "b", SyntheticSpec(seed=11))
    c = generate_fixture(tmp_path / "c", SyntheticSpec(seed=12))
    assert a.manifest["files"] == b.manifest["files"]
    assert (
        a.manifest["files"]["auth.txt.gz"]["sha256"] != c.manifest["files"]["auth.txt.gz"]["sha256"]
    )


def test_fixture_matches_lanl_format_and_is_marked_synthetic(tmp_path) -> None:
    res = generate_fixture(tmp_path, SyntheticSpec(seed=5))
    assert res.manifest["synthetic"] is True
    with gzip.open(res.auth_path, "rt") as fh:
        lines = fh.read().splitlines()
    widths = [len(line.split(",")) for line in lines]
    malformed = len(res.manifest["injected_quality_issues"]["malformed_rows"])
    # Every line has LANL's 9 columns except the injected wrong-width rows.
    assert sum(w != len(AUTH_SOURCE_COLUMNS) for w in widths) == 3
    assert malformed == 5
    with gzip.open(res.redteam_path, "rt") as fh:
        rt = fh.read().splitlines()
    assert all(len(line.split(",")) == len(REDTEAM_SOURCE_COLUMNS) for line in rt)
    times = [int(line.split(",")[0]) for line in rt]
    assert times == sorted(times)
    # Some attacker activity is deliberately left unlabeled.
    unlabeled = sum(
        c["unlabeled_failures"] + c["unlabeled_successful_hops"] for c in res.manifest["campaigns"]
    )
    assert unlabeled > 0


def test_mode_labels() -> None:
    assert mode_label("synthetic") == "Synthetic demo"
    syn = provenance_block("demo", "synthetic", "abc")
    real = provenance_block("lanl", "lanl", "abc")
    assert syn["is_synthetic"] and syn["label_source"] == "synthetic_redteam"
    assert "Not real network activity" in syn["source"]
    assert not real["is_synthetic"] and real["label_source"] == "lanl_redteam"
    assert "Kent" in real["source"] and "not live threat intelligence" in real["source"]
