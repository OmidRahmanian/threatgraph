from __future__ import annotations

from threatgraph.config import DAY_SECONDS
from threatgraph.data.splits import suggest_splits, yaml_snippet

KW = {"warmup_days": 2, "train_days": 6, "validation_days": 3, "test_days": 3}


def test_picks_window_with_records_in_validation_and_test() -> None:
    # Records on days 20-21 and 24: start day 12 puts 21 in validation [20,23) and 24 in test.
    out = suggest_splits({20: 5, 21: 2, 24: 3}, **KW)
    assert out["ok"]
    s = out["suggestion"]
    assert s["redteam_records"]["validation"] > 0 and s["redteam_records"]["test"] > 0
    sp = s["splits"]
    assert sp["test_end_day"] - s["start_day"] == 14
    assert s["time_window"]["start_seconds"] == s["start_day"] * DAY_SECONDS
    assert s["time_window"]["end_seconds"] == sp["test_end_day"] * DAY_SECONDS - 1
    assert "validation_end_day" in yaml_snippet(s)


def test_reports_when_no_window_works() -> None:
    out = suggest_splits({3: 10}, **KW)  # one day cannot cover both validation and test
    assert not out["ok"] and "both validation and test" in out["reason"]
    assert suggest_splits({}, **KW)["ok"] is False


def test_respects_last_day_of_data() -> None:
    out = suggest_splits({10: 1, 13: 1, 50: 4, 53: 4}, last_day=30, **KW)
    assert out["suggestion"]["splits"]["test_end_day"] <= 31
