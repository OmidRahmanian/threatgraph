from __future__ import annotations

import numpy as np
import pytest

from threatgraph.ml.metrics import (
    average_precision,
    detection_latency,
    evaluate_scores,
    pr_curve,
    precision_at_k,
    score_histogram,
    threshold_counts,
)

Y = np.array([1, 0, 0, 1, 0, 0, 0, 0])
S = np.array([0.9, 0.8, 0.1, 0.4, 0.4, 0.3, 0.2, 0.0])


def test_threshold_counts() -> None:
    m = threshold_counts(Y, S, 0.4)
    assert m["alerts"] == 4  # >= is inclusive: 0.9, 0.8, 0.4, 0.4
    assert m["known_positive_alerts"] == 2
    assert m["unlabeled_alerts"] == 2
    assert m["missed_known_positives"] == 0
    assert m["unlabeled_not_alerted"] == 4
    assert m["precision_lower_bound"] == pytest.approx(0.5)
    assert m["known_label_recall"] == pytest.approx(1.0)
    none = threshold_counts(Y, S, 10.0)
    assert none["alerts"] == 0 and none["precision_lower_bound"] is None


def test_precision_at_k_ties_keep_input_order() -> None:
    # Index 3 (positive) and 4 (unlabeled) tie at 0.4; the earlier index ranks first.
    assert precision_at_k(Y, S, 3)["known_positives"] == 2
    assert precision_at_k(Y, S, 100)["k_effective"] == len(Y)


def test_ap_not_estimable_without_positives() -> None:
    assert average_precision(np.zeros(5, dtype=int), np.arange(5.0)) is None
    assert pr_curve(np.zeros(5, dtype=int), np.arange(5.0)) == []
    perfect = average_precision(np.array([0, 0, 1, 1]), np.array([0.1, 0.2, 0.8, 0.9]))
    assert perfect == pytest.approx(1.0)


def test_histogram_partitions_all_scores() -> None:
    h = score_histogram(Y, S, bins=4)
    assert sum(h["known_positive"]) == 2 and sum(h["unlabeled"]) == 6
    assert len(h["bin_edges"]) == 5


def test_detection_latency() -> None:
    principals = np.array(["a", "a", "b", "c"])
    labels = np.array([1, 1, 1, 0])
    flagged = np.array([False, True, False, True])
    window_end = np.array([3600, 7200, 3600, 3600])
    first = np.array([100, 100, 50, -1])
    out = {
        r["principal"]: r for r in detection_latency(principals, labels, flagged, window_end, first)
    }
    assert set(out) == {"a", "b"}  # c has no known positives
    assert out["a"]["detected"] and out["a"]["latency_seconds"] == 7100
    assert not out["b"]["detected"] and out["b"]["latency_seconds"] is None


def test_evaluate_scores_shape() -> None:
    m = evaluate_scores(Y, S, 0.5, n_days=2.0)
    assert m["alerts_per_day"] == pytest.approx(1.0)
    assert m["random_ranking_average_precision"] == pytest.approx(2 / 8)
    assert m["average_precision_estimable"]
