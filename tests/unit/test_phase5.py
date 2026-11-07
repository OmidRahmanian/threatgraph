"""Uncertainty, drift and explanation-faithfulness helpers."""

from __future__ import annotations

import numpy as np
import polars as pl
import pytest

from threatgraph.config import ThresholdPolicy
from threatgraph.ml.drift import _edges, drift_report, psi
from threatgraph.ml.faithfulness import deletion_test
from threatgraph.ml.models import RobustZModel
from threatgraph.ml.uncertainty import account_bootstrap

RNG = np.random.default_rng(0)


def _toy(n_accounts: int = 40, per: int = 25):
    accounts = np.repeat(np.arange(n_accounts), per)
    labels = np.zeros(accounts.size, dtype=int)
    labels[(accounts < 6) & (np.arange(accounts.size) % per == 0)] = 1  # 6 positive accounts
    perfect = labels + RNG.random(accounts.size) * 0.5
    noise = RNG.random(accounts.size)
    return accounts, labels, {"noise": noise, "perfect": perfect}


def test_bootstrap_is_seeded_and_resamples_accounts() -> None:
    accounts, labels, scores = _toy()
    args = (accounts, labels, scores, {"noise": 0.99, "perfect": 1.0}, [("noise", "perfect")])
    a = account_bootstrap(*args, n_boot=200, seed=1)
    b = account_bootstrap(*args, n_boot=200, seed=1)
    assert a == b
    assert a["n_accounts"] == 40 and a["n_positive_accounts"] == 6
    ap = a["models"]["perfect"]["average_precision"]
    assert ap["low"] == pytest.approx(1.0) and ap["high"] == pytest.approx(1.0)
    noise = a["models"]["noise"]["average_precision"]
    assert noise["low"] < noise["high"] < 1.0
    # Resamples without any positive account cannot estimate AP; they are counted, not zeroed.
    assert 0.9 < ap["estimable_share"] <= 1.0
    pair = a["pairs"][0]
    assert pair["share_candidate_better"] == pytest.approx(1.0)
    assert pair["average_precision_delta"]["low"] > 0


def test_psi_and_drift_report() -> None:
    ref = RNG.normal(size=5000)
    edges = _edges(ref, 10)
    assert psi(ref, RNG.normal(size=5000), edges) < 0.02
    assert psi(ref, RNG.normal(loc=1.5, size=5000), edges) > 0.25
    df = pl.DataFrame(
        {
            "split": ["train"] * 300 + ["test"] * 300,
            "day": [0] * 300 + [5] * 300,
            "label": [0] * 600,
            "x": np.concatenate([RNG.normal(size=300), RNG.normal(loc=2, size=300)]),
            "constant": [1.0] * 600,
            "score__m": RNG.random(600),
        }
    )
    rep = drift_report(df, ["x", "constant"], {"m": 0.99}, 0.01)
    assert rep["constant_in_reference"] == ["constant"] and rep["features"] == ["x"]
    days = {d["day"]: d for d in rep["days"]}
    assert days[0]["feature_psi"]["x"] < 0.1 < 0.25 < days[5]["feature_psi"]["x"]
    assert days[5]["alert_rate"]["m"] == pytest.approx((df["score__m"][300:] >= 0.99).mean())


def test_deletion_test_ranks_exact_explanations_above_random() -> None:
    feats = ["n_events", "n_fail", "n_novel_dst", "n_remote"]
    X = RNG.poisson([5, 0.2, 0.1, 2], size=(500, 4)).astype(float)
    m = RobustZModel("m0", "M0", feats, {"min_scale": 1.0}).fit(X)
    m.calibrate_threshold(m.score(X), ThresholdPolicy(alert_rate=0.05))
    alerts = X[m.score(X) >= m.threshold]
    out = deletion_test(m, alerts, ks=(1,), n_random=10, seed=0)
    r = out["results"][0]
    assert out["n_alerts"] == len(alerts)
    # M0's score is the max z, so removing the top feature always helps at least as much.
    assert r["mean_score_drop_top"] >= r["mean_score_drop_random"]
    assert r["below_threshold_share_top"] >= r["below_threshold_share_random"]
