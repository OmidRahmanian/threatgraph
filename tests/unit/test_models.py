from __future__ import annotations

import numpy as np
import pytest

from threatgraph.config import ThresholdPolicy
from threatgraph.ml.models import AnomalyModel, IsolationForestModel, RobustZModel, robust_reference

FEATS = ["n_events", "n_fail", "n_novel_dst"]
RNG = np.random.default_rng(0)
X_TRAIN = RNG.poisson([5, 0.2, 0.1], size=(500, 3)).astype(float)


def test_robust_reference_fallbacks() -> None:
    X = np.array([[0.0, 1.0], [0.0, 2.0], [0.0, 3.0], [0.0, 4.0]])
    med, scale = robust_reference(X)
    assert med.tolist() == [0.0, 2.5]
    assert scale[0] == 1.0  # constant column falls back to 1
    assert robust_reference(X, min_scale=5.0)[1].min() == 5.0


def test_robust_z_score_equals_max_diagnostic() -> None:
    m = RobustZModel("m0", "M0", FEATS, {"min_scale": 1.0}).fit(X_TRAIN)
    x = np.array([5.0, 9.0, 0.0])
    score = m.score(x[None, :])[0]
    top = m.diagnostics(x)[0]
    assert top["feature"] == "n_fail"
    assert score == pytest.approx(max(0.0, top["robust_z"]))
    assert m.score(np.array([[0.0, 0.0, 0.0]]))[0] == 0.0  # only upward deviations count


def test_isolation_forest_deterministic_and_oriented() -> None:
    a = IsolationForestModel("m1", "M1", FEATS, {"random_state": 3}).fit(X_TRAIN)
    b = IsolationForestModel("m1", "M1", FEATS, {"random_state": 3}).fit(X_TRAIN)
    probe = np.array([[5.0, 0.0, 0.0], [80.0, 30.0, 25.0]])
    assert np.array_equal(a.score(probe), b.score(probe))
    s = a.score(probe)
    assert s[1] > s[0]  # higher = more anomalous


def test_threshold_calibration_uses_validation_quantile() -> None:
    m = RobustZModel("m0", "M0", FEATS, {}).fit(X_TRAIN)
    val = np.arange(1000, dtype=float)
    t = m.calibrate_threshold(val, ThresholdPolicy(alert_rate=0.01))
    assert t == 990.0
    assert m.threshold_policy is not None and m.threshold_policy["calibrated_on"] == "validation"
    assert (val >= t).sum() == 10


def test_predict_requires_threshold_and_rejects_bad_input() -> None:
    m = RobustZModel("m0", "M0", FEATS, {}).fit(X_TRAIN)
    with pytest.raises(RuntimeError):
        m.predict(X_TRAIN)
    with pytest.raises(ValueError):
        m.score(np.array([[np.nan, 0.0, 0.0]]))
    with pytest.raises(ValueError):
        m.score(np.zeros((2, 2)))
    with pytest.raises(ValueError):
        RobustZModel("m0", "M0", ["not_a_feature"], {})


def test_save_load_roundtrip(tmp_path) -> None:
    m = IsolationForestModel("m1", "M1", FEATS, {"random_state": 1}).fit(X_TRAIN)
    m.calibrate_threshold(m.score(X_TRAIN), ThresholdPolicy())
    meta = m.save(tmp_path / "m1")
    loaded = AnomalyModel.load(tmp_path / "m1")
    assert np.array_equal(loaded.score(X_TRAIN[:20]), m.score(X_TRAIN[:20]))
    assert len(meta["artifact_sha256"]) == 64
    assert meta["train_info"]["n_train_rows"] == 500
    assert "approximate" in meta["explanation_caveat"]
