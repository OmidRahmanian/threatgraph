"""Model interface and models: M0 robust z-score, Isolation Forests (M1, M3, M4, M5) and the
gated supervised model M2 (gradient boosting).

All scores are oriented so that *higher = more anomalous*. Scores are rankings, not
calibrated probabilities of compromise.
"""

from __future__ import annotations

import hashlib
import json
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, ClassVar

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest

from threatgraph.config import ModelSpec, ThresholdPolicy
from threatgraph.data.features import FEATURE_DESCRIPTIONS
from threatgraph.versions import library_versions

MAD_TO_SIGMA = 1.4826


def robust_reference(X: np.ndarray, min_scale: float = 0.0) -> tuple[np.ndarray, np.ndarray]:
    """Per-column median and robust scale (MAD → IQR → std → 1 fallback chain)."""
    med = np.median(X, axis=0)
    mad = MAD_TO_SIGMA * np.median(np.abs(X - med), axis=0)
    q75, q25 = np.percentile(X, [75, 25], axis=0)
    iqr = (q75 - q25) / 1.349
    std = X.std(axis=0)
    scale = np.where(mad > 0, mad, np.where(iqr > 0, iqr, np.where(std > 0, std, 1.0)))
    return med, np.maximum(scale, min_scale)


class AnomalyModel(ABC):
    kind: ClassVar[str]
    explanation_method: ClassVar[str]
    explanation_caveat: ClassVar[str]
    supervised: ClassVar[bool] = False

    def __init__(
        self, model_id: str, display_name: str, features: list[str], params: dict[str, Any]
    ):
        unknown = set(features) - set(FEATURE_DESCRIPTIONS)
        if unknown:
            raise ValueError(f"unknown features: {sorted(unknown)}")
        self.model_id = model_id
        self.display_name = display_name
        self.features = list(features)
        self.params = dict(params)
        self.threshold: float | None = None
        self.threshold_policy: dict[str, Any] | None = None
        self.ref_median: np.ndarray | None = None
        self.ref_scale: np.ndarray | None = None
        self.train_info: dict[str, Any] = {}

    # -- training ---------------------------------------------------------------
    def fit(
        self,
        X: np.ndarray,
        *,
        y: np.ndarray | None = None,
        train_info: dict[str, Any] | None = None,
    ) -> AnomalyModel:
        """Fit on the training split. `y` (training labels) is required by supervised models
        and refused by unsupervised ones, so labels cannot leak into an unsupervised model."""
        self._check(X)
        if self.supervised != (y is not None):
            raise ValueError(
                f"{self.kind}: labels {'required' if self.supervised else 'not allowed'}"
            )
        started = time.perf_counter()
        self.ref_median, self.ref_scale = robust_reference(
            X, float(self.params.get("min_scale", 0.0))
        )
        self._fit(X, y)
        self.train_info = {
            **(train_info or {}),
            "n_train_rows": int(X.shape[0]),
            "train_seconds": round(time.perf_counter() - started, 4),
        }
        return self

    def calibrate_threshold(self, validation_scores: np.ndarray, policy: ThresholdPolicy) -> float:
        """Alert-budget threshold from validation scores only (never test)."""
        if validation_scores.size == 0:
            raise ValueError("cannot calibrate on an empty validation split")
        q = 1.0 - policy.alert_rate
        self.threshold = float(np.quantile(validation_scores, q, method="higher"))
        self.threshold_policy = {
            **policy.model_dump(),
            "calibrated_on": "validation",
            "n_validation_rows": int(validation_scores.size),
        }
        return self.threshold

    def predict(self, X: np.ndarray) -> np.ndarray:
        if self.threshold is None:
            raise RuntimeError("threshold not calibrated")
        return self.score(X) >= self.threshold

    def score(self, X: np.ndarray) -> np.ndarray:
        self._check(X)
        return self._score(X)

    # -- explanation --------------------------------------------------------------
    def diagnostics(self, x: np.ndarray) -> list[dict[str, Any]]:
        """Observed feature deviations from the training reference, largest first."""
        assert self.ref_median is not None and self.ref_scale is not None
        z = (x - self.ref_median) / self.ref_scale
        rows = [
            {
                "feature": f,
                "description": FEATURE_DESCRIPTIONS[f],
                "value": float(x[i]),
                "reference_median": float(self.ref_median[i]),
                "reference_scale": float(self.ref_scale[i]),
                "robust_z": float(z[i]),
            }
            for i, f in enumerate(self.features)
        ]
        return sorted(rows, key=lambda r: -abs(r["robust_z"]))

    # -- persistence -------------------------------------------------------------
    def metadata(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "display_name": self.display_name,
            "kind": self.kind,
            "features": self.features,
            "hyperparameters": self.params,
            "threshold": self.threshold,
            "threshold_policy": self.threshold_policy,
            "explanation_method": self.explanation_method,
            "explanation_caveat": self.explanation_caveat,
            "train_info": self.train_info,
            "library_versions": library_versions(),
        }

    def save(self, directory: Path) -> dict[str, Any]:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "model.joblib"
        joblib.dump(self, path)
        meta = {**self.metadata(), "artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        (directory / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n")
        return meta

    @staticmethod
    def load(directory: Path) -> AnomalyModel:
        model = joblib.load(directory / "model.joblib")
        if not isinstance(model, AnomalyModel):
            raise TypeError(f"{directory} does not contain an AnomalyModel")
        return model

    # -- internals ---------------------------------------------------------------
    def _check(self, X: np.ndarray) -> None:
        if X.ndim != 2 or X.shape[1] != len(self.features):
            raise ValueError(f"expected (n, {len(self.features)}) matrix, got {X.shape}")
        if not np.isfinite(X).all():
            raise ValueError("feature matrix contains NaN/inf")

    @abstractmethod
    def _fit(self, X: np.ndarray, y: np.ndarray | None) -> None: ...

    @abstractmethod
    def _score(self, X: np.ndarray) -> np.ndarray: ...


class RobustZModel(AnomalyModel):
    """M0: score = largest upward robust z-score among a few interpretable count features.

    Medians and scales are fitted on the training split. The score is exactly the maximum
    diagnostic z, so its explanation is exact rather than approximate. Limitations: it is
    global (one reference for every principal), only sees upward deviations, and ignores
    feature interactions.
    """

    kind = "robust_z"
    explanation_method = "exact: the score equals the largest per-feature robust z-score"
    explanation_caveat = (
        "Reference medians/scales come from the training split and are shared by all principals."
    )

    def _fit(self, X: np.ndarray, y: np.ndarray | None) -> None:
        pass  # the robust reference computed in fit() is the whole model

    def _score(self, X: np.ndarray) -> np.ndarray:
        assert self.ref_median is not None and self.ref_scale is not None
        z = (X - self.ref_median) / self.ref_scale
        return np.maximum(z.max(axis=1), 0.0)


def signed_log1p(X: np.ndarray) -> np.ndarray:
    return np.sign(X) * np.log1p(np.abs(X))


class IsolationForestModel(AnomalyModel):
    """M1: Isolation Forest on signed-log-transformed features, trained without labels."""

    kind = "isolation_forest"
    explanation_method = (
        "proxy: per-feature robust z-scores of the window versus the training split"
    )
    explanation_caveat = (
        "Isolation Forest does not provide per-feature attributions. The listed deviations are "
        "approximate diagnostics that describe how the window differs from typical training "
        "windows; they are not the model's internal reasons."
    )

    def _fit(self, X: np.ndarray, y: np.ndarray | None) -> None:
        p = self.params
        self.forest = IsolationForest(
            n_estimators=int(p.get("n_estimators", 300)),
            max_samples=p.get("max_samples", 256),
            max_features=float(p.get("max_features", 1.0)),
            random_state=int(p.get("random_state", 42)),
            n_jobs=1,
        ).fit(signed_log1p(X))

    def _score(self, X: np.ndarray) -> np.ndarray:
        return -self.forest.score_samples(signed_log1p(X))


class SupervisedGBMModel(AnomalyModel):
    """M2: gradient-boosted trees trained on the training split's red-team labels.

    Unlabeled windows are treated as negatives *for fitting only* (the standard
    positive-unlabeled shortcut, which biases the model against undocumented attacker
    activity). Evaluation still treats unlabeled windows as unknown, exactly as for the
    unsupervised models. Classes are re-weighted because positives are rare. Hyperparameters
    are fixed in configs/models.yaml, never tuned on validation or test. The score is a
    ranking; it is not a calibrated probability of compromise. Trained only when the
    supervised gate finds enough training labels.
    """

    kind = "supervised_gbm"
    supervised = True
    explanation_method = (
        "proxy: per-feature robust z-scores of the window versus the training split"
    )
    explanation_caveat = (
        "Gradient boosting learns from the red-team labels of the training split; the listed "
        "deviations describe how the window differs from typical training windows, not the "
        "trees' internal reasons. Undocumented attacker activity was treated as negative."
    )

    def _fit(self, X: np.ndarray, y: np.ndarray | None) -> None:
        assert y is not None
        p = self.params
        self.clf = HistGradientBoostingClassifier(
            max_iter=int(p.get("max_iter", 200)),
            learning_rate=float(p.get("learning_rate", 0.05)),
            max_leaf_nodes=int(p.get("max_leaf_nodes", 15)),
            min_samples_leaf=int(p.get("min_samples_leaf", 20)),
            l2_regularization=float(p.get("l2_regularization", 1.0)),
            class_weight="balanced",
            early_stopping=False,
            random_state=int(p.get("random_state", 42)),
        ).fit(signed_log1p(X), y.astype(int))

    def _score(self, X: np.ndarray) -> np.ndarray:
        return self.clf.predict_proba(signed_log1p(X))[:, 1]


MODEL_KINDS: dict[str, type[AnomalyModel]] = {
    RobustZModel.kind: RobustZModel,
    IsolationForestModel.kind: IsolationForestModel,
    SupervisedGBMModel.kind: SupervisedGBMModel,
}


def build_model(model_id: str, spec: ModelSpec, features: list[str]) -> AnomalyModel:
    return MODEL_KINDS[spec.kind](model_id, spec.display_name, features, spec.params)
