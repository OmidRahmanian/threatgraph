"""Drift monitor: how far each day's windows move from the training period.

Population stability index (PSI) per feature and per model score, with bins at the training
split's quantiles, computed for every scored day. Conventional reading: < 0.1 stable,
0.1–0.25 moderate shift, > 0.25 major shift. The per-day alert rate is compared with the
alert budget the threshold was calibrated for. Drift says the inputs changed; it does not say
whether the change is malicious, benign or a data problem.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import polars as pl

STABLE, MAJOR = 0.1, 0.25
EPS = 1e-4


def _edges(ref: np.ndarray, bins: int) -> np.ndarray:
    """Interior bin edges from training quantiles (duplicates removed for discrete features)."""
    return np.unique(np.quantile(ref, np.linspace(0, 1, bins + 1)[1:-1]))


def psi(ref: np.ndarray, cur: np.ndarray, edges: np.ndarray) -> float | None:
    if cur.size == 0 or ref.size == 0:
        return None
    k = edges.size + 1
    p = np.bincount(np.searchsorted(edges, ref, side="right"), minlength=k) / ref.size
    q = np.bincount(np.searchsorted(edges, cur, side="right"), minlength=k) / cur.size
    p, q = np.clip(p, EPS, None), np.clip(q, EPS, None)
    return float(np.sum((q - p) * np.log(q / p)))


def drift_report(
    windows: pl.DataFrame,
    features: list[str],
    models: dict[str, float],
    alert_rate: float,
    *,
    bins: int = 10,
    expected: dict[str, str] | None = None,
) -> dict[str, Any]:
    """`windows` holds the scored windows (train/validation/test) with feature columns,
    `score__<model>` columns, `split`, `day` and `label`. `models` maps id -> threshold."""
    ref = windows.filter(pl.col("split") == "train")
    cols = features + [f"score__{m}" for m in models]
    edges = {c: _edges(ref[c].cast(pl.Float64).to_numpy(), bins) for c in cols}
    constant = [f for f in features if ref[f].n_unique() <= 1]
    days = []
    for (day, split), part in windows.group_by("day", "split", maintain_order=True):
        row: dict[str, Any] = {
            "day": int(day),
            "split": str(split),
            "n_windows": part.height,
            "n_known_positive_windows": int(part["label"].sum()),
            "feature_psi": {},
            "score_psi": {},
            "alert_rate": {},
        }
        for f in features:
            if f in constant:
                continue
            row["feature_psi"][f] = psi(
                ref[f].cast(pl.Float64).to_numpy(), part[f].cast(pl.Float64).to_numpy(), edges[f]
            )
        for m, thr in models.items():
            c = f"score__{m}"
            row["score_psi"][m] = psi(ref[c].to_numpy(), part[c].to_numpy(), edges[c])
            row["alert_rate"][m] = float((part[c] >= thr).mean())  # type: ignore[arg-type]
        days.append(row)
    days.sort(key=lambda r: r["day"])
    return {
        "reference": "train split",
        "bins": bins,
        "thresholds": {"stable": STABLE, "major": MAJOR},
        "alert_budget": alert_rate,
        "features": [f for f in features if f not in constant],
        "constant_in_reference": constant,
        # Features that drift by construction, so their PSI is not a warning sign.
        "expected_drift": expected or {},
        "models": list(models),
        "days": days,
        "semantics": (
            "PSI compares each day's windows with the training split (bins at training "
            "quantiles). Drift means the inputs changed, not that anything malicious happened. "
            "Training days are included to show the noise level of the measure itself."
        ),
    }
