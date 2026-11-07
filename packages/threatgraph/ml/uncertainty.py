"""Cluster-bootstrap confidence intervals for held-out metrics.

Windows of one account are correlated, and red-team labels arrive in per-account runs, so
resampling individual windows would understate uncertainty. We resample *accounts* with
replacement (all of an account's windows move together) and recompute each metric. Model
differences are paired: every model is scored on the same resample.

A resample with no known positives cannot estimate AP or recall. Those resamples are dropped
for that metric, and the share kept is reported so a reader can see how fragile the interval
is. With a handful of positive accounts, intervals are wide; that is the honest result.
"""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.metrics import average_precision_score


def _interval(values: list[float], n_boot: int, level: float) -> dict[str, Any]:
    v = np.asarray([x for x in values if np.isfinite(x)])
    if v.size == 0:
        return {"low": None, "high": None, "estimable_share": 0.0}
    a = (1 - level) / 2
    return {
        "low": float(np.quantile(v, a)),
        "high": float(np.quantile(v, 1 - a)),
        "estimable_share": round(v.size / n_boot, 4),
    }


def account_bootstrap(
    accounts: np.ndarray,
    labels: np.ndarray,
    scores: dict[str, np.ndarray],
    thresholds: dict[str, float],
    pairs: list[tuple[str, str]],
    *,
    n_boot: int,
    seed: int,
    level: float = 0.95,
) -> dict[str, Any]:
    """CIs per model for AP, known-label recall and precision (lower bound), plus paired
    AP differences (candidate − baseline) for each pair."""
    rng = np.random.default_rng(seed)
    _, inverse = np.unique(accounts, return_inverse=True)
    groups = [np.flatnonzero(inverse == g) for g in range(inverse.max() + 1)]
    n_groups = len(groups)
    draws: dict[str, dict[str, list[float]]] = {
        m: {"ap": [], "recall": [], "precision": []} for m in scores
    }
    deltas: dict[tuple[str, str], list[float]] = {p: [] for p in pairs}
    for _ in range(n_boot):
        idx = np.concatenate([groups[g] for g in rng.integers(0, n_groups, n_groups)])
        y = labels[idx].astype(bool)
        n_pos = int(y.sum())
        ap: dict[str, float] = {}
        for m, s_all in scores.items():
            s = s_all[idx]
            flagged = s >= thresholds[m]
            tp = int((flagged & y).sum())
            ap[m] = float(average_precision_score(y, s)) if 0 < n_pos < y.size else np.nan
            draws[m]["ap"].append(ap[m])
            draws[m]["recall"].append(tp / n_pos if n_pos else np.nan)
            draws[m]["precision"].append(tp / flagged.sum() if flagged.any() else np.nan)
        for base, cand in pairs:
            deltas[(base, cand)].append(ap[cand] - ap[base])
    out: dict[str, Any] = {
        "method": "account cluster bootstrap (percentile)",
        "n_boot": n_boot,
        "seed": seed,
        "level": level,
        "n_accounts": n_groups,
        "n_positive_accounts": len({accounts[i] for i in np.flatnonzero(labels)}),
        "models": {
            m: {
                "average_precision": _interval(d["ap"], n_boot, level),
                "known_label_recall": _interval(d["recall"], n_boot, level),
                "precision_lower_bound": _interval(d["precision"], n_boot, level),
            }
            for m, d in draws.items()
        },
        "pairs": [],
    }
    for (base, cand), vals in deltas.items():
        v = np.asarray([x for x in vals if np.isfinite(x)])
        out["pairs"].append(
            {
                "baseline": base,
                "candidate": cand,
                "average_precision_delta": _interval(vals, n_boot, level),
                "share_candidate_better": float((v > 0).mean()) if v.size else None,
            }
        )
    return out
