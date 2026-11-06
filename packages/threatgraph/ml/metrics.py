"""Evaluation metrics for incompletely labeled, extremely imbalanced anomaly scores.

Terminology used throughout (and in the UI):

* "known positive"  - a window containing at least one red-team-matched event;
* "unlabeled"       - every other window. It is *treated as negative* when computing
  precision/AP/confusion counts. Because some unlabeled windows may be malicious, the
  reported precision is a lower bound under the assumption that the labels that do exist
  are correct, and "known-label recall" only measures recall of documented events.
"""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score

EVALUATION_ASSUMPTIONS = [
    "Unlabeled windows are treated as negatives for precision, AP and confusion counts; "
    "true precision may be higher if unlabeled windows contain undocumented malicious activity.",
    "Known-label recall measures recall of documented red-team windows only.",
    "Thresholds are calibrated on the validation split; test metrics use that fixed threshold.",
    "Ranking ties are broken by window order (earlier first), which affects precision@K only "
    "when scores tie at the K boundary.",
]


def ranking(scores: np.ndarray) -> np.ndarray:
    """Indices sorted by score descending; stable so ties keep input order."""
    return np.argsort(-scores, kind="stable")


def threshold_counts(labels: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, Any]:
    flagged = scores >= threshold
    y = labels.astype(bool)
    tp = int((flagged & y).sum())
    fp = int((flagged & ~y).sum())
    fn = int((~flagged & y).sum())
    tn = int((~flagged & ~y).sum())
    alerts = tp + fp
    positives = tp + fn
    return {
        "threshold": float(threshold),
        "alerts": alerts,
        "known_positive_alerts": tp,
        "unlabeled_alerts": fp,
        "missed_known_positives": fn,
        "unlabeled_not_alerted": tn,
        "precision_lower_bound": tp / alerts if alerts else None,
        "known_label_recall": tp / positives if positives else None,
        "alert_rate": alerts / len(scores) if len(scores) else None,
    }


def precision_at_k(labels: np.ndarray, scores: np.ndarray, k: int) -> dict[str, Any]:
    k_eff = min(k, len(scores))
    top = ranking(scores)[:k_eff]
    hits = int(labels[top].sum())
    return {
        "k": k,
        "k_effective": k_eff,
        "known_positives": hits,
        "precision": hits / k_eff if k_eff else None,
    }


def average_precision(labels: np.ndarray, scores: np.ndarray) -> float | None:
    if labels.sum() == 0:
        return None  # not estimable without positives
    return float(average_precision_score(labels, scores))


def roc_auc(labels: np.ndarray, scores: np.ndarray) -> float | None:
    if labels.sum() == 0 or labels.sum() == len(labels):
        return None
    return float(roc_auc_score(labels, scores))


def pr_curve(
    labels: np.ndarray, scores: np.ndarray, max_points: int = 200
) -> list[dict[str, float]]:
    if labels.sum() == 0:
        return []
    precision, recall, thresholds = precision_recall_curve(labels, scores)
    # precision/recall have len(thresholds)+1 entries; drop the final (recall=0) sentinel.
    pts = [
        {"recall": float(r), "precision": float(p), "threshold": float(t)}
        for p, r, t in zip(precision[:-1], recall[:-1], thresholds, strict=True)
    ]
    if len(pts) > max_points:
        idx = np.unique(np.linspace(0, len(pts) - 1, max_points).round().astype(int))
        pts = [pts[i] for i in idx]
    return pts


def score_histogram(labels: np.ndarray, scores: np.ndarray, bins: int = 40) -> dict[str, Any]:
    if scores.size == 0:
        return {"bin_edges": [], "known_positive": [], "unlabeled": []}
    lo, hi = float(scores.min()), float(scores.max())
    edges = np.linspace(lo, hi if hi > lo else lo + 1.0, bins + 1)
    y = labels.astype(bool)
    pos, _ = np.histogram(scores[y], bins=edges)
    neg, _ = np.histogram(scores[~y], bins=edges)
    return {"bin_edges": edges.tolist(), "known_positive": pos.tolist(), "unlabeled": neg.tolist()}


def detection_latency(
    principals: np.ndarray,
    labels: np.ndarray,
    flagged: np.ndarray,
    window_end: np.ndarray,
    first_labeled_event: np.ndarray,
) -> list[dict[str, Any]]:
    """Per principal with known-positive windows: time from its first labeled event to the
    end of the first *alerted* known-positive window (alerts are emitted at window end)."""
    out = []
    for p in np.unique(principals[labels.astype(bool)]):
        mask = (principals == p) & labels.astype(bool)
        start = int(first_labeled_event[mask].min())
        hits = window_end[mask & flagged]
        detected = hits.size > 0
        out.append(
            {
                "principal": str(p),
                "first_labeled_event_seconds": start,
                "detected": bool(detected),
                "first_alert_seconds": int(hits.min()) if detected else None,
                "latency_seconds": int(hits.min() - start) if detected else None,
                "known_positive_windows": int(mask.sum()),
                "alerted_known_positive_windows": int((mask & flagged).sum()),
            }
        )
    return out


def evaluate_scores(
    labels: np.ndarray,
    scores: np.ndarray,
    threshold: float,
    *,
    n_days: float,
    ks: tuple[int, ...] = (10, 25, 50, 100),
) -> dict[str, Any]:
    op = threshold_counts(labels, scores, threshold)
    n_pos = int(labels.sum())
    return {
        "n_windows": len(scores),
        "n_positive_windows": n_pos,
        "prevalence": n_pos / len(scores) if len(scores) else None,
        "average_precision": average_precision(labels, scores),
        "average_precision_estimable": n_pos > 0,
        "random_ranking_average_precision": n_pos / len(scores) if len(scores) and n_pos else None,
        "roc_auc": roc_auc(labels, scores),
        "precision_at_k": [precision_at_k(labels, scores, k) for k in ks],
        "operating_point": op,
        "alerts_per_day": op["alerts"] / n_days if n_days else None,
        "alerts_per_1000_windows": 1000 * op["alerts"] / len(scores) if len(scores) else None,
        "pr_curve": pr_curve(labels, scores),
        "score_histogram": score_histogram(labels, scores),
    }
