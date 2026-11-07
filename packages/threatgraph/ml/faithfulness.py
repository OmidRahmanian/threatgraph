"""Deletion test for explanation faithfulness.

For each alerted test window, take the k features the explanation ranks highest (largest
|robust z|), reset them to their training medians, and re-score. If the explanation points at
what drives the score, this should lower the score more than resetting k randomly chosen
features does (averaged over random draws), and more often push the window below the
threshold. M0's explanation is exact by construction, so it serves as a reference; for
Isolation Forest the explanation is a proxy, and this measures how good a proxy it is.

With no alerts there is nothing to explain: the result says so (`estimable: false`) instead
of averaging an empty set.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from threatgraph.ml.models import AnomalyModel


def deletion_test(
    model: AnomalyModel,
    X: np.ndarray,
    *,
    ks: tuple[int, ...] = (1, 3),
    n_random: int = 20,
    seed: int = 42,
) -> dict[str, Any]:
    assert model.threshold is not None and model.ref_median is not None
    meta = {
        "method": "deletion test: reset the explanation's top-k features to training medians",
        "split": "test",
        "n_alerts": int(X.shape[0]),
        "n_random_draws": n_random,
        "seed": seed,
    }
    if X.shape[0] == 0:
        return {
            **meta,
            "estimable": False,
            "note": "No test window reached the threshold, so there are no explanations to test.",
            "results": [],
        }
    rng = np.random.default_rng(seed)
    base = model.score(X)
    n_feat = X.shape[1]
    index = {f: i for i, f in enumerate(model.features)}
    results = []
    for k in ks:
        if k > n_feat:
            continue
        top_drop, rand_drop, top_flip, rand_flip = [], [], [], []
        for i, x in enumerate(X):
            ranked = [index[d["feature"]] for d in model.diagnostics(x)][:k]
            xt = x.copy()
            xt[ranked] = model.ref_median[ranked]
            st = float(model.score(xt[None, :])[0])
            xr = np.repeat(x[None, :], n_random, axis=0)
            for r in range(n_random):
                cols = rng.choice(n_feat, size=k, replace=False)
                xr[r, cols] = model.ref_median[cols]
            sr = model.score(xr)
            top_drop.append(base[i] - st)
            rand_drop.append(float(np.mean(base[i] - sr)))
            top_flip.append(st < model.threshold)
            rand_flip.append(float(np.mean(sr < model.threshold)))
        results.append(
            {
                "k": k,
                "mean_score_drop_top": float(np.mean(top_drop)),
                "mean_score_drop_random": float(np.mean(rand_drop)),
                "below_threshold_share_top": float(np.mean(top_flip)),
                "below_threshold_share_random": float(np.mean(rand_flip)),
                "top_beats_random_share": float(np.mean(np.array(top_drop) > np.array(rand_drop))),
            }
        )
    return {**meta, "estimable": True, "note": None, "results": results}
