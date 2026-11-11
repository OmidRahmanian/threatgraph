"""Live behavioural model on simulated history: chronological training, budget threshold,
causal features, honest false-alert reporting, and scoring of a simulated scan."""

from __future__ import annotations

import re
from pathlib import Path

from threatgraph.live import scenarios
from threatgraph.live.behavior import (
    NAMES,
    build_windows,
    load_model,
    load_report,
    score_recent,
    train,
)
from threatgraph.live.config import load_live_config
from threatgraph.live.store import LiveStore

NOW = 1_794_000_000.0


def _cfg():
    cfg = load_live_config()
    cfg.ml.train_days = 0.25
    cfg.ml.validation_days = 0.05
    cfg.ml.min_train_windows = 100
    cfg.ml.alert_rate = 0.01
    return cfg


def test_features_are_causal_and_named() -> None:
    ev = [e.to_dict() | {"rowid": i} for i, e in enumerate(scenarios.ssh_bruteforce(NOW, n=12))]
    sens = [re.compile(r"^/\.env")]
    (w,) = build_windows(ev[:6], 3600, sens, seen := {})
    assert len(w.x) == len(NAMES)
    assert w.x[NAMES.index("new_source")] == 1.0 and w.x[NAMES.index("ssh_failures")] == 6
    # A later batch for the same source is no longer "new" and uses the earlier count.
    later = [e | {"ts": e["ts"] + 7200} for e in ev[6:]]
    (w2,) = build_windows(later, 3600, sens, seen)
    assert w2.x[NAMES.index("new_source")] == 0.0
    assert w2.x[NAMES.index("ssh_fail_ratio")] == 1.0


def test_insufficient_history_is_reported_not_trained(tmp_path: Path) -> None:
    store = LiveStore(tmp_path / "live.db")
    rep = train(store, _cfg(), str(tmp_path / "live.db"), now=NOW, simulated=True)
    assert rep["status"] == "insufficient_history"
    assert load_model(str(tmp_path / "live.db")) is None


def test_train_calibrate_and_score_a_simulated_scan(tmp_path: Path) -> None:
    db = str(tmp_path / "live.db")
    store = LiveStore(db)
    cfg = _cfg()
    store.insert_events(scenarios.benign_traffic(NOW, minutes=480), received_at=NOW)
    rep = train(store, cfg, db, now=NOW, simulated=True)
    assert rep["status"] == "trained" and rep["simulated_data"] is True
    assert rep["train_period"][1] == rep["validation_period"][0]  # chronological, no overlap
    assert rep["verified_false_alert_rate"] is None and "unknown" in rep["false_alert_note"]
    assert (
        0 < rep["validation_alerts"] <= max(3, 3 * cfg.ml.alert_rate * rep["n_validation_windows"])
    )
    model = load_model(db)
    assert model is not None and load_report(db)["model_version"] == rep["model_version"]
    # Same seed, same data: identical model version and threshold (reproducible).
    rep2 = train(store, cfg, db, now=NOW, simulated=True)
    assert (rep2["model_version"], rep2["threshold"]) == (rep["model_version"], rep["threshold"])

    later = NOW + 600
    store.insert_events(scenarios.http_recon(later - 300 + 200), received_at=later)
    findings = score_recent(store, cfg, model, later, simulated=True)
    scan = [f for f in findings if f.entity == scenarios.SCANNER]
    assert scan, "the simulated scanner should be the most unusual source"
    f = scan[0]
    assert f.detector == "model" and f.severity == "info" and f.assessment == "unusual"
    assert any("http_404_paths" in e or "http_sensitive" in e for e in f.evidence)
    # Real (non-simulated) scoring sees none of the simulated events.
    assert score_recent(store, cfg, model, later, simulated=False) == []
