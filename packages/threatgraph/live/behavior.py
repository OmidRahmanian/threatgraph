"""Behavioural anomaly model for live telemetry (Live Monitoring Mode).

A dedicated feature pipeline, separate from the LANL authentication features: HTTP and SSH
events are never fed to the research models. The scoring unit is one remote source (client
address as stored, possibly truncated or hashed by the agent's privacy policy) on one host
in one time bucket (default 5 minutes). Features are causal: novelty and rate change use only
earlier buckets.

Training is chronological: fit an Isolation Forest on the oldest `train_days`, calibrate the
alert threshold on the following `validation_days` as an alert budget (`alert_rate`), and
never look at labels while fitting. Verified labels come only from analysts' incident
verdicts; they are used to *measure* the false-alert rate on the validation period, not to
tune the model. With no verdicts the report says so instead of inventing a rate.

Model findings are reported as `unusual` with severity `info` by default: an anomaly score is
not evidence of an attack, and severity follows documented rule criteria, not raw scores.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from threatgraph.live.config import LiveConfig
from threatgraph.live.detect import Finding
from threatgraph.live.store import LiveStore
from threatgraph.ml.models import robust_reference, signed_log1p
from threatgraph.versions import library_versions

FEATURE_SET = "live_source_window_v1"
FEATURES: dict[str, str] = {
    "http_requests": "HTTP requests from the source in the bucket",
    "http_distinct_paths": "Distinct request paths",
    "http_4xx_ratio": "Share of responses with status 4xx",
    "http_5xx_ratio": "Share of responses with status 5xx",
    "http_404_paths": "Distinct paths that returned 404",
    "http_sensitive": "Requests for sensitive-looking paths (configured patterns)",
    "http_malformed": "Requests that were not well-formed HTTP",
    "http_non_get": "Requests with a method other than GET/HEAD",
    "ssh_failures": "Failed SSH authentications",
    "ssh_successes": "Successful SSH authentications",
    "ssh_distinct_users": "Distinct user names in SSH attempts",
    "ssh_fail_ratio": "Failed share of SSH authentications",
    "new_source": "1 if the source had no activity on this host in earlier buckets",
    "log_rate_change": "log((events + 1) / (events in the source's previous active bucket + 1))",
}
NAMES = list(FEATURES)


@dataclass
class Window:
    source_id: str
    client: str
    bucket: int
    x: list[float]
    rowids: list[int]


def build_windows(
    events: list[dict[str, Any]],
    bucket_seconds: int,
    sensitive: list[re.Pattern[str]],
    seen: dict[tuple[str, str], int] | None = None,
) -> list[Window]:
    """Aggregate http.access and ssh.auth events into per-(host, client, bucket) features.

    `seen` maps (host, client) to the event count of that pair's last active bucket before
    this batch; it is updated in place so consecutive batches stay causal.
    """
    seen = {} if seen is None else seen
    agg: dict[tuple[str, str, int], dict[str, Any]] = {}
    for e in events:
        a = e["attrs"]
        client = a.get("client") if e["kind"] == "http.access" else a.get("src_ip")
        if not client:
            continue
        key = (e["source_id"], str(client), int(e["ts"] // bucket_seconds))
        g = agg.setdefault(
            key,
            {
                "req": 0,
                "paths": set(),
                "4xx": 0,
                "5xx": 0,
                "nf": set(),
                "sens": 0,
                "bad": 0,
                "nonget": 0,
                "fail": 0,
                "ok": 0,
                "users": set(),
                "rows": [],
            },
        )
        g["rows"].append(e["rowid"])
        if e["kind"] == "http.access":
            g["req"] += 1
            path = a.get("path")
            status = int(a.get("status") or 0)
            g["paths"].add(path)
            g["4xx"] += 400 <= status < 500
            g["5xx"] += status >= 500
            if status == 404:
                g["nf"].add(path)
            g["sens"] += bool(path) and any(rx.search(path) for rx in sensitive)
            g["bad"] += not a.get("well_formed", True)
            g["nonget"] += a.get("method") not in (None, "GET", "HEAD")
        else:
            g["fail"] += a.get("outcome") == "failure"
            g["ok"] += a.get("outcome") == "success"
            g["users"].add(a.get("user"))
    out = []
    for src, client, bucket in sorted(agg, key=lambda k: (k[2], k[0], k[1])):
        g = agg[(src, client, bucket)]
        n = len(g["rows"])
        req, ssh = g["req"], g["fail"] + g["ok"]
        prev = seen.get((src, client))
        x = [
            req,
            len(g["paths"]),
            g["4xx"] / req if req else 0.0,
            g["5xx"] / req if req else 0.0,
            len(g["nf"]),
            g["sens"],
            g["bad"],
            g["nonget"],
            g["fail"],
            g["ok"],
            len(g["users"]),
            g["fail"] / ssh if ssh else 0.0,
            1.0 if prev is None else 0.0,
            math.log((n + 1) / ((prev or 0) + 1)),
        ]
        seen[(src, client)] = n
        out.append(Window(src, client, bucket, [float(v) for v in x], g["rows"]))
    return out


class LiveBehaviorModel:
    def __init__(self, params: dict[str, Any] | None = None, seed: int = 42) -> None:
        self.params = {"n_estimators": 200, "max_samples": 256, **(params or {})}
        self.seed = seed
        self.threshold: float | None = None
        self.metadata: dict[str, Any] = {}

    def fit(self, X: np.ndarray) -> LiveBehaviorModel:
        self.ref_median, self.ref_scale = robust_reference(X, 1.0)
        self.forest = IsolationForest(
            n_estimators=int(self.params["n_estimators"]),
            max_samples=min(int(self.params["max_samples"]), len(X)),
            random_state=self.seed,
            n_jobs=1,
        ).fit(signed_log1p(X))
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        return -self.forest.score_samples(signed_log1p(X))

    def calibrate(self, val_scores: np.ndarray, alert_rate: float) -> float:
        self.threshold = float(np.quantile(val_scores, 1 - alert_rate, method="higher"))
        return self.threshold

    def explain(self, x: np.ndarray, top: int = 3) -> list[dict[str, Any]]:
        z = (x - self.ref_median) / self.ref_scale
        idx = np.argsort(-np.abs(z))[:top]
        return [
            {
                "feature": NAMES[i],
                "description": FEATURES[NAMES[i]],
                "value": float(x[i]),
                "typical": float(self.ref_median[i]),
                "robust_z": round(float(z[i]), 1),
            }
            for i in idx
            if abs(z[i]) >= 2
        ]


def model_dir(db_path: str) -> Path:
    return Path(db_path).parent / "models" / "live_behavior"


def _labels(store: LiveStore) -> dict[tuple[str, str], list[tuple[float, float, bool]]]:
    """Verified labels from analyst verdicts: (host, client) → [(start, end, malicious)]."""
    out: dict[tuple[str, str], list[tuple[float, float, bool]]] = defaultdict(list)
    for inc in store.query(
        "SELECT source_id, entity, first_seen, last_seen, verdict FROM incidents "
        "WHERE verdict IS NOT NULL AND simulated = 0"
    ):
        malicious = inc["verdict"] == "confirmed_malicious"
        client = str(inc["entity"]).split(":")[0]
        out[(inc["source_id"] or "-", client)].append(
            (inc["first_seen"], inc["last_seen"], malicious)
        )
    return out


def train(
    store: LiveStore,
    cfg: LiveConfig,
    db_path: str,
    *,
    now: float | None = None,
    simulated: bool = False,
) -> dict[str, Any]:
    """Fit on train days, calibrate on validation days, write the model and a report."""
    now = time.time() if now is None else now
    m = cfg.ml
    b = m.bucket_seconds
    end = (int(now) // b) * b
    val_start = end - m.validation_days * 86_400
    train_start = val_start - m.train_days * 86_400
    sensitive = [re.compile(p) for p in cfg.detection.sensitive_paths]
    events = store.events(
        kinds=["http.access", "ssh.auth"],
        since=train_start,
        until=end,
        simulated=simulated,
        limit=5_000_000,
    )
    windows = build_windows(events, b, sensitive)
    tr = [w for w in windows if w.bucket * b < val_start]
    va = [w for w in windows if w.bucket * b >= val_start]
    report: dict[str, Any] = {
        "feature_set": FEATURE_SET,
        "trained_at": now,
        "train_period": [train_start, val_start],
        "validation_period": [val_start, end],
        "n_train_windows": len(tr),
        "n_validation_windows": len(va),
        "simulated_data": simulated,
    }
    if len(tr) < m.min_train_windows or not va:
        report["status"] = "insufficient_history"
        report["detail"] = (
            f"{len(tr)} training windows (need {m.min_train_windows}) and {len(va)} validation "
            "windows; the model is not used until enough history has been collected."
        )
        _write_report(db_path, report)
        return report
    Xtr = np.array([w.x for w in tr])
    Xva = np.array([w.x for w in va])
    model = LiveBehaviorModel(seed=m.seed).fit(Xtr)
    started = time.perf_counter()
    sva = model.score(Xva)
    latency_ms = 1000 * (time.perf_counter() - started) / max(len(va), 1)
    model.calibrate(sva, m.alert_rate)
    alerts = sva >= model.threshold
    # Measure (never tune) against analyst verdicts where they exist.
    labels = _labels(store)
    tp = fp = 0
    for w, flagged in zip(va, alerts, strict=True):
        if not flagged:
            continue
        t0 = w.bucket * b
        for s, e, malicious in labels.get((w.source_id, w.client), []):
            if s <= t0 + b and e >= t0:
                tp += malicious
                fp += not malicious
                break
    days = max(m.validation_days, 1e-9)
    version = hashlib.sha256(
        json.dumps([FEATURE_SET, m.model_dump(), report["train_period"], len(tr)]).encode()
    ).hexdigest()[:12]
    report.update(
        status="trained",
        model_version=version,
        threshold=model.threshold,
        threshold_policy={"type": "validation_alert_rate", "alert_rate": m.alert_rate},
        validation_alerts=int(alerts.sum()),
        validation_alerts_per_day=round(float(alerts.sum()) / days, 2),
        verified_alerts={"confirmed_malicious": tp, "false_or_benign": fp},
        verified_false_alert_rate=(round(fp / (tp + fp), 3) if tp + fp else None),
        false_alert_note=(
            "Measured on validation alerts that overlap analyst-verified incidents."
            if tp + fp
            else "No validation alert overlaps an analyst verdict yet, so the false-alert rate "
            "is unknown (not zero). Resolve incidents with a verdict to build verified labels."
        ),
        score_ms_per_window=round(latency_ms, 4),
        features=FEATURES,
        seed=m.seed,
        library_versions=library_versions(),
    )
    model.metadata = report
    d = model_dir(db_path)
    d.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, d / "model.joblib")
    _write_report(db_path, report)
    return report


def _write_report(db_path: str, report: dict[str, Any]) -> None:
    d = model_dir(db_path)
    d.mkdir(parents=True, exist_ok=True)
    (d / "report.json").write_text(json.dumps(report, indent=2, default=str) + "\n")


def load_model(db_path: str) -> LiveBehaviorModel | None:
    p = model_dir(db_path) / "model.joblib"
    if not p.exists():
        return None
    model = joblib.load(p)
    return model if isinstance(model, LiveBehaviorModel) else None


def load_report(db_path: str) -> dict[str, Any] | None:
    p = model_dir(db_path) / "report.json"
    return json.loads(p.read_text()) if p.exists() else None


def score_recent(
    store: LiveStore,
    cfg: LiveConfig,
    model: LiveBehaviorModel,
    now: float,
    *,
    simulated: bool = False,
    history_hours: float = 24,
) -> list[Finding]:
    """Score the last complete bucket. Earlier buckets only provide causal novelty state."""
    b = cfg.ml.bucket_seconds
    cur = (int(now) // b - 1) * b
    sensitive = [re.compile(p) for p in cfg.detection.sensitive_paths]
    seen: dict[tuple[str, str], int] = {}
    hist = store.events(
        kinds=["http.access", "ssh.auth"],
        since=cur - history_hours * 3600,
        until=cur,
        simulated=simulated,
        limit=2_000_000,
    )
    build_windows(hist, b, sensitive, seen)
    recent = store.events(
        kinds=["http.access", "ssh.auth"],
        since=cur,
        until=cur + b,
        simulated=simulated,
        limit=500_000,
    )
    windows = [w for w in build_windows(recent, b, sensitive, seen) if w.bucket * b == cur]
    if not windows or model.threshold is None:
        return []
    allow = set(cfg.detection.allowlist_sources)
    X = np.array([w.x for w in windows])
    scores = model.score(X)
    out = []
    rule = cfg.detection.rule("behavior_model")
    for w, x, s in zip(windows, X, scores, strict=True):
        if s < model.threshold or w.client in allow:
            continue
        why = model.explain(x)
        out.append(
            Finding(
                rule_id="behavior_model",
                detector="model",
                category="security",
                title="Unusual source behaviour (model)",
                severity=rule.severity,
                assessment="unusual",
                entity=w.client,
                source_id=w.source_id,
                service=None,
                first_seen=cur,
                last_seen=cur + b,
                evidence=[
                    f"Anomaly score {s:.3f} ≥ threshold {model.threshold:.3f} "
                    f"(model {model.metadata.get('model_version')}, alert budget "
                    f"{cfg.ml.alert_rate:.2%} of validation windows)"
                ]
                + [
                    f"{d['feature']} = {d['value']:g} (typical {d['typical']:g}, robust z {d['robust_z']})"
                    for d in why
                ],
                event_rowids=w.rowids[:100],
                confidence="Low on its own: an unsupervised score ranks unusualness only.",
                limitations="Isolation Forest has no per-feature attributions; the listed "
                "deviations are approximate diagnostics. New legitimate clients look unusual.",
                recommended_action="Review the source's events; resolve with a verdict so the "
                "false-alert rate can be measured.",
                simulated=simulated,
            )
        )
    return out
