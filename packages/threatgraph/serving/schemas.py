"""Versioned (v1) response schemas shared by the FastAPI app and the static export."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class Provenance(BaseModel):
    dataset: str
    mode: Literal["synthetic", "lanl"]
    mode_label: str
    is_synthetic: bool
    source: str
    source_url: str | None
    label_source: str
    config_hash: str
    pipeline_version: str


class SplitInfo(BaseModel):
    split: str
    start_seconds: int
    end_seconds: int
    n_windows: int
    n_positive_windows: int
    n_labeled_events: int
    n_principals: int


class FeatureInfo(BaseModel):
    name: str
    description: str


class Metadata(BaseModel):
    provenance: Provenance
    time_start_seconds: int
    time_end_seconds: int
    n_days: int
    time_semantics: str
    scoring_unit: str
    window_seconds: int
    label_semantics: str
    splits: list[SplitInfo]
    feature_set: str
    features: list[FeatureInfo]
    model_ids: list[str]
    implemented_views: list[str]


class FlaggedCount(BaseModel):
    model_id: str
    split: str
    threshold: float
    alerts: int


class Summary(BaseModel):
    provenance: Provenance
    processed_auth_events: int
    rejected_source_rows: int
    distinct_principals: int
    distinct_computers: int
    scored_windows: int
    redteam_records_in_window: int
    labeled_redteam_events: int
    known_positive_windows: int
    flagged_windows: list[FlaggedCount]
    model_versions: dict[str, str]


class HeadlineMetrics(BaseModel):
    split: str
    average_precision: float | None
    random_ranking_average_precision: float | None
    precision_at_10: float | None
    alerts: int
    known_label_recall: float | None
    precision_lower_bound: float | None


class ModelInfo(BaseModel):
    model_id: str
    display_name: str
    kind: str
    description: str
    features: list[str]
    hyperparameters: dict[str, Any]
    threshold: float
    threshold_policy: dict[str, Any]
    train_info: dict[str, Any]
    explanation_method: str
    explanation_caveat: str
    artifact_sha256: str
    library_versions: dict[str, str]
    headline: list[HeadlineMetrics]


class ModelList(BaseModel):
    provenance: Provenance
    models: list[ModelInfo]


class ThresholdPoint(BaseModel):
    threshold: float
    alerts: int
    known_positive_alerts: int
    unlabeled_alerts: int
    missed_known_positives: int
    unlabeled_not_alerted: int
    precision_lower_bound: float | None
    known_label_recall: float | None
    alert_rate: float | None


class PrecisionAtK(BaseModel):
    k: int
    k_effective: int
    known_positives: int
    precision: float | None


class PRPoint(BaseModel):
    recall: float
    precision: float
    threshold: float


class Histogram(BaseModel):
    bin_edges: list[float]
    known_positive: list[int]
    unlabeled: list[int]


class Latency(BaseModel):
    principal: str
    first_labeled_event_seconds: int
    detected: bool
    first_alert_seconds: int | None
    latency_seconds: int | None
    known_positive_windows: int
    alerted_known_positive_windows: int


class SplitMetrics(BaseModel):
    n_windows: int
    n_positive_windows: int
    n_labeled_events: int
    prevalence: float | None
    average_precision: float | None
    average_precision_estimable: bool
    random_ranking_average_precision: float | None
    roc_auc: float | None
    precision_at_k: list[PrecisionAtK]
    operating_point: ThresholdPoint
    alerts_per_day: float | None
    alerts_per_1000_windows: float | None
    pr_curve: list[PRPoint]
    score_histogram: Histogram
    detection_latency: list[Latency]


class ModelMetrics(BaseModel):
    provenance: Provenance
    model_id: str
    display_name: str
    threshold: float
    evaluation_assumptions: list[str]
    split_boundaries_seconds: dict[str, list[int]]
    splits: dict[str, SplitMetrics]


class ScoreTable(BaseModel):
    """Persisted held-out scores; the browser recomputes threshold metrics from these rows."""

    provenance: Provenance
    model_id: str
    split: str
    n_days: float
    calibrated_threshold: float
    columns: list[str] = Field(default=["window_id", "score", "label"])
    rows: list[tuple[str, float, int]]


class PredictionRow(BaseModel):
    window_id: str
    principal: str
    window_start: int
    window_end: int
    day: int
    score: float
    rank: int
    known_redteam: bool
    n_labeled_events: int
    flagged: bool


class PredictionPage(BaseModel):
    provenance: Provenance
    model_id: str
    split: str
    threshold: float
    total_flagged: int
    offset: int
    rows: list[PredictionRow]


class AuthEvent(BaseModel):
    event_id: int
    event_time_seconds: int
    day: int
    src_principal: str | None
    dst_principal: str | None
    src_computer: str | None
    dst_computer: str | None
    auth_type: str | None
    logon_type: str | None
    auth_orientation: str | None
    outcome: str | None
    known_redteam: bool
    used_in_features: bool


class FeatureDiagnostic(BaseModel):
    feature: str
    description: str
    value: float
    reference_median: float
    reference_scale: float
    robust_z: float


class Explanation(BaseModel):
    provenance: Provenance
    model_id: str
    window_id: str
    principal: str
    split: str
    window_start: int
    window_end: int
    score: float
    threshold: float
    flagged: bool
    label: Literal["known_redteam", "unlabeled"]
    n_labeled_events: int
    method: str
    caveat: str
    diagnostics: list[FeatureDiagnostic]
    feature_values: dict[str, float]
    n_events_in_window: int
    evidence_events: list[AuthEvent]
    evidence_truncated: bool


class ExplanationBundle(BaseModel):
    """Static-export container: precomputed explanations keyed by window_id."""

    provenance: Provenance
    model_id: str
    split: str
    selection: str
    explanations: dict[str, Explanation]


class EventPage(BaseModel):
    provenance: Provenance
    rows: list[AuthEvent]
    next_cursor: int | None


class Benchmarks(BaseModel):
    provenance: Provenance
    stages: dict[str, dict[str, Any]]
    ingest_rows_per_second: float | None
    processed_bytes: dict[str, int]
    export_payload_bytes: int | None
    library_versions: dict[str, str]


class Health(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    dataset: str
    mode: str
    detail: str | None = None
