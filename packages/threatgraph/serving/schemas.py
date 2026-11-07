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
    group: str


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


class AblationSplit(BaseModel):
    split: str
    n_positive_windows: int
    baseline: HeadlineMetrics
    candidate: HeadlineMetrics
    average_precision_delta: float | None


class Ablation(BaseModel):
    ablation_id: str
    title: str
    baseline: str
    candidate: str
    added_features: list[str]
    removed_features: list[str]
    note: str
    splits: list[AblationSplit]


class ModelList(BaseModel):
    provenance: Provenance
    models: list[ModelInfo]
    ablations: list[Ablation]


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
    # Large splits keep only the highest-scoring rows. Metrics stay exact for thresholds
    # above `exact_above` because every row scoring higher is included; totals cover all rows.
    n_rows_total: int
    n_known_positive_total: int
    truncated: bool
    exact_above: float | None


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
    # From `make benchmark` (artifacts/<ds>/reports/api_benchmark.json); null if never run.
    api_latency: dict[str, Any] | None = None


class EdgeEvent(BaseModel):
    """An authentication event behind a graph edge (principal and computers are the edge's)."""

    event_id: int
    event_time_seconds: int
    auth_type: str | None
    logon_type: str | None
    auth_orientation: str | None
    outcome: str | None
    known_redteam: bool


class GraphNode(BaseModel):
    node_id: str
    label: str
    hop: int
    n_principals_in_range: int
    is_hub: bool
    expanded: bool


class GraphEdge(BaseModel):
    edge_id: str
    principal: str
    principal_id: str
    source: str
    target: str
    hop: int
    n_events: int
    n_success: int
    n_fail: int
    n_known_redteam: int
    n_windows: int
    first_event_seconds: int
    last_event_seconds: int
    auth_types: list[str]
    edge_first_seen_seconds: int
    first_observed_in_range: bool
    is_local: bool
    sample_events: list[EdgeEvent]


class GraphPrincipal(BaseModel):
    principal_id: str
    label: str
    hop: int
    n_edges: int
    n_events: int
    n_known_redteam: int


class Subgraph(BaseModel):
    provenance: Provenance
    focus: str
    start_seconds: int
    end_seconds: int
    hops: int
    max_edges: int
    hub_max_principals: int
    n_edges_total: int
    truncated: bool
    truncation_order: str
    semantics: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    principals: list[GraphPrincipal]


class WindowScore(BaseModel):
    score: float
    threshold: float
    flagged: bool
    rank: int


class GraphWindowSummary(BaseModel):
    window_id: str
    principal: str
    principal_id: str
    split: str
    window_start: int
    window_end: int
    day: int
    label: Literal["known_redteam", "unlabeled"]
    n_labeled_events: int
    scores: dict[str, WindowScore]


class GraphWindowIndex(BaseModel):
    provenance: Provenance
    split: str
    selection: str
    windows: list[GraphWindowSummary]


class GraphWindow(BaseModel):
    provenance: Provenance
    window: GraphWindowSummary
    graph: Subgraph


class SplitWindows(BaseModel):
    split: str
    n_windows: int
    n_known_positive_windows: int


class EntityWindow(BaseModel):
    window_id: str
    window_start: int
    score: float
    flagged: bool
    known_redteam: bool


class EntityModelWindows(BaseModel):
    model_id: str
    display_name: str
    split: str
    n_windows: int
    alerts: int
    top_windows: list[EntityWindow]


class EntityLink(BaseModel):
    entity_id: str
    label: str
    n_events: int
    n_known_redteam: int
    first_seen_seconds: int
    last_seen_seconds: int


class EntityDetail(BaseModel):
    provenance: Provenance
    entity_id: str
    entity_type: Literal["principal", "computer"]
    label: str
    scope: str
    first_seen_seconds: int
    last_seen_seconds: int
    n_events: int
    n_fail: int
    n_known_redteam_events: int
    # principals
    n_active_windows: int | None = None
    n_distinct_src_computers: int | None = None
    n_distinct_dst_computers: int | None = None
    windows_by_split: list[SplitWindows] = []
    model_windows: list[EntityModelWindows] = []
    # computers
    n_distinct_principals: int | None = None
    in_degree: int | None = None
    out_degree: int | None = None
    n_local_events: int | None = None
    top_links: list[EntityLink]
    n_links_total: int


class IncidentScore(BaseModel):
    score: float
    threshold: float
    flagged: bool


class IncidentWindow(BaseModel):
    window_id: str
    window_start: int
    window_end: int
    split: str
    label: Literal["known_redteam", "unlabeled"]
    n_labeled_events: int
    scores: dict[str, IncidentScore]


class IncidentDetection(BaseModel):
    model_id: str
    display_name: str
    # detected: a labeled window was alerted; missed: none was; not_scored: no labeled window
    # falls in a scored split (e.g. the incident is in the warm-up period).
    status: Literal["detected", "missed", "not_scored"]
    first_alert_seconds: int | None  # end of the first alerted labeled window
    latency_seconds: int | None  # first labeled event -> first_alert_seconds
    labeled_windows: int
    alerted_labeled_windows: int
    alerted_windows_in_range: int
    max_labeled_score: float | None
    threshold: float


class IncidentHop(BaseModel):
    event_id: int
    event_time_seconds: int
    src_computer: str | None
    dst_computer: str | None
    auth_type: str | None
    outcome: str | None


class IncidentSummary(BaseModel):
    incident_id: str
    principal: str
    principal_id: str
    split: str
    start_seconds: int
    end_seconds: int
    n_labeled_events: int
    n_computers: int
    detections: list[IncidentDetection]


class IncidentIndex(BaseModel):
    provenance: Provenance
    scope: str
    definition: str
    incidents: list[IncidentSummary]


class Incident(BaseModel):
    provenance: Provenance
    summary: IncidentSummary
    definition: str
    range_start_seconds: int
    range_end_seconds: int
    hops: list[IncidentHop]
    events: list[AuthEvent]
    n_events_total: int
    events_truncated: bool
    windows: list[IncidentWindow]
    writeup: list[str]
    caveats: list[str]


class Health(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    dataset: str
    mode: str
    detail: str | None = None
