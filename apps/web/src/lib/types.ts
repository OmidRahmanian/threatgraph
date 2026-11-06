// Mirrors packages/threatgraph/serving/schemas.py (API v1). Keep in sync with the Pydantic models.

export type DatasetMode = "synthetic" | "lanl";
export type EvalSplit = "validation" | "test";

export interface Provenance {
  dataset: string;
  mode: DatasetMode;
  mode_label: string;
  is_synthetic: boolean;
  source: string;
  source_url: string | null;
  label_source: string;
  config_hash: string;
  pipeline_version: string;
}

export interface SplitInfo {
  split: string;
  start_seconds: number;
  end_seconds: number;
  n_windows: number;
  n_positive_windows: number;
  n_labeled_events: number;
  n_principals: number;
}

export interface Metadata {
  provenance: Provenance;
  time_start_seconds: number;
  time_end_seconds: number;
  n_days: number;
  time_semantics: string;
  scoring_unit: string;
  window_seconds: number;
  label_semantics: string;
  splits: SplitInfo[];
  feature_set: string;
  features: { name: string; description: string }[];
  model_ids: string[];
  implemented_views: string[];
}

export interface Summary {
  provenance: Provenance;
  processed_auth_events: number;
  rejected_source_rows: number;
  distinct_principals: number;
  distinct_computers: number;
  scored_windows: number;
  redteam_records_in_window: number;
  labeled_redteam_events: number;
  known_positive_windows: number;
  flagged_windows: { model_id: string; split: string; threshold: number; alerts: number }[];
  model_versions: Record<string, string>;
}

export interface HeadlineMetrics {
  split: EvalSplit;
  average_precision: number | null;
  random_ranking_average_precision: number | null;
  precision_at_10: number | null;
  alerts: number;
  known_label_recall: number | null;
  precision_lower_bound: number | null;
}

export interface ModelInfo {
  model_id: string;
  display_name: string;
  kind: string;
  description: string;
  features: string[];
  hyperparameters: Record<string, unknown>;
  threshold: number;
  threshold_policy: Record<string, unknown>;
  train_info: Record<string, unknown>;
  explanation_method: string;
  explanation_caveat: string;
  artifact_sha256: string;
  library_versions: Record<string, string>;
  headline: HeadlineMetrics[];
}

export interface ModelList {
  provenance: Provenance;
  models: ModelInfo[];
}

export interface ThresholdPoint {
  threshold: number;
  alerts: number;
  known_positive_alerts: number;
  unlabeled_alerts: number;
  missed_known_positives: number;
  unlabeled_not_alerted: number;
  precision_lower_bound: number | null;
  known_label_recall: number | null;
  alert_rate: number | null;
}

export interface Latency {
  principal: string;
  first_labeled_event_seconds: number;
  detected: boolean;
  first_alert_seconds: number | null;
  latency_seconds: number | null;
  known_positive_windows: number;
  alerted_known_positive_windows: number;
}

export interface SplitMetrics {
  n_windows: number;
  n_positive_windows: number;
  n_labeled_events: number;
  prevalence: number | null;
  average_precision: number | null;
  average_precision_estimable: boolean;
  random_ranking_average_precision: number | null;
  roc_auc: number | null;
  precision_at_k: { k: number; k_effective: number; known_positives: number; precision: number | null }[];
  operating_point: ThresholdPoint;
  alerts_per_day: number | null;
  alerts_per_1000_windows: number | null;
  pr_curve: { recall: number; precision: number; threshold: number }[];
  score_histogram: { bin_edges: number[]; known_positive: number[]; unlabeled: number[] };
  detection_latency: Latency[];
}

export interface ModelMetrics {
  provenance: Provenance;
  model_id: string;
  display_name: string;
  threshold: number;
  evaluation_assumptions: string[];
  split_boundaries_seconds: Record<string, [number, number]>;
  splits: Record<EvalSplit, SplitMetrics>;
}

export type ScoreRow = [windowId: string, score: number, label: 0 | 1];

export interface ScoreTable {
  provenance: Provenance;
  model_id: string;
  split: EvalSplit;
  n_days: number;
  calibrated_threshold: number;
  columns: string[];
  rows: ScoreRow[];
}

export interface AuthEvent {
  event_id: number;
  event_time_seconds: number;
  day: number;
  src_principal: string | null;
  dst_principal: string | null;
  src_computer: string | null;
  dst_computer: string | null;
  auth_type: string | null;
  logon_type: string | null;
  auth_orientation: string | null;
  outcome: string | null;
  known_redteam: boolean;
  used_in_features: boolean;
}

export interface FeatureDiagnostic {
  feature: string;
  description: string;
  value: number;
  reference_median: number;
  reference_scale: number;
  robust_z: number;
}

export interface Explanation {
  provenance: Provenance;
  model_id: string;
  window_id: string;
  principal: string;
  split: string;
  window_start: number;
  window_end: number;
  score: number;
  threshold: number;
  flagged: boolean;
  label: "known_redteam" | "unlabeled";
  n_labeled_events: number;
  method: string;
  caveat: string;
  diagnostics: FeatureDiagnostic[];
  feature_values: Record<string, number>;
  n_events_in_window: number;
  evidence_events: AuthEvent[];
  evidence_truncated: boolean;
}

export interface ExplanationBundle {
  provenance: Provenance;
  model_id: string;
  split: string;
  selection: string;
  explanations: Record<string, Explanation>;
}

export interface Benchmarks {
  provenance: Provenance;
  stages: Record<string, Record<string, number | string>>;
  ingest_rows_per_second: number | null;
  processed_bytes: Record<string, number>;
  export_payload_bytes: number | null;
  library_versions: Record<string, string>;
}
