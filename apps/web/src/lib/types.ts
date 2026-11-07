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
  features: { name: string; description: string; group: string }[];
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

export interface Interval {
  low: number | null;
  high: number | null;
  estimable_share: number;
}

export interface MetricIntervals {
  average_precision: Interval;
  known_label_recall: Interval;
  precision_lower_bound: Interval;
}

export interface HeadlineMetrics {
  split: EvalSplit;
  average_precision: number | null;
  intervals: MetricIntervals | null;
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

export interface AblationSplit {
  split: EvalSplit;
  n_positive_windows: number;
  baseline: HeadlineMetrics;
  candidate: HeadlineMetrics;
  average_precision_delta: number | null;
  average_precision_delta_interval: Interval | null;
  share_candidate_better: number | null;
}

export interface Ablation {
  ablation_id: string;
  title: string;
  baseline: string;
  candidate: string;
  added_features: string[];
  removed_features: string[];
  note: string;
  splits: AblationSplit[];
}

export interface BootstrapInfo {
  method: string;
  n_boot: number;
  seed: number;
  level: number;
  n_accounts: number;
  n_positive_accounts: number;
}

export interface SupervisedDecision {
  trained: boolean;
  labels_permit: boolean;
  train_positive_windows: number;
  train_positive_accounts: number;
  required: Record<string, number>;
  reason: string;
}

export interface ModelList {
  provenance: Provenance;
  models: ModelInfo[];
  ablations: Ablation[];
  bootstrap: Record<string, BootstrapInfo>;
  supervised_model: SupervisedDecision;
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
  uncertainty: MetricIntervals | null;
}

export interface Faithfulness {
  method: string;
  split: string;
  n_alerts: number;
  n_random_draws: number;
  seed: number;
  results: {
    k: number;
    mean_score_drop_top: number;
    mean_score_drop_random: number;
    below_threshold_share_top: number;
    below_threshold_share_random: number;
    top_beats_random_share: number;
  }[];
}

export interface ModelMetrics {
  provenance: Provenance;
  model_id: string;
  display_name: string;
  threshold: number;
  evaluation_assumptions: string[];
  split_boundaries_seconds: Record<string, [number, number]>;
  splits: Record<EvalSplit, SplitMetrics>;
  explanation_faithfulness: Faithfulness | null;
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
  /** Large splits keep only the top rows; counts are exact for thresholds above `exact_above`. */
  n_rows_total: number;
  n_known_positive_total: number;
  truncated: boolean;
  exact_above: number | null;
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
  api_latency: {
    dataset: string;
    repeats: number;
    endpoints: Record<string, { url: string; p50_ms: number; p95_ms: number; response_bytes: number }>;
  } | null;
}

export interface EdgeEvent {
  event_id: number;
  event_time_seconds: number;
  auth_type: string | null;
  logon_type: string | null;
  auth_orientation: string | null;
  outcome: string | null;
  known_redteam: boolean;
}

export interface GraphNode {
  node_id: string;
  label: string;
  hop: number;
  n_principals_in_range: number;
  is_hub: boolean;
  expanded: boolean;
}

export interface GraphEdge {
  edge_id: string;
  principal: string;
  principal_id: string;
  source: string;
  target: string;
  hop: number;
  n_events: number;
  n_success: number;
  n_fail: number;
  n_known_redteam: number;
  n_windows: number;
  first_event_seconds: number;
  last_event_seconds: number;
  auth_types: string[];
  edge_first_seen_seconds: number;
  first_observed_in_range: boolean;
  is_local: boolean;
  sample_events: EdgeEvent[];
}

export interface GraphPrincipal {
  principal_id: string;
  label: string;
  hop: number;
  n_edges: number;
  n_events: number;
  n_known_redteam: number;
}

export interface Subgraph {
  provenance: Provenance;
  focus: string;
  start_seconds: number;
  end_seconds: number;
  hops: number;
  max_edges: number;
  hub_max_principals: number;
  n_edges_total: number;
  truncated: boolean;
  truncation_order: string;
  semantics: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  principals: GraphPrincipal[];
}

export interface WindowScore {
  score: number;
  threshold: number;
  flagged: boolean;
  rank: number;
}

export interface GraphWindowSummary {
  window_id: string;
  principal: string;
  principal_id: string;
  split: string;
  window_start: number;
  window_end: number;
  day: number;
  label: "known_redteam" | "unlabeled";
  n_labeled_events: number;
  scores: Record<string, WindowScore>;
}

export interface GraphWindowIndex {
  provenance: Provenance;
  split: string;
  selection: string;
  windows: GraphWindowSummary[];
}

export interface GraphWindow {
  provenance: Provenance;
  window: GraphWindowSummary;
  graph: Subgraph;
}

export interface EntityLink {
  entity_id: string;
  label: string;
  n_events: number;
  n_known_redteam: number;
  first_seen_seconds: number;
  last_seen_seconds: number;
}

export interface EntityDetail {
  provenance: Provenance;
  entity_id: string;
  entity_type: "principal" | "computer";
  label: string;
  scope: string;
  first_seen_seconds: number;
  last_seen_seconds: number;
  n_events: number;
  n_fail: number;
  n_known_redteam_events: number;
  n_active_windows: number | null;
  n_distinct_src_computers: number | null;
  n_distinct_dst_computers: number | null;
  windows_by_split: { split: string; n_windows: number; n_known_positive_windows: number }[];
  model_windows: {
    model_id: string;
    display_name: string;
    split: string;
    n_windows: number;
    alerts: number;
    top_windows: { window_id: string; window_start: number; score: number; flagged: boolean; known_redteam: boolean }[];
  }[];
  n_distinct_principals: number | null;
  in_degree: number | null;
  out_degree: number | null;
  n_local_events: number | null;
  top_links: EntityLink[];
  n_links_total: number;
}

export interface IncidentDetection {
  model_id: string;
  display_name: string;
  status: "detected" | "missed" | "not_scored";
  first_alert_seconds: number | null;
  latency_seconds: number | null;
  labeled_windows: number;
  alerted_labeled_windows: number;
  alerted_windows_in_range: number;
  max_labeled_score: number | null;
  threshold: number;
}

export interface IncidentSummary {
  incident_id: string;
  principal: string;
  principal_id: string;
  split: string;
  start_seconds: number;
  end_seconds: number;
  n_labeled_events: number;
  n_computers: number;
  detections: IncidentDetection[];
}

export interface IncidentIndex {
  provenance: Provenance;
  scope: string;
  definition: string;
  incidents: IncidentSummary[];
}

export interface IncidentWindow {
  window_id: string;
  window_start: number;
  window_end: number;
  split: string;
  label: "known_redteam" | "unlabeled";
  n_labeled_events: number;
  scores: Record<string, { score: number; threshold: number; flagged: boolean }>;
}

export interface Incident {
  provenance: Provenance;
  summary: IncidentSummary;
  definition: string;
  range_start_seconds: number;
  range_end_seconds: number;
  hops: { event_id: number; event_time_seconds: number; src_computer: string | null; dst_computer: string | null; auth_type: string | null; outcome: string | null }[];
  events: AuthEvent[];
  n_events_total: number;
  events_truncated: boolean;
  windows: IncidentWindow[];
  writeup: string[];
  caveats: string[];
}

export interface DriftDay {
  day: number;
  split: string;
  n_windows: number;
  n_known_positive_windows: number;
  feature_psi: Record<string, number | null>;
  score_psi: Record<string, number | null>;
  alert_rate: Record<string, number>;
}

export interface Drift {
  provenance: Provenance;
  reference: string;
  bins: number;
  thresholds: { stable: number; major: number };
  alert_budget: number;
  features: string[];
  constant_in_reference: string[];
  expected_drift: Record<string, string>;
  models: string[];
  days: DriftDay[];
  semantics: string;
}

export interface MapWindow {
  window_id: string;
  window_start: number;
  day: number;
  known_redteam: boolean;
  scores: Record<string, WindowScore>;
}

export interface MapAccountScore {
  max_score: number;
  best_rank: number;
  n_alerts: number;
  alert_days: number[];
}

export interface MapAccount {
  node_id: string;
  label: string;
  n_windows: number;
  n_known_redteam_windows: number;
  n_computers_total: number;
  n_computers_shown: number;
  days: number[];
  scores: Record<string, MapAccountScore>;
  windows: MapWindow[];
}

export interface MapComputer {
  node_id: string;
  label: string;
  n_accounts_in_split: number;
  n_accounts_shown: number;
  n_known_redteam: number;
}

export interface MapLinkDay {
  day: number;
  n_events: number;
  n_fail: number;
  n_known_redteam: number;
  /** Indexes into NetworkMap.models of the models that flagged a window containing this link on this day. */
  alerted: number[];
}

export interface MapLink {
  account: string;
  computer: string;
  role: "source" | "destination" | "both" | "local";
  n_events: number;
  n_fail: number;
  n_known_redteam: number;
  first_event_seconds: number;
  last_event_seconds: number;
  by_day: MapLinkDay[];
}

export interface NetworkMap {
  provenance: Provenance;
  split: EvalSplit;
  models: string[];
  start_seconds: number;
  end_seconds: number;
  days: number[];
  selection: string;
  semantics: string;
  n_accounts_in_split: number;
  n_accounts_selected: number;
  max_accounts: number;
  max_computers_per_account: number;
  max_links: number;
  computer_order: string;
  accounts: MapAccount[];
  computers: MapComputer[];
  links: MapLink[];
}
