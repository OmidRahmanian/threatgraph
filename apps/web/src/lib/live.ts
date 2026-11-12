// Live Monitoring Mode client. Private data: it is fetched at runtime from the authenticated
// live API on the same origin (NEXT_PUBLIC_TG_LIVE_API_BASE, e.g. "/live-api/v1") and is never
// part of the static export. Research Mode data (lib/data.ts) is a separate source.

export const LIVE_API_BASE = process.env.NEXT_PUBLIC_TG_LIVE_API_BASE ?? "";
export const liveEnabled = Boolean(LIVE_API_BASE);

export type LiveRange = "15m" | "1h" | "24h" | "7d";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface AgentStatus {
  source_id: string;
  role: string;
  status: "online" | "offline" | "never_connected" | "disabled";
  last_seen: number | null;
  seconds_since_seen: number | null;
  version: string | null;
  buffered: number | null;
  dropped_samples: number | null;
  send_failures: number | null;
  last_error: string | null;
  logs: { path: string; type?: string; parsed?: number; unparsed?: number; readable?: boolean }[];
  collectors: Record<string, { ok: boolean; detail: string | null }>;
}

export interface HostHealth {
  source_id: string;
  sample_age_seconds: number;
  cpu_percent: number | null;
  mem_percent: number | null;
  load_1m: number | null;
  cpu_count: number | null;
  uptime_seconds: number | null;
  disks: { path: string; used_percent: number | null; free_gb: number; total_gb: number }[];
  cpu_series: (number | null)[];
  mem_series: (number | null)[];
}

export interface Availability {
  target: string;
  url: string | null;
  up: boolean;
  last_check_age_seconds: number;
  last_status: number | null;
  last_error: string | null;
  cert_days_left: number | null;
  checks: number;
  uptime_ratio: number;
  locations: string[];
  latency_series: (number | null)[];
  ok_series: (number | null)[];
}

export interface IncidentRow {
  id: string;
  title: string;
  severity: Severity;
  assessment: "unusual" | "suspected_malicious" | "confirmed";
  status: "open" | "acknowledged" | "resolved";
  category: string;
  service: string | null;
  source_id: string | null;
  entity: string;
  detector: string;
  rule_id: string;
  detected_at: number;
  first_seen?: number;
  last_seen: number;
  occurrences: number;
  verdict?: string | null;
  simulated: boolean;
}

export interface Overview {
  generated_at: number;
  range: LiveRange;
  bucket_seconds: number;
  buckets: number[];
  covered_buckets: number;
  simulated: boolean;
  agents: AgentStatus[];
  web: {
    requests: (number | null)[];
    status_4xx: (number | null)[];
    status_5xx: (number | null)[];
    total_requests: number;
    error_rate_5xx: number | null;
    mean_request_ms: number | null;
  };
  auth: {
    ssh_failures: (number | null)[];
    ssh_successes: (number | null)[];
    total_failures: number;
    total_successes: number;
    top_failure_sources: { source: string; failures: number }[];
    admin_events: number;
  };
  hosts: HostHealth[];
  availability: Availability[];
  incidents: { open_by_severity: Partial<Record<Severity, number>>; recent: IncidentRow[] };
  worker: { last_run: number; errors: Record<string, string>; channels: string[]; model_loaded: boolean } | null;
}

export interface LiveEvent {
  rowid: number;
  source_id: string;
  event_id: string;
  kind: string;
  ts: number;
  service: string | null;
  attrs: Record<string, unknown>;
  message: string | null;
  simulated: boolean;
}

export interface Investigation {
  created_at: number;
  model: string;
  status: "ok" | "failed";
  error: string | null;
  result: {
    advisory: string;
    evidence_map: Record<string, number>;
    injection_warnings: string[];
    summary?: string;
    possible_causes?: { cause: string; evidence_ids: string[]; likelihood?: string }[];
    correlations?: { observation: string; evidence_ids: string[] }[];
    uncertainty?: string;
    suggested_steps?: string[];
    dropped_unsupported_claims?: number;
  } | null;
}

export interface IncidentDetail {
  incident: IncidentRow & {
    evidence: string[];
    confidence: string;
    limitations: string;
    recommended_action: string;
    resolution: string | null;
    acknowledged_by: string | null;
    resolved_by: string | null;
  };
  evidence_events: LiveEvent[];
  notifications: {
    id: number;
    channel: string;
    kind: string;
    status: "pending" | "sent" | "failed" | "suppressed";
    attempts: number;
    created_at: number;
    sent_at: number | null;
    last_error: string | null;
  }[];
  investigation: Investigation | null;
}

export interface Me {
  username: string;
  channels: string[];
  llm_enabled: boolean;
}

export class LiveHttpError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${LIVE_API_BASE}${path}`, {
    credentials: "same-origin",
    cache: "no-store",
    ...init,
    headers: { "X-TG-Request": "1", ...(init?.body ? { "Content-Type": "application/json" } : {}), ...init?.headers },
  });
  if (!r.ok) {
    let detail = r.statusText;
    try {
      detail = (await r.json()).detail ?? detail;
    } catch {}
    throw new LiveHttpError(r.status, String(detail));
  }
  return r.json() as Promise<T>;
}

export const live = {
  me: () => call<Me>("/auth/me"),
  login: (username: string, password: string) =>
    call<{ username: string }>("/auth/login", { method: "POST", body: JSON.stringify({ username, password }) }),
  logout: () => call<{ ok: boolean }>("/auth/logout", { method: "POST" }),
  overview: (range: LiveRange, simulated: boolean) => call<Overview>(`/overview?range=${range}&simulated=${simulated}`),
  incidents: (status: "active" | "resolved" | null, simulated: boolean) =>
    call<{ incidents: IncidentRow[] }>(`/incidents?simulated=${simulated}${status ? `&status=${status}` : ""}`),
  incident: (id: string) => call<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`),
  events: (range: LiveRange, simulated: boolean, kinds?: string) =>
    call<{ events: LiveEvent[] }>(`/events?range=${range}&simulated=${simulated}&limit=200${kinds ? `&kinds=${kinds}` : ""}`),
  ack: (id: string) => call<{ changed: boolean }>(`/incidents/${encodeURIComponent(id)}/ack`, { method: "POST" }),
  resolve: (id: string, verdict: string, note: string) =>
    call<{ changed: boolean }>(`/incidents/${encodeURIComponent(id)}/resolve`, {
      method: "POST",
      body: JSON.stringify({ verdict, note }),
    }),
  investigate: (id: string) =>
    call<{ status: string; error: string | null }>(`/incidents/${encodeURIComponent(id)}/investigate`, { method: "POST" }),
};

// ------------------------------------------------------------------ pure helpers (unit tested)

/** UTC clock label for a bucket start; dates are shown for ranges longer than a day. */
export function bucketLabel(ts: number, range: LiveRange): string {
  const d = new Date(ts * 1000);
  const hm = `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`;
  if (range === "7d") return `${d.getUTCMonth() + 1}/${d.getUTCDate()} ${hm}`;
  return hm;
}

export function utc(ts: number | null | undefined): string {
  if (ts === null || ts === undefined) return "Never";
  return new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

export function ago(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "never";
  if (seconds < 90) return `${Math.max(0, Math.round(seconds))} s ago`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)} h ago`;
  return `${Math.round(seconds / 86400)} d ago`;
}

/** Chart rows. `null` stays null (no telemetry), so the line breaks instead of dropping to 0. */
export function toRows(buckets: number[], values: (number | null)[], range: LiveRange) {
  return buckets.map((t, i) => ({ t, label: bucketLabel(t, range), value: values[i] ?? null }));
}

export function missingCount(values: (number | null)[]): number {
  return values.filter((v) => v === null).length;
}

export function sum(values: (number | null)[]): number | null {
  const present = values.filter((v): v is number => v !== null);
  return present.length ? present.reduce((a, b) => a + b, 0) : null;
}

/** Metrics older than this are shown as stale rather than as the current state. */
export const STALE_SECONDS = 300;

export function sortIncidents(rows: IncidentRow[]): IncidentRow[] {
  const rank = (s: Severity) => SEVERITIES.indexOf(s);
  const open = (r: IncidentRow) => (r.status === "resolved" ? 1 : 0);
  return [...rows].sort((a, b) => open(a) - open(b) || rank(a.severity) - rank(b.severity) || b.detected_at - a.detected_at);
}

export const ASSESSMENT_TEXT: Record<IncidentRow["assessment"], string> = {
  unusual: "Unusual behaviour",
  suspected_malicious: "Suspected malicious",
  confirmed: "Confirmed incident",
};

/** One-line description of a live event for the timeline (fields only, never markup). */
export function describeEvent(e: LiveEvent): string {
  const a = e.attrs as Record<string, string | number | boolean | null | undefined>;
  switch (e.kind) {
    case "http.access":
      return `${a.client ?? "?"} ${a.method ?? ""} ${a.path ?? "(malformed request)"} → ${a.status}`;
    case "http.error":
      return `${a.level}: ${e.message ?? a.category}`;
    case "ssh.auth":
      return `SSH ${a.outcome} for ${a.user} from ${a.src_ip} (${a.method})`;
    case "ssh.probe":
      return `SSH connection without login from ${a.src_ip} (${a.reason})`;
    case "admin.sudo":
      return `sudo ${a.outcome}: ${a.user} → ${a.target_user}${a.command ? `: ${a.command}` : ""}`;
    case "admin.su":
      return `su ${a.outcome}: ${a.user ?? "?"} → ${a.target_user}`;
    case "admin.account":
      return `Account ${a.action}: ${a.target}${a.group ? ` → ${a.group}` : ""}`;
    case "system.service":
      return `Service ${a.unit}: ${a.state}`;
    case "system.kernel":
      return `Kernel ${a.event}: ${a.process}`;
    case "container.health":
      return `Container ${a.name}: ${a.state}${a.health ? ` (${a.health})` : ""}`;
    case "fim.change":
      return `File ${a.change}: ${a.path}`;
    case "probe.http":
      return `Check ${a.target}: ${a.ok ? "up" : "down"}${a.status ? ` (${a.status})` : ""}${a.error ? `: ${a.error}` : ""}`;
    case "system.metrics":
      return `CPU ${a.cpu_percent ?? "n/a"}% · memory ${a.mem_percent ?? "n/a"}%`;
    case "agent.heartbeat":
      return `Agent heartbeat (buffered ${a.buffered ?? 0})`;
    default:
      return e.kind;
  }
}
