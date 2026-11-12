"use client";

import { useCallback, useEffect, useState } from "react";
import { int } from "@/lib/format";
import {
  ago,
  ASSESSMENT_TEXT,
  describeEvent,
  live,
  liveEnabled,
  LiveHttpError,
  sortIncidents,
  STALE_SECONDS,
  utc,
  type IncidentRow,
  type LiveEvent,
  type LiveRange,
  type Me,
  type Overview,
} from "@/lib/live";
import { Callout, LoadingBlock, Panel, SectionTitle, Segmented, StatTile } from "../ui";
import { AgentState, LiveBadge, SeverityBadge, SimulatedBadge, UpDown } from "./badges";
import { IncidentPanel } from "./IncidentPanel";
import { LiveSeries } from "./LiveChart";

const RANGES: { value: LiveRange; label: string }[] = [
  { value: "15m", label: "Last 15 min" },
  { value: "1h", label: "Last hour" },
  { value: "24h", label: "Last 24 h" },
  { value: "7d", label: "Last 7 days" },
];
const REFRESH_MS = 30_000;

export function LiveDashboard() {
  const [me, setMe] = useState<Me | null | "anon">(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!liveEnabled) return;
    live.me().then(setMe, (e: unknown) => {
      if (e instanceof LiveHttpError && e.status === 401) setMe("anon");
      else setError(String(e));
    });
  }, []);

  return (
    <div className="space-y-6 fade-in">
      <header className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-semibold tracking-tight">Live monitoring</h1>
          <LiveBadge />
        </div>
        <p className="max-w-3xl text-sm leading-relaxed text-ink-2">
          Telemetry collected from your own servers and websites: health, availability, web traffic, authentication and
          incidents. This mode is separate from the research results on the other pages and never mixes with them.
        </p>
      </header>
      {!liveEnabled ? (
        <NotEnabled />
      ) : error ? (
        <Callout title="Live API unreachable">
          <p>{error}</p>
        </Callout>
      ) : me === null ? (
        <LoadingBlock label="Checking session…" />
      ) : me === "anon" ? (
        <Login onDone={() => live.me().then(setMe, (e: unknown) => setError(String(e)))} />
      ) : (
        <Dashboard me={me} onLogout={() => live.logout().finally(() => setMe("anon"))} />
      )}
    </div>
  );
}

function NotEnabled() {
  return (
    <div data-testid="live-not-enabled">
      <Callout title="Live monitoring is not enabled in this build">
        <p>
          This public site is a static research demo, so it contains no server telemetry. Live monitoring runs as a private,
          authenticated service on your own deployment and is configured with{" "}
          <code className="font-mono">NEXT_PUBLIC_TG_LIVE_API_BASE</code>. Nothing on this page is simulated or invented: with no
          live service there is simply nothing to show. Setup: <code className="font-mono">docs/live/README.md</code>.
        </p>
      </Callout>
    </div>
  );
}

function Login({ onDone }: { onDone: () => void }) {
  const [user, setUser] = useState("");
  const [pw, setPw] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setMsg(null);
    try {
      await live.login(user, pw);
      setPw("");
      onDone();
    } catch (err) {
      setMsg(err instanceof LiveHttpError ? err.message : String(err));
    }
  };
  return (
    <Panel className="max-w-sm">
      <SectionTitle title="Sign in" subtitle="Live monitoring data is private." />
      <form onSubmit={submit} className="space-y-3" data-testid="live-login">
        <label className="block text-xs text-ink-3">
          User name
          <input autoComplete="username" value={user} onChange={(e) => setUser(e.target.value)} className="mt-1 block w-full rounded-md border border-line bg-panel px-2 py-1.5 text-sm text-ink" />
        </label>
        <label className="block text-xs text-ink-3">
          Password
          <input type="password" autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} className="mt-1 block w-full rounded-md border border-line bg-panel px-2 py-1.5 text-sm text-ink" />
        </label>
        <button type="submit" className="rounded-md border border-line bg-panel-2 px-3 py-1.5 text-sm text-ink">
          Sign in
        </button>
        {msg ? (
          <p role="alert" className="text-sm text-ink-2">
            {msg}
          </p>
        ) : null}
      </form>
    </Panel>
  );
}

function Dashboard({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [range, setRange] = useState<LiveRange>("1h");
  const [simulated, setSimulated] = useState(false);
  const [ov, setOv] = useState<Overview | null>(null);
  const [incidents, setIncidents] = useState<IncidentRow[]>([]);
  const [incScope, setIncScope] = useState<"active" | "all">("active");
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [kind, setKind] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    Promise.all([
      live.overview(range, simulated),
      live.incidents(incScope === "active" ? "active" : null, simulated),
      live.events(range, simulated, kind || undefined),
    ]).then(
      ([o, i, e]) => {
        setOv(o);
        setIncidents(sortIncidents(i.incidents));
        setEvents(e.events);
        setError(null);
      },
      (e: unknown) => setError(String(e)),
    );
  }, [range, simulated, incScope, kind]);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, REFRESH_MS);
    return () => clearInterval(t);
  }, [refresh]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <Segmented label="Time range" value={range} onChange={setRange} options={RANGES} />
        <label className="inline-flex items-center gap-2 text-sm text-ink-2">
          <input type="checkbox" checked={simulated} onChange={(e) => setSimulated(e.target.checked)} />
          Show simulated test data instead of real telemetry
        </label>
        <span className="ml-auto text-xs text-ink-3">
          {me.username} · refreshes every 30 s ·{" "}
          <button onClick={onLogout} className="underline">
            Sign out
          </button>
        </span>
      </div>
      {simulated ? (
        <Callout title="Simulated test data" tone="synthetic">
          <p>Everything below comes from labeled test scenarios, not from your servers. Their notifications are not delivered.</p>
        </Callout>
      ) : null}
      {error ? <Callout title="Could not refresh">{error}</Callout> : null}
      {!ov ? (
        <LoadingBlock label="Loading telemetry…" />
      ) : (
        <>
          <Summary ov={ov} me={me} />
          <Agents ov={ov} />
          <Availability ov={ov} range={range} />
          <Hosts ov={ov} range={range} />
          <Panel>
            <SectionTitle
              title="Web traffic"
              subtitle={`${int(ov.web.total_requests)} requests · 5xx rate ${ov.web.error_rate_5xx === null ? "n/a" : `${(100 * ov.web.error_rate_5xx).toFixed(2)}%`}${ov.web.mean_request_ms === null ? "" : ` · mean response ${ov.web.mean_request_ms.toFixed(0)} ms`}`}
            />
            <div className="grid gap-6 lg:grid-cols-2">
              <LiveSeries testId="chart-requests" title="Requests" unit="requests" buckets={ov.buckets} values={ov.web.requests} range={range} />
              <LiveSeries testId="chart-5xx" title="Server errors (5xx)" unit="responses" buckets={ov.buckets} values={ov.web.status_5xx} range={range} />
            </div>
          </Panel>
          <Panel>
            <SectionTitle
              title="Authentication"
              subtitle={`${int(ov.auth.total_failures)} failed and ${int(ov.auth.total_successes)} successful SSH logins · ${int(ov.auth.admin_events)} administrative events`}
            />
            <div className="grid gap-6 lg:grid-cols-[2fr_1fr]">
              <LiveSeries testId="chart-ssh" title="Failed SSH logins" unit="failures" buckets={ov.buckets} values={ov.auth.ssh_failures} range={range} />
              <div>
                <div className="mb-1 text-sm font-medium text-ink">Top sources of failures</div>
                {ov.auth.top_failure_sources.length === 0 ? (
                  <p className="text-xs text-ink-3">None in this range.</p>
                ) : (
                  <table className="w-full text-sm">
                    <tbody>
                      {ov.auth.top_failure_sources.map((s) => (
                        <tr key={s.source} className="border-t border-line">
                          <td className="py-1 font-mono text-xs text-ink-2">{s.source}</td>
                          <td className="py-1 text-right tabular-nums">{int(s.failures)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          </Panel>
          <Panel id="incidents">
            <SectionTitle
              title="Incidents"
              subtitle="Severity follows documented rule criteria. 'Unusual' and 'suspected' are not confirmed compromises."
              right={<Segmented label="Incident scope" value={incScope} onChange={setIncScope} options={[{ value: "active", label: "Open" }, { value: "all", label: "History" }]} />}
            />
            <IncidentTable rows={incidents} onOpen={setOpen} />
            {open ? (
              <div className="mt-4 border-t border-line pt-4">
                <IncidentPanel key={open} id={open} me={me} onChange={refresh} onClose={() => setOpen(null)} />
              </div>
            ) : null}
          </Panel>
          <Panel>
            <SectionTitle
              title="Event timeline"
              subtitle="Most recent 200 events in the range. Log-derived text is shown as plain text."
              right={
                <select aria-label="Event kind" value={kind} onChange={(e) => setKind(e.target.value)} className="rounded-md border border-line bg-panel px-2 py-1 text-sm text-ink">
                  <option value="">Security and web events</option>
                  <option value="ssh.auth,ssh.probe">SSH</option>
                  <option value="admin.sudo,admin.su,admin.account">Administrative</option>
                  <option value="http.access">Web requests</option>
                  <option value="http.error">Web server errors</option>
                  <option value="system.service,system.kernel,container.health">Services and containers</option>
                  <option value="fim.change">File integrity</option>
                  <option value="probe.http">Availability checks</option>
                </select>
              }
            />
            <EventTable events={kind ? events : events.filter((e) => !["system.metrics", "agent.heartbeat", "probe.http"].includes(e.kind))} />
          </Panel>
        </>
      )}
    </div>
  );
}

function Summary({ ov, me }: { ov: Overview; me: Me }) {
  const open = Object.values(ov.incidents.open_by_severity).reduce((a, b) => a + (b ?? 0), 0);
  const online = ov.agents.filter((a) => a.status === "online").length;
  const down = ov.availability.filter((a) => !a.up).length;
  const w = ov.worker;
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <StatTile testId="tile-incidents" label="Open incidents" value={int(open)} note={(["critical", "high", "medium"] as const).map((s) => `${ov.incidents.open_by_severity[s] ?? 0} ${s}`).join(" · ")} />
      <StatTile testId="tile-agents" label="Agents online" value={`${online} / ${ov.agents.filter((a) => a.role === "agent").length}`} note="Probes listed separately" />
      <StatTile label="Monitored sites down" value={ov.availability.length ? int(down) : "No checks"} note={`${ov.availability.length} targets checked`} />
      <StatTile
        label="Detection worker"
        value={w ? ago(ov.generated_at - w.last_run) : "Not running"}
        note={w ? `Channels: ${w.channels.join(", ") || "none"}${Object.keys(w.errors).length ? ` · errors in ${Object.keys(w.errors).join(", ")}` : ""}` : `Channels: ${me.channels.join(", ") || "none"}`}
      />
    </div>
  );
}

function Agents({ ov }: { ov: Overview }) {
  return (
    <Panel>
      <SectionTitle title="Monitoring agents" subtitle="An agent that stops reporting leaves gaps in every chart; they are never filled in." />
      {ov.agents.length === 0 ? (
        <p className="text-sm text-ink-3">No agent registered. Add one with `threatgraph-live agent add &lt;name&gt;`.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-sm" data-testid="agents-table">
            <thead className="text-xs text-ink-3">
              <tr>
                <th className="py-1 pr-3 font-medium">Source</th>
                <th className="py-1 pr-3 font-medium">State</th>
                <th className="py-1 pr-3 font-medium">Last data</th>
                <th className="py-1 pr-3 font-medium">Buffer / dropped / send failures</th>
                <th className="py-1 font-medium">Logs and collectors</th>
              </tr>
            </thead>
            <tbody>
              {ov.agents.map((a) => (
                <tr key={a.source_id} className="border-t border-line align-top">
                  <td className="py-1.5 pr-3">
                    <div className="font-medium text-ink">{a.source_id}</div>
                    <div className="text-xs text-ink-3">
                      {a.role}
                      {a.version ? ` · v${a.version}` : ""}
                    </div>
                  </td>
                  <td className="py-1.5 pr-3">
                    <AgentState status={a.status} />
                  </td>
                  <td className="py-1.5 pr-3 text-ink-2">{ago(a.seconds_since_seen)}</td>
                  <td className="py-1.5 pr-3 tabular-nums text-ink-2">
                    {a.buffered ?? "n/a"} / {a.dropped_samples ?? "n/a"} / {a.send_failures ?? "n/a"}
                    {a.last_error ? <div className="text-xs text-ink-3">Last error: {a.last_error}</div> : null}
                  </td>
                  <td className="py-1.5 text-xs text-ink-2">
                    {a.logs.map((l) => (
                      <div key={l.path} className="break-all">
                        {l.path}: {l.readable === false ? "not readable" : `${int(l.parsed ?? 0)} parsed, ${int(l.unparsed ?? 0)} unrecognised`}
                      </div>
                    ))}
                    {Object.entries(a.collectors).map(([n, c]) => (
                      <div key={n}>
                        {n}: {c.ok ? "ok" : `problem: ${c.detail}`}
                      </div>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function Availability({ ov, range }: { ov: Overview; range: LiveRange }) {
  return (
    <Panel>
      <SectionTitle title="Website availability" subtitle="From external and on-server checks. Outages of the whole server are only visible to external checks." />
      {ov.availability.length === 0 ? (
        <p className="text-sm text-ink-3" data-testid="no-probes">
          No availability checks in this range. Configure probes (docs/live/probe.md).
        </p>
      ) : (
        <div className="grid gap-6 lg:grid-cols-2">
          {ov.availability.map((a) => (
            <div key={a.target} className="space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <div className="font-medium text-ink">{a.target}</div>
                  <div className="text-xs text-ink-3">{a.url}</div>
                </div>
                <UpDown up={a.up} label={a.up ? "Up" : `Down${a.last_error ? `: ${a.last_error}` : ""}`} />
              </div>
              <div className="text-xs text-ink-2">
                {(100 * a.uptime_ratio).toFixed(2)}% of {a.checks} checks succeeded · last check {ago(a.last_check_age_seconds)}
                {a.cert_days_left !== null ? ` · certificate expires in ${a.cert_days_left.toFixed(0)} days` : ""} · from {a.locations.join(", ")}
              </div>
              <LiveSeries title="Response time" unit="ms" kind="line" buckets={ov.buckets} values={a.latency_series} range={range} />
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

function Hosts({ ov, range }: { ov: Overview; range: LiveRange }) {
  return (
    <Panel>
      <SectionTitle title="Server health" />
      {ov.hosts.length === 0 ? (
        <p className="text-sm text-ink-3">No resource samples received in the last 7 days.</p>
      ) : (
        <div className="space-y-6">
          {ov.hosts.map((h) => {
            const stale = h.sample_age_seconds > STALE_SECONDS;
            return (
              <div key={h.source_id} className="space-y-3">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="font-medium text-ink">{h.source_id}</span>
                  <span className="text-xs text-ink-3">
                    latest sample {ago(h.sample_age_seconds)}
                    {stale ? ": stale, values below are not current" : ""}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                  <StatTile label="CPU" value={h.cpu_percent === null ? "n/a" : `${h.cpu_percent}%`} note={h.load_1m !== null ? `load ${h.load_1m} on ${h.cpu_count} cores` : undefined} />
                  <StatTile label="Memory" value={h.mem_percent === null ? "n/a" : `${h.mem_percent}%`} />
                  <StatTile
                    label="Disk"
                    value={h.disks.length ? `${Math.max(...h.disks.map((d) => d.used_percent ?? 0))}%` : "n/a"}
                    note={h.disks.map((d) => `${d.path} ${d.free_gb} GB free`).join(" · ")}
                  />
                  <StatTile label="Uptime" value={h.uptime_seconds === null ? "n/a" : `${(h.uptime_seconds / 86400).toFixed(1)} d`} />
                </div>
                <div className="grid gap-6 lg:grid-cols-2">
                  <LiveSeries title="CPU" unit="%" kind="line" digits={1} buckets={ov.buckets} values={h.cpu_series} range={range} />
                  <LiveSeries title="Memory" unit="%" kind="line" digits={1} buckets={ov.buckets} values={h.mem_series} range={range} />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </Panel>
  );
}

function IncidentTable({ rows, onOpen }: { rows: IncidentRow[]; onOpen: (id: string) => void }) {
  if (rows.length === 0) return <p className="text-sm text-ink-3" data-testid="no-incidents">No incidents in this view.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[560px] text-left text-sm" data-testid="incidents-table">
        <thead className="text-xs text-ink-3">
          <tr>
            <th className="py-1 pr-3 font-medium">Severity</th>
            <th className="py-1 pr-3 font-medium">Incident</th>
            <th className="py-1 pr-3 font-medium">Assessment</th>
            <th className="py-1 pr-3 font-medium">Status</th>
            <th className="py-1 font-medium">Detected</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} className="border-t border-line align-top">
              <td className="py-1.5 pr-3">
                <SeverityBadge severity={r.severity} />
              </td>
              <td className="py-1.5 pr-3">
                <button onClick={() => onOpen(r.id)} className="text-left font-medium text-ink underline-offset-2 hover:underline">
                  {r.title}
                </button>
                <div className="text-xs text-ink-3">
                  {r.id} · {r.entity} · {r.detector}
                  {r.occurrences > 1 ? ` · seen ${r.occurrences}×` : ""}
                </div>
                {r.simulated ? <SimulatedBadge /> : null}
              </td>
              <td className="py-1.5 pr-3 text-ink-2">{ASSESSMENT_TEXT[r.assessment]}</td>
              <td className="py-1.5 pr-3 text-ink-2">{r.status}</td>
              <td className="py-1.5 whitespace-nowrap text-xs text-ink-2">{utc(r.detected_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function EventTable({ events }: { events: LiveEvent[] }) {
  if (events.length === 0) return <p className="text-sm text-ink-3">No events of this kind in the range.</p>;
  return (
    <div className="max-h-96 overflow-auto rounded-lg border border-line">
      <table className="w-full text-left text-xs" data-testid="events-table">
        <tbody>
          {events.map((e) => (
            <tr key={e.rowid} className="border-t border-line first:border-t-0 align-top">
              <td className="hidden whitespace-nowrap px-2 py-1 text-ink-3 sm:table-cell">{utc(e.ts)}</td>
              <td className="hidden px-2 py-1 text-ink-3 sm:table-cell">{e.source_id}</td>
              <td className="hidden px-2 py-1 text-ink-3 sm:table-cell">{e.kind}</td>
              <td className="px-2 py-1 text-ink-2">
                <div className="text-ink-3 sm:hidden">
                  {utc(e.ts)} · {e.source_id} · {e.kind}
                </div>
                <div className="break-words [overflow-wrap:anywhere]">{describeEvent(e)}</div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
