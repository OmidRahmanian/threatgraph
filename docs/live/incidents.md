# Detection rules and incidents

Detection is deterministic first: rules count specific things in recent events and compare the
counts with thresholds from `configs/live.yaml`. Real and simulated events are evaluated
separately. The behavioural model ([ml.md](ml.md)) adds `info` findings on top; it never
replaces a rule and never sets severity from a raw score.

## Vocabulary

| Term | Meaning |
|---|---|
| **Unusual** | Deviates from a threshold or baseline. No intent is claimed. |
| **Suspected malicious** | Matches a pattern typical of hostile activity (brute force, scanning). Not a confirmed compromise. |
| **Confirmed** | Only set when a person resolves the incident with the verdict `confirmed_malicious`. |

## Severity criteria

Severity comes from what the rule observed, using these documented criteria:

| Severity | Criteria | Notified by default |
|---|---|---|
| **Critical** | Service down long enough to matter (availability failing ≥ 15 min), disk ≥ 97% full | yes |
| **High** | Likely impact or likely access: login succeeded after repeated failures, sensitive-looking file served with 2xx, privileged group changed, sensitive system file changed, site down, 5xx ≥ 50%, disk ≥ 90%, certificate expires within 3 days | yes |
| **Medium** | Sustained hostile pattern or operational failure without evidence of impact: SSH brute force or spraying, 5xx ≥ 25%, failed service or container, OOM kill, worker crash, memory pressure, repeated sudo failures, other monitored file changed, agent offline, certificate expires within 14 days | yes |
| **Low** | Common background noise worth seeing: web reconnaissance, request bursts, error-rate shifts, account changes outside privileged groups, admin by a user outside the allowlist | dashboard only |
| **Info** | Statistical observations: request-volume deviations, model findings | dashboard only |

Severity can rise while an incident is open (for example, an outage passing 15 minutes, or
reconnaissance that reaches a file). It never drops automatically.

## Rules

Thresholds are starting values for a small personal site. Each finding stores its evidence
lines, the supporting events, a confidence statement, its limitations and a recommended
action. ThreatGraph never blocks addresses or changes configuration.

| Rule | Type | Fires when (default) | Severity | Blind spots |
|---|---|---|---|---|
| `ssh_bruteforce` | event | ≥ 10 failed SSH logins from one address in 5 min | medium | Shared NAT addresses; slow attacks under the rate |
| `ssh_password_spray` | event | ≥ 5 distinct user names from one address in 10 min | medium | Distributed spraying from many addresses |
| `ssh_success_after_failures` | event | a successful login from an address with ≥ 5 failures in the previous hour | high | Mistyped passwords look identical; success from a different address is not linked |
| `http_recon` | event | per client in 5 min: ≥ 3 sensitive-looking paths, or ≥ 25 distinct 404 paths; **high** if a sensitive-looking path returned 2xx | low / high | Paths not in `sensitive_paths`; slow scanners |
| `http_request_burst` | event | ≥ 600 requests from one client in 60 s | low | Crawlers, load tests, shared proxies |
| `http_error_spike` | condition | ≥ 30 requests and ≥ 25% 5xx in 5 min (high at ≥ 50%) | medium / high | Only requests that reached nginx |
| `request_volume_deviation` | event | last 5-min request count has robust z ≥ 8 vs the previous 24 h (≥ 48 intervals, ≥ 200 requests) | info | Needs a day of history; launches and crawlers |
| `error_rate_deviation` | event | same method on nginx error-log volume (≥ 20 errors) | low | Same as above |
| `availability` | condition | the last 2 checks of a target failed (any location); **critical** after 15 min | high / critical | A single probe location's own network failure |
| `tls_expiry` | condition | certificate ≤ 14 days (high ≤ 3) | medium / high | Renewal may still succeed |
| `service_failure` | condition and event | a unit reported failed by `systemctl`; failures logged by systemd | medium | One-shot units that fail by design |
| `container_unhealthy` | condition | container unhealthy, exited, dead or restarting | medium | Containers stopped on purpose |
| `kernel_oom` | event | OOM kill or segfault in the kernel log | medium | Cause not in the log |
| `nginx_worker_crash` | event | nginx worker exited on a signal | medium | |
| `disk_usage` | condition | a monitored mount ≥ 90% (critical ≥ 97%) | high / critical | Only `disk_paths` |
| `memory_pressure` | condition | memory ≥ 95% in the last 5 samples | medium | Short spikes |
| `agent_offline` | condition | no data from a registered, previously connected agent for 5 min | medium | While offline, every other rule is blind for that host |
| `privileged_account_change` | event | user added to `sudo`/`wheel`/`adm`/`docker`/... (high); user created/deleted, password changed (low) | high / low | Changes made without the standard tools |
| `sudo_failure` | event | ≥ 3 failed sudo password attempts by one user in 10 min | medium | Typos |
| `unexpected_admin` | event | sudo by a user outside `allowed_sudo_users` (inactive while the list is empty) | low | Allowlist must be maintained |
| `file_integrity` | event | a monitored file's SHA-256 changed; high for sudoers, passwd, shadow, sshd_config, root's authorized_keys | medium / high | Only listed paths; first run is the baseline |
| `behavior_model` | event | model score ≥ validation threshold | info | See [ml.md](ml.md) |

Condition rules resolve their incident automatically when the condition clears, which sends a
recovery notification if the incident had been notified. Event rules stay open until a person
resolves them.

## Lifecycle and deduplication

1. A finding has a deduplication key: rule, host, service and entity (for example the source
   address). One open incident exists per key.
2. Repeated findings update the incident: last seen, occurrence count, evidence links (up to
   200 events). No new incident and no new alert.
3. Incident ids are `TG-000001`, `TG-000002`, ...
4. **Acknowledge** to show someone is looking. **Resolve** with a verdict:
   `confirmed_malicious`, `false_positive`, `expected_activity` or `benign`, and a note.
5. A resolved incident is not reopened by the same events still inside the detection window.
   New activity after it creates a new incident.

Verdicts are the only verified labels in Live Monitoring Mode. False-alert rates are measured
against them and reported as unknown when there are none.

## Tuning

Change thresholds in `configs/live.yaml` from what you see in the dashboard, then restart the
worker. Add your own monitoring addresses to `allowlist_sources`. Prefer raising a threshold or
narrowing `sensitive_paths` over disabling a rule. Record why in the YAML comments.
