# Live Monitoring Mode

Live Monitoring Mode watches your own Linux servers and websites: it collects real telemetry,
detects security and operational problems with deterministic rules (plus an optional
behavioural model), tracks incidents and notifies you by Telegram or e-mail.

It is separate from **Research Mode** (historical LANL and synthetic data, model comparison,
graph analysis). The two share the Python package, the ML utilities and the website shell,
but live events, incidents and notifications are stored, served and displayed separately, and
nothing in one mode feeds results into the other.

```
 monitored server                     ThreatGraph server (can be the same VPS)
┌────────────────────┐   HTTPS +    ┌───────────────────────────────────────────────────┐
│ threatgraph-agent  │  agent token │ Caddy :8443 (private IP) ─▶ live-ingest ─┐        │
│  nginx, auth.log,  │ ───────────▶ │                                          ▼        │
│  syslog, metrics,  │              │            SQLite (WAL) ◀── live-worker:         │
│  systemd, docker,  │              │                 ▲            rules, model,        │
│  file integrity    │              │                 │            incidents, notify ──┼──▶ Telegram / SMTP
└────────────────────┘              │ Caddy :443 ─▶ live-dashboard (/live-api, login)  │
┌────────────────────┐   probe      │      └──────▶ static site (/threatgraph/live)    │
│ external probe     │ ───────────▶ └───────────────────────────────────────────────────┘
│ (other machine or  │ ──── direct alert when the whole server is down ──▶ Telegram / SMTP
│  GitHub Actions)   │
└────────────────────┘
```

Pipeline: agent → ingestion (authentication, validation, dedup) → normalization (on the
agent: parsing, privacy filters) → storage → detection engine → dashboard and notifications.

## Guides

| Guide | Contents |
|---|---|
| [collector.md](collector.md) | Installing and configuring the agent on a VPS, log formats, permissions, privacy |
| [configuration.md](configuration.md) | `configs/live.yaml`, environment variables and secrets |
| [deployment.md](../deployment.md#live-monitoring) | Compose profile, TLS, private ingestion, backups and recovery |
| [incidents.md](incidents.md) | Every rule, its threshold, default severity and blind spots; incident lifecycle |
| [notifications.md](notifications.md) | Telegram and SMTP setup, deduplication, cooldowns, retries, testing |
| [probe.md](probe.md) | External availability checks that work when the server is down |
| [ml.md](ml.md) | Behavioural model: features, training, thresholds, false-alert measurement |
| [ai-investigation.md](ai-investigation.md) | Optional local LLM summaries and their safety controls |
| [troubleshooting.md](troubleshooting.md) | Incident and data-flow troubleshooting |
| [resources.md](resources.md) | Measured memory, image sizes and minimum requirements |

## Five-minute local trial (simulated data only)

```bash
export TG_LIVE_DB=data/live/live.db
.venv/bin/threatgraph-live agent add web1            # prints a token once
.venv/bin/threatgraph-live simulate ssh_bruteforce   # SIMULATED events, labeled as such
.venv/bin/threatgraph-live worker --once             # detection + incidents
```

Simulated events use documentation-only addresses (RFC 5737), are flagged `simulated` in
storage, are hidden unless "Show simulated test data" is ticked, and their notifications are
suppressed. See [deployment](../deployment.md#live-monitoring) for the real setup.

## What is verified and what is not

Verified by automated tests: parsing (including malformed and hostile lines), agent rotation,
reconnection and deduplication, ingestion authentication and limits, every detection rule on
simulated scenarios, no incident on benign simulated traffic, deduplication and cooldowns,
notification retries against local Telegram and SMTP stand-ins, LLM prompt-injection
handling, dashboard authentication and authorization.

Verified by hand on a development machine (colima, 2 CPU, 2 GB): the Compose stack behind
TLS; a real nginx container's access and error logs shipped by the real agent through
authenticated TLS ingestion; agent restart without duplicates; the dashboard in a browser on
desktop and mobile widths; backup and restore.

**Not yet verified**: a deployment on your VPS, real SSH logs from your server, delivery to
your real Telegram chat or mailbox (run `threatgraph-live notify-test` once configured), the
GitHub Actions probe template, and Ollama with a real model. Thresholds are starting values;
tune them against your own traffic (see [incidents.md](incidents.md#tuning)).
