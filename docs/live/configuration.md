# Live monitoring configuration

Two kinds of settings, kept apart on purpose:

- **Behaviour** (thresholds, retention, probes, model, LLM): `configs/live.yaml`, in git.
  Override the path with `TG_LIVE_CONFIG`.
- **Secrets** (tokens, passwords, bot credentials): environment variables only, never in YAML
  or git. Every secret also accepts `NAME_FILE=/path` (Docker or systemd secrets). Put
  Compose variables in `.env` and service secrets in `.env.live`; both are git-ignored.

## Environment

| Variable | Used by | Purpose |
|---|---|---|
| `TG_LIVE_DB` | all live services | SQLite path (container: `/data/live.db`) |
| `TG_LIVE_CONFIG` | all live services | alternative `live.yaml` |
| `TG_LIVE_ADMIN_USER` | dashboard | sign-in name (default `admin`) |
| `TG_LIVE_ADMIN_PASSWORD_HASH` | dashboard | scrypt hash from `threatgraph-live hash-password`; without it, sign-in is disabled |
| `TG_LIVE_SESSION_HOURS` | dashboard | session lifetime (default 12) |
| `TG_LIVE_COOKIE_SECURE` | dashboard | `true` behind HTTPS (default) |
| `TG_LIVE_LOGIN_ATTEMPTS` | dashboard | failed sign-ins per address per 15 minutes (default 10) |
| `TG_TELEGRAM_BOT_TOKEN`, `TG_TELEGRAM_CHAT_ID` | worker, probe | Telegram channel |
| `TG_SMTP_HOST`, `TG_SMTP_PORT`, `TG_SMTP_SECURITY`, `TG_SMTP_USER`, `TG_SMTP_PASSWORD`, `TG_SMTP_FROM`, `TG_SMTP_TO` | worker, probe | e-mail channel (`starttls`, `ssl`, or `none` for a local relay) |
| `TG_DOMAIN` | Caddy | public host name (automatic HTTPS) |
| `TG_INGEST_ADDRESS`, `TG_INGEST_BIND` | Caddy | ingestion site address and the host interface for port 8443 |
| `TG_AGENT_TOKEN`, `TG_AGENT_IP_HASH_KEY` | agent | override the token and hash-key files |
| `TG_PROBE_TOKEN` | probe | credential for reporting to ingestion (probe role) |
| `NEXT_PUBLIC_TG_LIVE_API_BASE` | web build | `/live-api/v1` to enable `/threatgraph/live`; unset in the public demo |
| `TG_NOTIFY_LIVE_TEST` | pytest | `1` lets one test send a real message (opt-in) |

## `configs/live.yaml`

| Section | Keys |
|---|---|
| `retention` | `event_days` (30), `metrics_days` (14), `incident_days` (365, resolved only), `notification_days` (90). Events linked to a stored incident are kept as evidence. |
| `ingest` | batch, body and decompressed-size caps, per-agent event rate, accepted clock skew |
| `services` | display names used in notifications (`website: Production Website`) |
| `detection` | run interval, lookback, agent offline threshold, `allowlist_sources` (addresses or CIDR ranges never alerted on by web/SSH rules, e.g. your uptime checker), `sensitive_paths`, and one entry per rule (`severity`, `params`, `enabled`) |
| `notifications` | `min_severity` (medium), `cooldown_seconds` (3600), retry settings, recovery messages, `dashboard_url` |
| `probes` | on-server availability checks (`targets`), run by the worker |
| `ml` | behavioural model: bucket size, training/validation days, alert budget, retrain interval, seed |
| `llm` | optional Ollama investigation: `enabled` (false), URL, model, timeout, evidence cap |

Rules and their parameters: [incidents.md](incidents.md).
