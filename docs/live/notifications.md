# Notifications (Telegram and e-mail)

The worker queues a notification for each configured channel when an incident at or above
`notifications.min_severity` (default `medium`) is created, escalates, gets new evidence after
the cooldown, or recovers. Delivery runs from a persistent outbox, so nothing is lost when a
channel is briefly down.

## Telegram

1. Talk to `@BotFather`, create a bot, copy its token.
2. Send any message to your bot, then open
   `https://api.telegram.org/bot<TOKEN>/getUpdates` and read `message.chat.id`.
3. In `.env.live`: `TG_TELEGRAM_BOT_TOKEN=...` and `TG_TELEGRAM_CHAT_ID=...`

The token never appears in stored errors or logs (errors keep only the HTTP status).

## E-mail (SMTP)

In `.env.live`:

```
TG_SMTP_HOST=smtp.example.com
TG_SMTP_PORT=587
TG_SMTP_SECURITY=starttls        # or ssl (465); none only for a relay on localhost
TG_SMTP_USER=...
TG_SMTP_PASSWORD=...             # or TG_SMTP_PASSWORD_FILE=/run/secrets/smtp
TG_SMTP_FROM=threatgraph@example.com
TG_SMTP_TO=you@example.com       # comma-separated for several recipients
```

Use an app password or a dedicated sending account, never your main mailbox password.

## Test the channels

```bash
docker compose --profile live exec live-worker threatgraph-live notify-test
```

This sends a message labeled as a test that is not based on any event. The automated test
suite never contacts real recipients; `TG_NOTIFY_LIVE_TEST=1 pytest -k real_channels`
opts in to one real delivery.

## Message format

```
ThreatGraph AI Security Alert

Severity: HIGH
Service: Production Website (web1)
Detection: Sensitive-looking path served successfully
Time: 2026-11-12 00:26:58 UTC
Detector: rule / http_recon

Evidence:
- 28 requests from 198.51.100.23 within 5 min
- 6 requests for sensitive-looking paths (threshold 3), e.g. /.aws/credentials, /.env
- Returned 2xx for: /.env

Assessment:
Pattern typical of hostile activity. No confirmed compromise.
Confidence: High that the requests occurred; intent is inferred from the paths requested.
Limitations: Automated scanners probe every public site; ...

Recommended action:
Check immediately whether the file is publicly readable ...

Incident ID: TG-000004
```

Every line is filled from the stored incident, which is built from real events. Messages for
simulated incidents carry a `[SIMULATED TEST: not real telemetry]` banner, and are suppressed
(stored, not delivered) unless test delivery is explicitly enabled in code.

## Avoiding alert floods

- **Deduplication**: one open incident per rule, host, service and entity. Ten overlapping
  detection runs over the same brute force create one incident and one alert.
- **Cooldown**: while an incident stays open, a reminder is sent at most once per
  `cooldown_seconds` (default 1 hour), and only if new evidence arrived.
- **Escalation**: a severity increase notifies again immediately.
- **Threshold**: `low` and `info` incidents appear in the dashboard only.
- **Recovery**: condition incidents (outages, full disks, offline agents) send one recovery
  message when they clear.

## Retries and delivery status

Failed deliveries retry after `retry_base_seconds × 2^(attempt-1)` (capped at
`retry_max_seconds`), up to `max_attempts`, then the row is marked `failed` with the last
error. The incident view in the dashboard shows each notification's channel, kind, status,
attempts and last error. A channel that is not configured is marked `failed` with
"channel not configured", so a missing secret is visible rather than silent.

If the ThreatGraph server itself is down, it cannot notify anyone: use the
[external probe](probe.md), which alerts directly.
