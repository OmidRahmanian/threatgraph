# Troubleshooting live monitoring

Start at the dashboard's **Monitoring agents** table and **Detection worker** tile: most
problems show there.

## No data in the dashboard

| Symptom | Check |
|---|---|
| Agent "Never connected" | Agent logs: `journalctl -u threatgraph-agent -n 50`. `401` = wrong token (re-issue with `threatgraph-live agent rotate`); TLS error = set `ca_file`; connection refused = `TG_INGEST_BIND`/firewall/WireGuard. |
| Agent "Offline" | Host or agent stopped, or the network between them. Its last error is in the table. An `agent_offline` incident opens after 5 minutes. |
| Agent online, log "not readable" | Permissions: add `tg-agent` to `adm`, or set ACLs (see [collector.md](collector.md#permissions)). |
| Many "unrecognised" lines | Log format differs: nginx needs `combined` or the `timed` format; auth logs need syslog or RFC 3339 timestamps. Run the agent with `--dry-run --once` to see what is parsed. |
| Charts show gaps | Intended: no agent was reporting during those intervals. Gaps are never filled with zeros. |
| Everything empty but simulated data exists | Tick "Show simulated test data"; simulated and real data are never shown together. |
| Times look shifted | Set `log_timezone` in `agent.toml` to the server's zone for logs without a zone. |

## Incidents

| Question | Answer |
|---|---|
| Why no incident for an obvious attack? | Compare with the rule's threshold in [incidents.md](incidents.md). Check `allowlist_sources`. Check the worker tile for errors. Events older than the detection lookback (15 min, or the rule's window) when they arrive are stored but not evaluated by event rules. |
| Too many incidents | Raise thresholds or narrow `sensitive_paths`; add your own monitoring to the allowlist. Low and info incidents never notify. |
| Incident reappeared after resolving | New activity after the resolution, or a condition rule whose condition still holds (an outage you resolved by hand while the site is still down). |
| "Website unavailable" but the site works | Look at "Checked from": a single location can fail on its own. Add a second probe location. |

## Notifications

| Symptom | Check |
|---|---|
| Nothing arrives | The incident's notification list: `failed: channel not configured` = missing secrets in `.env.live`; no rows = severity below `min_severity` or a simulated incident. Run `threatgraph-live notify-test`. |
| `telegram HTTP 400/403` | Wrong chat id, or you never messaged the bot. |
| `smtp: SMTPAuthenticationError` | Use an app password; check `TG_SMTP_SECURITY` and port. |
| Alerts repeat | Only reminders after `cooldown_seconds` with new evidence, escalations and recoveries are sent; check the notification kinds in the incident. |
| Server down and no alert | Expected without an external probe: ThreatGraph cannot alert about its own host. See [probe.md](probe.md). |

## Services

```bash
docker compose --profile live ps                      # health of every container
docker compose --profile live logs --tail 100 live-worker
docker compose --profile live exec live-worker threatgraph-live health
docker compose --profile live exec live-worker threatgraph-live worker --once
```

After rebuilding the website (`npm run build`), restart Caddy
(`docker compose --profile live restart caddy`): the build replaces `apps/web/out`, and a
running container keeps serving the old directory.
