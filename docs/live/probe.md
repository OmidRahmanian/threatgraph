# External availability checks

A collector on the monitored server cannot report that the server is down, and if ThreatGraph
runs on the same VPS, its worker goes down too. Outage detection therefore has three layers:

| Layer | Where it runs | Detects | Alerts through |
|---|---|---|---|
| On-server probes (`probes.targets` in `live.yaml`) | the worker | website down while the VPS is up (nginx stopped, app crashed, TLS broken) | ThreatGraph incidents and notifications |
| `agent_offline` rule | the worker | a monitored host that stopped sending data | ThreatGraph incidents |
| **External probe** | another machine, or GitHub Actions | everything above, plus the whole VPS (and ThreatGraph) being down | **direct** Telegram/SMTP, independent of ThreatGraph |

## Run the external probe on another machine

Standard library only (Python 3.11+):

```bash
pip install --no-deps git+https://github.com/OmidRahmanian/threatgraph   # or a checkout
cp deploy/external-probe/probe.example.toml probe.toml                   # set your URLs
export TG_TELEGRAM_BOT_TOKEN=... TG_TELEGRAM_CHAT_ID=...
python -m threatgraph.live.probe --config probe.toml          # loop
python -m threatgraph.live.probe --config probe.toml --once   # cron
```

Each check records status, latency, an optional expected text and the certificate's remaining
days. After `consecutive_failures` failed checks it sends **one** alert, and one recovery
message when the site answers again; its state file survives restarts.

Optionally also report results to ThreatGraph (dashboard availability charts, the
`availability` rule, checks from several locations): register a probe-only credential
(`threatgraph-live agent add probe-home --role probe`, which may send only probe results)
and set `report_url`, `report_token_file`. Reports that cannot be delivered are kept (up to
500) and sent later.

## GitHub Actions (backstop)

`deploy/external-probe/github-actions-uptime.yml` is a ready workflow that is **not active**.
Copy it to `.github/workflows/` of a repository you control and set the secrets it lists. It
runs every 5 minutes at best (GitHub may delay scheduled runs), keeps its state in the Actions
cache, and alerts directly. A probe on a second machine reacts faster.
