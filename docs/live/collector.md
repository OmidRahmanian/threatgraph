# Collector agent setup (VPS)

The agent is a single Python program that uses only the standard library (a test enforces
this), so it needs Python 3.11+ and nothing else. It reads logs and system state, never
writes outside its state directory, and runs as an unprivileged user.

## Install

On the monitored server, from a checkout of this repository (review the script first):

```bash
sudo bash deploy/agent/install.sh "$PWD"
```

It creates the `tg-agent` user, `/opt/threatgraph-agent/venv` (`pip install --no-deps`),
`/etc/threatgraph-agent/{agent.toml,token}` and the systemd unit. It does **not** start the
agent.

On the ThreatGraph server, register the host and copy the printed token (shown once; only its
SHA-256 is stored):

```bash
docker compose --profile live exec live-worker threatgraph-live agent add web1
```

Put the token in `/etc/threatgraph-agent/token` (mode 0640, group `tg-agent`), edit
`/etc/threatgraph-agent/agent.toml` ([example](../../deploy/agent/agent.example.toml)), then
check what would be sent without sending anything:

```bash
sudo -u tg-agent /opt/threatgraph-agent/venv/bin/python -m threatgraph.live.agent \
  --config /etc/threatgraph-agent/agent.toml --dry-run --once
sudo systemctl enable --now threatgraph-agent
journalctl -u threatgraph-agent -f
```

Token rotation: `threatgraph-live agent rotate web1`; revocation: `threatgraph-live agent
disable web1`.

## Collectors

Each is optional; disable what the server does not run. A missing source is reported in the
agent's heartbeat (dashboard: Monitoring agents), never treated as zero activity.

| Collector | Source | Events |
|---|---|---|
| `nginx_access` | access log, `combined` or `timed` format | `http.access` |
| `nginx_error` | error log | `http.error` (category, worker crashes) |
| `auth` | `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL) | `ssh.auth`, `ssh.probe`, `admin.sudo`, `admin.su`, `admin.account` |
| `syslog` | `/var/log/syslog` or `/var/log/messages` | `system.kernel` (OOM, segfault), `system.service` (unit failures) |
| `metrics` | `/proc`, `statvfs` | `system.metrics` (CPU, memory, swap, load, disks, uptime) |
| `systemd` | `systemctl list-units --state=failed` (read-only) | `system.service` on state changes |
| `docker` | Docker API `GET /containers/json` | `container.health` on state changes |
| `fim` | SHA-256 of configured files | `fim.change` (modified, added, removed) |

Response times need the `timed` nginx format (the parser also accepts plain `combined`):

```nginx
log_format timed '$remote_addr - $remote_user [$time_local] "$request" $status '
                 '$body_bytes_sent "$http_referer" "$http_user_agent" $request_time $upstream_response_time';
access_log /var/log/nginx/access.log timed;
```

Servers that log only to journald: enable a file sink (`rsyslog`) or point the `auth` and
`syslog` collectors at files written by `journalctl -f -o short-iso >> file` under a
dedicated unit. Direct journald reading is not implemented.

## Permissions

- Logs: membership of `adm` (Debian/Ubuntu) reads nginx, auth and syslog files. On RHEL use
  ACLs: `setfacl -m u:tg-agent:r /var/log/secure` (and in the logrotate `postrotate`).
- Docker: socket access is equivalent to root. Prefer a read-only socket proxy that allows
  only `GET /containers` (for example `tecnativa/docker-socket-proxy` with `CONTAINERS=1`)
  and set `socket` to it. Leave `docker` disabled otherwise.
- The unit applies `ProtectSystem=strict`, an empty capability set, `NoNewPrivileges`,
  `MemoryMax=128M` and `CPUQuota=20%`. No kernel modules, no security-policy changes.

## Delivery guarantees

- **Rotation**: rename (logrotate default) and `copytruncate` are handled; a rotated file is
  drained before the new one is read, including rotations that happen while the agent is
  stopped (it finishes `<log>.1`). Compressed rotations (`.1.gz`) are not read: if the agent is
  down across two rotations, lines in between are lost and the gap is visible.
- **At least once, stored once**: positions are committed only after the server acknowledges
  a batch; event ids derive from file identity, offset and line hash, so re-sent lines are
  ignored by the server.
- **Bounded memory and backpressure**: at most `buffer_max_events` are held. When full, logs
  are not read further (lines wait in the file) and periodic samples are dropped and counted
  (`dropped_samples`). HTTP 429/503 and network errors back off exponentially with jitter
  (1 s to 5 min, honouring `Retry-After`).
- **Clock**: events carry the time written in the log. Lines without a time zone (traditional
  syslog, nginx `error.log`) use `log_timezone`. The server rejects times more than 5 minutes
  in the future.

## Privacy controls

Applied on the host, before anything is sent:

- query strings dropped (`keep_query = true` keeps them with secret-looking values redacted);
- secrets redacted in every message (passwords, tokens, API keys, bearer/basic credentials,
  JWTs, private keys, AWS keys, credentials in URLs);
- control characters and terminal escape sequences removed; fields length-capped;
- client IPs kept, truncated to /24 or /48 (`ip_mode = "truncate"`), or replaced by a keyed
  hash (`ip_mode = "hash"` with a secret `ip_hash_key_file`) that still correlates repeats;
- unparsed lines are counted, never shipped.

`sudo` command lines are kept (redacted) because they are the evidence for administrative
activity; set the rule off and remove the `auth` collector if that is not acceptable.

## Transport security

`https://` is required. Plain HTTP is accepted only for a loopback server with
`allow_insecure_http = true` (local testing). Prefer a private network (WireGuard or
Tailscale) and bind ingestion to it (`TG_INGEST_BIND`); with Caddy's internal CA, copy
`/data/caddy/pki/authorities/local/root.crt` from the Caddy container to the agent and set
`ca_file`.
