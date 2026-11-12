#!/usr/bin/env bash
# Install the ThreatGraph collector agent on a Linux server (run as root, review first).
# It creates an unprivileged user, a virtualenv with the agent (standard library only, no
# third-party packages), the config directory and the systemd unit. It does NOT start the
# agent: edit /etc/threatgraph-agent/agent.toml and the token file first.
#
#   sudo bash deploy/agent/install.sh /path/to/threatgraph-checkout
set -euo pipefail
SRC="${1:?usage: install.sh /path/to/threatgraph-checkout}"
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 (>= 3.11) is required" >&2; exit 1; }
python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' || { echo "python3 >= 3.11 required" >&2; exit 1; }

id tg-agent >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin tg-agent
install -d -m 0755 /opt/threatgraph-agent
python3 -m venv /opt/threatgraph-agent/venv
# --no-deps: the agent, probe and parsers use only the standard library.
/opt/threatgraph-agent/venv/bin/pip install --quiet --no-deps "$SRC"
install -d -m 0750 -o root -g tg-agent /etc/threatgraph-agent
if [ ! -f /etc/threatgraph-agent/agent.toml ]; then
  install -m 0640 -o root -g tg-agent "$SRC/deploy/agent/agent.example.toml" /etc/threatgraph-agent/agent.toml
fi
if [ ! -f /etc/threatgraph-agent/token ]; then
  install -m 0640 -o root -g tg-agent /dev/null /etc/threatgraph-agent/token
fi
install -m 0644 "$SRC/deploy/agent/threatgraph-agent.service" /etc/systemd/system/threatgraph-agent.service
systemctl daemon-reload
cat <<MSG
Installed. Next:
  1. On the ThreatGraph server: threatgraph-live agent add $(hostname -s)   (prints a token once)
  2. Put the token in /etc/threatgraph-agent/token
  3. Edit /etc/threatgraph-agent/agent.toml (source_id, server_url, logs to read)
  4. Dry run (prints events, sends nothing):
       sudo -u tg-agent /opt/threatgraph-agent/venv/bin/python -m threatgraph.live.agent \\
         --config /etc/threatgraph-agent/agent.toml --dry-run --once
  5. systemctl enable --now threatgraph-agent && journalctl -u threatgraph-agent -f
MSG
