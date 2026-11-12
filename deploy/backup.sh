#!/usr/bin/env bash
# Online backup of the live database (consistent while services run), keeping 14 days.
# Run from the repository on the server, e.g. daily from cron:
#   15 3 * * * cd /opt/threatgraph && ./deploy/backup.sh >> /var/log/threatgraph-backup.log 2>&1
# Restore: docs/live/deployment.md#backup-and-recovery
set -euo pipefail
KEEP_DAYS="${KEEP_DAYS:-14}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p backups
docker-compose --profile live exec -T live-worker threatgraph-live backup "/backups/live-$STAMP.db"
gzip "backups/live-$STAMP.db"
find backups -name 'live-*.db.gz' -mtime +"$KEEP_DAYS" -delete
echo "backup ok: backups/live-$STAMP.db.gz"
