# Live Monitoring services (ingestion API, dashboard API, worker): one image, three commands.
# Code and configs only; the SQLite database lives on the mounted /data volume.
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY packages ./packages
COPY apps/api ./apps/api
COPY apps/live ./apps/live
RUN pip install --no-cache-dir . && useradd --create-home --uid 10001 tg && mkdir /data && chown tg /data
COPY configs ./configs
USER tg
ENV TG_REPO_ROOT=/app TG_LIVE_DB=/data/live.db TG_LIVE_CONFIG=/app/configs/live.yaml PYTHONUNBUFFERED=1
VOLUME ["/data"]
CMD ["threatgraph-live", "worker"]
