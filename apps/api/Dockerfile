# Read-only API image. Contains code only: datasets and artifacts are mounted at runtime
# (see docker-compose.yml), so raw or processed data never ends up in an image layer.
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY packages ./packages
COPY apps/api ./apps/api
RUN pip install --no-cache-dir . && useradd --create-home tg
COPY configs ./configs
USER tg
ENV TG_DATASET=demo TG_REPO_ROOT=/app
EXPOSE 8000
CMD ["uvicorn", "threatgraph_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
