FROM ghcr.io/astral-sh/uv:latest AS uv

FROM python:3.14-slim AS builder

COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.14-slim AS runtime

RUN useradd --create-home --uid 10001 wheelguard \
    && mkdir --parents /data \
    && chown wheelguard:wheelguard /data

WORKDIR /app
COPY --from=builder --chown=wheelguard:wheelguard /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WHEELGUARD_DATA_DIR=/data \
    WHEELGUARD_HOST=0.0.0.0 \
    WHEELGUARD_PORT=8000

USER wheelguard
EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"]

CMD ["wheelguard"]
