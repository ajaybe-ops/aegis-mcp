# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
# Non-editable install into an isolated prefix so the runtime stage can copy
# exactly one directory (package + all runtime dependencies).
RUN pip install --prefix=/install .

FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN useradd --create-home --uid 10001 aegis \
    && mkdir -p /data \
    && chown -R aegis:aegis /data

COPY --from=builder /install /usr/local

WORKDIR /app
USER aegis

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3).status == 200 else 1)"

CMD ["aegis-mcp", "serve", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8000"]
