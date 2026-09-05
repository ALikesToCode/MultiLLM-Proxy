FROM python:3.11-slim@sha256:1042b61448fef4ba92d16a8c7eb4996d027568ce64792a7877fd88511e0af7c6

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.lock ./requirements.lock

RUN pip install --disable-pip-version-check --require-hashes -r requirements.lock

COPY . .
RUN python scripts/build_release_metadata.py
COPY --chmod=755 scripts/cloudflare-entrypoint.sh /usr/local/bin/cloudflare-entrypoint.sh

RUN addgroup --system multillm && \
    adduser --system --ingroup multillm --home /tmp --no-create-home multillm && \
    mkdir -p /app/instance /tmp/multillm && \
    chown -R multillm:multillm /app/instance /tmp/multillm && \
    chmod -R a+rX /app && \
    chmod 0750 /app/instance /tmp/multillm

USER multillm

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import os, urllib.request; port = int(os.getenv('PORT') or os.getenv('SERVER_PORT') or '8080'); urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=3).close()"

CMD ["/usr/local/bin/cloudflare-entrypoint.sh"]
