FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.lock ./requirements.lock

RUN pip install --upgrade pip && \
    pip install -r requirements.lock

COPY . .
COPY --chmod=755 scripts/cloudflare-entrypoint.sh /usr/local/bin/cloudflare-entrypoint.sh

RUN addgroup --system multillm && \
    adduser --system --ingroup multillm --home /tmp --no-create-home multillm && \
    mkdir -p /app/instance /tmp/multillm && \
    chown -R multillm:multillm /app/instance /tmp/multillm && \
    chmod -R a+rX /app && \
    chmod 0750 /app/instance /tmp/multillm

USER multillm

EXPOSE 8080

CMD ["/usr/local/bin/cloudflare-entrypoint.sh"]
