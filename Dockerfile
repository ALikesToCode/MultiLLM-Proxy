FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt

RUN pip install --upgrade pip && \
    pip install -r requirements.txt

COPY . .
COPY --chmod=755 scripts/cloudflare-entrypoint.sh /usr/local/bin/cloudflare-entrypoint.sh

# Cloudflare Containers run as a non-root user, so app sources must be
# world-readable and the Flask instance directory must be writable.
RUN mkdir -p /app/instance && \
    chmod -R a+rX /app && \
    chmod 1777 /app/instance

EXPOSE 8080

CMD ["/usr/local/bin/cloudflare-entrypoint.sh"]
