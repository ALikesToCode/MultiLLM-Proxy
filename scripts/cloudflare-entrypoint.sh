#!/bin/sh
set -eu

export HOME=/tmp

if [ -n "${GOOGLE_APPLICATION_CREDENTIALS_JSON:-}" ]; then
  credentials_path="/tmp/google-credentials.json"
  printf '%s' "$GOOGLE_APPLICATION_CREDENTIALS_JSON" > "$credentials_path"
  export GOOGLE_APPLICATION_CREDENTIALS="$credentials_path"
fi

bind_port="${PORT:-${SERVER_PORT:-8080}}"

exec gunicorn "app:create_app()" \
  --bind "0.0.0.0:${bind_port}" \
  --workers "${GUNICORN_WORKERS:-2}" \
  --threads "${GUNICORN_THREADS:-8}" \
  --timeout "${GUNICORN_TIMEOUT:-120}" \
  --graceful-timeout "${GUNICORN_GRACEFUL_TIMEOUT:-30}" \
  --access-logfile - \
  --error-logfile -
