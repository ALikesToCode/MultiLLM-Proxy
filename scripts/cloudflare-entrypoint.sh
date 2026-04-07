#!/bin/sh
set -eu

if [ -n "${GOOGLE_APPLICATION_CREDENTIALS_JSON:-}" ]; then
  credentials_path="/tmp/google-credentials.json"
  printf '%s' "$GOOGLE_APPLICATION_CREDENTIALS_JSON" > "$credentials_path"
  export GOOGLE_APPLICATION_CREDENTIALS="$credentials_path"
fi

if [ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ] && [ -f "${GOOGLE_APPLICATION_CREDENTIALS}" ]; then
  gcloud auth activate-service-account --key-file="${GOOGLE_APPLICATION_CREDENTIALS}" --quiet >/dev/null

  if [ -n "${PROJECT_ID:-}" ]; then
    gcloud config set project "${PROJECT_ID}" >/dev/null
  fi
fi

exec gunicorn \
  --bind "0.0.0.0:${SERVER_PORT:-8080}" \
  --worker-class gthread \
  --workers "${GUNICORN_WORKERS:-1}" \
  --threads "${GUNICORN_THREADS:-8}" \
  --timeout "${GUNICORN_TIMEOUT:-0}" \
  --access-logfile - \
  --error-logfile - \
  wsgi:app
