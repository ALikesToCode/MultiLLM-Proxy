#!/bin/sh
set -eu

export HOME=/tmp

if [ -n "${GOOGLE_APPLICATION_CREDENTIALS_JSON:-}" ]; then
  credentials_path="/tmp/google-credentials.json"
  printf '%s' "$GOOGLE_APPLICATION_CREDENTIALS_JSON" > "$credentials_path"
  export GOOGLE_APPLICATION_CREDENTIALS="$credentials_path"
fi

exec python /app/app.py
