#!/usr/bin/env bash
# Deploy in dependency order: D1 schema, then the Knowledge Worker, then the main Worker.
# The main Worker and its Container read tables the migrations create, so they are deployed
# only after every migration is applied and verified. Extra arguments go to the final
# `wrangler deploy`. Workers Builds must run this script, not a bare `wrangler deploy`.
set -euo pipefail
cd "$(dirname "$0")/.."

DATABASE="${D1_DATABASE:-multillm-intelligence}"

npx --no-install wrangler d1 migrations apply "$DATABASE" --remote
node scripts/verify_d1_migrations.mjs "$DATABASE"
npx --no-install wrangler deploy --config wrangler.knowledge.jsonc
npx --no-install wrangler deploy "$@"
