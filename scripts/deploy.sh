#!/usr/bin/env bash
# Manual deploy in dependency order: D1 schema, then the Knowledge Worker, then the main Worker.
# The main Worker and its Container read tables the migrations create and call the Knowledge
# Worker, so each runs only after the step before it succeeded. .github/workflows/deploy.yml
# runs the same order after ci passes on main. Extra arguments go to the final
# `wrangler deploy`. A clean checkout tags both Worker versions with its commit.
set -euo pipefail
cd "$(dirname "$0")/.."

DATABASE="${D1_DATABASE:?Set D1_DATABASE explicitly to the configured target database}"
MAIN_CONFIG="${MAIN_WORKER_CONFIG:-wrangler.jsonc}"
KNOWLEDGE_CONFIG="${KNOWLEDGE_WORKER_CONFIG:-wrangler.knowledge.jsonc}"
export MAIN_WORKER_CONFIG="$MAIN_CONFIG" KNOWLEDGE_WORKER_CONFIG="$KNOWLEDGE_CONFIG"
# Validate target identity before any migration, upload or remote read.
node --input-type=module -e 'import { deploymentTarget } from "./scripts/deployment_target.mjs"; deploymentTarget({ mainConfig: process.env.MAIN_WORKER_CONFIG, knowledgeConfig: process.env.KNOWLEDGE_WORKER_CONFIG });'
state="$(mktemp)"
release_config="$(mktemp .release-wrangler-XXXXXX.jsonc)"
trap 'rm -f -- "$state" "$release_config"' EXIT
node scripts/container_rollout.mjs --prepare --state "$state" --output "$release_config" --config "$MAIN_CONFIG" --knowledge-config "$KNOWLEDGE_CONFIG"
annotations=()
if commit="$(git rev-parse HEAD 2>/dev/null)"; then
  # The deploy build rewrites worker/build-id.mjs, which is not a source change.
  if [ -z "$(git status --porcelain --untracked-files=no -- . ':(exclude)worker/build-id.mjs')" ]; then
    annotations=(--tag "$commit" --message "Manual deploy of $commit")
  else
    annotations=(--message "Manual deploy from $commit with uncommitted changes")
  fi
fi

node scripts/verify_d1_migrations.mjs --check
npx --no-install wrangler d1 migrations apply "$DATABASE" --remote --config "$MAIN_CONFIG"
node scripts/verify_d1_migrations.mjs "$DATABASE"
npx --no-install wrangler deploy --config "$KNOWLEDGE_CONFIG" ${annotations[@]+"${annotations[@]}"}
npx --no-install wrangler deploy --config "$release_config" ${annotations[@]+"${annotations[@]}"} "$@"
node scripts/container_rollout.mjs --verify --state "$state" --config "$MAIN_CONFIG" --knowledge-config "$KNOWLEDGE_CONFIG"
