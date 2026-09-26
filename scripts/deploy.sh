#!/usr/bin/env bash
# Manual deploy in dependency order: D1 schema, then the Knowledge Worker, then the main Worker.
# The main Worker and its Container read tables the migrations create and call the Knowledge
# Worker, so each runs only after the step before it succeeded. .github/workflows/deploy.yml
# runs the same order after ci passes on main. Extra arguments go to the final
# `wrangler deploy`. A clean checkout tags both Worker versions with its commit.
set -euo pipefail
cd "$(dirname "$0")/.."

DATABASE="${D1_DATABASE:-multillm-intelligence}"
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
npx --no-install wrangler d1 migrations apply "$DATABASE" --remote
node scripts/verify_d1_migrations.mjs "$DATABASE"
npx --no-install wrangler deploy --config wrangler.knowledge.jsonc ${annotations[@]+"${annotations[@]}"}
npx --no-install wrangler deploy ${annotations[@]+"${annotations[@]}"} "$@"
