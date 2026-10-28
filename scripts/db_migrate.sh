#!/usr/bin/env bash
# Schema migrations (ADR-0008 #5). usage: scripts/db_migrate.sh <alembic args>   e.g. current | upgrade head | revision -m "add x"
# Runs inside centinela-backend against the production database configured in .env. `upgrade` changes the real schema: review the revision first.
set -euo pipefail
cd "$(dirname "$0")/.."
docker exec -w /app centinela-backend python -m alembic "$@"
