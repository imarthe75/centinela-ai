#!/usr/bin/env bash
# Runs the test suite against a disposable PostgreSQL (container centinela-test-db), never against production.
# usage: scripts/run_tests.sh [pytest args...]      e.g. scripts/run_tests.sh tests/test_mr_review.py -q
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose --profile test up -d centinela-test-db >/dev/null
# The image first runs a temporary init server (socket only) and then restarts; only the final server listens on TCP.
ready=0
for i in $(seq 1 60); do
  if docker exec centinela-test-db pg_isready -h 127.0.0.1 -U centinela_test -d centinela_test >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[ "$ready" = "1" ] || { echo "[tests] centinela-test-db did not become ready" >&2; exit 1; }
# Build the schema with the real migrations (baseline = production schema, then every later revision) when the database is empty
# (it is wiped on every container stop). This also tests the migrations themselves.
tables=$(docker exec centinela-test-db psql -U centinela_test -d centinela_test -tAc "select count(*) from information_schema.tables where table_schema='public'")
# `upgrade head` is idempotent: it builds an empty database and applies the revisions added since a previous run left the test database behind.
docker exec -e DB_HOST=centinela-test-db -e DB_NAME=centinela_test -e DB_USER=centinela_test -e DB_PASSWORD=centinela_test_only \
  -w /app centinela-backend python -m alembic upgrade head >/dev/null
[ "$tables" = "0" ] && echo "[tests] schema built by alembic upgrade head"
# Default arguments as an array. ("${@:-tests/ -q}" expanded to ONE argument, "tests/ -q", and pytest ran no test.)
if [ "$#" -eq 0 ]; then set -- tests/ -q; fi
docker exec \
  -e DB_HOST=centinela-test-db -e DB_NAME=centinela_test -e DB_USER=centinela_test -e DB_PASSWORD=centinela_test_only \
  -e CENTINELA_TEST_RUN=1 \
  centinela-backend python -m pytest "$@"
