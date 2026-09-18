#!/bin/bash
# Runs once on first init of the centinela-postgres volume (docker-entrypoint-initdb.d).
# A .sh hook (unlike a .sql one) sees the container env, so the SonarQube role password
# comes from SONARQUBE_DB_PASSWORD (set in .env, passed via docker-compose.override.yml)
# -- never hard-coded in a tracked file.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE ROLE ${SONARQUBE_DB_USER:-centinela_sonarqube_user} LOGIN PASSWORD '${SONARQUBE_DB_PASSWORD:?SONARQUBE_DB_PASSWORD not set}';
    CREATE DATABASE centinela_sonarqube_db OWNER ${SONARQUBE_DB_USER:-centinela_sonarqube_user};
EOSQL
