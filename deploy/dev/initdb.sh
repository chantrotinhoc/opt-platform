#!/bin/sh
# Runs once when the dev PostgreSQL volume is first created:
# schema migrations in order, then dev-only login + seed data.
set -eu
for f in /opt/opt-sql/migrations/*.sql /opt/opt-sql/dev/*.sql; do
  echo "applying $f"
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -f "$f"
done
