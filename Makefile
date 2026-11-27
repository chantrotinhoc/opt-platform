.PHONY: test test-db up down smoke
export PYTHONPATH := apps/api:apps/agent

DEV_APP_URL ?= postgresql://opt_app:opt_app_dev@localhost:5432/opt
DEV_ADMIN_URL ?= postgresql://postgres:dev@localhost:5432/opt

# Unit tests, no services needed. Database tests are skipped.
test:
	python -m pytest -q apps tests

# Unit + database tests. Needs `make up` (or any migrated, seeded PostgreSQL).
test-db:
	OPT_DATABASE_URL=$(DEV_APP_URL) OPT_ADMIN_DATABASE_URL=$(DEV_ADMIN_URL) python -m pytest -q apps tests

up:
	docker compose -f docker-compose.dev.yml up -d --build --wait

down:
	docker compose -f docker-compose.dev.yml down -v

smoke:
	./scripts/smoke.sh
