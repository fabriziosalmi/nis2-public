.PHONY: dev dev-up dev-down dev-logs api-logs web-logs db-migrate db-upgrade db-seed test test-api test-scanner lint clean clean-all prod prod-up prod-down

# Development
dev: dev-up
	@echo ""
	@echo "  NIS2 Platform: http://localhost:8077"
	@echo "  API docs:      http://localhost:8000/docs"
	@echo "  API health:    http://localhost:8000/api/v1/health"
	@echo ""

# `--wait` (compose v2.20+) blocks until every service is either
# `running` or, where a healthcheck is declared, `healthy`. Without it
# `make dev` returns the moment the daemon accepts the spec — the user
# sees the URLs and visits them while postgres is still booting and
# the API is still doing RLS bootstrap. The first 10–30 seconds then
# look like a broken stack ("Loading…", 502 Bad Gateway), and we burn
# trust on what is actually a startup race. `--wait-timeout 90` caps
# that wait at 90s so a genuinely stuck service still surfaces.
dev-up:
	docker compose -f infra/docker/docker-compose.dev.yml up -d --build --wait --wait-timeout 90

dev-down:
	docker compose -f infra/docker/docker-compose.dev.yml down

dev-logs:
	docker compose -f infra/docker/docker-compose.dev.yml logs -f

api-logs:
	docker compose -f infra/docker/docker-compose.dev.yml logs -f api

web-logs:
	docker compose -f infra/docker/docker-compose.dev.yml logs -f web

# Database
db-migrate:
	docker compose -f infra/docker/docker-compose.dev.yml exec api alembic revision --autogenerate -m "$(msg)"

db-upgrade:
	docker compose -f infra/docker/docker-compose.dev.yml exec api alembic upgrade head

db-seed:
	docker compose -f infra/docker/docker-compose.dev.yml exec api python -m scripts.seed

# Testing
test: test-scanner test-api

test-scanner:
	cd packages/scanner && python -m pytest tests/ -v

test-api:
	cd packages/api && python -m pytest tests/ -v

# Production
prod: prod-up

prod-up:
	docker compose -f infra/docker/docker-compose.prod.yml up -d --build --wait --wait-timeout 120

prod-down:
	docker compose -f infra/docker/docker-compose.prod.yml down

# Cleanup — drops dev volumes (postgres data, etc.) and Python/Next caches.
# Safe to re-run; preserves images and node_modules so the next `make dev`
# still uses Docker's layer cache and skips `npm ci`.
clean:
	docker compose -f infra/docker/docker-compose.dev.yml down -v
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .next -exec rm -rf {} + 2>/dev/null || true

# Nuclear cleanup — what you reach for when "weird stale state" is the
# diagnosis and you want a guaranteed-fresh first run. Drops everything
# `clean` does plus host node_modules, the prod stack, and the per-project
# Docker images. The next `make dev` will refetch and rebuild from scratch.
clean-all: clean
	docker compose -f infra/docker/docker-compose.prod.yml down -v 2>/dev/null || true
	rm -rf packages/web/node_modules
	docker images --format '{{.Repository}}:{{.Tag}}' | grep -E '^docker-(api|web|celery|prom)' | xargs -r docker rmi -f 2>/dev/null || true
