.PHONY: dev dev-up dev-down dev-logs api-logs web-logs db-migrate db-upgrade db-seed test test-api test-scanner lint clean prod prod-up prod-down

# Development
dev: dev-up
	@echo "NIS2 Platform running at http://localhost:8077"
	@echo "API docs at http://localhost:8000/docs"

dev-up:
	docker compose -f infra/docker/docker-compose.dev.yml up -d --build

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
	docker compose -f infra/docker/docker-compose.prod.yml up -d --build

prod-down:
	docker compose -f infra/docker/docker-compose.prod.yml down

# Cleanup
clean:
	docker compose -f infra/docker/docker-compose.dev.yml down -v
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .next -exec rm -rf {} + 2>/dev/null || true
