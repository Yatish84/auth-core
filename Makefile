.PHONY: setup up down logs test lint validate health

setup:
	corepack enable
	corepack prepare pnpm@9.15.9 --activate
	pnpm install
	uv sync --project services/auth-api --all-groups

up:
	docker compose up --build

down:
	docker compose down

logs:
	docker compose logs -f

test:
	uv run --project services/auth-api pytest
	pnpm test:web
	cd services/jwt-verifier && go test ./...

lint:
	uv run --project services/auth-api ruff check services/auth-api
	uv run --project services/auth-api mypy services/auth-api/src
	pnpm lint:web
	pnpm typecheck:web
	cd services/jwt-verifier && go vet ./...

validate:
	python3 scripts/validate_docs.py
	docker compose config --quiet

health:
	curl --fail http://localhost:8000/health/live
	curl --fail http://localhost:8081/health/live
