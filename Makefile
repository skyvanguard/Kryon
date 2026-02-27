.PHONY: sync
sync:
	uv sync --all-extras --all-packages --group dev

.PHONY: format
format:
	uv run ruff format
	uv run ruff check --fix

.PHONY: lint
lint:
	uv run ruff check

.PHONY: mypy
mypy:
	uv run mypy .

.PHONY: tests
tests:
	uv run pytest

.PHONY: coverage
coverage:
	uv run coverage run -m pytest
	uv run coverage xml -o coverage.xml
	uv run coverage report -m --fail-under=95

.PHONY: snapshots-fix
snapshots-fix:
	uv run pytest --inline-snapshot=fix

.PHONY: snapshots-create
snapshots-create:
	uv run pytest --inline-snapshot=create

.PHONY: docker-build
docker-build:
	docker compose build

.PHONY: docker-up
docker-up:
	docker compose up -d

.PHONY: docker-down
docker-down:
	docker compose down

.PHONY: docker-prod
docker-prod:
	docker compose -f docker/docker-compose.production.yml up -d

.PHONY: security-scan
security-scan:
	pip-audit --strict --desc || true
	safety check --full-report || true

.PHONY: release
release:
	python -m build
	twine check dist/*
