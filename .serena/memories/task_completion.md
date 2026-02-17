# Task Completion Checklist for KRYON

## Before Completing a Task

### 1. Format Code
```bash
uv run ruff format
uv run ruff check --fix
```

### 2. Run Linting
```bash
uv run ruff check
```

### 3. Run Tests
```bash
uv run pytest
```

### 4. (Optional) Type Checking
```bash
uv run mypy .
```

## Quick All-in-One Check
```bash
# Format, lint, and test
uv run ruff format && uv run ruff check --fix && uv run pytest
```

## Coverage Requirements
- Minimum coverage: 95%
- Run full coverage check:
```bash
uv run coverage run -m pytest
uv run coverage report -m --fail-under=95
```
