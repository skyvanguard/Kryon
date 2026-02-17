# Suggested Commands for KRYON Development

## Package Management (UV)
```bash
# Sync dependencies
uv sync --all-extras --all-packages --group dev

# Install package in development mode
uv pip install -e .
```

## Running KRYON
```bash
# Launch KRYON CLI
kryon

# Or via UV
uv run kryon
```

## Code Quality
```bash
# Format code
uv run ruff format
uv run ruff check --fix

# Lint only (no fix)
uv run ruff check

# Type checking
uv run mypy .
```

## Testing
```bash
# Run all tests
uv run pytest

# Run with coverage
uv run coverage run -m pytest
uv run coverage xml -o coverage.xml
uv run coverage report -m --fail-under=95

# Fix inline snapshots
uv run pytest --inline-snapshot=fix

# Create inline snapshots
uv run pytest --inline-snapshot=create
```

## Documentation
```bash
# Build docs
uv run mkdocs build

# Serve docs locally
uv run mkdocs serve

# Deploy docs to GitHub Pages
uv run mkdocs gh-deploy --force --verbose
```

## Git Commands (Windows)
```bash
git status
git add <files>
git commit -m "message"
git push
git pull
git log --oneline -10
```

## System Commands (Windows/Git Bash)
```bash
ls -la          # List files
cd <dir>        # Change directory
cat <file>      # View file
grep -r "text"  # Search text
find . -name "*.py"  # Find files
```
