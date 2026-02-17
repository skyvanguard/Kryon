# KRYON Code Style and Conventions

## Formatting
- **Line Length**: 120 characters
- **Formatter**: Ruff
- **Target Python**: 3.10+

## Linting Rules (Ruff)
- E: pycodestyle errors
- W: pycodestyle warnings
- F: pyflakes
- I: isort
- B: flake8-bugbear
- C4: flake8-comprehensions
- UP: pyupgrade

## Docstrings
- **Convention**: Google style

## Type Hints
- MyPy is used but not strict mode
- Type hints are recommended but not enforced everywhere

## Import Organization
- isort with combine-as-imports
- First-party packages: `agents`

## Project Structure
```
src/kryon/
├── agents/       # Pre-built AI agents (Terminator Units)
├── cache/        # Caching utilities
├── internal/     # Internal utilities
├── knowledge/    # Knowledge base and RAG
├── prompts/      # Prompt templates
├── repl/         # Interactive REPL interface
├── sdk/          # Agent SDK for building custom agents
├── tools/        # Security tools integration
├── util/         # General utilities
├── cli.py        # Main CLI entry point
└── __init__.py
```

## Naming Conventions
- **Files**: snake_case
- **Classes**: PascalCase
- **Functions/Methods**: snake_case
- **Constants**: UPPER_SNAKE_CASE
