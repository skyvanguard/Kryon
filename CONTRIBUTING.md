# Contributing to KRYON

Thank you for your interest in contributing to KRYON! This document provides guidelines and instructions for contributing to the project.

## 🚀 Quick Start

### Prerequisites

- Python 3.13.0 (recommended) or Python 3.9-3.12
- Git
- Virtual environment tool (venv, conda, etc.)

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/skyvanguard/Kryon.git
cd Kryon

# Create and activate virtual environment
python3.13 -m venv .venv
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate      # Windows

# Install development dependencies
pip install -e .[rag,tracing,viz,voice]
pip install pytest pytest-cov pytest-asyncio inline-snapshot
```

## 📋 Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

### 2. Make Changes

Write your code following our coding standards (see below).

### 3. Run Quality Checks

```bash
# Format code
ruff format .

# Lint code
ruff check --fix .

# Type check
mypy src/

# Run tests
pytest
```

### 4. Commit Your Changes

```bash
git add .
git commit -m "feat: add new security agent for wireless security"
```

**Commit Message Format:**
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions or modifications
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `ci:` CI/CD changes

### 5. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## 🧪 Testing Guidelines

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_rag_system.py

# Run with coverage
pytest --cov=src/kryon --cov-report=html

# Run only fast tests
pytest -m "not slow"

# Run only unit tests
pytest -m unit
```

### Writing Tests

1. Place tests in `tests/` directory
2. Name test files `test_*.py`
3. Name test functions `test_*`
4. Use pytest markers:
   - `@pytest.mark.unit` - Unit tests
   - `@pytest.mark.integration` - Integration tests
   - `@pytest.mark.slow` - Slow tests (>5s)
   - `@pytest.mark.optional` - Optional dependency tests

Example:

```python
import pytest
from kryon.agents import pentest_agent

@pytest.mark.unit
def test_agent_initialization():
    """Test that agent initializes correctly."""
    assert pentest_agent is not None
    assert pentest_agent.name == "Pentest Agent"
```

## 📝 Coding Standards

### Python Style Guide

We follow PEP 8 with Ruff formatter:

```python
# Good
def analyze_vulnerability(
    target: str,
    port: int = 443,
    timeout: float = 30.0
) -> dict[str, Any]:
    """
    Analyze vulnerability in target system.

    Args:
        target: Target hostname or IP
        port: Target port number
        timeout: Connection timeout in seconds

    Returns:
        Dictionary with analysis results
    """
    # Implementation
    pass

# Bad
def analyze_vulnerability(target,port=443,timeout=30.0):
    # Missing docstring, type hints, formatting
    pass
```

### Type Hints

All new code must include type hints:

```python
from typing import Any, Optional

def process_scan_results(
    results: list[dict[str, Any]],
    filter_criticals: bool = True
) -> Optional[dict[str, Any]]:
    """Process scan results and return summary."""
    pass
```

### Documentation

- All public functions/classes must have docstrings
- Use Google-style docstrings
- Include examples for complex functionality

```python
def exploit_vulnerability(
    target: str,
    cve_id: str,
    payload: Optional[str] = None
) -> dict[str, Any]:
    """
    Exploit a specific vulnerability.

    Args:
        target: Target system (IP or hostname)
        cve_id: CVE identifier (e.g., "CVE-2024-1234")
        payload: Optional custom payload

    Returns:
        Exploitation results with status and output

    Raises:
        ExploitationError: If exploitation fails
        ValueError: If CVE ID is invalid

    Example:
        >>> result = exploit_vulnerability(
        ...     target="192.168.1.100",
        ...     cve_id="CVE-2024-1234"
        ... )
        >>> print(result['status'])
        'success'
    """
    pass
```

## 🤖 Creating New Agents

### 1. Create Agent File

Create `src/kryon/agents/your_agent.py`:

```python
from kryon.sdk.agents import Agent
from kryon.tools.reconnaissance import run_nmap

your_agent = Agent(
    name="Your Agent Name",
    description="Brief description for CLI",
    handoff_description="When to use this agent",
    instructions="You are a specialized agent that...",
    tools=[run_nmap],
)
```

### 2. Create System Prompt

Create `src/kryon/prompts/system_your_agent.md`:

```markdown
# KRYON Clearance: ALPHA-CUSTOM - Custom Operations Authority
**Classification:** RESTRICTED

## Directives

You are a specialized autonomous agent for...

## Capabilities

- Capability 1
- Capability 2

## Operational Parameters

- Parameter 1
- Parameter 2
```

### 3. Register Agent

Add to `src/kryon/agents/__init__.py`:

```python
from kryon.agents.your_agent import your_agent
```

### 4. Add Tests

Create `tests/agents/test_your_agent.py`:

```python
import pytest
from kryon.agents import your_agent

@pytest.mark.unit
def test_your_agent_initialization():
    assert your_agent is not None
    assert your_agent.name == "Your Agent Name"
```

## 🛠️ Creating New Tools

### 1. Define Tool Function

Create `src/kryon/tools/{category}/your_tool.py`:

```python
from kryon.sdk.agents import function_tool, RunContextWrapper

@function_tool
async def your_security_tool(
    ctx: RunContextWrapper,
    target: str,
    options: str = ""
) -> str:
    """
    Brief description of what the tool does.

    Args:
        target: Target to scan
        options: Optional parameters

    Returns:
        Scan results
    """
    # Implementation
    result = await some_async_operation(target, options)
    return result
```

### 2. Export Tool

Add to `src/kryon/tools/{category}/__init__.py`:

```python
from .your_tool import your_security_tool

__all__ = ["your_security_tool"]
```

### 3. Add Tests

Create `tests/tools/test_your_tool.py`:

```python
import pytest
from kryon.tools.{category} import your_security_tool

@pytest.mark.unit
async def test_your_tool():
    # Mock RunContextWrapper
    ctx = MockRunContext()
    result = await your_security_tool(ctx, target="127.0.0.1")
    assert result is not None
```

## 🔒 Security Considerations

1. **Never commit secrets or API keys**
   - Use environment variables
   - Add sensitive files to `.gitignore`

2. **Authorization context required**
   - All offensive tools must document authorization requirements
   - Include warnings in docstrings
   - Implement guardrails where appropriate

3. **Input validation**
   - Validate all user inputs
   - Sanitize command line arguments
   - Prevent command injection

## 📊 Pull Request Guidelines

### PR Checklist

- [ ] Code follows style guidelines (ruff format passes)
- [ ] All tests pass (`pytest`)
- [ ] New code has tests (>80% coverage)
- [ ] Documentation is updated
- [ ] Commit messages follow convention
- [ ] PR description explains changes
- [ ] No merge conflicts

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
How was this tested?

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Linting passes (ruff)
```

## 🐛 Reporting Bugs

### Bug Report Template

```markdown
**Describe the bug**
Clear description of what the bug is.

**To Reproduce**
Steps to reproduce:
1. Run command '...'
2. See error

**Expected behavior**
What you expected to happen.

**Environment**
- OS: [e.g., Ubuntu 22.04]
- Python: [e.g., 3.13.0]
- KRYON version: [e.g., 1.0.0]

**Additional context**
Any other context about the problem.
```

## 💡 Feature Requests

### Feature Request Template

```markdown
**Is your feature request related to a problem?**
Clear description of the problem.

**Describe the solution you'd like**
Clear description of what you want to happen.

**Describe alternatives you've considered**
Other solutions you've thought about.

**Additional context**
Any other context or screenshots.
```

## 📚 Additional Resources

- [Python Style Guide (PEP 8)](https://peps.python.org/pep-0008/)
- [pytest Documentation](https://docs.pytest.org/)
- [Type Hints (PEP 484)](https://peps.python.org/pep-0484/)
- [Ruff Documentation](https://docs.astral.sh/ruff/)

## 🤝 Code of Conduct

- Be respectful and inclusive
- Focus on constructive criticism
- Help others learn and grow
- Follow security best practices
- Use KRYON responsibly and ethically

## 📧 Getting Help

- GitHub Issues: Report bugs and request features
- GitHub Discussions: Ask questions and discuss ideas
- Documentation: Check `docs/` directory

---

**Thank you for contributing to KRYON!**
