# KRYON Testing Framework

**Version:** 1.0.0
**Status:** ✅ Complete
**Coverage Goal:** 80%+

---

## Overview

KRYON uses **pytest** as its testing framework, with comprehensive coverage across unit tests, integration tests, and validation checks. The testing infrastructure ensures code quality, reliability, and regression prevention.

### Testing Philosophy

1. **Fast Feedback** - Quick unit tests run on every commit
2. **Comprehensive Coverage** - Integration tests verify end-to-end workflows
3. **Automated Quality** - CI/CD pipeline runs all tests automatically
4. **Security First** - Security scans integrated into testing process

---

## Test Structure

```
tests/
├── __init__.py
├── conftest.py                    # Pytest configuration and fixtures
├── pytest.ini                     # Pytest settings
│
├── agents/                        # Agent tests
│   ├── test_agent_config.py
│   ├── test_agent_hooks.py
│   ├── test_agent_inference.py
│   └── test_guardrails.py
│
├── tools/                         # Tool tests
│   ├── test_ctf_automation.py     # Phase 14 CTF tools (NEW)
│   ├── test_function_tool.py
│   └── test_tool_generic_linux_command.py
│
├── test_tool_availability.py      # Tool import and availability (NEW)
├── test_integration_workflows.py  # Integration tests (NEW)
└── README.md
```

---

## Running Tests

### Quick Start

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/tools/test_ctf_automation.py

# Run specific test
pytest tests/tools/test_ctf_automation.py::TestAutoEnumerateTarget::test_quick_mode_enumeration
```

### Test Categories

#### Unit Tests (Fast)
```bash
# Run only unit tests (exclude integration)
pytest -m "not integration"

# Run specific tool tests
pytest -m tool

# Run agent tests
pytest -m agent
```

#### Integration Tests (Slow)
```bash
# Run only integration tests
pytest -m integration

# Run CTF-specific tests
pytest -m ctf

# Run with coverage
pytest --cov=src/skynet --cov-report=html
```

### Pre-Commit Validation

```bash
# Run quick validation (recommended before commit)
python scripts/validate.py

# Or use pytest markers
pytest -m "not integration and not slow" -x
```

---

## Test Markers

Tests are organized using pytest markers:

| Marker | Description | Usage |
|--------|-------------|-------|
| `unit` | Fast unit tests | Default, runs on every commit |
| `integration` | Integration tests requiring external services | CI/CD only |
| `slow` | Tests taking >5 seconds | Optional, CI/CD only |
| `ctf` | CTF-specific functionality | Phase 14 tests |
| `agent` | Agent-related tests | Agent system tests |
| `tool` | Tool-related tests | Tool functionality |
| `security` | Security and guardrail tests | Security validation |
| `optional` | Tests for optional dependencies | May skip if tools missing |

### Using Markers

```bash
# Run only fast tests
pytest -m "not slow"

# Run CTF and tool tests
pytest -m "ctf or tool"

# Skip integration tests
pytest -m "not integration"
```

---

## Coverage

### Measuring Coverage

```bash
# Generate coverage report
pytest --cov=src/skynet --cov-report=term

# Generate HTML coverage report
pytest --cov=src/skynet --cov-report=html

# Open HTML report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
start htmlcov/index.html  # Windows
```

### Coverage Goals

| Component | Target | Current |
|-----------|--------|---------|
| **Agents** | 80% | TBD |
| **Tools (Core)** | 85% | TBD |
| **Tools (CTF)** | 90% | TBD |
| **Framework** | 75% | TBD |
| **Overall** | 80% | TBD |

---

## Writing Tests

### Test File Structure

```python
"""
Test module docstring explaining what's being tested
"""

import pytest
from unittest.mock import Mock, patch

class TestFeatureName:
    """Test class for specific feature"""

    def test_basic_functionality(self):
        """Test basic functionality works"""
        # Arrange
        input_data = "test"

        # Act
        result = function_under_test(input_data)

        # Assert
        assert result == expected_output

    @pytest.mark.slow
    def test_slow_operation(self):
        """Test that may take time"""
        pass

    @pytest.mark.integration
    def test_external_service(self):
        """Test requiring external service"""
        pass
```

### Mocking External Dependencies

```python
@patch('subprocess.run')
def test_with_mocked_subprocess(self, mock_subprocess):
    """Test with mocked subprocess call"""
    # Setup mock
    mock_subprocess.return_value = Mock(
        returncode=0,
        stdout="mocked output"
    )

    # Test code
    result = function_that_calls_subprocess()

    # Verify
    assert result is not None
    mock_subprocess.assert_called_once()
```

### Parametrized Tests

```python
@pytest.mark.parametrize("input,expected", [
    ("test1", "result1"),
    ("test2", "result2"),
    ("test3", "result3"),
])
def test_multiple_inputs(self, input, expected):
    """Test with multiple parameter sets"""
    result = function(input)
    assert result == expected
```

---

## CI/CD Integration

### GitHub Actions Workflow

Tests run automatically on:
- ✅ Push to `main` or `develop` branches
- ✅ Pull requests
- ✅ Manual trigger (workflow_dispatch)

**Workflow File:** `.github/workflows/test.yml`

### CI/CD Jobs

1. **Test Job** - Run unit tests on multiple OS/Python versions
   - Ubuntu, Windows, macOS
   - Python 3.9, 3.10, 3.11, 3.12
   - Generate coverage reports

2. **Lint Job** - Code quality checks
   - Black (formatting)
   - Flake8 (linting)
   - Pylint (static analysis)

3. **Security Job** - Security scanning
   - Bandit (security linter)
   - Safety (dependency vulnerabilities)

4. **Integration Job** - Integration tests (main branch only)

5. **Docs Job** - Documentation validation

6. **Build Job** - Package build test

### CI/CD Status

Check CI/CD status:
- GitHub Actions tab in repository
- Badge in README.md (if configured)

---

## Test Coverage by Component

### Phase 14: CTF Tools (NEW)

**File:** `tests/tools/test_ctf_automation.py`

**Tests:**
- ✅ `auto_enumerate_target()` - Nmap + Gobuster automation
- ✅ `search_exploits()` - SearchSploit + Metasploit integration
- ✅ `hunt_flags()` - Automated flag discovery
- ✅ `generate_ctf_report()` - Report generation
- ✅ `check_thm_vpn()` - VPN connectivity
- ✅ `submit_thm_answer()` - Answer formatting
- ✅ `gtfobins_lookup()` - GTFOBins database
- ✅ Complete CTF workflow integration

### Tool Availability Tests (NEW)

**File:** `tests/test_tool_availability.py`

**Tests:**
- ✅ All tool modules can be imported
- ✅ All agent modules can be imported
- ✅ External dependencies available
- ✅ Function signatures and documentation
- ✅ Prompt files exist and have KRYON theming
- ✅ Clearance system documentation
- ✅ Session reports complete

### Integration Workflows (NEW)

**File:** `tests/test_integration_workflows.py`

**Tests:**
- ✅ Agent transfer workflows
- ✅ Tool chain workflows
- ✅ Complete CTF workflow (mocked)
- ✅ Multi-agent coordination
- ✅ Security guardrails
- ✅ Tool dependency chains
- ✅ Error handling

---

## Troubleshooting

### Common Issues

#### 1. Import Errors

**Problem:** `ModuleNotFoundError: No module named 'kryon'`

**Solution:**
```bash
# Install in development mode
pip install -e .

# Or add to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:/path/to/skynet/src"
```

#### 2. Missing Test Dependencies

**Problem:** `pytest: command not found`

**Solution:**
```bash
pip install pytest pytest-cov pytest-mock pytest-asyncio
```

#### 3. External Tool Tests Failing

**Problem:** Tests fail because nmap, gobuster, etc. not installed

**Solution:**
```bash
# Skip optional tool tests
pytest -m "not optional"

# Or install tools (Ubuntu/Kali)
sudo apt-get install nmap gobuster
```

#### 4. Integration Tests Timeout

**Problem:** Integration tests take too long or timeout

**Solution:**
```bash
# Skip integration tests
pytest -m "not integration"

# Or increase timeout in pytest.ini
```

---

## Best Practices

### 1. Test Naming

- ✅ Use descriptive names: `test_auto_enumerate_target_quick_mode`
- ❌ Avoid generic names: `test_function1`, `test_case2`

### 2. Test Independence

- ✅ Each test should run independently
- ❌ Don't rely on test execution order
- ✅ Use fixtures for setup/teardown

### 3. Mocking

- ✅ Mock external dependencies (subprocess, network calls)
- ✅ Use `patch` for temporary mocking
- ❌ Don't mock the code you're testing

### 4. Assertions

- ✅ Use specific assertions: `assert result == expected`
- ✅ Add assertion messages: `assert len(items) > 0, "No items found"`
- ❌ Don't use bare `assert True`

### 5. Test Coverage

- ✅ Aim for 80%+ coverage
- ✅ Test happy path AND error cases
- ✅ Test edge cases and boundary conditions

---

## Performance

### Test Execution Times

| Test Suite | Tests | Time (approx) |
|------------|-------|---------------|
| Unit tests only | ~50 | 10-20 seconds |
| All tests (no integration) | ~70 | 30-45 seconds |
| Integration tests | ~15 | 2-5 minutes |
| Full suite | ~85 | 3-6 minutes |
| Pre-commit validation | ~40 | 20-30 seconds |

### Optimization Tips

1. **Use markers** to run only relevant tests
2. **Parallelize** with `pytest-xdist`: `pytest -n auto`
3. **Cache** test results: `pytest --cache-clear`
4. **Profile** slow tests: `pytest --durations=10`

---

## Future Improvements

### Planned Enhancements

- [ ] Increase test coverage to 90%+
- [ ] Add performance/benchmark tests
- [ ] Add mutation testing (pytest-mutate)
- [ ] Create test data fixtures library
- [ ] Add API contract tests
- [ ] Implement visual regression testing for reports
- [ ] Add chaos engineering tests

### Contributing Tests

When adding new features:

1. ✅ Write unit tests for new functions
2. ✅ Write integration tests for workflows
3. ✅ Update test documentation
4. ✅ Run `python scripts/validate.py` before commit
5. ✅ Ensure CI/CD passes

---

## Resources

- **Pytest Documentation:** https://docs.pytest.org/
- **Coverage.py:** https://coverage.readthedocs.io/
- **unittest.mock:** https://docs.python.org/3/library/unittest.mock.html
- **GitHub Actions:** https://docs.github.com/en/actions

---

**Testing Status:** ✅ Framework Complete
**Last Updated:** January 22, 2025
**Maintained By:** KRYON Development Team

---

*🤖 Generated with Claude Code*
*Co-Authored-By: Claude <noreply@anthropic.com>*
