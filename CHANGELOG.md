# Changelog

All notable changes to KRYON will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-04

### Added
- **Core Platform**
  - Autonomous agent framework with ReACT model implementation
  - Support for 300+ LLMs (OpenAI, Claude, DeepSeek, Llama, Ollama, etc.)
  - Multi-agent orchestration patterns (Swarm, Hierarchical, Parallel)
  - Human-in-the-Loop (HITL) integration for critical decisions

- **Security Agents (Terminator Units)**
  - T-800 Infiltrator: System infiltration specialist
  - T-1000 Hunter: Bug hunting and vulnerability discovery
  - T-600 Scout: Reconnaissance operations
  - Guardian Protocol: Defensive security monitoring
  - Forensic Analyzer: Incident response and analysis
  - CodeAgent: Dynamic code execution and analysis

- **Security Tools (180+)**
  - Reconnaissance: 23 tools (nmap, subdomain enum, DNS, etc.)
  - Exploitation: 4 tools (Metasploit, manual exploits)
  - Privilege Escalation: 4 tools (Windows + Linux)
  - Lateral Movement: Network pivoting capabilities
  - Command & Control: 8 C2 modules
  - Anonymity: 116 functions for OPSEC
  - CTF Automation: Complete challenge solving suite

- **Knowledge System (RAG)**
  - Integration with ExploitDB, NVD, GitHub
  - Semantic search for vulnerabilities
  - Async query engine with caching
  - ChromaDB vector storage

- **Guardrails**
  - 70+ injection pattern detections
  - Unicode normalization anti-bypass
  - Parallel execution (not post-processing)
  - Input/Output validation framework

- **CLI & Interface**
  - Interactive REPL with rich formatting
  - CTF integration commands
  - Memory management
  - Cost tracking
  - Model selection runtime

- **DevOps**
  - CI/CD pipeline (GitHub Actions)
  - Multi-platform support (Linux, Windows)
  - Python 3.10-3.14 compatibility
  - Comprehensive test suite (1,079 tests)

### Changed
- Rebranded from SKYNET to KRYON
- Environment variables renamed: `SKYNET_*` -> `KRYON_*`
- Updated all documentation and references

### Security
- MIT License for open source distribution
- Clear disclaimer for authorized use only
- Guardrails enabled by default

## [0.9.0] - 2025-12-01 (Pre-release)

### Added
- Initial SKYNET platform development
- Core agent framework
- Basic security tools integration
- Local LLM support via Ollama

---

## Upgrade Guide

### From SKYNET to KRYON 1.0.0

1. **Update environment variables:**
   ```bash
   # Old
   SKYNET_MODEL="gpt-4o"
   SKYNET_GUARDRAILS="true"

   # New
   KRYON_MODEL="gpt-4o"
   KRYON_GUARDRAILS="true"
   ```

2. **Update CLI commands:**
   ```bash
   # Both commands work (skynet is aliased)
   kryon
   skynet  # Legacy alias
   ```

3. **Update imports (if using SDK):**
   ```python
   # No change needed - internal module is still skynet
   from skynet.sdk.agents import Agent, function_tool
   ```
