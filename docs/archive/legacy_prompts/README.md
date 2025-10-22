# Legacy Agent Prompts Archive

This directory contains legacy agent prompt files that have been superseded by updated versions with full SKYNET theming and Phase 10-13 tool integration.

---

## Archived Files

### `system_dfir_agent.md`
**Original Size:** 342 lines
**Created:** Early SKYNET development
**Archived:** January 22, 2025

**Replaced By:** `src/skynet/prompts/system_forensic_analyzer.md`

**Reason for Archival:**
- Legacy prompt without SKYNET branding
- Used generic `generic_linux_command()` calls
- Missing Phase 13 specialized DFIR functions
- Superseded by comprehensive Forensic Analyzer with:
  - Full SKYNET theming and clearance system
  - 13 specialized Phase 13 functions (Volatility, Autopsy, Zeek, Chainsaw, etc.)
  - Professional function-based API
  - Automated error handling and caching

**Last Used:** Agent code updated in commit 89b45a1 (January 22, 2025)

---

### `system_blue_team_agent.md`
**Original Size:** ~12KB
**Created:** Early SKYNET development
**Archived:** January 22, 2025

**Replaced By:** `src/skynet/prompts/system_guardian_protocol.md`

**Reason for Archival:**
- Legacy prompt without complete SKYNET branding
- Missing Phase 13 DFIR tools for incident detection
- Superseded by Guardian Protocol with:
  - Full SKYNET theming (Alpha-Blue clearance)
  - Phase 13 Network Forensics tools (NetworkMiner, Zeek, Wireshark)
  - Phase 13 Log Analysis tools (Chainsaw, EVTX parsing)
  - Enhanced threat hunting and incident detection capabilities

**Last Used:** Agent code updated in commit [current session] (January 22, 2025)

---

## Historical Context

These files represent the evolution of SKYNET from a general cybersecurity AI framework to a specialized, themed autonomous security platform:

**Early Development (Pre-SKYNET):**
- Generic agent names (dfir_agent, blue_team_agent)
- Basic tool access via shell commands
- Minimal branding

**Current State (SKYNET v1.0):**
- Themed agent names (Forensic Analyzer, Guardian Protocol)
- Specialized function-based tools (Phase 10-13)
- Complete clearance level system
- Professional security operation workflows

---

## Preservation Rationale

These files are preserved for:
1. **Historical reference** - Track project evolution
2. **Backward compatibility research** - Understanding previous implementations
3. **Documentation purposes** - Show progression of agent capabilities
4. **Educational value** - Demonstrate before/after transformation

---

## File Status

| File | Status | Replacement | Migration Date |
|------|--------|-------------|----------------|
| `system_dfir_agent.md` | ❌ ARCHIVED | `system_forensic_analyzer.md` | Jan 22, 2025 |
| `system_blue_team_agent.md` | ❌ ARCHIVED | `system_guardian_protocol.md` | Jan 22, 2025 |

**Note:** These files should NOT be used in active development. All references have been updated to point to their modern replacements.

---

## Related Documentation

- [SKYNET Clearance Levels](../../CLEARANCE_LEVELS.md) - Complete clearance system
- [Phase 13 Completion Report](../../sessions/PHASE_13_COMPLETION_REPORT.md) - DFIR tools implementation
- [Session: Clearance & Agent Fixes](../../sessions/SESSION_CLEARANCE_AND_AGENT_FIXES.md) - Agent migration details

---

**Archive Created:** January 22, 2025
**Archive Purpose:** Historical preservation and documentation
**Archive Status:** READ-ONLY

---

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>
