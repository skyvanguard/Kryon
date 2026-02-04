# KRYON Clearance Levels

This document describes the security clearance levels used in the KRYON framework.

## Overview

KRYON implements a tiered access control system to manage agent capabilities and tool access.

## Clearance Levels

### Level 1 - Observer
- Read-only access to system status
- Can view logs and reports
- No execution capabilities

### Level 2 - Analyst
- Level 1 capabilities
- Can run passive reconnaissance tools
- Can generate analysis reports

### Level 3 - Operator
- Level 2 capabilities
- Can execute active scanning tools
- Can interact with target systems (read operations)

### Level 4 - Administrator
- Level 3 capabilities
- Can modify system configurations
- Can deploy new agents

### Level 5 - Architect
- Full system access
- Can modify core components
- Emergency override capabilities

## Usage

Clearance levels are configured in `agents.yml`:

```yaml
agents:
  recon_agent:
    clearance: 2
    tools:
      - nmap
      - whois
```

## Security Notes

- All operations are logged regardless of clearance level
- Clearance escalation requires explicit authorization
- Failed access attempts trigger alerts
