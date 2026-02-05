"""
API & Credential Attack Tools
==============================

This module provides tools for API security testing, authentication exploitation,
and credential-based attacks.

Tool Categories:
- API Testing: REST API fuzzing, GraphQL testing
- Authentication: JWT exploitation, OAuth attacks, session hijacking
- Credential Attacks: Password spraying, credential stuffing
- API Discovery: Endpoint enumeration, schema extraction

KRYON Integration: Phase 9
"""

from kryon.tools.api_attacks.ffuf_api import ffuf_api_fuzz
from kryon.tools.api_attacks.hydra import hydra_attack
from kryon.tools.api_attacks.jwt_tool import jwt_crack, jwt_decode, jwt_forge
from kryon.tools.api_attacks.medusa import medusa_attack
from kryon.tools.api_attacks.wfuzz import wfuzz_scan

__all__ = [
    "ffuf_api_fuzz",
    "wfuzz_scan",
    "jwt_crack",
    "jwt_forge",
    "jwt_decode",
    "hydra_attack",
    "medusa_attack",
]
