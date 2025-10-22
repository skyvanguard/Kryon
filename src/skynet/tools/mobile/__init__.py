"""
Mobile Security Tools
=====================

This module provides tools for mobile application security testing, including
Android and iOS static/dynamic analysis, runtime instrumentation, and
vulnerability assessment.

Tool Categories:
- Static Analysis: APK/IPA decompilation, manifest analysis, code review
- Dynamic Analysis: Runtime behavior, API monitoring, network capture
- Runtime Instrumentation: Function hooking, SSL bypass, root detection bypass
- Automated Testing: Comprehensive security scanning and reporting

SKYNET Integration: Phase 11
"""

from skynet.tools.mobile.mobsf import (
    mobsf_static_analysis,
    mobsf_dynamic_analysis,
    mobsf_api_scan
)
from skynet.tools.mobile.apkid import apkid_detect
from skynet.tools.mobile.androguard import (
    androguard_analyze,
    androguard_extract_apk,
    androguard_decompile
)
from skynet.tools.mobile.frida_tools import (
    frida_hook_function,
    frida_intercept_ssl,
    frida_dump_memory
)
from skynet.tools.mobile.objection import (
    objection_explore,
    objection_bypass_root
)

__all__ = [
    # MobSF - Mobile Security Framework (3 functions)
    "mobsf_static_analysis",
    "mobsf_dynamic_analysis",
    "mobsf_api_scan",

    # APKiD - Application identifier (1 function)
    "apkid_detect",

    # Androguard - Android analysis (3 functions)
    "androguard_analyze",
    "androguard_extract_apk",
    "androguard_decompile",

    # Frida - Dynamic instrumentation (3 functions)
    "frida_hook_function",
    "frida_intercept_ssl",
    "frida_dump_memory",

    # Objection - Runtime exploration (2 functions)
    "objection_explore",
    "objection_bypass_root",
]
