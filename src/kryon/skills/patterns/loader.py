"""
Pattern library loader — reads YAML CWE specs, normalizes them,
exposes a uniform query API.

Schema (per file under patterns/cwe/):

    cwe: CWE-190
    name: Integer Overflow
    aliases: [CWE-191, CWE-194, CWE-195, CWE-196, CWE-197]
    detection:
      - regex: "..."
        confidence: low|medium|high
        context_required: optional
      - semgrep_rule: kryon.cwe-190.arith-in-alloc
    verification:
      poc_skeleton: |
        #include ...
      asan_class: heap-buffer-overflow|undefined-behavior|...
    escalation_hints: [str, ...]
    fpr_filters:
      - skip_if: "guarded by `if (size < N)`"

The loader minimally validates and caches by mtime — adding a new
CWE requires only dropping a YAML file in.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_PATTERNS_DIR = Path(__file__).parent / "cwe"
_cache: dict[str, dict] = {}
_cache_mtime: float = 0.0


# ---------------------------------------------------------------------------
# CWE alias normalization (F6.4)
# ---------------------------------------------------------------------------
# Map of detection-CWE → list of CWEs that should ALSO count as a match.
# Most static analyzers emit a parent CWE (e.g. CWE-787) when the actual
# Juliet label is a child (CWE-121 stack-overflow, CWE-122 heap-overflow).
# Aliases let us count parent emissions as matches for any child CWE.

_ALIAS_FAMILIES: list[set[str]] = [
    # Out-of-bounds write family
    {"CWE-787", "CWE-121", "CWE-122", "CWE-124", "CWE-119"},
    # Out-of-bounds read family
    {"CWE-125", "CWE-126", "CWE-127"},
    # Use of dangerous string functions → overflow family
    {"CWE-676", "CWE-787", "CWE-121", "CWE-122"},
    # Integer family
    {"CWE-190", "CWE-191", "CWE-192", "CWE-193", "CWE-194", "CWE-195", "CWE-196", "CWE-197", "CWE-680"},
    # Use-after-free / double-free family
    {"CWE-416", "CWE-415", "CWE-672"},
    # Null deref family
    {"CWE-476", "CWE-690"},
    # Format string family
    {"CWE-134", "CWE-79"},
    # Command/shell injection
    {"CWE-78", "CWE-77", "CWE-88"},
    # Path traversal
    {"CWE-22", "CWE-23", "CWE-36"},
    # Authentication / authorization
    {"CWE-287", "CWE-285", "CWE-288"},
]


def _build_alias_index() -> dict[str, set[str]]:
    idx: dict[str, set[str]] = {}
    for family in _ALIAS_FAMILIES:
        for cwe in family:
            idx.setdefault(cwe, set()).update(family)
    return idx


_ALIAS_INDEX = _build_alias_index()


def normalize_cwe(cwe: str) -> str:
    """Canonical form: 'CWE-787' (uppercase, dash, no extra)."""
    if not cwe:
        return ""
    s = cwe.strip().upper().replace("_", "-")
    m = re.search(r"CWE[-_]?(\d+)", s)
    if m:
        return f"CWE-{m.group(1)}"
    return s


def cwes_match(emitted: str, expected: str) -> bool:
    """True if the emitted CWE counts as a match for the expected one,
    accounting for parent/child aliases (F6.4)."""
    e = normalize_cwe(emitted)
    x = normalize_cwe(expected)
    if not e or not x:
        return False
    if e == x:
        return True
    # If e has a known family, check if x is in it
    fam = _ALIAS_INDEX.get(e)
    if fam and x in fam:
        return True
    fam2 = _ALIAS_INDEX.get(x)
    if fam2 and e in fam2:
        return True
    return False


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------


def _parse_yaml(text: str) -> dict[str, Any]:
    """Use PyYAML when available — handles backslash escapes, nested |
    blocks, and all standard YAML correctly. Fall back to our simple
    parser only if PyYAML is missing (kept for portability)."""
    try:
        import yaml

        result = yaml.safe_load(text)
        return result if isinstance(result, dict) else {}
    except ImportError:
        return _parse_yaml_simple(text)
    except Exception as e:
        logger.warning("PyYAML failed (%s), falling back to simple parser", e)
        return _parse_yaml_simple(text)


def _parse_yaml_simple(text: str) -> dict[str, Any]:
    """Tiny YAML parser fallback (no full PyYAML dep).
    Handles: scalars, inline lists [a,b,c], block lists, multi-line | strings, nested dicts (one level)."""
    result: dict[str, Any] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        # Detect indent
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        # Top-level key:value
        if indent == 0 and ":" in stripped:
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()
            if val == "|":
                # Multi-line literal block — collect indented lines
                block: list[str] = []
                i += 1
                while i < len(lines):
                    nxt = lines[i]
                    if not nxt.strip():
                        block.append("")
                        i += 1
                        continue
                    nxt_indent = len(nxt) - len(nxt.lstrip())
                    if nxt_indent == 0:
                        break
                    # Strip 2-space minimum indent
                    block.append(nxt[2:] if nxt.startswith("  ") else nxt.lstrip())
                    i += 1
                result[key] = "\n".join(block)
                continue
            elif val.startswith("[") and val.endswith("]"):
                # Inline list
                items = [x.strip().strip('"').strip("'") for x in val[1:-1].split(",") if x.strip()]
                result[key] = items
            elif val:
                result[key] = val.strip('"').strip("'")
            else:
                # Block-style — list or dict will follow at deeper indent
                next_items: list = []
                next_dict: dict = {}
                i += 1
                while i < len(lines):
                    nxt = lines[i]
                    if not nxt.strip() or nxt.lstrip().startswith("#"):
                        i += 1
                        continue
                    nxt_indent = len(nxt) - len(nxt.lstrip())
                    if nxt_indent == 0:
                        break
                    nxt_stripped = nxt.strip()
                    if nxt_stripped.startswith("- "):
                        item_body = nxt_stripped[2:].strip()
                        # Could be a scalar list item OR a dict (key: value)
                        if ":" in item_body and not item_body.startswith('"'):
                            # Dict item with possibly more keys at deeper indent
                            sub: dict = {}
                            ikey, _, ival = item_body.partition(":")
                            ikey = ikey.strip()
                            ival = ival.strip()
                            if ival == "|":
                                block: list[str] = []
                                i += 1
                                while i < len(lines):
                                    n2 = lines[i]
                                    if not n2.strip():
                                        block.append("")
                                        i += 1
                                        continue
                                    n2_indent = len(n2) - len(n2.lstrip())
                                    if n2_indent <= nxt_indent + 2:
                                        break
                                    block.append(
                                        n2[nxt_indent + 4 :] if n2.startswith(" " * (nxt_indent + 4)) else n2.lstrip()
                                    )
                                    i += 1
                                sub[ikey] = "\n".join(block)
                                next_items.append(sub)
                                continue
                            else:
                                sub[ikey] = ival.strip('"').strip("'")
                                # Look ahead for additional sub-keys at indent > nxt_indent
                                i += 1
                                while i < len(lines):
                                    n2 = lines[i]
                                    if not n2.strip():
                                        i += 1
                                        continue
                                    n2_indent = len(n2) - len(n2.lstrip())
                                    if n2_indent <= nxt_indent:
                                        break
                                    n2_stripped = n2.strip()
                                    if ":" in n2_stripped and not n2_stripped.startswith("-"):
                                        sk, _, sv = n2_stripped.partition(":")
                                        sub[sk.strip()] = sv.strip().strip('"').strip("'")
                                    i += 1
                                next_items.append(sub)
                                continue
                        else:
                            next_items.append(item_body.strip('"').strip("'"))
                            i += 1
                    elif ":" in nxt_stripped:
                        sk, _, sv = nxt_stripped.partition(":")
                        next_dict[sk.strip()] = sv.strip().strip('"').strip("'")
                        i += 1
                    else:
                        i += 1
                if next_items:
                    result[key] = next_items
                elif next_dict:
                    result[key] = next_dict
                else:
                    result[key] = None
                continue
        i += 1
    return result


def _scan_patterns() -> dict[str, dict]:
    """(Re)load all CWE YAML files; cache invalidated by directory mtime."""
    global _cache, _cache_mtime
    if not _PATTERNS_DIR.is_dir():
        logger.warning("patterns dir missing: %s", _PATTERNS_DIR)
        return {}
    current_mtime = _PATTERNS_DIR.stat().st_mtime
    # Also account for individual file changes
    try:
        current_mtime = max(
            current_mtime,
            *(p.stat().st_mtime for p in _PATTERNS_DIR.glob("*.yaml")),
        )
    except ValueError:
        pass
    if _cache and current_mtime <= _cache_mtime:
        return _cache

    out: dict[str, dict] = {}
    for path in sorted(_PATTERNS_DIR.glob("*.yaml")):
        try:
            data = _parse_yaml(path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning("failed to parse %s: %s", path.name, e)
            continue
        cwe = normalize_cwe(data.get("cwe", ""))
        if not cwe:
            logger.warning("%s missing cwe field", path.name)
            continue
        data["cwe"] = cwe
        data["_source_file"] = str(path)
        out[cwe] = data
    _cache = out
    _cache_mtime = current_mtime
    logger.info("loaded %d CWE patterns from %s", len(out), _PATTERNS_DIR)
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_pattern(cwe: str) -> dict | None:
    """Return the YAML for one CWE, or None if not registered."""
    return _scan_patterns().get(normalize_cwe(cwe))


def iter_all_patterns() -> list[dict]:
    """All loaded patterns. Useful for bulk operations."""
    return list(_scan_patterns().values())


def iter_detection_regexes() -> list[tuple[str, str, str]]:
    """Return [(regex_str, cwe, confidence)] for HeuristicHunter."""
    out: list[tuple[str, str, str]] = []
    for entry in _scan_patterns().values():
        cwe = entry.get("cwe", "")
        for det in entry.get("detection") or []:
            if isinstance(det, dict) and det.get("regex"):
                out.append((det["regex"], cwe, det.get("confidence", "medium")))
    return out


def get_poc_template(cwe: str) -> str | None:
    """Return the PoC skeleton C source for a CWE, or None."""
    p = get_pattern(cwe)
    if not p:
        return None
    ver = p.get("verification") or {}
    if isinstance(ver, dict):
        return ver.get("poc_skeleton")
    return None


def get_asan_class(cwe: str) -> str:
    """Expected ASAN crash class for a confirmed CWE-X bug."""
    p = get_pattern(cwe) or {}
    ver = p.get("verification") or {}
    if isinstance(ver, dict):
        return ver.get("asan_class", "")
    return ""
