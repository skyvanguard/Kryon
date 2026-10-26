#!/usr/bin/env python3
"""py_patch.py — safe in-place text patcher (no silent no-ops).

Usage: py_patch.py TARGET OLD_FILE NEW_FILE
  - TARGET: file to patch (read+written in UTF-8)
  - OLD_FILE: file containing the exact anchor text (may be multi-line)
  - NEW_FILE: file containing the replacement text

Behavior: asserts the anchor occurs EXACTLY ONCE, replaces it, exits 0.
Exit 1: anchor not found OR found more than once (nothing is modified).
This exists because silent replace-no-ops are the #1 source of "my patch
did not apply" debugging loops.
"""
import sys

def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__)
        return 2
    target, old_f, new_f = sys.argv[1], sys.argv[2], sys.argv[3]
    t = open(target, encoding="utf-8").read()
    old = open(old_f, encoding="utf-8").read()
    new = open(new_f, encoding="utf-8").read()
    n = t.count(old)
    if n == 0:
        print("PATCH_FAIL: anchor not found in " + target + " (head: " + repr(old[:60]) + ")")
        return 1
    if n > 1:
        print("PATCH_FAIL: anchor occurs " + str(n) + " times in " + target + " — make it unique")
        return 1
    open(target, "w", encoding="utf-8").write(t.replace(old, new, 1))
    print("PATCH_OK: " + target + " (" + str(len(old)) + " -> " + str(len(new)) + " bytes)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
