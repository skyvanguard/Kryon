"""Entrypoint so `python -m scripts.ci` resolves to the audit CLI."""

from __future__ import annotations

import sys

from scripts.ci.kryon_audit import main

if __name__ == "__main__":
    sys.exit(main())
