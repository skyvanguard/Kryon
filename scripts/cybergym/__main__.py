"""Entry point: `python -m scripts.cybergym`."""

from __future__ import annotations

import sys

from scripts.cybergym.cli import main

if __name__ == "__main__":
    sys.exit(main())
