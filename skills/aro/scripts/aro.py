#!/usr/bin/env python3
"""Cross-platform ARO command entrypoint; Python 3.11 or newer is required."""

import sys
from pathlib import Path

if sys.version_info < (3, 11):
    raise SystemExit("ARO requires Python 3.11 or newer. Install Python, then run this command again.")

# A skill can be copied by itself; it does not need pip installation.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from aro_core.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
