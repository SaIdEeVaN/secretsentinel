#!/usr/bin/env python3
"""Thin launcher so the CLI works from a source checkout without installation.

    python cli/secretsentinel_cli.py scan both .

Installed users should simply run ``secretsentinel`` (console script).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from secretsentinel.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
