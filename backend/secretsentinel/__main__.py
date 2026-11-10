"""Allow ``python -m secretsentinel``."""

import sys

from .cli import main

sys.exit(main())
