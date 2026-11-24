"""Run the configuration probe without installing it: ``python solutions/config-probe/probe.py --help``."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from config_probe.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
