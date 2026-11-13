"""Thin I/O layer of the watchdog: reads record files, prints a verdict, sets the exit code.

Usage: ``python -m supply_chain.watchdog_cli --runs-dir <checkout>/runs``
Exit code 0 when the newest record is within the limit, 1 when it is stale or
missing. The workflow that calls this lives in the Hub (handoff 15.2).
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from supply_chain import watchdog

LOGGER = logging.getLogger("supply_chain.watchdog")


def read_record_texts(runs_dir: Path) -> list[str]:
    """Reads every ``*.json`` file under ``runs_dir`` (empty list if it is absent)."""
    if not runs_dir.is_dir():
        return []
    return [p.read_text(encoding="utf-8") for p in sorted(runs_dir.rglob("*.json"))]


def main(argv: Sequence[str] | None = None, now: datetime | None = None) -> int:
    """Runs the check.

    Args:
        argv: Command line arguments.
        now: Clock override for tests; defaults to the current UTC time.

    Returns:
        0 if fresh, 1 if stale or no record.
    """
    parser = argparse.ArgumentParser(prog="watchdog")
    parser.add_argument("--runs-dir", type=Path, required=True)
    parser.add_argument("--limit-hours", type=float, default=watchdog.DEFAULT_LIMIT_HOURS)
    args = parser.parse_args(argv)
    result = watchdog.check(
        read_record_texts(args.runs_dir),
        now or datetime.now(UTC),
        args.limit_hours,
    )
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    LOGGER.info(
        "stale=%s latest_saved_at=%s invalid_records=%d limit_hours=%s",
        result.stale,
        result.latest_saved_at.isoformat() if result.latest_saved_at else None,
        result.invalid_records,
        args.limit_hours,
    )
    return 1 if result.stale else 0


if __name__ == "__main__":
    sys.exit(main())
