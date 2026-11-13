"""``infra-ledger`` subcommand: the public Infrastructure_Component_Ledger.

Reads ``docs/agent/infrastructure-component-ledger.json`` and reports every problem that
``check_infrastructure_ledger.check_public`` finds (Requirements 5.2, 5.4): only the three
public keys per row, one of the three match values, a real date, and no resource ID,
account ID, IP address or host name other than a placeholder. The checks live in
``scripts/check_infrastructure_ledger.py``; this module labels and prints them and does
not repeat them.

A row whose ``matched_on`` is over 90 days old (Requirement 5.8) is listed on stdout as
``needs re-check`` and does not change the exit code. Exactly 90 days is not listed; 91 is.
The private ledger is gitignored and not read here; compare it with
``python3 scripts/check_infrastructure_ledger.py --private <path>``.

A root without the ledger file scans 0 files and succeeds (as ``vex`` does without ``.vex/``;
the other fixtures' roots have none). This repository's own ledger is pinned by a test. A
ledger that is not valid JSON or cannot be read is ``Unparseable`` (exit code 2).
"""

from __future__ import annotations

import datetime as dt
import json
import re
import sys
from pathlib import Path

import check_infrastructure_ledger as ledger

from supply_chain_checks._common import Report, Unparseable, Violation

LEDGER_PATH = "docs/agent/infrastructure-component-ledger.json"
_ROW = re.compile(r"^row (\d+)")


def _row_line(text: str, index: int) -> int:
    """Return the 1-based line of the ``index``-th ``verified_version`` key (1 if absent)."""
    seen = -1
    for number, line in enumerate(text.split("\n"), start=1):
        if '"verified_version"' in line:
            seen += 1
            if seen == index:
                return number
    return 1


def _load(root: Path) -> tuple[str, object]:
    try:
        text = (root / LEDGER_PATH).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else type(exc).__name__
        raise Unparseable(LEDGER_PATH, f"cannot read: {reason}") from exc
    try:
        return text, json.loads(text)
    except json.JSONDecodeError as exc:
        raise Unparseable(LEDGER_PATH, f"not valid JSON: {exc.msg} (line {exc.lineno})", scanned=1) from exc


def check(root: Path, today: dt.date | None = None) -> Report:
    """Check the public ledger under ``root``.

    Args:
        root: Repository root, or a fixture directory that plays its role.
        today: The date the 90-day rule counts from (default: the current date).

    Returns:
        The report; one violation per problem.

    Raises:
        Unparseable: If the ledger cannot be read or is not JSON.
    """
    if not (root / LEDGER_PATH).exists():
        return Report()
    text, doc = _load(root)
    report = Report(scanned=1)
    for problem in ledger.check_public(doc):
        match = _ROW.match(problem)
        line = _row_line(text, int(match.group(1))) if match else 1
        report.violations.append(Violation(LEDGER_PATH, line, ledger.problem_kind(problem), problem))
    if isinstance(doc, dict) and isinstance(doc.get("rows"), list):
        rows = [r for r in doc["rows"] if isinstance(r, dict) and isinstance(r.get("verified_version"), str)]
        for version in ledger.stale_rows({"rows": rows}, today or dt.date.today()):
            sys.stdout.write(f"infra-ledger: needs re-check (over {ledger.RECHECK_DAYS} days): {version}\n")
    return report
