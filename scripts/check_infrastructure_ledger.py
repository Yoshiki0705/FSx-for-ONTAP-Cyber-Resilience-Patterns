#!/usr/bin/env python3
"""Check the public Infrastructure_Component_Ledger (and optionally the private one).

Public view: ``docs/agent/infrastructure-component-ledger.json``. Each row has only
``verified_version``, ``advisory_match`` and ``matched_on`` (Requirement 5.2), and holds no
account ID, resource ID, IP address or host name (Requirement 5.4). The private view
(``.private/supply-chain/...private.json``) holds every public row plus more (5.3).

The checks are pure functions over parsed JSON; ``main`` does the file reading.
Exit codes: 0 = no problem, 1 = problems found, 2 = a file could not be read.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any

MATCH_VALUES = ("該当あり", "該当なし", "判定保留")
PUBLIC_KEYS = frozenset({"verified_version", "advisory_match", "matched_on"})
PRIVATE_EXTRA_KEYS = frozenset(
    {
        "component_kind",
        "file_system_id",
        "running_version",
        "deployment_type",
        "verified_on",
        "management_endpoint",
    }
)
COMPONENT_PREFIXES = (
    "ONTAP ",
    "FSx for ONTAP ",
    "TrendAI ",
    "Deep Instinct ",
)
RECHECK_DAYS = 90

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_D_VERSION = re.compile(r"\d+\.\d+\.\d+P\d+D\d+")
_PLACEHOLDER_IDS = frozenset({"fs-0123456789abcdef0", "vpc-0123456789abcdef0"})
_SENSITIVE = (
    ("resource id", re.compile(r"\b(?:fs|vpc|subnet|sg|i|eni)-[0-9a-f]{8,17}\b")),
    ("account id", re.compile(r"(?<!\d)\d{12}(?!\d)")),
    ("ip address", re.compile(r"(?<!\d)\d{1,3}(?:\.\d{1,3}){3}(?!\d)")),
    ("host name", re.compile(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:amazonaws\.com|internal|local)\b")),
)


def _parse_date(value: str) -> dt.date | None:
    """Return the date for a ``YYYY-MM-DD`` string, or None if it is not a real date."""
    if not _DATE.match(value):
        return None
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        return None


def _sensitive_hits(text: str) -> list[str]:
    """Return the kinds of sensitive value found in text (placeholders excluded)."""
    hits: list[str] = []
    for kind, pattern in _SENSITIVE:
        for found in pattern.findall(text):
            if found in _PLACEHOLDER_IDS or found == "123456789012":
                continue
            if kind == "ip address" and found.startswith("10.0."):
                continue
            hits.append(kind)
            break
    return hits


def check_public(doc: Any) -> list[str]:
    """Return the problems in a parsed public ledger (empty list = clean)."""
    problems: list[str] = []
    rows = doc.get("rows") if isinstance(doc, dict) else None
    if not isinstance(rows, list) or not rows:
        return ["rows must be a non-empty list"]
    for i, row in enumerate(rows):
        where = f"row {i}"
        if not isinstance(row, dict):
            problems.append(f"{where}: not an object")
            continue
        if set(row) != PUBLIC_KEYS:
            problems.append(f"{where}: keys must be exactly {sorted(PUBLIC_KEYS)}, got {sorted(row)}")
            continue
        version, match, on = row["verified_version"], row["advisory_match"], row["matched_on"]
        if not isinstance(version, str) or not version.startswith(COMPONENT_PREFIXES):
            problems.append(f"{where}: verified_version must start with a component name")
            continue
        if match not in MATCH_VALUES:
            problems.append(f"{where}: advisory_match must be one of {MATCH_VALUES}")
        if on is not None and (not isinstance(on, str) or _parse_date(on) is None):
            problems.append(f"{where}: matched_on must be YYYY-MM-DD or null")
        if match in ("該当あり", "該当なし") and on is None:
            problems.append(f"{where}: a decided row needs matched_on")
        if match == "判定保留" and on is not None:
            problems.append(f"{where}: an undecided row keeps matched_on null unless it was decided before")
        if version.startswith(("ONTAP ", "FSx for ONTAP ")) and _D_VERSION.search(version) and match != "判定保留":
            problems.append(f"{where}: a D-suffixed version must stay 判定保留")
        for kind in _sensitive_hits(version):
            problems.append(f"{where}: verified_version holds a {kind}")
    note = doc.get("note", "")
    if not isinstance(note, str) or _sensitive_hits(note):
        problems.append("note must be a string without sensitive values")
    return problems


def check_private(public_doc: Any, private_doc: Any) -> list[str]:
    """Return the problems in the private ledger relative to the public one."""
    problems: list[str] = []
    pub_rows = public_doc.get("rows", []) if isinstance(public_doc, dict) else []
    priv_rows = private_doc.get("rows") if isinstance(private_doc, dict) else None
    if not isinstance(priv_rows, list):
        return ["private rows must be a list"]
    by_version: dict[str, dict[str, Any]] = {}
    for i, row in enumerate(priv_rows):
        if not isinstance(row, dict) or not (PUBLIC_KEYS | PRIVATE_EXTRA_KEYS) <= set(row):
            problems.append(f"private row {i}: missing keys")
            continue
        by_version[row["verified_version"]] = row
    for row in pub_rows:
        mine = by_version.get(row.get("verified_version"))
        if mine is None:
            problems.append(f"private ledger lacks the row {row.get('verified_version')!r}")
        elif (mine["advisory_match"], mine["matched_on"]) != (row["advisory_match"], row["matched_on"]):
            problems.append(f"private row {row['verified_version']!r} disagrees with the public one")
    return problems


def stale_rows(doc: Any, today: dt.date) -> list[str]:
    """Return the verified_version of rows whose matched_on is over 90 days old."""
    stale: list[str] = []
    for row in doc.get("rows", []):
        on = row.get("matched_on")
        parsed = _parse_date(on) if isinstance(on, str) else None
        if parsed is not None and (today - parsed).days > RECHECK_DAYS:
            stale.append(row["verified_version"])
    return stale


def main(argv: list[str] | None = None) -> int:
    """Run the checks on the files named on the command line."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public", default="docs/agent/infrastructure-component-ledger.json")
    parser.add_argument("--private", default=None, help="private ledger to compare (optional)")
    args = parser.parse_args(argv)
    try:
        public = json.loads(Path(args.public).read_text(encoding="utf-8"))
        private = json.loads(Path(args.private).read_text(encoding="utf-8")) if args.private else None
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"cannot read ledger: {exc}\n")
        return 2
    problems = check_public(public)
    if private is not None:
        problems += check_private(public, private)
    for line in problems:
        sys.stderr.write(f"infra-ledger: {line}\n")
    for version in stale_rows(public, dt.date.today()):
        sys.stdout.write(f"infra-ledger: needs re-check (over {RECHECK_DAYS} days): {version}\n")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
