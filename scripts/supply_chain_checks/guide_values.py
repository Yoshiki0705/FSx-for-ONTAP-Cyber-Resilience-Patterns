"""``guide-values`` subcommand: numbers in the Adoption_Guide equal the Policy_File's.

A number that the Policy_File owns is written in the guide right after a marker,
``<!-- policy:<key path> -->3 days``. This subcommand reads the whole number after each marker
and compares it with the value at that key path of ``docs/agent/supply-chain-policy.json``
(Requirement 21.10). It fails when:

* a marker's number differs from the Policy_File, the key path does not exist or is not a
  whole number, or no number follows the marker;
* a guide (Japanese or English) holds no marker at all, so the comparison would check
  nothing;
* a guide lacks a marker for the Cooldown values or for the Response_Target values,
  including the reference value for High and above (``response_target.fix_days_high``,
  14 days). Writing such a number as plain text would escape the comparison.

The Programme_Document carries markers of the same form (it repeats the Response_Target). Its
markers are compared the same way when the file exists, but it is not required to have any.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from supply_chain_checks._common import Report, Unparseable, Violation

POLICY_PATH = "docs/agent/supply-chain-policy.json"
GUIDE_PATHS = ("docs/ja/supply-chain-adoption-guide.md", "docs/en/supply-chain-adoption-guide.md")
OPTIONAL_PATHS = ("docs/ja/cyber-resilience-programme.md", "docs/en/cyber-resilience-programme.md")
#: Key paths every guide must mark: the Cooldown and the Response_Target (14 days for High).
REQUIRED_KEYS = (
    "cooldown_days.default",
    "cooldown_days.major",
    "response_target.detect_hours",
    "response_target.fix_days_kev_or_malicious",
    "response_target.fix_days_high",
)

_MARKER = re.compile(r"<!--\s*policy:([^\s>]+?)\s*-->(\s*)(\d+)?")


def _read(root: Path, rel: str, scanned: int) -> str:
    try:
        return (root / rel).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else type(exc).__name__
        raise Unparseable(rel, f"cannot read: {reason}", scanned=scanned) from exc


def _lookup(policy: dict[str, Any], key_path: str) -> Any:
    """Return the value at a dotted key path, or ``None`` when a key is absent."""
    node: Any = policy
    for part in key_path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _check_file(rel: str, text: str, policy: dict[str, Any], *, required: bool) -> list[Violation]:
    out: list[Violation] = []
    seen: set[str] = set()
    count = 0
    for number, row in enumerate(text.split("\n"), start=1):
        for match in _MARKER.finditer(row):
            count += 1
            key, digits = match.group(1), match.group(3)
            seen.add(key)
            want = _lookup(policy, key)
            if isinstance(want, bool) or not isinstance(want, int):
                out.append(
                    Violation(rel, number, "unknown_key", f"policy:{key} is not a whole number in the Policy_File")
                )
            elif digits is None:
                out.append(Violation(rel, number, "format", f"no number follows the marker policy:{key}"))
            elif int(digits) != want:
                out.append(
                    Violation(rel, number, "mismatch", f"policy:{key} is {digits} here; Policy_File wants {want}")
                )
    if required:
        if count == 0:
            out.append(Violation(rel, 1, "no_markers", "no <!-- policy:... --> marker found; nothing was compared"))
        else:
            for key in REQUIRED_KEYS:
                if key not in seen:
                    out.append(
                        Violation(
                            rel,
                            1,
                            "missing_marker",
                            f"no marker for policy:{key}; a number written as plain text is not compared",
                        )
                    )
    return out


def check(root: Path) -> Report:
    """Compare the marked numbers in the guides with the Policy_File.

    Args:
        root: The repository root, or a directory that plays its role.

    Returns:
        A report with one violation per finding.

    Raises:
        Unparseable: The Policy_File is absent or not valid, or one guide is absent while the
            other exists. When neither guide exists nothing is checked (scanned 0).
    """
    if not any((root / rel).is_file() for rel in GUIDE_PATHS):
        return Report()  # a Spoke, or a tree made for another subcommand, has no Adoption_Guide
    scanned = 0
    policy_text = _read(root, POLICY_PATH, scanned)
    scanned += 1
    try:
        policy = json.loads(policy_text)
    except json.JSONDecodeError as exc:
        raise Unparseable(POLICY_PATH, f"not valid JSON: {exc.msg} (line {exc.lineno})", scanned=scanned) from exc
    if not isinstance(policy, dict):
        raise Unparseable(POLICY_PATH, "top level is not a JSON object", scanned=scanned)
    out: list[Violation] = []
    for rel in GUIDE_PATHS:
        text = _read(root, rel, scanned)
        scanned += 1
        out += _check_file(rel, text, policy, required=True)
    for rel in OPTIONAL_PATHS:
        if (root / rel).is_file():
            text = _read(root, rel, scanned)
            scanned += 1
            out += _check_file(rel, text, policy, required=False)
    return Report(violations=out, scanned=scanned)
