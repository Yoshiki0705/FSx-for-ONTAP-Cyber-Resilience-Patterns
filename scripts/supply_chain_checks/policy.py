"""``policy`` subcommand: the Policy_File parses without a single issue.

Reads ``docs/agent/supply-chain-policy.json`` with ``supply_chain.policy.parse_policy``.
The parser already holds the rules the design lists for this gate: the four default
exclusions (``missing``), ``open_if_malicious`` fixed to ``true`` (``range``), and the
cross-field checks. Every issue it collects becomes one violation. A file that is absent,
unreadable or not JSON is not a violation but ``Unparseable`` (exit code 2).
"""

from __future__ import annotations

import re
from pathlib import Path

from supply_chain_checks._common import Report, Unparseable, Violation, use_supply_chain_package

#: Where the Policy_File lives, relative to the checked root.
POLICY_PATH = "docs/agent/supply-chain-policy.json"

_TOKEN = re.compile(r"\.([A-Za-z_][A-Za-z0-9_]*)|\[(\d*)\]")


def line_of(text: str, json_path: str) -> int:
    """Find the line of the last key in a ``$.a.b[2].c`` style path.

    Each key is searched for after the line of the key before it. Array indexes are not
    resolved, so an item of an array reports the line of the array's key.

    Args:
        text: The file's text.
        json_path: A path in the form that ``supply_chain.policy`` reports.

    Returns:
        A 1-based line number; 1 when no key is found.
    """
    lines = text.split("\n")
    here = 0
    for key in (m.group(1) for m in _TOKEN.finditer(json_path) if m.group(1)):
        pattern = re.compile(r'"' + re.escape(key) + r'"\s*:')
        for index in range(here, len(lines)):
            if pattern.search(lines[index]):
                here = index
                break
    return here + 1


def check(root: Path) -> Report:
    """Parse the Policy_File under ``root``.

    Args:
        root: The repository root, or a directory that plays its role.

    Returns:
        A report with one violation per parser issue and ``scanned`` of 1.

    Raises:
        Unparseable: The file is absent, unreadable, or not valid JSON.
    """
    use_supply_chain_package()
    from supply_chain.policy import PolicyError, parse_policy  # noqa: PLC0415

    target = root / POLICY_PATH
    try:
        text = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else type(exc).__name__
        raise Unparseable(POLICY_PATH, f"cannot read the Policy_File: {reason}") from exc
    try:
        parse_policy(text)
    except PolicyError as exc:
        if any(issue.kind == "invalid_json" for issue in exc.issues):
            detail = "; ".join(issue.detail for issue in exc.issues if issue.kind == "invalid_json")
            raise Unparseable(POLICY_PATH, f"not valid JSON: {detail}", scanned=1) from exc
        violations = [
            Violation(POLICY_PATH, line_of(text, issue.path), issue.kind, f"{issue.path} {issue.detail}")
            for issue in exc.issues
        ]
        return Report(violations=violations, scanned=1)
    return Report(scanned=1)
