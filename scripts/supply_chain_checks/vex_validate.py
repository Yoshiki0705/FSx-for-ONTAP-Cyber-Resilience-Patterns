"""``vex-validate`` subcommand: a pull request that changes ``.vex/`` needs a person's reasoned approval.

Task 11.22, Requirements 11.21, 11.22, 11.38, 11.39, 11.40. The judgment of a VEX statement is a person's. It is
written in the *review* of the approver, not in the pull request body: the body can be edited by the author of the
pull request, so it cannot show another person's decision (11.38).

The gate reads one JSON file and never touches the network (it is registered in ``make test``). The workflow
``.github/workflows/vex-validate.yml`` writes the file from the GitHub API; a test writes it by hand.

Input file (path in the environment variable ``VEX_VALIDATE_INPUT``, else ``<root>/.vex-validate-input.json``)::

    {"pull_request": {"user": "<author login>", "head_sha": "<head commit>", "body": "<pull request body>"},
     "files": ["<changed path>", ...],
     "reviews": [{"user": "<login>", "state": "APPROVED", "commit_id": "<sha>", "body": "<review body>"}, ...]}

Checks, only when a changed file is under the VEX directory (``vex.directory`` of the Policy_File, else ``.vex``):

* ``approval-missing``: no review in state ``APPROVED`` by a user other than the author. A reviewer's latest
  ``APPROVED``, ``CHANGES_REQUESTED`` or ``DISMISSED`` review counts; ``COMMENTED`` does not change it.
* ``self-approval``: the only approvals are the author's own.
* ``commit-mismatch``: the approval was given to a commit other than the head of the pull request (7.16 (3), 11.39).
* ``reason-heading-missing``: the approval's body has no heading ``判断理由``.
* ``reason-too-short``: the text under that heading has fewer than 20 characters.
* ``machine-field-missing`` / ``machine-field-invalid``: the pull request body lacks one of the fields the tool
  fills in (reachability command, the SHA-256 of its output, target purl, advisory URL and its SHA-256), or one is
  not in the form it names. The template ``.github/PULL_REQUEST_TEMPLATE/vex.md`` has only these fields.

One approval that passes every check is enough. When none does, each approval of another user reports why.
A pull request that changes nothing under the VEX directory is out of scope and passes. Without an input file the
subcommand scans 0 files and succeeds (the repository itself has no pull request to read).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from supply_chain_checks._common import Report, Unparseable, Violation

#: Where a fixture or the workflow puts the input when the environment variable is absent.
DEFAULT_INPUT = ".vex-validate-input.json"
POLICY_PATH = "docs/agent/supply-chain-policy.json"
DEFAULT_VEX_DIR = ".vex"
#: Heading that the approver's review must carry, and the length of the text under it (11.38).
REASON_HEADING = "判断理由"
MIN_REASON_CHARS = 20
#: Fields the tool fills in, as ``- key: value`` lines of the pull request body.
MACHINE_FIELDS = (
    "reachability_command",
    "reachability_output_sha256",
    "target_purl",
    "advisory_url",
    "advisory_sha256",
)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_HEADING = re.compile(r"^\s{0,3}#{1,6}\s*(.*?)\s*#*\s*$")
_FIELD = re.compile(r"^\s*[-*]\s*([a-z0-9_]+)\s*:(.*)$")
_STATES = ("APPROVED", "CHANGES_REQUESTED", "DISMISSED")


def _load(root: Path) -> tuple[str, dict[str, Any]]:
    override = os.environ.get("VEX_VALIDATE_INPUT")
    path = Path(override) if override else root / DEFAULT_INPUT
    shown = path.name if override else DEFAULT_INPUT
    if not path.is_file():
        return shown, {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise Unparseable(shown, f"cannot read the pull request input: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("pull_request"), dict):
        raise Unparseable(shown, "the input must be an object with a 'pull_request' object")
    return shown, data


def _vex_dir(root: Path) -> str:
    try:
        policy = json.loads((root / POLICY_PATH).read_text(encoding="utf-8"))
        value = policy["vex"]["directory"]
    except (OSError, ValueError, KeyError, TypeError):
        return DEFAULT_VEX_DIR
    return value if isinstance(value, str) and value else DEFAULT_VEX_DIR


def _reason_text(body: str) -> str | None:
    """Returns the text under the ``判断理由`` heading, or ``None`` when the heading is absent."""
    lines = body.splitlines()
    for index, line in enumerate(lines):
        match = _HEADING.match(line)
        if match and match.group(1) == REASON_HEADING:
            rest: list[str] = []
            for follower in lines[index + 1 :]:
                if _HEADING.match(follower):
                    break
                rest.append(follower)
            return "\n".join(rest).strip()
    return None


def _approvals(reviews: list[Any], author: str) -> tuple[list[dict[str, Any]], bool]:
    """Returns the standing approvals of users other than the author, and whether the author approved."""
    latest: dict[str, dict[str, Any]] = {}
    for review in reviews:
        if isinstance(review, dict) and review.get("state") in _STATES and isinstance(review.get("user"), str):
            latest[review["user"].lower()] = review
    standing = [r for r in latest.values() if r["state"] == "APPROVED"]
    others = [r for r in standing if r["user"].lower() != author.lower()]
    return others, len(others) != len(standing)


def _review_problem(review: dict[str, Any], head_sha: str) -> tuple[str, str] | None:
    if review.get("commit_id") != head_sha:
        return (
            "commit-mismatch",
            f"{review['user']}'s approval is for {review.get('commit_id')!r}, not the head {head_sha!r}",
        )
    reason = _reason_text(review.get("body") or "")
    if reason is None:
        return "reason-heading-missing", f"the approval of {review['user']} has no '{REASON_HEADING}' heading"
    if len(reason) < MIN_REASON_CHARS:
        return (
            "reason-too-short",
            f"the text under '{REASON_HEADING}' has {len(reason)} characters (need {MIN_REASON_CHARS})",
        )
    return None


def _machine_problems(body: str) -> list[tuple[str, str]]:
    found: dict[str, str] = {}
    for line in body.splitlines():
        match = _FIELD.match(line)
        if match and match.group(1) in MACHINE_FIELDS:
            found.setdefault(match.group(1), match.group(2).strip().strip("`").strip())
    problems: list[tuple[str, str]] = []
    for name in MACHINE_FIELDS:
        value = found.get(name, "")
        if not value:
            problems.append(("machine-field-missing", f"the pull request body has no value for '{name}'"))
        elif name.endswith("sha256") and not _SHA256.fullmatch(value):
            problems.append(("machine-field-invalid", f"'{name}' is not a lower-case hex SHA-256"))
        elif name == "target_purl" and not value.startswith("pkg:"):
            problems.append(("machine-field-invalid", "'target_purl' is not a purl"))
        elif name == "advisory_url" and not value.startswith("https://"):
            problems.append(("machine-field-invalid", "'advisory_url' is not an https URL"))
    return problems


def check(root: Path) -> Report:
    """Checks the pull request input; see the module docstring.

    Args:
        root: The checked tree (the Policy_File is read from it; the input file is read from it unless
            ``VEX_VALIDATE_INPUT`` names another path).

    Returns:
        The report; ``scanned`` is 1 when an input was read, 0 when there was none.

    Raises:
        Unparseable: The input exists but is not a JSON object with a ``pull_request`` object.
    """
    shown, data = _load(root)
    if not data:
        return Report()
    report = Report(scanned=1)
    files = [f for f in data.get("files", []) if isinstance(f, str)]
    prefix = _vex_dir(root).rstrip("/") + "/"
    if not any(f.startswith(prefix) for f in files):
        return report  # not a VEX change: out of scope (11.40)
    pr = data["pull_request"]
    author = str(pr.get("user") or "")
    head = str(pr.get("head_sha") or "")

    def add(kind: str, detail: str) -> None:
        report.violations.append(Violation(shown, 1, kind, detail))

    approvals, self_approved = _approvals(data.get("reviews") or [], author)
    if not approvals:
        if self_approved:
            add("self-approval", "the only approval is the author's own; another user must approve")
        else:
            add("approval-missing", "no APPROVED review by a user other than the author")
    else:
        problems = [_review_problem(r, head) for r in approvals]
        if all(problems):
            for problem in problems:
                if problem is not None:
                    add(*problem)
    for kind, detail in _machine_problems(str(pr.get("body") or "")):
        add(kind, detail)
    return report
