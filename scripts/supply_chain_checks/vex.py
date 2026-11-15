"""``vex`` subcommand: the VEX documents under ``.vex/`` and who may read them.

Checks (design section 9, Requirements 11.4, 11.12, 11.13, 11.14):

* Every ``.vex/*.openvex.json`` parses with ``supply_chain.vex.parse_openvex``; each
  violation the parser collects becomes one violation of kind ``schema`` (this covers the
  ``not_affected`` justification and files that are not valid JSON).
* One statement per document (``statement-count``), the convention the design uses to
  record a judge per decision.
* Every ``not_affected`` statement and every ``fixed`` statement carries evidence, a non-blank
  ``impact_statement`` (``evidence``; T2-04). This is the condition under which
  ``supply_chain.vex.effective_exclusions`` uses a statement at all, whatever the justification.
  The text itself is not judged; only its absence fails.
* The gate runs ``effective_exclusions`` over the documents with the Policy_File's ``vex`` section
  and the current time, so it agrees with the Aggregator about which statements are unusable:
  a statement later than now plus five minutes (``timestamp-future``) and a product that is not a
  purl (``product``) fail; a statement older than ``vex.max_age_days`` (``vex_expired``) or overridden
  by a newer one (``vex_superseded``) only warns, because both are the normal course of a record
  and would otherwise fail every pull request once a judgment ages. Whether the vulnerability was
  listed in the KEV catalog after the judgment (``vex_predates_kev``) needs the catalog; this offline
  gate cannot know it, and the Aggregator records it in ``rejected_vex``.
* A statement names at most one CVE in its ``name`` and ``aliases`` together (``multi-cve``, T12-R5-05): the
  Aggregator excludes every identifier a statement names, so a second CVE would be covered by a judgment
  about the first.
* No workflow, composite action or Makefile hands a VEX document to a layer B scanner
  (``vex-to-scanner``): ``--vex``, ``TRIVY_VEX``, or ``.vex/`` on a line of a scanner call.
  Only the Aggregator reads ``.vex/``.

A document with a ``MAL-`` statement is valid; it is reported as a warning on stderr
through ``logging`` and does not change the exit code. ``Report`` has no warning field,
and the shared module is not changed by this subcommand.

Without a ``.vex/`` directory the subcommand scans 0 VEX files and succeeds. ``scanned``
counts VEX documents only, not the workflow files read for the scanner check. A file that
cannot be read or decoded as UTF-8 is ``Unparseable`` (exit code 2).
"""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from supply_chain_checks._common import Report, Unparseable, Violation, use_supply_chain_package
from supply_chain_checks.policy import line_of

LOGGER = logging.getLogger(__name__)

#: Directory of VEX documents, relative to the checked root.
VEX_DIR = ".vex"
#: Statuses whose statement must carry an ``impact_statement`` (the statuses ``effective_exclusions`` applies).
EVIDENCE_STATUSES = ("not_affected", "fixed")
#: Where the Policy_File's ``vex`` section is read for ``vex_exclude_statuses`` and ``vex_max_age_days``.
POLICY_PATH = "docs/agent/supply-chain-policy.json"
_SCANNER_FLAG = re.compile(r"(?:^|\s)--vex(?:[\s=]|$)|\bTRIVY_VEX\b")
_SCANNER_CALL = re.compile(r"\b(?:trivy|grype|osv-scanner|snyk|inspector)\b", re.IGNORECASE)
_VEX_REF = re.compile(r"\.vex/|\.openvex\.json")
_COMMENT = re.compile(r"(?:^|\s)#.*$")


def _read(root: Path, rel: str, scanned: int) -> str:
    try:
        return (root / rel).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else type(exc).__name__
        raise Unparseable(rel, f"cannot read the file: {reason}", scanned=scanned) from exc


def _scanner_files(root: Path) -> list[str]:
    """List workflow, composite action and Makefile paths under ``root``, sorted."""
    found: list[Path] = []
    workflows = root / ".github" / "workflows"
    if workflows.is_dir():
        found += [p for p in workflows.iterdir() if p.suffix in {".yml", ".yaml"}]
    actions = root / ".github" / "actions"
    if actions.is_dir():
        found += [p for p in actions.rglob("*") if p.name in {"action.yml", "action.yaml"}]
    # Match the names against the directory listing: on a case-insensitive file system
    # ``root / "makefile"`` would also open ``Makefile`` and report it twice.
    found += [p for p in root.iterdir() if p.name in {"Makefile", "makefile", "GNUmakefile"}]
    return sorted({p.relative_to(root).as_posix() for p in found if p.is_file()})


def _scanner_violations(root: Path, scanned: int) -> list[Violation]:
    violations: list[Violation] = []
    for rel in _scanner_files(root):
        for number, raw in enumerate(_read(root, rel, scanned).split("\n"), start=1):
            line = _COMMENT.sub("", raw)
            if _SCANNER_FLAG.search(line) or (_SCANNER_CALL.search(line) and _VEX_REF.search(line)):
                violations.append(
                    Violation(
                        rel,
                        number,
                        "vex-to-scanner",
                        "a VEX document is handed to a layer B scanner; only the Aggregator reads .vex/",
                    )
                )
    return violations


def _document_violations(rel: str, text: str, parsed: list[Any]) -> list[Violation]:
    use_supply_chain_package()
    from supply_chain.canonical import canonical_id  # noqa: PLC0415
    from supply_chain.vex import MALICIOUS_PREFIX, VexError, parse_openvex  # noqa: PLC0415

    try:
        doc = parse_openvex(text, rel)
    except VexError as exc:
        return [
            Violation(rel, line_of(text, "$." + v.location), "schema", f"{v.location}: {v.message}")
            for v in exc.violations
        ]
    parsed.append(doc)
    violations: list[Violation] = []
    if len(doc.statements) != 1:
        violations.append(
            Violation(
                rel,
                line_of(text, "$.statements"),
                "statement-count",
                f"a document holds exactly 1 statement, found {len(doc.statements)}",
            )
        )
    for index, statement in enumerate(doc.statements):
        if statement.status in EVIDENCE_STATUSES and not (statement.impact_statement or "").strip():
            violations.append(
                Violation(
                    rel,
                    line_of(text, "$.statements"),
                    "evidence",
                    f"statements[{index}].impact_statement: a {statement.status} statement needs evidence"
                    " (how it was analysed, the call path, the fixed version)",
                )
            )
        # The same spelling the Aggregator matches with (strip and upper case), so that " CVE-2026-0002" is the CVE
        # it will exclude and not a different string (T12-R6-03).
        cves = {canonical_id(i) for i in (statement.vuln_id, *statement.aliases) if canonical_id(i).startswith("CVE-")}
        if len(cves) > 1:
            # The Aggregator excludes every identifier a statement names (Requirement 11.37), so one judgment
            # would cover CVEs nobody judged, and the file name shows only one of them (T12-R5-05).
            violations.append(
                Violation(
                    rel,
                    line_of(text, "$.statements"),
                    "multi-cve",
                    f"statements[{index}] names {len(cves)} different CVEs ({', '.join(sorted(cves))}); "
                    "write one statement per CVE",
                )
            )
        if any(i.upper().startswith(MALICIOUS_PREFIX) for i in (statement.vuln_id, *statement.aliases)):
            LOGGER.warning(
                "%s: warning: statements[%d] names a MAL- ID; the Aggregator will not use it to suppress a finding",
                rel,
                index,
            )
    return violations


def _vex_policy(root: Path) -> Any:
    """Return an object with the two ``vex`` settings ``effective_exclusions`` reads.

    The Policy_File is read as raw JSON; an absent, unreadable or malformed file falls back to the
    schema's values (both statuses, ``DEFAULT_VEX_MAX_AGE_DAYS``), because the ``policy`` subcommand
    is the one that reports a bad Policy_File.
    """
    statuses: tuple[str, ...] = EVIDENCE_STATUSES
    max_age: int | None = None
    try:
        vex = json.loads((root / POLICY_PATH).read_text(encoding="utf-8")).get("vex", {})
        listed = vex.get("exclude_statuses")
        if isinstance(listed, list) and all(isinstance(i, str) for i in listed):
            statuses = tuple(listed)
        days = vex.get("max_age_days")
        if isinstance(days, int) and not isinstance(days, bool) and days >= 1:
            max_age = days
    except (OSError, UnicodeDecodeError, ValueError, AttributeError):
        pass
    return SimpleNamespace(vex_exclude_statuses=statuses, vex_max_age_days=max_age)


def _time_violations(root: Path, docs: list[Any], now: datetime) -> list[Violation]:
    """Apply ``effective_exclusions`` and report why a statement is unusable (T2-04)."""
    from supply_chain.vex import (  # noqa: PLC0415
        REASON_EXPIRED,
        REASON_FUTURE,
        REASON_SUPERSEDED,
        REASON_UNPARSEABLE,
        effective_exclusions,
    )

    _, rejected = effective_exclusions(docs, _vex_policy(root), now=now)
    out: list[Violation] = []
    for path, reason in rejected:
        if reason == REASON_FUTURE:
            out.append(Violation(path, 1, "timestamp-future", "the statement is dated later than now plus 5 minutes"))
        elif reason == REASON_UNPARSEABLE:
            out.append(Violation(path, 1, "product", "a product is not a purl, so no Finding can match it"))
        elif reason in (REASON_EXPIRED, REASON_SUPERSEDED):
            LOGGER.warning("%s: warning: %s; the Aggregator does not use this statement", path, reason)
    return out


def check(root: Path, *, now: datetime | None = None) -> Report:
    """Check ``.vex/`` and the scanner-facing files under ``root``.

    Args:
        root: The repository root, or a directory that plays its role.
        now: The time the statements are judged against; the current time when omitted.

    Returns:
        A report with every violation; ``scanned`` is the number of VEX documents read.

    Raises:
        Unparseable: A file is unreadable or not UTF-8.
    """
    report = Report()
    parsed: list[Any] = []
    vex_dir = root / VEX_DIR
    names = sorted(p.name for p in vex_dir.glob("*.openvex.json") if p.is_file()) if vex_dir.is_dir() else []
    for name in names:
        rel = f"{VEX_DIR}/{name}"
        text = _read(root, rel, report.scanned)
        report.scanned += 1
        report.violations.extend(_document_violations(rel, text, parsed))
    if parsed:
        report.violations.extend(_time_violations(root, parsed, now or datetime.now(UTC)))
    report.violations.extend(_scanner_violations(root, report.scanned))
    return report
