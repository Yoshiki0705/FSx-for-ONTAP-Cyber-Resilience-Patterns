"""``vex`` subcommand: the VEX documents under ``.vex/`` and who may read them.

Checks (design section 9, Requirements 11.4, 11.12, 11.13, 11.14):

* Every ``.vex/*.openvex.json`` parses with ``supply_chain.vex.parse_openvex``; each
  violation the parser collects becomes one violation of kind ``schema`` (this covers the
  ``not_affected`` justification and files that are not valid JSON).
* One statement per document (``statement-count``), the convention the design uses to
  record a judge per decision.
* A ``not_affected`` statement whose justification rests on whether code runs
  (``vulnerable_code_not_in_execute_path``, ``vulnerable_code_cannot_be_controlled_by_adversary``)
  carries evidence, a non-blank ``impact_statement`` (``evidence``). The text itself is not
  judged; only its absence fails.
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

import logging
import re
from pathlib import Path

from supply_chain_checks._common import Report, Unparseable, Violation, use_supply_chain_package
from supply_chain_checks.policy import line_of

LOGGER = logging.getLogger(__name__)

#: Directory of VEX documents, relative to the checked root.
VEX_DIR = ".vex"
#: ``not_affected`` justifications that rest on what code does at run time.
EVIDENCE_JUSTIFICATIONS = (
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
)
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


def _document_violations(rel: str, text: str) -> list[Violation]:
    use_supply_chain_package()
    from supply_chain.vex import MALICIOUS_PREFIX, VexError, parse_openvex  # noqa: PLC0415

    try:
        doc = parse_openvex(text, rel)
    except VexError as exc:
        return [
            Violation(rel, line_of(text, "$." + v.location), "schema", f"{v.location}: {v.message}")
            for v in exc.violations
        ]
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
        if (
            statement.status == "not_affected"
            and statement.justification in EVIDENCE_JUSTIFICATIONS
            and not (statement.impact_statement or "").strip()
        ):
            violations.append(
                Violation(
                    rel,
                    line_of(text, "$.statements"),
                    "evidence",
                    f"statements[{index}].impact_statement: {statement.justification} needs evidence"
                    " (how it was analysed, the call path)",
                )
            )
        if any(i.upper().startswith(MALICIOUS_PREFIX) for i in (statement.vuln_id, *statement.aliases)):
            LOGGER.warning(
                "%s: warning: statements[%d] names a MAL- ID; the Aggregator will not use it to suppress a finding",
                rel,
                index,
            )
    return violations


def check(root: Path) -> Report:
    """Check ``.vex/`` and the scanner-facing files under ``root``.

    Args:
        root: The repository root, or a directory that plays its role.

    Returns:
        A report with every violation; ``scanned`` is the number of VEX documents read.

    Raises:
        Unparseable: A file is unreadable or not UTF-8.
    """
    report = Report()
    vex_dir = root / VEX_DIR
    names = sorted(p.name for p in vex_dir.glob("*.openvex.json") if p.is_file()) if vex_dir.is_dir() else []
    for name in names:
        rel = f"{VEX_DIR}/{name}"
        text = _read(root, rel, report.scanned)
        report.scanned += 1
        report.violations.extend(_document_violations(rel, text))
    report.violations.extend(_scanner_violations(root, report.scanned))
    return report
