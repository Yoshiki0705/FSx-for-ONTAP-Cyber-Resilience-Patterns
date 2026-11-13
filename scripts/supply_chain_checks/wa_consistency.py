"""``wa-consistency`` subcommand: one mapping table for Well-Architected IDs and CSF IDs.

The framework mapping holds the only table of Well-Architected best-practice (BP) IDs and the
only table that maps PDCA and accountability to NIST CSF 2.0 (Requirements 1.18, 1.23). The
Programme_Document and the Adoption_Guide link to them. For each language this subcommand
checks that:

1. every BP ID that appears in the Programme_Document or the Adoption_Guide is in the BP
   table of the framework mapping (Requirement 1.16);
2. no table row of those two documents holds two or more different BP IDs, which would be a
   copy of the mapping table (Requirement 1.18);
3. the BP table of the framework mapping has the same IDs and the same number of rows in
   Japanese and English (Requirement 21.12);
4. every CSF 2.0 ID in those two documents is a CSF ID that the framework mapping of the same
   language contains, and no table row holds two or more different CSF IDs (a copy of the CSF
   table); the CSF section of the framework mapping has the same IDs and rows in both
   languages and shows that its interpretive mapping is a ``hypothesis`` (Requirement 1.23).

A CSF ID may be a category (``GV.OV``) or a subcategory (``GV.OV-03``). A category is known
when the mapping contains it or any of its subcategories; a subcategory must appear itself.
"""

from __future__ import annotations

import re
from pathlib import Path

from supply_chain_checks._common import Report, Unparseable, Violation

LANGUAGES = ("ja", "en")
MAPPING = "docs/{lang}/cyber-resilience-framework-mapping.md"
CHECKED = ("docs/{lang}/cyber-resilience-programme.md", "docs/{lang}/supply-chain-adoption-guide.md")
BP_HEADINGS = {"ja": "ベストプラクティス ID との対応", "en": "Best-practice IDs"}
CSF_HEADINGS = {"ja": "PDCA と説明責任の CSF 2.0 への対応", "en": "Mapping PDCA and accountability to CSF 2.0"}

_BP = re.compile(r"\b(?:OPS|REL|SEC)\d{2}-BP\d{2}\b")
_CSF = re.compile(r"\b(?:GV|ID|PR|DE|RS|RC)\.[A-Z]{2}(?:-\d{2})?\b")
_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
_SEPARATOR = re.compile(r"^\|[\s:|-]+\|?\s*$")


def _read(root: Path, rel: str, scanned: int) -> str:
    try:
        return (root / rel).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else type(exc).__name__
        raise Unparseable(rel, f"cannot read: {reason}", scanned=scanned) from exc


def _section(lines: list[str], title: str) -> tuple[int, list[tuple[int, str]]] | None:
    """Return ``(heading line, [(line, text)...])`` of the section titled ``title``."""
    start = -1
    level = 0
    for index, row in enumerate(lines):
        match = _HEADING.match(row)
        if match and match.group(2) == title:
            start, level = index, len(match.group(1))
            break
    if start < 0:
        return None
    body: list[tuple[int, str]] = []
    for index in range(start + 1, len(lines)):
        match = _HEADING.match(lines[index])
        if match and len(match.group(1)) <= level:
            break
        body.append((index + 1, lines[index]))
    return start + 1, body


def _table_rows(body: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Return the data rows of the tables in ``body`` (not the header or separator rows)."""
    rows: list[tuple[int, str]] = []
    previous_was_table = False
    header_pending = False
    for number, row in body:
        is_row = row.lstrip().startswith("|")
        if is_row and not previous_was_table:
            header_pending = True
        elif is_row and header_pending:
            header_pending = False
        elif is_row and not _SEPARATOR.match(row):
            rows.append((number, row))
        previous_was_table = is_row
    return rows


def _ids(pattern: re.Pattern[str], text: str) -> list[str]:
    seen: list[str] = []
    for found in pattern.findall(text):
        if found not in seen:
            seen.append(found)
    return seen


def _compare(
    out: list[Violation],
    what: str,
    rels: dict[str, str],
    rows: dict[str, list[tuple[int, str]]],
    pattern: re.Pattern[str],
) -> None:
    """Report differences of the ID set and the row count between the two languages."""
    sets = {lang: {i for _, row in rows[lang] for i in _ids(pattern, row)} for lang in LANGUAGES}
    for lang, other in (("ja", "en"), ("en", "ja")):
        for missing in sorted(sets[other] - sets[lang]):
            out.append(
                Violation(
                    rels[lang],
                    1,
                    "language_mismatch",
                    f"{what} ID {missing} is in the {other} mapping but not in the {lang} one",
                )
            )
    if len(rows["ja"]) != len(rows["en"]):
        out.append(
            Violation(
                rels["en"],
                1,
                "language_mismatch",
                f"{what} table has {len(rows['en'])} row(s) in en and {len(rows['ja'])} in ja",
            )
        )


def _scan_documents(out: list[Violation], rel: str, text: str, bp: set[str], csf: set[str]) -> None:
    """Checks 1, 2 and the CSF part of 4 on one Programme_Document or Adoption_Guide."""
    for number, row in enumerate(text.split("\n"), start=1):
        is_row = row.lstrip().startswith("|") and not _SEPARATOR.match(row)
        for found in _ids(_BP, row):
            if found not in bp:
                out.append(
                    Violation(
                        rel,
                        number,
                        "unknown_bp_id",
                        f"{found} is not in the best-practice ID table of the framework mapping",
                    )
                )
        for found in _ids(_CSF, row):
            known = found in csf or (("-" not in found) and any(c.startswith(found + "-") for c in csf))
            if not known:
                out.append(
                    Violation(rel, number, "unknown_csf_id", f"{found} is not a CSF 2.0 ID in the framework mapping")
                )
        if is_row and len(_ids(_BP, row)) >= 2:
            out.append(
                Violation(
                    rel,
                    number,
                    "table_copy",
                    "a table row with two or more best-practice IDs looks like a copy of the mapping table; link to the framework mapping",
                )
            )
        if is_row and len(_ids(_CSF, row)) >= 2:
            out.append(
                Violation(
                    rel,
                    number,
                    "csf_table_copy",
                    "a table row with two or more CSF 2.0 IDs looks like a copy of the CSF table; link to the framework mapping",
                )
            )


def check(root: Path) -> Report:
    """Check the Well-Architected and CSF 2.0 IDs of the programme documents.

    Args:
        root: The repository root, or a directory that plays its role.

    Returns:
        A report with one violation per finding.

    Raises:
        Unparseable: A document is unreadable, or absent while another of the six exists. When
            none exists nothing is checked (scanned 0).
    """
    if not any((root / template.format(lang=lang)).is_file() for lang in LANGUAGES for template in (MAPPING, *CHECKED)):
        return Report()  # a Spoke, or a tree made for another subcommand, has none of these documents
    scanned = 0
    out: list[Violation] = []
    rels = {lang: MAPPING.format(lang=lang) for lang in LANGUAGES}
    bp_rows: dict[str, list[tuple[int, str]]] = {}
    csf_rows: dict[str, list[tuple[int, str]]] = {}
    bp_known: dict[str, set[str]] = {}
    csf_known: dict[str, set[str]] = {}
    for lang in LANGUAGES:
        rel = rels[lang]
        text = _read(root, rel, scanned)
        scanned += 1
        lines = text.split("\n")
        csf_known[lang] = set(_ids(_CSF, text))
        for name, headings, rows, known, pattern in (
            ("best-practice ID", BP_HEADINGS, bp_rows, bp_known, _BP),
            ("CSF 2.0", CSF_HEADINGS, csf_rows, None, _CSF),
        ):
            found = _section(lines, headings[lang])
            if found is None:
                out.append(Violation(rel, 1, "missing_section", f"no section titled {headings[lang]!r} ({name} table)"))
                rows[lang] = []
                if known is not None:
                    known[lang] = set()
                continue
            _, body = found
            rows[lang] = _table_rows(body)
            if known is not None:
                known[lang] = {i for _, row in rows[lang] for i in _ids(pattern, row)}
            if not rows[lang]:
                out.append(Violation(rel, found[0], "missing_table", f"the {name} section has no table rows"))
            if name == "CSF 2.0" and "hypothesis" not in "\n".join(row for _, row in body):
                out.append(
                    Violation(
                        rel,
                        found[0],
                        "missing_hypothesis",
                        "the CSF 2.0 section does not label its interpretive mapping as hypothesis",
                    )
                )
    _compare(out, "best-practice", rels, bp_rows, _BP)
    _compare(out, "CSF 2.0", rels, csf_rows, _CSF)
    for lang in LANGUAGES:
        for template in CHECKED:
            rel = template.format(lang=lang)
            text = _read(root, rel, scanned)
            scanned += 1
            _scan_documents(out, rel, text, bp_known[lang], csf_known[lang])
    return Report(violations=out, scanned=scanned)
