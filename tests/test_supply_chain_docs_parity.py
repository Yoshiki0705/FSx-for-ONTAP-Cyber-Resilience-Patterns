"""Structural parity between the Japanese and English public documents.

The pairs under test are not listed here: ``docs/ja/`` and ``docs/en/`` are
enumerated at run time and every file name present in both directories is a
pair. A pair is compared on:

* the number of headings at each level,
* the number of data rows in each table, in document order,
* the number of notes (blockquote blocks),
* the reference list: the order of its URLs and its reference dates.

``docs/ontap-native/ontap-upgrade-for-security-advisories.md`` keeps both
languages in one file (``## 日本語 / English`` headings), so it is compared
between its two halves instead.

Feature: cyber-resilience-phase4-supply-chain, task 16.7.

**Validates: Requirements 1.4, 2.7, 20.1, 21.1, 24.5**
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCS_JA = ROOT / "docs" / "ja"
DOCS_EN = ROOT / "docs" / "en"
UPGRADE_DOC = ROOT / "docs" / "ontap-native" / "ontap-upgrade-for-security-advisories.md"

# Task 4.14: sections added to the pairs. Each pair of titles (JA, EN) names a
# section whose own structure must also match, so a change inside it cannot be
# hidden by an opposite change elsewhere in the file.
ADDED_SECTIONS = {
    "cyber-resilience-programme.md": [("説明責任の観点", "Accountability across the pillars")],
    "cyber-resilience-framework-mapping.md": [
        (
            "PDCA と説明責任の CSF 2.0 への対応",
            "Mapping PDCA and accountability to CSF 2.0",
        )
    ],
}

REFERENCE_TITLES_JA = ("参考文献", "参考フレームワーク・文献")
REFERENCE_TITLES_EN = ("References",)

_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
_FENCE = re.compile(r"^\s*(```|~~~)")
_URL = re.compile(r"\]\((https?://[^)\s]+)\)|(?<![(\"'])\bhttps?://[^\s)|>\"']+")
_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
_CJK = re.compile(r"[\u3040-\u30ff\u3400-\u9fff]")


_JA_DATE = re.compile(r"(令和|平成|\d{4})\s*(\d{1,2})?\s*年\s*(\d{1,2})\s*月\s*(\d{1,2})\s*日")
_ERA_OFFSET = {"令和": 2018, "平成": 1988}


def _dates(line: str) -> list[str]:
    """Return the dates in ``line`` as ISO strings, in order of appearance.

    Japanese notation (``令和 8 年 6 月 12 日``, ``2026 年 6 月 12 日``) is
    converted, so the same day written in either language compares equal.
    """
    found: list[tuple[int, str]] = [(m.start(), m.group(0)) for m in _DATE.finditer(line)]
    for m in _JA_DATE.finditer(line):
        era, era_year, month, day = m.group(1), m.group(2), int(m.group(3)), int(m.group(4))
        if era in _ERA_OFFSET:
            if era_year is None:
                continue
            year = _ERA_OFFSET[era] + int(era_year)
        else:
            year = int(era)
        found.append((m.start(), f"{year:04d}-{month:02d}-{day:02d}"))
    return [text for _, text in sorted(found)]


_LOCALE_SEGMENT = re.compile(r"^(https://aws\.amazon\.com)/jp/")


def _normalise_url(url: str) -> str:
    """Drop the Japanese locale segment (``/jp/``) of an AWS page URL and trailing punctuation.

    A Japanese document may link the Japanese rendering of the same AWS page;
    that is the same reference, so it must not count as a URL mismatch.
    """
    return _LOCALE_SEGMENT.sub(r"\1/", url).rstrip(".,;")


@dataclass
class Section:
    """One heading and the lines up to the next heading of any level."""

    level: int
    title: str
    lines: list[str] = field(default_factory=list)


def _outside_fences(text: str) -> list[str]:
    """Return the lines of ``text`` that are not inside a code fence."""
    kept: list[str] = []
    inside = False
    for line in text.splitlines():
        if _FENCE.match(line):
            inside = not inside
            continue
        if not inside:
            kept.append(line)
    return kept


def split_sections(text: str) -> list[Section]:
    """Split a Markdown text into sections. Lines before the first heading are dropped."""
    sections: list[Section] = []
    for line in _outside_fences(text):
        match = _HEADING.match(line)
        if match:
            sections.append(Section(len(match.group(1)), match.group(2)))
        elif sections:
            sections[-1].lines.append(line)
    return sections


def heading_counts(sections: list[Section]) -> dict[int, int]:
    """Count headings per level."""
    return dict(sorted(Counter(s.level for s in sections).items()))


def table_row_counts(lines: list[str]) -> list[int]:
    """Return the data-row count of each table, in order (header and separator excluded)."""
    counts: list[int] = []
    run = 0
    for line in [*lines, ""]:
        if line.lstrip().startswith("|"):
            run += 1
        elif run:
            counts.append(max(run - 2, 0))
            run = 0
    return counts


def note_count(lines: list[str]) -> int:
    """Count blockquote blocks (runs of lines that start with ``>``)."""
    blocks = 0
    inside = False
    for line in lines:
        quoted = line.lstrip().startswith(">")
        if quoted and not inside:
            blocks += 1
        inside = quoted
    return blocks


def body_lines(sections: list[Section]) -> list[str]:
    """Join the lines of every section."""
    return [line for s in sections for line in s.lines]


def reference_items(sections: list[Section], titles: tuple[str, ...]) -> list[tuple[list[str], list[str]]]:
    """Return ``(urls, dates)`` for each row or list item of the reference section.

    The reference section is the H2 section whose title is in ``titles``,
    including its sub-sections, up to the next H2.
    """
    items: list[tuple[list[str], list[str]]] = []
    inside = False
    for section in sections:
        if section.level == 2:
            inside = section.title in titles
        if not inside:
            continue
        for line in section.lines:
            stripped = line.strip()
            is_row = stripped.startswith("|") and not re.fullmatch(r"[|\-:\s]+", stripped)
            is_item = bool(re.match(r"([-*]|\d+\.)\s", stripped))
            if not (is_row or is_item):
                continue
            urls = [_normalise_url(m.group(1) or m.group(0)) for m in _URL.finditer(line)]
            dates = _dates(line)
            if urls or dates:
                items.append((urls, dates))
    return items


def signature(text: str) -> dict[str, object]:
    """Build the structural signature of one document."""
    sections = split_sections(text)
    lines = body_lines(sections)
    return {
        "headings": heading_counts(sections),
        "tables": table_row_counts(lines),
        "notes": note_count(lines),
    }


def find_pairs() -> list[str]:
    """Return the file names present in both ``docs/ja`` and ``docs/en``."""
    ja = {p.name for p in DOCS_JA.glob("*.md")}
    en = {p.name for p in DOCS_EN.glob("*.md")}
    return sorted(ja & en)


def compare_pair(ja_text: str, en_text: str, name: str) -> list[str]:
    """Return the list of mismatches between a Japanese and an English text."""
    problems: list[str] = []
    ja, en = signature(ja_text), signature(en_text)
    for key in ("headings", "tables", "notes"):
        if ja[key] != en[key]:
            problems.append(f"{name}: {key} differ: ja={ja[key]} en={en[key]}")
    ja_sections, en_sections = split_sections(ja_text), split_sections(en_text)
    ja_refs = reference_items(ja_sections, REFERENCE_TITLES_JA)
    en_refs = reference_items(en_sections, REFERENCE_TITLES_EN)
    ja_urls = [u for urls, _ in ja_refs for u in urls]
    en_urls = [u for urls, _ in en_refs for u in urls]
    ja_dates = [d for _, ds in ja_refs for d in ds]
    en_dates = [d for _, ds in en_refs for d in ds]
    if ja_urls != en_urls:
        only_ja = [u for u in ja_urls if u not in en_urls]
        only_en = [u for u in en_urls if u not in ja_urls]
        problems.append(
            f"{name}: reference URLs differ in content or order "
            f"(ja={len(ja_urls)}, en={len(en_urls)}, only_ja={only_ja[:3]}, only_en={only_en[:3]})"
        )
    if ja_dates != en_dates:
        problems.append(f"{name}: reference dates differ (ja={len(ja_dates)}, en={len(en_dates)})")
    for ja_title, en_title in ADDED_SECTIONS.get(name, []):
        ja_part = _section_signature(ja_sections, ja_title)
        en_part = _section_signature(en_sections, en_title)
        if ja_part is None or en_part is None:
            problems.append(f"{name}: added section missing (ja={ja_part is not None}, en={en_part is not None})")
        elif ja_part != en_part:
            problems.append(f"{name}: added section '{en_title}' differs: ja={ja_part} en={en_part}")
    return problems


def _section_signature(sections: list[Section], title: str) -> dict[str, object] | None:
    """Return the signature of the section with ``title`` and its sub-sections, or ``None``."""
    for index, section in enumerate(sections):
        if section.title != title:
            continue
        end = index + 1
        while end < len(sections) and sections[end].level > section.level:
            end += 1
        part = sections[index:end]
        return {
            "headings": heading_counts(part),
            "tables": table_row_counts(body_lines(part)),
            "notes": note_count(body_lines(part)),
        }
    return None


def split_upgrade_headings(text: str) -> tuple[list[str], list[str]]:
    """Return the Japanese and English halves of the H2 headings of the upgrade document.

    A heading without the `` / `` separator contributes an empty half to the
    side that is missing, which the caller reports as a mismatch.
    """
    ja: list[str] = []
    en: list[str] = []
    for section in split_sections(text):
        if section.level != 2:
            continue
        ja_part, sep, en_part = section.title.partition(" / ")
        ja.append(ja_part if sep else "")
        en.append(en_part)
    return ja, en


def upgrade_items(text: str) -> tuple[int, int]:
    """Count procedure items (table rows) in the Japanese and English tables of the stage sections.

    A table belongs to the Japanese side when its header row has Japanese
    characters. The stage sections are the H2 sections whose heading starts
    with ``段階``.
    """
    ja_rows = en_rows = 0
    for section in split_sections(text):
        if section.level != 2 or not section.title.startswith("段階"):
            continue
        table: list[str] = []
        for line in [*section.lines, ""]:
            if line.lstrip().startswith("|"):
                table.append(line)
                continue
            if table:
                rows = max(len(table) - 2, 0)
                if _CJK.search(table[0]):
                    ja_rows += rows
                else:
                    en_rows += rows
                table = []
    return ja_rows, en_rows


# --------------------------------------------------------------------------- tests

PAIRS = find_pairs()


def test_pairs_are_enumerated_from_the_directories() -> None:
    """The set of pairs is read from disk and is not empty."""
    assert PAIRS, "no file name is present in both docs/ja and docs/en"
    for name in ("cyber-resilience-programme.md", "supply-chain-adoption-guide.md"):
        assert name in PAIRS


@pytest.mark.parametrize("name", PAIRS)
def test_pair_structure_matches(name: str) -> None:
    """Each pair has the same headings, table rows, notes and reference list."""
    problems = compare_pair(
        (DOCS_JA / name).read_text(encoding="utf-8"),
        (DOCS_EN / name).read_text(encoding="utf-8"),
        name,
    )
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize("name", ["cyber-resilience-programme.md", "supply-chain-adoption-guide.md"])
def test_reference_lists_are_not_empty(name: str) -> None:
    """A parity check on an empty reference list would pass without checking anything."""
    ja = reference_items(split_sections((DOCS_JA / name).read_text(encoding="utf-8")), REFERENCE_TITLES_JA)
    en = reference_items(split_sections((DOCS_EN / name).read_text(encoding="utf-8")), REFERENCE_TITLES_EN)
    assert len(ja) >= 10
    assert len(en) >= 10


def test_added_sections_exist_in_both_languages() -> None:
    """The sections added in 4.14 (accountability, CSF mapping) are found by title."""
    for name, titles in ADDED_SECTIONS.items():
        ja = split_sections((DOCS_JA / name).read_text(encoding="utf-8"))
        en = split_sections((DOCS_EN / name).read_text(encoding="utf-8"))
        for ja_title, en_title in titles:
            assert _section_signature(ja, ja_title) is not None, (name, ja_title)
            assert _section_signature(en, en_title) is not None, (name, en_title)


def test_upgrade_procedure_halves_match() -> None:
    """The upgrade procedure has the same section headings and procedure items in both languages."""
    text = UPGRADE_DOC.read_text(encoding="utf-8")
    ja, en = split_upgrade_headings(text)
    assert ja, "no H2 section found"
    assert all(ja), "an H2 heading has no ' / ' separator"
    assert all(en), "an H2 heading has no English half"
    assert all(_CJK.search(h) for h in ja)
    assert not any(_CJK.search(h) for h in en)
    ja_items, en_items = upgrade_items(text)
    assert ja_items > 0
    assert ja_items == en_items


# ------------------------------------------------------- the checks must be able to fail

PROGRAMME = "cyber-resilience-programme.md"


def _mutated_copy(tmp_path: Path, source: Path, mutate) -> str:  # noqa: ANN001
    """Write ``mutate(lines)`` of ``source`` under ``tmp_path`` and return its text."""
    lines = source.read_text(encoding="utf-8").splitlines()
    target = tmp_path / source.name
    target.write_text("\n".join(mutate(lines)) + "\n", encoding="utf-8")
    return target.read_text(encoding="utf-8")


def _drop_first_table_row(lines: list[str]) -> list[str]:
    """Remove the first data row of the first table after the first H2."""
    seen_h2 = False
    for index, line in enumerate(lines):
        seen_h2 = seen_h2 or line.startswith("## ")
        if seen_h2 and line.startswith("|---"):
            return lines[: index + 1] + lines[index + 2 :]
    raise AssertionError("no table found")


def _drop_a_heading(lines: list[str]) -> list[str]:
    """Remove the first H3 heading."""
    for index, line in enumerate(lines):
        if line.startswith("### "):
            return lines[:index] + lines[index + 1 :]
    raise AssertionError("no H3 found")


def _change_a_reference_url(lines: list[str]) -> list[str]:
    """Change the host of the first URL in the reference section."""
    inside = False
    for index, line in enumerate(lines):
        if line.startswith("## "):
            inside = line[3:].strip() in REFERENCE_TITLES_EN
        if inside and "](https://" in line:
            changed = line.replace("](https://", "](https://changed-", 1)
            return lines[:index] + [changed] + lines[index + 1 :]
    raise AssertionError("no reference URL found")


def _change_a_reference_date(lines: list[str]) -> list[str]:
    """Change the first date in the reference section."""
    inside = False
    for index, line in enumerate(lines):
        if line.startswith("## "):
            inside = line[3:].strip() in REFERENCE_TITLES_EN
        if inside and _DATE.search(line):
            return lines[:index] + [_DATE.sub("2000-01-01", line, count=1)] + lines[index + 1 :]
    raise AssertionError("no reference date found")


def _add_a_note(lines: list[str]) -> list[str]:
    """Append a blockquote note at the end of the first H2 section."""
    for index, line in enumerate(lines):
        if line.startswith("## ") and index > 0:
            return [*lines[:index], "> **Note**: extra", "", *lines[index:]]
    raise AssertionError("no second H2 found")


MUTATIONS = {
    "table row removed": (_drop_first_table_row, "tables"),
    "heading removed": (_drop_a_heading, "headings"),
    "reference URL changed": (_change_a_reference_url, "reference URLs"),
    "reference date changed": (_change_a_reference_date, "reference dates"),
    "note added": (_add_a_note, "notes"),
}


def test_unmodified_copy_has_no_problem(tmp_path: Path) -> None:
    """Control: an unmodified copy of the English text passes, so the mutations below are what fail."""
    en_copy = _mutated_copy(tmp_path, DOCS_EN / PROGRAMME, lambda lines: lines)
    ja_text = (DOCS_JA / PROGRAMME).read_text(encoding="utf-8")
    assert compare_pair(ja_text, en_copy, PROGRAMME) == []


@pytest.mark.parametrize("label", sorted(MUTATIONS))
def test_mutated_english_copy_is_reported(tmp_path: Path, label: str) -> None:
    """Each kind of drift in the English text is reported with its own kind of message."""
    mutate, expected = MUTATIONS[label]
    en_copy = _mutated_copy(tmp_path, DOCS_EN / PROGRAMME, mutate)
    ja_text = (DOCS_JA / PROGRAMME).read_text(encoding="utf-8")
    problems = compare_pair(ja_text, en_copy, PROGRAMME)
    assert any(expected in p for p in problems), problems


def test_mutated_added_section_is_reported(tmp_path: Path) -> None:
    """A table row removed inside the accountability section is reported for that section."""

    def drop_row_in_accountability(lines: list[str]) -> list[str]:
        inside = False
        for index, line in enumerate(lines):
            if line.startswith("## "):
                inside = line[3:].strip() == "Accountability across the pillars"
            if inside and line.startswith("|---"):
                return lines[: index + 1] + lines[index + 2 :]
        raise AssertionError("no table in the accountability section")

    en_copy = _mutated_copy(tmp_path, DOCS_EN / PROGRAMME, drop_row_in_accountability)
    ja_text = (DOCS_JA / PROGRAMME).read_text(encoding="utf-8")
    problems = compare_pair(ja_text, en_copy, PROGRAMME)
    assert any("added section" in p for p in problems), problems


def test_upgrade_doc_drift_is_reported(tmp_path: Path) -> None:
    """A removed English procedure row, or a removed English heading half, is reported."""

    def drop_english_row(lines: list[str]) -> list[str]:
        stage = False
        for index, line in enumerate(lines):
            if line.startswith("## "):
                stage = line.startswith("## 段階")
            if stage and line.startswith("| Product |"):
                return lines[: index + 2] + lines[index + 3 :]
        raise AssertionError("no English stage table")

    def drop_english_half(lines: list[str]) -> list[str]:
        return [ln.partition(" / ")[0] if ln.startswith("## 段階 5") else ln for ln in lines]

    original = UPGRADE_DOC.read_text(encoding="utf-8").splitlines()
    ja_items, en_items = upgrade_items("\n".join(original))
    row_copy = _mutated_copy(tmp_path, UPGRADE_DOC, drop_english_row)
    assert upgrade_items(row_copy) == (ja_items, en_items - 1)
    half_copy = _mutated_copy(tmp_path, UPGRADE_DOC, drop_english_half)
    assert not all(split_upgrade_headings(half_copy)[1])
