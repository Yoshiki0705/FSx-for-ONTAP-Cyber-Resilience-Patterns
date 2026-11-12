"""SPDX 2.3 JSON adapter: SBOM document -> format-independent components.

References (read 2026-11-12): SPDX Specification 2.3.1, "Document creation
information" (6.8 Creator, 6.9 Created) and "Relationships between SPDX
elements" (11.1, ``NONE``), https://spdx.github.io/spdx-spec/v2.3.1/.
SPDX 2.3 defines no field for the commit SHA, the generation stage or
dependency directness, so those are read by the conventions documented on
``parse_spdx`` and fall back to ``None`` / ``"unknown"``.

``parse_spdx`` takes an already-parsed JSON mapping and does no I/O;
``read_spdx`` is the one function that reads a file.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from supply_chain.models import UNKNOWN, Component, Directness

SUPPORTED_VERSION = "SPDX-2.3"
_DOCUMENT_ID = "SPDXRef-DOCUMENT"
_SHA = re.compile(r"[0-9a-f]{40}")
_COMMENT_SHA = re.compile(r"\bcommit[:= ]\s*([0-9a-f]{40})\b")
_TOOL = re.compile(r"^(.+?)-(\d\S*)$")
_NO_VALUE = frozenset({"NOASSERTION", "NONE", ""})
_DIRECT_FROM_ROOT = frozenset({"CONTAINS", "DEPENDS_ON"})
_DEPENDENCY_TYPES = frozenset(
    {
        "CONTAINS",
        "CONTAINED_BY",
        "DEPENDS_ON",
        "DEPENDENCY_OF",
        "BUILD_DEPENDENCY_OF",
        "DEV_DEPENDENCY_OF",
        "OPTIONAL_DEPENDENCY_OF",
        "RUNTIME_DEPENDENCY_OF",
        "PROVIDED_DEPENDENCY_OF",
        "TEST_DEPENDENCY_OF",
    }
)


class SbomFormatError(ValueError):
    """The document is not a readable SPDX 2.3 JSON SBOM."""


@dataclass(frozen=True, slots=True)
class SbomTool:
    """A ``Tool:`` creator entry split into name and version."""

    name: str
    version: str  # "unknown" when the entry has no trailing version


@dataclass(frozen=True, slots=True)
class SbomInfo:
    """What the Aggregator reads from one SBOM.

    ``components`` excludes the described root(s) and packages without a
    purl; the latter are counted in ``skipped_without_purl`` so a reader can
    see that the list is not the whole ``packages`` array.
    """

    format_version: str
    created: datetime | None
    tools: tuple[SbomTool, ...]
    commit_sha: str | None
    components: tuple[Component, ...]
    declared_empty: bool  # a ``CONTAINS`` -> ``NONE`` relationship exists
    skipped_without_purl: int

    @property
    def component_count(self) -> int:
        """Number of components (the ``component_count`` of generation.json)."""
        return len(self.components)


def _text(value: Any) -> str | None:
    """Returns a stripped string, or None for non-strings and empty text."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _created(info: Mapping[str, Any]) -> datetime | None:
    """Parses ``creationInfo.created`` to UTC; None if absent or naive."""
    raw = _text(info.get("created"))
    if raw is None:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def _tools(info: Mapping[str, Any]) -> tuple[SbomTool, ...]:
    """Reads ``Tool: <name>-<version>`` entries of ``creationInfo.creators``."""
    creators = info.get("creators")
    if not isinstance(creators, list):
        return ()
    tools: list[SbomTool] = []
    for entry in creators:
        text = _text(entry)
        if text is None or not text.startswith("Tool:"):
            continue
        ident = text[len("Tool:") :].strip()
        if not ident:
            continue
        match = _TOOL.match(ident)
        tools.append(SbomTool(match.group(1), match.group(2)) if match else SbomTool(ident, UNKNOWN))
    return tuple(tools)


def _purl(package: Mapping[str, Any]) -> str | None:
    """Returns the first purl locator in ``externalRefs``."""
    refs = package.get("externalRefs")
    if not isinstance(refs, list):
        return None
    for ref in refs:
        if isinstance(ref, Mapping) and ref.get("referenceType") == "purl":
            locator = _text(ref.get("referenceLocator"))
            if locator is not None and locator.startswith("pkg:"):
                return locator
    return None


def _party(package: Mapping[str, Any]) -> str:
    """Returns ``supplier`` or ``originator`` without its kind prefix."""
    for key in ("supplier", "originator"):
        text = _text(package.get(key))
        if text is None or text in _NO_VALUE:
            continue
        for prefix in ("Person:", "Organization:"):
            if text.startswith(prefix):
                text = text[len(prefix) :].strip()
        if text and text not in _NO_VALUE:
            return text
    return UNKNOWN


def _relationships(doc: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    """Returns ``(subject, type, object)`` triples of well-formed relationships."""
    raw = doc.get("relationships")
    if not isinstance(raw, list):
        return []
    out: list[tuple[str, str, str]] = []
    for rel in raw:
        if not isinstance(rel, Mapping):
            continue
        subject = _text(rel.get("spdxElementId"))
        kind = _text(rel.get("relationshipType"))
        target = _text(rel.get("relatedSpdxElement"))
        if subject and kind and target:
            out.append((subject, kind, target))
    return out


def _roots(doc: Mapping[str, Any], rels: list[tuple[str, str, str]]) -> set[str]:
    """Returns the SPDX ids the document describes (the SBOM's subject)."""
    roots: set[str] = set()
    declared = doc.get("documentDescribes")
    if isinstance(declared, list):
        roots.update(x for x in declared if isinstance(x, str))
    for subject, kind, target in rels:
        if kind == "DESCRIBES" and subject == _DOCUMENT_ID:
            roots.add(target)
        elif kind == "DESCRIBED_BY" and target == _DOCUMENT_ID:
            roots.add(subject)
    return roots


def _directness(spdx_id: str, roots: set[str], rels: list[tuple[str, str, str]]) -> Directness:
    """Classifies a package as direct, transitive or unknown from relationships."""
    linked = False
    for subject, kind, target in rels:
        if kind not in _DEPENDENCY_TYPES:
            continue
        if spdx_id not in (subject, target):
            continue
        linked = True
        if kind in _DIRECT_FROM_ROOT and subject in roots and target == spdx_id:
            return "direct"
        if kind.endswith("DEPENDENCY_OF") and subject == spdx_id and target in roots:
            return "direct"
        if kind == "CONTAINED_BY" and subject == spdx_id and target in roots:
            return "direct"
    return "transitive" if linked else "unknown"


def _commit(doc: Mapping[str, Any], packages: list[Mapping[str, Any]], roots: set[str]) -> str | None:
    """Reads the commit SHA: a root package's ``versionInfo``, else a comment."""
    for package in packages:
        if package.get("SPDXID") in roots:
            version = _text(package.get("versionInfo"))
            if version is not None and _SHA.fullmatch(version):
                return version
    info = doc.get("creationInfo")
    comments = [doc.get("comment")]
    if isinstance(info, Mapping):
        comments.append(info.get("comment"))
    for comment in comments:
        text = _text(comment)
        if text is not None and (match := _COMMENT_SHA.search(text)):
            return match.group(1)
    return None


def parse_spdx(doc: Mapping[str, Any]) -> SbomInfo:
    """Extracts metadata and components from a parsed SPDX 2.3 JSON document.

    Conventions (SPDX 2.3 has no standard field for these):
      * commit SHA: ``versionInfo`` of a described root package when it is 40
        lowercase hex digits, else ``commit: <sha>`` in a comment.
      * ``direct``: the root CONTAINS / DEPENDS_ON the package, or the package
        is a ``*_DEPENDENCY_OF`` / ``CONTAINED_BY`` the root; ``transitive``
        when it has only other dependency relationships; else ``unknown``.
      * ``author``: ``supplier``, else ``originator``, without the kind prefix.
      * ``generation_stage``: always ``unknown`` (no SPDX 2.3 field).

    Args:
        doc: The SBOM as parsed JSON.

    Returns:
        The extracted information. A document with no ``packages`` or only the
        root yields zero components.

    Raises:
        SbomFormatError: If ``doc`` is not a mapping or ``spdxVersion`` is not
            ``SPDX-2.3`` (Syft's default output is SPDX 3.0, design S-09).
    """
    if not isinstance(doc, Mapping):
        raise SbomFormatError("SBOM must be a JSON object")
    version = doc.get("spdxVersion")
    if version != SUPPORTED_VERSION:
        raise SbomFormatError(f"spdxVersion must be {SUPPORTED_VERSION!r}, got {version!r}")
    raw_packages = doc.get("packages", [])
    if not isinstance(raw_packages, list):
        raise SbomFormatError("packages must be an array")
    packages = [p for p in raw_packages if isinstance(p, Mapping)]
    rels = _relationships(doc)
    roots = _roots(doc, rels)

    components: list[Component] = []
    seen: set[str] = set()
    skipped = 0
    for package in packages:
        spdx_id = _text(package.get("SPDXID")) or ""
        if spdx_id in roots:
            continue
        purl = _purl(package)
        if purl is None:
            skipped += 1
            continue
        if purl in seen:
            continue
        seen.add(purl)
        components.append(
            Component(
                purl=purl,
                name=_text(package.get("name")) or UNKNOWN,
                version=_text(package.get("versionInfo")) or UNKNOWN,
                direct=_directness(spdx_id, roots, rels),
                author=_party(package),
                format_name="SPDX",
                format_version=SUPPORTED_VERSION.removeprefix("SPDX-"),
                generation_stage=UNKNOWN,
            )
        )

    info = doc.get("creationInfo")
    info_map: Mapping[str, Any] = info if isinstance(info, Mapping) else {}
    empty = any(kind == "CONTAINS" and target == "NONE" for _, kind, target in rels)
    return SbomInfo(
        format_version=SUPPORTED_VERSION.removeprefix("SPDX-"),
        created=_created(info_map),
        tools=_tools(info_map),
        commit_sha=_commit(doc, packages, roots),
        components=tuple(components),
        declared_empty=empty,
        skipped_without_purl=skipped,
    )


def read_spdx(path: Path) -> SbomInfo:
    """Reads an SPDX 2.3 JSON file and parses it with ``parse_spdx``.

    Args:
        path: File to read.

    Returns:
        The parsed information.

    Raises:
        SbomFormatError: If the file is not valid JSON or not SPDX 2.3.
    """
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SbomFormatError(f"not valid JSON: {exc.msg}") from exc
    return parse_spdx(doc)
