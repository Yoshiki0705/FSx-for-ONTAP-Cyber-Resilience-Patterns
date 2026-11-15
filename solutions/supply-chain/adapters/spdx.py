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

from supply_chain.canonical import purl_key
from supply_chain.models import UNKNOWN, Component, Directness

SUPPORTED_VERSION = "SPDX-2.3"
_DOCUMENT_ID = "SPDXRef-DOCUMENT"
_SHA = re.compile(r"[0-9a-f]{40}")
_COMMENT_SHA = re.compile(r"\bcommit[:= ]\s*([0-9a-f]{40})\b")
_TOOL = re.compile(r"^(.+?)-(\d\S*)$")
_NO_VALUE = frozenset({"NOASSERTION", "NONE", ""})
_DEPENDENCY_TYPES = frozenset(
    {
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
    # Components whose purl names no version (GitHub's export has such packages when it could not resolve one).
    unresolved_version: int = 0

    @property
    def component_count(self) -> int:
        """Number of components (the ``component_count`` of generation.json)."""
        return len(self.components)

    @property
    def coverage_complete(self) -> bool:
        """True when every package could be addressed by a purl with a version.

        False means the component list is not the whole SBOM. A reader that sees ``component_count == 0`` and
        ``coverage_complete == False`` has not scanned anything: it must not read that as "no vulnerability",
        and must not close an Issue on it (Requirement 4.14).
        """
        return self.skipped_without_purl == 0 and self.unresolved_version == 0


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


def _purl_has_version(purl: str) -> bool:
    """True when the last path segment of the purl (before qualifiers and subpath) carries ``@version``."""
    body = purl.split("#", 1)[0].split("?", 1)[0]
    return "@" in body.rsplit("/", 1)[-1]


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


def _is_flat(roots: set[str], rels: list[tuple[str, str, str]]) -> bool:
    """True when no dependency relationship joins two packages that are not the root.

    A document of this shape says "the root has these packages", not which of them the root uses itself:
    GitHub's dependency-graph export (read 2026-11-14, 20 packages) has the root ``DEPENDS_ON`` every package
    and no package-to-package relationship, transitive ones included.
    """
    skip = roots | {_DOCUMENT_ID}
    return not any(
        kind in _DEPENDENCY_TYPES and subject not in skip and target not in skip for subject, kind, target in rels
    )


def _directness(spdx_id: str, roots: set[str], rels: list[tuple[str, str, str]], *, flat: bool) -> Directness:
    """Classifies a package as direct, transitive or unknown from dependency relationships.

    ``CONTAINS`` is not a dependency (SPDX 2.3 "Relationships between SPDX elements"), so it never makes a
    package direct. In a flat document (``_is_flat``) the relationships do not separate direct from
    transitive, so every package is ``unknown`` (Requirement 4.1; observed for the GitHub export, a
    hypothesis for other producers).
    """
    if flat:
        return UNKNOWN
    linked = False
    for subject, kind, target in rels:
        if kind not in _DEPENDENCY_TYPES:
            continue
        if spdx_id not in (subject, target):
            continue
        linked = True
        if kind == "DEPENDS_ON" and subject in roots and target == spdx_id:
            return "direct"
        if kind.endswith("DEPENDENCY_OF") and subject == spdx_id and target in roots:
            return "direct"
    return "transitive" if linked else UNKNOWN


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


def _check_required(doc: Mapping[str, Any]) -> None:
    """Rejects a document that lacks a field SPDX 2.3 (6.1 to 6.9) requires of every document."""
    missing: list[str] = []
    if doc.get("SPDXID") != _DOCUMENT_ID:
        missing.append(f"SPDXID ({_DOCUMENT_ID})")
    if doc.get("dataLicense") != "CC0-1.0":
        missing.append("dataLicense (CC0-1.0)")
    for key in ("name", "documentNamespace"):
        if _text(doc.get(key)) is None:
            missing.append(key)
    info = doc.get("creationInfo")
    if not isinstance(info, Mapping):
        missing.append("creationInfo")
    else:
        if _text(info.get("created")) is None:  # an unparsable value is read as unknown, a missing one is not
            missing.append("creationInfo.created")
        creators = info.get("creators")
        if not isinstance(creators, list) or not any(_text(c) for c in creators):
            missing.append("creationInfo.creators")
    if missing:
        raise SbomFormatError("not a complete SPDX 2.3 document, missing or wrong: " + ", ".join(missing))


def parse_spdx(doc: Mapping[str, Any]) -> SbomInfo:
    """Extracts metadata and components from a parsed SPDX 2.3 JSON document.

    Conventions (SPDX 2.3 has no standard field for these):
      * commit SHA: ``versionInfo`` of a described root package when it is 40
        lowercase hex digits, else ``commit: <sha>`` in a comment.
      * ``direct``: the root ``DEPENDS_ON`` the package, or the package is a
        ``*_DEPENDENCY_OF`` the root, in a document where packages also depend
        on each other; ``transitive`` when it has only other dependency
        relationships; ``unknown`` otherwise, and for every package of a flat
        document (the root depends on all of them, nothing else is related).
        ``CONTAINS`` is containment, not dependency, and says nothing.
      * ``author``: ``supplier``, else ``originator``, without the kind prefix.
      * ``generation_stage``: always ``unknown`` (no SPDX 2.3 field).

    Args:
        doc: The SBOM as parsed JSON.

    Returns:
        The extracted information. Zero components is returned for a document that says so with
        ``CONTAINS`` -> ``NONE`` (Requirement 4.10), and for one whose packages all lack a purl, which comes
        back with ``coverage_complete`` false (Requirement 4.14).

    Raises:
        SbomFormatError: If ``doc`` is not a mapping, ``spdxVersion`` is not
            ``SPDX-2.3`` (Syft's default output is SPDX 3.0, design S-09), a
            field SPDX 2.3 requires of the document is missing (``SPDXID``,
            ``dataLicense``, ``name``, ``documentNamespace``,
            ``creationInfo.created``, ``creationInfo.creators``), or there is
            no component and no ``CONTAINS`` -> ``NONE``. A truncated or failed
            export looks like an empty one, and an empty SBOM must never be
            read as "no vulnerability" (which would close every Issue).
    """
    if not isinstance(doc, Mapping):
        raise SbomFormatError("SBOM must be a JSON object")
    version = doc.get("spdxVersion")
    if version != SUPPORTED_VERSION:
        raise SbomFormatError(f"spdxVersion must be {SUPPORTED_VERSION!r}, got {version!r}")
    _check_required(doc)
    raw_packages = doc.get("packages", [])
    if not isinstance(raw_packages, list):
        raise SbomFormatError("packages must be an array")
    packages = [p for p in raw_packages if isinstance(p, Mapping)]
    rels = _relationships(doc)
    roots = _roots(doc, rels)
    flat = _is_flat(roots, rels)
    components: list[Component] = []
    seen: set[str] = set()
    skipped = 0
    unresolved = 0
    for package in packages:
        spdx_id = _text(package.get("SPDXID")) or ""
        if spdx_id in roots:
            continue
        purl = _purl(package)
        if purl is None:
            skipped += 1
            continue
        # Two spellings of one purl (``Foo_Bar`` and ``foo-bar`` on PyPI) are one component (T1-R2-08).
        identity = purl_key(purl) or purl
        if identity in seen:
            continue
        seen.add(identity)
        if not _purl_has_version(purl):
            unresolved += 1
        components.append(
            Component(
                purl=purl,
                name=_text(package.get("name")) or UNKNOWN,
                version=_text(package.get("versionInfo")) or UNKNOWN,
                direct=_directness(spdx_id, roots, rels, flat=flat),
                author=_party(package),
                format_name="SPDX",
                format_version=SUPPORTED_VERSION.removeprefix("SPDX-"),
                generation_stage=UNKNOWN,
            )
        )

    info = doc.get("creationInfo")
    info_map: Mapping[str, Any] = info if isinstance(info, Mapping) else {}
    empty = any(kind == "CONTAINS" and target == "NONE" for _, kind, target in rels)
    if not components and not empty and skipped == 0:
        raise SbomFormatError(
            "no components and no CONTAINS -> NONE marker: refusing to read an empty or truncated SBOM "
            "as a clean one (Requirement 4.10)"
        )
    return SbomInfo(
        format_version=SUPPORTED_VERSION.removeprefix("SPDX-"),
        created=_created(info_map),
        tools=_tools(info_map),
        commit_sha=_commit(doc, packages, roots),
        components=tuple(components),
        declared_empty=empty,
        skipped_without_purl=skipped,
        unresolved_version=unresolved,
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
