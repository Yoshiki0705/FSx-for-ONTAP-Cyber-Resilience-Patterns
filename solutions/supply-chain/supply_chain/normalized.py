"""Normalized scanner findings -> ``Finding`` objects (design 6, ``findings.normalized.json``).

Pure: takes the parsed JSON mapping and does no I/O. The SBOM itself is read
by the format adapter in ``adapters/spdx.py``; this module sees only the
scanner output that the SBOM_Generator already normalized.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from supply_chain.models import UNKNOWN, Component, Finding, Layer, Repo, Severity

SCHEMA_VERSION = 1
MALICIOUS_PREFIX = "MAL-"
_SEVERITIES: tuple[Severity, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_SHA = re.compile(r"[0-9a-f]{40}")
_PCT = re.compile(r"%([0-9A-Fa-f]{2})")


class NormalizedFindingsError(ValueError):
    """``findings.normalized.json`` does not match the documented shape."""


@dataclass(frozen=True, slots=True)
class NormalizedFindings:
    """The scan metadata and the de-duplicated findings of one scan."""

    repo: Repo
    commit: str
    layer: Layer
    generated_at: datetime
    tool_name: str
    tool_version: str
    findings: tuple[Finding, ...]


def normalize_severity(raw: object) -> Severity | None:
    """Maps a scanner severity to ``Severity``.

    Args:
        raw: Value of ``cvss_severity``.

    Returns:
        The upper-cased level for CRITICAL/HIGH/MEDIUM/LOW. ``UNKNOWN``,
        ``null`` and any other value give ``None``.
    """
    if isinstance(raw, str):
        level = raw.strip().upper()
        for known in _SEVERITIES:
            if level == known:
                return known
    return None


def _unquote(text: str) -> str:
    """Decodes ``%XX`` escapes (UTF-8) without importing ``urllib``."""
    if "%" not in text:
        return text
    chunks = bytearray()
    pos = 0
    for match in _PCT.finditer(text):
        chunks += text[pos : match.start()].encode()
        chunks.append(int(match.group(1), 16))
        pos = match.end()
    chunks += text[pos:].encode()
    return chunks.decode("utf-8", errors="replace")


def component_from_purl(purl: str) -> Component:
    """Builds a ``Component`` from a purl, reading name and version from it.

    Args:
        purl: A ``pkg:`` package URL.

    Returns:
        A component whose other fields are ``unknown``. The version is
        ``unknown`` when the purl has none.
    """
    body = purl.split("#", 1)[0].split("?", 1)[0]
    head, sep, version = body.rpartition("@")
    if not sep or "/" in version:
        head, version = body, ""
    name = _unquote(head.rsplit("/", 1)[-1]) or UNKNOWN
    return Component(purl=purl, name=name, version=_unquote(version) or UNKNOWN)


def _parse_time(raw: object, *, required: str | None = None) -> datetime | None:
    """Parses an ISO 8601 time to UTC; naive or unparsable values are rejected."""
    text = raw.strip() if isinstance(raw, str) else ""
    parsed: datetime | None = None
    if text:
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            parsed = None
    if parsed is not None and parsed.utcoffset() is None:
        parsed = None
    if parsed is None:
        if required:
            raise NormalizedFindingsError(f"{required} must be an ISO 8601 time with a UTC offset")
        return None
    return parsed.astimezone(UTC)


def _required_text(obj: Mapping[str, Any], key: str, where: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        raise NormalizedFindingsError(f"{where}{key} must be a non-empty string")
    return value.strip()


def _parse_repo(raw: str) -> Repo:
    owner, sep, name = raw.partition("/")
    if not sep or not owner or not name or "/" in name:
        raise NormalizedFindingsError("repo must be '<owner>/<name>'")
    return Repo(owner, name)


def _aliases(raw: object) -> tuple[str, ...]:
    if not isinstance(raw, list):
        return ()
    return tuple(a.strip() for a in raw if isinstance(a, str) and a.strip())


def _merge(first: Finding, other: Finding) -> Finding:
    """Merges a duplicate into ``first``: union aliases, keep the strongest facts."""
    aliases = tuple(dict.fromkeys((*first.aliases, *other.aliases)))
    severity = first.cvss_severity
    if other.cvss_severity and (severity is None or _RANK[other.cvss_severity] > _RANK[severity]):
        severity = other.cvss_severity
    published = [t for t in (first.advisory_published_at, other.advisory_published_at) if t]
    return Finding(
        repo=first.repo,
        vuln_id=first.vuln_id,
        aliases=aliases,
        component=first.component,
        cvss_severity=None if first.vuln_id.startswith(MALICIOUS_PREFIX) else severity,
        fixed_version=first.fixed_version or other.fixed_version,
        advisory_published_at=min(published) if published else None,
        layer=first.layer,
        first_observed_component_at=min(first.first_observed_component_at, other.first_observed_component_at),
    )


def dedupe_findings(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    """Removes duplicates by ``(repo, vuln_id, purl)``, keeping first-seen order.

    Args:
        findings: Findings that may repeat (a scanner can report one pair twice).

    Returns:
        One finding per key. Aliases are unioned, the highest severity and the
        earliest advisory time are kept, and the first non-empty fixed version
        is kept. Repository comparison ignores case (``Repo.__eq__``).
    """
    merged: dict[tuple[Repo, str, str], Finding] = {}
    for finding in findings:
        key = (finding.repo, finding.vuln_id, finding.component.purl)
        merged[key] = _merge(merged[key], finding) if key in merged else finding
    return tuple(merged.values())


def _finding(
    entry: Mapping[str, Any],
    *,
    repo: Repo,
    layer: Layer,
    index: int,
    components: Mapping[str, Component],
    observed_at: datetime,
) -> Finding:
    where = f"findings[{index}]."
    vuln_id = _required_text(entry, "vuln_id", where)
    purl = _required_text(entry, "purl", where)
    aliases = _aliases(entry.get("aliases"))
    # A GHSA/CVE record that names a MAL- alias is the same malicious package:
    # report it under the MAL- id (design 6, "代表の ID は MAL- を優先").
    mal_alias = next((a for a in aliases if a.startswith(MALICIOUS_PREFIX)), None)
    if mal_alias and not vuln_id.startswith(MALICIOUS_PREFIX):
        aliases = tuple(dict.fromkeys((vuln_id, *(a for a in aliases if a != mal_alias))))
        vuln_id = mal_alias
    aliases = tuple(a for a in dict.fromkeys(aliases) if a != vuln_id)
    severity = None if vuln_id.startswith(MALICIOUS_PREFIX) else normalize_severity(entry.get("cvss_severity"))
    fixed = entry.get("fixed_version")
    return Finding(
        repo=repo,
        vuln_id=vuln_id,
        aliases=aliases,
        component=components.get(purl) or component_from_purl(purl),
        cvss_severity=severity,
        fixed_version=fixed.strip() if isinstance(fixed, str) and fixed.strip() else None,
        advisory_published_at=_parse_time(entry.get("advisory_published_at")),
        layer=layer,
        first_observed_component_at=observed_at,
    )


def findings_from_normalized(
    doc: Mapping[str, Any],
    *,
    components: Iterable[Component] = (),
    first_observed_at: datetime | None = None,
) -> NormalizedFindings:
    """Converts a parsed ``findings.normalized.json`` to ``Finding`` objects.

    Args:
        doc: The parsed JSON document (``schema_version`` 1).
        components: Components from the SBOM adapter. A finding whose purl
            matches one reuses it (direct/author etc.); others get a component
            built from the purl.
        first_observed_at: Value for ``first_observed_component_at`` (the
            first run that saw the version). Defaults to ``generated_at``.

    Returns:
        Metadata and findings. An empty ``findings`` array gives no findings.
        ``UNKNOWN`` severity maps to ``None``; a ``MAL-`` id is kept as
        ``vuln_id`` with severity ``None``; duplicates by
        ``(repo, vuln_id, purl)`` are merged.

    Raises:
        NormalizedFindingsError: If the shape is wrong. No partial result.
    """
    if not isinstance(doc, Mapping):
        raise NormalizedFindingsError("document must be a JSON object")
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise NormalizedFindingsError(f"schema_version must be {SCHEMA_VERSION}")
    repo = _parse_repo(_required_text(doc, "repo", ""))
    commit = _required_text(doc, "commit", "")
    if not _SHA.fullmatch(commit):
        raise NormalizedFindingsError("commit must be 40 lowercase hex digits")
    layer = doc.get("layer")
    if layer not in ("A", "B"):
        raise NormalizedFindingsError("layer must be 'A' or 'B'")
    generated = _parse_time(doc.get("generated_at"), required="generated_at")
    if generated is None:  # unreachable: _parse_time raises when required
        raise NormalizedFindingsError("generated_at is required")
    tool = doc.get("tool")
    if not isinstance(tool, Mapping):
        raise NormalizedFindingsError("tool must be an object")
    tool_name = _required_text(tool, "name", "tool.")
    tool_version = _required_text(tool, "version", "tool.")
    entries = doc.get("findings")
    if not isinstance(entries, list):
        raise NormalizedFindingsError("findings must be an array")
    observed = first_observed_at or generated
    if observed.utcoffset() is None:
        raise NormalizedFindingsError("first_observed_at must be timezone-aware")
    by_purl = {c.purl: c for c in components}
    parsed: list[Finding] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise NormalizedFindingsError(f"findings[{index}] must be an object")
        parsed.append(
            _finding(
                entry,
                repo=repo,
                layer=layer,
                index=index,
                components=by_purl,
                observed_at=observed.astimezone(UTC),
            )
        )
    return NormalizedFindings(repo, commit, layer, generated, tool_name, tool_version, dedupe_findings(parsed))
