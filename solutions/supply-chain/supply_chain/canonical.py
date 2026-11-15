"""Identifier and purl canonical forms (pure, no I/O).

Two layers report one vulnerability under different names: layer A (GitHub)
leads with a GHSA identifier, layer B (the scanners) with a CVE identifier.
``canonicalize`` joins the findings of one repository whose identifiers are
linked by aliases and gives each connected set one representative identifier,
so one vulnerability is one Issue (Requirement 8.1).

Representative order: ``MAL-`` first (a malicious package is a different class
of finding), then ``CVE-``, then ``GHSA-``, then anything else in text order.

Identifier case: ``CVE-`` and ``MAL-`` are upper case. A GHSA identifier has an
upper-case prefix and a lower-case rest (GitHub Docs, "About the GitHub
Advisory Database"; the KEV ``cveID`` is upper case, CISA ``kev-data`` schema).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import replace
from typing import Any

from supply_chain.models import Finding

_PCT = re.compile(r"%([0-9A-Fa-f]{2})")
_RANK = {"MAL-": 0, "CVE-": 1, "GHSA-": 2}
# purl types whose name is case-insensitive by their purl type definition.
_LOWER_NAME_TYPES = frozenset({"npm", "pypi", "github", "githubactions", "golang", "gem", "cargo", "composer"})


def canonical_id(vuln_id: str) -> str:
    """Returns the canonical spelling of a vulnerability identifier.

    Args:
        vuln_id: Any identifier; surrounding space is removed.

    Returns:
        ``CVE-`` / ``MAL-`` identifiers in upper case, ``GHSA-`` with an upper-case prefix and a lower-case
        rest, and any other identifier unchanged.
    """
    text = vuln_id.strip()
    upper = text.upper()
    if upper.startswith(("CVE-", "MAL-")):
        return upper
    if upper.startswith("GHSA-"):
        return "GHSA-" + text[5:].lower()
    return text


def _rank(vuln_id: str) -> tuple[int, str]:
    for prefix, rank in _RANK.items():
        if vuln_id.startswith(prefix):
            return (rank, vuln_id)
    return (len(_RANK), vuln_id)


def purl_key(purl: str) -> str | None:
    """Returns the comparison form of a purl, or ``None`` when it is not a purl.

    Qualifiers and the subpath are dropped (a scanner may add ``?arch=``), ``%XX`` escapes are decoded, and
    the name is lower-cased for the purl types that define it case-insensitive; for PyPI ``_`` and ``.`` also
    become ``-``. The version is kept as written.

    Args:
        purl: A ``pkg:`` package URL.

    Returns:
        ``pkg:<type>/<namespace>/<name>@<version>`` in canonical form, or ``None``.
    """
    text = purl.strip()
    if not text.startswith("pkg:"):
        return None
    body = text[4:].split("#", 1)[0].split("?", 1)[0].lstrip("/")
    head, sep, version = body.rpartition("@")
    if not sep or "/" in version:
        head, version = body, ""
    ptype, slash, path = head.partition("/")
    if not slash or not ptype or not path:
        return None
    ptype = ptype.lower()
    path = _unquote(path)
    if ptype in _LOWER_NAME_TYPES:
        path = path.lower()
    if ptype == "pypi":
        path = re.sub(r"[_.]+", "-", path)
    return f"pkg:{ptype}/{path}" + (f"@{_unquote(version)}" if version else "")


def _unquote(text: str) -> str:
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


def _merge_pair(first: Finding, other: Finding) -> Finding:
    """Merges two findings of the same ``(repo, vuln_id, purl)``: strongest severity, earliest times."""
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    severity, source = first.cvss_severity, first.cvss_source
    if other.cvss_severity and (severity is None or rank[other.cvss_severity] > rank[severity]):
        severity, source = other.cvss_severity, other.cvss_source
    published = [t for t in (first.advisory_published_at, other.advisory_published_at) if t]
    atype = "malware" if "malware" in (first.advisory_type, other.advisory_type) else first.advisory_type
    return replace(
        first,
        aliases=tuple(sorted({*first.aliases, *other.aliases} - {first.vuln_id})),
        cvss_severity=None if first.vuln_id.startswith("MAL-") else severity,
        cvss_source=None if first.vuln_id.startswith("MAL-") else source,
        fixed_version=first.fixed_version or other.fixed_version,
        advisory_published_at=min(published) if published else None,
        advisory_type=atype or other.advisory_type,
        first_observed_component_at=min(first.first_observed_component_at, other.first_observed_component_at),
    )


def _is_exempt(finding: Finding) -> bool:
    """A malicious-package record is grouped by package version, not by CVE, so the one-CVE rule skips it."""
    ids = (finding.vuln_id, *finding.aliases)
    return finding.advisory_type == "malware" or any(canonical_id(i).startswith("MAL-") for i in ids if i.strip())


def _ids_of(finding: Finding) -> list[str]:
    return [canonical_id(i) for i in (finding.vuln_id, *finding.aliases) if i.strip()]


def _split_multi_cve(finding: Finding) -> list[Finding]:
    """Splits a finding that names more than one CVE into one finding per CVE.

    A vendor record that lists several CVEs as aliases of one advisory describes several vulnerabilities. Each
    CVE becomes its own finding, and the identifiers that are not CVEs stay as the aliases of each, so a
    judgment about one CVE never covers another (T2-R2-02).
    """
    if _is_exempt(finding):
        return [finding]
    ids = _ids_of(finding)
    cves = sorted({i for i in ids if i.startswith("CVE-")})
    if len(cves) < 2:
        return [finding]
    others = tuple(sorted({i for i in ids if not i.startswith("CVE-")}))
    return [replace(finding, vuln_id=cve, aliases=others) for cve in cves]


def multi_cve_records(findings: Iterable[Finding]) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    """Lists the records that named more than one CVE: ``(repository, primary id, its CVEs)``.

    ``canonicalize`` splits them; this makes the sign visible, so the frequency of such records can be read
    from real data before a stricter rule is chosen (T2-R2-02).
    """
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for f in findings:
        if _is_exempt(f):
            continue
        cves = tuple(sorted({i for i in _ids_of(f) if i.startswith("CVE-")}))
        if len(cves) > 1:
            seen.add((f"{f.repo.owner}/{f.repo.name}".lower(), canonical_id(f.vuln_id), cves))
    return tuple(sorted(seen))


def canonicalize(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    """Gives every set of alias-linked findings of one repository one representative identifier.

    Within a repository the identifiers of one finding are connected. Each connected set takes one
    representative, by the order in the module docstring, and the other identifiers become aliases. Findings
    of the same representative and component purl are merged (highest severity, earliest advisory time).

    The connection never joins two CVEs, so the alias list of a finding stays what the sources declared for
    one vulnerability (T2-R2-02):

    * A finding that names several CVEs is split into one finding per CVE.
    * A connected set of identifiers that reaches two different CVEs, by any path, is not merged: each record
      keeps the identifiers it declared, so a shared identifier is listed under every record that names it, and
      a record that names no CVE is listed under every CVE of the set. The set is judged as a whole, so the result does not depend on the order of the records.

    A malicious-package record (``MAL-`` identifier or an advisory typed ``malware``) is not split: it is
    grouped by package version, not by CVE. Its identifiers still count when an identifier is checked for
    being declared with two CVEs, so the result does not change when the function is applied again.

    Args:
        findings: The findings of any repositories.

    Returns:
        The findings, sorted by repository, representative and purl, so the result does not depend on the
        order of ``findings``. Identifier case is canonical in every name and alias.
    """
    items = [part for f in findings for part in _split_multi_cve(f)]

    def key(f: Finding) -> tuple[str, str]:
        return (f.repo.owner.lower(), f.repo.name.lower())

    Node = tuple[tuple[str, str], str]  # noqa: N806
    parent: dict[Node, Node] = {}

    def find(node: Node) -> Node:
        parent.setdefault(node, node)
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def order(x: Finding) -> tuple[Any, ...]:
        return (key(x), canonical_id(x.vuln_id), x.component.purl, x.layer, x.repo.owner, x.repo.name)

    # Connected sets over every identifier the sources declared together. The sets are computed first and judged
    # afterwards, so the outcome does not depend on the order in which the links are read.
    for f in items:
        nodes = [(key(f), i) for i in _ids_of(f)]
        for node in nodes:
            find(node)
        for node in nodes[1:]:
            root_a, root_b = find(nodes[0]), find(node)
            if root_a != root_b:
                parent[max(root_a, root_b)] = min(root_a, root_b)
    members: dict[Node, set[str]] = {}
    for node in list(parent):
        members.setdefault(find(node), set()).add(node[1])
    # A set that reaches two different CVEs is not one vulnerability: no identifier of it is lent to another
    # record, and each record keeps the identifiers it declared (a shared identifier is listed under every record
    # that names it; a record without a CVE is listed under every CVE of the set). A set with at most one CVE is
    # one vulnerability.
    two_cves = {root for root, ids in members.items() if sum(i.startswith("CVE-") for i in ids) > 1}
    merged: dict[tuple[tuple[str, str], str, str], Finding] = {}
    for f in sorted(items, key=order):
        own = set(_ids_of(f))
        root = find((key(f), next(iter(own)))) if own else None
        if root is None or root not in two_cves:
            sets = [own if root is None else members[root]]
        elif any(i.startswith("CVE-") for i in own) or _is_exempt(f):
            sets = [own]
        else:
            # a record without a CVE, in a set that reaches two CVEs: it is listed under every CVE of the set
            sets = [own | {cve} for cve in sorted(i for i in members[root] if i.startswith("CVE-"))]
        for joined in sets:
            rep = min(joined, key=_rank)
            rewritten = replace(f, vuln_id=rep, aliases=tuple(sorted(joined - {rep})))
            slot = (key(f), rep, f.component.purl)
            merged[slot] = _merge_pair(merged[slot], rewritten) if slot in merged else rewritten
    return tuple(sorted(merged.values(), key=lambda x: (key(x), x.vuln_id, x.component.purl)))
