"""Tests for the SPDX 2.3 JSON adapter (``adapters/spdx.py``). Synthetic data only."""

from __future__ import annotations

import ast
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from adapters import spdx
from adapters.spdx import SbomFormatError, SbomTool, parse_spdx, read_spdx
from hypothesis import event, given, settings
from hypothesis import strategies as st

SHA = "0123456789abcdef0123456789abcdef01234567"
ADAPTER_DIR = Path(__file__).parent.parent / "solutions" / "supply-chain" / "adapters"


def sbom(packages: list[dict[str, Any]] | None = None, **extra: Any) -> dict[str, Any]:
    """Builds a minimal SPDX 2.3 document with a described root package."""
    root = {"SPDXID": "SPDXRef-root", "name": "example-app", "versionInfo": SHA}
    doc: dict[str, Any] = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": "2026-11-10T01:02:03Z",
            "creators": ["Tool: syft-1.2.3", "Organization: Example Org"],
        },
        "packages": [root, *(packages or [])],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-root"}
        ],
    }
    doc.update(extra)
    return doc


def pkg(spdx_id: str, name: str, version: str, purl: str | None = None, **extra: Any) -> dict[str, Any]:
    refs = (
        []
        if purl is None
        else [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}]
    )
    return {"SPDXID": spdx_id, "name": name, "versionInfo": version, "externalRefs": refs, **extra}


def rel(a: str, kind: str, b: str) -> dict[str, str]:
    return {"spdxElementId": a, "relationshipType": kind, "relatedSpdxElement": b}


def test_zero_components_sbom_declared_empty() -> None:
    """A root-only SBOM with CONTAINS -> NONE has no components (Requirement 4.10)."""
    doc = sbom()
    doc["relationships"].append(rel("SPDXRef-root", "CONTAINS", "NONE"))
    info = parse_spdx(doc)
    assert info.components == ()
    assert info.component_count == 0
    assert info.declared_empty is True


def test_zero_components_without_packages_key_or_none_marker() -> None:
    """Missing ``packages`` and a missing NONE marker both read as zero components."""
    doc = sbom()
    del doc["packages"]
    info = parse_spdx(doc)
    assert info.component_count == 0
    assert info.declared_empty is False
    assert info.commit_sha is None  # no root package to carry it


def test_reads_created_tool_and_commit() -> None:
    """Generation time (UTC), tool name and version, and commit SHA are read."""
    info = parse_spdx(sbom())
    assert info.created == datetime(2026, 11, 10, 1, 2, 3, tzinfo=UTC)
    assert info.tools == (SbomTool("syft", "1.2.3"),)
    assert info.commit_sha == SHA
    assert info.format_version == "2.3"


def test_tool_name_with_hyphen_and_missing_version() -> None:
    doc = sbom()
    doc["creationInfo"]["creators"] = ["Tool: my-scan-tool-0.9.1", "Tool: bare", "Person: Someone"]
    assert parse_spdx(doc).tools == (SbomTool("my-scan-tool", "0.9.1"), SbomTool("bare", "unknown"))


def test_created_with_offset_is_converted_to_utc_and_naive_is_unknown() -> None:
    doc = sbom()
    doc["creationInfo"]["created"] = "2026-11-10T10:00:00+09:00"
    assert parse_spdx(doc).created == datetime(2026, 11, 10, 1, 0, tzinfo=UTC)
    doc["creationInfo"]["created"] = "2026-11-10T10:00:00"
    assert parse_spdx(doc).created is None
    doc["creationInfo"]["created"] = "not a time"
    assert parse_spdx(doc).created is None


def test_commit_sha_from_comment_when_root_has_none() -> None:
    doc = sbom()
    doc["packages"][0]["versionInfo"] = "1.0.0"
    assert parse_spdx(doc).commit_sha is None
    doc["creationInfo"]["comment"] = f"built from commit: {SHA}"
    assert parse_spdx(doc).commit_sha == SHA


def test_commit_sha_rejects_non_sha_and_uppercase() -> None:
    doc = sbom()
    doc["packages"][0]["versionInfo"] = SHA.upper()
    assert parse_spdx(doc).commit_sha is None
    doc["packages"][0]["versionInfo"] = SHA[:39]
    assert parse_spdx(doc).commit_sha is None


def test_components_fields_and_directness() -> None:
    """Direct, transitive and unlinked packages; unknown for what SPDX 2.3 lacks."""
    doc = sbom(
        [
            pkg("SPDXRef-a", "alpha", "1.0.0", "pkg:pypi/alpha@1.0.0", supplier="Organization: Alpha Inc"),
            pkg("SPDXRef-b", "beta", "2.0.0", "pkg:pypi/beta@2.0.0", originator="Person: Bea"),
            pkg("SPDXRef-c", "gamma", "3.0.0", "pkg:pypi/gamma@3.0.0", supplier="NOASSERTION"),
            pkg("SPDXRef-d", "delta", "4.0.0", "pkg:pypi/delta@4.0.0"),
        ]
    )
    doc["relationships"] += [
        rel("SPDXRef-root", "DEPENDS_ON", "SPDXRef-a"),
        rel("SPDXRef-b", "DEPENDENCY_OF", "SPDXRef-root"),
        rel("SPDXRef-a", "DEPENDS_ON", "SPDXRef-c"),
    ]
    by_name = {c.name: c for c in parse_spdx(doc).components}
    assert by_name["alpha"].direct == "direct"
    assert by_name["alpha"].author == "Alpha Inc"
    assert by_name["beta"].direct == "direct"
    assert by_name["beta"].author == "Bea"
    assert by_name["gamma"].direct == "transitive"
    assert by_name["gamma"].author == "unknown"
    assert by_name["delta"].direct == "unknown"
    assert all(c.format_name == "SPDX" and c.format_version == "2.3" for c in by_name.values())
    assert all(c.generation_stage == "unknown" for c in by_name.values())
    assert "example-app" not in by_name  # the described root is not a component


def test_package_without_purl_is_counted_not_listed() -> None:
    doc = sbom([pkg("SPDXRef-a", "alpha", "1", None), pkg("SPDXRef-b", "beta", "2", "pkg:npm/beta@2")])
    info = parse_spdx(doc)
    assert [c.purl for c in info.components] == ["pkg:npm/beta@2"]
    assert info.skipped_without_purl == 1


def test_duplicate_purl_is_listed_once() -> None:
    doc = sbom([pkg("SPDXRef-a", "alpha", "1", "pkg:npm/alpha@1"), pkg("SPDXRef-b", "alpha", "1", "pkg:npm/alpha@1")])
    assert parse_spdx(doc).component_count == 1


@pytest.mark.parametrize("version", ["SPDX-3.0", "SPDX-2.2", None, 2.3])
def test_other_spdx_versions_are_rejected(version: object) -> None:
    doc = sbom()
    doc["spdxVersion"] = version
    with pytest.raises(SbomFormatError):
        parse_spdx(doc)


@pytest.mark.parametrize("doc", [[], "text", None, {"spdxVersion": "SPDX-2.3", "packages": {}}])
def test_malformed_documents_are_rejected(doc: object) -> None:
    with pytest.raises(SbomFormatError):
        parse_spdx(doc)  # type: ignore[arg-type]


def test_read_spdx_reads_a_file_and_rejects_bad_json(tmp_path: Path) -> None:
    good = tmp_path / "sbom.spdx.json"
    good.write_text(json.dumps(sbom([pkg("SPDXRef-a", "alpha", "1", "pkg:npm/alpha@1")])), encoding="utf-8")
    assert read_spdx(good).component_count == 1
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    with pytest.raises(SbomFormatError):
        read_spdx(bad)


def test_adapter_imports_no_network_modules() -> None:
    """The adapter sits outside ``supply_chain`` so the 8.1 scan does not cover it."""
    forbidden = {"urllib", "http", "socket", "requests", "boto3", "subprocess"}
    for path in ADAPTER_DIR.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
                if isinstance(node, ast.ImportFrom) and node.level == 0
                else []
            )
            assert not {n.split(".")[0] for n in names} & forbidden, path.name


_PURLS = st.sampled_from([f"pkg:npm/p{i}@1.{i}" for i in range(6)])


@settings(max_examples=100, deadline=None)
@given(
    purls=st.lists(st.one_of(_PURLS, st.none()), max_size=12),
    add_none_marker=st.booleans(),
)
def test_property_component_count_is_distinct_purls(purls: list[str | None], add_none_marker: bool) -> None:
    """The component list is the distinct purls in order; others are only counted.

    **Validates: Requirements 4.1, 4.6, 4.10**
    """
    packages = [pkg(f"SPDXRef-{i}", f"n{i}", "1", p) for i, p in enumerate(purls)]
    doc = sbom(packages)
    if add_none_marker:
        doc["relationships"].append(rel("SPDXRef-root", "CONTAINS", "NONE"))
    info = parse_spdx(doc)
    expected = list(dict.fromkeys(p for p in purls if p))
    event(f"components={min(len(expected), 3)}")
    assert [c.purl for c in info.components] == expected
    assert info.component_count == len(expected)
    assert info.skipped_without_purl == sum(1 for p in purls if p is None)
    assert info.declared_empty is add_none_marker


def test_module_exposes_supported_version() -> None:
    assert spdx.SUPPORTED_VERSION == "SPDX-2.3"
