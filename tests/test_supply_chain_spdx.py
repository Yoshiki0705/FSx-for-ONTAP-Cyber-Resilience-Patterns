"""Tests for the SPDX 2.3 JSON adapter (``adapters/spdx.py``). Synthetic data only."""

from __future__ import annotations

import ast
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from adapters import spdx
from adapters.spdx import SbomFormatError, SbomTool, parse_spdx, read_spdx
from hypothesis import event, given, settings
from hypothesis import strategies as st

SHA = "0123456789abcdef0123456789abcdef01234567"
ADAPTER_DIR = Path(__file__).parent.parent / "solutions" / "supply-chain" / "adapters"


def sbom(packages: list[dict[str, Any]] | None = None, *, declare_empty: bool = True, **extra: Any) -> dict[str, Any]:
    """Builds a minimal SPDX 2.3 document with a described root package.

    Without packages the document declares itself empty (``CONTAINS`` -> ``NONE``) unless ``declare_empty`` is
    false: an empty SBOM has to say so, otherwise it is refused (Requirement 4.10).
    """
    root = {"SPDXID": "SPDXRef-root", "name": "example-app", "versionInfo": SHA}
    doc: dict[str, Any] = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "example-app",
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://example.com/spdxdocs/example-app-0000",
        "creationInfo": {
            "created": "2026-11-10T01:02:03Z",
            "creators": ["Tool: syft-1.2.3", "Organization: Example Org"],
        },
        "packages": [root, *(packages or [])],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-root"}
        ],
    }
    if not packages and declare_empty:
        doc["relationships"].append(
            {"spdxElementId": "SPDXRef-root", "relationshipType": "CONTAINS", "relatedSpdxElement": "NONE"}
        )
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


def test_zero_components_without_a_none_marker_is_refused() -> None:
    """A root-only or package-less document is a truncated export, not a clean SBOM (T1-08)."""
    for doc in (sbom(declare_empty=False), {k: v for k, v in sbom(declare_empty=False).items() if k != "packages"}):
        with pytest.raises(SbomFormatError, match="CONTAINS -> NONE"):
            parse_spdx(doc)


def test_a_document_with_only_the_version_is_refused() -> None:
    with pytest.raises(SbomFormatError, match="missing or wrong"):
        parse_spdx({"spdxVersion": "SPDX-2.3"})


@pytest.mark.parametrize(
    "drop", ["SPDXID", "dataLicense", "name", "documentNamespace", "creationInfo", "created", "creators"]
)
def test_each_required_document_field_is_checked(drop: str) -> None:
    doc = sbom([pkg("SPDXRef-a", "alpha", "1", "pkg:npm/alpha@1")])
    if drop == "created":
        del doc["creationInfo"]["created"]
    elif drop == "creators":
        doc["creationInfo"]["creators"] = []
    else:
        del doc[drop]
    with pytest.raises(SbomFormatError, match="missing or wrong"):
        parse_spdx(doc)


def test_only_unaddressable_packages_is_still_reported_not_refused() -> None:
    info = parse_spdx(sbom([pkg("SPDXRef-a", "alpha", "1", None)]))
    assert info.component_count == 0
    assert info.skipped_without_purl == 1
    assert info.declared_empty is False


def test_contains_is_not_a_dependency_and_a_flat_document_says_nothing_about_directness() -> None:
    doc = sbom([pkg("SPDXRef-a", "alpha", "1", "pkg:npm/alpha@1"), pkg("SPDXRef-b", "beta", "1", "pkg:npm/beta@1")])
    doc["relationships"] += [
        rel("SPDXRef-root", "CONTAINS", "SPDXRef-a"),
        rel("SPDXRef-b", "CONTAINED_BY", "SPDXRef-root"),
    ]
    assert [c.direct for c in parse_spdx(doc).components] == ["unknown", "unknown"]
    flat = sbom([pkg("SPDXRef-a", "alpha", "1", "pkg:npm/alpha@1"), pkg("SPDXRef-b", "beta", "1", "pkg:npm/beta@1")])
    flat["relationships"] += [
        rel("SPDXRef-root", "DEPENDS_ON", "SPDXRef-a"),
        rel("SPDXRef-root", "DEPENDS_ON", "SPDXRef-b"),
    ]
    assert [c.direct for c in parse_spdx(flat).components] == ["unknown", "unknown"]


def test_real_github_dependency_graph_export_has_no_direct_marking() -> None:
    """The export read on 2026-11-14 (names replaced): the root depends on all 20 packages, nothing else is related."""
    path = Path(__file__).parent / "fixtures" / "supply_chain" / "github-dependency-graph-sbom.spdx.json"
    info = read_spdx(path)
    assert info.component_count == 18  # 20 packages, 18 distinct purls
    assert {c.direct for c in info.components} == {"unknown"}
    assert info.tools[0].name.startswith("protobom")


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
    created = parse_spdx(doc).created
    assert created == datetime(2026, 11, 10, 1, 0, tzinfo=UTC)
    assert created is not None
    assert created.utcoffset() == timedelta(0)  # equality alone ignores the offset
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
    doc = sbom(packages, declare_empty=False)
    if add_none_marker:
        doc["relationships"].append(rel("SPDXRef-root", "CONTAINS", "NONE"))
    expected = list(dict.fromkeys(p for p in purls if p))
    if not purls and not add_none_marker:
        with pytest.raises(SbomFormatError):
            parse_spdx(doc)
        return
    info = parse_spdx(doc)
    event(f"components={min(len(expected), 3)}")
    assert [c.purl for c in info.components] == expected
    assert info.component_count == len(expected)
    assert info.skipped_without_purl == sum(1 for p in purls if p is None)
    assert info.declared_empty is add_none_marker


def test_module_exposes_supported_version() -> None:
    assert spdx.SUPPORTED_VERSION == "SPDX-2.3"


def test_a_document_of_packages_without_purls_is_returned_but_not_complete() -> None:
    info = parse_spdx(sbom([pkg("SPDXRef-a", "alpha", "1", None)], declare_empty=False))
    assert (info.component_count, info.coverage_complete) == (0, False)
    assert parse_spdx(sbom([pkg("SPDXRef-a", "alpha", "1", "pkg:npm/alpha@1")])).coverage_complete is True


def test_a_purl_without_a_version_makes_the_list_incomplete() -> None:
    info = parse_spdx(
        sbom([pkg("SPDXRef-a", "alpha", "1", "pkg:pypi/alpha"), pkg("SPDXRef-b", "b", "1", "pkg:npm/b@1")])
    )
    assert info.component_count == 2
    assert info.unresolved_version == 1
    assert info.coverage_complete is False
    scoped = parse_spdx(sbom([pkg("SPDXRef-a", "s", "1", "pkg:npm/%40scope/pkg@1.0.0?arch=x#sub")]))
    assert scoped.unresolved_version == 0  # a version after a scoped name, with qualifiers, is a version


def test_two_spellings_of_one_purl_are_one_component() -> None:
    info = parse_spdx(
        sbom(
            [
                pkg("SPDXRef-a", "Foo_Bar", "1", "pkg:pypi/Foo_Bar@1"),
                pkg("SPDXRef-b", "foo-bar", "1", "pkg:pypi/foo-bar@1"),
                pkg("SPDXRef-c", "foo-bar", "2", "pkg:pypi/foo-bar@2"),
            ]
        )
    )
    assert [c.purl for c in info.components] == ["pkg:pypi/Foo_Bar@1", "pkg:pypi/foo-bar@2"]
