"""Tests for ``supply_chain.normalized`` (findings.normalized.json -> Finding). Synthetic data only."""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain.models import Component, Finding, Repo
from supply_chain.normalized import (
    NormalizedFindingsError,
    component_from_purl,
    dedupe_findings,
    findings_from_normalized,
    normalize_severity,
)

SHA = "0123456789abcdef0123456789abcdef01234567"


def doc(*findings: dict[str, Any], **extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema_version": 1,
        "repo": "example-owner/example-repo",
        "commit": SHA,
        "layer": "B",
        "generated_at": "2026-11-10T00:00:00Z",
        "tool": {"name": "trivy", "version": "1.2.3"},
        "findings": list(findings),
    }
    base.update(extra)
    return base


def entry(vuln_id: str = "CVE-2026-0001", purl: str = "pkg:pypi/x@1.2.3", **extra: Any) -> dict[str, Any]:
    return {"vuln_id": vuln_id, "aliases": [], "purl": purl, "cvss_severity": "HIGH", "fixed_version": "1.2.4", **extra}


def test_zero_findings_gives_none_and_keeps_metadata() -> None:
    result = findings_from_normalized(doc())
    assert result.findings == ()
    assert result.repo == Repo("example-owner", "example-repo")
    assert (result.commit, result.layer, result.tool_name, result.tool_version) == (SHA, "B", "trivy", "1.2.3")
    assert result.generated_at == datetime(2026, 11, 10, tzinfo=UTC)


def test_zero_component_sbom_flow_gives_no_findings() -> None:
    """An empty SBOM and an empty scan (Requirement 4.10) load as zero findings."""
    from adapters.spdx import parse_spdx

    sbom = {"spdxVersion": "SPDX-2.3", "packages": [], "relationships": []}
    info = parse_spdx(sbom)
    assert findings_from_normalized(doc(), components=info.components).findings == ()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CRITICAL", "CRITICAL"),
        ("HIGH", "HIGH"),
        ("MEDIUM", "MEDIUM"),
        ("LOW", "LOW"),
        ("high", "HIGH"),
        ("UNKNOWN", None),
        (None, None),
        ("NEGLIGIBLE", None),
        ("", None),
        (7, None),
    ],
)
def test_severity_mapping(raw: object, expected: str | None) -> None:
    assert normalize_severity(raw) == expected


def test_unknown_severity_in_document_maps_to_none() -> None:
    result = findings_from_normalized(doc(entry(cvss_severity="UNKNOWN")))
    assert result.findings[0].cvss_severity is None


def test_mal_id_is_kept_with_no_severity_even_if_scanner_gave_one() -> None:
    result = findings_from_normalized(doc(entry("MAL-2026-1234", cvss_severity="CRITICAL")))
    finding = result.findings[0]
    assert finding.vuln_id == "MAL-2026-1234"
    assert finding.cvss_severity is None


def test_ghsa_with_mal_alias_is_reported_under_the_mal_id() -> None:
    result = findings_from_normalized(doc(entry("GHSA-aaaa-bbbb-cccc", aliases=["MAL-2026-1", "CVE-2026-9"])))
    finding = result.findings[0]
    assert finding.vuln_id == "MAL-2026-1"
    assert finding.cvss_severity is None
    assert set(finding.aliases) == {"GHSA-aaaa-bbbb-cccc", "CVE-2026-9"}


def test_duplicates_by_repo_vuln_id_purl_are_merged() -> None:
    first = entry(aliases=["GHSA-x"], cvss_severity="LOW", fixed_version=None)
    second = entry(aliases=["GHSA-y", "GHSA-x"], cvss_severity="CRITICAL", fixed_version="9.9.9")
    other_purl = entry(purl="pkg:pypi/x@2.0.0")
    other_id = entry("CVE-2026-0002")
    result = findings_from_normalized(doc(first, second, other_purl, other_id))
    assert [(f.vuln_id, f.component.purl) for f in result.findings] == [
        ("CVE-2026-0001", "pkg:pypi/x@1.2.3"),
        ("CVE-2026-0001", "pkg:pypi/x@2.0.0"),
        ("CVE-2026-0002", "pkg:pypi/x@1.2.3"),
    ]
    merged = result.findings[0]
    assert merged.aliases == ("GHSA-x", "GHSA-y")
    assert merged.cvss_severity == "CRITICAL"
    assert merged.fixed_version == "9.9.9"


def test_dedupe_ignores_repo_case() -> None:
    a = findings_from_normalized(doc(entry(), repo="Example-Owner/Example-Repo")).findings
    b = findings_from_normalized(doc(entry())).findings
    assert len(dedupe_findings(a + b)) == 1


def test_dedupe_of_malicious_findings_keeps_severity_none() -> None:
    """``dedupe_findings`` is public: a MAL- pair given a severity still merges to None."""
    when = datetime(2026, 11, 10, tzinfo=UTC)

    def make(severity: str | None) -> Finding:
        return Finding(
            repo=Repo("example-owner", "example-repo"),
            vuln_id="MAL-2026-1",
            aliases=(),
            component=component_from_purl("pkg:npm/a@1"),
            cvss_severity=severity,  # type: ignore[arg-type]
            fixed_version=None,
            advisory_published_at=None,
            layer="B",
            first_observed_component_at=when,
        )

    (merged,) = dedupe_findings([make(None), make("CRITICAL")])
    assert merged.cvss_severity is None


def test_component_reused_from_sbom_and_built_from_purl_otherwise() -> None:
    known = Component(purl="pkg:pypi/x@1.2.3", name="x", version="1.2.3", direct="direct")
    result = findings_from_normalized(doc(entry(), entry(purl="pkg:npm/%40scope/pkg@4.5.6")), components=[known])
    assert result.findings[0].component is known
    other = result.findings[1].component
    assert (other.name, other.version, other.direct) == ("pkg", "4.5.6", "unknown")


@pytest.mark.parametrize(
    ("purl", "name", "version"),
    [
        ("pkg:pypi/x@1.2.3", "x", "1.2.3"),
        ("pkg:npm/%40scope/pkg@1.0.0?arch=x#sub", "pkg", "1.0.0"),
        ("pkg:golang/example.com/m/v2@v2.1.0", "v2", "v2.1.0"),
        ("pkg:pypi/noversion", "noversion", "unknown"),
    ],
)
def test_component_from_purl(purl: str, name: str, version: str) -> None:
    component = component_from_purl(purl)
    assert (component.name, component.version) == (name, version)


def test_times_are_utc_and_first_observed_defaults_to_generated_at() -> None:
    result = findings_from_normalized(doc(entry(advisory_published_at="2026-11-01T09:00:00+09:00")))
    finding = result.findings[0]
    assert finding.advisory_published_at == datetime(2026, 11, 1, tzinfo=UTC)
    assert finding.advisory_published_at is not None
    assert finding.advisory_published_at.utcoffset() == timedelta(0)
    assert finding.first_observed_component_at == result.generated_at
    later = datetime(2026, 11, 11, tzinfo=UTC)
    assert (
        findings_from_normalized(doc(entry()), first_observed_at=later).findings[0].first_observed_component_at == later
    )


def test_unparsable_advisory_time_is_none() -> None:
    assert findings_from_normalized(doc(entry(advisory_published_at="soon"))).findings[0].advisory_published_at is None


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(schema_version=2),
        lambda d: d.update(repo="no-slash"),
        lambda d: d.update(repo="a/b/c"),
        lambda d: d.update(commit="abc"),
        lambda d: d.update(layer="C"),
        lambda d: d.update(generated_at="2026-11-10T00:00:00"),
        lambda d: d.update(tool=[]),
        lambda d: d["tool"].pop("version"),
        lambda d: d.pop("findings"),
        lambda d: d.update(findings=["x"]),
        lambda d: d["findings"].append({"purl": "pkg:npm/a@1"}),
        lambda d: d["findings"].append({"vuln_id": "CVE-1"}),
    ],
)
def test_malformed_documents_raise_without_partial_result(mutate: Any) -> None:
    bad = copy.deepcopy(doc(entry()))
    mutate(bad)
    with pytest.raises(NormalizedFindingsError):
        findings_from_normalized(bad)


def test_non_mapping_document_raises() -> None:
    with pytest.raises(NormalizedFindingsError):
        findings_from_normalized([])  # type: ignore[arg-type]


_IDS = st.sampled_from(["CVE-2026-1", "CVE-2026-2", "GHSA-aaaa-bbbb-cccc", "MAL-2026-1"])
_PURLS = st.sampled_from(["pkg:npm/a@1", "pkg:npm/b@2", "pkg:pypi/c@3"])
_ENTRIES = st.builds(
    lambda i, p, s, a: entry(i, p, cvss_severity=s, aliases=a),
    _IDS,
    _PURLS,
    st.sampled_from(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", None, "weird"]),
    st.lists(st.sampled_from(["CVE-2026-1", "GHSA-zzzz-zzzz-zzzz", "MAL-2026-9"]), max_size=2),
)


@settings(max_examples=100, deadline=None)
@given(entries=st.lists(_ENTRIES, max_size=15))
def test_property_load_is_unique_idempotent_and_mal_has_no_severity(entries: list[dict[str, Any]]) -> None:
    """Result keys are unique, de-duplication is idempotent, MAL- ids carry no severity.

    **Validates: Requirements 4.6, 7.1**
    """
    result = findings_from_normalized(doc(*entries))
    keys = [(f.vuln_id, f.component.purl) for f in result.findings]
    event(f"findings={min(len(keys), 4)}")
    event("has_mal" if any(k[0].startswith("MAL-") for k in keys) else "no_mal")
    assert len(keys) == len(set(keys))
    assert len(keys) <= len(entries)
    assert dedupe_findings(result.findings) == result.findings
    for f in result.findings:
        assert f.vuln_id not in f.aliases
        assert f.cvss_severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", None}
        if f.vuln_id.startswith("MAL-"):
            assert f.cvss_severity is None
    # Same input twice must give the same output.
    assert findings_from_normalized(doc(*entries)).findings == result.findings
