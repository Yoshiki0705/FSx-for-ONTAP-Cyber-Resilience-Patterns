"""Tests for ``supply_chain.canonical``: identifier case, alias joining, and the purl comparison form."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain import models
from supply_chain.canonical import canonical_id, canonicalize, purl_key

NOW = datetime(2026, 11, 10, 6, 0, tzinfo=UTC)
REPO = models.Repo("example-org", "svc-api")
OTHER = models.Repo("example-org", "svc-web")
PURL = "pkg:npm/left-pad@1.3.0"


def _f(
    vuln_id: str,
    aliases: tuple[str, ...] = (),
    *,
    severity: models.Severity | None = "HIGH",
    repo: models.Repo = REPO,
    purl: str = PURL,
    published: datetime | None = None,
) -> models.Finding:
    name, _, version = purl.removeprefix("pkg:npm/").partition("@")
    return models.Finding(
        repo=repo,
        vuln_id=vuln_id,
        aliases=aliases,
        component=models.Component(purl=purl, name=name, version=version),
        cvss_severity=severity,
        fixed_version=None,
        advisory_published_at=published,
        layer="A",
        first_observed_component_at=NOW - timedelta(days=5),
    )


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        ("cve-2026-0001", "CVE-2026-0001"),
        (" CVE-2026-0001 ", "CVE-2026-0001"),
        ("mal-2026-0001", "MAL-2026-0001"),
        ("GHSA-AAAA-BBBB-CCCC", "GHSA-aaaa-bbbb-cccc"),
        ("ghsa-aaaa-bbbb-cccc", "GHSA-aaaa-bbbb-cccc"),
        ("PYSEC-2026-1", "PYSEC-2026-1"),
    ],
)
def test_canonical_id(raw: str, want: str) -> None:
    assert canonical_id(raw) == want


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        ("pkg:npm/left-pad@1.3.0", "pkg:npm/left-pad@1.3.0"),
        ("pkg:npm/Left-Pad@1.3.0?arch=x86#sub/path", "pkg:npm/left-pad@1.3.0"),
        ("pkg:npm/%40scope/Name@1.0.0", "pkg:npm/@scope/name@1.0.0"),
        ("pkg:npm/@scope/name@1.0.0", "pkg:npm/@scope/name@1.0.0"),
        ("pkg:pypi/Foo_Bar.baz@2.0", "pkg:pypi/foo-bar-baz@2.0"),
        ("PKG:NPM/x@1".replace("PKG:NPM", "pkg:NPM"), "pkg:npm/x@1"),
        ("pkg:npm/left-pad", "pkg:npm/left-pad"),
        ("pkg:maven/Org.Example/Artifact@1.0", "pkg:maven/Org.Example/Artifact@1.0"),  # maven is case-sensitive
    ],
)
def test_purl_key(raw: str, want: str) -> None:
    assert purl_key(raw) == want


@pytest.mark.parametrize("raw", ["https://example.com/p/1", "", "pkg:", "pkg:npm", "left-pad@1.0.0"])
def test_a_string_that_is_not_a_purl_has_no_key(raw: str) -> None:
    assert purl_key(raw) is None


def test_a_ghsa_and_a_cve_that_name_each_other_become_one_finding_with_the_cve_as_representative() -> None:
    a = _f("CVE-2026-0001", ("GHSA-aaaa-bbbb-cccc",))
    b = _f("GHSA-aaaa-bbbb-cccc", ("CVE-2026-0001",), severity="CRITICAL")
    (one,) = canonicalize([a, b])
    assert one.vuln_id == "CVE-2026-0001"
    assert one.aliases == ("GHSA-aaaa-bbbb-cccc",)
    assert one.cvss_severity == "CRITICAL"  # the stronger severity of the two reports


def test_a_link_through_a_third_identifier_joins_the_set() -> None:
    a = _f("GHSA-aaaa-bbbb-cccc", ("CVE-2026-0001",))
    b = _f("GHSA-dddd-eeee-ffff", ("CVE-2026-0001",))
    (one,) = canonicalize([a, b])
    assert one.vuln_id == "CVE-2026-0001"
    assert one.aliases == ("GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff")


def test_a_mal_identifier_is_the_representative_over_cve_and_ghsa() -> None:
    (one,) = canonicalize([_f("GHSA-aaaa-bbbb-cccc", ("MAL-2026-0001", "CVE-2026-0001"))])
    assert one.vuln_id == "MAL-2026-0001"
    assert one.aliases == ("CVE-2026-0001", "GHSA-aaaa-bbbb-cccc")


def test_identifier_case_is_canonical_in_names_and_aliases() -> None:
    one = canonicalize([_f("ghsa-AAAA-bbbb-cccc", ("cve-2026-0001",))])
    assert [(f.vuln_id, f.aliases) for f in one] == [("CVE-2026-0001", ("GHSA-aaaa-bbbb-cccc",))]


def test_unrelated_identifiers_and_other_repositories_stay_apart() -> None:
    items = [_f("CVE-2026-0001"), _f("CVE-2026-0002"), _f("CVE-2026-0001", repo=OTHER)]
    assert len(canonicalize(items)) == 3


def test_the_same_vulnerability_on_two_components_is_two_findings_with_one_identifier() -> None:
    a = _f("CVE-2026-0001", ("GHSA-aaaa-bbbb-cccc",))
    b = _f("GHSA-aaaa-bbbb-cccc", purl="pkg:npm/left-pad@1.4.0")
    out = canonicalize([a, b])
    assert [(f.vuln_id, f.component.version) for f in out] == [("CVE-2026-0001", "1.3.0"), ("CVE-2026-0001", "1.4.0")]


def test_merging_keeps_the_earliest_publication_and_a_malware_type() -> None:
    early, late = NOW - timedelta(days=3), NOW - timedelta(days=1)
    a = _f("CVE-2026-0001", ("GHSA-aaaa-bbbb-cccc",), published=late)
    b = replace(_f("GHSA-aaaa-bbbb-cccc", published=early), advisory_type="malware")
    (one,) = canonicalize([a, b])
    assert one.advisory_published_at == early
    assert one.advisory_type == "malware"


def test_the_result_does_not_depend_on_the_order_of_records_that_link_two_cves_through_other_identifiers() -> None:
    # A shared GHSA and a PYSEC reach both CVEs through records that each name one CVE only (T2-R2-02): every
    # order of the three records gives the same result, and applying the function again changes nothing.
    import itertools

    records = [
        _f("CVE-2026-0001", ("PYSEC-1",), repo=OTHER),
        _f("GHSA-aaaa-bbbb-cccc", ("CVE-2026-0002",), repo=OTHER),
        _f("GHSA-aaaa-bbbb-cccc", ("PYSEC-1",), repo=OTHER),
    ]
    results = {canonicalize(list(p)) for p in itertools.permutations(records)}
    assert len(results) == 1
    (out,) = results
    assert canonicalize(out) == out
    assert [(f.vuln_id, f.aliases) for f in out] == [
        ("CVE-2026-0001", ("GHSA-aaaa-bbbb-cccc", "PYSEC-1")),
        ("CVE-2026-0002", ("GHSA-aaaa-bbbb-cccc", "PYSEC-1")),
    ]


_NAMES = st.sampled_from(
    ["CVE-2026-0001", "CVE-2026-0002", "GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff", "MAL-2026-0001", "PYSEC-1"]
)
_CASE = st.sampled_from([str.upper, str.lower, lambda t: t])
_findings = st.builds(
    lambda name, aliases, repo, case: _f(case(name), tuple(case(a) for a in aliases), repo=repo),
    _NAMES,
    st.lists(_NAMES, max_size=2).map(tuple),
    st.sampled_from([REPO, OTHER]),
    _CASE,
)


# Feature: cyber-resilience-phase4-supply-chain, Property 8 (T2-02): alias-linked reports are one vulnerability
@settings(max_examples=200, deadline=None)
@given(st.lists(_findings, max_size=6), st.randoms(use_true_random=False))
def test_property_canonicalize_is_idempotent_order_free_and_leaves_no_shared_identifier(
    items: list[models.Finding], rnd: object
) -> None:
    """**Validates: Requirements 8.1**"""
    once = canonicalize(items)
    event(f"findings={min(len(once), 4)}")
    assert canonicalize(once) == once
    shuffled = list(items)
    rnd.shuffle(shuffled)  # type: ignore[attr-defined]
    assert canonicalize(shuffled) == once
    seen: dict[tuple[str, str], set[str]] = {}
    for f in once:
        repo = (f.repo.owner.lower(), f.repo.name.lower())
        for i in (f.vuln_id, *f.aliases):
            assert i == canonical_id(i)
            seen.setdefault((repo[0] + "/" + repo[1], i), set()).add(f.vuln_id)
    for (_, i), reps in seen.items():
        # an identifier names one vulnerability per repository, so one representative; the only exception is an
        # identifier that the sources declare together with two different CVEs (T2-R2-02): it is listed under each
        # CVE, and a record that names it alone stays its own vulnerability
        # (a malicious-package record that also names a CVE keeps its MAL- representative beside the CVE's own)
        assert len({r for r in reps if not r.startswith("MAL-")}) <= 1 or not i.startswith(("CVE-", "MAL-"))
    keys = [(f.repo.owner.lower(), f.repo.name.lower(), f.vuln_id, f.component.purl) for f in once]
    assert len(keys) == len(set(keys))
