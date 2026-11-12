"""Unit and property tests for ``supply_chain.threshold``."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain import models, threshold

NOW = datetime(2026, 11, 10, 0, 0, tzinfo=UTC)
REPO = models.Repo("example-org", "example-repo")
COMPONENT = models.Component(purl="pkg:npm/left-pad@1.3.0", name="left-pad", version="1.3.0")
HIGH_BAR = models.OpeningThreshold("HIGH", True, True)
KEV = frozenset({"CVE-2026-9999"})


def _finding(
    vuln_id: str = "CVE-2026-0001",
    severity: models.Severity | None = None,
    aliases: tuple[str, ...] = (),
) -> models.Finding:
    return models.Finding(
        repo=REPO,
        vuln_id=vuln_id,
        aliases=aliases,
        component=COMPONENT,
        cvss_severity=severity,
        fixed_version=None,
        advisory_published_at=NOW,
        layer="A",
        first_observed_component_at=NOW,
    )


def test_severity_rank_is_ordered() -> None:
    ranks = [threshold.SEVERITY_RANK[s] for s in ("LOW", "MEDIUM", "HIGH", "CRITICAL")]
    assert ranks == [1, 2, 3, 4]
    assert threshold.MALICIOUS_PREFIX == "MAL-"


@pytest.mark.parametrize(
    ("severity", "expected"),
    [("CRITICAL", True), ("HIGH", True), ("MEDIUM", False), ("LOW", False), (None, False)],
)
def test_high_threshold_boundary(severity: models.Severity | None, expected: bool) -> None:
    assert threshold.meets_opening_threshold(_finding(severity=severity), frozenset(), HIGH_BAR) is expected


def test_min_severity_follows_policy() -> None:
    medium_bar = models.OpeningThreshold("MEDIUM", True, True)
    assert threshold.meets_opening_threshold(_finding(severity="MEDIUM"), frozenset(), medium_bar)
    assert not threshold.meets_opening_threshold(_finding(severity="LOW"), frozenset(), medium_bar)
    critical_bar = models.OpeningThreshold("CRITICAL", True, True)
    assert not threshold.meets_opening_threshold(_finding(severity="HIGH"), frozenset(), critical_bar)


def test_kev_listing_opens_low_and_unscored() -> None:
    for severity in ("LOW", "MEDIUM", None):
        assert threshold.meets_opening_threshold(_finding("CVE-2026-9999", severity), KEV, HIGH_BAR)


def test_kev_listing_via_alias() -> None:
    f = _finding("GHSA-aaaa-bbbb-cccc", "LOW", aliases=("CVE-2026-9999",))
    assert threshold.meets_opening_threshold(f, KEV, HIGH_BAR)


def test_kev_not_listed_is_below() -> None:
    assert not threshold.meets_opening_threshold(_finding("CVE-2026-0001", "MEDIUM"), KEV, HIGH_BAR)


def test_kev_ignored_when_policy_disables_it() -> None:
    bar = models.OpeningThreshold("HIGH", False, True)
    assert not threshold.meets_opening_threshold(_finding("CVE-2026-9999", "LOW"), KEV, bar)


def test_kev_none_means_feed_missing() -> None:
    assert not threshold.meets_opening_threshold(_finding("CVE-2026-9999", "LOW"), None, HIGH_BAR)
    # Severity still decides without KEV.
    assert threshold.meets_opening_threshold(_finding("CVE-2026-9999", "HIGH"), None, HIGH_BAR)


def test_empty_kev_differs_from_none_only_by_listing() -> None:
    assert not threshold.meets_opening_threshold(_finding("CVE-2026-9999", "LOW"), frozenset(), HIGH_BAR)


def test_malicious_always_opens() -> None:
    f = _finding("MAL-2026-0001", None)
    assert threshold.is_malicious(f)
    assert threshold.meets_opening_threshold(f, None, models.OpeningThreshold("CRITICAL", False, True))
    assert threshold.meets_opening_threshold(f, frozenset(), HIGH_BAR)


def test_malicious_via_alias() -> None:
    f = _finding("GHSA-aaaa-bbbb-cccc", None, aliases=("MAL-2026-0001",))
    assert threshold.is_malicious(f)
    assert threshold.meets_opening_threshold(f, None, HIGH_BAR)


def test_is_malicious_is_prefix_and_case_sensitive() -> None:
    assert not threshold.is_malicious(_finding("CVE-2026-0001", aliases=("GHSA-xMAL-1",)))
    assert not threshold.is_malicious(_finding("mal-2026-0001"))
    assert not threshold.is_malicious(_finding("MAL2026"))


def test_unscored_non_kev_non_malicious_is_below() -> None:
    assert not threshold.meets_opening_threshold(_finding("CVE-2026-0001", None), KEV, HIGH_BAR)


def test_malicious_vex_does_not_matter_here() -> None:
    # VEX exclusion is the planner's concern; the threshold function has no VEX input.
    import inspect

    params = inspect.signature(threshold.meets_opening_threshold).parameters
    assert list(params) == ["finding", "kev_ids", "threshold"]


# ---- Property 5 (local strategies; 9.1 owns the shared generators) ----

_PREFIXES = ("CVE-2026-", "GHSA-", "MAL-")
_vuln_ids = st.builds(lambda p, n: f"{p}{n}", st.sampled_from(_PREFIXES), st.integers(0, 30))
_severities = st.sampled_from(["CRITICAL", "HIGH", "MEDIUM", "LOW", None])
_findings = st.builds(
    lambda v, a, s: _finding(v, s, tuple(a)),
    _vuln_ids,
    st.lists(_vuln_ids, max_size=3),
    _severities,
)
_thresholds = st.builds(
    models.OpeningThreshold,
    st.sampled_from(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
    st.booleans(),
    st.just(True),
)
_kev = st.one_of(st.none(), st.frozensets(_vuln_ids, max_size=10))


def _oracle(f: models.Finding, kev: frozenset[str] | None, t: models.OpeningThreshold) -> bool:
    ids = (f.vuln_id, *f.aliases)
    mal = any(i.startswith("MAL-") for i in ids)
    sev = (
        f.cvss_severity is not None
        and threshold.SEVERITY_RANK[f.cvss_severity] >= threshold.SEVERITY_RANK[t.min_cvss_severity]
    )
    in_kev = t.open_if_kev_listed and kev is not None and any(i in kev for i in ids)
    return mal or sev or in_kev


# Feature: cyber-resilience-phase4-supply-chain, Property 5: 閾値判定は定義どおりで EPSS に依存しない
@settings(max_examples=300, deadline=None)
@given(f=_findings, kev=_kev, t=_thresholds, other_severity=_severities, other_kev=_kev)
def test_property_5_threshold_matches_definition(
    f: models.Finding,
    kev: frozenset[str] | None,
    t: models.OpeningThreshold,
    other_severity: models.Severity | None,
    other_kev: frozenset[str] | None,
) -> None:
    """Property 5: the decision equals the definition; malicious always opens.

    **Validates: Requirements 7.3, 7.4, 7.5, 7.9, 7.11**
    """
    result = threshold.meets_opening_threshold(f, kev, t)
    assert result is _oracle(f, kev, t)
    event(f"malicious={threshold.is_malicious(f)}")
    event(f"result={result}")
    if threshold.is_malicious(f):
        changed = _finding(f.vuln_id, other_severity, f.aliases)
        assert threshold.meets_opening_threshold(changed, other_kev, t)
    elif f.cvss_severity is None and not (kev and any(i in kev for i in (f.vuln_id, *f.aliases))):
        assert result is False
