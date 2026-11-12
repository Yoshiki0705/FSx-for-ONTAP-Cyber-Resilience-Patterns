"""Property 5: the Opening_Threshold decision follows its definition and ignores EPSS.

Uses the shared generators of task 9.1 (``findings``, ``policies``, ``feeds``).
"""

from __future__ import annotations

import dataclasses
import inspect
from collections.abc import Sequence

import hypothesis.strategies as st
from hypothesis import HealthCheck, event, given, settings
from supply_chain.models import FeedSnapshot, Finding, OpeningThreshold, Policy
from supply_chain.threshold import meets_opening_threshold

from tests.strategies import supply_chain as sc

_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def _ids(finding: Finding) -> tuple[str, ...]:
    return (finding.vuln_id, *finding.aliases)


def _expected(finding: Finding, kev: frozenset[str] | None, bar: OpeningThreshold) -> bool:
    """The definition of Property 5, written from the design text."""
    if any(i.startswith("MAL-") for i in _ids(finding)):
        return True
    if finding.cvss_severity is not None and _RANK[finding.cvss_severity] >= _RANK[bar.min_cvss_severity]:
        return True
    return bar.open_if_kev_listed and kev is not None and any(i in kev for i in _ids(finding))


def _kev_ids(snapshot: FeedSnapshot) -> frozenset[str] | None:
    return None if snapshot.kev is None else frozenset(snapshot.kev)


@st.composite
def _cases(draw: st.DrawFn) -> tuple[Sequence[Finding], Policy, sc.FeedsCase, sc.FeedsCase]:
    found = sorted(draw(sc.findings(max_size=30)), key=repr)
    ids = sorted({i for f in found for i in _ids(f)})
    return found, draw(sc.policies()), draw(sc.feeds(vuln_ids=ids)), draw(sc.feeds(vuln_ids=ids))


# Feature: cyber-resilience-phase4-supply-chain, Property 5: 閾値判定は定義どおりで EPSS に依存しない
@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(case=_cases())
def test_threshold_follows_definition_and_ignores_epss(
    case: tuple[Sequence[Finding], Policy, sc.FeedsCase, sc.FeedsCase],
) -> None:
    """Every Finding is judged as defined, for every severity bar and with EPSS swapped.

    **Validates: Requirements 7.3, 7.4, 7.5, 7.6, 7.9, 7.11, 27.4**
    """
    found, policy, feeds_a, feeds_b = case
    kev = _kev_ids(feeds_a.snapshot)
    swapped = dataclasses.replace(feeds_a.snapshot, epss=feeds_b.snapshot.epss)
    assert _kev_ids(swapped) == kev
    event(f"kev={'missing' if kev is None else 'present'}")
    event(f"epss_swap={'different' if feeds_a.snapshot.epss != feeds_b.snapshot.epss else 'same'}")

    for finding in found:
        malicious = any(i.startswith("MAL-") for i in _ids(finding))
        listed = kev is not None and any(i in kev for i in _ids(finding))
        bar = policy.opening_threshold
        got = meets_opening_threshold(finding, kev, bar)
        assert got is _expected(finding, kev, bar)
        # EPSS is not an input: the decision with the other EPSS feed's snapshot is the same.
        assert meets_opening_threshold(finding, _kev_ids(swapped), bar) is got

        if malicious:
            event("shape=malicious")
            # Any severity, KEV set and bar leaves it open.
            for level in _LEVELS:
                for open_kev in (False, True):
                    other = OpeningThreshold(level, open_kev, True)
                    for other_kev in (None, frozenset(), kev or frozenset()):
                        changed = dataclasses.replace(finding, cvss_severity=level)
                        assert meets_opening_threshold(changed, other_kev, other) is True
        elif finding.cvss_severity is None and not (bar.open_if_kev_listed and listed):
            event("shape=below")
            assert got is False
        elif listed and bar.open_if_kev_listed:
            event("shape=kev")
            assert got is True
        else:
            event("shape=severity")

        # The severity boundary: for each bar, a non-malicious, non-KEV finding opens iff rank >= bar.
        if not malicious and not listed and finding.cvss_severity is not None:
            for level in _LEVELS:
                edge = OpeningThreshold(level, bar.open_if_kev_listed, True)
                assert meets_opening_threshold(finding, kev, edge) is (_RANK[finding.cvss_severity] >= _RANK[level])


def test_signature_has_no_epss_input() -> None:
    """The decision function takes only the finding, the KEV set and the threshold."""
    assert list(inspect.signature(meets_opening_threshold).parameters) == ["finding", "kev_ids", "threshold"]
