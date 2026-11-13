"""Property 13 for ``supply_chain.issue_body`` (task 9.5): every required item is in the body.

Inputs come from the task 9.1 generator (``tests/strategies/supply_chain.py``): a ``Finding`` is
drawn from ``sc.findings()`` and turned into a ``FindingIssue``, with KEV and EPSS present or absent
independently. The expected values are derived from the ``Finding`` and from
``threshold.is_malicious``, not from ``issue_body``. Task 9.4's
``test_supply_chain_issue_body.py`` checks the same property on hand-written inputs; this file
adds the generator-driven version and the table (the human-readable part) item by item.
"""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import date

import hypothesis.strategies as st
from hypothesis import HealthCheck, event, given, settings
from supply_chain import issue_body as ib
from supply_chain.models import Finding
from supply_chain.threshold import is_malicious

from tests.strategies import supply_chain as sc

_SETTINGS = settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])

MALICIOUS_TEXT = "該当なし（パッケージを取り除くか、記録に載っていないバージョンに変える）"
_DATES = st.dates(min_value=date(2020, 1, 1), max_value=date(2030, 1, 1))
_KEV = st.one_of(st.none(), st.tuples(_DATES, st.sampled_from([None, True, False])))
_EPSS = st.one_of(
    st.none(),
    st.tuples(st.sampled_from(["0.00054", "0.12345", "0.97000"]), _DATES, st.sampled_from(["v2023.03.01", "v5.1"])),
)
_ROW = re.compile(r"^\| (.+?) \| (.*) \|$")


@st.composite
def _cases(draw: st.DrawFn) -> tuple[Finding, ib.FindingIssue] | None:
    """A Finding from the 9.1 generator and the Issue contents built from it; None for an empty set."""
    found = draw(sc.findings(max_size=12))
    if not found:
        return None
    finding = draw(
        st.sampled_from(sorted(found, key=lambda f: (f.repo.owner, f.repo.name, f.vuln_id, f.component.purl)))
    )
    # The generator never puts a MAL- id only in the aliases; swapping the first alias into the
    # primary position gives that shape (a GHSA primary with a MAL- alias, and the reverse).
    if finding.aliases and draw(st.booleans()):
        finding = replace(finding, vuln_id=finding.aliases[0], aliases=(finding.vuln_id, *finding.aliases[1:]))
    kev = draw(_KEV)
    epss = draw(_EPSS)
    opened = draw(sc.utc_datetimes())
    due = draw(sc.utc_datetimes())
    detected = draw(sc.utc_datetimes())
    issue = ib.FindingIssue(
        repo=finding.repo,
        vuln_id=finding.vuln_id,
        aliases=finding.aliases,
        components=(finding.component,),
        cvss_severity=finding.cvss_severity,
        kev=kev,
        epss=epss,
        fixed_version=finding.fixed_version,
        origin_at=finding.advisory_published_at or finding.first_observed_component_at,
        origin_is_date_only=draw(st.booleans()),
        detected_at=detected,
        opened_at=opened,
        due_at=due,
        last_run_id=draw(st.sampled_from(["run-1", "run-2"])),
        history=(),
    )
    return finding, issue


def _table(body: str) -> dict[str, str]:
    """The first two-column table of the body as ``{item: value}``."""
    rows: dict[str, str] = {}
    for line in body.split("\n"):
        m = _ROW.match(line)
        if m and m.group(1) not in ("項目", "purl"):
            rows[m.group(1)] = m.group(2)
    return rows


def _labels(finding: Finding, issue: ib.FindingIssue) -> frozenset[str]:
    unfixed = not is_malicious(finding) and finding.fixed_version is None
    return frozenset(
        {
            f"unfixed_non_malicious={unfixed}",
            f"malicious={is_malicious(finding)}",
            f"fixed={finding.fixed_version is not None}",
            f"epss={issue.epss is not None}",
            f"kev={issue.kev is not None}",
            f"severity={finding.cvss_severity}",
            f"aliases={bool(finding.aliases)}",
            f"malicious_only_in_aliases={is_malicious(finding) and not finding.vuln_id.startswith('MAL-')}",
        }
    )


# Feature: cyber-resilience-phase4-supply-chain, Property 13: Issue 本文は必須の項目をすべて持つ
@_SETTINGS
@given(_cases())
def test_body_has_every_required_item(case: tuple[Finding, ib.FindingIssue] | None) -> None:
    """**Validates: Requirements 8.3, 8.6, 26.4**"""
    if case is None:
        event("empty finding set")
        return
    finding, issue = case
    for label in _labels(finding, issue):
        event(label)
    malicious = is_malicious(finding)
    body = ib.render_finding(issue)

    # Line 1 is the marker for this Issue.
    marker = ib.parse_marker(body)
    assert marker is not None and ib.is_managed(marker, finding.repo)
    assert (marker.kind, marker.repo, marker.vuln_id) == ("finding", finding.repo, finding.vuln_id)

    # State block: malicious matches is_malicious, and no item is dropped.
    state = ib.parse_state(body)
    assert state is not None
    assert state["malicious"] is malicious
    assert state["vuln_id"] == finding.vuln_id
    assert state["components"] == [{"purl": finding.component.purl, "version": finding.component.version}]
    assert state["cvss_severity"] == finding.cvss_severity
    assert state["kev_listed"] is (issue.kev is not None)
    for key in ("epss", "fixed_version", "detected_at", "due_at", "opened_at", "origin_at"):
        assert key in state
    stamp = "%Y-%m-%dT%H:%M:%SZ"
    assert state["detected_at"] == issue.detected_at.strftime(stamp)
    assert state["due_at"] == issue.due_at.strftime(stamp)

    # Table: one row per required item, with the value or the stated placeholder.
    rows = _table(body)
    assert rows["脆弱性識別子"] == finding.vuln_id
    assert rows["悪意のあるパッケージ（MAL-）"] == ("はい" if malicious else "いいえ")
    assert rows["CVSS 重大度"] == (finding.cvss_severity or "未付与")
    assert rows["検出日時"] == issue.detected_at.strftime(stamp)
    assert rows["修正の期限（Response_Target）"] == issue.due_at.strftime(stamp)
    assert finding.component.purl in body and finding.component.version in body
    if issue.kev is None:
        assert rows["KEV 掲載"] == "掲載なし"
    else:
        assert issue.kev[0].isoformat() in rows["KEV 掲載"]
    if issue.epss is None:
        assert "未取得" in rows["EPSS"] and state["epss"] is None
    else:
        score, day, model = issue.epss
        assert score in rows["EPSS"] and day.isoformat() in rows["EPSS"] and model in rows["EPSS"]
        assert state["epss"] == {"score": score, "date": day.isoformat(), "model_version": model}
    if malicious:
        assert rows["修正済みバージョン"] == MALICIOUS_TEXT
        assert state["fixed_version"] is None
    elif finding.fixed_version is None:
        assert rows["修正済みバージョン"] == "未判明"
    else:
        assert rows["修正済みバージョン"] == finding.fixed_version
    assert all(value.strip() for value in rows.values())


def test_the_generator_reaches_every_shape_the_property_names() -> None:
    """The property is not vacuous: both values of each named input occur (fixed seed, 400 draws)."""
    seen: set[str] = set()

    @settings(
        max_examples=400, deadline=None, derandomize=True, database=None, suppress_health_check=[HealthCheck.too_slow]
    )
    @given(_cases())
    def collect(case: tuple[Finding, ib.FindingIssue] | None) -> None:
        seen.add("nonempty" if case else "empty")
        if case:
            seen.update(_labels(*case))

    collect()
    for needed in (
        "nonempty",
        "malicious=True",
        "malicious=False",
        "fixed=True",
        "fixed=False",
        "epss=True",
        "epss=False",
        "kev=True",
        "kev=False",
        "aliases=True",
        "aliases=False",
        "severity=None",
        "severity=HIGH",
    ):
        assert needed in seen, needed
    # The "未判明" case: one Finding that is not malicious and has no fixed version.
    assert "unfixed_non_malicious=True" in seen
    # A MAL- identifier that is only an alias (the primary is a GHSA or CVE).
    assert "malicious_only_in_aliases=True" in seen
