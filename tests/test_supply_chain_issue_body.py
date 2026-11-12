"""Unit and property tests for ``supply_chain.issue_body`` (task 9.4)."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta

import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain import issue_body as ib
from supply_chain.models import Component, Repo

NOW = datetime(2026, 11, 10, 3, 4, 5, tzinfo=UTC)
REPO = Repo("example-org", "example-repo")
HUB = Repo("example-org", "example-hub")

_ID_TAIL = st.text(alphabet="ABCDEFGHJKMNPQRSTVWXYZ0123456789-", min_size=1, max_size=12)
_vuln_ids = st.one_of(
    _ID_TAIL.map(lambda s: f"CVE-{s}"), _ID_TAIL.map(lambda s: f"GHSA-{s}"), _ID_TAIL.map(lambda s: f"MAL-{s}")
)
_alias_lists = st.lists(_vuln_ids, max_size=3, unique=True).map(tuple)
# Characters that would break a table, a JSON fence or a marker if they were not handled.
_nasty = st.text(alphabet="ab|`\n\r\\<>-! 日本", min_size=1, max_size=20)
_components = st.builds(
    Component,
    purl=st.text(alphabet="abc/@:.0123456789", min_size=3, max_size=30).map(lambda s: "pkg:npm/" + s),
    name=_nasty,
    version=st.text(alphabet="0123456789.", min_size=1, max_size=8),
)
_dts = st.datetimes(min_value=datetime(2020, 1, 1), max_value=datetime(2030, 1, 1)).map(
    lambda d: d.replace(microsecond=0, tzinfo=UTC)
)
_dates = st.dates(min_value=date(2020, 1, 1), max_value=date(2030, 1, 1))
_history = st.lists(
    st.builds(ib.HistoryEntry, op=st.sampled_from(["open", "update", "close", "reopen"]), run_id=_ID_TAIL, at=_dts),
    max_size=6,
).map(tuple)


@st.composite
def finding_issues(draw: st.DrawFn, max_components: int = 8) -> ib.FindingIssue:
    """A FindingIssue with and without fixed version, EPSS, KEV and aliases."""
    vuln = draw(_vuln_ids)
    return ib.FindingIssue(
        repo=draw(st.sampled_from([REPO, HUB])),
        vuln_id=vuln,
        aliases=draw(_alias_lists),
        components=tuple(draw(st.lists(_components, min_size=1, max_size=max_components))),
        cvss_severity=draw(st.sampled_from([None, "CRITICAL", "HIGH", "MEDIUM", "LOW"])),
        kev=draw(st.one_of(st.none(), st.tuples(_dates, st.sampled_from([None, True, False])))),
        epss=draw(st.one_of(st.none(), st.tuples(st.just("0.00540"), _dates, st.just("v5.1")))),
        fixed_version=draw(st.one_of(st.none(), st.just("1.2.3"))),
        origin_at=draw(_dts),
        origin_is_date_only=draw(st.booleans()),
        detected_at=draw(_dts),
        opened_at=draw(_dts),
        due_at=draw(_dts),
        last_run_id=draw(_ID_TAIL),
        history=draw(_history),
    )


def _fi(**kw: object) -> ib.FindingIssue:
    base = {
        "repo": REPO,
        "vuln_id": "CVE-2026-0001",
        "aliases": (),
        "components": (Component("pkg:npm/left-pad@1.3.0", "left-pad", "1.3.0"),),
        "cvss_severity": "HIGH",
        "kev": None,
        "epss": None,
        "fixed_version": None,
        "origin_at": NOW,
        "origin_is_date_only": False,
        "detected_at": NOW,
        "opened_at": NOW,
        "due_at": NOW + timedelta(days=7),
        "last_run_id": "run-1",
        "history": (),
    }
    base.update(kw)
    return ib.FindingIssue(**base)  # type: ignore[arg-type]


def _big(n: int, name_len: int = 400) -> tuple[Component, ...]:
    return tuple(Component(f"pkg:npm/p{i:04d}@1.0.0", "n" * name_len, "1.0.0") for i in range(n))


# Feature: cyber-resilience-phase4-supply-chain, Property 13: Issue 本文は必須の項目をすべて持つ
@settings(max_examples=100, deadline=None)
@given(finding_issues())
def test_body_has_marker_state_and_every_required_item(data: ib.FindingIssue) -> None:
    """**Validates: Requirements 8.3, 8.6, 26.4**"""
    body = ib.render_finding(data)
    marker = ib.parse_marker(body)
    assert marker is not None
    assert (marker.kind, marker.repo, marker.vuln_id) == ("finding", data.repo, data.vuln_id)
    assert marker.aliases == tuple(sorted(set(data.aliases) - {data.vuln_id}))
    state = ib.parse_state(body)
    assert state is not None
    malicious = any(i.startswith("MAL-") for i in (data.vuln_id, *data.aliases))
    event(f"malicious={malicious}")
    event(f"fixed={data.fixed_version is not None}")
    event(f"epss={data.epss is not None}")
    assert state["malicious"] is malicious
    assert state["vuln_id"] == data.vuln_id
    assert state["kev_listed"] is (data.kev is not None)
    assert state["cvss_severity"] == data.cvss_severity
    assert state["due_at"].endswith("Z") and state["detected_at"].endswith("Z")
    assert state["origin_is_date_only"] is data.origin_is_date_only
    assert data.vuln_id in body
    assert data.due_at.strftime("%Y-%m-%dT%H:%M:%SZ") in body
    assert data.detected_at.strftime("%Y-%m-%dT%H:%M:%SZ") in body
    if data.epss is None:
        assert ib.EPSS_MISSING in body and state["epss"] is None
    else:
        assert data.epss[1].isoformat() in body and data.epss[2] in body
        assert state["epss"] == {"score": data.epss[0], "date": data.epss[1].isoformat(), "model_version": data.epss[2]}
    if malicious:
        assert ib.MALICIOUS_FIXED_TEXT in body
    elif data.fixed_version is None:
        assert ib.NOT_FIXED_YET in body
    else:
        assert data.fixed_version in body
    if data.kev is not None:
        assert data.kev[0].isoformat() in body
        assert state["kev"]["known_ransomware_campaign_use"] is data.kev[1]
    assert [h["run_id"] for h in state["history"]] == [h.run_id for h in data.history]
    assert state["last_run_id"] == data.last_run_id


def test_missing_values_are_written_not_omitted() -> None:
    body = ib.render_finding(_fi())
    assert ib.NOT_FIXED_YET in body and ib.EPSS_MISSING in body
    assert "いいえ" in body  # not a malicious package


def test_malicious_issue_uses_the_design_wording_and_null_severity() -> None:
    data = _fi(vuln_id="MAL-2026-0001", aliases=("GHSA-aaaa-bbbb",), cvss_severity=None, fixed_version="9.9.9")
    body = ib.render_finding(data)
    state = ib.parse_state(body)
    assert ib.MALICIOUS_FIXED_TEXT in body
    assert "9.9.9" not in body
    assert state is not None and state["malicious"] is True and state["cvss_severity"] is None
    assert body.splitlines()[0] == (
        "<!-- supply-chain-aggregator:v1 kind=finding repo=example-org/example-repo vuln=MAL-2026-0001 "
        "aliases=GHSA-aaaa-bbbb -->"
    )


def test_a_ghsa_primary_with_mal_alias_is_still_malicious() -> None:
    state = ib.parse_state(ib.render_finding(_fi(vuln_id="GHSA-aaaa", aliases=("MAL-2026-1",))))
    assert state is not None and state["malicious"] is True


def test_kev_and_epss_are_shown_with_date_and_model() -> None:
    data = _fi(kev=(date(2026, 11, 1), True), epss=("0.97000", date(2026, 11, 9), "v5.1"), origin_is_date_only=True)
    body = ib.render_finding(data)
    assert "2026-11-01" in body and "確認あり" in body
    assert "0.97000" in body and "2026-11-09" in body and "v5.1" in body
    assert "日付だけの値" in body


# Feature: cyber-resilience-phase4-supply-chain, Property 13: Issue 本文は必須の項目をすべて持つ
@settings(max_examples=100, deadline=None)
@given(
    st.integers(min_value=0, max_value=260),
    st.sampled_from([0, 30, 400]),
    st.sampled_from([2_000, 20_000, ib.MAX_BODY_CHARS]),
)
def test_body_is_cut_to_the_limit_and_the_cut_is_written(n: int, name_len: int, limit: int) -> None:
    """**Validates: Requirements 8.3**"""
    comps = _big(n, name_len) if n else ()
    data = _fi(components=comps)
    body = ib.render_finding(data, max_chars=limit)
    assert len(body) <= limit
    state = ib.parse_state(body)
    if state is None:  # fixed fields alone exceed a tiny limit; clipped
        event("clipped")
        return
    shown = len(state["components"])
    omitted = state["components_omitted"]
    assert shown + omitted == n
    assert shown <= ib.MAX_COMPONENTS
    event(f"cut={omitted > 0}")
    if omitted:
        assert f"{omitted} 件" in body
    # Maximality: the body is within one component's size (plus the omitted-count line) of the limit.
    if shown < min(n, ib.MAX_COMPONENTS):
        big = 10**9
        one_more = len(ib.render_finding(_fi(components=comps[:2]), big)) - len(
            ib.render_finding(_fi(components=comps[:1]), big)
        )
        assert len(body) + one_more + 80 > limit


def test_more_than_200_components_are_cut_at_200_with_the_count() -> None:
    body = ib.render_finding(_fi(components=_big(230, 0)))
    state = ib.parse_state(body)
    assert state is not None
    assert len(state["components"]) == 200 and state["components_omitted"] == 30
    assert "30 件" in body


def test_history_is_dropped_oldest_first_when_components_alone_do_not_help() -> None:
    hist = tuple(ib.HistoryEntry("update", f"r{i:03d}", NOW) for i in range(400))
    full = ib.render_finding(_fi(history=hist), max_chars=10**9)
    body = ib.render_finding(_fi(history=hist), max_chars=len(full) - 100)
    state = ib.parse_state(body)
    assert state is not None and len(body) <= len(full) - 100
    kept = [h["run_id"] for h in state["history"]]
    assert kept == [h.run_id for h in hist][-len(kept) :] and 0 < len(kept) < 400


def test_a_limit_below_the_fixed_fields_still_returns_at_most_the_limit() -> None:
    assert len(ib.render_finding(_fi(), max_chars=50)) == 50


# Feature: cyber-resilience-phase4-supply-chain, Property 13: Issue 本文は必須の項目をすべて持つ
@settings(max_examples=100, deadline=None)
@given(finding_issues(), _ID_TAIL, _history)
def test_comparison_state_ignores_only_history_and_last_run_id(data: ib.FindingIssue, run: str, hist: tuple) -> None:
    """**Validates: Requirements 8.2**"""
    a = ib.parse_state(ib.render_finding(data))
    other = ib.parse_state(ib.render_finding(_replace(data, last_run_id=run, history=hist)))
    assert a is not None and other is not None
    assert ib.comparison_state(a) == ib.comparison_state(other)
    assert set(a) - set(ib.comparison_state(a)) == {"history", "last_run_id"}
    changed = ib.parse_state(ib.render_finding(_replace(data, due_at=data.due_at + timedelta(days=1))))
    assert changed is not None and ib.comparison_state(changed) != ib.comparison_state(a)


def _asdict(obj: ib.FindingIssue) -> dict[str, object]:
    return {f: getattr(obj, f) for f in obj.__slots__}


def _replace(obj: ib.FindingIssue, **kw: object) -> ib.FindingIssue:
    return ib.FindingIssue(**{**_asdict(obj), **kw})


# Feature: cyber-resilience-phase4-supply-chain, Property 13: Issue 本文は必須の項目をすべて持つ
@settings(max_examples=100, deadline=None)
@given(finding_issues(), st.randoms(use_true_random=False))
def test_rendering_is_deterministic_and_ignores_component_order(data: ib.FindingIssue, rnd: object) -> None:
    """**Validates: Requirements 8.5**"""
    shuffled = list(data.components)
    rnd.shuffle(shuffled)  # type: ignore[attr-defined]
    assert ib.render_finding(data) == ib.render_finding(_replace(data, components=tuple(shuffled)))


# Feature: cyber-resilience-phase4-supply-chain, Property 13: Issue 本文は必須の項目をすべて持つ
@settings(max_examples=100, deadline=None)
@given(finding_issues())
def test_hostile_text_does_not_break_the_state_block_or_marker(data: ib.FindingIssue) -> None:
    """**Validates: Requirements 8.6**"""
    body = ib.render_finding(data)
    state = ib.parse_state(body)
    assert state is not None
    assert len(state["components"]) == len(data.components)
    assert body.count("```json " + ib.STATE_FENCE_TAG) == 1
    assert body.count("\n```\n") == 1  # the fence closes once; names cannot add a fence
    assert ib.parse_marker(body) is not None


# Feature: cyber-resilience-phase4-supply-chain, Property 14: 管理対象でない Issue は操作されない
@settings(max_examples=100, deadline=None)
@given(finding_issues(), st.sampled_from(["other-org/example-repo", "example-org/other-repo"]))
def test_marker_repo_must_match_the_issue_repo(data: ib.FindingIssue, other: str) -> None:
    """**Validates: Requirements 8.6**"""
    marker = ib.parse_marker(ib.render_finding(data))
    assert ib.is_managed(marker, data.repo)
    assert ib.is_managed(marker, Repo(data.repo.owner.upper(), data.repo.name.lower()))
    owner, _, name = other.partition("/")
    assert not ib.is_managed(marker, Repo(owner, name))


@pytest.mark.parametrize(
    "body",
    [
        None,
        "",
        "no marker here",
        " <!-- supply-chain-aggregator:v1 kind=finding repo=example-org/example-repo vuln=CVE-1 -->",
        "<!-- supply-chain-aggregator:v1 kind=finding repo=example-org/example-repo vuln=CVE-1 --> trailing",
        "<!-- supply-chain-aggregator:v2 kind=finding repo=example-org/example-repo vuln=CVE-1 -->",
        "<!-- supply-chain-aggregator:v1 kind=other repo=example-org/example-repo -->",
        "<!-- supply-chain-aggregator:v1 kind=finding repo=noslash vuln=CVE-1 -->",
        "<!-- supply-chain-aggregator:v1 kind=finding repo=a/b/c vuln=CVE-1 -->",
        "text first\n<!-- supply-chain-aggregator:v1 kind=finding repo=example-org/example-repo vuln=CVE-1 -->",
    ],
)
def test_only_a_well_formed_first_line_is_a_marker(body: str | None) -> None:
    assert ib.parse_marker(body) is None


def test_marker_without_repo_is_parsed_but_not_managed() -> None:
    marker = ib.parse_marker("<!-- supply-chain-aggregator:v1 kind=summary -->\nbody")
    assert marker is not None and marker.repo is None
    assert not ib.is_managed(marker, REPO)


def test_crlf_first_line_is_accepted() -> None:
    body = ib.render_marker("finding", REPO, "CVE-1") + "\r\nrest"
    assert ib.parse_marker(body) is not None


@pytest.mark.parametrize("vuln", ["CVE 1", "", "CVE-1\nx"])
def test_render_marker_rejects_whitespace(vuln: str) -> None:
    with pytest.raises(ValueError):
        ib.render_marker("finding", REPO, vuln)


def test_render_marker_rejects_unknown_kind_and_comma_alias() -> None:
    with pytest.raises(ValueError):
        ib.render_marker("other", REPO)
    with pytest.raises(ValueError):
        ib.render_marker("finding", REPO, "CVE-1", ("A,B",))


def test_parse_state_returns_none_for_missing_or_broken_blocks() -> None:
    marker = ib.render_marker("finding", REPO, "CVE-1")
    assert ib.parse_state(None) is None
    assert ib.parse_state(marker) is None
    assert ib.parse_state(f"{marker}\n```json {ib.STATE_FENCE_TAG}\n{{broken\n```\n") is None
    assert ib.parse_state(f"{marker}\n```json {ib.STATE_FENCE_TAG}\n[1]\n```\n") is None
    assert ib.parse_state(f"{marker}\n```json\n{{}}\n```\n") is None


def test_summary_and_failure_round_trip_and_are_cut() -> None:
    entries = [ib.SummaryEntry(f"CVE-2026-{i:05d}", "HIGH", i % 2 == 0, False) for i in range(300)]
    body = ib.render_summary(REPO, entries, "run-9")
    marker = ib.parse_marker(body)
    state = ib.parse_state(body)
    assert marker is not None and marker.kind == "summary" and ib.is_managed(marker, REPO)
    assert state is not None and state["total"] == 300 and state["entries_omitted"] == 0
    small = ib.render_summary(REPO, entries, "run-9", max_chars=3_000)
    st_small = ib.parse_state(small)
    assert len(small) <= 3_000 and st_small is not None
    assert st_small["entries_omitted"] > 0 and f"{st_small['entries_omitted']} 件" in small
    failure = ib.render_failure(HUB, "run-9", NOW, ["a|b", "c\nd"])
    fmarker = ib.parse_marker(failure)
    assert fmarker is not None and fmarker.kind == "failure" and ib.is_managed(fmarker, HUB)
    assert not ib.is_managed(fmarker, REPO)
    fstate = ib.parse_state(failure)
    assert fstate is not None and fstate["messages"] == ["a|b", "c\nd"]
    assert json.dumps(fstate["messages_omitted"]) == "0"
