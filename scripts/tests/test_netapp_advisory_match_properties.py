"""Property tests for the NetApp advisory matcher (task 13.2).

The design lists no numbered property for the matcher, so the properties below are named
here and carry no number.

**Validates: Requirements 5.5, 5.6, 5.7, 5.9**
"""

from __future__ import annotations

import datetime as dt

import netapp_advisory_match as nam
from hypothesis import event, find, given, settings
from hypothesis import strategies as st
from test_netapp_advisory_match import control_item, make_feed, make_item

TODAY = dt.date(2031, 3, 1)
LINE = (9, 17, 1)
MATCH_VALUES = (nam.YES, nam.NO, nam.PENDING)
SETTINGS = settings(max_examples=300, deadline=None)

ranks = st.tuples(st.integers(0, 12), st.integers(0, 2))


def fmt(line: tuple[int, int, int], patch: int, hotfix: int, d_level: int | None = None) -> str:
    """Render a version string such as 9.17.1P7HF1D1."""
    text = ".".join(str(n) for n in line)
    text += f"P{patch}" if patch else ""
    text += f"HF{hotfix}" if hotfix and patch else ""
    return text + (f"D{d_level}" if d_level else "")


@st.composite
def advisories(draw: st.DrawFn) -> nam.Advisory:
    """An advisory with random product lists, fixes on two release lines, and revisions."""
    placement = draw(
        st.sampled_from(["affected"] * 4 + ["not_affected"] * 3 + ["investigating", "both", "fixes_only", "other"])
    )
    names = ("ONTAP 9",)
    fixes = tuple(
        dict.fromkeys(
            fmt(draw(st.sampled_from([LINE, (9, 16, 1)])), p, h)
            for p, h in draw(st.lists(ranks, max_size=3, unique=True))
        )
    )
    day = dt.date(2030, 1, 1)
    revisions = [nam.Revision("1.0", day, "Initial Public Release")]
    for i, version in enumerate(fixes, start=2):
        gap = draw(st.integers(0, 40))
        revisions.append(nam.Revision(f"{i}.0", day + dt.timedelta(days=gap), f"ONTAP {version} added"))
    return nam.Advisory(
        advisory_id=f"NTAP-2030{draw(st.integers(1, 12)):02d}01-{draw(st.integers(1, 9999)):04d}",
        revision=revisions[-1].number,
        updated=max(r.date for r in revisions),
        title="synthetic",
        status=draw(st.sampled_from(["Final", "Interim", None])),
        affected=names if placement in ("affected", "both") else ("Other",),
        investigating=names if placement == "investigating" else (),
        not_affected=names if placement in ("not_affected", "both") else (),
        fixes=fixes if placement != "other" else (),
        revisions=tuple(revisions),
    )


@st.composite
def rows(draw: st.DrawFn) -> nam.LedgerRow:
    """An ONTAP row; the GA date is unknown, recent, or around the 3-year edge."""
    patch, hotfix = draw(ranks)
    d_level = draw(st.sampled_from([None, None, None, None, 1, 2]))
    kind = draw(st.sampled_from(["recent"] * 6 + ["edge"] * 2 + ["unknown"]))
    ga_days = {"recent": draw(st.integers(0, 800)), "edge": draw(st.integers(1000, 1200)), "unknown": None}[kind]
    ga = None if ga_days is None else TODAY - dt.timedelta(days=ga_days)
    return nam.LedgerRow("ONTAP " + fmt(LINE, patch, hotfix, d_level), nam.PENDING, None, ga)


def _past_3y(ga: dt.date | None) -> bool:
    return ga is not None and nam._add_years(ga, 3) < TODAY


# Feature: cyber-resilience-phase4-supply-chain, Property (unnumbered, task 13.2): a proposal obeys the stated rules
@SETTINGS
@given(row=rows(), adv=advisories())
def test_a_judgment_obeys_the_pending_rules_and_the_7_day_clock(row: nam.LedgerRow, adv: nam.Advisory) -> None:
    """**Validates: Requirements 5.5, 5.6, 5.7**

    A D-suffixed version and a version more than 3 years past GA are always pending; a
    not-affected proposal needs a recorded GA date; the deadline is the deciding revision
    plus 7 days, and the deciding date is one of the advisory's own dates.
    """
    j = nam.judge_advisory(row, adv, TODAY)
    ver = nam.parse_ontap_version(row.verified_version.removeprefix("ONTAP "))
    assert ver is not None
    if j is None:
        event("advisory names nothing")
        assert adv.affected == ("Other",) and not adv.fixes and not adv.investigating and not adv.not_affected
        return
    event(f"verdict={j.verdict}")
    assert j.verdict in MATCH_VALUES
    if ver.d_level is not None:
        assert j.verdict == nam.PENDING and "d-suffix-version" in j.reasons
    if _past_3y(row.ga_date):
        assert j.verdict == nam.PENDING and "more-than-3-years-past-ga" in j.reasons
    if j.verdict == nam.NO:
        assert row.ga_date is not None and not _past_3y(row.ga_date) and ver.d_level is None
    if j.verdict != j.reference_verdict:
        assert j.verdict == nam.PENDING
    assert j.confirm_by == j.decisive_date + dt.timedelta(days=7)
    assert j.decisive_date in {r.date for r in adv.revisions} | {adv.updated}


# Feature: cyber-resilience-phase4-supply-chain, Property (unnumbered, task 13.2): a higher patch level never turns not-affected into affected
@SETTINGS
@given(adv=advisories(), low=ranks, high=ranks)
def test_a_higher_patch_level_never_moves_from_not_affected_to_affected(
    adv: nam.Advisory, low: tuple[int, int], high: tuple[int, int]
) -> None:
    """**Validates: Requirements 5.5, 5.6**"""
    low, high = sorted([low, high])
    ga = TODAY - dt.timedelta(days=100)
    j_low = nam.judge_advisory(nam.LedgerRow("ONTAP " + fmt(LINE, *low), nam.PENDING, None, ga), adv, TODAY)
    j_high = nam.judge_advisory(nam.LedgerRow("ONTAP " + fmt(LINE, *high), nam.PENDING, None, ga), adv, TODAY)
    if j_low is None or j_high is None:
        assert j_low is None and j_high is None
        return
    event(f"low={j_low.verdict}, high={j_high.verdict}")
    if j_low.verdict == nam.NO:
        assert j_high.verdict == nam.NO
    if j_high.verdict == nam.YES:
        assert j_low.verdict == nam.YES


# Feature: cyber-resilience-phase4-supply-chain, Property (unnumbered, task 13.2): a row's verdict follows the precedence over its judgments
@SETTINGS
@given(row=rows(), advs=st.lists(advisories(), max_size=5), offset=st.integers(0, 60))
def test_row_verdict_follows_precedence_and_overdue_follows_the_earliest_deadline(
    row: nam.LedgerRow, advs: list[nam.Advisory], offset: int
) -> None:
    """**Validates: Requirements 5.5, 5.6, 5.7**"""
    today = TODAY + dt.timedelta(days=offset)
    p = nam.propose_row(row, tuple(advs), today)
    judgments = [j for a in advs if (j := nam.judge_advisory(row, a, today)) is not None]
    assert len(p.judgments) == len(judgments)
    if not judgments:
        event("no judgments")
        assert p.verdict is None and p.confirm_by is None and not p.overdue
        return
    verdicts = {j.verdict for j in judgments}
    expected = nam.YES if nam.YES in verdicts else nam.PENDING if nam.PENDING in verdicts else nam.NO
    event(f"row verdict={expected}")
    assert p.verdict == expected
    assert p.confirm_by == min(j.confirm_by for j in judgments if j.verdict == expected)
    assert p.overdue == (today > p.confirm_by)


# Feature: cyber-resilience-phase4-supply-chain, Property (unnumbered, task 13.2): parsing keeps what the feed says
@SETTINGS
@given(advs=st.lists(advisories(), min_size=1, max_size=4, unique_by=lambda a: a.advisory_id))
def test_parsing_a_rendered_feed_returns_the_same_lists_and_fixes(advs: list[nam.Advisory]) -> None:
    """**Validates: Requirement 5.9**"""
    items = [
        make_item(
            a.advisory_id,
            rev=a.revision,
            pub=a.updated.strftime("%a, %d %b %Y 00:00:00 +0000"),
            affected=list(a.affected),
            not_affected=list(a.not_affected) or None,
            investigating=list(a.investigating) or None,
            fixes=list(a.fixes) or None,
            revisions=[(r.number, r.date.strftime("%Y%m%d"), r.comment) for r in a.revisions],
            status=a.status or "Final",
        )
        for a in advs
    ]
    parsed = nam.parse_feed(make_feed(items)).advisories
    assert len(parsed) == len(advs)
    for got, want in zip(parsed, advs, strict=True):
        event(f"fixes={len(want.fixes)}")
        assert (got.advisory_id, got.revision, got.updated) == (want.advisory_id, want.revision, want.updated)
        assert (got.affected, got.not_affected, got.investigating) == (
            want.affected,
            want.not_affected,
            want.investigating,
        )
        assert got.fixes == want.fixes and got.revisions == want.revisions


# Feature: cyber-resilience-phase4-supply-chain, Property (unnumbered, task 13.2): a broken feed is an error, never a match
@SETTINGS
@given(cut=st.floats(0.0, 0.999), extra=st.integers(0, 3))
def test_a_truncated_feed_is_an_error_with_no_rows(cut: float, extra: int) -> None:
    """**Validates: Requirement 5.9**"""
    text = make_feed(
        [control_item()] + [make_item(f"NTAP-20300101-{i + 2:04d}", not_affected=["ONTAP 9"]) for i in range(extra)]
    )
    broken = text[: int(len(text) * cut)]
    result = nam.run_match(
        broken,
        [nam.LedgerRow("ONTAP 9.17.1P1", nam.PENDING, None, None)],
        TODAY,
        control=nam.ControlSpec("NTAP-20300101-0001", ("9.16.1P9", "9.17.1P2")),
    )
    event(f"status={result.status}")
    assert result.status == "error" and result.rows == () and result.error is not None


# Feature: cyber-resilience-phase4-supply-chain, Property (unnumbered, task 13.2): a feed whose control advisory is not read is an error
@SETTINGS
@given(mutation=st.sampled_from(["drop", "wrong-product", "fixes-missing", "no-history"]), extra=st.integers(0, 3))
def test_a_feed_that_does_not_yield_the_control_advisory_is_an_error(mutation: str, extra: int) -> None:
    """**Validates: Requirement 5.9**"""
    control = {
        "drop": None,
        "wrong-product": make_item(affected=["Other"], fixes=["9.16.1P9", "9.17.1P2"]),
        "fixes-missing": make_item(affected=["ONTAP 9"], fixes=["9.16.1P9"]),
        "no-history": control_item().replace("Revision History", "History"),
    }[mutation]
    others = [make_item(f"NTAP-20300101-{i + 2:04d}", not_affected=["ONTAP 9"]) for i in range(extra + 1)]
    result = nam.run_match(
        make_feed(([control] if control else []) + others),
        [nam.LedgerRow("ONTAP 9.17.1P1", nam.PENDING, None, None)],
        TODAY,
        control=nam.ControlSpec("NTAP-20300101-0001", ("9.16.1P9", "9.17.1P2")),
    )
    event(f"mutation={mutation}")
    assert result.status == "error" and result.rows == () and (result.error or "").startswith("control:")


def test_the_generators_reach_every_verdict_and_both_sides_of_the_clock() -> None:
    row_ok = nam.LedgerRow("ONTAP " + fmt(LINE, 1, 0), nam.PENDING, None, TODAY - dt.timedelta(days=100))
    for verdict in MATCH_VALUES:
        found = find(
            advisories(),
            lambda a, v=verdict: (j := nam.judge_advisory(row_ok, a, TODAY)) is not None and j.verdict == v,
        )
        assert found is not None
    d_row = nam.LedgerRow("ONTAP " + fmt(LINE, 1, 0, 1), nam.PENDING, None, TODAY)
    assert find(
        advisories(),
        lambda a: (j := nam.judge_advisory(d_row, a, TODAY)) is not None and j.reference_verdict != nam.PENDING,
    )
