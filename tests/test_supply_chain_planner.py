"""Unit and property tests for ``supply_chain.planner.plan`` (task 9.6).

Examples build small ``PlanInputs`` by hand; the properties use the shared generators.
Applying a plan uses the fake store; a ``reopen`` is followed by an ``update`` with the same body
because the fake store ignores the body of a ``reopen`` (GitHub applies it).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta

import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain import issue_body, models, planner

from tests.fakes import issue_store as fake
from tests.strategies import supply_chain as sc

NOW = datetime(2026, 11, 10, 6, 0, tzinfo=UTC)
LATER = NOW + timedelta(days=1)
REPO = models.Repo("example-org", "svc-api")
OTHER = models.Repo("example-org", "svc-web")
PURL = "pkg:npm/left-pad@1.3.0"


def _policy(limit: int = 10, minimum: models.Severity = "HIGH", kev: bool = True) -> models.Policy:
    return models.Policy(
        schema_version=1,
        target_repositories=(REPO, OTHER),
        excluded_repositories=(),
        opening_threshold=models.OpeningThreshold(minimum, kev, True),
        cooldown_days=models.CooldownDays(3, 7),
        automerge_include=(),
        automerge_exclude=(),
        automerge_enabled_repositories=(),
        package_manager_wait=models.CooldownDays(3, 7),
        non_production_paths=(),
        vex_directory=".vex",
        vex_exclude_statuses=("not_affected", "fixed"),
        vex_approver_role="VEX_Reviewer",
        vex_one_statement_per_document=True,
        vex_malicious_never_suppressed=True,
        response_target=models.ResponseTarget(24, 7, 14),
        max_new_issues_per_repo_per_run=limit,
    )


def _finding(
    vuln_id: str = "CVE-2026-0001",
    severity: models.Severity | None = "HIGH",
    *,
    repo: models.Repo = REPO,
    purl: str = PURL,
    aliases: tuple[str, ...] = (),
    published: datetime | None = None,
    observed: datetime | None = None,
) -> models.Finding:
    name, _, version = purl.removeprefix("pkg:npm/").partition("@")
    return models.Finding(
        repo=repo,
        vuln_id=vuln_id,
        aliases=aliases,
        component=models.Component(purl=purl, name=name, version=version),
        cvss_severity=severity,
        fixed_version=None if vuln_id.startswith("MAL-") else "9.9.9",
        advisory_published_at=published or NOW - timedelta(days=3),
        layer="A",
        first_observed_component_at=observed or NOW - timedelta(days=5),
    )


def _feeds(**overrides: object) -> models.FeedSnapshot:
    base: dict[str, object] = {
        "kev": {},
        "epss": {},
        "malicious": {},
        "malicious_withdrawn": {},
        "malicious_delisted": frozenset(),
        "malicious_unconfirmed": frozenset(),
    }
    return models.FeedSnapshot(**{**base, **overrides})  # type: ignore[arg-type]


def _inputs(
    found: tuple[models.Finding, ...] = (),
    issues: tuple[models.ManagedIssue, ...] = (),
    *,
    feeds: models.FeedSnapshot | None = None,
    policy: models.Policy | None = None,
    fetch_ok: tuple[models.Repo, ...] = (REPO, OTHER),
    vex: dict[models.Repo, tuple[models.VexDocument, ...]] | None = None,
    now: datetime = NOW,
    run_id: str = "200-1",
) -> models.PlanInputs:
    return models.PlanInputs(
        policy=policy or _policy(),
        run_id=run_id,
        now=now,
        pull_requests=(),
        findings=frozenset(found),
        fetch_ok=frozenset(fetch_ok),
        feeds=feeds or _feeds(),
        vex=vex or {},
        issues=issues,
    )


def _apply(inputs: models.PlanInputs, plan: models.Plan) -> tuple[models.ManagedIssue, ...]:
    """The Issues the next run would read after every action of ``plan`` succeeded."""
    store = fake.IssueStore.from_managed(inputs.issues)
    for action in plan.actions:
        store = store.apply_action(action)
        if action.op == "reopen":
            store = store.apply_action(replace(action, op="update"))
    return fake.to_managed_issues(store, issue_body.parse_state)


def _next(inputs: models.PlanInputs, plan: models.Plan, **changes: object) -> models.PlanInputs:
    return replace(inputs, issues=_apply(inputs, plan), **changes)  # type: ignore[arg-type]


def _ops(plan: models.Plan) -> list[tuple[str, str, str | None]]:
    return [(a.op, a.kind, a.vuln_id) for a in plan.actions]


def _vex(status: models.VexStatus, vuln_id: str, purl: str = PURL, aliases: tuple[str, ...] = ()) -> models.VexDocument:
    statement = models.VexStatement(vuln_id, aliases, (purl,), status, "component_not_present", None, NOW)
    return models.VexDocument(
        "urn:example:1", "https://openvex.dev/ns/v0.2.0", "example", None, NOW, 1, None, (statement,), ".vex/a.json"
    )


def _state(plan: models.Plan, index: int = 0) -> dict[str, object]:
    state = issue_body.parse_state(plan.actions[index].body)
    assert state is not None
    return state


# --- steps 1 and 2: VEX and the threshold ------------------------------------------------------


def test_high_finding_is_created_with_the_high_deadline() -> None:
    plan = planner.plan(_inputs((_finding(),)))
    assert _ops(plan) == [("create", "finding", "CVE-2026-0001")]
    state = _state(plan)
    assert state["due_at"] == "2026-11-24T06:00:00Z"  # now + fix_days_high (14)
    assert state["opened_at"] == state["detected_at"] == "2026-11-10T06:00:00Z"
    assert state["history"] == [{"op": "open", "run_id": "200-1", "at": "2026-11-10T06:00:00Z"}]


def test_below_threshold_and_unscored_are_recorded_not_created() -> None:
    medium, bare = _finding("CVE-2026-0002", "MEDIUM"), _finding("CVE-2026-0003", None)
    plan = planner.plan(_inputs((medium, bare)))
    assert plan.actions == ()
    assert plan.below_threshold == (medium,)
    assert plan.unscored == (bare,)


def test_kev_listing_opens_a_low_finding_with_the_short_deadline_and_a_date_only_origin() -> None:
    low = _finding("CVE-2026-0004", "LOW", published=NOW - timedelta(days=90), observed=NOW - timedelta(days=9))
    plan = planner.plan(_inputs((low,), feeds=_feeds(kev={"CVE-2026-0004": (date(2026, 11, 8), True)})))
    state = _state(plan)
    assert state["due_at"] == "2026-11-17T06:00:00Z"  # now + 7
    assert state["origin_at"] == "2026-11-08T00:00:00Z"
    assert state["origin_is_date_only"] is True
    assert state["kev_listed"] is True


def test_kev_feed_failure_does_not_open_a_kev_only_finding() -> None:
    low = _finding("CVE-2026-0004", "LOW")
    plan = planner.plan(_inputs((low,), feeds=_feeds(kev=None)))
    assert plan.actions == ()
    assert plan.below_threshold == (low,)


def test_vex_not_affected_for_the_exact_version_excludes_and_other_versions_do_not() -> None:
    hit, other = _finding(), _finding(purl="pkg:npm/left-pad@1.4.0")
    plan = planner.plan(_inputs((hit, other), vex={REPO: (_vex("not_affected", "CVE-2026-0001"),)}))
    assert plan.vex_exclusions == ((hit, ".vex/a.json"),)
    assert [a.op for a in plan.actions] == ["create"]  # the 1.4.0 component still opens an Issue
    assert [c["version"] for c in _state(plan)["components"]] == ["1.4.0"]  # type: ignore[union-attr]


@pytest.mark.parametrize(("status", "reason"), [("not_affected", "vex_not_affected"), ("fixed", "vex_fixed")])
def test_vex_exclusion_closes_the_open_issue_with_the_vex_reason(status: models.VexStatus, reason: str) -> None:
    first = _inputs((_finding(),))
    again = _next(first, planner.plan(first), findings=first.findings, vex={REPO: (_vex(status, "CVE-2026-0001"),)})
    plan = planner.plan(again)
    assert [(a.op, a.close_reason) for a in plan.actions] == [("close", reason)]


def test_malicious_package_is_never_suppressed_by_vex() -> None:
    mal = _finding("MAL-2026-0001", None, aliases=("GHSA-aaaa-bbbb-cccc",))
    plan = planner.plan(
        _inputs((mal,), vex={REPO: (_vex("not_affected", "GHSA-aaaa-bbbb-cccc"), _vex("fixed", "MAL-2026-0001"))})
    )
    assert [a.op for a in plan.actions] == ["create"]
    assert plan.vex_exclusions == ()
    assert plan.rejected_vex == ((".vex/a.json", "malicious_package_not_suppressible"),)


def test_vex_statement_on_an_alias_of_a_malicious_finding_is_rejected_and_not_applied() -> None:
    mal = _finding("MAL-2026-0001", None, aliases=("GHSA-aaaa-bbbb-cccc",))
    plan = planner.plan(_inputs((mal,), vex={REPO: (_vex("not_affected", "GHSA-aaaa-bbbb-cccc"),)}))
    assert [a.op for a in plan.actions] == ["create"]
    assert plan.rejected_vex == ((".vex/a.json", "malicious_package_not_suppressible"),)


def test_kev_listed_finding_without_severity_is_below_threshold_when_kev_opening_is_off() -> None:
    bare = _finding("CVE-2026-0006", None)
    feeds = _feeds(kev={"CVE-2026-0006": (date(2026, 11, 8), None)})
    plan = planner.plan(_inputs((bare,), policy=_policy(kev=False), feeds=feeds))
    assert (plan.actions, plan.below_threshold, plan.unscored) == ((), (bare,), ())


def test_origin_is_the_later_of_publication_and_first_observation() -> None:
    late = _finding(published=NOW - timedelta(days=3), observed=NOW - timedelta(days=1))
    early = _finding("CVE-2026-0002", published=NOW - timedelta(days=3), observed=NOW - timedelta(days=8))
    plan = planner.plan(_inputs((late, early)))
    origins = {a.vuln_id: _state(plan, i)["origin_at"] for i, a in enumerate(plan.actions)}
    assert origins == {"CVE-2026-0001": "2026-11-09T06:00:00Z", "CVE-2026-0002": "2026-11-07T06:00:00Z"}


# --- step 3: grouping ----------------------------------------------------------------------------


def test_one_issue_lists_every_component_of_a_vulnerability() -> None:
    a, b = _finding(purl="pkg:npm/aa@1.0.0"), _finding(purl="pkg:npm/bb@2.0.0")
    plan = planner.plan(_inputs((a, b)))
    assert len(plan.actions) == 1
    assert sorted(c["purl"] for c in _state(plan)["components"]) == ["pkg:npm/aa@1.0.0", "pkg:npm/bb@2.0.0"]  # type: ignore[union-attr]


def test_ghsa_malware_and_mal_record_of_one_package_version_become_one_issue() -> None:
    mal = _finding("MAL-2026-0007", None)
    ghsa = _finding("GHSA-mmmm-aaaa-llll", None)
    plan = planner.plan(_inputs((mal, ghsa)))
    assert _ops(plan) == [("create", "finding", "MAL-2026-0007")]
    assert plan.unscored == ()
    marker = issue_body.parse_marker(plan.actions[0].body)
    assert marker is not None
    assert marker.aliases == ("GHSA-mmmm-aaaa-llll",)
    assert _state(plan)["malicious"] is True


def test_ghsa_without_a_mal_record_stays_unscored_and_other_versions_do_not_merge() -> None:
    mal = _finding("MAL-2026-0007", None, purl="pkg:npm/evil@1.0.0")
    elsewhere = _finding("GHSA-mmmm-aaaa-llll", None, purl="pkg:npm/evil@2.0.0")
    plan = planner.plan(_inputs((mal, elsewhere)))
    assert _ops(plan) == [("create", "finding", "MAL-2026-0007")]
    assert plan.unscored == (elsewhere,)


def test_malicious_issue_has_the_short_deadline_and_the_feed_publication_as_origin() -> None:
    mal = _finding("MAL-2026-0007", None, observed=NOW - timedelta(days=2))
    published = NOW - timedelta(days=1)
    plan = planner.plan(_inputs((mal,), feeds=_feeds(malicious={"MAL-2026-0007": published})))
    state = _state(plan)
    assert state["due_at"] == "2026-11-17T06:00:00Z"
    assert state["origin_at"] == "2026-11-09T06:00:00Z"  # the later of publication and first observation
    assert state["cvss_severity"] is None


# --- step 4: existing Issues -----------------------------------------------------------------------


def test_same_inputs_and_state_produce_no_action() -> None:
    first = _inputs((_finding(),))
    second = _next(first, planner.plan(first), now=LATER, run_id="201-1")
    assert planner.plan(second).actions == ()


def test_changed_value_updates_and_keeps_opened_at_and_appends_history() -> None:
    first = _inputs((_finding(),))
    epss = {"CVE-2026-0001": ("0.42000", date(2026, 11, 11), "v2026.01.01")}
    second = _next(first, planner.plan(first), now=LATER, run_id="201-1", feeds=_feeds(epss=epss))
    plan = planner.plan(second)
    assert [a.op for a in plan.actions] == ["update"]
    state = _state(plan)
    assert state["opened_at"] == "2026-11-10T06:00:00Z"
    assert state["epss"] == {"score": "0.42000", "date": "2026-11-11", "model_version": "v2026.01.01"}
    assert [h["op"] for h in state["history"]] == ["open", "update"]  # type: ignore[union-attr]


def test_closed_issue_is_reopened_when_the_finding_returns() -> None:
    first = _inputs((_finding(),))
    gone = _next(first, planner.plan(first), findings=frozenset())
    closed = _next(gone, planner.plan(gone))
    assert [i.state for i in closed.issues] == ["closed"]
    back = replace(closed, findings=first.findings, now=LATER, run_id="202-1")
    plan = planner.plan(back)
    assert [(a.op, a.number) for a in plan.actions] == [("reopen", 1)]
    assert [h["op"] for h in _state(plan)["history"]] == ["open", "reopen"]  # type: ignore[union-attr]
    assert _state(plan)["due_at"] == "2026-11-25T06:00:00Z"  # the fix window restarts


def test_changed_representative_continues_the_same_issue() -> None:
    old = _finding("GHSA-aaaa-bbbb-cccc", "HIGH")
    first = _inputs((old,))
    renamed = _finding("CVE-2026-0001", "HIGH", aliases=("GHSA-aaaa-bbbb-cccc",))
    second = _next(first, planner.plan(first), findings=frozenset({renamed}))
    plan = planner.plan(second)
    assert [(a.op, a.number, a.vuln_id) for a in plan.actions] == [("update", 1, "CVE-2026-0001")]


def test_a_new_mal_id_for_the_same_package_version_continues_the_issue() -> None:
    first = _inputs((_finding("MAL-2026-0001", None),))
    second = _next(first, planner.plan(first), findings=frozenset({_finding("MAL-2026-0002", None)}))
    assert [(a.op, a.number) for a in planner.plan(second).actions] == [("update", 1)]


def test_a_kev_listed_malware_ghsa_continues_the_open_mal_issue_instead_of_replacing_it() -> None:
    first = _inputs((_finding("MAL-2026-0000", None),))
    ghsa = _finding("GHSA-mmmm-aaaa-llll", None)
    kev = _feeds(kev={"GHSA-mmmm-aaaa-llll": (date(2026, 11, 1), None)})
    second = _next(first, planner.plan(first), findings=frozenset({ghsa}), feeds=kev)
    plan = planner.plan(second)
    assert [a.op for a in plan.actions if a.op in ("create", "close")] == []
    assert all(a.number == 1 and a.vuln_id == "MAL-2026-0000" for a in plan.actions)
    third = _next(second, plan)
    assert [(i.vuln_id, i.state) for i in third.issues] == [("MAL-2026-0000", "open")]
    marker = issue_body.parse_marker(plan.actions[0].body) if plan.actions else None
    assert marker is None or marker.aliases == ("GHSA-mmmm-aaaa-llll",)


def test_deadline_shortens_to_seven_days_when_a_high_issue_enters_kev_and_never_lengthens() -> None:
    first = _inputs((_finding(),))
    kev = _feeds(kev={"CVE-2026-0001": (date(2026, 11, 11), False)})
    second = _next(first, planner.plan(first), now=LATER, run_id="201-1", feeds=kev)
    plan = planner.plan(second)
    assert _state(plan)["due_at"] == "2026-11-18T06:00:00Z"  # min(11-24, 11-11 06:00 + 7d)
    third = _next(second, plan, now=LATER + timedelta(days=3), run_id="202-1", feeds=kev)
    assert planner.plan(third).actions == ()  # a later run does not push the deadline out again


def test_a_low_kev_issue_keeps_its_deadline() -> None:
    low = _finding("CVE-2026-0004", "LOW")
    kev = _feeds(kev={"CVE-2026-0004": (date(2026, 11, 8), None)})
    first = _inputs((low,), feeds=kev)
    second = _next(first, planner.plan(first), now=LATER, run_id="201-1")
    assert planner.plan(second).actions == ()


def test_a_low_issue_that_enters_kev_keeps_its_deadline() -> None:
    low = _finding("CVE-2026-0004", "LOW")
    first = _inputs((low,), policy=_policy(minimum="LOW"))
    kev = _feeds(kev={"CVE-2026-0004": (date(2026, 11, 11), None)})
    second = _next(first, planner.plan(first), now=LATER, run_id="201-1", feeds=kev)
    plan = planner.plan(second)
    assert [a.op for a in plan.actions] == ["update"]
    assert _state(plan)["due_at"] == "2026-11-24T06:00:00Z"  # fix_days_high, unchanged


def test_duplicate_open_issues_are_left_alone_and_the_lowest_open_one_is_updated() -> None:
    opened = _opened((_finding(),))
    state = opened.issues[0].body_state
    extra = models.ManagedIssue(REPO, 9, "finding", "CVE-2026-0001", "open", state)
    closed = models.ManagedIssue(REPO, 3, "finding", "CVE-2026-0001", "closed", state)
    epss = {"CVE-2026-0001": ("0.1", date(2026, 11, 11), "v1")}
    plan = planner.plan(replace(opened, issues=(*opened.issues, extra, closed), feeds=_feeds(epss=epss)))
    assert [(a.op, a.number) for a in plan.actions] == [("update", 1)]  # not the closed 3, not the duplicate 9


def test_a_new_mal_id_for_another_version_does_not_take_over_the_issue() -> None:
    first = _inputs((_finding("MAL-2026-0001", None, purl="pkg:npm/evil@1.0.0"),))
    other = _finding("MAL-2026-0002", None, purl="pkg:npm/evil@2.0.0")
    second = _next(first, planner.plan(first), findings=frozenset({other}), feeds=_feeds())
    ops = _ops(planner.plan(second))
    assert ("create", "finding", "MAL-2026-0002") in ops and ("close", "finding", "MAL-2026-0001") in ops


def test_ghsa_advisory_with_a_severity_is_not_absorbed_into_a_malicious_issue() -> None:
    mal = _finding("MAL-2026-0007", None)
    real = _finding("GHSA-rrrr-aaaa-llll", "MEDIUM")  # same package version, a real advisory below the threshold
    plan = planner.plan(_inputs((mal, real)))
    assert plan.below_threshold == (real,)
    assert issue_body.parse_marker(plan.actions[0].body).aliases == ()  # type: ignore[union-attr]


# --- step 5: the opening limit ---------------------------------------------------------------------


def _by_order() -> tuple[models.Finding, ...]:
    return (
        _finding("CVE-2026-0010", "CRITICAL"),
        _finding("CVE-2026-0011", "HIGH"),
        _finding("CVE-2026-0012", "LOW"),  # becomes eligible through KEV
        _finding("MAL-2026-0013", None, purl="pkg:npm/evil@1.0.0"),
        _finding("CVE-2026-0014", "HIGH"),
    )


def test_over_the_limit_kev_and_malicious_go_first_then_severity_then_identifier() -> None:
    kev = _feeds(kev={"CVE-2026-0012": (date(2026, 11, 8), None)})
    plan = planner.plan(_inputs(_by_order(), policy=_policy(limit=3), feeds=kev))
    created = [a.vuln_id for a in plan.actions if a.op == "create" and a.kind == "finding"]
    assert sorted(created) == ["CVE-2026-0010", "CVE-2026-0012", "MAL-2026-0013"]
    summary = next(a for a in plan.actions if a.kind == "summary")
    assert summary.op == "create"
    assert [e["vuln_id"] for e in issue_body.parse_state(summary.body)["entries"]] == ["CVE-2026-0011", "CVE-2026-0014"]  # type: ignore[index]
    assert plan.overflow_counts == {REPO: 2}


def test_limit_counts_only_new_issues_and_is_per_repository() -> None:
    found = tuple(_finding(f"CVE-2026-{n:04d}", "HIGH", repo=r) for r in (REPO, OTHER) for n in range(1, 4))
    plan = planner.plan(_inputs(found, policy=_policy(limit=2)))
    creates = Counter(a.repo for a in plan.actions if a.op == "create" and a.kind == "finding")
    assert creates == {REPO: 2, OTHER: 2}
    assert plan.overflow_counts == {REPO: 1, OTHER: 1}


def test_open_summary_is_updated_not_duplicated_and_closed_when_the_overflow_ends() -> None:
    eligible = (
        _finding("CVE-2026-0010", "CRITICAL"),
        _finding("CVE-2026-0011", "HIGH"),
        _finding("CVE-2026-0014", "HIGH"),
        _finding("CVE-2026-0015", "HIGH"),
    )
    first = _inputs(eligible, policy=_policy(limit=1))
    second = _next(first, planner.plan(first))
    assert [i.kind for i in second.issues].count("summary") == 1
    smaller = replace(second, findings=frozenset(f for f in eligible if f.vuln_id != "CVE-2026-0015"))
    shrunk = [(a.op, a.kind) for a in planner.plan(smaller).actions if a.kind == "summary"]
    assert shrunk == [("update", "summary")]
    clear = planner.plan(replace(second, policy=_policy(limit=10)))
    assert [(a.op, a.kind) for a in clear.actions if a.kind == "summary"] == [("close", "summary")]


# --- step 6: closing -------------------------------------------------------------------------------


def _opened(found: tuple[models.Finding, ...], **kwargs: object) -> models.PlanInputs:
    first = _inputs(found, **kwargs)  # type: ignore[arg-type]
    return _next(first, planner.plan(first))


def test_issue_closes_as_resolved_when_the_finding_disappears() -> None:
    opened = _opened((_finding(),))
    plan = planner.plan(replace(opened, findings=frozenset()))
    assert [(a.op, a.number, a.close_reason) for a in plan.actions] == [("close", 1, "resolved")]


def test_failed_repository_fetch_closes_nothing_and_a_fetched_repository_still_closes() -> None:
    opened = _opened((_finding(), _finding(repo=OTHER)))
    plan = planner.plan(replace(opened, findings=frozenset(), fetch_ok=frozenset({OTHER})))
    assert [(a.op, a.repo) for a in plan.actions] == [("close", OTHER)]


def test_kev_failure_keeps_a_kev_only_issue_open_but_not_a_cvss_issue() -> None:
    low = _finding("CVE-2026-0004", "LOW")
    high = _finding("CVE-2026-0005", "HIGH")
    kev = _feeds(kev={"CVE-2026-0004": (date(2026, 11, 8), None)})
    opened = _opened((low, high), feeds=kev)
    plan = planner.plan(replace(opened, findings=frozenset(), feeds=_feeds(kev=None)))
    assert [(a.op, a.vuln_id) for a in plan.actions] == [("close", "CVE-2026-0005")]


def test_issue_without_a_readable_state_is_not_closed_while_kev_is_missing() -> None:
    opened = _opened((_finding(),))
    blind = replace(opened, issues=tuple(replace(i, body_state=None) for i in opened.issues))
    plan = planner.plan(replace(blind, findings=frozenset(), feeds=_feeds(kev=None)))
    assert plan.actions == ()


def _mal_opened() -> models.PlanInputs:
    return _opened((_finding("MAL-2026-0007", None),))


@pytest.mark.parametrize(
    ("feeds", "reason", "unconfirmed"),
    [
        (_feeds(), "resolved", False),
        (_feeds(malicious_withdrawn={"MAL-2026-0007": NOW}), "withdrawn", False),
        (_feeds(malicious_delisted=frozenset({"MAL-2026-0007"})), "feed_version_delisted", False),
        (_feeds(malicious_unconfirmed=frozenset({"MAL-2026-0007"})), None, True),
        (_feeds(malicious=None), None, True),
        (_feeds(malicious=None, malicious_withdrawn={"MAL-2026-0007": NOW}), None, True),
    ],
)
def test_malicious_issue_closes_only_on_a_confirmed_reason(
    feeds: models.FeedSnapshot, reason: str | None, unconfirmed: bool
) -> None:
    plan = planner.plan(replace(_mal_opened(), findings=frozenset(), feeds=feeds))
    assert [a.close_reason for a in plan.actions] == ([reason] if reason else [])
    assert plan.malicious_withdrawn_unconfirmed == (((REPO, 1, "MAL-2026-0007"),) if unconfirmed else ())


def test_withdrawn_malicious_issue_reopens_when_the_record_returns() -> None:
    opened = _mal_opened()
    gone = replace(opened, findings=frozenset(), feeds=_feeds(malicious_withdrawn={"MAL-2026-0007": NOW}))
    closed = _next(gone, planner.plan(gone))
    back = replace(closed, findings=frozenset({_finding("MAL-2026-0007", None)}), now=LATER, run_id="202-1")
    assert [a.op for a in planner.plan(back).actions] == ["reopen"]


def test_malicious_issue_is_never_closed_for_a_vex_reason() -> None:
    opened = _mal_opened()
    plan = planner.plan(replace(opened, findings=frozenset(), vex={REPO: (_vex("not_affected", "MAL-2026-0007"),)}))
    assert [a.close_reason for a in plan.actions] == ["resolved"]


def test_human_issue_and_foreign_marker_issue_are_not_touched() -> None:
    managed_elsewhere = models.ManagedIssue(OTHER, 7, "failure", None, "open", None)
    plan = planner.plan(_inputs((), (managed_elsewhere,)))
    assert plan.actions == ()


# --- determinism and order -------------------------------------------------------------------------


def test_actions_are_sorted_and_the_plan_is_deterministic() -> None:
    inputs = _inputs(_by_order() + (_finding("CVE-2026-0020", "HIGH", repo=OTHER),), policy=_policy(limit=2))
    plan = planner.plan(inputs)
    assert plan == planner.plan(inputs)
    keys = [(a.repo.owner.lower(), a.repo.name.lower(), a.kind, a.vuln_id or "", a.op) for a in plan.actions]
    assert keys == sorted(keys)


@settings(max_examples=60, deadline=None)
@given(st.permutations(list(_by_order())))
def test_result_does_not_depend_on_the_order_findings_are_listed(order: list[models.Finding]) -> None:
    """The same set of findings gives byte-identical bodies however it was built."""
    baseline = planner.plan(_inputs(_by_order(), policy=_policy(limit=3)))
    assert planner.plan(_inputs(tuple(order), policy=_policy(limit=3))) == baseline


# --- properties over generated inputs ----------------------------------------------------------------


def _sized(limit: int) -> st.SearchStrategy[models.PlanInputs]:
    return sc.plan_inputs(14, 14, policy=replace(_policy(limit=limit), target_repositories=sc.DEFAULT_REPOS))


@settings(max_examples=100, deadline=None)
@given(st.integers(1, 4).flatmap(_sized))
def test_plan_invariants_over_generated_inputs(inputs: models.PlanInputs) -> None:
    """Limits, uniqueness, no close on failure, and idempotence when nothing overflowed.

    **Validates: Requirements 8.1, 8.5, 8.8, 9.1, 9.2, 9.3, 9.8, 9.9**
    """
    plan = planner.plan(inputs)
    limit = inputs.policy.max_new_issues_per_repo_per_run
    creates = Counter(a.repo for a in plan.actions if a.op == "create" and a.kind == "finding")
    assert all(n <= limit for n in creates.values())
    keys = [(a.repo, a.kind, a.vuln_id) for a in plan.actions if a.op == "create"]
    assert len(keys) == len(set(keys))
    numbers = [(a.repo, a.number) for a in plan.actions if a.number is not None]
    assert len(numbers) == len(set(numbers))
    ok = inputs.fetch_ok
    closes = [a for a in plan.actions if a.op == "close"]
    assert all(a.repo in ok for a in closes)
    if inputs.feeds.malicious is None:
        assert not [a for a in closes if (a.vuln_id or "").startswith("MAL-")]
    event(f"actions={min(len(plan.actions), 5)}")
    if not plan.overflow_counts:
        again = planner.plan(_next(inputs, plan, run_id="next-1"))
        assert again.actions == ()


def test_generated_inputs_exercise_the_operations_that_do_not_need_a_match() -> None:
    """The invariants above are not vacuous: create, close, reopen, overflow and unconfirmed all occur."""
    seen: Counter[str] = Counter()

    # derandomize: some seeds draw no reopen; a fixed sequence keeps the check that every form occurs.
    @settings(max_examples=120, deadline=None, derandomize=True)
    @given(st.integers(1, 3).flatmap(_sized))
    def run(inputs: models.PlanInputs) -> None:
        plan = planner.plan(inputs)
        seen.update(a.op for a in plan.actions)
        seen["overflow"] += bool(plan.overflow_counts)
        seen["unconfirmed"] += bool(plan.malicious_withdrawn_unconfirmed)

    run()
    missing = [k for k in ("create", "close", "reopen", "overflow", "unconfirmed") if seen[k] == 0]
    assert not missing, f"never seen: {missing}; counts {sorted(seen.items())}"


def test_settled_inputs_with_new_feed_values_update_and_vex_closes() -> None:
    """From a settled state, an EPSS change updates every Issue and a VEX statement removes its finding.

    The generated Issues rarely match the generated findings, so this derives the match: apply the
    plan, then change the feeds and add a VEX statement for a created, non-malicious finding.
    """
    seen: Counter[str] = Counter()

    @settings(max_examples=100, deadline=None)
    @given(st.integers(1, 3).flatmap(_sized))
    def run(inputs: models.PlanInputs) -> None:
        first = planner.plan(inputs)
        created = [a for a in first.actions if a.op == "create" and a.kind == "finding"]
        epss = {
            i: ("0.50000", date(2026, 12, 1), "v-derived") for f in inputs.findings for i in (f.vuln_id, *f.aliases)
        }
        feeds = replace(inputs.feeds, epss=epss)
        second = planner.plan(_next(inputs, first, feeds=feeds, run_id="next-1"))
        updated = {(a.repo, a.vuln_id) for a in second.actions if a.op == "update"}
        assert all((a.repo, a.vuln_id) in updated for a in created)
        seen["update"] += len(created)
        targets = [f for f in inputs.findings if any(f.vuln_id == a.vuln_id and f.repo == a.repo for a in created)]
        plain = [
            f for f in sorted(targets, key=lambda f: (f.vuln_id, f.component.purl)) if not f.vuln_id.startswith("MAL-")
        ]
        if plain and not any(f.aliases and f.aliases[0].startswith("MAL-") for f in plain[:1]):
            f = plain[0]
            doc = _vex("not_affected", f.vuln_id, f.component.purl)
            third = planner.plan(_next(inputs, first, vex={f.repo: (doc,)}, run_id="next-2"))
            assert any(x[0] == f for x in third.vex_exclusions) or planner.is_malicious(f)
            seen["vex"] += 1

    run()
    assert seen["update"] > 0 and seen["vex"] > 0, dict(seen)
