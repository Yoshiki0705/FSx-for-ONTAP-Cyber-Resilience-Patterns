"""Round 6 (F14): VEX names that miss a Finding are counted, and a statement that wins elsewhere is not "superseded"."""

from __future__ import annotations

from dataclasses import replace

from supply_chain import issue_body, models, planner
from supply_chain.vex import REASON_ALIAS_ONLY, REASON_SUPERSEDED, effective_exclusions

from tests.test_supply_chain_planner import NOW, PURL, REPO, _apply, _finding, _inputs, _policy, _state, _vex

GHSA = "GHSA-aaaa-bbbb-cccc"
CVE = "CVE-2026-0001"
PATH = ".vex/a.json"


def _plan(statement_name: str, aliases: tuple[str, ...] = (), finding_aliases: tuple[str, ...] = (GHSA,)):
    inputs = _inputs(
        (_finding(CVE, "HIGH", aliases=finding_aliases),),
        vex={REPO: (_vex("not_affected", statement_name, aliases=aliases),)},
    )
    return inputs, planner.plan(inputs)


def test_a_statement_named_by_the_ghsa_only_is_recorded_and_counted() -> None:
    _, plan = _plan(GHSA)
    assert [a.op for a in plan.actions] == ["create"]
    assert plan.rejected_vex == ((PATH, REASON_ALIAS_ONLY),)
    assert plan.vex_name_only_ghsa == (("example-org/svc-api", CVE, PATH),)
    assert _state(plan)["vex_names_alias_only"] == PATH


def test_a_statement_that_names_the_cve_or_lists_it_is_not_counted() -> None:
    for name, aliases in ((CVE, ()), (CVE, (GHSA,)), (GHSA, (CVE,))):
        _, plan = _plan(name, aliases)
        assert plan.vex_name_only_ghsa == (), (name, aliases)
        assert plan.rejected_vex == ()
        assert plan.actions == ()


def test_a_shared_ghsa_is_counted_for_each_cve_it_misses() -> None:
    inputs = _inputs(
        (_finding(CVE, "HIGH", aliases=(GHSA,)), _finding("CVE-2026-0002", "HIGH", aliases=(GHSA,))),
        vex={REPO: (_vex("not_affected", GHSA),)},
    )
    plan = planner.plan(inputs)
    assert {c for _, c, _ in plan.vex_name_only_ghsa} == {CVE, "CVE-2026-0002"}
    assert len([a for a in plan.actions if a.op == "create"]) == 2


def test_the_record_does_not_break_convergence() -> None:
    inputs, plan = _plan(GHSA)
    again = planner.plan(replace(inputs, issues=_apply(inputs, plan), run_id="200-2"))
    assert again.actions == ()
    assert again.vex_name_only_ghsa == plan.vex_name_only_ghsa


def test_a_finding_with_no_alias_in_the_table_has_no_record() -> None:
    _, plan = _plan("CVE-2026-9999")
    assert plan.vex_name_only_ghsa == () and plan.rejected_vex == ()
    assert "vex_names_alias_only" not in _state(plan)


def test_issue_state_omits_the_field_when_unset() -> None:
    plan = planner.plan(_inputs((_finding(CVE, "HIGH"),)))
    assert "vex_names_alias_only" not in issue_body.parse_state(plan.actions[0].body)


# --- T12-R5-04 -----------------------------------------------------------------------------------------------


def _doc(path: str, status: models.VexStatus, name: str, aliases: tuple[str, ...], days_ago: int) -> models.VexDocument:
    from datetime import timedelta

    when = NOW - timedelta(days=days_ago)
    statement = models.VexStatement(name, aliases, (PURL,), status, "component_not_present", "reviewed", when)
    return models.VexDocument(
        "urn:x:" + path, "https://openvex.dev/ns/v0.2.0", "a", None, when, 1, None, (statement,), path
    )


def test_a_statement_that_loses_one_key_but_excludes_another_is_not_superseded() -> None:
    a = _doc(".vex/a.json", "not_affected", "CVE-2026-0001", ("CVE-2026-0002",), 2)
    b = _doc(".vex/b.json", "affected", "CVE-2026-0002", (), 1)
    table, rejected = effective_exclusions([a, b], _policy(), now=NOW)
    assert [k[0] for k in table] == ["CVE-2026-0001"]
    assert (".vex/a.json", REASON_SUPERSEDED) not in rejected


def test_a_statement_that_loses_every_key_is_still_superseded() -> None:
    a = _doc(".vex/a.json", "not_affected", "CVE-2026-0002", (), 2)
    b = _doc(".vex/b.json", "affected", "CVE-2026-0002", (), 1)
    table, rejected = effective_exclusions([a, b], _policy(), now=NOW)
    assert table == {}
    assert (".vex/a.json", REASON_SUPERSEDED) in rejected
