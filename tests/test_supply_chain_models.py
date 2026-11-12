"""Unit tests for ``supply_chain.models``."""

from __future__ import annotations

import dataclasses
import typing
from datetime import UTC, date, datetime, timedelta, timezone

import pytest
from supply_chain import models

NOW = datetime(2026, 11, 10, 0, 0, tzinfo=UTC)
REPO = models.Repo("example-org", "example-repo")
COMPONENT = models.Component(purl="pkg:npm/left-pad@1.3.0", name="left-pad", version="1.3.0")


def _finding(**overrides: object) -> models.Finding:
    base: dict[str, object] = {
        "repo": REPO,
        "vuln_id": "CVE-2026-0001",
        "aliases": (),
        "component": COMPONENT,
        "cvss_severity": "HIGH",
        "fixed_version": None,
        "advisory_published_at": NOW,
        "layer": "A",
        "first_observed_component_at": NOW,
    }
    base.update(overrides)
    return models.Finding(**base)  # type: ignore[arg-type]


def _feeds(**overrides: object) -> models.FeedSnapshot:
    base: dict[str, object] = {
        "kev": {},
        "epss": {},
        "malicious": {},
        "malicious_withdrawn": {},
        "malicious_delisted": frozenset(),
        "malicious_unconfirmed": frozenset(),
    }
    base.update(overrides)
    return models.FeedSnapshot(**base)  # type: ignore[arg-type]


def _all_classes() -> list[type]:
    return [c for c in vars(models).values() if isinstance(c, type) and dataclasses.is_dataclass(c)]


def test_every_model_is_frozen_with_slots() -> None:
    classes = _all_classes()
    assert len(classes) == 16
    for cls in classes:
        params = cls.__dataclass_params__  # type: ignore[attr-defined]
        assert params.frozen, cls.__name__
        assert "__slots__" in vars(cls), cls.__name__


def test_assignment_is_rejected() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        REPO.owner = "other"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        _finding().vuln_id = "x"  # type: ignore[misc]


def test_repo_equality_and_hash_ignore_case() -> None:
    other = models.Repo("EXAMPLE-ORG", "Example-Repo")
    assert REPO == other
    assert hash(REPO) == hash(other)
    assert REPO != models.Repo("example-org", "different")
    assert len({REPO, other}) == 1


def test_component_defaults_are_unknown() -> None:
    assert COMPONENT.direct == "unknown"
    assert COMPONENT.author == "unknown"
    assert COMPONENT.format_name == "unknown"
    assert COMPONENT.format_version == "unknown"
    assert COMPONENT.generation_stage == "unknown"


def test_finding_is_hashable() -> None:
    assert len({_finding(), _finding()}) == 1


def test_naive_datetime_is_rejected_everywhere() -> None:
    naive = datetime(2026, 11, 10)
    with pytest.raises(ValueError):
        _finding(first_observed_component_at=naive)
    with pytest.raises(ValueError):
        _finding(advisory_published_at=naive)
    with pytest.raises(ValueError):
        _feeds(malicious={"MAL-2026-1": naive})
    with pytest.raises(ValueError):
        _feeds(malicious_withdrawn={"MAL-2026-1": naive})
    with pytest.raises(ValueError):
        models.VexStatement("CVE-1", (), (), "fixed", None, None, naive)
    with pytest.raises(ValueError):
        models.VexDocument("id", "ctx", "a", None, naive, 1, None, (), "p")
    with pytest.raises(ValueError):
        models.PullRequestRef(REPO, "CVE-1", naive, None)
    with pytest.raises(ValueError):
        models.PullRequestRef(REPO, "CVE-1", NOW, naive)


def test_non_utc_offset_is_rejected() -> None:
    jst = datetime(2026, 11, 10, 9, 0, tzinfo=timezone(timedelta(hours=9)))
    with pytest.raises(ValueError):
        _finding(first_observed_component_at=jst)


def test_optional_datetimes_accept_none() -> None:
    assert _finding(advisory_published_at=None).advisory_published_at is None
    assert _feeds(malicious={"MAL-2026-1": None}).malicious == {"MAL-2026-1": None}
    assert _feeds(kev=None, epss=None, malicious=None).kev is None


def test_plan_inputs_rejects_naive_now() -> None:
    kwargs = {
        "run_id": "1-1",
        "pull_requests": (),
        "findings": frozenset(),
        "fetch_ok": frozenset(),
        "feeds": _feeds(),
        "vex": {},
        "issues": (),
    }
    policy = _policy()
    models.PlanInputs(policy=policy, now=NOW, **kwargs)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        models.PlanInputs(policy=policy, now=datetime(2026, 1, 1), **kwargs)  # type: ignore[arg-type]


def _policy() -> models.Policy:
    cd = models.CooldownDays(default=7, major=14)
    return models.Policy(
        schema_version=1,
        target_repositories=(REPO,),
        excluded_repositories=(),
        opening_threshold=models.OpeningThreshold("HIGH", True, True),
        cooldown_days=cd,
        automerge_include=(),
        automerge_exclude=("hub_reusable_workflow",),
        automerge_enabled_repositories=(),
        package_manager_wait=cd,
        non_production_paths=(),
        vex_directory=".vex",
        vex_exclude_statuses=("not_affected", "fixed"),
        vex_approver_role="maintainer",
        vex_one_statement_per_document=True,
        vex_malicious_never_suppressed=True,
        response_target=models.ResponseTarget(24, 7, 30),
        max_new_issues_per_repo_per_run=10,
    )


def _literal_values(alias: object) -> set[str]:
    return set(typing.get_args(alias))


def test_enumerations_match_the_design() -> None:
    assert _literal_values(models.Severity) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert _literal_values(models.VexStatus) == {
        "not_affected",
        "affected",
        "fixed",
        "under_investigation",
    }
    assert _literal_values(models.FeedName) == {"kev", "epss", "malicious"}
    assert _literal_values(models.CloseReason) == {
        "resolved",
        "withdrawn",
        "feed_version_delisted",
        "vex_not_affected",
        "vex_fixed",
    }
    assert _literal_values(models.Layer) == {"A", "B"}
    assert _literal_values(models.IssueKind) == {"finding", "summary", "failure"}
    assert _literal_values(models.IssueState) == {"open", "closed"}
    assert _literal_values(models.IssueOp) == {"create", "update", "close", "reopen"}


def test_field_names_match_the_design() -> None:
    def names(cls: type) -> list[str]:
        return [f.name for f in dataclasses.fields(cls)]

    assert names(models.FeedSnapshot) == [
        "kev",
        "epss",
        "malicious",
        "malicious_withdrawn",
        "malicious_delisted",
        "malicious_unconfirmed",
    ]
    assert names(models.PlanInputs) == [
        "policy",
        "run_id",
        "now",
        "pull_requests",
        "findings",
        "fetch_ok",
        "feeds",
        "vex",
        "issues",
    ]
    assert names(models.Plan) == [
        "actions",
        "vex_exclusions",
        "rejected_vex",
        "below_threshold",
        "unscored",
        "overflow_counts",
        "malicious_withdrawn_unconfirmed",
    ]
    assert names(models.Component) == [
        "purl",
        "name",
        "version",
        "direct",
        "author",
        "format_name",
        "format_version",
        "generation_stage",
    ]
    assert names(models.PullRequestRef) == ["repo", "vuln_id", "created_at", "merged_at"]


def test_kev_values_hold_date_and_ransomware_flag() -> None:
    feeds = _feeds(kev={"CVE-1": (date(2026, 1, 1), None)})
    assert feeds.kev == {"CVE-1": (date(2026, 1, 1), None)}


def test_full_model_graph_builds() -> None:
    policy = _policy()
    action = models.IssueAction("close", REPO, "finding", "MAL-1", 3, None, "withdrawn")
    plan = models.Plan((action,), (), (), (), (), {REPO: 0}, ((REPO, 3, "MAL-1"),))
    assert plan.actions[0].close_reason == "withdrawn"
    assert policy.vex_malicious_never_suppressed is True
