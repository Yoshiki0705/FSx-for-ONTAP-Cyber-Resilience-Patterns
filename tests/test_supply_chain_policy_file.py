"""Example tests that pin the initial values of the real Policy_File (task 8.3)."""

from __future__ import annotations

from pathlib import Path

import pytest
from supply_chain.models import Policy
from supply_chain.policy import DEFAULT_EXCLUDED_REPOSITORIES, parse_policy, render_policy

POLICY_PATH = Path(__file__).resolve().parent.parent / "docs" / "agent" / "supply-chain-policy.json"

EXPECTED_TARGETS = (
    "Yoshiki0705/FSx-for-ONTAP-Cyber-Resilience-Patterns",
    "Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook",
    "Yoshiki0705/FSx-for-ONTAP-App-Modernization-Patterns",
    "Yoshiki0705/FSx-for-ONTAP-Container-Datastore-Patterns",
    "Yoshiki0705/S3-Burst-on-ONTAP-Files",
    "Yoshiki0705/VMware-Migration-EC2-ONTAP",
    "Yoshiki0705/ONTAP-Edge-to-Cloud-AI",
    "Yoshiki0705/FSx-for-ONTAP-Lakehouse-Integrations",
    "Yoshiki0705/FSx-for-ONTAP-Observability-integrations",
    "Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns",
    "Yoshiki0705/BLEA-FSx-for-ONTAP-Usecase",
    "Yoshiki0705/FSx-for-ONTAP-Agentic-Access-Aware-RAG",
)


@pytest.fixture(scope="module")
def text() -> str:
    return POLICY_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def policy(text: str) -> Policy:
    return parse_policy(text)


def test_real_file_parses(policy: Policy) -> None:
    assert policy.schema_version == 1


def test_render_of_parse_is_the_file_itself(text: str) -> None:
    assert render_policy(parse_policy(text)) == text


def test_twelve_targets_with_the_design_names(policy: Policy) -> None:
    assert len(policy.target_repositories) == 12
    assert tuple(f"{r.owner}/{r.name}" for r in policy.target_repositories) == EXPECTED_TARGETS


def test_four_exclusions_and_none_is_a_target(policy: Policy) -> None:
    assert len(policy.excluded_repositories) == 4
    assert {f"{r.owner}/{r.name}" for r in policy.excluded_repositories} == set(DEFAULT_EXCLUDED_REPOSITORIES)
    assert not set(policy.excluded_repositories) & set(policy.target_repositories)


def test_malicious_packages_are_always_opened_and_never_suppressed(policy: Policy) -> None:
    assert policy.opening_threshold.open_if_malicious is True
    assert policy.vex_malicious_never_suppressed is True


def test_opening_threshold_initial_values(policy: Policy) -> None:
    assert policy.opening_threshold.min_cvss_severity == "HIGH"
    assert policy.opening_threshold.open_if_kev_listed is True


def test_response_target_values(policy: Policy) -> None:
    target = policy.response_target
    assert target.detect_hours == 24
    assert target.fix_days_kev_or_malicious == 7
    # Reference value (Q-13); the pilot decides whether to keep it or return to 30.
    assert target.fix_days_high == 14


def test_package_manager_wait_equals_cooldown(policy: Policy) -> None:
    assert (policy.cooldown_days.default, policy.cooldown_days.major) == (3, 7)
    assert policy.package_manager_wait == policy.cooldown_days


def test_automerge_starts_disabled_everywhere(policy: Policy) -> None:
    assert policy.automerge_enabled_repositories == ()
    assert "vulnerability_fix" in policy.automerge_exclude
    assert "hub_reusable_workflow" in policy.automerge_exclude


def test_issue_limit_is_within_range(policy: Policy) -> None:
    assert 1 <= policy.max_new_issues_per_repo_per_run <= 100
    assert policy.max_new_issues_per_repo_per_run == 10


def test_vex_and_scope_initial_values(policy: Policy) -> None:
    assert policy.vex_directory == ".vex"
    assert set(policy.vex_exclude_statuses) == {"not_affected", "fixed"}
    assert policy.vex_approver_role == "VEX_Reviewer"
    assert policy.vex_one_statement_per_document is True
    assert policy.non_production_paths == ("tests/", "docs/")
