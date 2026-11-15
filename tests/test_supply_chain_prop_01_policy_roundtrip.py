"""Property 1: Policy_File round trip (task 8.4)."""

from __future__ import annotations

from dataclasses import replace

from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain.models import Policy
from supply_chain.policy import parse_policy, render_policy

from tests.strategies import supply_chain as sc


# Feature: cyber-resilience-phase4-supply-chain, Property 1: Policy_File のラウンドトリップ
@settings(max_examples=200, deadline=None)
@given(policy=sc.policies())
def test_policy_file_round_trip(policy: Policy) -> None:
    """parse(render(p)) == p, and render(parse(render(p))) is byte-identical to render(p).

    **Validates: Requirements 21.5, 21.7, 21.8**
    """
    event(f"targets={min(len(policy.target_repositories), 5)}")
    event(f"extra_excluded={min(len(policy.excluded_repositories) - 4, 3)}")
    event(f"automerge_enabled={'some' if policy.automerge_enabled_repositories else 'none'}")
    event(f"include_rules={len(policy.automerge_include)}")

    text = render_policy(policy)
    assert render_policy(policy) == text  # same input, same bytes (21.7)
    parsed = parse_policy(text)

    assert parsed == policy
    assert isinstance(text, str)
    assert render_policy(parsed) == text
    assert render_policy(parsed).encode("utf-8") == text.encode("utf-8")


@settings(max_examples=100, deadline=None)
@given(policy=sc.policies(), hours=st.one_of(st.none(), st.integers(1, 10_000)))
def test_policy_file_round_trip_with_the_watchdog_limit(policy: Policy, hours: int | None) -> None:
    """The optional ``watchdog.limit_hours`` survives the round trip, and an absent one stays absent (task 8.12)."""
    policy = replace(policy, watchdog_limit_hours=hours)
    text = render_policy(policy)
    assert parse_policy(text) == policy
    assert render_policy(parse_policy(text)) == text
    assert ("watchdog" in text) == (hours is not None)
