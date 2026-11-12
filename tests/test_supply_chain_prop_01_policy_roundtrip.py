"""Property 1: Policy_File round trip (task 8.4)."""

from __future__ import annotations

from hypothesis import event, given, settings
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
    parsed = parse_policy(text)

    assert parsed == policy
    assert isinstance(text, str)
    assert render_policy(parsed) == text
    assert render_policy(parsed).encode("utf-8") == text.encode("utf-8")
