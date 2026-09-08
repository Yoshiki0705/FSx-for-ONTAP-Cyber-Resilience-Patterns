"""Tests for how an ARP volume state is classified and reported.

ARP has seven states, and the failure this pins is silent rather than loud. Code that
tests membership of the two states meaning "protected" and treats everything else as
unprotected does not raise: it reports a protected volume as unprotected, or hides a
paused one among ordinary failures. Nothing in a test suite notices unless a test supplies
the value, which is why the values are enumerated here rather than sampled.

The seven come from the parameter enumeration in `security anti-ransomware volume show`.
The prose immediately below that enumeration lists six and drops `paused`; reading only
the prose is how a value reaches production matching nothing.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for candidate in ("solutions/shared", "solutions/compliance"):
    path = str(ROOT / candidate)
    if path not in sys.path:
        sys.path.insert(0, path)

from ontap_client import classify_arp_state  # noqa: E402


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ("enabled", "protecting"),
        ("dry_run", "protecting"),
        ("disabled", "not_protecting"),
        ("paused", "not_protecting"),
        ("dry_run_paused", "not_protecting"),
        ("enable_paused", "not_protecting"),
        ("disable_in_progress", "transitional"),
    ],
)
def test_every_documented_state_is_classified(state: str, expected: str) -> None:
    """All seven, including the one the reference's prose omits."""
    assert classify_arp_state(state) == expected


@pytest.mark.parametrize(
    "state",
    ["disable-in-progress", "DISABLE-IN-PROGRESS", " Disable_In_Progress "],
)
def test_the_cli_spelling_classifies_the_same_as_the_rest_spelling(state: str) -> None:
    """REST returns underscores, the CLI prints hyphens, and both reach this code."""
    assert classify_arp_state(state) == "transitional"


@pytest.mark.parametrize("state", ["", None, "something_ontap_added_later", 42])
def test_an_unrecognised_state_is_unknown_rather_than_unprotected(state: object) -> None:
    """A value this code has not seen must not inherit an answer from a default branch.

    Reporting it as unprotected is the silent failure; reporting it as unknown makes the
    caller decide.
    """
    assert classify_arp_state(state) == "unknown"


class _FakeClient:
    """Minimal ONTAP client returning fixed states per volume."""

    def __init__(self, states: list[str]) -> None:
        self._states = states

    def list_volumes(self) -> list[dict]:
        return [{"name": f"vol{i}", "uuid": f"uuid-{i}"} for i in range(len(self._states))]

    def get_arp_status(self, uuid: str) -> dict:
        return {"state": self._states[int(uuid.split("-")[1])]}


def _check(states: list[str]) -> tuple[str, bool, dict]:
    from compliance_collector import _check_arp_status

    return _check_arp_status(_FakeClient(states))


def test_a_transitional_volume_is_not_reported_as_unprotected() -> None:
    """`disable_in_progress` is still protecting, and took over 10 minutes when observed."""
    actual, all_protected, detail = _check(["enabled", "disable_in_progress"])

    assert detail["counts"]["transitional"] == 1
    assert "1 transitional" in actual
    assert all_protected is False  # not yet protecting-everywhere, and it says why


def test_a_paused_volume_is_counted_and_named() -> None:
    """The value the reference's prose omits must still reach the report."""
    actual, all_protected, detail = _check(["enabled", "paused"])

    assert detail["volumes"][1]["classification"] == "not_protecting"
    assert "1 not protecting" in actual
    assert all_protected is False


def test_all_protecting_is_true_only_when_every_volume_protects() -> None:
    actual, all_protected, _ = _check(["enabled", "dry_run"])

    assert all_protected is True
    assert actual == "2/2 protecting"


def test_no_volumes_is_not_reported_as_compliant() -> None:
    """An empty list satisfies `all()` vacuously, which would read as fully protected."""
    _, all_protected, _ = _check([])

    assert all_protected is False
