"""Tests of ``cli.py confirm-ref`` and of how ``confirmed_refs`` reaches ``dag.ready`` (task 15.4, IN-2).

**Validates: Requirements 28.12, 23.5**

The harness itself checks a ref before it records it: a SHA with ``git fetch`` and
``git merge-base --is-ancestor <sha> origin/main``, a tag with ``git ls-remote --tags origin`` (and
its commit must be on ``origin/main`` too). The tests use the sandbox's bare repository as
``origin``; nothing touches the network. Every value is synthetic.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from handoff import state
from hypothesis import given, settings
from hypothesis import strategies as st
from test_handoff_cli_integration import (
    REPO,
    call,
    config_value,
    item,
    prepare,
    read_status,
    status_path,
)

if TYPE_CHECKING:
    from conftest import HandoffSandbox

T0 = "2026-11-11T00:00:00Z"
READY = "r-hub-needs-x"
WAITING = "w-hub-needs-y"
UNKNOWN_SHA = "0" * 40


# ---------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------


def clone_for_pushing(sb: HandoffSandbox) -> Path:
    """A second clone of the sandbox remote, in which the tests make the commits and tags that they push."""
    work = sb.root / "pusher"
    if not work.exists():
        sb.git("clone", "-q", str(sb.bare), str(work))
    return work


def commit_in(sb: HandoffSandbox, work: Path, message: str) -> str:
    """An empty commit with synthetic authorship in ``work``; its SHA."""
    sb.git(
        *("-c", "user.name=Example", "-c", "user.email=example@example.com", "-c", f"core.hooksPath={sb.hooks_dir}"),
        *("-C", str(work), "commit", "--allow-empty", "-q", "-m", message),
    )
    return sb.git("-C", str(work), "rev-parse", "HEAD").stdout.decode().strip()


def advance_main(sb: HandoffSandbox) -> str:
    """Push one more commit to ``main`` of the remote; the sandbox's main working tree has not fetched it."""
    work = clone_for_pushing(sb)
    sb.git("-C", str(work), "checkout", "-q", "main")
    sha = commit_in(sb, work, "chore: advance main")
    sb.git("-C", str(work), "push", "-q", "origin", "main")
    return sha


def push_side_commit(sb: HandoffSandbox) -> str:
    """Push a commit on a branch other than ``main``; it is not an ancestor of ``origin/main``."""
    work = clone_for_pushing(sb)
    sb.git("-C", str(work), "checkout", "-q", "-B", "side", "origin/main")
    sha = commit_in(sb, work, "chore: a commit off main")
    sb.git("-C", str(work), "push", "-q", "origin", "side")
    sb.git("-C", str(work), "checkout", "-q", "main")
    return sha


def push_tag(sb: HandoffSandbox, name: str, target: str, *, annotated: bool) -> None:
    """Create a tag on ``target`` in the pusher's clone and push it."""
    work = clone_for_pushing(sb)
    sb.git("-C", str(work), "fetch", "-q", "origin")
    config = ("-c", "user.name=Example", "-c", "user.email=example@example.com", "-c", "tag.gpgSign=false")
    args = ("tag", "-a", "-m", "synthetic tag") if annotated else ("tag",)
    sb.git(*config, "-C", str(work), *args, name, target)
    sb.git("-C", str(work), "push", "-q", "origin", f"refs/tags/{name}")


def with_manifest(
    sb: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, needs_x: dict[str, str], needs_y: dict[str, str]
) -> None:
    """``prepare`` the sandbox with two change items, each requiring one ref of the sandbox repository."""
    manifest = {
        "schema_version": 1,
        "items": [
            item(READY, "a", mode="change", requires_refs=[{"repo": REPO, **needs_x}]),
            item(WAITING, "b", mode="change", requires_refs=[{"repo": REPO, **needs_y}]),
        ],
    }
    prepare(sb, monkeypatch, manifest=manifest, config=config_value())


def confirm(sb: HandoffSandbox, kind: str, name: str) -> tuple[int, str, str]:
    """``cli.py confirm-ref`` for the sandbox repository."""
    return call(sb, "confirm-ref", "--repo", REPO, "--kind", kind, "--name", name)


def recorded(sb: HandoffSandbox) -> list[dict[str, Any]]:
    """The confirmed refs in ``status.json``; empty when the file or the key is missing."""
    if not status_path(sb).exists():
        return []
    return list(read_status(sb).get("confirmed_refs", []))


def plan_text(sb: HandoffSandbox, item_id: str) -> str:
    """Standard output of ``plan --items <id>``."""
    code, out, err = call(sb, "plan", "--items", item_id)
    assert code == 0, (out, err)
    return out


# ---------------------------------------------------------------------------------------------
# confirm-ref: what the harness checks before it records
# ---------------------------------------------------------------------------------------------


def test_a_sha_on_origin_main_is_fetched_checked_and_recorded(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The commit exists only on the remote: success shows that the harness fetched; the record names it."""
    sb = handoff_sandbox
    pushed = advance_main(sb)
    with_manifest(sb, monkeypatch, {"kind": "sha", "name": pushed}, {"kind": "tag", "name": "never-made-1"})
    code, out, err = confirm(sb, "sha", pushed)
    assert code == 0, (out, err)
    assert pushed in out
    entries = recorded(sb)
    assert [(e["repo"], e["kind"], e["name"], e["sha"]) for e in entries] == [(REPO, "sha", pushed, pushed)]
    assert state.parse_status(status_path(sb).read_text(encoding="utf-8")) == read_status(sb)


@pytest.mark.parametrize("how", ["unknown", "not-fetched-side-branch", "fetched-side-branch"])
def test_a_sha_that_is_not_an_ancestor_of_origin_main_is_not_recorded(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    """An unknown commit, a commit the main working tree never fetched, and one it has but off main: all refused."""
    sb = handoff_sandbox
    if how == "unknown":
        sha = UNKNOWN_SHA
    else:
        sha = push_side_commit(sb)
        if how == "fetched-side-branch":
            sb.git("-C", str(sb.main_tree), "fetch", "-q", "origin", "side")
    with_manifest(sb, monkeypatch, {"kind": "sha", "name": sha}, {"kind": "tag", "name": "never-made-1"})
    code, out, err = confirm(sb, "sha", sha)
    assert code != 0, (out, err)
    assert recorded(sb) == []
    expected = {
        "unknown": "is not a commit of this repository",
        "not-fetched-side-branch": "is not a commit of this repository",
        "fetched-side-branch": "is not an ancestor of origin/main",
    }[how]
    assert expected in err, err


def test_an_annotated_tag_is_recorded_with_the_commit_it_points_to(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``ls-remote --tags`` lists the tag object and, peeled, the commit; the record keeps the commit."""
    sb = handoff_sandbox
    pushed = advance_main(sb)
    push_tag(sb, "preset-v1.0.0", pushed, annotated=True)
    tag_object = sb.git("-C", str(sb.bare), "rev-parse", "refs/tags/preset-v1.0.0").stdout.decode().strip()
    assert tag_object != pushed  # the tag is annotated, so its own ID is not the commit
    with_manifest(sb, monkeypatch, {"kind": "tag", "name": "preset-v1.0.0"}, {"kind": "tag", "name": "never-made-1"})
    code, out, err = confirm(sb, "tag", "preset-v1.0.0")
    assert code == 0, (out, err)
    assert [(e["kind"], e["name"], e["sha"]) for e in recorded(sb)] == [("tag", "preset-v1.0.0", pushed)]


def test_a_lightweight_tag_is_recorded_with_its_commit(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lightweight tag has no peeled line; its own ID is the commit."""
    sb = handoff_sandbox
    push_tag(sb, "light-1", sb.base_sha, annotated=False)
    with_manifest(sb, monkeypatch, {"kind": "tag", "name": "light-1"}, {"kind": "tag", "name": "never-made-1"})
    code, out, err = confirm(sb, "tag", "light-1")
    assert code == 0, (out, err)
    assert [(e["name"], e["sha"]) for e in recorded(sb)] == [("light-1", sb.base_sha)]


def test_a_tag_that_does_not_exist_is_not_recorded(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No tag of that name on the remote: exit code other than 0, nothing recorded; a tag of a longer name does not count."""
    sb = handoff_sandbox
    push_tag(sb, "x/preset-v1.0.0", sb.base_sha, annotated=True)  # ls-remote's tail match would list this one too
    with_manifest(sb, monkeypatch, {"kind": "tag", "name": "preset-v1.0.0"}, {"kind": "tag", "name": "never-made-1"})
    code, out, err = confirm(sb, "tag", "preset-v1.0.0")
    assert code != 0, (out, err)
    assert "has no tag preset-v1.0.0" in err, err
    assert recorded(sb) == []


def test_a_tag_whose_commit_is_not_on_origin_main_is_not_recorded(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The tag exists, but it points off the default branch (Requirement 28.12 waits for the default branch)."""
    sb = handoff_sandbox
    side = push_side_commit(sb)
    push_tag(sb, "off-main-1", side, annotated=True)
    sb.git("-C", str(sb.main_tree), "fetch", "-q", "origin", "side")  # the commit is here, but not on main
    with_manifest(sb, monkeypatch, {"kind": "tag", "name": "off-main-1"}, {"kind": "tag", "name": "never-made-1"})
    code, out, err = confirm(sb, "tag", "off-main-1")
    assert code != 0, (out, err)
    assert "is not an ancestor of origin/main" in err, err
    assert recorded(sb) == []


def test_there_is_no_way_to_give_the_sha_by_hand(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the repository, the kind and the name are arguments; a SHA that is not the harness's own finding is refused."""
    sb = handoff_sandbox
    with_manifest(sb, monkeypatch, {"kind": "tag", "name": "never-made-1"}, {"kind": "tag", "name": "never-made-2"})
    code, _, err = call(sb, "confirm-ref", "--repo", REPO, "--kind", "tag", "--name", "t-1", "--sha", sb.base_sha)
    assert code == 2 and "--sha" in err
    assert recorded(sb) == []


@pytest.mark.parametrize(
    ("repo", "kind", "name"),
    [
        (REPO, "sha", "abc123"),  # not 40 digits
        (REPO, "tag", "-oops"),  # would read as an option in an argv
        ("not-a-repo", "tag", "t-1"),  # not in repos of config.json
    ],
)
def test_a_malformed_request_ends_with_2_before_any_git_runs(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch, repo: str, kind: str, name: str
) -> None:
    """The name has the form of ``RequiredRef`` and the repository is a key of ``repos``."""
    sb = handoff_sandbox
    with_manifest(sb, monkeypatch, {"kind": "tag", "name": "never-made-1"}, {"kind": "tag", "name": "never-made-2"})
    code, _, _ = call(sb, "confirm-ref", "--repo", repo, "--kind", kind, f"--name={name}")
    assert code == 2
    assert recorded(sb) == []


def test_confirming_twice_changes_nothing_and_a_moved_tag_is_refused(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same ref again is a no-op; a tag that now points to another commit does not overwrite the record."""
    sb = handoff_sandbox
    first = advance_main(sb)
    push_tag(sb, "moving-1", first, annotated=False)
    with_manifest(sb, monkeypatch, {"kind": "tag", "name": "moving-1"}, {"kind": "tag", "name": "never-made-1"})
    assert confirm(sb, "tag", "moving-1")[0] == 0
    before = status_path(sb).read_bytes()
    assert confirm(sb, "tag", "moving-1")[0] == 0
    assert status_path(sb).read_bytes() == before
    work = clone_for_pushing(sb)
    second = commit_in(sb, work, "chore: a later commit")
    sb.git("-C", str(work), "push", "-q", "origin", "main")
    sb.git("-C", str(work), "tag", "-f", "moving-1", second)
    sb.git("-C", str(work), "push", "-q", "-f", "origin", "refs/tags/moving-1")
    code, out, err = confirm(sb, "tag", "moving-1")
    assert code != 0, (out, err)
    assert status_path(sb).read_bytes() == before


# ---------------------------------------------------------------------------------------------
# the confirmed refs reach dag.ready
# ---------------------------------------------------------------------------------------------


def test_an_item_waits_until_its_ref_is_recorded_and_only_that_ref_releases_it(
    handoff_sandbox: HandoffSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before: ``ref_unconfirmed``. After the record: ready. An item that requires another ref stays queued."""
    sb = handoff_sandbox
    pushed = advance_main(sb)
    with_manifest(sb, monkeypatch, {"kind": "sha", "name": pushed}, {"kind": "tag", "name": "never-made-1"})
    assert "ref_unconfirmed" in plan_text(sb, READY)
    assert "ref_unconfirmed" in plan_text(sb, WAITING)
    assert confirm(sb, "sha", pushed)[0] == 0
    ready = plan_text(sb, READY)
    assert "ref_unconfirmed" not in ready
    assert "selftest_unconfirmed" in ready  # ready, so run would reach the next check: the change item's selftest
    assert "ref_unconfirmed" in plan_text(sb, WAITING)


# ---------------------------------------------------------------------------------------------
# state: the record in status.json
# ---------------------------------------------------------------------------------------------


def test_the_record_round_trips_and_a_status_without_it_is_still_a_status() -> None:
    """Write, read, equal; the key is optional, so every earlier ``status.json`` stays valid."""
    bare = state.empty_status()
    assert "confirmed_refs" not in bare and state.confirmed_refs_of(bare) == ()
    sha = "a" * 40
    status = state.confirm_ref(bare, repo=REPO, kind="tag", name="t-1", sha=sha, at=T0)
    assert state.parse_status(state.render_status(status)) == status
    assert state.confirmed_refs_of(status) == ({"repo": REPO, "kind": "tag", "name": "t-1", "sha": sha, "at": T0},)
    assert "confirmed_refs" not in bare  # the argument is not changed
    assert state.confirm_ref(status, repo=REPO, kind="tag", name="t-1", sha=sha, at="2026-11-12T00:00:00Z") == status
    with pytest.raises(state.TransitionError):
        state.confirm_ref(status, repo=REPO, kind="tag", name="t-1", sha="b" * 40, at=T0)


@pytest.mark.parametrize(
    "entry",
    [
        {"repo": REPO, "kind": "tag", "name": "t-1", "sha": "short", "at": T0},
        {"repo": REPO, "kind": "branch", "name": "t-1", "sha": "a" * 40, "at": T0},
        {"repo": REPO, "kind": "tag", "name": "t-1", "sha": "a" * 40, "at": "yesterday"},
        {"repo": REPO, "kind": "tag", "name": "t-1", "sha": "a" * 40, "at": T0, "extra": 1},
        {"repo": REPO, "kind": "sha", "name": "a" * 40, "sha": "b" * 40, "at": T0},  # a sha ref names its own commit
    ],
)
def test_a_malformed_entry_is_not_a_status(entry: dict[str, Any]) -> None:
    """``check_status`` is the gate on every read, so a damaged record stops the harness as any damage does."""
    status = state.empty_status()
    status["confirmed_refs"] = [entry]  # type: ignore[typeddict-unknown-key]
    with pytest.raises(state.InvalidStatusError):
        state.check_status(status)


def test_a_repeated_ref_is_not_a_status() -> None:
    """One entry per ref."""
    entry = {"repo": REPO, "kind": "tag", "name": "t-1", "sha": "a" * 40, "at": T0}
    status = state.empty_status()
    status["confirmed_refs"] = [entry, dict(entry)]  # type: ignore[typeddict-unknown-key]
    with pytest.raises(state.InvalidStatusError):
        state.check_status(status)


@settings(max_examples=100, deadline=None)
@given(
    refs=st.lists(
        st.tuples(st.sampled_from(("tag", "sha")), st.text(alphabet="abcdef0123456789", min_size=40, max_size=40)),
        max_size=6,
        unique_by=lambda ref: ref,
    )
)
def test_any_sequence_of_confirmations_round_trips(refs: list[tuple[str, str]]) -> None:
    """Whatever is confirmed, in whatever order, renders and parses back to an equal status."""
    status = state.empty_status()
    for kind, digits in refs:
        name = digits if kind == "sha" else f"t-{digits}"
        status = state.confirm_ref(status, repo=REPO, kind=kind, name=name, sha=digits, at=T0)
    assert state.parse_status(state.render_status(status)) == status
    assert len(state.confirmed_refs_of(status)) == len(refs)
