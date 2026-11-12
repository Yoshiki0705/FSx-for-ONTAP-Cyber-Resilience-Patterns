"""Tests of the publish mode of ``cli.py publish --approval``, started as a file (task 5.4).

Each test makes the change item ``succeeded`` with ``run_change`` of ``test_handoff_change_integration.py``
(a ``guards_active`` selftest, then the fake ``kiro-cli`` commits the declared file), writes an
approval record below ``.private/handoff/approvals/``, and starts ``python cli.py publish --approval
<file>``. The remote ``origin`` is the sandbox's local bare repository: the main working tree's
``remote.origin.url`` is set to a made-up GitHub URL that ``url.<bare>.insteadOf`` rewrites to the
bare repository, so that the harness derives ``OWNER/NAME`` from the URL as it does for a real remote
and every push goes to the local bare repository. ``gh`` and ``git`` are scripts in ``<root>/bin``
that come first on ``PATH``: the fake ``gh`` records its argv and prints a pull request URL; the
``git`` records its argv and runs the real git, except that ``ls-remote`` prints what
``FAKE_GIT_LSREMOTE`` says when it is set. Nothing uses the network, this machine's ``~/.config/gh``
or a real remote, and the real ``kiro-cli`` is never started.

Design section 20, "公開（publish）" and Requirements 28.14, 28.15, 28.20 and 28.23:

- an item that the approval does not list, and one that is not ``succeeded``, is not published;
- a scan finding in a commit message or an added line, and a conflict with the default branch, hold
  the item (it stays ``succeeded``, ``published.hold`` says why) and nothing is pushed;
- after the push, ``ls-remote`` must print the SHA of the local branch before the pull request is
  opened; the pull request number and the result of ``gh pr checks`` go to ``published``;
- an item that is published is not published again;
- the commands run are those of ``command.build_publish_plan``, never with ``--force``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from handoff import state
from test_handoff_change_integration import (
    BRANCH,
    CHANGE,
    DECLARED,
    QUERY,
    Ended,
    git_text,
    read_status,
    remote_refs,
    run_change,
    run_cli,
)

if TYPE_CHECKING:
    from conftest import HandoffSandbox

#: The made-up GitHub repository that ``origin`` names.
GITHUB_REPO = "example-owner/example-hub"
GITHUB_URL = f"https://github.com/{GITHUB_REPO}.git"
#: The customer name of the deny list that ``prepare`` writes, put together here so that this file
#: holds no deny term itself.
DENY_TERM = "example" + "corp"
PR_NUMBER = 7
FORCING = {"--force", "-f", "--force-with-lease", "--mirror", "--delete"}

FAKE_GH = """#!{python}
import json, os, sys

args = sys.argv[1:]
with open(os.environ["FAKE_GH_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps({{"argv": args, "cwd": os.getcwd()}}) + "\\n")
if args[:2] == ["pr", "create"]:
    print("https://github.com/{repo}/pull/" + os.environ.get("FAKE_GH_PR", "{number}"))
elif args[:2] == ["pr", "checks"]:
    print("build\\tpending")
    sys.exit(int(os.environ.get("FAKE_GH_CHECKS_EXIT", "8")))
else:
    sys.stderr.write("fake gh: unexpected " + repr(args))
    sys.exit(2)
"""

FAKE_GIT = """#!{python}
import json, os, sys

args = sys.argv[1:]
with open(os.environ["FAKE_GIT_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(args) + "\\n")
if "ls-remote" in args and "FAKE_GIT_LSREMOTE" in os.environ:
    if os.environ["FAKE_GIT_LSREMOTE"]:
        print(os.environ["FAKE_GIT_LSREMOTE"] + "\\t" + args[-1])
    sys.exit(0)
os.execv({real!r}, [{real!r}] + args)
"""


def now() -> str:
    """The current moment as ``approved_at`` is written."""
    return state.format_timestamp(datetime.now(timezone.utc))


def succeeded(sb: HandoffSandbox, behaviors: str = "commit") -> Ended:
    """Run the change item to its end, and set up the fake ``gh``, the ``git`` wrapper and the GitHub URL."""
    ended = run_change(sb, behaviors)
    bin_dir = sb.root / "bin"
    bin_dir.mkdir()
    real_git = shutil.which("git")
    assert real_git is not None
    for name, text in (
        ("gh", FAKE_GH.format(python=sys.executable, repo=GITHUB_REPO, number=PR_NUMBER)),
        ("git", FAKE_GIT.format(python=sys.executable, real=real_git)),
    ):
        (bin_dir / name).write_text(text, encoding="utf-8")
        (bin_dir / name).chmod(0o755)
    main = str(sb.main_tree)
    sb.git("-C", main, "config", "remote.origin.url", GITHUB_URL)
    sb.git("-C", main, "config", f"url.{sb.bare}.insteadOf", GITHUB_URL)
    return ended


def write_approval(sb: HandoffSandbox, ids: list[str], approved_at: str | None = None, **changes: Any) -> Path:
    """Write ``approvals/<moment>.json`` and return its path; ``changes`` replace or (with ``None``) drop keys."""
    record: dict[str, Any] = {
        "approved_at": approved_at or now(),
        "item_ids": ids,
        "approved_in": ".private/tasks/phase4/decisions.md",
    }
    for key, value in changes.items():
        if value is None:
            record.pop(key)
        else:
            record[key] = value
    directory = sb.handoff_dir / "approvals"
    directory.mkdir(exist_ok=True)
    path = directory / f"{record['approved_at'].replace(':', '-')}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def publish(sb: HandoffSandbox, approval: Path, **extra: str) -> subprocess.CompletedProcess[str]:
    """``cli.py publish --approval <approval>`` with the fake ``gh`` and the ``git`` wrapper first on ``PATH``."""
    logs = sb.root / "records"
    return run_cli(
        sb,
        "publish",
        "--approval",
        str(approval),
        PATH=f"{sb.root / 'bin'}:{sb.environ()['PATH']}",
        FAKE_GH_LOG=str(logs / "gh.jsonl"),
        FAKE_GIT_LOG=str(logs / "git.jsonl"),
        **extra,
    )


def gh_calls(sb: HandoffSandbox) -> list[list[str]]:
    """The argv of each call of the fake ``gh``, in order."""
    path = sb.root / "records" / "gh.jsonl"
    if not path.exists():
        return []
    return [json.loads(line)["argv"] for line in path.read_text(encoding="utf-8").splitlines()]


def git_calls(sb: HandoffSandbox) -> list[list[str]]:
    """The argv of each call of the ``git`` wrapper, in order."""
    path = sb.root / "records" / "git.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def pushes(sb: HandoffSandbox) -> list[list[str]]:
    """The calls of ``git push``."""
    return [call for call in git_calls(sb) if "push" in call]


def branch_on_remote(sb: HandoffSandbox) -> str | None:
    """The SHA of ``handoff/<id>`` in the bare repository, or ``None``."""
    for line in remote_refs(sb):
        name, _, sha = line.partition(" ")
        if name == f"refs/heads/{BRANCH}":
            return sha
    return None


def published_of(sb: HandoffSandbox) -> dict[str, Any]:
    """``published`` of the change item's record."""
    published: dict[str, Any] = read_status(sb)["items"][CHANGE]["published"]
    return published


def commit_in_worktree(sb: HandoffSandbox, ended: Ended, *, message: str, text: str | None = None) -> None:
    """Add a commit to the worktree's branch after the run: one that the observations did not see."""
    worktree = str(ended.worktree)
    if text is not None:
        with open(ended.worktree / DECLARED, "a", encoding="utf-8") as handle:
            handle.write(text)
        sb.git("-C", worktree, "add", "--", DECLARED)
        sb.git("-C", worktree, "commit", "-q", "-m", message)
    else:
        sb.git("-C", worktree, "commit", "-q", "--allow-empty", "-m", message)


def untouched(sb: HandoffSandbox) -> None:
    """Nothing was pushed, no pull request was opened, and the item has no pull request number."""
    assert branch_on_remote(sb) is None
    assert pushes(sb) == []
    assert gh_calls(sb) == []
    assert published_of(sb)["pr"] is None


# ---------------------------------------------------------------------------------------------
# the control: an item that meets every condition is published
# ---------------------------------------------------------------------------------------------


def test_a_listed_succeeded_item_is_pushed_confirmed_and_opened_as_a_draft(handoff_sandbox: HandoffSandbox) -> None:
    """The approval lists the ``succeeded`` item, scan and conflict check pass: push, SHA check, draft PR, checks."""
    sb = handoff_sandbox
    ended = succeeded(sb)
    approved_at = now()
    done = publish(sb, write_approval(sb, [CHANGE], approved_at))
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert f"{CHANGE}: 公開した（PR #{PR_NUMBER}、checks: pending）" in done.stdout
    head = git_text(sb, "-C", str(ended.worktree), "rev-parse", "HEAD")
    assert branch_on_remote(sb) == head, "the pushed branch is the local one"
    record = read_status(sb)["items"][CHANGE]
    assert record["state"] == state.SUCCEEDED
    published = record["published"]
    assert published["approved_at"] == approved_at and published["pr"] == PR_NUMBER
    assert published["url"] == f"https://github.com/{GITHUB_REPO}/pull/{PR_NUMBER}"
    assert published["ci"] == {"result": "pending", "exit_code": 8, "output": "build\tpending\n"}
    assert "hold" not in published
    create, checks = gh_calls(sb)
    body = str(sb.handoff_dir / "publish" / f"{CHANGE}-pr-body.md")
    assert create == [
        *("pr", "create", "--draft", "--base", "main", "--head", BRANCH),
        *("--title", "test: change made by the fake kiro-cli", "--body-file", body, "--repo", GITHUB_REPO),
    ]
    assert checks == ["pr", "checks", str(PR_NUMBER), "--repo", GITHUB_REPO]
    events = [event["kind"] for event in read_status(sb)["events"]]
    assert events[-1] == "publish_batch"


def test_the_commands_that_run_are_the_plans_and_never_force(handoff_sandbox: HandoffSandbox) -> None:
    """The only push is ``git -C <worktree> push origin handoff/<id>``, and no call of git or gh forces anything."""
    sb = handoff_sandbox
    ended = succeeded(sb)
    done = publish(sb, write_approval(sb, [CHANGE]))
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert pushes(sb) == [["-C", str(ended.worktree), "push", "origin", BRANCH]]
    for call in [*git_calls(sb), *gh_calls(sb)]:
        assert not FORCING & set(call), call
        assert not any(arg.startswith(("--force", "+")) for arg in call), call
    assert [call[:2] for call in gh_calls(sb)] == [["pr", "create"], ["pr", "checks"]]


# ---------------------------------------------------------------------------------------------
# what the approval does not cover
# ---------------------------------------------------------------------------------------------


def test_an_item_the_approval_does_not_list_is_not_published(handoff_sandbox: HandoffSandbox) -> None:
    """The approval lists the query item and an unknown ID; the ``succeeded`` change item is left alone."""
    sb = handoff_sandbox
    succeeded(sb)
    done = publish(sb, write_approval(sb, [QUERY, "no-such-item"]))
    assert done.returncode == 1, (done.stdout, done.stderr)
    assert f"{QUERY}: 公開しなかった: query_mode" in done.stdout
    assert "no-such-item: 公開しなかった: not_in_manifest" in done.stdout
    assert CHANGE not in done.stdout
    untouched(sb)
    assert read_status(sb)["items"][CHANGE]["published"] == {"approved_at": None, "pr": None}


def test_an_item_that_is_not_succeeded_is_not_published(handoff_sandbox: HandoffSandbox) -> None:
    """A change item that ended ``needs-human`` is listed by the approval, and still nothing is pushed."""
    sb = handoff_sandbox
    succeeded(sb, "undeclared")
    assert read_status(sb)["items"][CHANGE]["state"] == state.NEEDS_HUMAN
    done = publish(sb, write_approval(sb, [CHANGE]))
    assert done.returncode == 1, (done.stdout, done.stderr)
    assert f"{CHANGE}: 公開しなかった: not_succeeded" in done.stdout
    untouched(sb)


def test_an_item_that_succeeded_after_the_approval_is_not_published(handoff_sandbox: HandoffSandbox) -> None:
    """An approval from before the success covers the branches as they were then, not this one."""
    sb = handoff_sandbox
    succeeded(sb)
    done = publish(sb, write_approval(sb, [CHANGE], "2000-01-01T00:00:00Z"))
    assert done.returncode == 1, (done.stdout, done.stderr)
    assert f"{CHANGE}: 公開しなかった: succeeded_after_approval" in done.stdout
    untouched(sb)


@pytest.mark.parametrize(
    ("changes", "complaint"),
    [
        ({"approved_in": None}, "approval.approved_in: missing"),
        ({"extra": "x"}, "unknown key 'extra'"),
        ({"approved_at": "tomorrow"}, "approval.approved_at: must be a moment"),
        ({"approved_at": "2999-01-01T00:00:00Z"}, "is in the future"),
        ({"item_ids": [CHANGE, CHANGE]}, "repeats"),
        ({"item_ids": []}, "non-empty"),
        ({"approved_in": "/etc/passwd"}, "relative path"),
    ],
    ids=["missing", "unknown-key", "bad-moment", "future", "repeated", "empty", "absolute-record"],
)
def test_a_malformed_approval_is_refused_before_anything_runs(
    handoff_sandbox: HandoffSandbox, changes: dict[str, Any], complaint: str
) -> None:
    """Exit code 2 with the problem on standard error; no push, no call of gh."""
    sb = handoff_sandbox
    succeeded(sb)
    done = publish(sb, write_approval(sb, [CHANGE], **changes))
    assert done.returncode == 2, (done.stdout, done.stderr)
    assert complaint in done.stderr
    untouched(sb)


def test_an_approval_outside_the_approvals_directory_is_refused(handoff_sandbox: HandoffSandbox) -> None:
    """The record must be a file directly below ``.private/handoff/approvals/``."""
    sb = handoff_sandbox
    succeeded(sb)
    elsewhere = sb.root / "approval.json"
    elsewhere.write_text(json.dumps({"approved_at": now(), "item_ids": [CHANGE], "approved_in": ".private/x.md"}))
    done = publish(sb, elsewhere)
    assert done.returncode == 2, (done.stdout, done.stderr)
    assert "directly below" in done.stderr
    untouched(sb)


# ---------------------------------------------------------------------------------------------
# the checks before a push: scan and conflicts
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("where", ["added-line", "commit-message"])
def test_a_scan_finding_holds_the_item_and_nothing_is_pushed(handoff_sandbox: HandoffSandbox, where: str) -> None:
    """A deny term in a commit made after the run (an added line, or a message) holds the item.

    The commit is one that the observations did not see, so the scan of the publish step is the only
    check that can stop it. The item stays ``succeeded``: no transition leaves that state, so the hold is
    ``published.hold`` and an event ``publish_held``. The term itself is not written anywhere.
    """
    sb = handoff_sandbox
    ended = succeeded(sb)
    if where == "added-line":
        commit_in_worktree(sb, ended, message="docs: add a note", text=f"A note about {DENY_TERM}.\n")
    else:
        commit_in_worktree(sb, ended, message=f"docs: a note for {DENY_TERM}")
    done = publish(sb, write_approval(sb, [CHANGE]))
    assert done.returncode == 1, (done.stdout, done.stderr)
    assert f"{CHANGE}: 公開しなかった: publish_scan_findings（保留。" in done.stdout
    untouched(sb)
    record = read_status(sb)["items"][CHANGE]
    assert record["state"] == state.SUCCEEDED
    hold = record["published"]["hold"]
    assert hold["reason"] == "publish_scan_findings"
    location = f"{DECLARED} line" if where == "added-line" else "commit message 0 line 1"
    assert location in hold["detail"]
    kinds = [event["kind"] for event in read_status(sb)["events"]]
    assert kinds[-2:] == ["publish_held", "publish_batch"]
    everything = done.stdout + done.stderr + (sb.handoff_dir / "status.json").read_text(encoding="utf-8")
    assert DENY_TERM not in everything


CONFLICT_CASES = {
    "same-file": (DECLARED, "publish_conflicts"),
    "other-file": ("docs/other-session.md", "published"),
}


@pytest.mark.parametrize(("path", "reason"), list(CONFLICT_CASES.values()), ids=list(CONFLICT_CASES))
def test_a_change_of_the_items_file_on_the_default_branch_holds_the_item(
    handoff_sandbox: HandoffSandbox, path: str, reason: str
) -> None:
    """Another clone pushes to ``main`` after the run; the fetch before the push finds a file changed on both sides."""
    sb = handoff_sandbox
    succeeded(sb)
    other = sb.root / "other-session"
    sb.git("clone", "-q", str(sb.bare), str(other))
    target = other / path
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "a", encoding="utf-8") as handle:
        handle.write("An edit that another session pushed to main.\n")
    sb.git("-C", str(other), "add", "--", path)
    identity = ("-c", "user.name=Other Session", "-c", "user.email=other-session@example.com")
    sb.git("-C", str(other), *identity, "commit", "-q", "-m", "docs: an edit of another session")
    sb.git("-C", str(other), "push", "-q", "origin", "HEAD:refs/heads/main")
    done = publish(sb, write_approval(sb, [CHANGE]))
    if reason == "published":
        assert done.returncode == 0, (done.stdout, done.stderr)
        assert branch_on_remote(sb) is not None
        return
    assert done.returncode == 1, (done.stdout, done.stderr)
    assert f"{CHANGE}: 公開しなかった: {reason}（保留。" in done.stdout
    untouched(sb)
    record = read_status(sb)["items"][CHANGE]
    assert record["state"] == state.SUCCEEDED
    assert record["published"]["hold"]["reason"] == reason
    assert DECLARED in record["published"]["hold"]["detail"]


# ---------------------------------------------------------------------------------------------
# after the push: the SHA on the remote
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("seen", ["another-sha", "no-branch"])
def test_a_branch_on_the_remote_that_is_not_the_local_one_stops_before_the_pull_request(
    handoff_sandbox: HandoffSandbox, seen: str
) -> None:
    """``ls-remote`` after the push prints another SHA, or nothing: no pull request is opened and the item is held."""
    sb = handoff_sandbox
    succeeded(sb)
    printed = "0123456789abcdef0123456789abcdef01234567" if seen == "another-sha" else ""
    done = publish(sb, write_approval(sb, [CHANGE]), FAKE_GIT_LSREMOTE=printed)
    assert done.returncode == 1, (done.stdout, done.stderr)
    assert f"{CHANGE}: 公開しなかった: publish_sha_mismatch（保留。" in done.stdout
    assert len(pushes(sb)) == 1, "the push was made"
    assert gh_calls(sb) == [], "no pull request was opened"
    published = published_of(sb)
    assert published["pr"] is None and published["hold"]["reason"] == "publish_sha_mismatch"
    assert read_status(sb)["items"][CHANGE]["state"] == state.SUCCEEDED


# ---------------------------------------------------------------------------------------------
# an item is published once
# ---------------------------------------------------------------------------------------------


def test_a_published_item_is_not_published_twice(handoff_sandbox: HandoffSandbox) -> None:
    """The same approval, run again, pushes nothing and opens no second pull request."""
    sb = handoff_sandbox
    succeeded(sb)
    approval = write_approval(sb, [CHANGE])
    first = publish(sb, approval)
    assert first.returncode == 0, (first.stdout, first.stderr)
    calls = (len(pushes(sb)), len(gh_calls(sb)))
    again = publish(sb, approval)
    assert again.returncode == 1, (again.stdout, again.stderr)
    assert f"{CHANGE}: 公開しなかった: already_published" in again.stdout
    assert (len(pushes(sb)), len(gh_calls(sb))) == calls == (1, 2)
    assert published_of(sb)["pr"] == PR_NUMBER
