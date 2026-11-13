"""Tests of the per-repository worktree prerequisites (the pure parts): config, ``child_env`` and the upstream command.

Task 15.3, second stage. A change item of a repository whose gate needs data that git does not
carry (a gitignored ledger) or tools that only the main working tree has (a pinned ``ruff`` in its
``.venv``) gets them from the harness instead of from the agent. This module checks what needs no
file system: the ``repos.<name>.prerequisites`` key of ``config.json``, the ``path_prepend``
argument of ``command.child_env`` and the ``git branch --set-upstream-to`` command of the plan.
The runner's use of them is in ``test_handoff_worktree_prerequisites_integration.py``.

Every path and name is synthetic.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest
from handoff import command, config, manifest

HOME = "/home/example"
OWN_MAIN_TREE = "/home/example/Projects/example-this-repo"
SESSION_DIR = "~/Projects/.kiro-worktrees"
SHA = "a" * 40

RAW: dict[str, Any] = {
    "schema_version": 1,
    "kiro_cli": "~/.local/bin/kiro-cli",
    "timeout_seconds": 60,
    "max_concurrency": 1,
    "worktrees_root": "~/Projects/.handoff-worktrees",
    "min_free_disk_gb": 1,
    "mode_tool_ceiling": {"query": ["fs_read"], "change": ["fs_read", "fs_write"]},
    "agents": {},
    "repos": {
        "example-hub": {
            "main_tree": "~/Projects/example-hub",
            "prerequisites": {"copy_readonly": [".private/ledger"], "path_prepend": [".venv/bin"]},
        },
        "example-spoke": {"main_tree": "~/Projects/example-spoke"},
    },
}


def parse(raw: Any) -> config.HandoffConfig:
    """Parse ``raw`` with the synthetic home and protected trees."""
    return config.parse_config(raw, home=HOME, extra_main_trees=[OWN_MAIN_TREE], session_worktrees_dir=SESSION_DIR)


def with_prerequisites(value: Any) -> dict[str, Any]:
    """A copy of :data:`RAW` whose ``example-hub`` prerequisites are ``value``."""
    raw = copy.deepcopy(RAW)
    raw["repos"]["example-hub"]["prerequisites"] = value
    return raw


def test_prerequisites_are_read_and_a_repository_without_them_has_none() -> None:
    """The two lists are kept as tuples in the given order; the other repository has ``None``."""
    parsed = parse(RAW)
    hub = parsed.repos["example-hub"].prerequisites
    assert hub == config.Prerequisites(copy_readonly=(".private/ledger",), path_prepend=(".venv/bin",))
    assert parsed.repos["example-spoke"].prerequisites is None


def test_each_list_is_optional_inside_prerequisites() -> None:
    """A repository can need only the copy or only the PATH; the other list is empty."""
    only_copy = parse(with_prerequisites({"copy_readonly": ["data"]})).repos["example-hub"].prerequisites
    only_path = parse(with_prerequisites({"path_prepend": ["bin"]})).repos["example-hub"].prerequisites
    assert only_copy == config.Prerequisites(("data",), ())
    assert only_path == config.Prerequisites((), ("bin",))


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param([], {("repos.example-hub.prerequisites", "type")}, id="not-an-object"),
        pytest.param({}, {("repos.example-hub.prerequisites", "format")}, id="names-nothing"),
        pytest.param(
            {"copy_readonly": "data"},
            {("repos.example-hub.prerequisites.copy_readonly", "type")},
            id="a-string-instead-of-a-list",
        ),
        pytest.param(
            {"copy_readonly": ["/etc"]},
            {("repos.example-hub.prerequisites.copy_readonly[0]", "format")},
            id="absolute",
        ),
        pytest.param(
            {"copy_readonly": ["~/data"]},
            {("repos.example-hub.prerequisites.copy_readonly[0]", "format")},
            id="tilde",
        ),
        pytest.param(
            {"path_prepend": ["../bin"]},
            {("repos.example-hub.prerequisites.path_prepend[0]", "format")},
            id="leaves-the-tree",
        ),
        pytest.param(
            {"copy_readonly": ["data/"]},
            {("repos.example-hub.prerequisites.copy_readonly[0]", "format")},
            id="trailing-slash",
        ),
        pytest.param(
            {"copy_readonly": [".git/hooks"]},
            {("repos.example-hub.prerequisites.copy_readonly[0]", "format")},
            id="into-dot-git",
        ),
        pytest.param(
            {"copy_readonly": ["data", "data"]},
            {("repos.example-hub.prerequisites.copy_readonly[1]", "format")},
            id="duplicate",
        ),
        pytest.param(
            {"copy_readonly": ["data", "data/inner"]},
            {("repos.example-hub.prerequisites.copy_readonly[1]", "overlap")},
            id="nested",
        ),
        pytest.param(
            {"copy_readonly": [""]},
            {("repos.example-hub.prerequisites.copy_readonly[0]", "format")},
            id="empty",
        ),
        pytest.param(
            {"copy": ["data"]},
            {("repos.example-hub.prerequisites.copy", "unknown_key")},
            id="unknown-key",
        ),
    ],
)
def test_malformed_prerequisites_are_rejected_at_their_own_location(value: Any, expected: set[tuple[str, str]]) -> None:
    """Fail closed: a prerequisite that cannot be trusted stops the configuration, it is not skipped."""
    with pytest.raises(config.ConfigError) as caught:
        parse(with_prerequisites(value))
    assert {(issue.path, issue.kind) for issue in caught.value.issues} == expected


def paths(root: str) -> dict[str, str]:
    """Three separate synthetic paths for ``child_env``."""
    return {
        "push_url": f"{root}/push",
        "gh_config_dir": f"{root}/gh",
        "aws_empty_file": f"{root}/aws",
    }


def test_child_env_puts_the_prepended_directories_first_and_keeps_the_rest() -> None:
    """``PATH`` becomes ``<dirs, in order>:<parent PATH>``; nothing else about the environment changes."""
    parent = {"PATH": "/usr/bin:/bin", "HOME": "/home/example"}
    plain = command.child_env(parent, **paths("/tmp/x"))
    layered = command.child_env(parent, **paths("/tmp/x"), path_prepend=("/opt/a/bin", "/opt/b/bin"))
    assert layered["PATH"] == "/opt/a/bin:/opt/b/bin:/usr/bin:/bin"
    assert {key: value for key, value in layered.items() if key != "PATH"} == {
        key: value for key, value in plain.items() if key != "PATH"
    }
    assert plain["PATH"] == "/usr/bin:/bin"


def test_child_env_without_a_parent_path_sets_only_the_prepended_directories() -> None:
    """An empty ``PATH`` entry would mean the current directory, so none is added."""
    layered = command.child_env({}, **paths("/tmp/x"), path_prepend=("/opt/a/bin",))
    assert layered["PATH"] == "/opt/a/bin"


@pytest.mark.parametrize("bad", ["relative/bin", "/opt/a/../bin", "/opt/a:/opt/b", ""])
def test_child_env_refuses_a_prepended_directory_that_is_not_one_normal_absolute_path(bad: str) -> None:
    """A colon would add a second entry; a relative path would depend on the working directory."""
    with pytest.raises(ValueError, match="path_prepend"):
        command.child_env({"PATH": "/bin"}, **paths("/tmp/x"), path_prepend=(bad,))


def change_item(item_id: str = "b-example", mode: str = "change") -> manifest.Item:
    """A change item (or, with ``mode="query"``, a query item), built through the manifest checker."""
    query = mode == "query"
    raw = {
        "id": item_id,
        "repo": "example-hub",
        "sync_point": "a" if query else "b",
        "mode": mode,
        "template": "templates/query.md" if query else "templates/change.md",
        "vars": {},
        "depends_on": [],
        "requires_refs": [],
        "trust_tools": ["fs_read"] if query else ["fs_read", "fs_write"],
        "trust_all": None,
        "declared_files": [] if query else ["docs/guide.md"],
        "verify_commands": [],
        "batch": None,
        "gates": [],
        "knowledge_kinds": ["records under .private/"] if query else [],
        "read_paths": [],
        "artifact_paths": [],
    }
    return manifest.parse_manifest({"schema_version": 1, "items": [raw]}, config=parse(RAW)).by_id[item_id]


def test_the_upstream_command_names_origin_main_and_the_items_branch() -> None:
    """The branch follows ``origin/main`` so that ``git branch -d`` sees the merge and a bare push is refused."""
    plan = command.build_git_plan(parse(RAW), change_item())
    step = plan.set_upstream()
    assert step.argv == (
        "git",
        "-C",
        plan.main_tree,
        "branch",
        "--set-upstream-to=origin/main",
        "handoff/b-example",
    )
    assert step.cwd == plan.main_tree
    assert not set(step.argv) & command.FORBIDDEN_GIT_WORDS


def test_a_query_item_has_no_upstream_to_set() -> None:
    """Its worktree is detached, so there is no branch."""
    plan = command.build_git_plan(parse(RAW), change_item("a-example", mode="query"))
    with pytest.raises(command.CommandError):
        plan.set_upstream()
    with pytest.raises(command.CommandError):
        plan.delete_branch_at(SHA)


def test_the_branch_is_deleted_with_update_ref_at_the_recorded_sha() -> None:
    """``update-ref -d <ref> <old>`` refuses a branch that moved; neither ``branch -d`` nor ``-D`` is built."""
    plan = command.build_git_plan(parse(RAW), change_item())
    step = plan.delete_branch_at(SHA)
    assert step.argv == ("git", "-C", plan.main_tree, "update-ref", "-d", "refs/heads/handoff/b-example", SHA)
    assert not set(step.argv) & command.FORBIDDEN_GIT_WORDS
    assert "-D" not in step.argv and "branch" not in step.argv


@pytest.mark.parametrize("bad", ["", "abc123", "A" * 40, "a" * 39, "refs/heads/main"])
def test_a_creation_sha_that_is_not_forty_lowercase_hex_digits_is_refused(bad: str) -> None:
    """An abbreviation or a ref name would make the check against the branch tip meaningless."""
    plan = command.build_git_plan(parse(RAW), change_item())
    with pytest.raises(command.CommandError):
        plan.delete_branch_at(bad)
