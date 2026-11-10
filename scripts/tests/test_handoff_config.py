"""Tests for ``handoff.config``: the Handoff_Harness configuration is checked, never defaulted.

Task 1.2 of the phase 4 spec, Requirements 28.5, 28.7 and 28.11. The rules under test are
in the docstring of ``scripts/handoff/config.py``.

Every path is synthetic (``/home/example/...``) and every repository name is made up, so
no test depends on the real home directory or on a real repository. The module under
test never touches the file system; only the test of symbolic links creates files, in
``tmp_path``.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import pytest
from handoff import config

HOME = "/home/example"
OWN_MAIN_TREE = "/home/example/Projects/example-this-repo"
SESSION_DIR = "~/Projects/.kiro-worktrees"

#: The design's example (Data Models), with made-up repositories.
VALID: dict[str, Any] = {
    "schema_version": 1,
    "kiro_cli": "~/.local/bin/kiro-cli",
    "timeout_seconds": 1800,
    "max_concurrency": 3,
    "worktrees_root": "~/Projects/.handoff-worktrees",
    "min_free_disk_gb": 50,
    "mode_tool_ceiling": {"query": ["fs_read"], "change": ["fs_read", "fs_write"]},
    "agents": {"query": "handoff-query", "change": "handoff-change"},
    "repos": {
        "example-hub": {"main_tree": "~/Projects/example-hub"},
        "example-spoke": {"main_tree": "/home/example/Projects/example-spoke"},
    },
}

NUMERIC_KEYS = ("timeout_seconds", "max_concurrency", "min_free_disk_gb")


def parse(raw: Any, **arguments: Any) -> config.HandoffConfig:
    """Call ``parse_config`` with the synthetic home, main tree and IDE directory.

    Args:
        raw: The configuration.
        **arguments: Replacements for the keyword arguments.

    Returns:
        The checked configuration.
    """
    keywords: dict[str, Any] = {
        "home": HOME,
        "extra_main_trees": [OWN_MAIN_TREE],
        "session_worktrees_dir": SESSION_DIR,
    }
    keywords.update(arguments)
    return config.parse_config(raw, **keywords)


def rejected(raw: Any, **arguments: Any) -> set[tuple[str, str]]:
    """Return ``(path, kind)`` of every issue, failing the test if nothing is rejected.

    Args:
        raw: The configuration.
        **arguments: Replacements for the keyword arguments.

    Returns:
        The locations and kinds of the issues.
    """
    with pytest.raises(config.ConfigError) as caught:
        parse(raw, **arguments)
    return {(issue.path, issue.kind) for issue in caught.value.issues}


def replaced(keys: tuple[str, ...], value: Any) -> dict[str, Any]:
    """Return a copy of :data:`VALID` with one value set, adding the key if it is new.

    Args:
        keys: The path to the value, from the top level.
        value: The new value.

    Returns:
        The modified copy.
    """
    raw = copy.deepcopy(VALID)
    target = raw
    for key in keys[:-1]:
        target = target[key]
    target[keys[-1]] = value
    return raw


def without(*keys: str) -> dict[str, Any]:
    """Return a copy of :data:`VALID` without some top-level keys.

    Args:
        *keys: The keys to remove.

    Returns:
        The modified copy.
    """
    raw = copy.deepcopy(VALID)
    for key in keys:
        del raw[key]
    return raw


def test_the_design_example_is_accepted() -> None:
    """The values decided on 2026-11-10 pass, with every path normalized."""
    checked = parse(copy.deepcopy(VALID))

    assert checked.schema_version == 1
    assert checked.kiro_cli == "~/.local/bin/kiro-cli"
    assert checked.timeout_seconds == 1800
    assert checked.max_concurrency == 3
    assert checked.worktrees_root == "/home/example/Projects/.handoff-worktrees"
    assert checked.min_free_disk_gb == 50
    assert checked.mode_tool_ceiling == {"query": ("fs_read",), "change": ("fs_read", "fs_write")}
    assert checked.agents == {"query": "handoff-query", "change": "handoff-change"}
    assert checked.repos == {
        "example-hub": config.RepoConfig("/home/example/Projects/example-hub"),
        "example-spoke": config.RepoConfig("/home/example/Projects/example-spoke"),
    }


def test_the_checked_configuration_cannot_be_changed() -> None:
    """The mappings are read-only views, so a later module cannot widen a ceiling by accident."""
    checked = parse(copy.deepcopy(VALID))

    with pytest.raises(TypeError):
        checked.mode_tool_ceiling["query"] = ("fs_read", "fs_write")  # type: ignore[index]


@pytest.mark.parametrize("key", config.LIMIT_KEYS)
def test_each_of_the_four_limit_keys_missing_is_rejected(key: str) -> None:
    """Decision D-14: no default for these keys. The missing key is the only issue."""
    assert rejected(without(key)) == {(key, "missing")}


def test_the_four_limit_keys_missing_together_are_all_reported() -> None:
    """The check does not stop at the first problem."""
    assert rejected(without(*config.LIMIT_KEYS)) == {(key, "missing") for key in config.LIMIT_KEYS}


@pytest.mark.parametrize("key", [key for key in config.REQUIRED_KEYS if key not in config.LIMIT_KEYS])
def test_no_other_key_has_a_default_either(key: str) -> None:
    """Every key is required, not only the four of D-14."""
    assert rejected(without(key)) == {(key, "missing")}


@pytest.mark.parametrize("value", [0, -1], ids=["zero", "negative"])
@pytest.mark.parametrize("key", NUMERIC_KEYS)
def test_zero_and_negative_values_are_rejected(key: str, value: int) -> None:
    """The three numbers are 1 or more; ``min_free_disk_gb`` included."""
    assert rejected(replaced((key,), value)) == {(key, "range")}


@pytest.mark.parametrize(
    "value",
    [True, False, 1800.0, 1.5, "1800", None, [1800]],
    ids=["true", "false", "integral-float", "float", "string", "null", "list"],
)
@pytest.mark.parametrize("key", NUMERIC_KEYS)
def test_values_that_are_not_integers_are_rejected(key: str, value: Any) -> None:
    """``bool`` is a subclass of ``int`` and is still rejected, as is ``1800.0``."""
    assert rejected(replaced((key,), value)) == {(key, "type")}


@pytest.mark.parametrize("key", NUMERIC_KEYS)
def test_one_is_the_smallest_accepted_value(key: str) -> None:
    """The lower bound is inclusive."""
    assert getattr(parse(replaced((key,), 1)), key) == 1


def test_min_free_disk_gb_is_counted_in_gib() -> None:
    """The unit is 2**30 bytes, the block of ``df -g``, and is applied in one place."""
    assert config.DISK_UNIT_BYTES == 2**30
    assert parse(copy.deepcopy(VALID)).min_free_disk_bytes == 50 * 2**30


@pytest.mark.parametrize(
    ("written", "normalized"),
    [
        pytest.param(
            "~/Projects/.handoff-worktrees/", "/home/example/Projects/.handoff-worktrees", id="trailing-slash"
        ),
        pytest.param(
            "~/Projects/./tmp/../.handoff-worktrees", "/home/example/Projects/.handoff-worktrees", id="dot-and-dot-dot"
        ),
        pytest.param("//srv//handoff-worktrees/", "/srv/handoff-worktrees", id="repeated-slashes"),
        pytest.param(
            "~/Projects/example-hub-worktrees",
            "/home/example/Projects/example-hub-worktrees",
            id="shares-a-prefix-with-a-main-tree",
        ),
        pytest.param(
            "~/Projects/.kiro-worktrees-handoff",
            "/home/example/Projects/.kiro-worktrees-handoff",
            id="shares-a-prefix-with-the-ide-directory",
        ),
    ],
)
def test_worktrees_root_is_normalized_lexically(written: str, normalized: str) -> None:
    """A shared string prefix is not containment: paths are compared by component."""
    assert parse(replaced(("worktrees_root",), written)).worktrees_root == normalized


@pytest.mark.parametrize(
    "written",
    [
        pytest.param("~/Projects/example-hub", id="equals-a-main-tree-in-repos"),
        pytest.param("~/Projects/example-hub/", id="equals-a-main-tree-with-a-trailing-slash"),
        pytest.param("~/Projects/example-hub/.handoff", id="inside-a-main-tree-in-repos"),
        pytest.param("/home/example/Projects/example-spoke/wt", id="inside-a-main-tree-written-absolute"),
        pytest.param("~/Projects/example-this-repo/.private/handoff/wt", id="inside-the-caller-main-tree"),
        pytest.param("~/Projects/.handoff-worktrees/../example-hub/wt", id="inside-a-main-tree-through-dot-dot"),
        pytest.param("~/projects/EXAMPLE-Hub/wt", id="inside-a-main-tree-in-another-case"),
        pytest.param("~/Projects/.kiro-worktrees", id="equals-the-ide-directory"),
        pytest.param("~/Projects/.kiro-worktrees/handoff", id="under-the-ide-directory"),
        pytest.param("~/Projects", id="contains-the-main-trees-and-the-ide-directory"),
        pytest.param("~", id="home"),
        pytest.param("/", id="root"),
    ],
)
def test_worktrees_root_that_overlaps_a_protected_path_is_rejected(written: str) -> None:
    """Equal, inside, or containing: each is an overlap with a main tree or the IDE directory."""
    assert rejected(replaced(("worktrees_root",), written)) == {("worktrees_root", "overlap")}


def test_unicode_normalization_is_ignored_when_comparing() -> None:
    """NFC and NFD spellings of the same name count as the same directory."""
    raw = replaced(("repos", "example-hub", "main_tree"), "~/Projects/caf\u00e9")
    raw["worktrees_root"] = "~/Projects/cafe\u0301/wt"

    assert rejected(raw) == {("worktrees_root", "overlap")}


def test_the_overlap_detail_names_the_protected_path() -> None:
    """The maintainer can tell which tree was hit without rerunning anything."""
    with pytest.raises(config.ConfigError) as caught:
        parse(replaced(("worktrees_root",), "~/Projects/example-hub/wt"))

    assert [str(issue) for issue in caught.value.issues] == [
        "worktrees_root: overlap: is inside the main working tree in repos.example-hub "
        "(/home/example/Projects/example-hub)"
    ]


@pytest.mark.parametrize(
    "written",
    ["", "Projects/.handoff-worktrees", "./wt", "~other/wt", "~other"],
    ids=["empty", "relative", "dot-relative", "tilde-user-path", "tilde-user"],
)
def test_worktrees_root_that_is_not_absolute_after_expansion_is_rejected(written: str) -> None:
    """A relative path could not be compared; ``~user`` would need the user database."""
    assert rejected(replaced(("worktrees_root",), written)) == {("worktrees_root", "format")}


def test_worktrees_root_that_is_not_a_string_is_rejected() -> None:
    """A path is a JSON string."""
    assert rejected(replaced(("worktrees_root",), 42)) == {("worktrees_root", "type")}


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(["fs_read", "fs_write"], {("mode_tool_ceiling.query", "format")}, id="one-tool-too-many"),
        pytest.param(["fs_write"], {("mode_tool_ceiling.query", "format")}, id="another-tool"),
        pytest.param(["fs_read", "fs_read"], {("mode_tool_ceiling.query", "format")}, id="fs-read-twice"),
        pytest.param([], {("mode_tool_ceiling.query", "format")}, id="empty"),
        pytest.param("fs_read", {("mode_tool_ceiling.query", "type")}, id="a-string-not-a-list"),
    ],
)
def test_the_query_ceiling_must_be_exactly_fs_read(value: Any, expected: set[tuple[str, str]]) -> None:
    """The query mode reads and nothing else."""
    assert rejected(replaced(("mode_tool_ceiling", "query"), value)) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param([], {("mode_tool_ceiling.change", "format")}, id="empty"),
        pytest.param(["fs_read", ""], {("mode_tool_ceiling.change[1]", "format")}, id="empty-name"),
        pytest.param(["fs_read", "  "], {("mode_tool_ceiling.change[1]", "format")}, id="blank-name"),
        pytest.param(["fs_read", 3], {("mode_tool_ceiling.change[1]", "type")}, id="a-number"),
        pytest.param("fs_read,fs_write", {("mode_tool_ceiling.change", "type")}, id="a-string-not-a-list"),
    ],
)
def test_the_change_ceiling_must_be_a_non_empty_list_of_names(value: Any, expected: set[tuple[str, str]]) -> None:
    """Only the shape is checked; the tool names are not known yet."""
    assert rejected(replaced(("mode_tool_ceiling", "change"), value)) == expected


def test_the_change_ceiling_accepts_any_tool_name() -> None:
    """A made-up shell tool name passes."""
    checked = parse(replaced(("mode_tool_ceiling", "change"), ["fs_read", "fs_write", "example_shell"]))

    assert checked.mode_tool_ceiling["change"] == ("fs_read", "fs_write", "example_shell")


@pytest.mark.parametrize(
    ("keys", "value", "expected"),
    [
        pytest.param(("schema_version",), 2, {("schema_version", "range")}, id="schema-version-2"),
        pytest.param(("schema_version",), True, {("schema_version", "type")}, id="schema-version-true"),
        pytest.param(("schema_version",), "1", {("schema_version", "type")}, id="schema-version-string"),
        pytest.param(("kiro_cli",), "", {("kiro_cli", "format")}, id="kiro-cli-empty"),
        pytest.param(("kiro_cli",), None, {("kiro_cli", "type")}, id="kiro-cli-null"),
        pytest.param(("mode_tool_ceiling",), ["fs_read"], {("mode_tool_ceiling", "type")}, id="ceiling-not-an-object"),
        pytest.param(
            ("mode_tool_ceiling",),
            {"change": ["fs_read"]},
            {("mode_tool_ceiling.query", "missing")},
            id="ceiling-without-query",
        ),
        pytest.param(
            ("mode_tool_ceiling",),
            {"query": ["fs_read"]},
            {("mode_tool_ceiling.change", "missing")},
            id="ceiling-without-change",
        ),
        pytest.param(
            ("mode_tool_ceiling", "publish"),
            ["fs_read"],
            {("mode_tool_ceiling.publish", "unknown_key")},
            id="ceiling-unknown-mode",
        ),
        pytest.param(("agents",), ["handoff-query"], {("agents", "type")}, id="agents-not-an-object"),
        pytest.param(("agents", "query"), "", {("agents.query", "format")}, id="agent-name-empty"),
        pytest.param(("agents", "query"), None, {("agents.query", "type")}, id="agent-name-null"),
        pytest.param(
            ("agents", "chnage"), "handoff-change", {("agents.chnage", "unknown_key")}, id="agents-misspelt-mode"
        ),
        pytest.param(("repos",), [], {("repos", "type")}, id="repos-not-an-object"),
        pytest.param(
            ("repos", "example-hub"), "~/Projects/example-hub", {("repos.example-hub", "type")}, id="repo-not-an-object"
        ),
        pytest.param(
            ("repos", "example-hub"), {}, {("repos.example-hub.main_tree", "missing")}, id="repo-without-main-tree"
        ),
        pytest.param(
            ("repos", "example-hub", "main_tree"), 7, {("repos.example-hub.main_tree", "type")}, id="main-tree-a-number"
        ),
        pytest.param(
            ("repos", "example-hub", "main_tree"),
            "Projects/example-hub",
            {("repos.example-hub.main_tree", "format")},
            id="main-tree-relative",
        ),
        pytest.param(
            ("repos", "example-hub", "remote"),
            "example/hub",
            {("repos.example-hub.remote", "unknown_key")},
            id="repo-unknown-key",
        ),
        pytest.param(
            ("repos", "example.hub"),
            {"main_tree": 7},
            {('repos["example.hub"].main_tree', "type")},
            id="repo-name-with-a-dot",
        ),
        pytest.param(("timeout_second",), 1800, {("timeout_second", "unknown_key")}, id="unknown-top-level-key"),
    ],
)
def test_the_other_keys_are_checked_for_type_and_shape(
    keys: tuple[str, ...], value: Any, expected: set[tuple[str, str]]
) -> None:
    """Each problem is reported at its own location and nothing else is reported."""
    assert rejected(replaced(keys, value)) == expected


def test_agents_can_be_empty() -> None:
    """A mode without an agent configuration is left out of ``agents``."""
    assert parse(replaced(("agents",), {})).agents == {}


@pytest.mark.parametrize("raw", [[], "config", None], ids=["list", "string", "null"])
def test_a_configuration_that_is_not_an_object_is_rejected(raw: Any) -> None:
    """The whole value is ``$``."""
    assert rejected(raw) == {("$", "type")}


def test_every_problem_is_reported_in_one_error() -> None:
    """Problems in different keys and kinds come back together, one line each."""
    raw = without("max_concurrency")
    raw["timeout_seconds"] = 0
    raw["worktrees_root"] = "~/Projects/.kiro-worktrees/handoff"
    raw["mode_tool_ceiling"]["query"] = ["fs_read", "fs_write"]
    raw["repos"]["example-spoke"]["main_tree"] = "relative"

    with pytest.raises(config.ConfigError) as caught:
        parse(raw)

    assert {(issue.path, issue.kind) for issue in caught.value.issues} == {
        ("max_concurrency", "missing"),
        ("timeout_seconds", "range"),
        ("worktrees_root", "overlap"),
        ("mode_tool_ceiling.query", "format"),
        ("repos.example-spoke.main_tree", "format"),
    }
    assert str(caught.value).splitlines() == [str(issue) for issue in caught.value.issues]
    assert "timeout_seconds: range: must be 1 or more, got 0" in str(caught.value).splitlines()


@pytest.mark.parametrize(
    ("arguments", "named"),
    [
        pytest.param({"home": "home/example"}, "home", id="relative-home"),
        pytest.param({"extra_main_trees": []}, "extra_main_trees", id="no-main-tree"),
        pytest.param({"extra_main_trees": ["Projects/example-this-repo"]}, "extra_main_trees", id="relative-main-tree"),
        pytest.param(
            {"session_worktrees_dir": "Projects/.kiro-worktrees"}, "session_worktrees_dir", id="relative-ide-directory"
        ),
    ],
)
def test_unusable_arguments_are_a_value_error_not_a_config_error(arguments: dict[str, Any], named: str) -> None:
    """A fault of the caller is not reported as a fault of the configuration, and names the argument."""
    with pytest.raises(ValueError, match=named) as caught:
        parse(copy.deepcopy(VALID), **arguments)

    assert not isinstance(caught.value, config.ConfigError)


def test_one_string_for_the_main_trees_is_a_type_error() -> None:
    """Iterating a string would protect one-letter paths instead of the tree."""
    with pytest.raises(TypeError):
        parse(copy.deepcopy(VALID), extra_main_trees=OWN_MAIN_TREE)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("~", "/home/example"),
        ("~/", "/home/example"),
        ("~/a/b/", "/home/example/a/b"),
        ("/a//b/./c/../d", "/a/b/d"),
        ("//a", "/a"),
        ("/../a", "/a"),
        ("/a/~/b", "/a/~/b"),
    ],
)
def test_normalize_path(path: str, expected: str) -> None:
    """``~`` is expanded only at the start; everything else is ``posixpath.normpath``."""
    assert config.normalize_path(path, HOME) == expected


@pytest.mark.parametrize(
    ("path", "parent", "expected"),
    [
        ("/a/b", "/a/b", True),
        ("/a/b/c", "/a/b", True),
        ("/a/b/", "/a/b", True),
        ("/a/bc", "/a/b", False),
        ("/a", "/a/b", False),
        ("/A/b/C", "/a/B", True),
        ("/x", "/", True),
    ],
)
def test_is_within(path: str, parent: str, expected: bool) -> None:
    """Containment by component, ignoring letter case."""
    assert config.is_within(path, parent) is expected


def test_overlaps_is_symmetric() -> None:
    """Either side may be the one inside."""
    assert config.overlaps("/a", "/a/b")
    assert config.overlaps("/a/b", "/a")
    assert not config.overlaps("/a/b", "/a/c")


def test_the_comparison_refuses_a_relative_path() -> None:
    """``~`` must be expanded by ``normalize_path`` before comparing."""
    with pytest.raises(ValueError):
        config.is_within("~/a", "/home/example")


def test_symbolic_links_are_not_followed(tmp_path: Path) -> None:
    """The check is lexical, so a link into a main tree passes here.

    This pins a limit that the I/O layer has to cover: it resolves both paths with
    ``os.path.realpath`` and calls ``overlaps`` again, which does see the overlap.
    """
    main_tree = tmp_path / "main"
    main_tree.mkdir()
    link = tmp_path / "link"
    link.symlink_to(main_tree, target_is_directory=True)

    checked = parse(replaced(("worktrees_root",), str(link / "wt")), extra_main_trees=[str(main_tree)])

    assert checked.worktrees_root == str(link / "wt")
    assert config.overlaps(os.path.realpath(checked.worktrees_root), os.path.realpath(main_tree))
