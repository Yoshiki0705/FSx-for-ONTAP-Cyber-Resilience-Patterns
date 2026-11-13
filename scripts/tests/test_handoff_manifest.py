"""Tests for ``handoff.manifest``: Handoff items are checked against the configuration.

Task 1.4 of the phase 4 spec, Requirements 23.2, 28.3, 28.4, 28.7, 28.12 and 28.14. The
rules under test are in the docstrings of ``scripts/handoff/manifest.py``. These are
examples at the edge of each check: one input that passes and one or more that each check
must reject. Property 22 (task 1.12) and the generator ``manifests()`` (task 1.11) are
separate tasks.

Every repository name, item ID, path and command argument is made up.
"""

from __future__ import annotations

import copy
import dataclasses
from typing import Any

import pytest
from handoff import config, manifest
from handoff.executor import Executor, choose

CONFIG = config.parse_config(
    {
        "schema_version": 1,
        "kiro_cli": "~/.local/bin/kiro-cli",
        "timeout_seconds": 1800,
        "max_concurrency": 3,
        "worktrees_root": "~/Projects/.handoff-worktrees",
        "min_free_disk_gb": 50,
        "mode_tool_ceiling": {"query": ["fs_read"], "change": ["fs_read", "fs_write", "example_shell"]},
        "agents": {},
        "repos": {
            "example-hub": {"main_tree": "~/Projects/example-hub"},
            "example-spoke": {"main_tree": "~/Projects/example-spoke"},
        },
    },
    home="/home/example",
    extra_main_trees=["/home/example/Projects/example-this-repo"],
    session_worktrees_dir="~/Projects/.kiro-worktrees",
)

SHA = "0123456789abcdef0123456789abcdef01234567"

#: The issue of a ref name that does not fit its kind.
NAME_FORMAT = {("items[1].requires_refs[0].name", "format")}

#: A Sync_Point (a) query: row 4 of the executor table, and its prompt in this repository (row 6).
QUERY: dict[str, Any] = {
    "id": "a-example-hub",
    "repo": "example-hub",
    "sync_point": "a",
    "mode": "query",
    "template": "templates/query.md",
    "vars": {"questions": ["q1"]},
    "depends_on": [],
    "requires_refs": [],
    "trust_tools": ["fs_read"],
    "trust_all": None,
    "declared_files": [],
    "verify_commands": [],
    "batch": None,
    "gates": [],
    "knowledge_kinds": [".private/ records", "memory"],
    "read_paths": [],
    "artifact_paths": [".private/handoff/sync/a-example-hub.md"],
}

#: A Sync_Point (c) change to the Hub: rows 1 and 2.
HUB: dict[str, Any] = {
    "id": "c-example-hub-preset",
    "repo": "example-hub",
    "sync_point": "c",
    "mode": "change",
    "template": "templates/hub-supply-chain.md",
    "vars": {},
    "depends_on": [],
    "requires_refs": [],
    "trust_tools": ["fs_read", "fs_write"],
    "trust_all": None,
    "declared_files": ["renovate/supply-chain.json"],
    "verify_commands": [{"cmd": ["make", "all"], "offline": True}],
    "batch": "pilot",
    "gates": ["AGENTS.md"],
    "knowledge_kinds": [],
    "read_paths": [],
    "artifact_paths": [],
}

#: A rollout change to a Spoke that waits for the Hub item and two of its refs.
SPOKE: dict[str, Any] = {
    "id": "rollout-example-spoke",
    "repo": "example-spoke",
    "sync_point": "rollout",
    "mode": "change",
    "template": "templates/spoke-supply-chain.md",
    "vars": {},
    "depends_on": ["c-example-hub-preset"],
    "requires_refs": [
        {"repo": "example-hub", "kind": "tag", "name": "example-preset-v1.0.0"},
        {"repo": "example-hub", "kind": "sha", "name": SHA},
    ],
    "trust_tools": ["fs_read", "fs_write", "example_shell"],
    "trust_all": None,
    "declared_files": ["renovate.json", ".github/workflows/supply-chain.yml"],
    "verify_commands": [{"cmd": ["make", "test"], "offline": True}, {"cmd": ["make", "deploy"], "offline": False}],
    "batch": "batch-1",
    "gates": [],
    "knowledge_kinds": [],
    "read_paths": [],
    "artifact_paths": [],
}

TRUST_ALL = {
    "reason": "the item runs a generator that asks for every tool",
    "approved_at": "2026-11-10T00:00:00Z",
    "approved_in": ".private/tasks/phase4/example-approval.md",
}


def manifest_of(*items: dict[str, Any]) -> dict[str, Any]:
    """Return a manifest with copies of the given items.

    Args:
        *items: The items, in order.

    Returns:
        The decoded form of ``manifest.json``.
    """
    return {"schema_version": 1, "items": [copy.deepcopy(item) for item in items]}


def with_item(base: dict[str, Any], **changes: Any) -> dict[str, Any]:
    """Return a copy of an item with some keys set, adding a key if it is new.

    Args:
        base: The item to copy.
        **changes: The keys to set.

    Returns:
        The modified copy.
    """
    item = copy.deepcopy(base)
    item.update(copy.deepcopy(changes))
    return item


def parse(raw: Any) -> manifest.Manifest:
    """Check a manifest against the synthetic configuration.

    Args:
        raw: The manifest.

    Returns:
        The checked manifest.
    """
    return manifest.parse_manifest(raw, config=CONFIG)


def rejected(raw: Any) -> set[tuple[str, str]]:
    """Return ``(path, kind)`` of every issue, failing the test if nothing is rejected.

    Args:
        raw: The manifest.

    Returns:
        The locations and kinds of the issues.
    """
    with pytest.raises(manifest.ManifestError) as caught:
        parse(raw)
    return {(issue.path, issue.kind) for issue in caught.value.issues}


def test_the_example_manifest_is_accepted() -> None:
    """A query, a Hub change and a Spoke change that waits for the Hub pass, in manifest order."""
    checked = parse(manifest_of(QUERY, HUB, SPOKE))

    assert checked.schema_version == 1
    assert [item.id for item in checked.items] == ["a-example-hub", "c-example-hub-preset", "rollout-example-spoke"]
    spoke = checked.by_id["rollout-example-spoke"]
    assert spoke.depends_on == ("c-example-hub-preset",)
    assert spoke.requires_refs == (
        manifest.RequiredRef("example-hub", "tag", "example-preset-v1.0.0"),
        manifest.RequiredRef("example-hub", "sha", SHA),
    )
    assert spoke.verify_commands == (
        manifest.VerifyCommand(("make", "test"), True),
        manifest.VerifyCommand(("make", "deploy"), False),
    )
    assert (spoke.trust_tools, spoke.trust_all, spoke.batch) == (
        ("fs_read", "fs_write", "example_shell"),
        None,
        "batch-1",
    )
    assert checked.by_id["a-example-hub"].vars == {"questions": ("q1",)}


def test_an_empty_manifest_is_accepted() -> None:
    """Task 2.5 starts with no items."""
    assert parse({"schema_version": 1, "items": []}).items == ()


def test_the_checked_items_cannot_be_changed() -> None:
    """Items are frozen, ``vars`` is read-only at every depth, and the input stays separate."""
    raw = manifest_of(QUERY)
    item = parse(raw).items[0]

    with pytest.raises(dataclasses.FrozenInstanceError):
        item.mode = "change"  # type: ignore[misc]
    with pytest.raises(TypeError):
        item.vars["questions"] = ()  # type: ignore[index]
    raw["items"][0]["vars"]["questions"].append("q2")
    assert item.vars["questions"] == ("q1",)


def test_the_executor_rows_come_from_the_item_fields() -> None:
    """Row 1 from declared files, row 2 from gates and verification commands, rows 4 and 6 as named."""
    checked = parse(manifest_of(QUERY, HUB, SPOKE))

    query = choose(checked.by_id["a-example-hub"].executor_attrs(uncommitted_count=0))
    hub = choose(checked.by_id["c-example-hub-preset"].executor_attrs(uncommitted_count=0))
    spoke = choose(checked.by_id["rollout-example-spoke"].executor_attrs(uncommitted_count=0))

    assert query.executor is Executor.TARGET_REPO_KIRO
    assert [(reason.number, reason.details) for reason in query.reasons] == [
        (4, (".private/ records", "memory")),
        (6, (".private/handoff/sync/a-example-hub.md",)),
    ]
    assert hub.executor is Executor.TARGET_REPO_KIRO
    assert [(reason.number, reason.details) for reason in hub.reasons] == [
        (1, ("renovate/supply-chain.json",)),
        (2, ("AGENTS.md", "make all")),
    ]
    assert spoke.executor is Executor.TARGET_REPO_KIRO
    assert spoke.rows == (1, 2)
    assert spoke.reasons[1].details == ("make deploy", "make test")


def test_the_observed_uncommitted_count_adds_row_3() -> None:
    """The check passes 0; a caller passes what it observed, and row 3 appears."""
    hub = parse(manifest_of(HUB)).items[0]

    assert choose(hub.executor_attrs(uncommitted_count=2)).rows == (1, 2, 3)


def test_a_verification_command_is_written_as_it_would_be_typed() -> None:
    """``shlex.join`` quotes an element that needs it."""
    hub = with_item(HUB, verify_commands=[{"cmd": ["make", "test", "ARGS=a b"], "offline": True}])

    reasons = choose(parse(manifest_of(hub)).items[0].executor_attrs(uncommitted_count=0)).reasons

    assert reasons[1].details == ("AGENTS.md", "make test 'ARGS=a b'")


def test_a_query_item_that_only_reads_committed_paths_goes_to_this_session() -> None:
    """Rows 5 and 6 alone name this session. The design rejects only items with no row."""
    item = with_item(QUERY, knowledge_kinds=[], artifact_paths=[], read_paths=["AGENTS.md"])

    choice = choose(parse(manifest_of(item)).items[0].executor_attrs(uncommitted_count=0))

    assert (choice.executor, choice.rows) == (Executor.THIS_SESSION, (5,))


def test_an_item_to_which_no_row_applies_is_rejected() -> None:
    """Property 29: ``executor.choose`` refuses it, and so does the manifest check."""
    item = with_item(QUERY, knowledge_kinds=[], artifact_paths=[])

    assert rejected(manifest_of(item)) == {("items[0]", "executor")}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param([], {("$", "type")}, id="a-list"),
        pytest.param(None, {("$", "type")}, id="null"),
        pytest.param({"items": []}, {("schema_version", "missing")}, id="no-schema-version"),
        pytest.param({"schema_version": 1}, {("items", "missing")}, id="no-items"),
        pytest.param({"schema_version": 2, "items": []}, {("schema_version", "range")}, id="schema-version-2"),
        pytest.param({"schema_version": True, "items": []}, {("schema_version", "type")}, id="schema-version-true"),
        pytest.param({"schema_version": 1, "items": {}}, {("items", "type")}, id="items-not-an-array"),
        pytest.param({"schema_version": 1, "items": [], "item": []}, {("item", "unknown_key")}, id="unknown-key"),
        pytest.param({"schema_version": 1, "items": ["c-hub"]}, {("items[0]", "type")}, id="item-not-an-object"),
    ],
)
def test_the_top_level_shape(raw: Any, expected: set[tuple[str, str]]) -> None:
    """``{"schema_version": 1, "items": [...]}`` and nothing else."""
    assert rejected(raw) == expected


@pytest.mark.parametrize("key", manifest.ITEM_KEYS)
def test_every_item_key_is_required(key: str) -> None:
    """No key has a default, the four added for the executor table included."""
    item = copy.deepcopy(HUB)
    del item[key]

    assert rejected(manifest_of(item)) == {(f"items[0].{key}", "missing")}


def test_an_unknown_item_key_is_rejected() -> None:
    """A misspelt key would otherwise be ignored."""
    assert rejected(manifest_of(with_item(HUB, trust_tool=["fs_read"]))) == {("items[0].trust_tool", "unknown_key")}


@pytest.mark.parametrize(
    "item_id",
    ["C-hub", "c_hub", "c/hub", "c.hub", "c,hub", "c hub", "-c", "c-", "c--hub", "", "a" * 65],
    ids=[
        "upper-case",
        "underscore",
        "slash",
        "dot",
        "comma",
        "space",
        "leading-hyphen",
        "trailing-hyphen",
        "double-hyphen",
        "empty",
        "65-characters",
    ],
)
def test_an_id_outside_the_form_is_rejected(item_id: str) -> None:
    """An ID names a directory, a branch ``handoff/<id>`` and an entry of ``--items``."""
    assert rejected(manifest_of(with_item(HUB, id=item_id))) == {("items[0].id", "format")}


@pytest.mark.parametrize("item_id", ["a" * 64, "1", "b-2-c"], ids=["64-characters", "a-digit", "groups"])
def test_an_id_in_the_form_is_accepted(item_id: str) -> None:
    """The upper bound is inclusive, and digits may start an ID."""
    assert parse(manifest_of(with_item(HUB, id=item_id))).items[0].id == item_id


def test_an_id_that_is_not_a_string_is_rejected() -> None:
    """A number is not an ID."""
    assert rejected(manifest_of(with_item(HUB, id=7))) == {("items[0].id", "type")}


def test_a_repeated_id_is_reported_at_its_second_item() -> None:
    """IDs are unique in the manifest."""
    assert rejected(manifest_of(HUB, with_item(QUERY, id=HUB["id"]))) == {("items[1].id", "duplicate")}


@pytest.mark.parametrize(
    ("repo", "kind"),
    [
        pytest.param("example-other", "unknown_reference", id="not-in-the-configuration"),
        pytest.param("example/hub", "format", id="two-components"),
        pytest.param("..", "format", id="dot-dot"),
        pytest.param(".", "format", id="dot"),
        pytest.param("", "format", id="empty"),
        pytest.param(7, "type", id="a-number"),
    ],
)
def test_the_repo_is_a_configured_path_component(repo: Any, kind: str) -> None:
    """``<worktrees_root>/<repo>/<id>`` must stay one level below the root."""
    assert rejected(manifest_of(with_item(HUB, repo=repo))) == {("items[0].repo", kind)}


@pytest.mark.parametrize("sync_point", manifest.SYNC_POINTS)
def test_each_sync_point_is_accepted(sync_point: str) -> None:
    """``a`` to ``e`` and ``rollout``."""
    assert parse(manifest_of(with_item(HUB, sync_point=sync_point))).items[0].sync_point == sync_point


@pytest.mark.parametrize(
    ("key", "value", "kind"),
    [
        pytest.param("sync_point", "f", "format", id="sync-point-f"),
        pytest.param("sync_point", "A", "format", id="sync-point-upper-case"),
        pytest.param("sync_point", "", "format", id="sync-point-empty"),
        pytest.param("sync_point", None, "type", id="sync-point-null"),
        pytest.param("mode", "publish", "format", id="mode-publish"),
        pytest.param("mode", "Change", "format", id="mode-upper-case"),
        pytest.param("mode", None, "type", id="mode-null"),
    ],
)
def test_sync_point_and_mode_take_listed_values(key: str, value: Any, kind: str) -> None:
    """The publish mode has no items; it is a separate run."""
    assert rejected(manifest_of(with_item(HUB, **{key: value}))) == {(f"items[0].{key}", kind)}


BAD_PATHS = [
    pytest.param("/srv/templates/x.md", id="absolute"),
    pytest.param("~/x.md", id="tilde"),
    pytest.param("../x.md", id="leading-dot-dot"),
    pytest.param("templates/../../x.md", id="inner-dot-dot"),
    pytest.param("./x.md", id="leading-dot"),
    pytest.param("templates/./x.md", id="inner-dot"),
    pytest.param("templates//x.md", id="double-slash"),
    pytest.param("templates/", id="trailing-slash"),
    pytest.param("", id="empty"),
    pytest.param("  ", id="blank"),
    pytest.param("x\n.md", id="line-break"),
    pytest.param("x\x00.md", id="nul"),
]


@pytest.mark.parametrize("path", BAD_PATHS)
def test_a_template_path_outside_normal_form_is_rejected(path: str) -> None:
    """Relative, without ``..``, and written the way git prints a path."""
    assert rejected(manifest_of(with_item(HUB, template=path))) == {("items[0].template", "format")}


@pytest.mark.parametrize("key", ["declared_files", "read_paths", "artifact_paths"])
@pytest.mark.parametrize("path", ["../x.md", "/srv/x.md", "docs//x.md"], ids=["dot-dot", "absolute", "double-slash"])
def test_the_path_lists_follow_the_same_rule(key: str, path: str) -> None:
    """Each entry is checked, and reported at its index."""
    item = with_item(HUB, **{key: [*HUB[key], path]})

    assert rejected(manifest_of(item)) == {(f"items[0].{key}[{len(HUB[key])}]", "format")}


@pytest.mark.parametrize(
    ("value", "kind"),
    [([], "type"), ("x", "type"), ({"": "x"}, "format")],
    ids=["a-list", "a-string", "an-empty-key"],
)
def test_vars_is_an_object_with_named_keys(value: Any, kind: str) -> None:
    """The values are left to ``prompt.render``; the keys must name something."""
    assert rejected(manifest_of(with_item(HUB, vars=value))) == {("items[0].vars", kind)}


@pytest.mark.parametrize(
    ("depends_on", "expected"),
    [
        pytest.param(
            ["c-example-hub-preset", "c-example-other"],
            {("items[1].depends_on[1]", "unknown_reference")},
            id="unknown-item",
        ),
        pytest.param(
            ["c-example-hub-preset", "c-example-hub-preset"], {("items[1].depends_on[1]", "duplicate")}, id="repeated"
        ),
        pytest.param([7], {("items[1].depends_on[0]", "type")}, id="a-number"),
        pytest.param("c-example-hub-preset", {("items[1].depends_on", "type")}, id="a-string"),
    ],
)
def test_each_dependency_is_an_item_of_the_manifest(depends_on: Any, expected: set[tuple[str, str]]) -> None:
    """The refs need a valid ``depends_on`` before their ordering is checked, so nothing else is reported."""
    assert rejected(manifest_of(HUB, with_item(SPOKE, depends_on=depends_on))) == expected


def test_an_item_that_depends_on_itself_is_a_cycle() -> None:
    """A cycle of one item."""
    with pytest.raises(manifest.ManifestError) as caught:
        parse(manifest_of(with_item(HUB, depends_on=[HUB["id"]])))

    assert [str(issue) for issue in caught.value.issues] == [
        "items[0].depends_on: cycle: forms a cycle: c-example-hub-preset -> c-example-hub-preset"
    ]


def test_each_cycle_is_reported_once_at_its_first_item() -> None:
    """Two separate cycles give two issues in manifest order; an item that only waits on a cycle is not in one."""
    items = [
        with_item(HUB, id="x-a", depends_on=["x-c"]),
        with_item(HUB, id="x-b", depends_on=["x-a"]),
        with_item(HUB, id="x-c", depends_on=["x-b"]),
        with_item(HUB, id="x-d", depends_on=["x-a"]),
        with_item(HUB, id="y-a", depends_on=["y-b"]),
        with_item(HUB, id="y-b", depends_on=["y-a"]),
    ]

    with pytest.raises(manifest.ManifestError) as caught:
        parse(manifest_of(*items))

    assert [str(issue) for issue in caught.value.issues] == [
        "items[0].depends_on: cycle: forms a cycle: x-a -> x-c -> x-b -> x-a",
        "items[4].depends_on: cycle: forms a cycle: y-a -> y-b -> y-a",
    ]


def test_a_cycle_is_reported_even_when_its_items_have_other_problems() -> None:
    """Other problems do not hide a cycle."""
    items = [
        with_item(HUB, id="x-a", depends_on=["x-b"], template="/srv/x.md"),
        with_item(HUB, id="x-b", depends_on=["x-a"]),
    ]

    assert rejected(manifest_of(*items)) == {("items[0].template", "format"), ("items[0].depends_on", "cycle")}


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        pytest.param(
            {"repo": "example-hub", "kind": "branch", "name": "main"},
            {("items[1].requires_refs[0].kind", "format")},
            id="unknown-kind",
        ),
        pytest.param({"repo": "example-hub", "kind": "sha", "name": SHA.upper()}, NAME_FORMAT, id="sha-upper-case"),
        pytest.param({"repo": "example-hub", "kind": "sha", "name": SHA[:39]}, NAME_FORMAT, id="sha-39-digits"),
        pytest.param({"repo": "example-hub", "kind": "sha", "name": "v1.0.0"}, NAME_FORMAT, id="sha-given-a-tag"),
        pytest.param({"repo": "example-hub", "kind": "tag", "name": "-v1"}, NAME_FORMAT, id="tag-leading-hyphen"),
        pytest.param({"repo": "example-hub", "kind": "tag", "name": "v1..2"}, NAME_FORMAT, id="tag-dot-dot"),
        pytest.param({"repo": "example-hub", "kind": "tag", "name": "v1.lock"}, NAME_FORMAT, id="tag-lock"),
        pytest.param({"repo": "example-hub", "kind": "tag", "name": "a/.b"}, NAME_FORMAT, id="tag-component-dot"),
        pytest.param({"repo": "example-hub", "kind": "tag", "name": "v1/"}, NAME_FORMAT, id="tag-trailing-slash"),
        pytest.param({"repo": "example-hub", "kind": "tag", "name": "v1."}, NAME_FORMAT, id="tag-trailing-dot"),
        pytest.param({"repo": "example-hub", "kind": "tag", "name": "a//b"}, NAME_FORMAT, id="tag-double-slash"),
        pytest.param({"repo": "example-hub", "kind": "tag", "name": "v 1"}, NAME_FORMAT, id="tag-space"),
        pytest.param(
            {"repo": "example-other", "kind": "tag", "name": "v1"},
            {("items[1].requires_refs[0].repo", "unknown_reference")},
            id="unknown-repo",
        ),
        pytest.param(
            {"repo": "example-hub", "kind": "tag"}, {("items[1].requires_refs[0].name", "missing")}, id="no-name"
        ),
        pytest.param(
            {"repo": "example-hub", "kind": "tag", "name": "v1", "ref": "v1"},
            {("items[1].requires_refs[0].ref", "unknown_key")},
            id="unknown-key",
        ),
        pytest.param("example-hub@v1", {("items[1].requires_refs[0]", "type")}, id="not-an-object"),
    ],
)
def test_each_required_ref_is_checked(ref: Any, expected: set[tuple[str, str]]) -> None:
    """A SHA is 40 lowercase hex digits; a tag follows the git rules that concern its characters."""
    item = with_item(SPOKE, requires_refs=[ref])

    assert rejected(manifest_of(HUB, item)) == expected


def test_a_repeated_ref_is_rejected() -> None:
    """Each ref once."""
    ref = SPOKE["requires_refs"][0]

    assert rejected(manifest_of(HUB, with_item(SPOKE, requires_refs=[ref, ref]))) == {
        ("items[1].requires_refs[1]", "duplicate")
    }


def test_a_ref_of_another_repository_needs_a_dependency_on_that_repository() -> None:
    """Requirements 23.5 and 28.12: the Hub item runs first, and the prompt can name it."""
    assert rejected(manifest_of(HUB, with_item(SPOKE, depends_on=[]))) == {
        ("items[1].requires_refs[0]", "ordering"),
        ("items[1].requires_refs[1]", "ordering"),
    }


def test_a_ref_of_the_items_own_repository_needs_no_dependency() -> None:
    """Only a ref of another repository has an item to wait for."""
    item = with_item(HUB, requires_refs=[{"repo": "example-hub", "kind": "tag", "name": "release/v1"}])

    assert parse(manifest_of(item)).items[0].requires_refs == (
        manifest.RequiredRef("example-hub", "tag", "release/v1"),
    )


@pytest.mark.parametrize(
    ("base", "tools", "expected"),
    [
        pytest.param(QUERY, ["fs_read", "fs_write"], {("items[0].trust_tools[1]", "ceiling")}, id="query-and-a-write"),
        pytest.param(QUERY, ["fs_write"], {("items[0].trust_tools[0]", "ceiling")}, id="query-without-fs-read"),
        pytest.param(HUB, ["fs_read", "example_other"], {("items[0].trust_tools[1]", "ceiling")}, id="change-outside"),
        pytest.param(HUB, [], {("items[0].trust_tools", "format")}, id="empty"),
        pytest.param(HUB, ["fs_read", "fs_read"], {("items[0].trust_tools[1]", "duplicate")}, id="repeated"),
        pytest.param(HUB, ["fs_read", 3], {("items[0].trust_tools[1]", "type")}, id="a-number"),
        pytest.param(HUB, "fs_read", {("items[0].trust_tools", "type")}, id="a-string"),
    ],
)
def test_trusted_tools_stay_within_the_ceiling_of_the_mode(
    base: dict[str, Any], tools: Any, expected: set[tuple[str, str]]
) -> None:
    """A query trusts ``fs_read`` only; a change item trusts a non-empty part of its ceiling."""
    assert rejected(manifest_of(with_item(base, trust_tools=tools))) == expected


def test_a_complete_trust_all_is_accepted() -> None:
    """Reason, approval time and approval record."""
    item = parse(manifest_of(with_item(HUB, trust_all=TRUST_ALL))).items[0]

    assert item.trust_all == manifest.TrustAll(**TRUST_ALL)


@pytest.mark.parametrize("key", manifest.TRUST_ALL_KEYS)
def test_trust_all_needs_all_three_parts(key: str) -> None:
    """A partial approval is not an approval."""
    partial = {name: value for name, value in TRUST_ALL.items() if name != key}

    assert rejected(manifest_of(with_item(HUB, trust_all=partial))) == {(f"items[0].trust_all.{key}", "missing")}


@pytest.mark.parametrize(
    ("key", "value"),
    [
        pytest.param("approved_at", "2026-11-10T00:00:00+00:00", id="offset"),
        pytest.param("approved_at", "2026-11-10 00:00:00Z", id="space"),
        pytest.param("approved_at", "2026-11-10T00:00:00.5Z", id="fraction"),
        pytest.param("approved_at", "2026-1-10T00:00:00Z", id="one-digit-month"),
        pytest.param("approved_at", "2026-02-30T00:00:00Z", id="no-such-day"),
        pytest.param("approved_at", "\uff12\uff10\uff12\uff16-11-10T00:00:00Z", id="full-width-digits"),
        pytest.param("reason", " ", id="blank-reason"),
        pytest.param("reason", "first line\nsecond line", id="two-line-reason"),
        pytest.param("approved_in", "/srv/approval.md", id="absolute-record"),
        pytest.param("approved_in", "notes/approval.md", id="record-outside-private"),
        pytest.param("approved_in", ".private", id="the-private-directory-itself"),
        pytest.param("approved_in", ".private/../approval.md", id="record-escaping-private"),
    ],
)
def test_each_part_of_trust_all_has_a_form(key: str, value: str) -> None:
    """The time is written as ``state.format_timestamp`` writes it; the record is a session record."""
    item = with_item(HUB, trust_all={**TRUST_ALL, key: value})

    assert rejected(manifest_of(item)) == {(f"items[0].trust_all.{key}", "format")}


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(True, {("items[0].trust_all", "type")}, id="true"),
        pytest.param(
            {},
            {(f"items[0].trust_all.{key}", "missing") for key in manifest.TRUST_ALL_KEYS},
            id="empty-object",
        ),
        pytest.param({**TRUST_ALL, "scope": "all"}, {("items[0].trust_all.scope", "unknown_key")}, id="unknown-key"),
    ],
)
def test_trust_all_is_null_or_the_three_parts(value: Any, expected: set[tuple[str, str]]) -> None:
    """Anything else is rejected."""
    assert rejected(manifest_of(with_item(HUB, trust_all=value))) == expected


@pytest.mark.parametrize(
    ("key", "value"),
    [
        pytest.param("trust_all", TRUST_ALL, id="trust-all"),
        pytest.param("declared_files", ["README.md"], id="declared-files"),
        pytest.param("verify_commands", [{"cmd": ["make", "all"], "offline": True}], id="verify-commands"),
        pytest.param("requires_refs", [{"repo": "example-hub", "kind": "tag", "name": "v1"}], id="requires-refs"),
    ],
)
def test_a_query_item_writes_nothing_and_trusts_nothing_more(key: str, value: Any) -> None:
    """Sections 3, 4, 7 and 8 of a query prompt do not apply, and the query mode trusts ``fs_read`` only."""
    assert rejected(manifest_of(with_item(QUERY, **{key: value}))) == {(f"items[0].{key}", "mode")}


def test_a_change_item_declares_at_least_one_file() -> None:
    """The result check compares the changed files with the declared ones."""
    assert rejected(manifest_of(with_item(HUB, declared_files=[]))) == {("items[0].declared_files", "mode")}


@pytest.mark.parametrize(
    ("commands", "expected"),
    [
        pytest.param(["make all"], {("items[0].verify_commands[0]", "type")}, id="a-string-entry"),
        pytest.param(
            [{"cmd": "make all", "offline": True}], {("items[0].verify_commands[0].cmd", "type")}, id="a-shell-string"
        ),
        pytest.param([{"cmd": [], "offline": True}], {("items[0].verify_commands[0].cmd", "format")}, id="empty-argv"),
        pytest.param(
            [{"cmd": ["make", ""], "offline": True}],
            {("items[0].verify_commands[0].cmd[1]", "format")},
            id="empty-element",
        ),
        pytest.param(
            [{"cmd": ["make", "a\nb"], "offline": True}],
            {("items[0].verify_commands[0].cmd[1]", "format")},
            id="line-break",
        ),
        pytest.param(
            [{"cmd": ["make", 1], "offline": True}], {("items[0].verify_commands[0].cmd[1]", "type")}, id="a-number"
        ),
        pytest.param([{"cmd": ["make", "all"]}], {("items[0].verify_commands[0].offline", "missing")}, id="no-offline"),
        pytest.param(
            [{"cmd": ["make", "all"], "offline": 1}], {("items[0].verify_commands[0].offline", "type")}, id="offline-1"
        ),
        pytest.param(
            [{"cmd": ["make", "all"], "offline": "true"}],
            {("items[0].verify_commands[0].offline", "type")},
            id="offline-string",
        ),
        pytest.param(
            [{"cmd": ["make", "all"], "offline": None}],
            {("items[0].verify_commands[0].offline", "type")},
            id="offline-null",
        ),
        pytest.param(
            [{"cmd": ["make", "all"], "offline": True, "timeout": 60}],
            {("items[0].verify_commands[0].timeout", "unknown_key")},
            id="unknown-key",
        ),
        pytest.param(
            [{"cmd": ["make", "all"], "offline": True}, {"cmd": ["make", "all"], "offline": False}],
            {("items[0].verify_commands[1]", "duplicate")},
            id="repeated-argv",
        ),
    ],
)
def test_each_verification_command_is_an_argv_with_a_boolean_offline(
    commands: Any, expected: set[tuple[str, str]]
) -> None:
    """The argv runs with ``shell=False``; ``offline`` is a JSON boolean, not 1 or a string."""
    assert rejected(manifest_of(with_item(HUB, verify_commands=commands))) == expected


@pytest.mark.parametrize(
    ("batch", "kind"),
    [("Batch 1", "format"), ("batch_1", "format"), (1, "type")],
    ids=["upper-case-and-space", "underscore", "a-number"],
)
def test_batch_is_null_or_a_label(batch: Any, kind: str) -> None:
    """A label has the form of an ID."""
    assert rejected(manifest_of(with_item(HUB, batch=batch))) == {("items[0].batch", kind)}


@pytest.mark.parametrize("key", ["gates", "knowledge_kinds"])
@pytest.mark.parametrize(
    ("entry", "kind"),
    [(" ", "format"), ("a\nb", "format"), ("a\u2028b", "format"), (7, "type")],
    ids=["blank", "line-break", "line-separator", "a-number"],
)
def test_reason_entries_are_single_lines(key: str, entry: Any, kind: str) -> None:
    """``prompt.render`` writes one entry per line of the executor section."""
    assert rejected(manifest_of(with_item(HUB, **{key: [entry]}))) == {(f"items[0].{key}[0]", kind)}


@pytest.mark.parametrize("key", ["gates", "knowledge_kinds", "read_paths", "artifact_paths", "declared_files"])
def test_list_entries_are_not_repeated(key: str) -> None:
    """A repeated entry is reported at its second position."""
    item = with_item(HUB, **{key: ["AGENTS.md", "AGENTS.md"]})

    assert rejected(manifest_of(item)) == {(f"items[0].{key}[1]", "duplicate")}


def test_every_problem_is_reported_in_one_error() -> None:
    """Problems of several items and the top level come back together, one line each, in a fixed order."""
    broken_query = with_item(QUERY, trust_tools=["fs_write"], declared_files=["a.md"])
    broken_hub = with_item(HUB, template="../x.md", batch="Pilot")
    del broken_hub["gates"]
    raw = manifest_of(broken_query, broken_hub)
    raw["note"] = "x"

    with pytest.raises(manifest.ManifestError) as caught:
        parse(raw)

    assert [(issue.path, issue.kind) for issue in caught.value.issues] == [
        ("items[0].trust_tools[0]", "ceiling"),
        ("items[0].declared_files", "mode"),
        ("items[1].gates", "missing"),
        ("items[1].template", "format"),
        ("items[1].batch", "format"),
        ("note", "unknown_key"),
    ]
    assert str(caught.value).splitlines() == [str(issue) for issue in caught.value.issues]


def test_a_configuration_that_was_not_checked_is_a_type_error() -> None:
    """The ceiling and the repositories come from a checked configuration only."""
    with pytest.raises(TypeError):
        manifest.parse_manifest(manifest_of(HUB), config={"repos": {}})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("cmd", "expected"),
    [
        pytest.param(["aws"], ("aws ",), id="aws-alone"),
        pytest.param(["aws", "s3", "ls"], ("aws ",), id="aws-with-arguments"),
        pytest.param(["AWS", "sts", "get-caller-identity"], ("aws ",), id="aws-upper-case"),
        pytest.param(["/usr/local/bin/aws", "s3", "ls"], ("aws ",), id="aws-by-path"),
        pytest.param(["bash", "-c", "x=1;aws s3 ls"], ("aws ",), id="aws-in-a-shell-string"),
        pytest.param(["aws-vault", "exec", "dev"], ("aws ",), id="aws-vault"),
        pytest.param(["gh"], ("gh ",), id="gh-alone"),
        pytest.param(["gh", "pr", "create"], ("gh ",), id="gh-with-arguments"),
        pytest.param(["git", "push"], ("git push",), id="git-push"),
        pytest.param(["git", "-C", "wt", "push", "origin"], ("git push",), id="git-option-before-push"),
        pytest.param(["sh", "-c", "git push origin HEAD"], ("git push",), id="git-push-in-a-shell-string"),
        pytest.param(["make", "deploy"], ("deploy",), id="make-deploy"),
        pytest.param(["make", "predeploy-check"], ("deploy",), id="deploy-inside-a-word"),
        pytest.param(
            ["bash", "-c", "aws s3 ls && gh pr list && git push && make deploy"],
            ("aws ", "gh ", "git push", "deploy"),
            id="all-four",
        ),
        pytest.param(["pytest", "-k", "high and low"], ("gh ",), id="accepted-false-positive"),
        pytest.param(["make", "all"], (), id="make-all"),
        pytest.param(["make", "test", "AWS_DEFAULT_REGION=ap-northeast-1"], (), id="aws-in-a-variable-name"),
        pytest.param(["git", "status", "--porcelain"], (), id="git-without-push"),
        pytest.param(["python3", "-m", "pytest", "scripts/tests/"], (), id="pytest"),
    ],
)
def test_rerun_exclusions(cmd: list[str], expected: tuple[str, ...]) -> None:
    """The design's four patterns, matched in the joined text and as words of the argv."""
    assert manifest.rerun_exclusions(cmd) == expected


def test_rerun_exclusions_refuses_a_shell_string() -> None:
    """A string would be read one character at a time and match nothing."""
    with pytest.raises(TypeError):
        manifest.rerun_exclusions("aws s3 ls")


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        pytest.param(manifest.VerifyCommand(("make", "all"), True), None, id="offline-and-clean"),
        pytest.param(manifest.VerifyCommand(("make", "all"), False), "offline: false", id="not-offline"),
        pytest.param(manifest.VerifyCommand(("make", "deploy"), True), "'deploy'", id="offline-but-excluded"),
    ],
)
def test_rerun_skip_reason(command: manifest.VerifyCommand, expected: str | None) -> None:
    """``None`` means re-run; otherwise the reason names the cause."""
    reason = manifest.rerun_skip_reason(command)

    if expected is None:
        assert reason is None
    else:
        assert reason is not None and expected in reason
