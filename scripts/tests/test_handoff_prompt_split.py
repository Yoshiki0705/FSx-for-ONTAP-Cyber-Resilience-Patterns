"""Prompt paths of items that share a Sync_Point and a repository (task 15.3c).

An extension of Property 25 for ``command.prompt_is_split`` and the ``split`` argument of
``command.handoff_files``; it adds no numbered property.
"""

from __future__ import annotations

from collections import Counter
from types import SimpleNamespace

from handoff import command
from hypothesis import event, given, settings
from hypothesis import strategies as st

HANDOFF_DIR = "/home/example/repo/.private/handoff"
SYNC_POINTS = ("a", "b", "c", "rollout")
REPOS = ("hub", "Hub", "spoke", "my-repo.v2")


def legacy(repo: str, sync_point: str) -> str:
    """The prompt path before the change, which a lone item keeps."""
    return f"{HANDOFF_DIR}/{repo}.md" if sync_point == "rollout" else f"{HANDOFF_DIR}/sync/{sync_point}-{repo}.md"


@st.composite
def item_lists(draw: st.DrawFn) -> list[SimpleNamespace]:
    """Items with unique IDs; repository names may differ in letter case only."""
    pairs = draw(st.lists(st.tuples(st.sampled_from(SYNC_POINTS), st.sampled_from(REPOS)), min_size=1, max_size=8))
    return [SimpleNamespace(id=f"item-{n}", sync_point=sp, repo=repo) for n, (sp, repo) in enumerate(pairs)]


# Feature: cyber-resilience-phase4-supply-chain, Property 25 (extension): prompt paths of a pair carry the item ID
@settings(max_examples=200, deadline=None)
@given(item_lists())
def test_lone_items_keep_the_legacy_path_and_pairs_get_distinct_ones(items: list[SimpleNamespace]) -> None:
    """A group of one keeps ``<sync>-<repo>.md``; a group of two or more gets distinct paths with the ID.

    **Validates: Requirements 23.4, 28.22**
    """
    sizes = Counter((i.sync_point, i.repo.casefold()) for i in items)
    paths: dict[str, list[str]] = {}
    for item in items:
        split = command.prompt_is_split(items, item)
        group = sizes[(item.sync_point, item.repo.casefold())]
        assert split == (group > 1)
        prompt = command.handoff_files(
            HANDOFF_DIR, repo=item.repo, item_id=item.id, sync_point=item.sync_point, split=split
        ).prompt
        if group == 1:
            event("lone item")
            assert prompt == legacy(item.repo, item.sync_point)
        else:
            event("item of a group")
            assert prompt != legacy(item.repo, item.sync_point) and item.id in prompt
            paths.setdefault(f"{item.sync_point}/{item.repo.casefold()}", []).append(prompt.casefold())
    for group_paths in paths.values():
        assert len(set(group_paths)) == len(group_paths)


def test_split_paths_for_both_kinds_of_sync_point() -> None:
    """The ID goes between the repository and ``.md`` in ``sync/`` and in the rollout directory."""
    sync = command.handoff_files(HANDOFF_DIR, repo="hub", item_id="x-1", sync_point="a", split=True)
    rollout = command.handoff_files(HANDOFF_DIR, repo="hub", item_id="x-1", sync_point="rollout", split=True)
    assert sync.prompt == f"{HANDOFF_DIR}/sync/a-hub-x-1.md"
    assert rollout.prompt == f"{HANDOFF_DIR}/hub-x-1.md"
    assert sync.report == rollout.report and sync.status == rollout.status
