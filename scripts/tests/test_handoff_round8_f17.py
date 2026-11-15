"""Round 8 (F17): persistence places named by T4-R7-02, nested git control names of T4-R7-03.

The tests that run ``sandbox-exec`` are for macOS and skip elsewhere.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from handoff import os_boundary as osb
from test_handoff_round4_boundary import Tree, git, needs_sandbox_exec
from test_handoff_round5_boundary import commit_as_agent, strict_profile

PERSISTENCE_TARGETS = [
    "Library/Python/3.9/lib/python/site-packages/a.pth",
    ".config/pip/pip.conf",
    ".pip/pip.conf",
    ".condarc",
    ".config/nvim/init.lua",
    ".emacs.d/init.el",
    ".config/helix/config.toml",
    ".claude/settings.json",
    ".codex/config.toml",
    ".gemini/settings.json",
    ".cursor/mcp.json",
    "Library/Application Support/Cursor/User/settings.json",
]


def test_the_profile_names_the_persistence_places() -> None:
    text = osb.build_profile(home="/Users/u", main_trees=["/Users/u/r"])
    for name in (
        "Library/Python",
        ".config/pip",
        ".pip",
        ".config/nvim",
        ".emacs.d",
        ".config/helix",
        ".claude",
        ".codex",
        ".gemini",
        ".cursor",
        "Library/Application Support/Cursor",
    ):
        assert f'(deny file-write* (subpath "/Users/u/{name}"))' in text, name
    assert '(deny file-write* (literal "/Users/u/.condarc"))' in text


@needs_sandbox_exec
@pytest.mark.parametrize("target", PERSISTENCE_TARGETS)
def test_an_agent_cannot_write_the_persistence_places(tmp_path: Path, target: str) -> None:
    tree = Tree(tmp_path)
    path = tree.home / target
    path.parent.mkdir(parents=True, exist_ok=True)
    objects = tree.root / "agent-objects"
    objects.mkdir()
    profile = strict_profile(tree, objects)
    assert tree.sandboxed(profile, f': > "{path}"').returncode != 0
    assert not path.exists()
    # control: the own worktree still takes a write and a commit
    result = commit_as_agent(tree, profile, objects)
    assert result.returncode == 0, result.stderr


def test_the_nested_git_control_rule_names_modules_and_worktrees() -> None:
    text = osb.build_profile(home="/Users/u", main_trees=["/Users/u/r"], allow_write=["/w/run"])
    rule = next(line for line in text.splitlines() if "regex" in line and "hooks" in line)
    assert "modules" in rule and "worktrees" in rule
    assert text.index(rule) < text.index('(allow file-write* (subpath "/w/run"))')


@needs_sandbox_exec
@pytest.mark.parametrize(
    "target",
    [
        ".git/modules/sub/hooks/pre-commit",
        ".git/modules/sub/config",
        ".git/modules/a/b/hooks/x",
        ".git/modules/sub/modules/inner/config",
        ".git/worktrees/w/hooks/x",
        ".git/worktrees/w/config.worktree",
    ],
)
def test_an_unregistered_repository_nested_git_control_is_closed(tmp_path: Path, target: str) -> None:
    tree = Tree(tmp_path)
    other = tree.home / "Projects" / "other"
    other.mkdir(parents=True)
    git(tree.env, "init", "-q", cwd=other)
    path = other / target
    path.parent.mkdir(parents=True, exist_ok=True)
    profile = strict_profile(tree)
    assert tree.sandboxed(profile, f': > "{path}"').returncode != 0
    assert not path.exists()


@needs_sandbox_exec
def test_refs_and_the_own_worktree_stay_open(tmp_path: Path) -> None:
    tree = Tree(tmp_path)
    other = tree.home / "Projects" / "other"
    other.mkdir(parents=True)
    git(tree.env, "init", "-q", cwd=other)
    profile = strict_profile(tree)
    assert tree.sandboxed(profile, f': > "{other}/.git/refs/heads/x"').returncode == 0
    inner = "git init -q inner && printf x > inner/.git/hooks/pre-commit"
    assert tree.sandboxed(profile, inner).returncode == 0
