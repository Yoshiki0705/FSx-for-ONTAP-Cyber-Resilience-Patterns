"""Check that llms.txt and AGENTS.md link to existing supply-chain files.

Links are extracted at run time from the two files, so the test does not pin a
fixed list. It fails when no supply-chain link is found or a target is missing.

**Validates: Requirements 21.4**
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
INDEX_FILES = ("llms.txt", "AGENTS.md")
LINK_RE = re.compile(r"\]\(([^)\s#]+)(?:#[^)\s]*)?\)")


def supply_chain_links(text: str) -> list[str]:
    """Return relative Markdown link targets that mention supply-chain."""
    return [target for target in LINK_RE.findall(text) if "supply-chain" in target and "://" not in target]


@pytest.mark.parametrize("name", INDEX_FILES)
def test_supply_chain_links_exist(name: str) -> None:
    """Every supply-chain link in the file resolves to an existing path."""
    text = (REPO_ROOT / name).read_text(encoding="utf-8")
    links = supply_chain_links(text)
    assert links, f"{name} has no supply-chain relative link"
    missing = [t for t in links if not (REPO_ROOT / t).exists()]
    assert not missing, f"{name} links to missing paths: {missing}"


@pytest.mark.parametrize("name", INDEX_FILES)
def test_links_cover_policy_and_both_guides(name: str) -> None:
    """The links include the policy file and the JA and EN guides."""
    text = (REPO_ROOT / name).read_text(encoding="utf-8")
    links = supply_chain_links(text)
    assert any(t.endswith("supply-chain-policy.json") for t in links)
    assert any(t.startswith("docs/ja/") and t.endswith("adoption-guide.md") for t in links)
    assert any(t.startswith("docs/en/") and t.endswith("adoption-guide.md") for t in links)
