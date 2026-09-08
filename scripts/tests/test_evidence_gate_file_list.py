"""Pin the two ways the evidence gate's file list went quiet.

Local to this repository, deliberately. `test_check_evidence_claims.py` is a copy of a
canonical file shared by every project, and adding to it would diverge that copy as well.
The fixes under test live in `scripts/check_evidence_claims.py`, which has already
diverged from its canonical original; these tests exist so the divergence is pinned
rather than merely described in a comment.

Both failures have the same shape and it is the shape that matters: **an empty file list
read as a clean tree.** The checker enumerated markdown through `git ls-files`. When git
could not run, it printed nothing and exited 128, and the scan then examined zero files
and reported success. When git ran but the document was not yet added, the file was
absent from the list for the same silent reason -- and a document is untracked at exactly
the moment somebody writes a new claim into it.

Delete either fix and its test fails. That was checked by restoring the pre-fix body and
watching two of the three fail, rather than assumed -- a test that still passes with the
fix removed is the failure it was written to stop. The third test is not a test of a fix
but a guard on the widening: `-co` must not drag in ignored trees such as a virtualenv.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

CHECKER = Path(__file__).resolve().parents[1] / "check_evidence_claims.py"


def _load_module() -> ModuleType:
    """Import the checker by path.

    It is a script rather than a package member, so it cannot be imported by name.

    Returns:
        The imported module.
    """
    spec = importlib.util.spec_from_file_location("evidence_checker_file_list", CHECKER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_git_failing_is_not_an_empty_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A directory that is not a repository must fail, not report nothing to check."""
    module = _load_module()
    monkeypatch.setattr(module, "ROOT", tmp_path)  # no .git here
    (tmp_path / "claim.md").write_text("AWS does not support this metric.\n", encoding="utf-8")

    with pytest.raises(SystemExit) as raised:
        module._tracked_markdown()

    assert "git could not list files" in str(raised.value)


def test_a_document_not_yet_added_is_still_scanned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A new file is untracked exactly when a new claim is written into it."""
    import subprocess

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)  # noqa: S603, S607
    (tmp_path / "new.md").write_text("AWS does not support this metric.\n", encoding="utf-8")
    module = _load_module()
    monkeypatch.setattr(module, "ROOT", tmp_path)

    assert "new.md" in module._tracked_markdown()


def test_gitignored_documents_stay_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Widening to untracked files must not drag in ignored trees such as a virtualenv."""
    import subprocess

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)  # noqa: S603, S607
    (tmp_path / ".gitignore").write_text("ignored/\n", encoding="utf-8")
    (tmp_path / "ignored").mkdir()
    (tmp_path / "ignored" / "vendored.md").write_text("AWS does not support this.\n", encoding="utf-8")
    module = _load_module()
    monkeypatch.setattr(module, "ROOT", tmp_path)

    assert module._tracked_markdown() == []
