"""A closed name that is a symbolic link closes its target too (found by a real ``kiro-cli`` run, 2026-11-15)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from handoff import os_boundary as osb  # noqa: E402
from handoff import runner  # noqa: E402

SANDBOX = "/usr/bin/sandbox-exec"
pytestmark = pytest.mark.skipif(not os.path.exists(SANDBOX), reason="needs macOS sandbox-exec")


def _home(tmp_path: Path) -> tuple[str, str]:
    home = tmp_path.resolve() / "home"
    target = tmp_path.resolve() / "synced" / "kiro-prompts"
    (home / ".kiro").mkdir(parents=True)
    target.mkdir(parents=True)
    (home / ".kiro" / "prompts").symlink_to(target)
    return str(home), str(target)


def test_symlink_targets_names_the_target_of_a_closed_link(tmp_path: Path) -> None:
    home, target = _home(tmp_path)
    assert target in runner._symlink_targets(home)


def _touch(profile: str, path: str, tmp_path: Path) -> int:
    sb = tmp_path / "p.sb"
    sb.write_text(profile)
    return subprocess.run([SANDBOX, "-f", str(sb), "/usr/bin/touch", path], capture_output=True, check=False).returncode


def test_the_target_of_a_closed_link_is_not_writable_under_the_profile(tmp_path: Path) -> None:
    home, target = _home(tmp_path)
    main = str(tmp_path.resolve() / "main")
    work = str(tmp_path.resolve() / "work")
    os.makedirs(main)
    os.makedirs(work)
    probe = os.path.join(target, "zz-probe")
    old = osb.build_profile(home=home, main_trees=[main], allow_write=[work])
    assert _touch(old, probe, tmp_path) == 0  # the hole: a rule on the link only
    os.unlink(probe)
    new = osb.build_profile(
        home=home, main_trees=[main], allow_write=[work], symlink_targets=runner._symlink_targets(home)
    )
    assert _touch(new, probe, tmp_path) != 0
    assert not os.path.exists(probe)
