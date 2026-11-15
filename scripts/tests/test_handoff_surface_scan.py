"""The scan of an execution-surface diff before the maintainer acknowledges it (task 5.18).

No tool is installed by these tests: ``zizmor`` and ``gitleaks`` are replaced by a fake that returns what the real
ones print, and git runs in a throwaway repository with an empty global configuration. Nothing of the real home,
repository or credentials is read, and no ``kiro-cli`` or ``sandbox-exec`` starts.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import handoff_surface_scan as tool
import pytest
from handoff import cli, surface_scan
from test_handoff_round4_boundary import Tree, git

DIFF = """diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -1,2 +1,4 @@
 name: ci
+on: pull_request_target
+# +++ not a header
 jobs: {}
diff --git a/docs/a.md b/docs/a.md
--- a/docs/a.md
+++ b/docs/a.md
@@ -1 +1,2 @@
 x
+doc line
"""


def test_added_lines_reads_only_the_added_lines_of_the_wanted_paths() -> None:
    found = surface_scan.added_lines(DIFF, [".github/workflows/ci.yml", "scripts/none.sh"])
    assert found == {
        ".github/workflows/ci.yml": ["on: pull_request_target", "# +++ not a header"],
        "scripts/none.sh": [],
    }


def test_workflow_files_are_the_files_zizmor_reads() -> None:
    names = ["a.sh", ".github/workflows/x.yaml", ".github/actions/setup/action.yml", ".github/dependabot.yml"]
    assert surface_scan.workflow_files(names) == (".github/actions/setup/action.yml", ".github/workflows/x.yaml")


@pytest.mark.parametrize(("text", "count"), [("", 0), ("[]", 0), ("[{}, {}]", 2)])
def test_zizmor_findings_are_counted(text: str, count: int) -> None:
    assert surface_scan.count_zizmor_findings(text) == count


@pytest.mark.parametrize(("text", "count"), [("", 0), ("null", 0), ("[]", 0), ('[{"a":1}]', 1)])
def test_gitleaks_findings_are_counted(text: str, count: int) -> None:
    assert surface_scan.count_gitleaks_findings(text) == count


def test_a_report_that_is_not_a_list_is_refused() -> None:
    with pytest.raises(ValueError, match="list"):
        surface_scan.count_zizmor_findings("{}")
    with pytest.raises(ValueError, match="list"):
        surface_scan.count_gitleaks_findings('"x"')


def _entry() -> dict[str, Any]:
    run = surface_scan.ToolRun(True, 0, 0, "s")
    return surface_scan.scan_entry("a" * 40, ["b", "a", "a"], run, run)


def test_an_entry_built_here_passes_its_own_check() -> None:
    assert surface_scan.scans_issues({"item-a": _entry()}) == []
    assert _entry()["files"] == ["a", "b"]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.pop("zizmor"),
        lambda e: e.update(extra=1),
        lambda e: e["gitleaks"].update(exit_code="0"),
        lambda e: e["gitleaks"].update(ran=1),
        lambda e: e["zizmor"].pop("scope"),
        lambda e: e.update(files="x"),
    ],
)
def test_an_entry_with_the_wrong_form_is_reported(mutate: Any) -> None:
    entry = _entry()
    mutate(entry)
    assert surface_scan.scans_issues({"item-a": entry}) != []
    assert surface_scan.scans_issues([]) != []


# ---- the script, with a real throwaway repository and fake tools


class _Tools:
    """Stands in for zizmor and gitleaks and records what they were given."""

    def __init__(self, zizmor: tuple[int, str] = (0, "[]"), gitleaks: tuple[int, str] = (0, "[]")) -> None:
        self.zizmor, self.gitleaks = zizmor, gitleaks
        self.seen: dict[str, dict[str, str]] = {}

    def __call__(self, argv: Any, cwd: str | None) -> subprocess.CompletedProcess[str]:
        argv = list(argv)
        if argv[0] == "git":
            return tool._run(argv, cwd)
        if argv[0] == "gitleaks":
            source = Path(argv[argv.index("--source") + 1])
            self.seen["gitleaks"] = {
                str(p.relative_to(source)): p.read_text(encoding="utf-8") for p in source.rglob("*") if p.is_file()
            }
            Path(argv[argv.index("--report-path") + 1]).write_text(self.gitleaks[1], encoding="utf-8")
            return subprocess.CompletedProcess(argv, self.gitleaks[0], "", "")
        assert argv[0] == "zizmor"
        source = Path(argv[-1])
        self.seen["zizmor"] = {
            str(p.relative_to(source)): p.read_text(encoding="utf-8") for p in source.rglob("*") if p.is_file()
        }
        return subprocess.CompletedProcess(argv, self.zizmor[0], self.zizmor[1], "")


def _branch(tree: Tree, files: dict[str, str]) -> tuple[str, str]:
    base = git(tree.env, "rev-parse", "HEAD", cwd=tree.wt).stdout.decode().strip()
    for name, text in files.items():
        path = tree.wt / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        git(tree.env, "add", name, cwd=tree.wt)
    git(tree.env, "-c", "credential.helper=", "commit", "-q", "-m", "change", cwd=tree.wt)
    return base, "handoff/x"


def _approval(tmp: Path) -> Path:
    path = tmp / "approval.json"
    path.write_text(json.dumps({"approved_at": "2026-11-15T00:00:00Z", "item_ids": ["item-a"], "approved_in": "x"}))
    return path


def test_the_scan_gives_gitleaks_the_added_lines_and_zizmor_the_whole_workflow(tmp_path: Path) -> None:
    tree = Tree(tmp_path)
    base, head = _branch(
        tree, {".github/workflows/w.yml": "name: w\non: push\njobs: {}\n", "tool.sh": "echo hi\n", "d.md": "doc\n"}
    )
    approval = _approval(tmp_path)
    tools = _Tools(zizmor=(0, '[{"id": 1}]'), gitleaks=(1, '[{"RuleID": "k"}]'))
    code = tool.main(
        ["--approval", str(approval), "--item", "item-a", "--repo", str(tree.main), "--base", base, "--head", head],
        run=tools,
    )
    assert code == 0
    assert tools.seen["gitleaks"] == {
        ".github/workflows/w.yml": "name: w\non: push\njobs: {}\n",
        "tool.sh": "echo hi\n",
    }
    assert tools.seen["zizmor"] == {".github/workflows/w.yml": "name: w\non: push\njobs: {}\n"}
    saved = json.loads(approval.read_text(encoding="utf-8"))
    entry = saved[surface_scan.SCANS_KEY]["item-a"]
    assert (entry["zizmor"]["exit_code"], entry["zizmor"]["findings"]) == (0, 1)
    assert (entry["gitleaks"]["exit_code"], entry["gitleaks"]["findings"]) == (1, 1)
    assert entry["files"] == [".github/workflows/w.yml", "tool.sh"]
    assert "execution_surface_ack" not in saved and saved["item_ids"] == ["item-a"]


def test_without_a_workflow_zizmor_does_not_run(tmp_path: Path) -> None:
    tree = Tree(tmp_path)
    base, head = _branch(tree, {"tool.sh": "echo hi\n"})
    approval = _approval(tmp_path)
    tools = _Tools()
    argv = ["--approval", str(approval), "--item", "item-a", "--repo", str(tree.main), "--base", base, "--head", head]
    assert tool.main(argv, run=tools) == 0
    assert "zizmor" not in tools.seen
    assert json.loads(approval.read_text())[surface_scan.SCANS_KEY]["item-a"]["zizmor"]["ran"] is False


def test_a_diff_without_a_surface_file_records_nothing(tmp_path: Path) -> None:
    tree = Tree(tmp_path)
    base, head = _branch(tree, {"docs/a.md": "doc\n"})
    approval = _approval(tmp_path)
    argv = ["--approval", str(approval), "--item", "item-a", "--repo", str(tree.main), "--base", base, "--head", head]
    assert tool.main(argv, run=_Tools()) == 2
    assert surface_scan.SCANS_KEY not in json.loads(approval.read_text())


def test_a_missing_tool_is_exit_2_not_a_clean_record(tmp_path: Path) -> None:
    tree = Tree(tmp_path)
    base, head = _branch(tree, {"tool.sh": "echo hi\n"})
    approval = _approval(tmp_path)

    def broken(argv: Any, cwd: str | None) -> subprocess.CompletedProcess[str]:
        if argv[0] == "gitleaks":
            raise tool.ScanError("gitleaks: not found")
        return tool._run(argv, cwd)

    argv = ["--approval", str(approval), "--item", "item-a", "--repo", str(tree.main), "--base", base, "--head", head]
    assert tool.main(argv, run=broken) == 2
    assert surface_scan.SCANS_KEY not in json.loads(approval.read_text())


# ---- the approval that publish reads


def _write_approval(handoff: Path, extra: dict[str, Any]) -> Path:
    directory = handoff / "approvals"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "a.json"
    body = {"approved_at": "2026-11-15T00:00:00Z", "item_ids": ["item-a"], "approved_in": ".private/x.md", **extra}
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def _inputs(handoff: Path) -> Any:
    return type("I", (), {"handoff_dir": str(handoff)})()


def test_publish_accepts_an_approval_that_carries_the_scans(tmp_path: Path) -> None:
    path = _write_approval(
        tmp_path, {"execution_surface_ack": ["item-a"], surface_scan.SCANS_KEY: {"item-a": _entry()}}
    )
    approval = cli._read_publish_approval(str(path), _inputs(tmp_path))
    assert approval.execution_surface_ack == ("item-a",)


def test_publish_rejects_scans_of_the_wrong_form(tmp_path: Path) -> None:
    path = _write_approval(tmp_path, {surface_scan.SCANS_KEY: {"item-a": {"zizmor": {}}}})
    with pytest.raises(cli._Exit):
        cli._read_publish_approval(str(path), _inputs(tmp_path))


def test_publish_still_rejects_an_unknown_key(tmp_path: Path) -> None:
    path = _write_approval(tmp_path, {"scans_of_something": {}})
    with pytest.raises(cli._Exit):
        cli._read_publish_approval(str(path), _inputs(tmp_path))
