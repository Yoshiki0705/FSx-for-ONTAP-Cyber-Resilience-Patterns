"""Tests of the ``agent-components`` subcommand of the supply-chain gate."""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import check_supply_chain as gate
import pytest
from supply_chain_checks import agent_components as ac

REPO = Path(__file__).resolve().parents[2]
FIXTURES = gate.FIXTURES_DIR / "agent-components"
_GIT_ENV = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}


def _run(root: Path) -> tuple[int, str]:
    out = io.StringIO()
    code = gate.main(["agent-components", "--root", str(root)], out=out)
    return code, out.getvalue()


def _write(root: Path, rel: str, text: str) -> None:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=_GIT_ENV)  # noqa: S603, S607


def _judge(line: str, path: str = "doc.md", index: ac.PackageIndex = ac.EMPTY_INDEX) -> list[tuple[str, str | None]]:
    return [(c.name, c.problem) for c in ac.scan_command_line(line, path, 1, "install-step", index)]


@pytest.mark.parametrize("case", sorted(p.name for p in FIXTURES.iterdir() if p.name.startswith("fail-")))
def test_each_failing_fixture_fails_for_its_stated_reason(case: str) -> None:
    want_code, kind = (FIXTURES / case / "EXPECT").read_text(encoding="utf-8").splitlines()[0].split()
    code, text = _run(FIXTURES / case)
    assert code == int(want_code)
    assert f": {kind}:" in text
    for line in text.splitlines()[:-1]:
        assert re.match(r"^[^:\s]+:\d+: \w[\w-]*: .+", line), line


@pytest.mark.parametrize("case", sorted(p.name for p in FIXTURES.iterdir() if p.name.startswith("pass-")))
def test_good_fixtures_pass_with_files_scanned(case: str) -> None:
    code, text = _run(FIXTURES / case)
    assert code == 0
    assert re.search(r"scanned [1-9]\d* file\(s\), 0 violation\(s\)", text), text


def test_selftest_of_the_subcommand_passes() -> None:
    out = io.StringIO()
    assert gate.main(["agent-components", "--selftest"], out=out) == 0
    assert "selftest ok" in out.getvalue()


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("npx -y example@1.2.3", [("example", None)]),
        ("npx --yes @scope/example@1.2.3", [("@scope/example", None)]),
        ("npx -y @scope/example", [("@scope/example", "unpinned")]),
        ("npx -y example@latest", [("example", "latest")]),
        ("npx -y example@next", [("example", "unpinned")]),
        ("npx -y example@^1.2.0", [("example", "range")]),
        ("npx -y example@1", [("example", "range")]),
        ("npx -p example@1.2.3 some-bin", [("example", None)]),
        ("uvx example==1.2.3", [("example", None)]),
        ("uvx example", [("example", "unpinned")]),
        ("uvx example@latest", [("example", "latest")]),
        ("uvx --from example==1.2.3 cmd", [("example", None)]),
        ("uvx --from example cmd", [("example", "unpinned")]),
        ("uvx 'example>=1.0'", [("example", "range")]),
        ("uvx 'example===1.0'", [("example", "range")]),
        ("uvx 'example==1.*'", [("example", "range")]),
        ("pipx run example==1.2.3", [("example", None)]),
        ("pipx run example", [("example", "unpinned")]),
        ("bunx example", [("example", "unpinned")]),
        ("dnx Example.Tool", [("Example.Tool", "unpinned")]),
        ("dnx Example.Tool --version 1.2.3 --yes", [("Example.Tool", None)]),
        ("dnx Example.Tool@1.2.3", [("Example.Tool", None)]),
        ("make build && npx example", [("example", "unpinned")]),
        ("FOO=1 npx example@1.2.3", [("example", None)]),
        ("$ npx example", [("example", "unpinned")]),
        ("- run: uvx example", [("example", "unpinned")]),
        ("docker run --rm -e A=b example/tool:1.2.3", [("example/tool", None)]),
        ("docker run example/tool", [("example/tool", "unpinned")]),
        ("docker run example/tool:latest", [("example/tool", "latest")]),
        (f"docker run example/tool@sha256:{'b' * 64}", [("example/tool", None)]),
        ("claude mcp add x -- docker run -i example/mcp:1.2.3", [("example/mcp", "digest")]),
    ],
)
def test_command_lines_are_judged(line: str, expected: list[tuple[str, str | None]]) -> None:
    assert _judge(line) == expected


@pytest.mark.parametrize(
    "line",
    [
        "npx --version",
        "uvx --help",
        "command -v npx",
        "which uvx",
        'echo "npx example"',
        "# npx example",
        "npx",
        "npx ./local-tool",
        "npx ${PACKAGE}",
        "npx <package>",
        "cp ~/.kiro/settings/mcp.json . && npx -y example",
        "docker run $IMAGE",
        "npx -y ~/.kiro/bin/example",
    ],
)
def test_status_prose_placeholders_and_kiro_home_are_not_findings(line: str) -> None:
    assert _judge(line) == []


def test_local_bin_rule_needs_exact_version_and_lock_file() -> None:
    declared = {"": {"example-tool": "1.2.3"}}
    with_lock = ac.PackageIndex(declared, frozenset({""}))
    without_lock = ac.PackageIndex(declared, frozenset())
    assert _judge("npx example-tool", index=with_lock) == [("example-tool", None)]
    assert _judge("npx example-tool", "sub/doc.md", with_lock) == [("example-tool", None)]
    assert _judge("npx example-tool", index=without_lock) == [("example-tool", "unpinned")]
    assert _judge("npx example-tool@latest", index=with_lock) == [("example-tool", "latest")]
    assert _judge("npx other-tool", index=with_lock) == [("other-tool", "unpinned")]
    pinned = ac.scan_command_line("npx example-tool", "doc.md", 1, "install-step", with_lock)[0]
    assert pinned.pin_scope == "dependency-tree"


def test_pin_scope_is_top_level_for_exact_versions_and_none_for_unpinned() -> None:
    exact = ac.scan_command_line("npx example@1.2.3", "doc.md", 1, "install-step", ac.EMPTY_INDEX)[0]
    loose = ac.scan_command_line("npx example", "doc.md", 1, "install-step", ac.EMPTY_INDEX)[0]
    assert (exact.pin_scope, exact.version) == ("top-level", "1.2.3")
    assert (loose.pin_scope, loose.version) == ("none", "未指定")


def test_url_only_server_is_not_applicable_and_not_unpinned() -> None:
    comps = ac.scan_file("mcp.json", '{"mcpServers": {"r": {"url": "https://example.com/mcp"}}}')
    assert [(c.executor, c.version, c.problem) for c in comps] == [("remote", "該当なし", None)]


def test_server_that_refers_to_kiro_home_is_not_recorded() -> None:
    text = '{"mcpServers": {"a": {"command": "node", "args": ["~/.kiro/mcp/server.js"]}}}'
    assert ac.scan_file("mcp.json", text) == []


def test_shell_wrapped_server_is_judged() -> None:
    text = '{"mcpServers": {"a": {"command": "bash", "args": ["-c", "npx -y example"]}}}'
    comps = ac.scan_file("mcp.json", text)
    assert [(c.name, c.problem, c.server) for c in comps] == [("example", "unpinned", "a")]


def test_local_server_command_has_no_version_to_pin() -> None:
    comps = ac.scan_file("mcp.json", '{"mcpServers": {"a": {"command": "node", "args": ["server.js"]}}}')
    assert [(c.executor, c.version, c.problem) for c in comps] == [("node", "該当なし", None)]


def test_hook_command_in_agent_json_is_judged() -> None:
    text = '{"then": {"type": "runCommand", "command": "npx example"}}'
    comps = ac.scan_file(".kiro/hooks/x.kiro.hook", text)
    assert [(c.kind, c.problem) for c in comps] == [("agent-config", "unpinned")]


def test_kind_follows_the_file() -> None:
    assert ac.scan_file("AGENTS.md", "`npx example`\n")[0].kind == "agent-config"
    assert ac.scan_file("docs/guide.md", "`npx example`\n")[0].kind == "install-step"
    assert (
        ac.scan_file("mcp.json", '{"mcpServers": {"a": {"command": "npx", "args": ["example"]}}}')[0].kind
        == "mcp-server"
    )


def test_dockerfile_from_stage_alias_and_scratch_are_not_findings() -> None:
    text = "```dockerfile\nFROM example/base:1.0 AS build\nFROM scratch\nFROM build\n```\n"
    assert [(c.name, c.problem) for c in ac.scan_file("README.md", text)] == [("example/base", None)]
    assert [c.problem for c in ac.scan_file("README.md", "```dockerfile\nFROM example/base\n```\n")] == ["unpinned"]


def test_backslash_continuation_is_one_command() -> None:
    comps = ac.scan_file("run.sh", "npx \\\n  example\n")
    assert [(c.name, c.line) for c in comps] == [("example", 1)]


def test_makefile_recipe_prefix_is_ignored() -> None:
    comps = ac.scan_file("Makefile", "build:\n\t@npx example\n")
    assert [(c.name, c.line) for c in comps] == [("example", 2)]


def test_yaml_block_with_mcp_servers_is_a_structure() -> None:
    text = "```yaml\nmcpServers:\n  a:\n    command: uvx\n    args: [example]\n```\n"
    assert [(c.name, c.server, c.line) for c in ac.scan_file("README.md", text)] == [("example", "a", 3)]


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        ("README.md", "```yaml\nmcpServers: [oops\n```\n"),
        ("README.md", "---\nmcpServers: [oops\n---\n"),
        (".claude/settings.json", '{"mcpServers": oops}'),
    ],
)
def test_unparseable_structures_raise(rel: str, text: str) -> None:
    with pytest.raises(ac.Unparseable):
        ac.scan_file(rel, text)


def test_add_json_argument_that_is_not_json_raises() -> None:
    with pytest.raises(ac.Unparseable):
        ac.scan_command_line("claude mcp add-json x '{not json}'", "README.md", 1, "install-step", ac.EMPTY_INDEX)


def test_json_block_that_is_not_about_servers_is_ignored_when_broken() -> None:
    assert ac.scan_file("README.md", "```json\n{ ... }\n```\n") == []


def test_non_utf8_target_is_unparseable(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_bytes(b"\xff\xfe\x00")
    code, text = _run(tmp_path)
    assert code == 2
    assert "README.md:1: unparseable" in text


def test_no_target_file_scans_zero_files_and_succeeds(tmp_path: Path) -> None:
    _write(tmp_path, "src/main.py", "print('x')\n")
    code, text = _run(tmp_path)
    assert code == 0
    assert text.strip() == "agent-components: scanned 0 files (nothing was checked), 0 violation(s)"


def test_only_tracked_files_are_read_and_fixture_directories_are_skipped(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "core.hooksPath", str(tmp_path / "no-hooks"))
    _write(tmp_path, "tracked/README.md", "`npx pinned@1.2.3`\n")
    _write(tmp_path, "scripts/tests/fixtures/x/README.md", "`npx bad`\n")
    _write(tmp_path, "untracked.md", "`npx bad`\n")
    _git(tmp_path, "add", "tracked/README.md", "scripts/tests/fixtures/x/README.md")
    code, text = _run(tmp_path)
    assert code == 0
    assert text.strip() == "agent-components: scanned 1 file(s), 0 violation(s)"
    _git(tmp_path, "add", "untracked.md")
    code, text = _run(tmp_path)
    assert code == 1
    assert "untracked.md:1: unpinned" in text


def test_inventory_has_time_sha_and_regeneration_note(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "core.hooksPath", str(tmp_path / "no-hooks"))
    _git(tmp_path, "config", "user.name", "Example")
    _git(tmp_path, "config", "user.email", "example@example.com")
    _write(tmp_path, "README.md", "`npx example`\n")
    _git(tmp_path, "add", "README.md")
    _git(tmp_path, "commit", "-q", "-m", "init")
    sha = subprocess.run(
        ["git", "-C", str(tmp_path), "rev-parse", "HEAD"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
        env=_GIT_ENV,
    ).stdout.strip()
    now = datetime(2026, 1, 2, 3, 4, 5, 678, tzinfo=UTC)
    inventory = ac.build_inventory(tmp_path, now=now)
    assert inventory["commit_sha"] == sha
    assert inventory["generated_at"] == "2026-01-02T03:04:05+00:00"
    assert "agent_components.py --write" in inventory["description"]
    assert inventory["unpinned_count"] == 1
    assert inventory["components"][0]["name"] == "example"
    assert ac.main(["--write", "--root", str(tmp_path)]) == 0
    written = json.loads((tmp_path / ac.INVENTORY_PATH).read_text(encoding="utf-8"))
    assert written["commit_sha"] == sha


def test_real_repository_passes() -> None:
    code, text = _run(REPO)
    assert code == 0, text
    assert re.search(r"scanned [1-9]\d* file\(s\)", text), text
