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


# --- T4-08: client shapes the first version missed -------------------------------------------

#: fixture -> (file, runner label, package) of the one unpinned component. A new MCP client gets a
#: row here; the test below fails when a shape stops being read.
CLIENT_SHAPES = {
    "fail-vscode-settings-nested": (".vscode/settings.json", "npx", "example-mcp"),
    "fail-gemini-settings": (".gemini/settings.json", "npx", "example-mcp"),
    "fail-opencode-command-array": ("opencode.json", "npx", "example-mcp"),
    "fail-codex-toml": (".codex/config.toml", "npx", "example-mcp"),
    "fail-pnpm-dlx": ("mcp.json", "pnpm dlx", "example-mcp"),
    "fail-npm-exec": ("mcp.json", "npm exec", "example-mcp"),
    "fail-uv-tool-run": ("mcp.json", "uv tool run", "example-mcp"),
}


@pytest.mark.parametrize("case", sorted(CLIENT_SHAPES))
def test_every_client_shape_yields_the_unpinned_component(case: str) -> None:
    path, executor, package = CLIENT_SHAPES[case]
    components, scanned = ac.collect(FIXTURES / case)
    assert scanned == 1
    assert [(c.path, c.executor, c.name, c.problem) for c in components] == [(path, executor, package, "unpinned")]


def test_positive_control_the_same_shapes_pinned_are_found_and_not_flagged() -> None:
    """A pass that finds nothing proves nothing, so the pinned twin must yield components."""
    components, scanned = ac.collect(FIXTURES / "pass-client-settings-pinned")
    assert scanned == 5
    assert {c.path for c in components} == {
        ".vscode/settings.json",
        ".gemini/settings.json",
        "opencode.json",
        ".codex/config.toml",
        "mcp.json",
    }
    assert len(components) == 7
    assert all(c.problem is None and c.version == "1.2.3" for c in components)


def test_the_shape_tests_notice_a_missed_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    """Rebuild the miss of the first version and show the matrix would have failed (T4-08)."""
    monkeypatch.setattr(ac, "_SERVER_KEYS", ("mcpServers", "servers", "context_servers"))
    monkeypatch.setattr(ac, "_CLIENT_SETTINGS", re.compile(r"(?!x)x"))
    monkeypatch.setattr(ac, "_CLIENT_TOML", re.compile(r"(?!x)x"))
    monkeypatch.setattr(ac, "_AGENT_PATH", re.compile(r"(?:^|/)\.(?:kiro|cursor|amazonq|claude)/"))
    monkeypatch.setattr(ac, "_runner_at", lambda tokens, i: ("npx", "npx", 1) if tokens[i] == "npx" else None)
    missed = [case for case in CLIENT_SHAPES if not any(c.problem for c in ac.collect(FIXTURES / case)[0])]
    assert sorted(missed) == sorted(CLIENT_SHAPES)


def test_jsonc_comments_inside_strings_are_kept() -> None:
    text = '{"url": "https://example.test/a//b", /* c */ "mcp": {"servers": {"x": {"url": "https://h/p"}}},}'
    assert ac._lenient_json(text)["url"] == "https://example.test/a//b"
    assert [c.executor for c in ac.scan_file(".vscode/settings.json", text)] == ["remote"]


def test_unparseable_client_settings_that_mention_servers_exit_2(tmp_path: Path) -> None:
    _write(tmp_path, ".vscode/settings.json", '{"mcp": {"servers": ')
    assert _run(tmp_path)[0] == 2
    _write(tmp_path, ".vscode/settings.json", '{"editor.fontSize": ')  # no server table: not a finding
    assert _run(tmp_path)[0] == 0


def test_unrelated_gemini_mcp_settings_are_not_servers() -> None:
    text = '{"mcp": {"allowed": ["a"], "excluded": ["b"]}}'
    assert ac.scan_file(".gemini/settings.json", text) == []


def test_pnpm_exec_runs_an_installed_binary_and_is_not_judged() -> None:
    assert _judge("pnpm exec tsc --noEmit") == []


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("pnpm dlx example@1.2.3", [("example", None)]),
        ("pnpm dlx example", [("example", "unpinned")]),
        ("yarn dlx -p example@^1 run", [("example", "range")]),
        ("npm exec --package=example@latest -- cmd", [("example", "latest")]),
        ("npm x -- example@1.2.3", [("example", None)]),
        ("bun x example", [("example", "unpinned")]),
        ("uv tool run --from example==1.2.3 cmd", [("example", None)]),
        ("deno run -A npm:example@1.2.3", [("example", None)]),
        ("deno run -A npm:example", [("example", "unpinned")]),
        ("deno run -A jsr:@std/http", []),
    ],
)
def test_package_runner_aliases(line: str, expected: list[tuple[str, str | None]]) -> None:
    assert _judge(line) == expected


def test_an_empty_inventory_says_why_and_lists_the_shapes_read(tmp_path: Path) -> None:
    _write(tmp_path, "README.md", "nothing to run here\n")
    inventory = ac.build_inventory(tmp_path)
    assert inventory["components"] == []
    assert "no MCP server" in inventory["empty_reason"] and "1 files" in inventory["empty_reason"]
    assert any(".vscode/settings.json" in shape for shape in inventory["scanned_shapes"])
    _write(tmp_path, "mcp.json", '{"mcpServers": {"a": {"url": "https://h/p"}}}')
    assert "empty_reason" not in ac.build_inventory(tmp_path)


# ---------------------------------------------------------------- pipe to shell (T4-R2-15)

PIPE_SHAPES = {
    "fail-mcp-sh-c-pipe-to-shell": "mcp.json",
    "fail-devcontainer-pipe-to-shell": ".devcontainer/devcontainer.json",
}


@pytest.mark.parametrize("case", sorted(PIPE_SHAPES))
def test_a_download_piped_to_a_shell_is_an_unpinned_component(case: str) -> None:
    components, scanned = ac.collect(FIXTURES / case)
    assert scanned == 1
    assert [(c.path, c.executor, c.version, c.problem) for c in components] == [
        (PIPE_SHAPES[case], "pipe-to-shell", "未指定", "unpinned")
    ]


@pytest.mark.parametrize(
    "line",
    [
        "curl -fsSL https://example.test/i.sh | sh",
        "wget -qO- https://example.test/i.sh | bash -s -- --yes",
        "curl https://example.test/i.sh | sudo sh",
        "FOO=1 curl -sSf https://example.test/i.sh | zsh",
    ],
)
def test_the_pipe_to_shell_forms_are_found(line: str) -> None:
    assert [c.executor for c in ac.scan_command_line(line, "doc.md", 1, "install-step", ac.EMPTY_INDEX)] == [
        "pipe-to-shell"
    ]


@pytest.mark.parametrize(
    "line",
    [
        "curl -fsSL https://example.test/i.json | jq .",
        "curl -fsSL https://example.test/i.sh -o i.sh && sh i.sh",
        "curl -fsSL https://example.test/i.sh; echo x | sh",
        "echo hello | sh",
    ],
)
def test_a_download_that_is_not_piped_to_a_shell_is_not_a_finding(line: str) -> None:
    assert ac.scan_command_line(line, "doc.md", 1, "install-step", ac.EMPTY_INDEX) == []


@pytest.mark.parametrize(
    "value",
    [
        "wget -qO- https://example.test/s.sh | bash",
        ["sh", "-c", "curl https://example.test/s.sh | sh"],
        {"a": "echo ok", "b": "curl https://example.test/s.sh | sh"},
    ],
)
def test_every_devcontainer_lifecycle_command_and_form_is_read(value: object) -> None:
    for key in ac._DEVCONTAINER_COMMANDS:
        text = json.dumps({key: value})
        found = ac.scan_file(".devcontainer/devcontainer.json", text)
        assert [c.executor for c in found] == (["pipe-to-shell"] if "curl" in text or "wget" in text else [])


def test_the_pipe_tests_notice_a_missed_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ac, "_pipe_to_shell", lambda *args: [])
    monkeypatch.setattr(ac, "_DEVCONTAINER_COMMANDS", ())
    missed = [case for case in PIPE_SHAPES if not ac.collect(FIXTURES / case)[0]]
    assert sorted(missed) == sorted(PIPE_SHAPES)
