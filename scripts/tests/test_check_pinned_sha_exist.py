"""Tests of ``scripts/check_pinned_sha_exist.py`` (task 11.14). No network: queries are fakes."""

from __future__ import annotations

import io
import urllib.error
from pathlib import Path

import check_pinned_sha_exist as gate
import pytest

GOOD = "11bd71901bbe5b1630ceea73d27597364c9af683"
GONE = "0123456789abcdef0123456789abcdef01234567"
OTHER = "48ab28a6f5dbc2a99bf1e0131198dd8f1df78169"
KNOWN = {("actions/checkout", GOOD), ("github/codeql-action", OTHER)}


def _write(root: Path, name: str, *uses: str) -> None:
    folder = root / ".github" / "workflows"
    folder.mkdir(parents=True, exist_ok=True)
    body = "".join(f"      - uses: {u}\n" for u in uses)
    (folder / name).write_text("name: x\njobs:\n  b:\n    steps:\n" + body, encoding="utf-8")


def _fake(repo: str, sha: str) -> gate.Lookup:
    if sha == "f" * 40:
        return gate.Lookup(gate.ERROR, "HTTP 503")
    return gate.Lookup(gate.EXISTS if (repo, sha) in KNOWN else gate.MISSING)


def _run(root: Path) -> tuple[int, list[str]]:
    lines: list[str] = []
    return gate.run(root, _fake, lines.append), lines


def test_existing_sha_passes(tmp_path: Path) -> None:
    _write(tmp_path, "a.yml", f"actions/checkout@{GOOD} # v4", "./local", "docker://alpine:3", "actions/x@v4")
    code, lines = _run(tmp_path)
    assert code == 0
    assert "1 pinned ref(s)" in lines[-1] and "0 missing" in lines[-1]


def test_nonexistent_sha_is_a_violation(tmp_path: Path) -> None:
    _write(tmp_path, "a.yml", f"actions/checkout@{GONE}")
    code, lines = _run(tmp_path)
    assert code == 1
    assert lines[0].startswith(".github/workflows/a.yml:5: missing-sha:")


def test_sha_of_another_repository_is_a_violation(tmp_path: Path) -> None:
    """GOOD is a commit of actions/checkout, not of github/codeql-action/upload-sarif."""
    _write(tmp_path, "a.yml", f"github/codeql-action/upload-sarif@{GOOD}")
    code, lines = _run(tmp_path)
    assert code == 1
    assert "github/codeql-action" in lines[0]


def test_failed_lookup_exits_2_and_still_reports_missing(tmp_path: Path) -> None:
    _write(tmp_path, "a.yml", f"actions/checkout@{GONE}", f"actions/setup-python@{'f' * 40}")
    code, lines = _run(tmp_path)
    assert code == 2
    assert any("missing-sha" in line for line in lines)
    assert any("lookup-failed" in line and "HTTP 503" in line for line in lines)


def test_each_distinct_sha_is_asked_once(tmp_path: Path) -> None:
    _write(tmp_path, "a.yml", f"actions/checkout@{GOOD}", f"actions/checkout@{GOOD}")
    _write(tmp_path, "b.yml", f"actions/checkout@{GOOD}")
    asked: list[tuple[str, str]] = []

    def counting(repo: str, sha: str) -> gate.Lookup:
        asked.append((repo, sha))
        return gate.Lookup(gate.EXISTS)

    assert gate.run(tmp_path, counting, lambda _l: None) == 0
    assert asked == [("actions/checkout", GOOD)]


def test_no_token_exits_2_without_querying(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write(tmp_path, "a.yml", f"actions/checkout@{GONE}")
    assert gate.main(["--root", str(tmp_path)], env={}) == 2
    assert "GITHUB_TOKEN" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("code", "status"),
    [(404, gate.MISSING), (422, gate.MISSING), (403, gate.ERROR), (429, gate.ERROR), (500, gate.ERROR)],
)
def test_http_statuses_are_told_apart_and_token_is_not_leaked(code: int, status: str) -> None:
    secret = "tok-" + "x" * 8

    def opener(request: object, timeout: int) -> object:
        raise urllib.error.HTTPError("https://api.github.com/x", code, "msg", {}, io.BytesIO(b""))  # type: ignore[arg-type]

    answer = gate.github_query(secret, opener)("actions/checkout", GOOD)
    assert answer.status == status
    assert secret not in answer.detail


def test_network_error_is_an_error() -> None:
    def opener(request: object, timeout: int) -> object:
        raise urllib.error.URLError("down")

    assert gate.github_query("t", opener)("a/b", GOOD).status == gate.ERROR
