"""Tests of ``scripts/check_pinned_sha_exist.py`` (task 11.14). No network: queries are fakes.

The reachability rules (tag comment, ancestor of the default branch, annotated tags) run
against a fake GitHub API so that an impostor commit, which GitHub answers 200 for on the
commits endpoint, is shown to fail.
"""

from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path

import check_pinned_sha_exist as gate
import pytest

GOOD = "11bd71901bbe5b1630ceea73d27597364c9af683"
GONE = "0123456789abcdef0123456789abcdef01234567"
OTHER = "48ab28a6f5dbc2a99bf1e0131198dd8f1df78169"
FORK_ONLY = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
KNOWN = {("actions/checkout", GOOD), ("github/codeql-action", OTHER)}


def _write(root: Path, name: str, *uses: str) -> None:
    folder = root / ".github" / "workflows"
    folder.mkdir(parents=True, exist_ok=True)
    body = "".join(f"      - uses: {u}\n" for u in uses)
    (folder / name).write_text("name: x\njobs:\n  b:\n    steps:\n" + body, encoding="utf-8")


def _fake(repo: str, sha: str, tag: str | None) -> gate.Lookup:
    if sha == "f" * 40:
        return gate.Lookup(gate.ERROR, "HTTP 503")
    if sha == FORK_ONLY:
        return gate.Lookup(gate.IMPOSTOR, f"{sha} is behind main of {repo}")
    return gate.Lookup(gate.EXISTS if (repo, sha) in KNOWN else gate.MISSING)


def _run(root: Path) -> tuple[int, list[str]]:
    lines: list[str] = []
    return gate.run(root, _fake, lines.append), lines


def test_existing_sha_passes(tmp_path: Path) -> None:
    _write(tmp_path, "a.yml", f"actions/checkout@{GOOD} # v4", "./local", "docker://alpine:3", "actions/x@v4")
    code, lines = _run(tmp_path)
    assert code == 0
    assert "1 pinned ref(s)" in lines[-1] and "0 finding(s)" in lines[-1]


def test_nonexistent_sha_is_a_violation(tmp_path: Path) -> None:
    _write(tmp_path, "a.yml", f"actions/checkout@{GONE}")
    code, lines = _run(tmp_path)
    assert code == 1
    assert lines[0].startswith(".github/workflows/a.yml:5: missing-sha:")


def test_impostor_commit_is_a_violation(tmp_path: Path) -> None:
    _write(tmp_path, "a.yml", f"actions/checkout@{FORK_ONLY} # v4.2.2")
    code, lines = _run(tmp_path)
    assert code == 1
    assert "impostor-or-orphan" in lines[0]


def test_sha_of_another_repository_is_a_violation(tmp_path: Path) -> None:
    """GOOD is a commit of actions/checkout, not of github/codeql-action/upload-sarif."""
    _write(tmp_path, "a.yml", f"github/codeql-action/upload-sarif@{GOOD}")
    code, lines = _run(tmp_path)
    assert code == 1
    assert "github/codeql-action" in lines[0]


def test_failed_lookup_exits_2_and_still_reports_findings(tmp_path: Path) -> None:
    _write(tmp_path, "a.yml", f"actions/checkout@{GONE}", f"actions/setup-python@{'f' * 40}")
    code, lines = _run(tmp_path)
    assert code == 2
    assert any("missing-sha" in line for line in lines)
    assert any("lookup-failed" in line and "HTTP 503" in line for line in lines)


def test_each_distinct_sha_is_asked_once(tmp_path: Path) -> None:
    _write(tmp_path, "a.yml", f"actions/checkout@{GOOD}", f"actions/checkout@{GOOD}")
    _write(tmp_path, "b.yml", f"actions/checkout@{GOOD}")
    asked: list[tuple[str, str, str | None]] = []

    def counting(repo: str, sha: str, tag: str | None) -> gate.Lookup:
        asked.append((repo, sha, tag))
        return gate.Lookup(gate.EXISTS)

    assert gate.run(tmp_path, counting, lambda _l: None) == 0
    assert asked == [("actions/checkout", GOOD, None)]


def test_version_comment_is_passed_to_the_query(tmp_path: Path) -> None:
    _write(tmp_path, "a.yml", f"actions/checkout@{GOOD} # v4.2.2", f"actions/cache@{OTHER} # pinned by hand")
    refs = gate.collect_refs("x", (tmp_path / ".github/workflows/a.yml").read_text(encoding="utf-8"))
    assert [r.tag for r in refs] == ["v4.2.2", None]


def test_no_token_exits_2_without_querying(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write(tmp_path, "a.yml", f"actions/checkout@{GONE}")
    assert gate.main(["--root", str(tmp_path)], env={}) == 2
    assert "GITHUB_TOKEN" in capsys.readouterr().err


# --- the GitHub client against a fake API --------------------------------------------------


class _Response(io.BytesIO):
    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://api.github.com/x", code, "msg", {}, io.BytesIO(b""))  # type: ignore[arg-type]


def _fake_api(routes: dict[str, object], calls: list[str] | None = None):
    """Opener answering ``routes`` (path -> JSON body or an int HTTP error code)."""

    def opener(request: object, timeout: int) -> object:
        path = request.full_url.removeprefix(gate.API)  # type: ignore[attr-defined]
        if calls is not None:
            calls.append(path)
        answer = routes.get(path, 404)
        if isinstance(answer, int):
            raise _http_error(answer)
        return _Response(json.dumps(answer).encode())

    return opener


REPO = "actions/checkout"
TAGGED = "a" * 40


def test_untagged_sha_must_be_an_ancestor_of_the_default_branch() -> None:
    routes = {
        f"/repos/{REPO}": {"default_branch": "main"},
        f"/repos/{REPO}/compare/{GOOD}...main": {"status": "ahead"},
        f"/repos/{REPO}/compare/{FORK_ONLY}...main": {"status": "behind"},
        f"/repos/{REPO}/compare/{GONE}...main": 404,
    }
    query = gate.github_query("t", _fake_api(routes))
    assert query(REPO, GOOD, None).status == gate.EXISTS
    impostor = query(REPO, FORK_ONLY, None)
    assert impostor.status == gate.IMPOSTOR and "fork" in impostor.detail
    assert query(REPO, GONE, None).status == gate.MISSING


def test_diverged_is_not_reachable() -> None:
    routes = {
        f"/repos/{REPO}": {"default_branch": "main"},
        f"/repos/{REPO}/compare/{GOOD}...main": {"status": "diverged"},
    }
    assert gate.github_query("t", _fake_api(routes))(REPO, GOOD, None).status == gate.IMPOSTOR


def test_default_branch_is_asked_once_per_repository() -> None:
    calls: list[str] = []
    routes = {
        f"/repos/{REPO}": {"default_branch": "main"},
        f"/repos/{REPO}/compare/{GOOD}...main": {"status": "identical"},
        f"/repos/{REPO}/compare/{OTHER}...main": {"status": "ahead"},
    }
    query = gate.github_query("t", _fake_api(routes, calls))
    query(REPO, GOOD, None)
    query(REPO, OTHER, None)
    assert calls.count(f"/repos/{REPO}") == 1


def test_exact_version_comment_must_point_at_the_sha() -> None:
    routes = {f"/repos/{REPO}/git/ref/tags/v4.2.2": {"object": {"type": "commit", "sha": TAGGED}}}
    query = gate.github_query("t", _fake_api(routes))
    assert query(REPO, TAGGED, "v4.2.2").status == gate.EXISTS
    wrong = query(REPO, GOOD, "v4.2.2")
    assert wrong.status == gate.TAG_MISMATCH and TAGGED in wrong.detail


def test_annotated_tag_is_peeled() -> None:
    routes = {
        f"/repos/{REPO}/git/ref/tags/v4.2.2": {"object": {"type": "tag", "sha": "b" * 40}},
        f"/repos/{REPO}/git/tags/{'b' * 40}": {"object": {"type": "commit", "sha": TAGGED}},
    }
    assert gate.github_query("t", _fake_api(routes))(REPO, TAGGED, "v4.2.2").status == gate.EXISTS


def test_floating_tag_accepts_an_ancestor_of_what_it_points_at_now() -> None:
    routes = {
        f"/repos/{REPO}/git/ref/tags/v4": {"object": {"type": "commit", "sha": TAGGED}},
        f"/repos/{REPO}/compare/{GOOD}...{TAGGED}": {"status": "ahead"},
        f"/repos/{REPO}/compare/{FORK_ONLY}...{TAGGED}": {"status": "diverged"},
    }
    query = gate.github_query("t", _fake_api(routes))
    assert query(REPO, GOOD, "v4").status == gate.EXISTS
    assert query(REPO, FORK_ONLY, "v4").status == gate.TAG_MISMATCH


def test_comment_naming_a_tag_that_does_not_exist_is_a_mismatch() -> None:
    assert gate.github_query("t", _fake_api({}))(REPO, GOOD, "v9.9.9").status == gate.TAG_MISMATCH


@pytest.mark.parametrize(
    ("code", "status"),
    [(404, gate.MISSING), (422, gate.MISSING), (403, gate.ERROR), (429, gate.ERROR), (500, gate.ERROR)],
)
def test_http_statuses_are_told_apart_and_token_is_not_leaked(code: int, status: str) -> None:
    secret = "tok-" + "x" * 8
    routes = {f"/repos/{REPO}": {"default_branch": "main"}, f"/repos/{REPO}/compare/{GOOD}...main": code}
    answer = gate.github_query(secret, _fake_api(routes))(REPO, GOOD, None)
    assert answer.status == status
    assert secret not in answer.detail


def test_network_error_is_an_error() -> None:
    def opener(request: object, timeout: int) -> object:
        raise urllib.error.URLError("down")

    assert gate.github_query("t", opener)("a/b", GOOD, None).status == gate.ERROR


# --- the Hub preset tag ---------------------------------------------------------------------


def _policy(root: Path, body: dict[str, object]) -> None:
    target = root / gate.POLICY_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(body), encoding="utf-8")


def test_preset_tag_that_moved_is_reported(tmp_path: Path) -> None:
    _policy(tmp_path, {"renovate_preset": {"tag": "supply-chain-preset-v1.0.0", "commit": TAGGED}})
    moved, _ = gate.check_preset_tag(tmp_path, lambda _r, _t: gate.Lookup(gate.EXISTS, GOOD))
    assert moved and "tag-moved" in moved[0]
    same, errs = gate.check_preset_tag(tmp_path, lambda _r, _t: gate.Lookup(gate.EXISTS, TAGGED))
    assert same == [] and errs == []


def test_preset_tag_lookup_failure_is_an_error_not_a_pass(tmp_path: Path) -> None:
    _policy(tmp_path, {"renovate_preset": {"tag": "t-v1.0.0", "commit": TAGGED}})
    _, errs = gate.check_preset_tag(tmp_path, lambda _r, _t: gate.Lookup(gate.ERROR, "HTTP 503"))
    assert errs and "HTTP 503" in errs[0]


def test_no_recorded_preset_checks_nothing(tmp_path: Path) -> None:
    _policy(tmp_path, {"schema_version": 1})
    assert gate.check_preset_tag(tmp_path, lambda _r, _t: pytest.fail("must not ask")) == ([], [])
