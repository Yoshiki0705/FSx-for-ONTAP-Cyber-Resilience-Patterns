"""Checks of what ``kiro-cli`` produced and of what it could have touched (T4-02, T4-05 to T4-07).

This module is part of the pure core (see ``handoff/__init__.py``): it reads no file and
starts no process. The runner reads the files, runs git and passes plain values in.

What is here:

- :func:`redact_secrets`: replaces the text of credentials in the output of ``kiro-cli``
  before it is written to a Handoff_Report. The line count does not change, because the
  line numbers of ``report_flags`` point into the report.
- :func:`changed_entries`: which entries of two digests of the same names differ, for the
  files that a worktree shares with the main working tree (``config``, ``hooks/``,
  ``info/`` of the common git directory) and for the control files of the harness.
- :func:`execution_surface`: the changed files that are not documentation, which is where code that runs, or
  that decides who may run what, once it is merged can be (T4-R2-07: the list of documentation is the closed
  one; every other file counts).
- :func:`risky_added_lines`: the added lines of such files that have an executable side
  effect of the kinds that the review of an unattended change looks for.
- :func:`cited_paths`: the repository paths that the answer of a query item names, to be
  checked against the commit that the item was started from.

Every detector here is a heuristic: it can miss a form it does not know and can flag text
that is harmless. Each says which, in its own docstring. A flag points a human at a place;
none of them is proof that a thing is safe.
"""

from __future__ import annotations

import posixpath
import re
import unicodedata
from collections.abc import Iterable, Mapping
from typing import Final

__all__ = [
    "CITED_PATH_LIMIT",
    "EXECUTION_SURFACE_PATTERNS",
    "DOCUMENTATION_PATTERNS",
    "cited_locations",
    "cited_paths",
    "changed_entries",
    "surface_kind",
    "execution_surface",
    "redact_secrets",
    "risky_added_lines",
]

# --------------------------------------------------------------------------------------------
# Secrets in the output of kiro-cli (T4-05)
# --------------------------------------------------------------------------------------------

#: ``(kind, pattern, replacement)`` of one credential form each. A match is replaced by
#: ``[REDACTED:<kind>]``; a name that precedes the value stays. Forms: AWS access key IDs, the
#: values of ``aws_secret_access_key`` and ``aws_session_token``, GitHub tokens, GitLab and npm tokens, ``sk-``
#: keys, Slack tokens,
#: JSON Web Tokens, ``Bearer`` values, and an assignment of a long mixed value to a name that
#: says it is a secret.
_SECRET_PATTERNS: Final[tuple[tuple[str, re.Pattern[str], str], ...]] = (
    (
        "aws_access_key_id",
        re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}(?![A-Za-z0-9])"),
        "[REDACTED:aws_access_key_id]",
    ),
    (
        "aws_secret",
        re.compile(r"(?i)(aws_secret_access_key|aws_session_token|aws_secret_key)(\s*[=:]\s*)[\"']?[^\s\"']+[\"']?"),
        r"\1\2[REDACTED:aws_secret]",
    ),
    (
        "github_token",
        re.compile(r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
        "[REDACTED:github_token]",
    ),
    (
        "gitlab_token",
        re.compile(r"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,}"),
        "[REDACTED:gitlab_token]",
    ),
    ("npm_token", re.compile(r"(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])"), "[REDACTED:npm_token]"),
    # ``sk-`` keys of model and payment services, including the ``sk-ant-api03-`` form; 32 characters or more
    ("api_key_sk", re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{32,}"), "[REDACTED:api_key_sk]"),
    ("slack_token", re.compile(r"(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9-]{10,}"), "[REDACTED:slack_token]"),
    (
        "jwt",
        re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        "[REDACTED:jwt]",
    ),
    ("bearer", re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{20,}"), r"\1[REDACTED:bearer]"),
    (
        "authorization_basic",
        re.compile(r"(?i)(authorization:\s*basic\s+)[A-Za-z0-9+/=]{8,}"),
        r"\1[REDACTED:authorization_basic]",
    ),
    (
        "url_credential",
        re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)[^/\s@]+(@)"),
        r"\1[REDACTED:url_credential]\2",
    ),
    ("docker_auth", re.compile(r'(?i)("auth"\s*:\s*")[A-Za-z0-9+/=]{16,}'), r"\1[REDACTED:docker_auth]"),
    (
        "assignment",
        re.compile(
            r"(?i)(\b[A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)[A-Za-z0-9_.-]*"
            r"\s*[=:]\s*[\"']?)(?=[A-Za-z0-9/+=_.-]*\d)(?=[A-Za-z0-9/+=_.-]*[A-Za-z])[A-Za-z0-9/+=_.-]{16,}"
        ),
        r"\1[REDACTED:assignment]",
    ),
)
#: Control sequences of a terminal (colour, cursor). Taken out before the patterns look, so that
#: ``ESC[1mAKIA...ESC[0m`` and a token with a colour change inside it are found (T4-R2-10). A newline is never part of
#: one, so the line count does not change.
_ANSI: Final = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_KEY_BEGIN: Final = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")
_KEY_END: Final = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")


def redact_secrets(text: str) -> tuple[str, tuple[str, ...]]:
    """Replace the credentials in a text, keeping its lines.

    A private key block is replaced line by line, from the ``BEGIN`` line to the ``END``
    line (to the end of the text when there is no ``END`` line). Every other match is
    replaced inside its line. The number of ``\\n`` does not change, so a line number of
    ``report_flags`` still points at the same line.

    Terminal control sequences (colour and the like) are taken out first, so a key between two colour changes is
    found; the text that is returned has none. The patterns are a list of known credential forms plus one assignment
    form. A secret in another form (a bare 40-character secret key on a line of its own, a password of fewer than 16
    characters in an assignment) is not found: the result says "no credential form was seen", which is not "the text
    has no secret".

    Args:
        text: The output of ``kiro-cli``, decoded.

    Returns:
        The text with each match replaced by ``[REDACTED:<kind>]``, and the sorted kinds that
        matched (empty when nothing did). The matched text is not returned.

    Raises:
        TypeError: ``text`` is not a ``str``.
    """
    if not isinstance(text, str):
        raise TypeError(f"text must be a str, not {type(text).__name__}")
    kinds: set[str] = set()
    lines: list[str] = []
    in_key = False
    for line in _ANSI.sub("", text).split("\n"):
        if in_key:
            lines.append("[REDACTED:private_key]")
            in_key = _KEY_END.search(line) is None
            continue
        if _KEY_BEGIN.search(line):
            kinds.add("private_key")
            lines.append("[REDACTED:private_key]")
            in_key = _KEY_END.search(line) is None
            continue
        for kind, pattern, replacement in _SECRET_PATTERNS:
            line, count = pattern.subn(replacement, line)
            if count:
                kinds.add(kind)
        lines.append(line)
    return "\n".join(lines), tuple(sorted(kinds))


# --------------------------------------------------------------------------------------------
# Files that a worktree shares with the main working tree, and the control files (T4-02, T4-03)
# --------------------------------------------------------------------------------------------


def changed_entries(before: Mapping[str, str | None], after: Mapping[str, str | None]) -> tuple[str, ...]:
    """The names whose digest differs between two snapshots, including one that appeared or vanished.

    A name that is in one snapshot only differs, whatever its value: a hook file that was
    added, or a control file that was deleted, is a change.

    Args:
        before: Digest (or ``None`` for a file that could not be read) by name.
        after: The same, later.

    Returns:
        The names that differ, sorted.

    Raises:
        TypeError: An argument is not a mapping.
    """
    for name, value in (("before", before), ("after", after)):
        if not isinstance(value, Mapping):
            raise TypeError(f"{name} must be a mapping, not {type(value).__name__}")
    return tuple(
        sorted(
            key
            for key in set(before) | set(after)
            if key not in before or key not in after or before[key] != after[key]
        )
    )


# --------------------------------------------------------------------------------------------
# Files whose content runs (T4-07)
# --------------------------------------------------------------------------------------------

#: The kinds of file that the review named as running code or deciding who may, for the label of
#: :func:`surface_kind` (``(kind, pattern)`` on the path folded to lowercase NFKC, matched against the whole path).
#: It no longer decides what counts as the surface; :func:`execution_surface` does, the other way round.
#: Files that steer an agent or configure what it may run: the steering, agent configuration, skills, hooks and specs
#: below ``.kiro/``, the instruction files of other agent tools, and ``llms.txt``. Most are Markdown, which
#: :data:`DOCUMENTATION_PATTERNS` would pass as prose. They are not prose: a ``.kiro/agents/<name>.md`` can name an
#: MCP server's ``command`` and the permissions of an agent, and an unattended run reads the workspace's agents,
#: hooks and steering without asking (https://kiro.dev/docs/permissions/, read 2026-11-14). Matched against the
#: folded path, as a whole (T4-R3-05).
AGENT_CONTROL_SURFACE: Final = re.compile(
    r"(?:.*/)?\.kiro/.+"
    r"|(?:.*/)?(?:agents?(?:\.override)?|claude(?:\.local)?|gemini|copilot-instructions|cursorrules|skill"
    r"|conventions|warp|codex)\.md"
    r"|(?:.*/)?[^/]+\.(?:prompt|instructions)\.md"
    r"|(?:.*/)?\.cursorrules"
    r"|(?:.*/)?\.github/(?:copilot-instructions\.md|instructions/.+|prompts/.+)"
    r"|(?:.*/)?\.(?:cursor|windsurf|clinerules|continue|codex|gemini|claude|amazonq|roo|aider)/.+"
    r"|(?:.*/)?llms(?:-full)?\.txt"
)
#: Paths with a dotted element that are documents all the same: the templates and community files that GitHub reads from
#: ``.github/`` (matched on the folded path). Any other path with an element that starts with a dot is the execution
#: surface (T4-R4-05): the places where agent products keep their instructions (``.github/agents/``, ``.junie/``,
#: ``.kilocode/``, ``.augment/``, ``.agents/``, ...) are many and new ones appear, so no list of them is kept.
_DOCUMENT_DOT_EXCEPTIONS: Final = re.compile(
    r"\.github/(?:[^/]+\.md|pull_request_template/.+\.md|issue_template/.+\.md)"
)
EXECUTION_SURFACE_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("agent_control", AGENT_CONTROL_SURFACE),
    ("workflow", re.compile(r"\.github/workflows/.+")),
    ("composite_action", re.compile(r"\.github/actions/.+")),
    ("git_hook", re.compile(r"\.(?:githooks|husky)/.+")),
    ("pre_commit", re.compile(r"(?:.*/)?\.pre-commit-config\.ya?ml")),
    ("makefile", re.compile(r"(?:.*/)?(?:makefile|gnumakefile|[^/]+\.mk)")),
    ("shell_script", re.compile(r".+\.(?:sh|bash|zsh)")),
    ("renovate", re.compile(r"(?:.*/)?(?:renovate[^/]*\.json5?|\.renovaterc(?:\.json5?)?)")),
    ("code_owners", re.compile(r"(?:\.github/|docs/)?codeowners")),
    ("vex", re.compile(r"\.vex/.+")),
)


#: Files that are documentation, and so not the execution surface: ``(extension group, pattern)`` on the repository-relative
#: path, folded to lowercase NFKC, each matched against the whole path. Prose and images of any directory;
#: ``.txt`` except the lists that a package manager installs from (``requirements*.txt``, ``constraints*.txt``);
#: ``LICENSE``, ``NOTICE`` and ``COPYING`` files. ``.json`` and ``.yaml`` are not here, also below ``docs/``: a policy
#: file that a gate reads is data that decides what passes (T4-R2-07).
DOCUMENTATION_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"(?:.*/)?[^/]+\.(?:md|markdown|rst|png|jpe?g|gif|svg|webp|ico|drawio|pdf)"),
    re.compile(r"(?:.*/)?(?!requirements|constraints)[^/]+\.txt"),
    re.compile(r"(?:.*/)?(?:license|notice|copying)(?:\.[a-z]+)?"),
)


def _folded(path: str) -> str:
    """The form that the patterns are matched against: NFKC, then case folded."""
    if not isinstance(path, str):
        raise TypeError(f"a path must be a str, not {type(path).__name__}")
    return unicodedata.normalize("NFKC", path).casefold()


def execution_surface(changed_files: Iterable[str]) -> tuple[str, ...]:
    """The changed files that are not documentation (T4-R2-07).
    The list that names the files that run (:data:`EXECUTION_SURFACE_PATTERNS`) was a list of what the review had
    thought of: ``package.json``, a ``Dockerfile``, ``conftest.py`` and the scripts that ``make test`` and CI run
    were not in it. The test is turned round: a file is *not* on the surface only when it matches
    :data:`DOCUMENTATION_PATTERNS`, so a kind of file that nobody listed counts. A Markdown or text file that steers
    an agent (:data:`AGENT_CONTROL_SURFACE`: ``.kiro/``, ``AGENTS.md``, ``CLAUDE.md``, ``llms.txt``, ...) is not
    documentation although it matches, and neither is a path with an element that starts with a dot (T4-R4-05), except
    the community files of ``.github/`` (:data:`_DOCUMENT_DOT_EXCEPTIONS`). ``docs/agents.md`` (a page about agents)
    counts as the surface by its name: it costs one approval, and a name that is read as an instruction file on a
    case-insensitive file system cannot be told apart by its case. ``..`` or an absolute path in a
    name is not documentation either. The match ignores letter case and Unicode normalization. A symbolic link
    named ``x.md`` that points at a script is not seen by a name: git records it as a file.
    Args:
        changed_files: Repository-relative paths.
    Returns:
        The paths that are not documentation, sorted, without duplicates.
    Raises:
        TypeError: A path is not a ``str``.
    """
    found: set[str] = set()
    for path in changed_files:
        folded = _folded(path)
        unsafe = folded.startswith("/") or ".." in folded.split("/")
        steers_agents = AGENT_CONTROL_SURFACE.fullmatch(folded) is not None
        dotted = any(part.startswith(".") for part in folded.split("/")) and not _DOCUMENT_DOT_EXCEPTIONS.fullmatch(
            folded
        )
        if (
            unsafe
            or steers_agents
            or dotted
            or not any(pattern.fullmatch(folded) for pattern in DOCUMENTATION_PATTERNS)
        ):
            found.add(path)
    return tuple(sorted(found))


def surface_kind(path: str) -> str:
    """What kind of execution surface a path is, by :data:`EXECUTION_SURFACE_PATTERNS`, or ``other``.
    A label for the report; whether the path counts is decided by :func:`execution_surface`.
    """
    folded = _folded(path)
    for kind, pattern in EXECUTION_SURFACE_PATTERNS:
        if pattern.fullmatch(folded):
            return kind
    return "other"


#: Added lines with a side effect that a review of unattended changes looks for.
_RISKY_LINE: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("network_fetch", re.compile(r"(?<![A-Za-z0-9_-])(?:curl|wget|nc|ncat)(?![A-Za-z0-9_-])")),
    ("pull_request_target", re.compile(r"\bpull_request_target\b")),
    ("secrets_reference", re.compile(r"\$\{\{\s*secrets\.")),
    ("write_all", re.compile(r"\bpermissions\s*:\s*write-all\b")),
    ("eval_or_decode", re.compile(r"(?<![A-Za-z0-9_-])(?:eval\s|base64\s+(?:-d|--decode))")),
    ("pipe_to_shell", re.compile(r"\|\s*(?:sudo\s+)?(?:ba|z)?sh\b")),
)


def risky_added_lines(diff: str, surface: Iterable[str]) -> tuple[tuple[str, str, int], ...]:
    """Added lines of the execution-surface files of a unified diff that match a risky form.

    Only lines that the diff adds (``+``) under a ``+++ b/<path>`` header of a path in
    ``surface`` are read. The forms are in :data:`_RISKY_LINE`: a network fetch, a
    ``pull_request_target`` trigger, a ``secrets`` reference, ``permissions: write-all``,
    ``eval`` or ``base64 -d``, and a pipe into a shell. A form not listed is not found, and a
    comment that mentions one is found.

    Args:
        diff: ``git diff`` output with ``a/`` and ``b/`` prefixes.
        surface: The paths to read (:func:`execution_surface` of the changed files).

    Returns:
        ``(path, kind, line number in the new file)`` for each match, in diff order. The
        line's text is not returned.

    Raises:
        TypeError: ``diff`` is not a ``str``.
    """
    if not isinstance(diff, str):
        raise TypeError(f"diff must be a str, not {type(diff).__name__}")
    wanted = set(surface)
    found: list[tuple[str, str, int]] = []
    path: str | None = None
    number = 0
    for line in diff.split("\n"):
        if line.startswith("+++ "):
            target = line[4:]
            path = target[2:] if target.startswith("b/") else None
            if path not in wanted:
                path = None
            continue
        if line.startswith("--- ") or line.startswith("diff --git "):
            path = None if line.startswith("diff --git ") else path
            continue
        hunk = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if hunk:
            number = int(hunk.group(1))
            continue
        if path is None:
            continue
        if line.startswith("+"):
            for kind, pattern in _RISKY_LINE:
                if pattern.search(line[1:]):
                    found.append((path, kind, number))
            number += 1
        elif line.startswith(" "):
            number += 1
    return tuple(found)


# --------------------------------------------------------------------------------------------
# Paths cited by a query answer (T4-06)
# --------------------------------------------------------------------------------------------

#: The most paths :func:`cited_paths` returns. A longer answer is cut, and the check is made on those.
CITED_PATH_LIMIT: Final = 200

_URL: Final = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://\S+")
_KNOWN_EXTENSIONS: Final = (
    "md|py|ya?ml|json|toml|sh|txt|ts|tsx|js|mjs|go|rs|tf|cfg|ini|lock|mk|rst|html|css|sql|java|rb|c|h|cpp"
)
_PATH: Final = re.compile(
    r"(?<![A-Za-z0-9_./~@:-])"
    r"(?:\./)?"
    r"(?P<path>(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]*[A-Za-z0-9_-]\.[A-Za-z][A-Za-z0-9]{0,7}"
    rf"|[A-Za-z0-9_-][A-Za-z0-9_.-]*\.(?:{_KNOWN_EXTENSIONS})|(?:Makefile|Dockerfile|LICENSE|CODEOWNERS))"
    r"(?::\d+(?:-\d+)?)?(?![A-Za-z0-9_/-])"
)


_PATH_WITH_LINE: Final = re.compile(_PATH.pattern.replace(r"(?::\d+(?:-\d+)?)?", r"(?::(?P<line>\d+)(?:-\d+)?)?"))


def cited_locations(text: str) -> tuple[tuple[str, int | None], ...]:
    """The paths that an answer names with the first line it names, ``None`` when it names none (T4-R2-11).
    The same reading as :func:`cited_paths`, keeping the ``:line`` (or the start of ``:line-line``) that
    follows a path. A path that appears with and without a line is returned once for each. The line is
    not checked here: the runner checks it against the file at the commit the item started from.
    Args:
        text: The standard output of a query run, decoded.
    Returns:
        ``(path, line)`` pairs in order of first appearance, at most :data:`CITED_PATH_LIMIT`.
    Raises:
        TypeError: ``text`` is not a ``str``.
    """
    if not isinstance(text, str):
        raise TypeError(f"text must be a str, not {type(text).__name__}")
    stripped = _URL.sub(" ", text)
    seen: dict[tuple[str, int | None], None] = {}
    for match in _PATH_WITH_LINE.finditer(stripped):
        path = posixpath.normpath(match.group("path"))
        if path.startswith("../") or path == "..":
            continue
        line = match.group("line")
        seen.setdefault((path, int(line) if line is not None and len(line) < 9 else None), None)
        if len(seen) >= CITED_PATH_LIMIT:
            break
    return tuple(seen)


def cited_paths(text: str) -> tuple[str, ...]:
    """The repository-relative paths that an answer names.

    URLs are removed first. A path is a run of ``/``-separated names that ends in a file name
    with an extension, or a bare file name with a common extension, or ``Makefile``,
    ``Dockerfile``, ``LICENSE`` or ``CODEOWNERS``. A ``./`` prefix and a ``:line`` suffix are
    dropped. A path with a glob character, an absolute path and a ``~`` path are not taken:
    they do not name a file of the checked-out commit.

    A word such as ``e.g.`` or a version such as ``1.2/3.4`` can look like a path; the check
    against the commit then reports it as missing, which a human reads. A path in a form the
    pattern does not know is not found.

    Args:
        text: The standard output of a query run, decoded.

    Returns:
        The distinct paths in order of first appearance, at most :data:`CITED_PATH_LIMIT`.

    Raises:
        TypeError: ``text`` is not a ``str``.
    """
    if not isinstance(text, str):
        raise TypeError(f"text must be a str, not {type(text).__name__}")
    stripped = _URL.sub(" ", text)
    seen: dict[str, None] = {}
    for match in _PATH.finditer(stripped):
        path = posixpath.normpath(match.group("path"))
        if path.startswith("../") or path == "..":
            continue
        seen.setdefault(path, None)
        if len(seen) >= CITED_PATH_LIMIT:
            break
    return tuple(seen)
