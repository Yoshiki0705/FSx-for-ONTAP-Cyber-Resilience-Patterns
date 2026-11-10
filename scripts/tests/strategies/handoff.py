"""Hypothesis strategies for the pure core of the Handoff_Harness (``scripts/handoff/``).

Task 1.11 of the phase 4 spec (Requirement 28.24). The property tests of tasks 1.12 to 1.20
draw their inputs from here, and ``scripts/tests/test_handoff_strategies.py`` checks that each
strategy makes what its docstring says. Import as::

    from strategies import handoff as handoff_strategies

Results. A strategy returns either a plain value or a case object. A case object holds the
input as the I/O layer would pass it (decoded JSON, text) together with what the strategy
planted in it, and a test compares the module's answer with the planted one:

- :func:`configs`: :class:`ConfigCase`, with the checked ``config`` of a valid input or the
  ``expected_issues`` of an invalid one.
- :func:`manifests`: :class:`ManifestCase`, with the checked ``manifest`` of an acyclic input
  or the planted ``cycle`` of a cyclic one, and a template for each item.
- :func:`prompt_vars`: :class:`PromptVars`, with the ``planted`` scan kinds and the
  ``deny_terms``.
- :func:`observations`: :class:`ObservationsCase`, with the ``conditions`` of
  ``evaluate.PRECEDENCE`` that hold.
- :func:`report_texts`: :class:`ReportText`, with the ``flags`` of the request lines.
- :func:`executor_attrs`: :class:`ExecutorAttrsCase`, with the ``rows`` of the executor table.
- Plain values: :func:`paths` and :func:`item_ids` (strings), :func:`statuses` (a status
  built through ``state.transition``) and :func:`confirmed_refs` (a set of refs).

Construction. No strategy uses ``filter`` or ``assume``, so none can trip the
``filter_too_much`` health check. A value that must be avoided is mapped away instead: a
12-digit number skips the account ID placeholders, a drawn subset of conditions is adjusted
when it cannot be met (see :func:`observations`), a fresh directory name is extended until it
differs from every other. (``st.lists(..., unique=True)`` retries a draw that repeats an
element; hypothesis does that internally, and the pools are large enough for it to succeed.)

Synthetic data only. Names, IDs, paths, terms and addresses are made up, and the values that
the leak checks look for (a home path of the ``/Users/`` form, a 12-digit number, an IPv4
address, a case number) are assembled at run time from parts, so this file holds none of them.
The home directory is :data:`HOME`.

Scan-clean text. Every string that :func:`manifests`, :func:`configs` and
:func:`prompt_vars` (with nothing planted) put into a Handoff_Prompt passes
``handoff.scan.check`` with the deny terms of :func:`prompt_vars`:

- No 12-digit number other than the placeholder ``123456789012``: an item ID group has at most
  11 characters and a filler number at most 4 digits, and the digits of a 40-character SHA
  always touch another digit or a letter of the SHA, which keeps them from counting.
- No dotted quad: filler tokens with a dot hold no digit, and tokens are joined by white space.
- No ``case`` or ``ケース``: item IDs and the planted user names leave out ``s``, and the word
  pools hold neither word, so a placeholder or a number cannot follow one.
- No deny term: every deny term starts with ``Zq`` or ``ヅ``. The word pools and the ID
  alphabet hold no ``q``, ``z`` or ``ヅ`` (nor the half-width ``ﾂﾞ`` that NFKC turns into it).
- No unconfirmed ref name in a slot: tag names end in ``-v<n>.<n>.<n>`` and SHAs have 40
  hexadecimal digits, and no filler token has either form.
"""

from __future__ import annotations

import copy
import dataclasses
import string
import unicodedata
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from itertools import combinations
from types import MappingProxyType
from typing import Any, Final

import check_sensitive_patterns as csp
from handoff.config import MODES, REQUIRED_KEYS, HandoffConfig, parse_config
from handoff.evaluate import (
    PRECEDENCE,
    REPORT_FLAG_KINDS,
    REPORT_FLAG_TERMS,
    Observations,
    RerunResult,
    RerunSkip,
    conflicting_files,
    undeclared_files,
)
from handoff.executor import ExecutorAttrs
from handoff.manifest import SYNC_POINTS, Manifest, RequiredRef, parse_manifest
from handoff.prompt import PLACEHOLDERS
from handoff.state import (
    FAILED,
    MAX_SAFE_INTEGER,
    NEEDS_HUMAN,
    QUEUED,
    RUNNING,
    SUCCEEDED,
    StatusDoc,
    add_item,
    empty_status,
    format_timestamp,
    transition,
)
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

# --------------------------------------------------------------------------------------------
# Shared constants and pools
# --------------------------------------------------------------------------------------------

#: The home directory of every generated configuration and of every rendered prompt.
HOME: Final = "/home/example"

#: This repository's own main working tree, passed as ``extra_main_trees``.
THIS_REPO_TREE: Final = HOME + "/Projects/example-this-repo"

#: The IDE session worktree directory, passed as ``session_worktrees_dir``.
SESSION_WORKTREES_DIR: Final = "~/Projects/.kiro-worktrees"

#: Target repository names. One path component each; no two differ only in letter case.
REPO_NAMES: Final[tuple[str, ...]] = (
    "example-hub",
    "example-spoke-a",
    "example-spoke-b",
    "example.spoke_c",
    "Example-Spoke-D",
)

#: Tool names for ``mode_tool_ceiling.change``. Each has the form that ``command.py`` accepts in
#: ``--trust-tools=`` (``[A-Za-z0-9_@][A-Za-z0-9_.:/@-]*``), so a valid configuration never
#: makes ``build_kiro_argv`` refuse on a tool name.
TOOL_NAMES: Final[tuple[str, ...]] = (
    "fs_read",
    "fs_write",
    "example_shell",
    "grep",
    "glob",
    "@example-mcp/search_docs",
)

#: Agent names for ``agents``, of the form that ``command.py`` accepts in ``--agent``.
AGENT_NAMES: Final[tuple[str, ...]] = ("example-query", "example_change.v1")

#: The scan kinds that :func:`prompt_vars` can plant, in the order of ``handoff.scan.KINDS``.
PLANTABLE_KINDS: Final[tuple[str, ...]] = (
    "deny_term",
    "account_id",
    "public_ip",
    "internal_ip",
    "home_path",
    "case_number",
)

#: Path components of :func:`paths`: shared prefixes (``b``, ``bc``), spellings that differ
#: only in letter case or in Unicode normalization, and the special components ``..``, ``.``
#: and ``""`` (which writes ``//``).
_NFC_CAFE: Final = unicodedata.normalize("NFC", "caf\u00e9")
_NFD_CAFE: Final = unicodedata.normalize("NFD", _NFC_CAFE)
PATH_COMPONENTS: Final[tuple[str, ...]] = (
    *(
        "a",
        "b",
        "bc",
        "B",
        "Projects",
        "projects",
        "example-hub",
        "Example-Hub",
        ".kiro-worktrees",
        ".handoff-worktrees",
    ),
    *(_NFC_CAFE, _NFD_CAFE, _NFC_CAFE.upper(), "日本語", "..", ".", ""),
)

#: Lines of a Handoff_Report that hold no headword of ``evaluate.REPORT_FLAG_TERMS``.
REPORT_FILLER: Final[tuple[str, ...]] = (
    "Updated docs/guide.md with one new paragraph.",
    "All verification commands ended with exit code 0.",
    "No file outside the declared list was changed.",
    "The worktree has no uncommitted changes.",
    "Committed 2 changes on the handoff branch.",
    "docs/guide.md に段落を 1 つ足した。",
    "検証の終了コードはすべて 0 だった。",
    "宣言の外のファイルは変えていない。",
    "worktree に未コミットの変更はない。",
    "## 結果",
    "- 変更: 1 件",
    "```text",
    "```",
)

#: The first line of every template that :func:`template_text` writes.
TEMPLATE_COMMENT: Final = "<!-- 合成のテンプレート。scripts/tests/strategies/handoff.py が作る -->"

#: Lowercase letters without ``q`` and ``z`` (the deny-term marker) and ``s`` (so that no
#: ``case`` can be spelled).
_LETTERS: Final = "".join(letter for letter in string.ascii_lowercase if letter not in "qsz")
_ID_CHARACTERS: Final = _LETTERS + string.digits
_HEX_DIGITS: Final = string.digits + "abcdef"

_KIRO_CLI_FORMS: Final = ("~/.local/bin/kiro-cli", HOME + "/.local/bin/kiro-cli", "/opt/example/bin/kiro-cli")
_WORKTREES_ROOT_FORMS: Final = (
    "~/Projects/.handoff-worktrees",
    "~/Projects/.handoff-worktrees/",
    HOME + "/Projects/.handoff-worktrees",
    "~/handoff-worktrees",
    "~/Projects/x/../.handoff-worktrees",
)
_SESSION_DIR_FORMS: Final = (SESSION_WORKTREES_DIR, HOME + "/Projects/.kiro-worktrees/")
_EXTRA_TREE_FORMS: Final = (
    (THIS_REPO_TREE,),
    ("~/Projects/example-this-repo",),
    (THIS_REPO_TREE, "~/Projects/example-other-tree"),
)

_FILE_DIRS: Final = ("docs", ".github/workflows", "scripts", "日本語の文書", "with space")
_FILE_NAMES: Final = (
    *("README.md", "readme.md", "guide.md", "ci.yml", "renovate.json", "Makefile", "日本語.md", "with space.md"),
    *(_NFC_CAFE + ".md", _NFD_CAFE + ".md", "a", "bc"),
)
_GATES: Final = ("AGENTS.md", ".kiro/steering/", "make test の前提", "CI: lint", "pre-commit のフック")
_KNOWLEDGE_KINDS: Final = (".private/ の記録", "memory", "運用の記録", "過去の判断の記録")
_PROGRAMS: Final = ("make", "pytest", "python3", "npm", "aws", "gh", "git")
_PROGRAM_ARGS: Final = tuple(
    "test all lint -q --tb=short scripts/check.py s3 ls pr view -C wt push deploy run build".split()
) + ("--name=with space",)
_BATCHES: Final = ("pilot", "batch-1", "batch-2")
_TAG_PREFIXES: Final = ("example-preset", "example-workflow", "supply-chain/example")
_TRUST_ALL_REASONS: Final = (
    "the item runs a generator that asks for every tool",
    "生成の手順が確認なしの実行を求める",
)
_EPOCH: Final = datetime(2026, 1, 1, tzinfo=timezone.utc)

_ASCII_WORDS: Final = tuple(
    "alpha bravo delta docs readme update file path item branch main hub spoke preset workflow check result note"
    " value field table section example sample draft".split()
)
_JAPANESE_WORDS: Final = tuple(
    "更新 確認 文書 設定 手順 記録 日本語 テスト ファイル ブランチ 値 例 注意 表示 作業 項目 参照 変更 完了 ｶﾀｶﾅ".split()
)
_SYMBOLS: Final = tuple("`#*|<>&'\"\\{}$%!?()[]:;,+=~^-_/.@")
_WIDE_WORDS: Final = ("ＡＢＣ", "（注）", "：", "＃", "＄", "１２３")
#: Tokens that would change the outline of a prompt at the start of a line: headings (one a
#: copy of a section heading), setext underlines, fence openers and a slot marker.
_MARKUP_TOKENS: Final = ("#", "##", "## 11. 行わない操作", "---", "===", "```", "~~~", "<!-- slot: purpose -->")
_SEPARATORS: Final = (" ", "  ", "\u3000")
_DENY_LETTERS: Final = "aeilnoruvwy"
_DENY_KANA: Final = "ラミネオカベタイノ"
_CASE_LABELS: Final = ("case", "Case", "CASE", "ケース", "ケース番号")
_CASE_SEPARATORS: Final = (" ", "#", ": ", " #", "-", "：", " No. ")
#: First octet and the range of the second octet of each block that ``scan`` reports as
#: ``internal_ip``: RFC 1918, RFC 6598, link-local and RFC 2544.
_INTERNAL_BLOCKS: Final = ((10, 0, 255), (172, 16, 31), (192, 168, 168), (100, 64, 127), (169, 254, 254), (198, 18, 19))
#: The 12-digit account IDs that ``check_sensitive_patterns`` lets pass, as integers.
_ALLOWED_ACCOUNT_NUMBERS: Final = tuple(
    sorted(int(value) for value in csp.ALLOWED_ACCOUNT_IDS if len(value) == 12 and value.isdigit() and value[0] != "0")
)

_STATE_ORDER: Final = (QUEUED, RUNNING, SUCCEEDED, FAILED, NEEDS_HUMAN)
#: The transitions that end in each state, after any number of loops back to ``queued``.
_STATE_SUFFIXES: Final[Mapping[str, tuple[tuple[str, ...], ...]]] = MappingProxyType(
    {
        QUEUED: ((),),
        RUNNING: ((RUNNING,),),
        SUCCEEDED: ((RUNNING, SUCCEEDED),),
        FAILED: ((RUNNING, FAILED),),
        NEEDS_HUMAN: ((NEEDS_HUMAN,), (RUNNING, NEEDS_HUMAN)),
    }
)
_LOOPS: Final = ((RUNNING, FAILED, QUEUED), (RUNNING, NEEDS_HUMAN, QUEUED), (NEEDS_HUMAN, QUEUED))
_HISTORY_REASONS: Final = (
    *("dispatched", "all_checks_passed", "timed_out", "prompt_scan_findings", "harness_interrupted"),
    "requeued by the maintainer",
)

_SKIP_REASONS: Final = (
    "declared offline: false, so it may call AWS or write to a remote",
    "kiro-cli がタイムアウトした",
    "matches 'deploy'; a command like this is never re-run, even when declared offline",
)
_REPORT_NOISE: Final = string.digits + " #:;,.()[]-"
_ANSI_OPENERS: Final = ("\x1b[1m", "\x1b[31m", "\x1b[0;32m")
_ANSI_RESET: Final = "\x1b[0m"

#: Every subset of the six rows of the executor table, the empty one first, then by size.
_ROW_SETS: Final[tuple[frozenset[int], ...]] = tuple(
    frozenset(rows) for size in range(7) for rows in combinations(range(1, 7), size)
)


class _Missing:
    """The type of :data:`MISSING`."""

    def __repr__(self) -> str:
        """Show the marker as its name."""
        return "MISSING"


#: The value of a :class:`ConfigDefect` that removes its key instead of writing a value.
MISSING: Final = _Missing()


# --------------------------------------------------------------------------------------------
# configs()
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ConfigDefect:
    """One change that makes a valid ``config.json`` invalid, and the issue it must cause.

    Attributes:
        key: The top-level key that the change writes or removes.
        value: The value written under ``key``, or :data:`MISSING` to remove the key. For the
            two limit keys that ``build_kiro_argv`` checks again, a test can put the value
            into a :class:`handoff.config.HandoffConfig` with ``dataclasses.replace`` (with
            ``None`` for :data:`MISSING`) to reach ``command.py`` without ``parse_config``.
        issue: ``(path, kind)`` of the one :class:`handoff.config.ConfigIssue` that the change
            causes in an otherwise valid configuration.
    """

    key: str
    value: Any
    issue: tuple[str, str]


_BAD_POSITIVE_INTS: Final = (
    (0, "range"),
    (-1, "range"),
    (True, "type"),
    (False, "type"),
    (1.5, "type"),
    ("1800", "type"),
    (None, "type"),
)

#: Every defect that :func:`configs` can plant. At most one is applied per key, and the
#: defects of different keys do not interact, so the issues of a drawn configuration are the
#: union of the planted ones.
CONFIG_DEFECTS: Final[tuple[ConfigDefect, ...]] = (
    *(ConfigDefect(key, MISSING, (key, "missing")) for key in REQUIRED_KEYS),
    *(
        ConfigDefect(key, value, (key, kind))
        for key in ("timeout_seconds", "max_concurrency", "min_free_disk_gb")
        for value, kind in _BAD_POSITIVE_INTS
    ),
    ConfigDefect("schema_version", 2, ("schema_version", "range")),
    ConfigDefect("schema_version", "1", ("schema_version", "type")),
    ConfigDefect("schema_version", True, ("schema_version", "type")),
    ConfigDefect("kiro_cli", "", ("kiro_cli", "format")),
    ConfigDefect("kiro_cli", "   ", ("kiro_cli", "format")),
    ConfigDefect("kiro_cli", 7, ("kiro_cli", "type")),
    ConfigDefect("worktrees_root", "handoff-worktrees", ("worktrees_root", "format")),
    ConfigDefect("worktrees_root", "~other/handoff-worktrees", ("worktrees_root", "format")),
    ConfigDefect("worktrees_root", 42, ("worktrees_root", "type")),
    ConfigDefect("worktrees_root", THIS_REPO_TREE, ("worktrees_root", "overlap")),
    ConfigDefect("worktrees_root", SESSION_WORKTREES_DIR + "/handoff", ("worktrees_root", "overlap")),
    ConfigDefect("worktrees_root", "~/Projects", ("worktrees_root", "overlap")),
    ConfigDefect("worktrees_root", "~", ("worktrees_root", "overlap")),
    ConfigDefect(
        "mode_tool_ceiling",
        {"query": ["fs_read", "fs_write"], "change": ["fs_read"]},
        ("mode_tool_ceiling.query", "format"),
    ),
    ConfigDefect("mode_tool_ceiling", "fs_read", ("mode_tool_ceiling", "type")),
    ConfigDefect("agents", "example-query", ("agents", "type")),
    ConfigDefect("agents", {"query": ""}, ("agents.query", "format")),
    ConfigDefect("agents", {"other": "example-query"}, ("agents.other", "unknown_key")),
    ConfigDefect("repos", [], ("repos", "type")),
    ConfigDefect("repos", {"example-hub": {}}, ("repos.example-hub.main_tree", "missing")),
    ConfigDefect("timeout", 1800, ("timeout", "unknown_key")),
)


@dataclass(frozen=True)
class ConfigCase:
    """A decoded ``config.json``, the arguments ``parse_config`` needs, and the expected result.

    Attributes:
        raw: The decoded JSON value, a new dict for each draw.
        home: The ``home`` argument, :data:`HOME`.
        extra_main_trees: The ``extra_main_trees`` argument.
        session_worktrees_dir: The ``session_worktrees_dir`` argument.
        config: The result of ``parse_config`` for a valid configuration, ``None`` otherwise.
        expected_issues: ``(path, kind)`` of every issue that ``parse_config`` must raise for an
            invalid configuration, and nothing else. Empty for a valid one.
    """

    raw: dict[str, Any]
    home: str
    extra_main_trees: tuple[str, ...]
    session_worktrees_dir: str
    config: HandoffConfig | None
    expected_issues: frozenset[tuple[str, str]]

    @property
    def valid(self) -> bool:
        """Whether the configuration passes ``parse_config``."""
        return self.config is not None

    def parse(self) -> HandoffConfig:
        """Call ``parse_config`` on :attr:`raw` with the stored arguments.

        Returns:
            The checked configuration.

        Raises:
            handoff.config.ConfigError: The configuration is invalid.
        """
        return parse_config(
            self.raw,
            home=self.home,
            extra_main_trees=self.extra_main_trees,
            session_worktrees_dir=self.session_worktrees_dir,
        )


def configs(
    *,
    valid: bool = True,
    min_repos: int = 1,
    max_repos: int = 4,
    defect_keys: Collection[str] | None = None,
    defect_kinds: Collection[str] | None = None,
) -> SearchStrategy[ConfigCase]:
    """Draw a ``config.json`` value, valid or with planted defects.

    A valid configuration has every required key; ``timeout_seconds``, ``max_concurrency`` and
    ``min_free_disk_gb`` from 1 up; ``kiro_cli`` that starts with ``~/`` or ``/``; a
    ``worktrees_root`` under :data:`HOME` that overlaps no protected path; a ``mode_tool_ceiling``
    whose ``query`` is ``["fs_read"]`` and whose ``change`` holds names of :data:`TOOL_NAMES`; zero
    to two agents; and one entry per drawn name of :data:`REPO_NAMES`, each with a main working
    tree ``~/Projects/<name>`` written in one of several equivalent forms (a trailing slash,
    ``./``, ``//``). The paths are under the home directory, so ``prompt.render`` can write them.

    An invalid configuration starts from a valid one and applies one to three defects of
    :data:`CONFIG_DEFECTS`, each to a different key.

    Args:
        valid: Draw a valid configuration (``config`` set) or an invalid one
            (``expected_issues`` set).
        min_repos: Fewest repositories. 0 or more.
        max_repos: Most repositories, at most ``len(REPO_NAMES)``.
        defect_keys: For ``valid=False``, the keys whose defects may be planted, such as
            ``handoff.config.LIMIT_KEYS``. ``None`` allows every key.
        defect_kinds: For ``valid=False``, the issue kinds whose defects may be planted, such
            as ``("missing",)``. ``None`` allows every kind.

    Returns:
        A strategy of :class:`ConfigCase`.

    Raises:
        ValueError: The bounds are out of range, or no defect is left after ``defect_keys``
            and ``defect_kinds``.
    """
    if not 0 <= min_repos <= max_repos <= len(REPO_NAMES):
        raise ValueError(f"need 0 <= min_repos <= max_repos <= {len(REPO_NAMES)}")
    by_key: dict[str, list[ConfigDefect]] = {}
    for defect in CONFIG_DEFECTS:
        if defect_keys is not None and defect.key not in defect_keys:
            continue
        if defect_kinds is not None and defect.issue[1] not in defect_kinds:
            continue
        by_key.setdefault(defect.key, []).append(defect)
    if not valid and not by_key:
        raise ValueError("no defect of CONFIG_DEFECTS has those keys and kinds")
    return _configs(
        valid=valid,
        min_repos=min_repos,
        max_repos=max_repos,
        defects=MappingProxyType({key: tuple(found) for key, found in by_key.items()}),
    )


@st.composite
def _configs(
    draw: st.DrawFn,
    *,
    valid: bool,
    min_repos: int,
    max_repos: int,
    defects: Mapping[str, tuple[ConfigDefect, ...]],
) -> ConfigCase:
    """Draw one :class:`ConfigCase` (see :func:`configs`)."""
    names = draw(st.lists(st.sampled_from(REPO_NAMES), min_size=min_repos, max_size=max_repos, unique=True))
    agents: dict[str, str] = {}
    for mode in MODES:
        agent = draw(st.none() | st.sampled_from(AGENT_NAMES))
        if agent is not None:
            agents[mode] = agent
    raw: dict[str, Any] = {
        "schema_version": 1,
        "kiro_cli": draw(st.sampled_from(_KIRO_CLI_FORMS)),
        "timeout_seconds": draw(st.integers(1, 86_400)),
        "max_concurrency": draw(st.integers(1, 16)),
        "worktrees_root": draw(st.sampled_from(_WORKTREES_ROOT_FORMS)),
        "min_free_disk_gb": draw(st.integers(1, 4_096)),
        "mode_tool_ceiling": {
            "query": ["fs_read"],
            "change": draw(st.lists(st.sampled_from(TOOL_NAMES), min_size=1, unique=True)),
        },
        "agents": agents,
        "repos": {name: {"main_tree": draw(st.sampled_from(_main_tree_forms(name)))} for name in names},
    }
    extra = draw(st.sampled_from(_EXTRA_TREE_FORMS))
    session = draw(st.sampled_from(_SESSION_DIR_FORMS))
    if valid:
        checked = parse_config(raw, home=HOME, extra_main_trees=extra, session_worktrees_dir=session)
        return ConfigCase(raw, HOME, extra, session, checked, frozenset())

    keys = draw(st.lists(st.sampled_from(sorted(defects)), min_size=1, max_size=min(3, len(defects)), unique=True))
    issues: set[tuple[str, str]] = set()
    for key in keys:
        defect = draw(st.sampled_from(defects[key]))
        if defect.value is MISSING:
            raw.pop(key, None)
        else:
            raw[key] = copy.deepcopy(defect.value)
        issues.add(defect.issue)
    return ConfigCase(raw, HOME, extra, session, None, frozenset(issues))


def _main_tree_forms(name: str) -> tuple[str, ...]:
    """Equivalent ways to write the main working tree of one repository."""
    return (f"~/Projects/{name}", f"{HOME}/Projects/{name}/", f"~/Projects/./{name}", f"~/Projects//{name}")


# --------------------------------------------------------------------------------------------
# paths() and item_ids()
# --------------------------------------------------------------------------------------------


def paths(*, home: str = HOME, tilde: bool = True, max_depth: int = 5) -> SearchStrategy[str]:
    """Draw a path as a configuration writes it: absolute, or under ``~``.

    The path starts at ``/``, at ``home`` written out, or (with ``tilde``) at ``~/``; ``~``
    alone is drawn too. Up to ``max_depth`` components follow, from :data:`PATH_COMPONENTS`,
    and a trailing slash is added at random. ``..`` can climb above ``home`` or ``/``. Every
    result is accepted by ``normalize_path(path, home)``, so it can be ``worktrees_root``, a
    ``main_tree``, an entry of ``extra_main_trees`` or ``session_worktrees_dir``.

    The components come from a small pool, so independent draws nest or coincide now and then,
    but two draws that differ only in Unicode normalization are rare (none in 1,000 pairs with
    the seed of the self-check). :func:`related_paths` makes every such relation frequent.

    Args:
        home: The home directory that ``~`` stands for. Absolute.
        tilde: Whether ``~`` forms are drawn.
        max_depth: Most components after the start.

    Returns:
        A strategy of path strings.

    Raises:
        ValueError: ``home`` is not absolute, or ``max_depth`` is negative.
    """
    if not home.startswith("/"):
        raise ValueError(f"home must be absolute, got {home!r}")
    if max_depth < 0:
        raise ValueError("max_depth must be 0 or more")
    starts = ["/", home.rstrip("/") + "/"] + (["~/"] if tilde else [])
    return _paths(starts=tuple(starts), max_depth=max_depth)


@st.composite
def _paths(draw: st.DrawFn, *, starts: tuple[str, ...], max_depth: int) -> str:
    """Draw one path (see :func:`paths`)."""
    start = draw(st.sampled_from(starts))
    parts = draw(st.lists(st.sampled_from(PATH_COMPONENTS), max_size=max_depth))
    if start == "~/" and not parts and draw(st.booleans()):
        return "~"
    path = start + "/".join(parts)
    if parts and draw(st.booleans()):
        path += "/"
    return path


#: The components of :data:`PATH_COMPONENTS` that name a directory: not ``..``, ``.`` or ``""``.
_PATH_NAMES: Final = tuple(part for part in PATH_COMPONENTS if part not in ("..", ".", ""))

#: How :func:`related_paths` derives a path from an earlier one.
PATH_DERIVATIONS: Final[tuple[str, ...]] = (
    "child",
    "longer_name",
    "parent",
    "swapped_case",
    "nfd",
    "nfc",
    "trailing_slash",
    "dot_dot",
    "dot",
    "tilde",
    "fresh",
)


def related_paths(*, home: str = HOME, min_size: int = 2, max_size: int = 6) -> SearchStrategy[tuple[str, ...]]:
    """Draw several paths, most of them derived from an earlier one, for the overlap checks.

    Independent draws of :func:`paths` rarely differ only in Unicode normalization or share a
    string prefix without nesting. Here the first path comes from :func:`paths`, and each later
    one is derived from a drawn earlier one by one of :data:`PATH_DERIVATIONS`:

    - ``child``: a component added (nested); ``parent``: the last component removed
      (containing).
    - ``longer_name``: ``c`` added to the last component (``/a/b`` to ``/a/bc``): a shared
      string prefix, not nested.
    - ``swapped_case``, ``nfd``, ``nfc``: the same path in another spelling.
    - ``trailing_slash``, ``dot_dot`` (``/x/..`` added), ``dot`` (``/.`` added) and ``tilde``
      (``home`` written as ``~`` or back): the same path after ``normalize_path``.
    - ``fresh``: a new path from :func:`paths`.

    Every result is accepted by ``handoff.config.normalize_path(path, home)``. A test of
    Property 25 can hand the paths out as ``worktrees_root``, the session directory and the
    main working trees.

    Args:
        home: The home directory that ``~`` stands for. Absolute.
        min_size: Fewest paths, at least 1.
        max_size: Most paths.

    Returns:
        A strategy of tuples of path strings.

    Raises:
        ValueError: ``home`` is not absolute, or the sizes are out of range.
    """
    if not home.startswith("/"):
        raise ValueError(f"home must be absolute, got {home!r}")
    if not 1 <= min_size <= max_size:
        raise ValueError("need 1 <= min_size <= max_size")
    return _related_paths(home=home.rstrip("/") or "/", min_size=min_size, max_size=max_size)


@st.composite
def _related_paths(draw: st.DrawFn, *, home: str, min_size: int, max_size: int) -> tuple[str, ...]:
    """Draw one family of paths (see :func:`related_paths`)."""
    count = draw(st.integers(min_size, max_size))
    found = [draw(paths(home=home))]
    while len(found) < count:
        origin = draw(st.sampled_from(found))
        found.append(_derived_path(draw, origin, draw(st.sampled_from(PATH_DERIVATIONS)), home))
    return tuple(found)


def _derived_path(draw: st.DrawFn, path: str, how: str, home: str) -> str:
    """Derive a path from ``path`` as :func:`related_paths` describes."""
    stem = path.rstrip("/")
    last = stem.rsplit("/", 1)[-1]
    if how == "child" or (how == "longer_name" and last in ("", "~")):
        return stem + "/" + draw(st.sampled_from(_PATH_NAMES))
    if how == "longer_name":
        return stem + "c"
    if how == "parent":
        head = stem.rsplit("/", 1)[0] if "/" in stem else stem
        return head or "/"
    if how == "swapped_case":
        return path.swapcase()
    if how in ("nfd", "nfc"):
        return unicodedata.normalize(how.upper(), path)
    if how == "trailing_slash":
        return (stem or "/") if path.endswith("/") and path != "/" else path + "/"
    if how == "dot_dot":
        return stem + "/x/.."
    if how == "dot":
        return stem + "/."
    if how == "tilde":
        if path == home or path.startswith(home + "/"):
            return "~" + path[len(home) :]
        if path.startswith("~"):
            return home + path[1:]
        return path
    return draw(paths(home=home))


def item_ids() -> SearchStrategy[str]:
    """Draw an item ID of the manifest's form: ``[a-z0-9]+(-[a-z0-9]+)*``, 64 characters at most.

    One to four groups of one to eleven characters, joined by ``-`` (47 characters at most).
    The letters leave out ``q``, ``s`` and ``z``, and no group can hold 12 digits, so an ID in a
    prompt never looks like a deny term, a case number or an account ID.

    Returns:
        A strategy of IDs.
    """
    return st.lists(st.text(_ID_CHARACTERS, min_size=1, max_size=11), min_size=1, max_size=4).map("-".join)


# --------------------------------------------------------------------------------------------
# prompt_vars() and template_text()
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class PromptVars:
    """Template variables for one item, the deny terms, and what was planted in the values.

    Attributes:
        vars: The variables, as the item's ``vars`` in ``manifest.json``: identifier keys, and
            values that are one non-blank line without NUL or a lone surrogate.
        deny_terms: Synthetic deny terms for ``scan.check`` and ``prompt.render``: ``Zq`` or
            ``ヅ`` followed by letters. Present whether or not one was planted.
        planted: The scan kinds planted in the values, one piece each. ``scan.check`` finds
            exactly these kinds in the values (and, rendered, in the whole body).
        placement: For each variable, in the order of ``vars``, the slot its placeholder goes
            to: 0 for ``purpose``, 1 for ``completion`` (change mode) or ``questions`` (query
            mode).
    """

    vars: dict[str, str]
    deny_terms: tuple[str, ...]
    planted: frozenset[str]
    placement: tuple[int, ...]

    def template_text(self, mode: str) -> str:
        """Write a template that uses every variable once.

        Args:
            mode: ``query`` or ``change``.

        Returns:
            The template text (see :func:`template_text`).
        """
        return template_text(mode, tuple(self.vars), self.placement)


def template_text(mode: str, keys: Sequence[str] = (), placement: Sequence[int] | None = None) -> str:
    """Write a template that ``prompt.render`` accepts for an item of ``mode``.

    The template starts with :data:`TEMPLATE_COMMENT`. The ``purpose`` slot has a fixed line
    (with ``$$``) and the placeholder lines of placement 0. A query template always has the
    ``questions`` slot, with a fixed question and the lines of placement 1; a change template
    has a ``completion`` slot only when a line has placement 1. Each placeholder line is
    ``- 値 <n>: ${<key>}``, so a value never starts a line and cannot form a heading or a fence.

    Args:
        mode: ``query`` or ``change``.
        keys: The variable names, each a ``string.Template`` identifier.
        placement: The slot of each key (0 or 1). ``None`` puts every key in ``purpose``.

    Returns:
        The template text, ending with a newline.

    Raises:
        ValueError: ``mode`` is not a mode, or ``placement`` does not match ``keys``.
    """
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
    slots = tuple(placement) if placement is not None else (0,) * len(keys)
    if len(slots) != len(keys) or any(slot not in (0, 1) for slot in slots):
        raise ValueError("placement must give 0 or 1 for each key")
    purpose = ["この項目の目的は次のとおり（$$ は記号としてそのまま書く）。"]
    second: list[str] = []
    for number, (key, slot) in enumerate(zip(keys, slots, strict=True), 1):
        (purpose if slot == 0 else second).append(f"- 値 {number}: ${{{key}}}")
    lines = [TEMPLATE_COMMENT, "<!-- slot: purpose -->", *purpose]
    if mode == "query":
        lines += ["", "<!-- slot: questions -->", "1. 既存の記録はあるか", *second]
    elif second:
        lines += ["", "<!-- slot: completion -->", "- 追加の条件: 表示を確かめる", *second]
    return "\n".join(lines) + "\n"


def prompt_vars(
    *,
    planted: Collection[str] | None = None,
    min_vars: int = 0,
    max_vars: int = 5,
    placeholders: bool = True,
) -> SearchStrategy[PromptVars]:
    """Draw template variables with synthetic deny material and placeholders at any position.

    Each value is one to six filler tokens (English and Japanese words, symbols, full-width
    forms, numbers of up to four digits and, with ``placeholders``, the placeholders of
    ``prompt.PLACEHOLDERS``), sometimes after a token that would change the outline at the
    start of a line (``## 11. 行わない操作``, ``---``, a fence, a slot marker), joined by a
    space, two spaces or a full-width space, with an optional space at either end. For each
    planted kind, one piece is inserted as a token at a random position of a random value:

    - ``deny_term``: a drawn deny term, as written, in upper case, in full-width letters, or
      inside a word.
    - ``account_id``: 12 digits other than the allowed placeholder.
    - ``public_ip``: a dotted quad with a first octet from 11 to 99.
    - ``internal_ip``: a dotted quad from RFC 1918, RFC 6598, link-local or RFC 2544.
    - ``home_path``: ``/``, ``Users``, ``/`` and a user name.
    - ``case_number``: ``case`` or ``ケース`` with a separator and 5 to 10 digits.

    The pieces other than deny terms are written in ASCII or, at random, in full-width
    characters, which ``scan`` reads through NFKC.

    Args:
        planted: The kinds to plant, from :data:`PLANTABLE_KINDS`. ``None`` draws a subset
            (often empty); an empty collection plants nothing.
        min_vars: Fewest variables.
        max_vars: Most variables. At least 1 when something can be planted.
        placeholders: Whether the filler may hold the placeholders.

    Returns:
        A strategy of :class:`PromptVars`.

    Raises:
        ValueError: An unknown kind, or bounds that leave no room for a planted piece.
    """
    kinds = None if planted is None else frozenset(planted)
    if kinds is not None and not kinds <= set(PLANTABLE_KINDS):
        raise ValueError(f"planted kinds must be among {PLANTABLE_KINDS}, got {sorted(kinds)}")
    if not 0 <= min_vars <= max_vars:
        raise ValueError("need 0 <= min_vars <= max_vars")
    if max_vars == 0 and kinds != frozenset():
        raise ValueError("planting needs max_vars >= 1; pass planted=() for no variables")
    return _prompt_vars(planted=kinds, min_vars=min_vars, max_vars=max_vars, placeholders=placeholders)


@st.composite
def _prompt_vars(
    draw: st.DrawFn, *, planted: frozenset[str] | None, min_vars: int, max_vars: int, placeholders: bool
) -> PromptVars:
    """Draw one :class:`PromptVars` (see :func:`prompt_vars`)."""
    kinds = planted if planted is not None else frozenset(draw(st.sets(st.sampled_from(PLANTABLE_KINDS))))
    count = draw(st.integers(max(min_vars, 1 if kinds else 0), max_vars))
    keys = draw(st.lists(_identifiers(), min_size=count, max_size=count, unique=True))
    tokens = [
        draw(st.lists(_markup_tokens(), max_size=1))
        + draw(st.lists(_filler_tokens(placeholders), min_size=1, max_size=6))
        for _ in keys
    ]
    terms = tuple(draw(st.lists(_deny_terms(), min_size=1 if "deny_term" in kinds else 0, max_size=3, unique=True)))
    for kind in PLANTABLE_KINDS:
        if kind in kinds:
            target = tokens[draw(st.integers(0, count - 1))]
            target.insert(draw(st.integers(0, len(target))), draw(_planted_piece(kind, terms)))
    values = [draw(_joined(parts)) for parts in tokens]
    placement = tuple(draw(st.integers(0, 1)) for _ in keys)
    return PromptVars(
        vars=dict(zip(keys, values, strict=True)),
        deny_terms=terms,
        planted=kinds,
        placement=placement,
    )


def _identifiers() -> SearchStrategy[str]:
    """Draw a ``string.Template`` identifier: ASCII letters, digits and ``_``, not starting with a digit."""
    return st.builds(
        str.__add__,
        st.sampled_from(string.ascii_letters + "_"),
        st.text(string.ascii_letters + string.digits + "_", max_size=11),
    )


def _markup_tokens() -> SearchStrategy[str]:
    """Draw a token that would be a heading, a setext underline, a fence or a slot marker at a line start."""
    return st.sampled_from(_MARKUP_TOKENS)


def _filler_tokens(placeholders: bool) -> SearchStrategy[str]:
    """Draw one filler token of a value (see :func:`prompt_vars`)."""
    choices: list[SearchStrategy[str]] = [
        st.sampled_from(_ASCII_WORDS),
        st.sampled_from(_JAPANESE_WORDS),
        st.sampled_from(_SYMBOLS),
        st.sampled_from(_WIDE_WORDS),
        st.integers(0, 9_999).map(str),
    ]
    if placeholders:
        choices.append(st.sampled_from(PLACEHOLDERS))
    return st.one_of(choices)


def _deny_terms() -> SearchStrategy[str]:
    """Draw a synthetic deny term: ``Zq`` and three to seven letters, or ``ヅ`` and two to four kana."""
    latin = st.text(_DENY_LETTERS, min_size=3, max_size=7).map("Zq".__add__)
    kana = st.text(_DENY_KANA, min_size=2, max_size=4).map("ヅ".__add__)
    return latin | kana


@st.composite
def _planted_piece(draw: st.DrawFn, kind: str, terms: tuple[str, ...]) -> str:
    """Draw one piece that ``scan.check`` reports as ``kind`` (see :func:`prompt_vars`)."""
    if kind == "deny_term":
        term = draw(st.sampled_from(terms))
        form = draw(st.sampled_from(("as_written", "upper", "full_width", "inside_a_word")))
        if form == "upper":
            return term.upper()
        if form == "full_width":
            return _full_width(term)
        if form == "inside_a_word":
            return draw(st.sampled_from(_ASCII_WORDS)) + term + draw(st.sampled_from(_ASCII_WORDS))
        return term
    if kind == "account_id":
        number = draw(st.integers(10**11, 10**12 - 1 - len(_ALLOWED_ACCOUNT_NUMBERS)))
        for allowed in _ALLOWED_ACCOUNT_NUMBERS:
            if number >= allowed:
                number += 1
        text = str(number)
    elif kind == "public_ip":
        text = ".".join(str(octet) for octet in (draw(st.integers(11, 99)), *_octets(draw, 3)))
    elif kind == "internal_ip":
        first, low, high = draw(st.sampled_from(_INTERNAL_BLOCKS))
        text = ".".join(str(octet) for octet in (first, draw(st.integers(low, high)), *_octets(draw, 2)))
    elif kind == "home_path":
        text = "/".join(("", "Users", draw(st.text(_LETTERS, min_size=1, max_size=12))))
    elif kind == "case_number":
        label = draw(st.sampled_from(_CASE_LABELS))
        text = label + draw(st.sampled_from(_CASE_SEPARATORS)) + str(draw(st.integers(10_000, 9_999_999_999)))
    else:
        raise ValueError(f"cannot plant {kind!r}")
    return _full_width(text) if draw(st.booleans()) else text


def _octets(draw: st.DrawFn, count: int) -> list[int]:
    """Draw ``count`` octets from 0 to 255."""
    return [draw(st.integers(0, 255)) for _ in range(count)]


@st.composite
def _joined(draw: st.DrawFn, parts: Sequence[str]) -> str:
    """Join the tokens of one value with drawn separators, with an optional space at either end."""
    text = parts[0]
    for part in parts[1:]:
        text += draw(st.sampled_from(_SEPARATORS)) + part
    return draw(st.sampled_from(("", " "))) + text + draw(st.sampled_from(("", " ")))


def _full_width(text: str) -> str:
    """Write the printable ASCII characters of a text in full-width form, and spaces as U+3000."""
    return "".join(
        chr(ord(char) + 0xFEE0) if "!" <= char <= "~" else "\u3000" if char == " " else char for char in text
    )


# --------------------------------------------------------------------------------------------
# manifests() and confirmed_refs()
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ManifestCase:
    """A decoded ``manifest.json``, its configuration, and the expected result.

    Attributes:
        config_case: The valid configuration the manifest is checked against.
        raw: The decoded JSON value, a new dict for each draw.
        manifest: The result of ``parse_manifest`` for an acyclic manifest, ``None`` for a
            cyclic one.
        cycle: For a cyclic manifest, the item IDs of the planted cycle: each depends on the
            next, and the last on the first (one ID depends on itself). Empty otherwise.
        templates: A template for each item that ``prompt.render`` accepts with the item's
            current ``vars`` (see :meth:`with_prompt_vars`).
    """

    config_case: ConfigCase
    raw: dict[str, Any]
    manifest: Manifest | None
    cycle: tuple[str, ...]
    templates: Mapping[str, str]

    @property
    def config(self) -> HandoffConfig:
        """The checked configuration."""
        checked = self.config_case.config
        if checked is None:
            raise AssertionError("a ManifestCase always has a valid configuration")
        return checked

    @property
    def ids(self) -> tuple[str, ...]:
        """The item IDs, in manifest order."""
        return tuple(item["id"] for item in self.raw["items"])

    def template_text(self, item_id: str) -> str:
        """The template to render an item with.

        Args:
            item_id: An item of the manifest.

        Returns:
            The template text.
        """
        return self.templates[item_id]

    def with_prompt_vars(self, item_id: str, prompt_vars: PromptVars) -> ManifestCase:
        """Return a copy in which one item has the variables of ``prompt_vars`` and their template.

        The manifest is checked again (variables never fail the check), so :attr:`manifest`
        holds the new variables.

        Args:
            item_id: An item of the manifest.
            prompt_vars: The variables, from :func:`prompt_vars`.

        Returns:
            The new case. This one is not changed.

        Raises:
            KeyError: The manifest has no such item.
        """
        raw = copy.deepcopy(self.raw)
        entry = next((item for item in raw["items"] if item["id"] == item_id), None)
        if entry is None:
            raise KeyError(item_id)
        entry["vars"] = dict(prompt_vars.vars)
        templates = dict(self.templates)
        templates[item_id] = prompt_vars.template_text(entry["mode"])
        checked = None if self.manifest is None else parse_manifest(raw, config=self.config)
        return dataclasses.replace(self, raw=raw, manifest=checked, templates=MappingProxyType(templates))


def manifests(
    *,
    config: ConfigCase | None = None,
    cyclic: bool = False,
    min_items: int = 1,
    max_items: int = 6,
    modes: Sequence[str] = MODES,
    max_files: int = 4,
    max_refs: int = 2,
    provided_refs: bool = True,
) -> SearchStrategy[ManifestCase]:
    """Draw a manifest whose items pass every check, with or without a dependency cycle.

    Items get distinct IDs from :func:`item_ids`, repositories of the configuration, any
    Sync_Point, and modes from ``modes``. The dependencies follow a drawn topological order
    that is independent of the manifest order, so an item can depend on an item written after
    it. Per mode:

    - Change: one to ``max_files`` declared files (case and NFC/NFD spellings included), up to
      three verification commands with drawn ``offline`` flags, trusted tools from the change
      ceiling, ``trust_all`` absent or complete, and up to ``max_refs`` refs. A ref's repository
      is the repository of a direct dependency, so the ``ordering`` rule holds; with
      ``provided_refs`` the item's own repository is used only when a dependency is in it, so
      ``prompt.render`` can name the Handoff that confirms each unconfirmed ref.
    - Query: no declared files, commands or refs, ``trust_tools`` ``["fs_read"]``,
      ``trust_all`` null, and at least one of ``gates``, ``knowledge_kinds``, ``read_paths``,
      ``artifact_paths``, so a row of the executor table applies.

    Every item has ``vars`` ``{}``; :attr:`ManifestCase.templates` has a template without
    placeholders for each, and :meth:`ManifestCase.with_prompt_vars` swaps in variables.

    With ``cyclic``, one to four distinct items are joined into a cycle (each depends on the
    next) after the acyclic dependencies are drawn; one item that depends on itself is a cycle
    of one. The only issues of such a manifest are ``cycle`` issues.

    Args:
        config: The configuration to use. ``None`` draws one from :func:`configs`.
        cyclic: Plant a cycle.
        min_items: Fewest items (at least 1 when ``cyclic``).
        max_items: Most items.
        modes: The modes to draw from.
        max_files: Most declared files of a change item, at least 1.
        max_refs: Most refs of a change item.
        provided_refs: Draw a ref of the item's own repository only when a dependency is in
            that repository.

    Returns:
        A strategy of :class:`ManifestCase`.

    Raises:
        ValueError: The bounds are out of range, a mode is unknown, or ``config`` is invalid or
            has no repository.
    """
    if config is not None and (config.config is None or not config.config.repos):
        raise ValueError("config must be a valid ConfigCase with at least one repository")
    low = max(min_items, 1) if cyclic else min_items
    if not 0 <= low <= max_items:
        raise ValueError("need 0 <= min_items <= max_items, and max_items >= 1 for a cycle")
    if not modes or any(mode not in MODES for mode in modes):
        raise ValueError(f"modes must be a non-empty subset of {MODES}")
    if max_files < 1 or max_refs < 0:
        raise ValueError("need max_files >= 1 and max_refs >= 0")
    return _manifests(
        config=config,
        cyclic=cyclic,
        min_items=low,
        max_items=max_items,
        modes=tuple(modes),
        max_files=max_files,
        max_refs=max_refs,
        provided_refs=provided_refs,
    )


@st.composite
def _manifests(
    draw: st.DrawFn,
    *,
    config: ConfigCase | None,
    cyclic: bool,
    min_items: int,
    max_items: int,
    modes: tuple[str, ...],
    max_files: int,
    max_refs: int,
    provided_refs: bool,
) -> ManifestCase:
    """Draw one :class:`ManifestCase` (see :func:`manifests`)."""
    config_case = config if config is not None else draw(configs())
    checked_config = config_case.config
    if checked_config is None:
        raise AssertionError("configs() drew an invalid configuration for a manifest")
    repos = sorted(checked_config.repos)
    count = draw(st.integers(min_items, max_items))
    ids = draw(st.lists(item_ids(), min_size=count, max_size=count, unique=True))
    rank = draw(st.permutations(range(count)))
    repo_of = [draw(st.sampled_from(repos)) for _ in ids]
    mode_of = [draw(st.sampled_from(modes)) for _ in ids]

    depends: list[list[int]] = []
    for index in range(count):
        earlier = [other for other in range(count) if rank[other] < rank[index]]
        chosen = draw(st.lists(st.sampled_from(earlier), max_size=min(3, len(earlier)), unique=True)) if earlier else []
        depends.append(chosen)
    cycle: tuple[str, ...] = ()
    if cyclic:
        length = draw(st.integers(1, min(count, 4)))
        members = draw(st.lists(st.integers(0, count - 1), min_size=length, max_size=length, unique=True))
        for position, member in enumerate(members):
            target = members[(position + 1) % length]
            if target not in depends[member]:
                depends[member].append(target)
        cycle = tuple(ids[member] for member in members)

    items: list[dict[str, Any]] = []
    for index in range(count):
        linkable = {repo_of[other] for other in depends[index]}
        if not provided_refs:
            linkable.add(repo_of[index])
        items.append(
            draw(
                _raw_items(
                    item_id=ids[index],
                    repo=repo_of[index],
                    mode=mode_of[index],
                    depends_on=tuple(ids[other] for other in depends[index]),
                    linkable=tuple(sorted(linkable)),
                    ceiling=checked_config.mode_tool_ceiling["change"],
                    max_files=max_files,
                    max_refs=max_refs,
                )
            )
        )
    raw = {"schema_version": 1, "items": items}
    checked = None if cyclic else parse_manifest(raw, config=checked_config)
    templates = MappingProxyType({ids[index]: template_text(mode_of[index]) for index in range(count)})
    return ManifestCase(config_case=config_case, raw=raw, manifest=checked, cycle=cycle, templates=templates)


@st.composite
def _raw_items(
    draw: st.DrawFn,
    *,
    item_id: str,
    repo: str,
    mode: str,
    depends_on: tuple[str, ...],
    linkable: tuple[str, ...],
    ceiling: tuple[str, ...],
    max_files: int,
    max_refs: int,
) -> dict[str, Any]:
    """Draw the JSON value of one item (see :func:`manifests`)."""
    change = mode == "change"
    refs: list[dict[str, str]] = []
    if change and linkable and max_refs:
        refs = draw(
            st.lists(
                _raw_refs(linkable),
                max_size=max_refs,
                unique_by=lambda ref: (ref["repo"], ref["kind"], ref["name"]),
            )
        )
    item: dict[str, Any] = {
        "id": item_id,
        "repo": repo,
        "sync_point": draw(st.sampled_from(SYNC_POINTS)),
        "mode": mode,
        "template": f"templates/{item_id}.md",
        "vars": {},
        "depends_on": list(depends_on),
        "requires_refs": refs,
        "trust_tools": (
            draw(st.lists(st.sampled_from(ceiling), min_size=1, max_size=len(ceiling), unique=True))
            if change
            else ["fs_read"]
        ),
        "trust_all": draw(st.none() | _trust_alls()) if change else None,
        "declared_files": (
            draw(st.lists(_relative_paths(), min_size=1, max_size=max_files, unique=True)) if change else []
        ),
        "verify_commands": (
            [
                {"cmd": list(argv), "offline": draw(st.booleans())}
                for argv in draw(st.lists(_argvs(), max_size=3, unique=True))
            ]
            if change
            else []
        ),
        "batch": draw(st.none() | st.sampled_from(_BATCHES)),
    }
    item.update(draw(_executor_lists(query=not change)))
    return item


@st.composite
def _executor_lists(draw: st.DrawFn, *, query: bool) -> dict[str, list[str]]:
    """Draw ``gates``, ``knowledge_kinds``, ``read_paths`` and ``artifact_paths``; one is not empty for a query."""
    pools: dict[str, SearchStrategy[str]] = {
        "gates": st.sampled_from(_GATES),
        "knowledge_kinds": st.sampled_from(_KNOWLEDGE_KINDS),
        "read_paths": _relative_paths(),
        "artifact_paths": _relative_paths().map(".private/handoff/".__add__),
    }
    forced = draw(st.sampled_from(sorted(pools))) if query else None
    return {
        name: draw(st.lists(pool, min_size=1 if name == forced else 0, max_size=2, unique=True))
        for name, pool in pools.items()
    }


def _relative_paths() -> SearchStrategy[str]:
    """Draw a repository-relative path in normal form: an optional directory, ``part-<n>`` and a file name."""
    return st.builds(
        _join_path,
        st.sampled_from(("", *_FILE_DIRS)),
        st.just("") | st.integers(1, 99).map("part-{}".format),
        st.sampled_from(_FILE_NAMES),
    )


def _join_path(*parts: str) -> str:
    """Join the non-empty parts with ``/``."""
    return "/".join(part for part in parts if part)


def _argvs() -> SearchStrategy[tuple[str, ...]]:
    """Draw the argv of a verification command: a program and up to three arguments."""
    return st.builds(
        lambda program, arguments: (program, *arguments),
        st.sampled_from(_PROGRAMS),
        st.lists(st.sampled_from(_PROGRAM_ARGS), max_size=3),
    )


@st.composite
def _raw_refs(draw: st.DrawFn, linkable: tuple[str, ...]) -> dict[str, str]:
    """Draw one entry of ``requires_refs`` for a repository of ``linkable``."""
    kind = draw(st.sampled_from(("tag", "sha")))
    if kind == "sha":
        name = draw(st.text(_HEX_DIGITS, min_size=40, max_size=40))
    else:
        major, minor, patch = (draw(st.integers(0, 99)) for _ in range(3))
        name = f"{draw(st.sampled_from(_TAG_PREFIXES))}-v{major}.{minor}.{patch}"
    return {"repo": draw(st.sampled_from(linkable)), "kind": kind, "name": name}


@st.composite
def _trust_alls(draw: st.DrawFn) -> dict[str, str]:
    """Draw a complete ``trust_all``: a reason, an approval time and a record under ``.private/``."""
    moment = _EPOCH + timedelta(seconds=draw(st.integers(0, 10**8)))
    return {
        "reason": draw(st.sampled_from(_TRUST_ALL_REASONS)),
        "approved_at": format_timestamp(moment),
        "approved_in": ".private/tasks/" + draw(item_ids()) + ".md",
    }


def confirmed_refs(manifest: Manifest, *, extra: bool = True) -> SearchStrategy[frozenset[RequiredRef]]:
    """Draw the refs that the IN-2 check confirmed: each ref of the manifest, or not.

    Args:
        manifest: A checked manifest.
        extra: Whether to add up to two refs of a repository that no configuration has
            (``example-unlisted``), which no item requires and which must change nothing.

    Returns:
        A strategy of sets of :class:`handoff.manifest.RequiredRef`.
    """
    refs = sorted(
        {ref for item in manifest.items for ref in item.requires_refs},
        key=lambda ref: (ref.repo, ref.kind, ref.name),
    )
    return _confirmed_refs(refs=tuple(refs), extra=extra)


@st.composite
def _confirmed_refs(draw: st.DrawFn, *, refs: tuple[RequiredRef, ...], extra: bool) -> frozenset[RequiredRef]:
    """Draw one set of confirmed refs (see :func:`confirmed_refs`)."""
    chosen = {ref for ref in refs if draw(st.booleans())}
    if extra:
        unlisted = st.integers(0, 99).map(
            lambda major: RequiredRef("example-unlisted", "tag", f"unlisted-v{major}.0.0")
        )
        chosen.update(draw(st.lists(unlisted, max_size=2)))
    return frozenset(chosen)


# --------------------------------------------------------------------------------------------
# statuses()
# --------------------------------------------------------------------------------------------


def statuses(
    *,
    ids: Sequence[str] | None = None,
    max_running: int | None = None,
    max_outside: int = 0,
    payloads: bool = False,
) -> SearchStrategy[StatusDoc]:
    """Draw a status built with ``state.empty_status``, ``state.add_item`` and ``state.transition``.

    Each item gets a drawn state and a history that reaches it along allowed edges: zero to
    two loops back to ``queued`` (through ``failed`` or ``needs-human``), then the edges to the
    state. The timestamps never decrease; the first is a drawn moment between 2026 and 2029.

    Args:
        ids: The item IDs that must have a record, such as every ID of a manifest. ``None``
            draws up to six IDs from :func:`item_ids`.
        max_running: Most ``running`` records in the whole status, the records outside
            ``ids`` included (``dag.select`` counts them all). ``None`` sets no bound.
        max_outside: Most extra records whose IDs (``outside_<n>``) are not in ``ids``, as an
            item removed from the manifest leaves behind. They can be in any state.
        payloads: Fill the fields that other modules own (``pid``, ``worktree``, ``branch``,
            ``base_sha``, ``report``, ``observations``, ``rerun``, ``rerun_skipped``,
            ``report_flags``, ``published``, ``selftest``) with JSON values within the data
            model of ``state.check_status`` (integers within ``±MAX_SAFE_INTEGER``, finite
            floats, no lone surrogate, shallow nesting, nothing shared), and use free text as
            history reasons. Otherwise the fields keep the values of ``add_item``.

    Returns:
        A strategy of statuses that pass ``state.check_status``.

    Raises:
        ValueError: ``ids`` repeats an ID or holds an empty one, or a bound is negative.
    """
    names = None if ids is None else tuple(ids)
    if names is not None and (len(set(names)) != len(names) or not all(isinstance(n, str) and n for n in names)):
        raise ValueError("ids must be distinct non-empty strings")
    if (max_running is not None and max_running < 0) or max_outside < 0:
        raise ValueError("max_running and max_outside must be 0 or more")
    return _statuses(ids=names, max_running=max_running, max_outside=max_outside, payloads=payloads)


@st.composite
def _statuses(
    draw: st.DrawFn, *, ids: tuple[str, ...] | None, max_running: int | None, max_outside: int, payloads: bool
) -> StatusDoc:
    """Draw one status (see :func:`statuses`)."""
    names = list(ids) if ids is not None else draw(st.lists(item_ids(), max_size=6, unique=True))
    for number in range(draw(st.integers(0, max_outside))):
        outside = f"outside_{number}"
        while outside in names:
            outside += "_"
        names.append(outside)
    reasons = _nonblank_texts() if payloads else st.sampled_from(_HISTORY_REASONS)
    moment = _EPOCH + timedelta(seconds=draw(st.integers(0, 10**8)))
    status = empty_status()
    running = 0
    for name in names:
        status = add_item(status, name)
        room = max_running is None or running < max_running
        target = draw(st.sampled_from(_STATE_ORDER if room else tuple(s for s in _STATE_ORDER if s != RUNNING)))
        running += target == RUNNING
        steps = [step for loop in draw(st.lists(st.sampled_from(_LOOPS), max_size=2)) for step in loop]
        steps += draw(st.sampled_from(_STATE_SUFFIXES[target]))
        for step in steps:
            moment += timedelta(seconds=draw(st.integers(0, 3_600)))
            status = transition(status, name, step, at=format_timestamp(moment), reason=draw(reasons))
    if payloads:
        status["selftest"] = draw(st.none() | _json_objects())
        for record in status["items"].values():
            record["pid"] = draw(st.none() | st.integers(1, MAX_SAFE_INTEGER))
            record["worktree"] = draw(st.none() | st.text(min_size=1, max_size=12))
            record["branch"] = draw(st.none() | st.text(min_size=1, max_size=12))
            record["base_sha"] = draw(st.none() | st.text(min_size=1, max_size=12))
            record["report"] = draw(st.none() | st.text(min_size=1, max_size=12))
            record["observations"] = draw(st.none() | _json_objects())
            record["rerun"] = draw(st.lists(_json_values(), max_size=3))
            record["rerun_skipped"] = draw(st.lists(_json_values(), max_size=3))
            record["report_flags"] = draw(st.lists(_json_values(), max_size=3))
            record["published"] = draw(_json_objects())
    return status


def _json_values() -> SearchStrategy[Any]:
    """Draw a JSON value within the data model of ``state.check_status``, nested a few levels at most."""
    scalars = (
        st.none()
        | st.booleans()
        | st.integers(-MAX_SAFE_INTEGER, MAX_SAFE_INTEGER)
        | st.floats(allow_nan=False, allow_infinity=False)
        | st.text(max_size=8)
    )
    return st.recursive(
        scalars,
        lambda children: st.lists(children, max_size=3) | st.dictionaries(st.text(max_size=8), children, max_size=3),
        max_leaves=6,
    )


def _json_objects() -> SearchStrategy[dict[str, Any]]:
    """Draw a JSON object of :func:`_json_values`."""
    return st.dictionaries(st.text(max_size=8), _json_values(), max_size=3)


def _nonblank_texts() -> SearchStrategy[str]:
    """Draw free text with at least one character that is not white space. Line breaks may occur."""
    anchor = st.characters(exclude_categories=("Cs", "Cc", "Zs", "Zl", "Zp"))
    return st.builds(lambda head, middle, tail: head + middle + tail, st.text(max_size=8), anchor, st.text(max_size=8))


# --------------------------------------------------------------------------------------------
# observations()
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ObservationsCase:
    """Observations of one run, the declaration they belong to, and the conditions planted.

    Attributes:
        mode: ``query`` or ``change``, the ``mode`` of ``evaluate.final_state``.
        declared_files: The ``declared_files`` of ``final_state``.
        verify_commands: The ``verify_commands`` of ``final_state``, each argv once.
        default_branch_files: The files changed on the default branch, as passed to
            ``evaluate.conflicting_files``.
        batch_files: The files changed by the other items of the batch, as passed to
            ``conflicting_files``.
        conditions: The conditions of ``evaluate.PRECEDENCE`` that hold for these
            observations, as planted. ``final_state`` returns exactly these as reasons.
        observations: The observations. ``undeclared_files`` and ``conflicts`` were computed
            with ``evaluate.undeclared_files`` and ``evaluate.conflicting_files``.
    """

    mode: str
    declared_files: tuple[str, ...]
    verify_commands: tuple[tuple[str, ...], ...]
    default_branch_files: tuple[str, ...]
    batch_files: tuple[str, ...]
    conditions: frozenset[str]
    observations: Observations


#: The conditions that need a verification command each.
_RERUN_CONDITIONS: Final = ("rerun_unaccounted", "rerun_failed")


def observations(
    *,
    mode: str | None = None,
    declared_files: Sequence[str] | None = None,
    verify_commands: Sequence[Sequence[str]] | None = None,
    conditions: Collection[str] | None = None,
) -> SearchStrategy[ObservationsCase]:
    """Draw the observations of one run by first deciding which conditions hold.

    A subset of the conditions of ``evaluate.PRECEDENCE`` that apply is drawn (often empty,
    which gives ``succeeded``), or taken from ``conditions``, and the observations are built to
    meet exactly that subset:

    - ``no_commits`` applies to the change mode and ``empty_output`` to the query mode;
      ``rerun_unaccounted`` and ``rerun_failed`` need a verification command each.
    - For a drawn subset, two adjustments keep it possible: a conflict without declared files
      also makes ``undeclared_files`` hold (every changed file is then undeclared), and with one
      command ``rerun_failed`` is dropped when ``rerun_unaccounted`` is drawn too. A given
      ``conditions`` is not adjusted; one that cannot be met is refused.
    - Changed files are declared files, plus, for ``undeclared_files``, paths in a fresh
      directory or declared files with their letter case swapped (an exact comparison calls
      those undeclared).
    - Conflicts come from files that ``conflicting_files`` must match: a changed file written
      as it is, with its case swapped, in upper case, or in NFD or NFC, put on the default
      branch or in the batch. Other files of both sides are in a fresh directory.
    - Each declared command is re-run with exit code 0 or not, skipped with a reason, or left
      unaccounted, as the conditions require; re-runs are in a drawn order.

    Args:
        mode: The mode. ``None`` draws one, or takes the one that ``conditions`` needs.
        declared_files: The declared files, such as an item's ``declared_files``. ``None``
            draws one to five paths for the change mode and none for the query mode.
        verify_commands: The argvs, such as an item's ``verify_commands``. ``None`` draws up to
            three for the change mode and none for the query mode, and as many as
            ``conditions`` needs.
        conditions: The exact conditions to plant, such as ``{"conflicts"}``. ``None`` draws a
            subset.

    Returns:
        A strategy of :class:`ObservationsCase`.

    Raises:
        ValueError: ``mode`` is not a mode, a condition is unknown, or ``conditions`` cannot
            be met with the given mode, declared files and commands.
    """
    if mode is not None and mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
    declared = None if declared_files is None else tuple(declared_files)
    commands = None if verify_commands is None else tuple(dict.fromkeys(tuple(argv) for argv in verify_commands))
    wanted = None if conditions is None else frozenset(conditions)
    if wanted is not None:
        mode = _mode_for_conditions(wanted, mode, declared, commands)
    return _observations(mode=mode, declared_files=declared, verify_commands=commands, conditions=wanted)


def _mode_for_conditions(
    wanted: frozenset[str],
    mode: str | None,
    declared: tuple[str, ...] | None,
    commands: tuple[tuple[str, ...], ...] | None,
) -> str | None:
    """Check that a given set of conditions can be met, and return the mode it needs, if any.

    Raises:
        ValueError: A condition is unknown, or the set cannot be met.
    """
    known = {condition for condition, _ in PRECEDENCE}
    if not wanted <= known:
        raise ValueError(f"unknown conditions {sorted(wanted - known)}")
    needs = {mode} if mode is not None else set(MODES)
    if "no_commits" in wanted:
        needs &= {"change"}
    if "empty_output" in wanted:
        needs &= {"query"}
    conflict_needs_declared = "conflicts" in wanted and "undeclared_files" not in wanted
    if conflict_needs_declared and declared is None:
        needs &= {"change"}
    if not needs:
        raise ValueError(f"no mode meets {sorted(wanted)}")
    if conflict_needs_declared and declared == ():
        raise ValueError("a conflict without undeclared files needs a declared file")
    if commands is not None and len(commands) < len(wanted & set(_RERUN_CONDITIONS)):
        raise ValueError(f"{sorted(wanted & set(_RERUN_CONDITIONS))} need one verification command each")
    return mode if mode is not None else (next(iter(needs)) if len(needs) == 1 else None)


def _applicable_conditions(mode: str, commands: tuple[tuple[str, ...], ...]) -> tuple[str, ...]:
    """The conditions of ``PRECEDENCE`` that can hold for the mode and the commands."""
    found: list[str] = []
    for condition, _ in PRECEDENCE:
        if condition == "no_commits" and mode != "change":
            continue
        if condition == "empty_output" and mode != "query":
            continue
        if condition in ("rerun_unaccounted", "rerun_failed") and not commands:
            continue
        found.append(condition)
    return tuple(found)


@st.composite
def _observations(
    draw: st.DrawFn,
    *,
    mode: str | None,
    declared_files: tuple[str, ...] | None,
    verify_commands: tuple[tuple[str, ...], ...] | None,
    conditions: frozenset[str] | None,
) -> ObservationsCase:
    """Draw one :class:`ObservationsCase` (see :func:`observations`)."""
    mode = mode if mode is not None else draw(st.sampled_from(MODES))
    change = mode == "change"
    if declared_files is not None:
        declared = declared_files
    else:
        declared = tuple(draw(st.lists(_relative_paths(), min_size=1, max_size=5, unique=True))) if change else ()
    needed = 0 if conditions is None else len(conditions & set(_RERUN_CONDITIONS))
    if verify_commands is not None:
        commands = verify_commands
    else:
        most = 3 if change else needed
        commands = tuple(draw(st.lists(_argvs(), min_size=needed, max_size=max(most, needed), unique=True)))

    if conditions is not None:
        planted = set(conditions)
    else:
        planted = set(draw(st.sets(st.sampled_from(_applicable_conditions(mode, commands)))))
        if "conflicts" in planted and not declared:
            planted.add("undeclared_files")
        if len(commands) < 2 and set(_RERUN_CONDITIONS) <= planted:
            planted.discard("rerun_failed")
    holds = frozenset(planted)

    changed = draw(st.lists(st.sampled_from(declared), max_size=len(declared), unique=True)) if declared else []
    if "conflicts" in holds and "undeclared_files" not in holds and not changed:
        changed.append(draw(st.sampled_from(declared)))
    if "undeclared_files" in holds:
        fresh = _fresh_directory("extra", declared)
        for path in draw(st.lists(_undeclared_paths(declared, fresh), min_size=1, max_size=3, unique=True)):
            if path not in changed:
                changed.append(path)

    other = _fresh_directory("other", changed)
    default_side = [f"{other}/{path}" for path in draw(st.lists(_relative_paths(), max_size=3))]
    batch_side = [f"{other}/{path}" for path in draw(st.lists(_relative_paths(), max_size=3))]
    if "conflicts" in holds:
        for path in draw(st.lists(st.sampled_from(changed), min_size=1, max_size=len(changed), unique=True)):
            spelled = draw(st.sampled_from(_spellings(path)))
            (default_side if draw(st.booleans()) else batch_side).append(spelled)

    nonzero = st.integers(1, 255) | st.integers(-64, -1) | st.sampled_from((MAX_SAFE_INTEGER, -MAX_SAFE_INTEGER))
    order = draw(st.permutations(range(len(commands))))
    category: dict[int, str] = {}
    pending = list(order)
    if "rerun_unaccounted" in holds:
        category[pending.pop(0)] = "unaccounted"
    if "rerun_failed" in holds:
        category[pending.pop(0)] = "failed"
    allowed = ["passed", "skipped"]
    allowed += [
        name
        for name, condition in (("unaccounted", "rerun_unaccounted"), ("failed", "rerun_failed"))
        if condition in holds
    ]
    for index in pending:
        category[index] = draw(st.sampled_from(allowed))
    run = [index for index in range(len(commands)) if category[index] in ("passed", "failed")]
    rerun = tuple(
        RerunResult(commands[index], draw(nonzero) if category[index] == "failed" else 0)
        for index in draw(st.permutations(run))
    )
    skipped = tuple(
        RerunSkip(commands[index], draw(st.sampled_from(_SKIP_REASONS) | _nonblank_texts()))
        for index in range(len(commands))
        if category[index] == "skipped"
    )

    if "empty_output" in holds:
        stdout_bytes = 0
    else:
        stdout_bytes = draw(st.integers(0 if change else 1, MAX_SAFE_INTEGER))
    if change:
        commits = 0 if "no_commits" in holds else draw(st.integers(1, MAX_SAFE_INTEGER))
    else:
        commits = draw(st.integers(0, MAX_SAFE_INTEGER))
    observed = Observations(
        exit_code=draw(nonzero) if "exit_code_nonzero" in holds else 0,
        timed_out="timed_out" in holds,
        stdout_bytes=stdout_bytes,
        commits=commits,
        changed_files=tuple(changed),
        undeclared_files=undeclared_files(changed, declared),
        dirty="dirty" in holds,
        conflicts=conflicting_files(changed, default_side, batch_side),
        remote_branch_exists="remote_branch_exists" in holds,
        main_tree_change=("relevant" if "main_tree_changed" in holds else draw(st.sampled_from(("none", "unrelated")))),
        rerun=rerun,
        rerun_skipped=skipped,
    )
    return ObservationsCase(
        mode=mode,
        declared_files=declared,
        verify_commands=commands,
        default_branch_files=tuple(default_side),
        batch_files=tuple(batch_side),
        conditions=holds,
        observations=observed,
    )


@st.composite
def _undeclared_paths(draw: st.DrawFn, declared: tuple[str, ...], fresh: str) -> str:
    """Draw a changed path that is not exactly a declared one."""
    if declared and draw(st.booleans()):
        variant = draw(st.sampled_from(declared)).swapcase()
        if variant not in declared:
            return variant
    return f"{fresh}/{draw(_relative_paths())}"


def _spellings(path: str) -> tuple[str, ...]:
    """Spellings of a path that ``conflicting_files`` treats as the same file."""
    candidates = (
        path,
        path.swapcase(),
        path.upper(),
        unicodedata.normalize("NFD", path),
        unicodedata.normalize("NFC", path),
    )
    return tuple(dict.fromkeys(candidates))


def _fresh_directory(base: str, paths: Collection[str]) -> str:
    """A top-level directory name that no path in ``paths`` starts with, ignoring case and normalization."""
    used = {_fold(path.split("/", 1)[0]) for path in paths}
    name = base
    while _fold(name) in used:
        name += "-x"
    return name


def _fold(text: str) -> str:
    """Fold a text as ``evaluate`` and ``config`` compare paths: NFD, case fold, NFD."""
    return unicodedata.normalize("NFD", unicodedata.normalize("NFD", text).casefold())


# --------------------------------------------------------------------------------------------
# report_texts()
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ReportText:
    """A Handoff_Report text and the lines planted in it that ask for something.

    Attributes:
        text: The text. Lines end with LF or CRLF; a line can hold ANSI escapes, a form feed or
            U+2028, none of which ``evaluate.report_flags`` counts as a line break.
        flags: ``(line, kind)`` for each planted request line and each kind it holds, ordered
            by line and then by ``evaluate.REPORT_FLAG_KINDS``. Lines are numbered from 1,
            split at LF only. ``report_flags(text)`` returns exactly these.
    """

    text: str
    flags: tuple[tuple[int, str], ...]


def report_texts(*, requests: bool | None = None, max_lines: int = 12) -> SearchStrategy[ReportText]:
    """Draw a report with synthetic request lines mixed in at any line.

    Other lines are filler without a headword (:data:`REPORT_FILLER`, the same with ANSI
    colors, runs of digits and punctuation, blank lines). A request line holds one or two
    headwords of ``evaluate.REPORT_FLAG_TERMS``, possibly of the same kind, each disguised in
    ways that ``report_flags`` folds back: upper case, full-width letters, extra white space
    (tabs, U+3000, U+2028) between words, a zero-width space, ANSI escapes. Noise that starts
    and ends with a digit stands between the two headwords of a line and, or nothing, at its
    ends. No headword holds a digit, so none can form across a boundary.

    Args:
        requests: ``True`` for at least one request line, ``False`` for none, ``None`` for any
            number.
        max_lines: Most lines, at least 1 when ``requests`` is ``True``.

    Returns:
        A strategy of :class:`ReportText`.

    Raises:
        ValueError: ``max_lines`` is out of range.
    """
    if max_lines < (1 if requests else 0):
        raise ValueError("max_lines must leave room for the lines asked for")
    return _report_texts(requests=requests, max_lines=max_lines)


@st.composite
def _report_texts(draw: st.DrawFn, *, requests: bool | None, max_lines: int) -> ReportText:
    """Draw one :class:`ReportText` (see :func:`report_texts`)."""
    count = draw(st.integers(1 if requests else 0, max_lines))
    forced = draw(st.integers(1, count)) if requests else None
    lines: list[str] = []
    flags: list[tuple[int, str]] = []
    for number in range(1, count + 1):
        if requests is not False and (number == forced or draw(st.booleans())):
            line, kinds = draw(_request_lines())
            flags += [(number, kind) for kind in REPORT_FLAG_KINDS if kind in kinds]
        else:
            line = draw(_filler_lines())
        lines.append(line + draw(st.sampled_from(("", "\r"))))
    text = "\n".join(lines) + (draw(st.sampled_from(("", "\n"))) if lines else "")
    return ReportText(text=text, flags=tuple(flags))


@st.composite
def _request_lines(draw: st.DrawFn) -> tuple[str, frozenset[str]]:
    """Draw a line with one or two disguised headwords, and the kinds of those headwords."""
    kinds = draw(st.lists(st.sampled_from(REPORT_FLAG_KINDS), min_size=1, max_size=2))
    pieces = [draw(st.just("") | _digit_noise())]
    for position, kind in enumerate(kinds):
        if position:
            pieces.append(draw(_digit_noise()))
        pieces.append(draw(_disguised(draw(st.sampled_from(REPORT_FLAG_TERMS[kind])))))
    pieces.append(draw(st.just("") | _digit_noise()))
    return "".join(pieces), frozenset(kinds)


def _digit_noise() -> SearchStrategy[str]:
    """Draw noise that starts and ends with a digit and holds no letter."""
    return st.builds(
        lambda head, middle, tail: head + middle + tail,
        st.sampled_from(string.digits),
        st.text(_REPORT_NOISE, max_size=4),
        st.sampled_from(string.digits),
    )


@st.composite
def _disguised(draw: st.DrawFn, term: str) -> str:
    """Disguise a headword in ways that the folding of ``report_flags`` undoes."""
    text = term
    if text.isascii():
        if draw(st.booleans()):
            text = text.upper()
        if draw(st.booleans()):
            text = _full_width(text)
        elif " " in text and draw(st.booleans()):
            text = text.replace(" ", draw(st.sampled_from(("  ", "\t", " \u2028", "\u3000"))))
    if len(text) > 1 and draw(st.booleans()):
        cut = draw(st.integers(1, len(text) - 1))
        text = text[:cut] + "\u200b" + text[cut:]
    if draw(st.booleans()):
        text = draw(st.sampled_from(_ANSI_OPENERS)) + text + _ANSI_RESET
    return text


@st.composite
def _filler_lines(draw: st.DrawFn) -> str:
    """Draw a line without a headword."""
    shape = draw(st.sampled_from(("sentence", "colored", "noise", "blank")))
    if shape == "sentence":
        return draw(st.sampled_from(REPORT_FILLER))
    if shape == "colored":
        return draw(st.sampled_from(_ANSI_OPENERS)) + draw(st.sampled_from(REPORT_FILLER)) + _ANSI_RESET
    if shape == "noise":
        return draw(st.text(_REPORT_NOISE + "\u3000\f\u2028", max_size=12))
    return ""


# --------------------------------------------------------------------------------------------
# executor_attrs()
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ExecutorAttrsCase:
    """Attributes for ``executor.choose`` and the rows of the executor table they apply to.

    Attributes:
        attrs: The attributes.
        rows: The rows planted: row 3 when ``uncommitted_count`` is above 0, each other row
            when its attribute is not empty.
    """

    attrs: ExecutorAttrs
    rows: frozenset[int]


def executor_attrs(*, allow_no_row: bool = False) -> SearchStrategy[ExecutorAttrsCase]:
    """Draw executor attributes for a drawn set of rows of the executor table.

    The set of rows is drawn with ``sampled_from`` from the 63 non-empty subsets of rows 1 to
    6, or from all 64 with ``allow_no_row``, so every combination can be drawn and each row
    applies in about half of the draws. A row in the set gets one to four entries of free text
    (one non-blank line each, duplicates possible) or, for row 3, a count from 1 to
    ``MAX_SAFE_INTEGER``; a row outside the set gets no entry, or 0.

    Args:
        allow_no_row: Include the set in which no row applies, which ``executor.choose``
            rejects.

    Returns:
        A strategy of :class:`ExecutorAttrsCase`.
    """
    return _executor_attrs(row_sets=_ROW_SETS if allow_no_row else _ROW_SETS[1:])


@st.composite
def _executor_attrs(draw: st.DrawFn, *, row_sets: tuple[frozenset[int], ...]) -> ExecutorAttrsCase:
    """Draw one :class:`ExecutorAttrsCase` (see :func:`executor_attrs`)."""
    rows = draw(st.sampled_from(row_sets))
    entries = {
        row: draw(st.lists(_line_texts(), min_size=1, max_size=4)) if row in rows else [] for row in (1, 2, 4, 5, 6)
    }
    attrs = ExecutorAttrs(
        changed_paths=entries[1],
        gates=entries[2],
        uncommitted_count=draw(st.integers(1, MAX_SAFE_INTEGER)) if 3 in rows else 0,
        knowledge_kinds=entries[4],
        read_paths=entries[5],
        artifact_paths=entries[6],
    )
    return ExecutorAttrsCase(attrs=attrs, rows=rows)


def _line_texts() -> SearchStrategy[str]:
    """Draw one non-blank line of free text: no line break of any kind, no NUL, no lone surrogate."""
    character = st.characters(exclude_categories=("Cs", "Cc", "Zl", "Zp"))
    anchor = st.characters(exclude_categories=("Cs", "Cc", "Zs", "Zl", "Zp"))
    return st.builds(
        lambda head, middle, tail: head + middle + tail,
        st.text(character, max_size=6),
        anchor,
        st.text(character, max_size=6),
    )
