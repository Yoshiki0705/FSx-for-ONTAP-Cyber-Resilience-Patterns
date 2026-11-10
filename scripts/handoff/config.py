"""Check the Handoff_Harness configuration (``.private/handoff/config.json``).

Part of the pure core described in ``scripts/handoff/__init__.py``: this module reads no
file. The I/O layer (``cli.py``) reads and decodes ``config.json`` and passes the decoded
value to :func:`parse_config`, together with what only the I/O layer can know: the home
directory, this repository's own main working tree, and the directory where IDE sessions
keep their worktrees. When :func:`parse_config` raises :class:`ConfigError`, the I/O
layer exits with code 2 before any I/O other than reading the configuration (design
section 20).

Rules (design section 20 and Data Models; Requirements 28.5, 28.7 and 28.11):

- Every key is required and none has a default value. A missing key is reported, never
  filled in. This includes the four keys of decision D-14 (:data:`LIMIT_KEYS`).
- ``timeout_seconds``, ``max_concurrency`` and ``min_free_disk_gb`` are integers of 1 or
  more, with no upper bound. ``true`` and ``false`` are rejected although ``bool`` is a
  subclass of ``int`` in Python, and so are floats and strings, even ``1800.0`` and
  ``"1800"``.
- ``worktrees_root`` must not equal, lie inside, or contain a protected path: a main
  working tree (each ``repos.<name>.main_tree`` and the trees the caller adds) or the IDE
  session worktree directory. Containing one is rejected too, because the harness creates
  ``<worktrees_root>/<repo>/<id>``, which could then land in a protected tree.
- ``mode_tool_ceiling.query`` is exactly ``["fs_read"]``. ``mode_tool_ceiling.change`` is
  a non-empty list of non-empty strings; the name of the shell tool is decided later.
- ``schema_version`` is 1, ``kiro_cli`` is a non-empty string, ``agents`` maps a mode to a
  non-empty agent name (a mode without an agent is left out), and each ``repos.<name>``
  has a string ``main_tree``. A key that this module does not read is reported as
  ``unknown_key``: no key is optional in the sense of being silently ignored.
- Every problem is collected and raised together, in one :class:`ConfigError`.

Paths are compared lexically:

- :func:`normalize_path` expands ``~`` with the home directory given by the caller and
  applies ``posixpath.normpath``, which drops a trailing slash and resolves ``.`` and
  ``..``. A main working tree must also be absolute after the expansion; a relative one
  could not be compared.
- :func:`is_within` compares component by component, so ``/a/bc`` is not inside
  ``/a/b``. It ignores letter case and Unicode normalization (NFD, case fold, NFD again),
  because the default APFS format on macOS is case-insensitive, and on such a volume NFC
  and NFD spellings of a name were also observed to open the same file. On a file system
  that tells them apart, this rejects more paths than needed, never fewer.
- Symbolic links are not resolved, since that would read the file system: a
  ``worktrees_root`` that reaches a main working tree through a symbolic link passes
  here. The I/O layer can call :func:`overlaps` again on ``os.path.realpath`` results
  before it creates a worktree.

Unit of ``min_free_disk_gb``: one GiB, 2**30 bytes (:data:`DISK_UNIT_BYTES`). It is the
unit of ``df -g``, in which the design's disk figures were taken.
:attr:`HandoffConfig.min_free_disk_bytes` converts the value for comparison with
``shutil.disk_usage(...).free``, so the unit is decided here and nowhere else.
"""

from __future__ import annotations

import json
import posixpath
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, TypeVar

#: The only ``schema_version`` this module reads.
SCHEMA_VERSION = 1

#: The modes of a handoff item.
MODES: tuple[str, ...] = ("query", "change")

#: The only tool ceiling accepted for the query mode.
QUERY_TOOL_CEILING: tuple[str, ...] = ("fs_read",)

#: The keys of decision D-14. Without one of them the harness does not start.
LIMIT_KEYS: tuple[str, ...] = ("timeout_seconds", "max_concurrency", "worktrees_root", "min_free_disk_gb")

#: Every top-level key. All are required.
REQUIRED_KEYS: tuple[str, ...] = (
    "schema_version",
    "kiro_cli",
    "timeout_seconds",
    "max_concurrency",
    "worktrees_root",
    "min_free_disk_gb",
    "mode_tool_ceiling",
    "agents",
    "repos",
)

#: Bytes in one unit of ``min_free_disk_gb``: a GiB, the 1024**3-byte block of ``df -g``.
DISK_UNIT_BYTES = 1024**3

IssueKind = Literal["missing", "type", "range", "format", "overlap", "unknown_key"]

_T = TypeVar("_T")

#: Stands for a key that is absent, so that ``null`` stays a value of its own.
_MISSING: Any = object()

_PLAIN_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")


@dataclass(frozen=True)
class ConfigIssue:
    """One problem in the configuration.

    Attributes:
        path: Where the problem is, as a key path: keys joined with ``.``, list indices
            in brackets, and a key that is not a plain name in brackets as a JSON string.
            Examples: ``timeout_seconds``, ``repos.example-hub.main_tree``,
            ``mode_tool_ceiling.change[1]``, ``repos["a.b"].main_tree``. ``$`` is the
            configuration as a whole.
        kind: ``missing`` (a required key is absent), ``type`` (the JSON type is wrong),
            ``range`` (an integer out of range, or an unsupported ``schema_version``),
            ``format`` (the type is right and the shape is not: an empty string, a path
            that is not absolute after ``~`` expansion, a query ceiling other than
            ``["fs_read"]``), ``overlap`` (``worktrees_root`` meets a protected path) or
            ``unknown_key`` (a key that this module does not read).
        detail: An explanation for the maintainer. It can contain local paths, so it
            belongs in local output, not in a tracked file.
    """

    path: str
    kind: IssueKind
    detail: str

    def __str__(self) -> str:
        """Render the issue as one line: ``<path>: <kind>: <detail>``."""
        return f"{self.path}: {self.kind}: {self.detail}"


class ConfigError(ValueError):
    """The configuration was rejected.

    Attributes:
        issues: Every problem found, not only the first, in a fixed order: the same
            configuration always gives the same list.
    """

    def __init__(self, issues: Iterable[ConfigIssue]) -> None:
        """Keep the issues and use one line per issue as the message.

        Args:
            issues: One or more problems.
        """
        self.issues: tuple[ConfigIssue, ...] = tuple(issues)
        super().__init__("\n".join(str(issue) for issue in self.issues))


@dataclass(frozen=True)
class RepoConfig:
    """One entry of ``repos``.

    Attributes:
        main_tree: The repository's main working tree, normalized like ``worktrees_root``.
    """

    main_tree: str


@dataclass(frozen=True)
class HandoffConfig:
    """A configuration that passed every check.

    Attributes:
        schema_version: Always :data:`SCHEMA_VERSION`.
        kiro_cli: The ``kiro_cli`` value as written, with ``~`` not expanded.
        timeout_seconds: Seconds after which a ``kiro-cli`` run is stopped. 1 or more.
        max_concurrency: The most items that run at the same time. 1 or more.
        worktrees_root: The directory for the harness's worktrees: absolute, ``~``
            expanded, normalized, letter case kept. It does not equal, lie inside, or
            contain any protected path given to :func:`parse_config`.
        min_free_disk_gb: Free disk space, in GiB, required before a worktree is
            created. 1 or more.
        mode_tool_ceiling: For each mode in :data:`MODES`, the tools that an item of that
            mode may trust. ``query`` is :data:`QUERY_TOOL_CEILING`.
        agents: The agent configuration name for each mode that has one. Can be empty.
        repos: The target repositories by name.
    """

    schema_version: int
    kiro_cli: str
    timeout_seconds: int
    max_concurrency: int
    worktrees_root: str
    min_free_disk_gb: int
    mode_tool_ceiling: Mapping[str, tuple[str, ...]]
    agents: Mapping[str, str]
    repos: Mapping[str, RepoConfig]

    @property
    def min_free_disk_bytes(self) -> int:
        """``min_free_disk_gb`` in bytes, to compare with ``shutil.disk_usage(...).free``."""
        return self.min_free_disk_gb * DISK_UNIT_BYTES


def parse_config(
    raw: Mapping[str, Any],
    *,
    home: str,
    extra_main_trees: Iterable[str],
    session_worktrees_dir: str,
) -> HandoffConfig:
    """Check a decoded ``config.json`` and return it as a :class:`HandoffConfig`.

    Args:
        raw: The decoded JSON value. A value that is not a mapping is rejected.
        home: The absolute home directory, used to expand ``~``. It is an argument so
            that this module does not read the environment.
        extra_main_trees: Main working trees to protect in addition to every
            ``repos.<name>.main_tree``. It must name at least this repository's own main
            working tree, which ``repos`` does not list. ``~`` is expanded.
        session_worktrees_dir: The directory where IDE sessions keep their worktrees
            (``~/Projects/.kiro-worktrees``). ``~`` is expanded.

    Returns:
        The checked configuration.

    Raises:
        ConfigError: The configuration has one or more problems, all of them in
            ``issues``.
        ValueError: An argument other than ``raw`` cannot be used: ``home`` or a
            protected path is not absolute after ``~`` expansion, or
            ``extra_main_trees`` is empty. This is a fault of the caller, not of the
            configuration, so it is not a :class:`ConfigError`.
        TypeError: ``extra_main_trees`` is one string instead of a collection of paths.
    """
    if not home.startswith("/"):
        raise ValueError(f"home must be an absolute path, got {home!r}")
    if isinstance(extra_main_trees, str):
        raise TypeError("extra_main_trees must be a collection of paths, not one string")
    main_trees = [_argument_path(tree, home, "extra_main_trees") for tree in extra_main_trees]
    if not main_trees:
        raise ValueError("extra_main_trees must name at least this repository's own main working tree")
    session_dir = _argument_path(session_worktrees_dir, home, "session_worktrees_dir")

    if not isinstance(raw, Mapping):
        raise ConfigError([ConfigIssue("$", "type", f"must be a JSON object, got {_describe(raw)}")])

    issues: list[ConfigIssue] = []
    found = {key: _take(raw, (key,), issues) for key in REQUIRED_KEYS}

    schema_version = _schema_version(found["schema_version"], issues)
    kiro_cli = _non_empty_string(found["kiro_cli"], ("kiro_cli",), issues)
    timeout_seconds = _positive_int(found["timeout_seconds"], "timeout_seconds", issues)
    max_concurrency = _positive_int(found["max_concurrency"], "max_concurrency", issues)
    worktrees_root = _absolute_path(found["worktrees_root"], ("worktrees_root",), home, issues)
    min_free_disk_gb = _positive_int(found["min_free_disk_gb"], "min_free_disk_gb", issues)
    ceiling = _tool_ceiling(found["mode_tool_ceiling"], issues)
    agents = _agents(found["agents"], issues)
    repos = _repos(found["repos"], home, issues)

    if worktrees_root is not None:
        protected = [
            (f"the main working tree in {_key_path('repos', name)}", repo.main_tree)
            for name, repo in (repos or {}).items()
        ]
        protected += [("a main working tree given by the caller", tree) for tree in main_trees]
        protected.append(("the IDE session worktree directory", session_dir))
        issues.extend(_overlap_issues(worktrees_root, protected))
    issues.extend(_unknown_keys(raw, REQUIRED_KEYS, ()))

    if issues:
        raise ConfigError(issues)
    return HandoffConfig(
        schema_version=_present(schema_version),
        kiro_cli=_present(kiro_cli),
        timeout_seconds=_present(timeout_seconds),
        max_concurrency=_present(max_concurrency),
        worktrees_root=_present(worktrees_root),
        min_free_disk_gb=_present(min_free_disk_gb),
        mode_tool_ceiling=MappingProxyType(_present(ceiling)),
        agents=MappingProxyType(_present(agents)),
        repos=MappingProxyType(_present(repos)),
    )


def normalize_path(path: str, home: str) -> str:
    """Normalize a path without reading the file system.

    ``~`` alone, or followed by ``/``, is replaced by ``home``. The result goes through
    ``posixpath.normpath``, which removes a trailing slash, repeated slashes and ``.``
    components, and resolves ``..`` against the component before it. This is lexical:
    ``link/..`` becomes the directory that holds ``link`` even when ``link`` is a
    symbolic link to somewhere else. Two leading slashes, which ``normpath`` keeps, become
    one.

    Args:
        path: The path as written.
        home: The absolute home directory.

    Returns:
        The normalized absolute path, with its letter case kept.

    Raises:
        ValueError: ``home`` is not absolute, ``path`` uses the ``~user`` form (which
            needs the user database), or ``path`` is not absolute after ``~``
            expansion.
    """
    if not home.startswith("/"):
        raise ValueError(f"home must be an absolute path, got {home!r}")
    if path == "~" or path.startswith("~/"):
        path = home + path[1:]
    elif path.startswith("~"):
        raise ValueError(f"the ~user form is not supported, got {path!r}")
    if not path.startswith("/"):
        raise ValueError(f"must be an absolute path or start with ~/, got {path!r}")
    return _lexical(path)


def is_within(path: str, parent: str) -> bool:
    """Tell whether ``path`` is ``parent`` or lies below it.

    Both paths are normalized lexically and compared component by component, ignoring
    letter case and Unicode normalization. ``/a/bc`` is not within ``/a/b``; ``/A/b/c`` is
    within ``/a/B``.

    Args:
        path: An absolute path.
        parent: An absolute path.

    Returns:
        True when the components of ``parent`` are the first components of ``path``.

    Raises:
        ValueError: One of the paths is not absolute. Expand ``~`` with
            :func:`normalize_path` first.
    """
    inner = _components(path)
    outer = _components(parent)
    return inner[: len(outer)] == outer


def overlaps(a: str, b: str) -> bool:
    """Tell whether one of two absolute paths is the other or lies below it.

    Args:
        a: An absolute path.
        b: An absolute path.

    Returns:
        ``is_within(a, b) or is_within(b, a)``.

    Raises:
        ValueError: One of the paths is not absolute.
    """
    return is_within(a, b) or is_within(b, a)


def _argument_path(path: str, home: str, name: str) -> str:
    """Normalize a protected path given as an argument, naming the argument on failure."""
    try:
        return normalize_path(path, home)
    except ValueError as exc:
        raise ValueError(f"{name}: {exc}") from exc


def _lexical(path: str) -> str:
    """Apply ``posixpath.normpath`` to an absolute path and keep one leading slash."""
    return "/" + posixpath.normpath(path).lstrip("/")


def _components(path: str) -> tuple[str, ...]:
    """Split an absolute path into components folded for comparison (NFD, case fold, NFD)."""
    if not path.startswith("/"):
        raise ValueError(f"must be an absolute path, got {path!r}")
    folded = unicodedata.normalize("NFD", unicodedata.normalize("NFD", _lexical(path)).casefold())
    return tuple(part for part in folded.split("/") if part)


def _key_path(*parts: str | int) -> str:
    """Render the location of a value for :attr:`ConfigIssue.path`. No parts is ``$``."""
    rendered = ""
    for part in parts:
        if isinstance(part, int):
            rendered += f"[{part}]"
        elif _PLAIN_KEY.fullmatch(part):
            rendered += f".{part}" if rendered else part
        else:
            rendered += f"[{json.dumps(part, ensure_ascii=False)}]"
    return rendered or "$"


def _describe(value: Any) -> str:
    """Show a value as JSON for an issue detail, clipped to 80 characters."""
    text = json.dumps(value, ensure_ascii=False, default=repr)
    return text if len(text) <= 80 else text[:77] + "..."


def _present(value: _T | None) -> _T:
    """Return a checked value. Every check that gives ``None`` has recorded an issue."""
    if value is None:
        raise AssertionError("a check rejected a value without recording an issue")
    return value


def _take(mapping: Mapping[str, Any], where: tuple[str, ...], issues: list[ConfigIssue]) -> Any:
    """Return ``mapping[where[-1]]``, or record a ``missing`` issue and return ``_MISSING``."""
    if where[-1] in mapping:
        return mapping[where[-1]]
    issues.append(ConfigIssue(_key_path(*where), "missing", "required; there is no default value"))
    return _MISSING


def _unknown_keys(mapping: Mapping[Any, Any], known: tuple[str, ...], where: tuple[str, ...]) -> list[ConfigIssue]:
    """Report the keys of ``mapping`` that are not in ``known``, in sorted order."""
    return [
        ConfigIssue(_key_path(*where, key), "unknown_key", "not read by the harness")
        for key in sorted(map(str, mapping))
        if key not in known
    ]


def _schema_version(value: Any, issues: list[ConfigIssue]) -> int | None:
    """Check ``schema_version``: the integer :data:`SCHEMA_VERSION`, not ``true``."""
    if value is _MISSING:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        issues.append(ConfigIssue("schema_version", "type", f"must be an integer, got {_describe(value)}"))
        return None
    if value != SCHEMA_VERSION:
        issues.append(ConfigIssue("schema_version", "range", f"only {SCHEMA_VERSION} is supported, got {value}"))
        return None
    return value


def _positive_int(value: Any, key: str, issues: list[ConfigIssue]) -> int | None:
    """Check an integer of 1 or more. ``bool``, floats and strings are type errors."""
    if value is _MISSING:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        issues.append(ConfigIssue(key, "type", f"must be an integer, got {_describe(value)}"))
        return None
    if value < 1:
        issues.append(ConfigIssue(key, "range", f"must be 1 or more, got {value}"))
        return None
    return value


def _non_empty_string(value: Any, where: tuple[str | int, ...], issues: list[ConfigIssue]) -> str | None:
    """Check a string that is not empty or only white space."""
    if value is _MISSING:
        return None
    if not isinstance(value, str):
        issues.append(ConfigIssue(_key_path(*where), "type", f"must be a string, got {_describe(value)}"))
        return None
    if not value.strip():
        issues.append(ConfigIssue(_key_path(*where), "format", "must not be empty"))
        return None
    return value


def _absolute_path(value: Any, where: tuple[str, ...], home: str, issues: list[ConfigIssue]) -> str | None:
    """Check a path string and return it normalized by :func:`normalize_path`."""
    if value is _MISSING:
        return None
    if not isinstance(value, str):
        issues.append(ConfigIssue(_key_path(*where), "type", f"must be a string, got {_describe(value)}"))
        return None
    try:
        return normalize_path(value, home)
    except ValueError as exc:
        issues.append(ConfigIssue(_key_path(*where), "format", str(exc)))
        return None


def _tool_ceiling(value: Any, issues: list[ConfigIssue]) -> dict[str, tuple[str, ...]] | None:
    """Check ``mode_tool_ceiling``: ``query`` exactly ``["fs_read"]``, ``change`` a list of names."""
    if value is _MISSING:
        return None
    if not isinstance(value, Mapping):
        issues.append(ConfigIssue("mode_tool_ceiling", "type", f"must be an object, got {_describe(value)}"))
        return None
    before = len(issues)

    query = _take(value, ("mode_tool_ceiling", "query"), issues)
    if query is not _MISSING:
        if not isinstance(query, (list, tuple)):
            issues.append(ConfigIssue("mode_tool_ceiling.query", "type", f"must be a list, got {_describe(query)}"))
        elif tuple(query) != QUERY_TOOL_CEILING:
            issues.append(
                ConfigIssue("mode_tool_ceiling.query", "format", f'must be exactly ["fs_read"], got {_describe(query)}')
            )

    change = _take(value, ("mode_tool_ceiling", "change"), issues)
    if change is not _MISSING:
        if not isinstance(change, (list, tuple)):
            issues.append(ConfigIssue("mode_tool_ceiling.change", "type", f"must be a list, got {_describe(change)}"))
        elif not change:
            issues.append(ConfigIssue("mode_tool_ceiling.change", "format", "must name at least one tool"))
        else:
            for index, tool in enumerate(change):
                _non_empty_string(tool, ("mode_tool_ceiling", "change", index), issues)

    issues.extend(_unknown_keys(value, MODES, ("mode_tool_ceiling",)))
    if len(issues) > before:
        return None
    return {"query": QUERY_TOOL_CEILING, "change": tuple(change)}


def _agents(value: Any, issues: list[ConfigIssue]) -> dict[str, str] | None:
    """Check ``agents``: an object from a mode to a non-empty agent name. Modes are optional."""
    if value is _MISSING:
        return None
    if not isinstance(value, Mapping):
        issues.append(ConfigIssue("agents", "type", f"must be an object, got {_describe(value)}"))
        return None
    before = len(issues)
    agents: dict[str, str] = {}
    for mode in MODES:
        if mode in value:
            name = _non_empty_string(value[mode], ("agents", mode), issues)
            if name is not None:
                agents[mode] = name
    issues.extend(_unknown_keys(value, MODES, ("agents",)))
    return None if len(issues) > before else agents


def _repos(value: Any, home: str, issues: list[ConfigIssue]) -> dict[str, RepoConfig] | None:
    """Check ``repos``: an object from a name to ``{"main_tree": <path>}``.

    Returns:
        The entries that passed, even when another entry failed, so that the overlap
        check of ``worktrees_root`` still sees them. ``None`` when ``repos`` is absent or
        not an object.
    """
    if value is _MISSING:
        return None
    if not isinstance(value, Mapping):
        issues.append(ConfigIssue("repos", "type", f"must be an object, got {_describe(value)}"))
        return None
    repos: dict[str, RepoConfig] = {}
    for name in sorted(value, key=str):
        where = ("repos", str(name))
        entry = value[name]
        if not isinstance(entry, Mapping):
            issues.append(ConfigIssue(_key_path(*where), "type", f"must be an object, got {_describe(entry)}"))
            continue
        main_tree = _absolute_path(_take(entry, (*where, "main_tree"), issues), (*where, "main_tree"), home, issues)
        issues.extend(_unknown_keys(entry, ("main_tree",), where))
        if main_tree is not None:
            repos[str(name)] = RepoConfig(main_tree)
    return repos


def _overlap_issues(root: str, protected: list[tuple[str, str]]) -> list[ConfigIssue]:
    """Report each protected path that ``root`` equals, lies inside, or contains."""
    found: list[ConfigIssue] = []
    for label, other in protected:
        if is_within(root, other):
            relation = "equals" if is_within(other, root) else "is inside"
        elif is_within(other, root):
            relation = "contains"
        else:
            continue
        found.append(ConfigIssue("worktrees_root", "overlap", f"{relation} {label} ({other})"))
    return found
