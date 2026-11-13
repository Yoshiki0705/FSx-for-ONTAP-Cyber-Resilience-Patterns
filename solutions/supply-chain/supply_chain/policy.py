"""Parser and printer for the Policy_File (``docs/agent/supply-chain-policy.json``).

``parse_policy`` validates the text against the same rules as
``docs/agent/supply-chain-policy.schema.json`` plus the checks that JSON Schema
cannot express, collects every violation instead of stopping at the first, and
returns a :class:`~supply_chain.models.Policy`. ``render_policy`` writes a
Policy back as JSON, byte-for-byte deterministic. Standard library only, no I/O.

The tables below (``OBJECT_KEYS``, ``REQUIRED_KEYS``, ``ENUMS``, ``CONSTS``,
``INT_RANGES``) are the parser's copy of the schema's shape. A test reads the
schema file and compares it with these tables, so the two cannot drift apart
unnoticed. Paths use ``$`` for the root, ``.key`` for a member and ``[]`` for
every array element (``[3]`` in an issue path, ``[]`` in a table key).

Issue kinds used for the checks JSON Schema cannot express:

* ``range``: a value outside its allowed set or order (``major < default``,
  ``package_manager_wait`` different from ``cooldown_days``,
  ``fix_days_kev_or_malicious > fix_days_high``, an ``enabled_repositories``
  entry that is not a target, a ``const`` that is not the required value).
* ``overlap``: a repository that is both a target and an exclusion.
* ``missing``: an excluded default repository, or ``vulnerability_fix`` in
  ``automerge.exclude``, that is absent.
* ``duplicate``: a repeated JSON key, or a repeated array item (repositories
  compare without regard to case).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from supply_chain.models import (
    AutomergeRule,
    CooldownDays,
    OpeningThreshold,
    Policy,
    Repo,
    ResponseTarget,
)

IssueKindName = Literal["invalid_json", "missing", "type", "range", "unknown_key", "duplicate", "overlap", "format"]

# Same expression as ``$defs.repo.pattern`` in the schema (anchors included).
REPO_PATTERN = r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$"
_REPO_RE = re.compile(REPO_PATTERN[1:-1])  # used with fullmatch, so no trailing-newline gap

# The four exclusions every Policy_File must keep (D-1b, Requirement 3.2, 3.5).
DEFAULT_EXCLUDED_REPOSITORIES: tuple[str, ...] = (
    "aws-samples/baseline-environment-on-aws",
    "aws-samples/baseline-environment-on-aws-for-financial-services-institute",
    "Yoshiki0705/baseline-environment-on-aws",
    "Yoshiki0705/baseline-environment-on-aws-for-financial-services-institute",
)

OBJECT_KEYS: Mapping[str, tuple[str, ...]] = {
    "$": (
        "schema_version",
        "target_repositories",
        "excluded_repositories",
        "opening_threshold",
        "cooldown_days",
        "package_manager_wait",
        "dependency_scope",
        "automerge",
        "vex",
        "response_target",
        "issue_limits",
    ),
    "$.opening_threshold": (
        "min_cvss_severity",
        "open_if_kev_listed",
        "open_if_malicious",
        "epss_used_for_opening",
    ),
    "$.cooldown_days": ("default", "major"),
    "$.package_manager_wait": ("default_days", "major_days"),
    "$.dependency_scope": ("non_production_paths",),
    "$.automerge": ("enabled_repositories", "include", "exclude"),
    "$.automerge.include[]": ("manager", "dep_types", "update_types"),
    "$.vex": (
        "directory",
        "exclude_statuses",
        "approver_role",
        "one_statement_per_document",
        "malicious_never_suppressed",
    ),
    "$.response_target": ("detect_hours", "fix_days_kev_or_malicious", "fix_days_high"),
    "$.issue_limits": ("max_new_issues_per_repo_per_run",),
}

# Every key is required except the ones listed here.
OPTIONAL_KEYS: Mapping[str, frozenset[str]] = {"$.automerge.include[]": frozenset({"dep_types"})}
REQUIRED_KEYS: Mapping[str, frozenset[str]] = {
    path: frozenset(keys) - OPTIONAL_KEYS.get(path, frozenset()) for path, keys in OBJECT_KEYS.items()
}

ENUMS: Mapping[str, tuple[str, ...]] = {
    "$.opening_threshold.min_cvss_severity": ("LOW", "MEDIUM", "HIGH", "CRITICAL"),
    "$.automerge.include[].manager": ("npm", "github-actions"),
    "$.automerge.include[].dep_types[]": ("devDependencies",),
    "$.automerge.exclude[]": (
        "vulnerability_fix",
        "runtime_dependencies",
        "minor",
        "major",
        "digest_only",
        "unknown_dep_type",
        "hub_reusable_workflow",
    ),
    "$.vex.exclude_statuses[]": ("not_affected", "fixed"),
}

CONSTS: Mapping[str, Any] = {
    "$.schema_version": 1,
    "$.opening_threshold.open_if_malicious": True,
    "$.opening_threshold.epss_used_for_opening": False,
    "$.automerge.include[].update_types[]": "patch",
    "$.vex.directory": ".vex",
    "$.vex.approver_role": "VEX_Reviewer",
    "$.vex.one_statement_per_document": True,
    "$.vex.malicious_never_suppressed": True,
}

# Inclusive (minimum, maximum); ``None`` means no upper bound.
INT_RANGES: Mapping[str, tuple[int, int | None]] = {
    "$.cooldown_days.default": (1, None),
    "$.cooldown_days.major": (1, None),
    "$.package_manager_wait.default_days": (1, None),
    "$.package_manager_wait.major_days": (1, None),
    "$.response_target.detect_hours": (1, None),
    "$.response_target.fix_days_kev_or_malicious": (1, None),
    "$.response_target.fix_days_high": (1, None),
    "$.issue_limits.max_new_issues_per_repo_per_run": (1, 100),
}

# Minimum array lengths (``minItems``).
MIN_ITEMS: Mapping[str, int] = {
    "$.target_repositories": 1,
    "$.excluded_repositories": 4,
    "$.automerge.include": 1,
    "$.automerge.include[].update_types": 1,
    "$.vex.exclude_statuses": 1,
}


@dataclass(frozen=True, slots=True)
class PolicyIssue:
    """One violation found in a Policy_File.

    Attributes:
        path: JSON path of the offending location, e.g. ``$.cooldown_days.major``.
        kind: Category of the violation.
        detail: Human-readable explanation.
    """

    path: str
    kind: IssueKindName
    detail: str


class PolicyError(Exception):
    """Raised by :func:`parse_policy` with every violation found."""

    def __init__(self, issues: list[PolicyIssue]) -> None:
        self.issues = list(issues)
        lines = [f"{i.path} [{i.kind}] {i.detail}" for i in self.issues]
        super().__init__(f"{len(self.issues)} policy issue(s): " + "; ".join(lines))


class _Obj(dict):  # type: ignore[type-arg]
    """A JSON object that remembers keys that appeared more than once."""

    dups: list[str]


def _pairs_hook(pairs: list[tuple[str, Any]]) -> _Obj:
    obj = _Obj()
    obj.dups = []
    for key, value in pairs:
        if key in obj and key not in obj.dups:
            obj.dups.append(key)
        obj[key] = value  # the last value wins, as in json.loads
    return obj


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name}")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class _Checker:
    """Collects issues while walking a decoded document."""

    def __init__(self) -> None:
        self.issues: list[PolicyIssue] = []

    def add(self, path: str, kind: IssueKindName, detail: str) -> None:
        self.issues.append(PolicyIssue(path, kind, detail))

    def obj(self, value: Any, path: str, table: str) -> dict[str, Any] | None:
        """Checks an object's shape; returns it when it is an object, else None."""
        if not isinstance(value, dict):
            self.add(path, "type", f"expected an object, got {type(value).__name__}")
            return None
        for key in getattr(value, "dups", []):
            self.add(f"{path}.{key}", "duplicate", "key appears more than once")
        known = OBJECT_KEYS[table]
        for key in value:
            if key not in known:
                self.add(f"{path}.{key}", "unknown_key", "key is not defined by the schema")
        for key in known:
            if key in REQUIRED_KEYS[table] and key not in value:
                self.add(f"{path}.{key}", "missing", "required key is absent")
        return value

    def array(self, value: Any, path: str, table: str) -> list[Any] | None:
        if not isinstance(value, list):
            self.add(path, "type", f"expected an array, got {type(value).__name__}")
            return None
        need = MIN_ITEMS.get(table, 0)
        if len(value) < need:
            self.add(path, "range", f"expected at least {need} item(s), got {len(value)}")
        return value

    def integer(self, parent: dict[str, Any], key: str, path: str, table: str) -> int | None:
        if key not in parent:
            return None
        value = parent[key]
        here = f"{path}.{key}"
        if not _is_int(value):
            self.add(here, "type", f"expected an integer, got {type(value).__name__}")
            return None
        low, high = INT_RANGES[f"{table}.{key}"]
        if value < low or (high is not None and value > high):
            bound = f">= {low}" if high is None else f"{low}..{high}"
            self.add(here, "range", f"{value} is outside {bound}")
            return None
        return value

    def boolean(self, parent: dict[str, Any], key: str, path: str) -> bool | None:
        if key not in parent:
            return None
        if not isinstance(parent[key], bool):
            self.add(f"{path}.{key}", "type", f"expected a boolean, got {type(parent[key]).__name__}")
            return None
        return parent[key]

    def const(self, value: Any, path: str, table: str) -> bool:
        """Checks a ``const``; returns True when ``value`` equals it."""
        want = CONSTS[table]
        if type(value) is not type(want):
            self.add(path, "type", f"expected {type(want).__name__} {want!r}, got {type(value).__name__}")
            return False
        if value != want:
            self.add(path, "range", f"must be exactly {want!r}")
            return False
        return True

    def const_field(self, parent: dict[str, Any], key: str, path: str, table: str) -> Any | None:
        if key not in parent:
            return None
        return parent[key] if self.const(parent[key], f"{path}.{key}", f"{table}.{key}") else None

    def enum(self, value: Any, path: str, table: str) -> str | None:
        if not isinstance(value, str):
            self.add(path, "type", f"expected a string, got {type(value).__name__}")
            return None
        if value not in ENUMS[table]:
            self.add(path, "range", f"{value!r} is not one of {list(ENUMS[table])}")
            return None
        return value

    def repos(self, value: Any, path: str, table: str) -> tuple[Repo, ...] | None:
        """Parses an array of ``<owner>/<name>`` strings, reporting every bad item."""
        items = self.array(value, path, table)
        if items is None:
            return None
        found: list[Repo] = []
        seen: dict[Repo, int] = {}
        ok = True
        for index, item in enumerate(items):
            here = f"{path}[{index}]"
            if not isinstance(item, str):
                self.add(here, "type", f"expected a string, got {type(item).__name__}")
                ok = False
                continue
            if not _REPO_RE.fullmatch(item):
                self.add(here, "format", f"{item!r} does not match <owner>/<name>")
                ok = False
                continue
            owner, name = item.split("/")
            repo = Repo(owner, name)
            if repo in seen:
                self.add(here, "duplicate", f"same repository as item {seen[repo]} (case-insensitive)")
                ok = False
                continue
            seen[repo] = index
            found.append(repo)
        return tuple(found) if ok else None

    def string_set(self, value: Any, path: str, table: str) -> tuple[str, ...] | None:
        """Parses a unique array of non-empty strings."""
        items = self.array(value, path, table)
        if items is None:
            return None
        out: list[str] = []
        ok = True
        for index, item in enumerate(items):
            here = f"{path}[{index}]"
            if not isinstance(item, str):
                self.add(here, "type", f"expected a string, got {type(item).__name__}")
                ok = False
            elif not item:
                self.add(here, "range", "must not be empty")
                ok = False
            elif item in out:
                self.add(here, "duplicate", f"{item!r} is repeated")
                ok = False
            else:
                out.append(item)
        return tuple(out) if ok else None

    def enum_array(self, value: Any, path: str, table: str, *, unique: bool) -> tuple[str, ...] | None:
        items = self.array(value, path, table)
        if items is None:
            return None
        out: list[str] = []
        ok = True
        for index, item in enumerate(items):
            here = f"{path}[{index}]"
            got = self.enum(item, here, f"{table}[]")
            if got is None:
                ok = False
            elif unique and got in out:
                self.add(here, "duplicate", f"{got!r} is repeated")
                ok = False
            else:
                out.append(got)
        return tuple(out) if ok else None


def _parse_include(chk: _Checker, value: Any) -> tuple[AutomergeRule, ...] | None:
    path, table = "$.automerge.include", "$.automerge.include"
    items = chk.array(value, path, table)
    if items is None:
        return None
    rules: list[AutomergeRule] = []
    ok = True
    for index, item in enumerate(items):
        here = f"{path}[{index}]"
        obj = chk.obj(item, here, f"{table}[]")
        if obj is None:
            ok = False
            continue
        manager = chk.enum(obj["manager"], f"{here}.manager", f"{table}[].manager") if "manager" in obj else None
        dep_types: tuple[str, ...] | None = ()
        if "dep_types" in obj:
            dep_types = chk.enum_array(obj["dep_types"], f"{here}.dep_types", f"{table}[].dep_types", unique=False)
        update_types: tuple[str, ...] | None = None
        if "update_types" in obj:
            update_types = _parse_update_types(chk, obj["update_types"], f"{here}.update_types")
        if manager is None or dep_types is None or update_types is None:
            ok = False
            continue
        rules.append(
            AutomergeRule(manager=manager, dep_types=dep_types, update_types=update_types)  # type: ignore[arg-type]
        )
    return tuple(rules) if ok else None


def _parse_update_types(chk: _Checker, value: Any, path: str) -> tuple[str, ...] | None:
    table = "$.automerge.include[].update_types"
    items = chk.array(value, path, table)
    if items is None:
        return None
    results = [chk.const(item, f"{path}[{i}]", f"{table}[]") for i, item in enumerate(items)]
    ok = all(results)  # every item is checked first, so every bad item is reported
    return tuple(items) if ok and len(items) >= MIN_ITEMS[table] else None


def parse_policy(text: str) -> Policy:
    """Parses a Policy_File.

    Every violation is collected; the function does not stop at the first one.

    Args:
        text: The JSON text of the Policy_File.

    Returns:
        The validated Policy.

    Raises:
        PolicyError: If the text violates the schema or a cross-field rule. The
            ``issues`` attribute lists every violation with its JSON path and kind.
    """
    try:
        doc = json.loads(text, object_pairs_hook=_pairs_hook, parse_constant=_reject_constant)
    except (ValueError, RecursionError, TypeError) as exc:
        raise PolicyError([PolicyIssue("$", "invalid_json", str(exc))]) from exc

    chk = _Checker()
    root = chk.obj(doc, "$", "$")
    if root is None:
        raise PolicyError(chk.issues)

    version = chk.const_field(root, "schema_version", "$", "$")
    targets = (
        chk.repos(root["target_repositories"], "$.target_repositories", "$.target_repositories")
        if "target_repositories" in root
        else None
    )
    excluded = (
        chk.repos(root["excluded_repositories"], "$.excluded_repositories", "$.excluded_repositories")
        if "excluded_repositories" in root
        else None
    )

    threshold = _parse_threshold(chk, root)
    cooldown = _parse_pair(chk, root, "cooldown_days", ("default", "major"))
    wait = _parse_pair(chk, root, "package_manager_wait", ("default_days", "major_days"))
    paths = _parse_scope(chk, root)
    automerge = _parse_automerge(chk, root)
    vex = _parse_vex(chk, root)
    target = _parse_response(chk, root)
    limit = _parse_limits(chk, root)

    _cross_checks(chk, targets, excluded, cooldown, wait, automerge, target)

    if (
        chk.issues
        or version is None
        or targets is None
        or excluded is None
        or threshold is None
        or cooldown is None
        or wait is None
        or paths is None
        or automerge is None
        or vex is None
        or target is None
        or limit is None
    ):
        raise PolicyError(chk.issues)

    include, exclude, enabled = automerge
    directory, statuses, role, one_statement, never_suppressed = vex
    return Policy(
        schema_version=version,
        target_repositories=targets,
        excluded_repositories=excluded,
        opening_threshold=threshold,
        cooldown_days=cooldown,
        automerge_include=include,
        automerge_exclude=exclude,
        automerge_enabled_repositories=enabled,
        package_manager_wait=wait,
        non_production_paths=paths,
        vex_directory=directory,
        vex_exclude_statuses=statuses,  # type: ignore[arg-type]
        vex_approver_role=role,
        vex_one_statement_per_document=one_statement,
        vex_malicious_never_suppressed=never_suppressed,
        response_target=target,
        max_new_issues_per_repo_per_run=limit,
    )


def _section(chk: _Checker, root: dict[str, Any], key: str) -> dict[str, Any] | None:
    if key not in root:
        return None
    return chk.obj(root[key], f"$.{key}", f"$.{key}")


def _parse_threshold(chk: _Checker, root: dict[str, Any]) -> OpeningThreshold | None:
    sec = _section(chk, root, "opening_threshold")
    if sec is None:
        return None
    path = "$.opening_threshold"
    severity = (
        chk.enum(sec["min_cvss_severity"], f"{path}.min_cvss_severity", f"{path}.min_cvss_severity")
        if "min_cvss_severity" in sec
        else None
    )
    kev = chk.boolean(sec, "open_if_kev_listed", path)
    malicious = chk.const_field(sec, "open_if_malicious", path, path)
    epss = chk.const_field(sec, "epss_used_for_opening", path, path)
    if severity is None or kev is None or malicious is None or epss is None:
        return None
    return OpeningThreshold(min_cvss_severity=severity, open_if_kev_listed=kev, open_if_malicious=True)  # type: ignore[arg-type]


def _parse_pair(chk: _Checker, root: dict[str, Any], key: str, names: tuple[str, str]) -> CooldownDays | None:
    sec = _section(chk, root, key)
    if sec is None:
        return None
    first = chk.integer(sec, names[0], f"$.{key}", f"$.{key}")
    second = chk.integer(sec, names[1], f"$.{key}", f"$.{key}")
    if first is None or second is None:
        return None
    return CooldownDays(default=first, major=second)


def _parse_scope(chk: _Checker, root: dict[str, Any]) -> tuple[str, ...] | None:
    sec = _section(chk, root, "dependency_scope")
    if sec is None or "non_production_paths" not in sec:
        return None
    return chk.string_set(
        sec["non_production_paths"],
        "$.dependency_scope.non_production_paths",
        "$.dependency_scope.non_production_paths",
    )


def _parse_automerge(
    chk: _Checker, root: dict[str, Any]
) -> tuple[tuple[AutomergeRule, ...], tuple[str, ...], tuple[Repo, ...]] | None:
    sec = _section(chk, root, "automerge")
    if sec is None:
        return None
    path = "$.automerge"
    enabled = (
        chk.repos(sec["enabled_repositories"], f"{path}.enabled_repositories", f"{path}.enabled_repositories")
        if "enabled_repositories" in sec
        else None
    )
    include = _parse_include(chk, sec["include"]) if "include" in sec else None
    exclude = (
        chk.enum_array(sec["exclude"], f"{path}.exclude", f"{path}.exclude", unique=True) if "exclude" in sec else None
    )
    if exclude is not None and "vulnerability_fix" not in exclude:
        chk.add(f"{path}.exclude", "missing", "must contain 'vulnerability_fix'")
        exclude = None
    if enabled is None or include is None or exclude is None:
        return None
    return include, exclude, enabled


def _parse_vex(chk: _Checker, root: dict[str, Any]) -> tuple[str, tuple[str, ...], str, bool, bool] | None:
    sec = _section(chk, root, "vex")
    if sec is None:
        return None
    path = "$.vex"
    directory = chk.const_field(sec, "directory", path, path)
    statuses = (
        chk.enum_array(sec["exclude_statuses"], f"{path}.exclude_statuses", f"{path}.exclude_statuses", unique=True)
        if "exclude_statuses" in sec
        else None
    )
    role = chk.const_field(sec, "approver_role", path, path)
    one = chk.const_field(sec, "one_statement_per_document", path, path)
    never = chk.const_field(sec, "malicious_never_suppressed", path, path)
    if None in (directory, statuses, role, one, never):
        return None
    return directory, statuses, role, one, never  # type: ignore[return-value]


def _parse_response(chk: _Checker, root: dict[str, Any]) -> ResponseTarget | None:
    sec = _section(chk, root, "response_target")
    if sec is None:
        return None
    path = "$.response_target"
    detect = chk.integer(sec, "detect_hours", path, path)
    urgent = chk.integer(sec, "fix_days_kev_or_malicious", path, path)
    high = chk.integer(sec, "fix_days_high", path, path)
    if detect is None or urgent is None or high is None:
        return None
    return ResponseTarget(detect_hours=detect, fix_days_kev_or_malicious=urgent, fix_days_high=high)


def _parse_limits(chk: _Checker, root: dict[str, Any]) -> int | None:
    sec = _section(chk, root, "issue_limits")
    if sec is None:
        return None
    return chk.integer(sec, "max_new_issues_per_repo_per_run", "$.issue_limits", "$.issue_limits")


def _cross_checks(
    chk: _Checker,
    targets: tuple[Repo, ...] | None,
    excluded: tuple[Repo, ...] | None,
    cooldown: CooldownDays | None,
    wait: CooldownDays | None,
    automerge: tuple[tuple[AutomergeRule, ...], tuple[str, ...], tuple[Repo, ...]] | None,
    response: ResponseTarget | None,
) -> None:
    """Checks that JSON Schema cannot express; each runs only when its inputs parsed."""
    if cooldown is not None and cooldown.major < cooldown.default:
        chk.add("$.cooldown_days.major", "range", f"major ({cooldown.major}) must be >= default ({cooldown.default})")
    if wait is not None and wait.major < wait.default:
        chk.add(
            "$.package_manager_wait.major_days",
            "range",
            f"major_days ({wait.major}) must be >= default_days ({wait.default})",
        )
    if cooldown is not None and wait is not None:
        if wait.default != cooldown.default:
            chk.add(
                "$.package_manager_wait.default_days",
                "range",
                f"must equal cooldown_days.default ({cooldown.default}), got {wait.default}",
            )
        if wait.major != cooldown.major:
            chk.add(
                "$.package_manager_wait.major_days",
                "range",
                f"must equal cooldown_days.major ({cooldown.major}), got {wait.major}",
            )
    if response is not None and response.fix_days_kev_or_malicious > response.fix_days_high:
        chk.add(
            "$.response_target.fix_days_kev_or_malicious",
            "range",
            f"({response.fix_days_kev_or_malicious}) must be <= fix_days_high ({response.fix_days_high})",
        )
    if targets is not None and excluded is not None:
        excluded_set = set(excluded)
        for index, repo in enumerate(targets):
            if repo in excluded_set:
                chk.add(f"$.target_repositories[{index}]", "overlap", f"{repo.owner}/{repo.name} is also excluded")
    if excluded is not None:
        have = set(excluded)
        for text in DEFAULT_EXCLUDED_REPOSITORIES:
            owner, name = text.split("/")
            if Repo(owner, name) not in have:
                chk.add("$.excluded_repositories", "missing", f"default exclusion {text} is absent")
    if automerge is not None and targets is not None:
        target_set = set(targets)
        for index, repo in enumerate(automerge[2]):
            if repo not in target_set:
                chk.add(
                    f"$.automerge.enabled_repositories[{index}]",
                    "range",
                    f"{repo.owner}/{repo.name} is not in target_repositories",
                )


def _repo_text(repo: Repo) -> str:
    return f"{repo.owner}/{repo.name}"


def render_policy(policy: Policy) -> str:
    """Renders a Policy as a Policy_File, deterministically.

    Keys are sorted, the indent is two spaces, line endings are LF, the text ends
    with one newline and non-ASCII characters are written as they are. The same
    Policy always yields the same bytes. ``epss_used_for_opening`` is not part of
    the Policy (the schema fixes it to false) and is always written as false.

    Args:
        policy: A Policy that already satisfies the parser's rules.

    Returns:
        The JSON text.
    """
    doc: dict[str, Any] = {
        "schema_version": policy.schema_version,
        "target_repositories": [_repo_text(r) for r in policy.target_repositories],
        "excluded_repositories": [_repo_text(r) for r in policy.excluded_repositories],
        "opening_threshold": {
            "min_cvss_severity": policy.opening_threshold.min_cvss_severity,
            "open_if_kev_listed": policy.opening_threshold.open_if_kev_listed,
            "open_if_malicious": policy.opening_threshold.open_if_malicious,
            "epss_used_for_opening": False,
        },
        "cooldown_days": {"default": policy.cooldown_days.default, "major": policy.cooldown_days.major},
        "package_manager_wait": {
            "default_days": policy.package_manager_wait.default,
            "major_days": policy.package_manager_wait.major,
        },
        "dependency_scope": {"non_production_paths": list(policy.non_production_paths)},
        "automerge": {
            "enabled_repositories": [_repo_text(r) for r in policy.automerge_enabled_repositories],
            "include": [
                {
                    "manager": rule.manager,
                    "dep_types": list(rule.dep_types),
                    "update_types": list(rule.update_types),
                }
                for rule in policy.automerge_include
            ],
            "exclude": list(policy.automerge_exclude),
        },
        "vex": {
            "directory": policy.vex_directory,
            "exclude_statuses": list(policy.vex_exclude_statuses),
            "approver_role": policy.vex_approver_role,
            "one_statement_per_document": policy.vex_one_statement_per_document,
            "malicious_never_suppressed": policy.vex_malicious_never_suppressed,
        },
        "response_target": {
            "detect_hours": policy.response_target.detect_hours,
            "fix_days_kev_or_malicious": policy.response_target.fix_days_kev_or_malicious,
            "fix_days_high": policy.response_target.fix_days_high,
        },
        "issue_limits": {"max_new_issues_per_repo_per_run": policy.max_new_issues_per_repo_per_run},
    }
    return json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False, separators=(",", ": ")) + "\n"
