"""``renovate`` subcommand: the Renovate_Preset and the repository's own Renovate config.

Reads ``renovate/supply-chain.json`` (the preset), ``renovate/supply-chain-automerge.json``
(only when it exists), ``renovate.json`` (or ``.github/renovate.json`` / ``.renovaterc.json``)
and the Policy_File, and checks:

* (a Spoke has no preset file and skips these preset checks) the preset's ``minimumReleaseAge`` is a positive whole number of days equal to
  ``cooldown_days.default``, its ``major`` rule equals ``cooldown_days.major``, and
  ``major >= default``; ``internalChecksFilter`` is ``strict``;
* ``vulnerabilityAlerts.automerge`` is explicitly ``false`` in the preset;
* a preset file that automerges has a later rule that stops vulnerability fixes, and every
  preset has a later rule that stops Hub reusable workflows, from being automerged;
* the automerge rules (when present) equal ``automerge.include`` of the Policy_File, and the
  automerge preset is not referenced while ``automerge.enabled_repositories`` is empty;
* every ``automerge.enabled_repositories`` entry has a recorded count of 1 or more required
  status checks in ``docs/agent/automerge-required-checks.json`` (Requirement 14.4); the
  gate is offline, so the maintainer's configuration check is the input;
* the repository's config sets none of ``minimumReleaseAge``, ``automerge``,
  ``platformAutomerge`` or ``internalChecksFilter``, and does not set
  ``vulnerabilityAlerts.automerge`` to ``true``;
* the repository's config does not weaken what the preset sets (``minimumReleaseAgeBehaviour``,
  ``ignoreTests``, ``prCreation``, ``internalChecksAsSuccess``, ``registryUrls``,
  ``hostRules``, ``ignorePresets``, ``enabled: false``, ``osvVulnerabilityAlerts: false`` and
  ``vulnerabilityAlerts`` overrides), at the top level or in a ``packageRules`` entry;
* every ``extends`` entry is either a built-in preset on an allowlist (``ALLOWED_BUILTIN_PRESETS``: a built-in
  such as ``:disableVulnerabilityAlerts`` or ``:skipStatusChecks`` sets what the Hub preset owns, T1-R2-01),
  or the Hub preset itself, and the Hub preset comes last (a later ``extends`` entry overrides an earlier one). A ``github>`` reference to any other
  owner or repository is a ``reference`` violation: a preset is a configuration injection
  path (T1-05);
* a reference to the Hub preset carries a tag or a 40-digit commit SHA, and, when the
  Policy_File records ``renovate_preset`` (``tag``, ``commit``), that same tag or commit
  (T1-06; ``scripts/check_pinned_sha_exist.py`` asks GitHub whether the tag still points at
  the recorded commit);
* the preset gives ``pinDigest`` updates no ``minimumReleaseAge`` (T1-02: pinning freezes
  what the reference already resolves to, so waiting only prolongs the unpinned state), and
  no other rule opts out of the cooldown;
* an automerge rule for ``github-actions`` is limited to first-party ``actions/**`` packages
  (T1-04: the age of a ``github-tags`` update is the commit date, which a force-pushed tag
  does not reset, so a third-party Action must reach a human);
* package-manager waits (npm ``min-release-age``, pnpm ``minimumReleaseAge``, uv
  ``exclude-newer``) equal ``package_manager_wait.default_days`` where the repository uses
  that tool. ``pip --uploaded-prior-to`` takes an absolute time and is not compared. A
  non-empty npm ``min-release-age-exclude`` is logged as a warning (T1-03: an exclusion made
  to let a security fix through must be removed after the merge).
"""

from __future__ import annotations

import json
import logging
import re
import tomllib
from pathlib import Path
from typing import Any

from supply_chain_checks._common import Report, Unparseable, Violation, use_supply_chain_package

PRESET_PATH = "renovate/supply-chain.json"
AUTOMERGE_PRESET_PATH = "renovate/supply-chain-automerge.json"
POLICY_PATH = "docs/agent/supply-chain-policy.json"
REQUIRED_CHECKS_PATH = "docs/agent/automerge-required-checks.json"
#: Where Renovate looks for the repository config, in its own order, and stops at the first file it finds
#: (https://docs.renovatebot.com/configuration-options/, "Locations for configuration filenames", checked
#: 2026-11-14). ``package.json`` (a ``renovate`` section, deprecated) is the last candidate. The gate must read the
#: file Renovate reads, so the list is the documented one in full (T12-R4-01). A self-hosted ``configFileNames``
#: setting would add names before these; the repository cannot see it.
REPO_CONFIG_PATHS = (
    "renovate.json",
    "renovate.jsonc",
    "renovate.json5",
    ".github/renovate.json",
    ".github/renovate.jsonc",
    ".github/renovate.json5",
    ".gitlab/renovate.json",
    ".gitlab/renovate.jsonc",
    ".gitlab/renovate.json5",
    ".renovaterc",
    ".renovaterc.json",
    ".renovaterc.jsonc",
    ".renovaterc.json5",
)
PACKAGE_JSON_PATH = "package.json"
#: Files whose content the gate must parse as strict JSON (a failure to parse is "cannot read", exit 2). The others
#: (JSONC, JSON5, extensionless) are tried as JSON; if that fails the gate cannot check them and fails (``unsupported_config``).
_STRICT_JSON_CONFIGS = ("renovate.json", ".github/renovate.json", ".gitlab/renovate.json", ".renovaterc.json")
HUB_PREFIX = "Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook"
#: Keys of the preset (or switches of Renovate's safety checks) that a repository must not set,
#: at the top level or in a packageRules entry.
FORBIDDEN_REPO_KEYS = (
    "minimumReleaseAge",
    "minimumReleaseAgeBehaviour",
    "minimumReleaseAgePackageManager",
    "automerge",
    "platformAutomerge",
    "internalChecksFilter",
    "internalChecksAsSuccess",
    "ignoreTests",
    "prCreation",
    "registryUrls",
    "hostRules",
    "ignorePresets",
)
#: Keys whose subtree the all-depth scan skips because they hold definitions, not option values:
#: ``hostRules`` (credentials and registries; the parent scan already refuses the key itself),
#: ``customManagers`` / ``regexManagers`` (``fileMatch``, ``matchStrings``) and ``customDatasources``.
#: ``lockFileMaintenance`` and ``vulnerabilityAlerts`` are NOT here: Renovate documents both as objects that take
#: the same options as a packageRule (scopes ``repo, packageRule, manager, vulnerabilityAlert``; T12-R6-01), so
#: they are the widest way round the preset's cooldown and automerge ban.
_NOT_SCOPES = frozenset({"hostRules", "customManagers", "regexManagers", "customDatasources"})
#: Every key that starts with this prefix touches the cooldown (``minimumReleaseAgeBuffer``,
#: ``minimumReleaseAgePackageManagerSync`` and whatever Renovate adds next; T12-R6-05).
_COOLDOWN_PREFIX = "minimumreleaseage"
#: ``vulnerabilityAlerts`` sub-keys a repository must not set at all (``automerge`` is checked
#: apart; ``enabled`` and ``osvVulnerabilityAlerts`` are only refused when set to ``false``).
#: The object itself is not passed to ``scan`` (``walk_scopes``), so the keys of ``FORBIDDEN_REPO_KEYS`` that can
#: sit directly in it are listed here.
FORBIDDEN_ALERT_KEYS = (
    "minimumReleaseAge",
    "minimumReleaseAgeBehaviour",
    "prCreation",
    "ignoreTests",
    "platformAutomerge",
    "internalChecksFilter",
    "internalChecksAsSuccess",
)
#: Packages whose patch updates the automerge preset may merge: first-party Actions only.
FIRST_PARTY_ACTION_PREFIXES = ("actions/",)
#: Built-in presets an ``extends`` entry may use (an allowlist, T1-R2-01). Renovate ships presets that set
#: what the Hub preset owns: ``:disableVulnerabilityAlerts`` sets ``vulnerabilityAlerts.enabled: false``,
#: ``:skipStatusChecks`` sets ``ignoreTests: true``, ``:disableRenovate`` sets ``enabled: false``,
#: ``:prImmediately`` sets ``prCreation``, ``:automergeStableNonMajor`` and its siblings set ``automerge``,
#: ``security:minimumReleaseAgeNpm`` sets ``minimumReleaseAge`` (https://docs.renovatebot.com/presets-default/,
#: read 2026-11-14). A list of the harmful ones would go stale with every Renovate release; a name that is not
#: here is refused, and the owner of the Hub preset adds it after reading what it sets.
ALLOWED_BUILTIN_PRESETS = frozenset(
    {
        "config:recommended",
        "config:best-practices",
        "helpers:pinGitHubActionDigests",
        "helpers:pinGitHubActionDigestsToSemver",
        ":dependencyDashboard",
        ":semanticCommits",
        ":semanticCommitsDisabled",
        ":semanticPrefixFixDepsChoreOthers",
        ":configMigration",
        ":pinDevDependencies",
        ":maintainLockFilesWeekly",
    }
)
#: Built-in presets that only label or assign, with an argument: ``:label(x)``, ``:timezone(Asia/Tokyo)``.
_ALLOWED_PARAMETERIZED = re.compile(r"^:(labels?|assignees?|reviewers?|timezone)\([^()\s]+\)$")
#: Preset families that hold grouping, replacement and workaround data; their names must still not say they
#: turn something off.
_ALLOWED_FAMILIES = ("group:", "mergeConfidence:", "replacements:", "workarounds:", "monorepo:")
_HARMFUL_STEM = re.compile(r"disable|skip|automerge|ignore|immediate|notpending|never|minimumreleaseage|enabled", re.I)
_LOG = logging.getLogger(__name__)

_DAYS = re.compile(r"^\s*(-?\d+)\s*days?\s*$")
#: The only external preset a Spoke may extend: the Hub's (owner and repository are fixed; GitHub
#: treats them case-insensitively, so the match is too).
_PRESET_REF = re.compile(
    r"^github>" + re.escape(HUB_PREFIX) + r"//renovate/(supply-chain(?:-automerge)?)(?:#(.*))?$", re.IGNORECASE
)
_EXTERNAL_PRESET = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*>")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_TAG = re.compile(r"^[A-Za-z0-9._-]*\d+\.\d+\.\d+[A-Za-z0-9._-]*$")


def _builtin_allowed(ref: str) -> bool:
    """True when ``ref`` is a built-in preset that does not set anything the Hub preset owns."""
    if ref in ALLOWED_BUILTIN_PRESETS or _ALLOWED_PARAMETERIZED.match(ref):
        return True
    return ref.startswith(_ALLOWED_FAMILIES) and not _HARMFUL_STEM.search(ref)


def _line(text: str, key: str, after: int = 0) -> int:
    """Return the 1-based line of ``"key":`` at or after line ``after`` (1 if absent)."""
    pattern = re.compile(r'"' + re.escape(key) + r'"\s*:')
    lines = text.split("\n")
    for index in range(max(after - 1, 0), len(lines)):
        if pattern.search(lines[index]):
            return index + 1
    return 1


def _read(root: Path, rel: str, scanned: int) -> str:
    try:
        return (root / rel).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else type(exc).__name__
        raise Unparseable(rel, f"cannot read: {reason}", scanned=scanned) from exc


def _load_json(root: Path, rel: str, scanned: int) -> tuple[str, dict[str, Any]]:
    text = _read(root, rel, scanned)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise Unparseable(rel, f"not valid JSON: {exc.msg} (line {exc.lineno})", scanned=scanned + 1) from exc
    if not isinstance(data, dict):
        raise Unparseable(rel, "top level is not a JSON object", scanned=scanned + 1)
    return text, data


def _rules(data: dict[str, Any]) -> list[dict[str, Any]]:
    rules = data.get("packageRules")
    return [r for r in rules if isinstance(r, dict)] if isinstance(rules, list) else []


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _days(value: Any) -> int | None:
    """Parse ``"N days"``; ``None`` when the text is not that form."""
    if not isinstance(value, str):
        return None
    match = _DAYS.match(value)
    return int(match.group(1)) if match else None


def _check_days(out: list[Violation], rel: str, line: int, label: str, value: Any, want: int) -> int | None:
    if value is None:
        out.append(Violation(rel, line, "missing", f"{label} is not set (Policy_File wants {want} days)"))
        return None
    days = _days(value)
    if days is None:
        out.append(Violation(rel, line, "format", f"{label} {value!r} is not of the form 'N days'"))
        return None
    if days <= 0:
        out.append(Violation(rel, line, "range", f"{label} must be a positive integer of days, got {days}"))
        return days
    if days != want:
        out.append(Violation(rel, line, "mismatch", f"{label} is {days} days; Policy_File wants {want}"))
    return days


def _automerge_key(rule: dict[str, Any]) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    managers = _as_list(rule.get("matchManagers"))
    return (
        str(managers[0]) if managers else "",
        tuple(sorted(str(x) for x in _as_list(rule.get("matchDepTypes")))),
        tuple(sorted(str(x) for x in _as_list(rule.get("matchUpdateTypes")))),
    )


def _is_vuln_guard(rule: dict[str, Any]) -> bool:
    jsonata = " ".join(str(x) for x in _as_list(rule.get("matchJsonata")))
    return "isVulnerabilityAlert" in jsonata and rule.get("automerge") is False


def _is_hub_guard(rule: dict[str, Any]) -> bool:
    names = [str(x) for x in _as_list(rule.get("matchPackageNames"))]
    return any(n.casefold().startswith(HUB_PREFIX.casefold()) for n in names) and rule.get("automerge") is False


def _check_preset(
    out: list[Violation], rel: str, text: str, data: dict[str, Any], policy: Any, *, base: bool
) -> list[tuple[str, tuple[str, ...], tuple[str, ...]]]:
    """Check one preset file; return the automerge rules it grants."""
    rules = _rules(data)
    if base:
        age_line = _line(text, "minimumReleaseAge") if "minimumReleaseAge" in data else 1
        default = _check_days(
            out, rel, age_line, "minimumReleaseAge", data.get("minimumReleaseAge"), policy.cooldown_days.default
        )
        majors = [r for r in rules if "major" in _as_list(r.get("matchUpdateTypes")) and "minimumReleaseAge" in r]
        if not majors:
            out.append(
                Violation(
                    rel,
                    _line(text, "packageRules"),
                    "missing",
                    "no packageRules entry gives major updates a minimumReleaseAge "
                    f"(Policy_File wants {policy.cooldown_days.major} days)",
                )
            )
        pin_rules = [r for r in rules if "pinDigest" in _as_list(r.get("matchUpdateTypes"))]
        if not any(r.get("minimumReleaseAge") is None and "minimumReleaseAge" in r for r in pin_rules):
            out.append(
                Violation(
                    rel,
                    _line(text, "packageRules"),
                    "missing",
                    "no packageRules entry (matchUpdateTypes pinDigest) sets minimumReleaseAge to null: "
                    "pinning freezes what the reference already resolves to, and a cooldown on it only "
                    "prolongs the unpinned state",
                )
            )
        for rule in rules:
            if "minimumReleaseAge" in rule and rule["minimumReleaseAge"] is None:
                kinds = _as_list(rule.get("matchUpdateTypes"))
                if kinds != ["pinDigest"] and "major" not in kinds:  # a null major rule is reported above
                    out.append(
                        Violation(
                            rel,
                            _line(text, "minimumReleaseAge", _line(text, "packageRules")),
                            "mismatch",
                            "only a rule that matches pinDigest alone may set minimumReleaseAge to null",
                        )
                    )
        for rule in rules:
            age = rule.get("minimumReleaseAge")
            kinds = _as_list(rule.get("matchUpdateTypes"))
            if age is None or "major" in kinds:
                continue  # null is checked above; a major rule has its own check below
            days = _days(age)
            if days is None or days < policy.cooldown_days.default:
                out.append(
                    Violation(
                        rel,
                        _line(text, "minimumReleaseAge", _line(text, "packageRules")),
                        "range",
                        f"a packageRules minimumReleaseAge ({age!r}) is below the default "
                        f"{policy.cooldown_days.default} days: a rule must not shorten the cooldown",
                    )
                )
        major_line = _line(text, "minimumReleaseAge", _line(text, "packageRules"))
        for rule in majors:
            major = _check_days(
                out,
                rel,
                major_line,
                "major minimumReleaseAge",
                rule.get("minimumReleaseAge"),
                policy.cooldown_days.major,
            )
            if major is not None and default is not None and major < default:
                out.append(Violation(rel, major_line, "range", f"major ({major}) must be >= default ({default})"))
        if data.get("internalChecksFilter") != "strict":
            out.append(
                Violation(
                    rel,
                    _line(text, "internalChecksFilter"),
                    "missing" if "internalChecksFilter" not in data else "mismatch",
                    "internalChecksFilter must be 'strict'",
                )
            )
        behaviour = data.get("minimumReleaseAgeBehaviour")
        if behaviour is not None and behaviour != "timestamp-required":
            out.append(
                Violation(
                    rel,
                    _line(text, "minimumReleaseAgeBehaviour"),
                    "mismatch",
                    "minimumReleaseAgeBehaviour must be 'timestamp-required'",
                )
            )
    alerts = data.get("vulnerabilityAlerts")
    alert_automerge = alerts.get("automerge") if isinstance(alerts, dict) else None
    if alert_automerge is True:
        out.append(
            Violation(
                rel,
                _line(text, "automerge", _line(text, "vulnerabilityAlerts")),
                "automerge",
                "vulnerabilityAlerts.automerge must be false",
            )
        )
    elif base and alert_automerge is not False:
        out.append(
            Violation(
                rel, _line(text, "vulnerabilityAlerts"), "missing", "vulnerabilityAlerts.automerge must be set to false"
            )
        )
    if data.get("automerge") is True:
        out.append(Violation(rel, _line(text, "automerge"), "automerge", "top-level automerge must not be true"))
    granted: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = []
    last = -1
    for index, rule in enumerate(rules):
        if rule.get("automerge") is True:
            granted.append(_automerge_key(rule))
            last = index
            if "github-actions" in _as_list(rule.get("matchManagers")):
                names = [str(x).casefold() for x in _as_list(rule.get("matchPackageNames"))]
                if not names or not all(n.startswith(FIRST_PARTY_ACTION_PREFIXES) for n in names):
                    out.append(
                        Violation(
                            rel,
                            _line(text, "packageRules"),
                            "automerge",
                            "a github-actions automerge rule must list only first-party packages "
                            f"in matchPackageNames ({', '.join(p + '**' for p in FIRST_PARTY_ACTION_PREFIXES)}); "
                            "the cooldown of a github-tags update does not detect a moved tag",
                        )
                    )
    after = rules[last + 1 :]
    if last >= 0 and not any(_is_vuln_guard(r) for r in after):
        out.append(
            Violation(
                rel,
                _line(text, "packageRules"),
                "automerge",
                "automerges without a later rule (matchJsonata isVulnerabilityAlert, automerge false) that excludes vulnerability fixes",
            )
        )
    # every preset keeps the Hub out of automerge; the automerge preset needs it even with no rules
    if not any(_is_hub_guard(r) for r in after):
        out.append(
            Violation(
                rel,
                _line(text, "packageRules"),
                "missing",
                f"no rule after the automerge rules keeps {HUB_PREFIX} workflows out of automerge",
            )
        )
    return granted


def _check_repo_config(
    out: list[Violation],
    rel: str,
    text: str,
    data: dict[str, Any],
    policy: Any,
    recorded_preset: dict[str, Any] | None = None,
) -> None:
    forbidden = {k.casefold(): k for k in FORBIDDEN_REPO_KEYS}

    def scan(container: dict[str, Any], where: str, *, enabled_ok: bool = False) -> None:
        for key in container:
            name = forbidden.get(str(key).casefold())
            if name is None and str(key).casefold().startswith(_COOLDOWN_PREFIX):
                name = str(key)
            if name is not None:
                out.append(
                    Violation(rel, _line(text, str(key)), "override", f"{where} sets {name}; it belongs to the preset")
                )
        if container.get("osvVulnerabilityAlerts") is False:
            out.append(
                Violation(
                    rel,
                    _line(text, "osvVulnerabilityAlerts"),
                    "override",
                    f"{where} turns osvVulnerabilityAlerts off; the preset turns it on",
                )
            )
        if container.get("enabled") is False and not enabled_ok:
            out.append(
                Violation(
                    rel,
                    _line(text, "enabled"),
                    "override",
                    f"{where} sets enabled to false; a disabled manager or package stops getting updates "
                    "and the supply-chain preset cannot reach it",
                )
            )

    def walk_scopes(node: Any, where: str, via: str = "") -> None:
        """Apply ``scan`` to every object at any depth (T12-R5-01).

        Renovate lets ``minimumReleaseAge`` and the other keys sit in a manager object (``npm``), an update-type
        object (``major``), ``packageRules`` entries and any nesting of them, so the walk covers the whole tree
        instead of a list of known places. The subtrees in ``_NOT_SCOPES`` hold definitions, not option values.
        ``via`` is the key just above ``node``. The ``vulnerabilityAlerts`` object itself is checked apart (the
        ``FORBIDDEN_ALERT_KEYS`` block below); its children are walked. A ``lockFileMaintenance`` object may say
        ``enabled: false`` (that is its default, not a stop of updates), but nothing else of the ban is lifted.
        """
        if isinstance(node, dict):
            # Only the top-level object is checked apart (T12-R7-01); one nested elsewhere, or a list, is scanned.
            if not (via == "vulnerabilityAlerts" and where == "vulnerabilityAlerts"):
                scan(node, where, enabled_ok=via == "lockFileMaintenance")
            for key, value in node.items():
                if str(key) in _NOT_SCOPES:
                    continue
                walk_scopes(value, f"{where}.{key}" if where != "the repository config" else str(key), str(key))
        elif isinstance(node, list):
            for n, item in enumerate(node):
                walk_scopes(item, f"{where}[{n}]", via)

    walk_scopes(data, "the repository config")
    alerts = data.get("vulnerabilityAlerts")
    if isinstance(alerts, dict):
        if alerts.get("automerge") is True:
            out.append(
                Violation(
                    rel,
                    _line(text, "automerge", _line(text, "vulnerabilityAlerts")),
                    "automerge",
                    "vulnerabilityAlerts.automerge must be false",
                )
            )
        if alerts.get("enabled") is False:
            out.append(
                Violation(
                    rel,
                    _line(text, "enabled", _line(text, "vulnerabilityAlerts")),
                    "override",
                    "vulnerabilityAlerts.enabled is false; vulnerability-fix pull requests are off",
                )
            )
        alert_forbidden = {k.casefold() for k in FORBIDDEN_ALERT_KEYS}
        for key in alerts:
            folded = str(key).casefold()
            if folded in alert_forbidden or folded.startswith(_COOLDOWN_PREFIX):
                out.append(
                    Violation(
                        rel,
                        _line(text, str(key), _line(text, "vulnerabilityAlerts")),
                        "override",
                        f"vulnerabilityAlerts sets {key}; it belongs to the preset",
                    )
                )

    def walk_extends(node: Any, path: str) -> None:
        """Check every nested ``extends`` (T12-R4-07; the top level has its own, stricter check below).

        Renovate may or may not resolve ``extends`` inside a nested object (unconfirmed, T1-R3-R2-01), so the
        gate treats it as resolved: only an allowlisted built-in preset may appear there.
        """
        if isinstance(node, dict):
            for key, value in node.items():
                here = f"{path}.{key}" if path else str(key)
                if key == "extends" and path:
                    for ref in [value] if isinstance(value, str) else _as_list(value):
                        if isinstance(ref, str) and _builtin_allowed(ref) and not _EXTERNAL_PRESET.match(ref):
                            continue
                        out.append(
                            Violation(
                                rel,
                                _line(text, "extends", _line(text, path.split(".")[0].split("[")[0])),
                                "reference",
                                f"{here} {ref!r} is not on the allowlist of built-in presets",
                            )
                        )
                else:
                    walk_extends(value, here)
        elif isinstance(node, list):
            for n, item in enumerate(node):
                walk_extends(item, f"{path}[{n}]")

    walk_extends(data, "")
    raw_extends = data.get("extends")
    first_hub: int | None = None
    for position, ref in enumerate([raw_extends] if isinstance(raw_extends, str) else _as_list(raw_extends)):
        if not isinstance(ref, str):
            continue
        line = _line(text, "extends")
        for index, row in enumerate(text.split("\n"), start=1):
            if ref in row:
                line = index
        match = _PRESET_REF.match(ref)
        if match and first_hub is None:
            first_hub = position
        elif not match and first_hub is not None and not _EXTERNAL_PRESET.match(ref) and _builtin_allowed(ref):
            out.append(
                Violation(
                    rel,
                    line,
                    "reference",
                    f"{ref!r} comes after the Hub preset; a later extends entry overrides an earlier one, so the "
                    "Hub preset must be last",
                )
            )
        if not match:
            if _EXTERNAL_PRESET.match(ref):
                out.append(
                    Violation(
                        rel,
                        line,
                        "reference",
                        f"{ref!r} is neither a Renovate built-in preset nor the Hub preset "
                        f"({HUB_PREFIX}//renovate/supply-chain); a preset can set any option, so only the "
                        "Hub's is allowed",
                    )
                )
            elif not _builtin_allowed(ref):
                out.append(
                    Violation(
                        rel,
                        line,
                        "reference",
                        f"{ref!r} is not on the allowlist of built-in presets; a built-in preset can set what the "
                        "Hub preset owns (vulnerabilityAlerts, ignoreTests, prCreation, automerge, "
                        "minimumReleaseAge, enabled)",
                    )
                )
            continue
        pin = match.group(2)
        if not pin:
            out.append(Violation(rel, line, "reference", f"{ref!r} has no tag or SHA"))
        elif not (_SHA.match(pin) or _TAG.match(pin)):
            out.append(Violation(rel, line, "reference", f"{ref!r} is neither a tag nor a 40-digit SHA"))
        elif recorded_preset and pin != recorded_preset["tag"] and pin.lower() != recorded_preset["commit"]:
            out.append(
                Violation(
                    rel,
                    line,
                    "reference",
                    f"{ref!r} differs from the renovate_preset recorded in the Policy_File "
                    f"({recorded_preset['tag']!r}); update both together",
                )
            )
        if match.group(1).casefold() == "supply-chain-automerge" and not policy.automerge_enabled_repositories:
            out.append(
                Violation(
                    rel, line, "automerge", "automerge preset referenced while automerge.enabled_repositories is empty"
                )
            )


def _recorded_preset(policy: Any) -> dict[str, str] | None:
    """Return the Policy_File's parsed ``renovate_preset`` as ``{"tag", "commit"}``, or ``None`` when absent."""
    preset = getattr(policy, "renovate_preset", None)
    return None if preset is None else {"tag": preset.tag, "commit": preset.commit.lower()}


def _check_required_checks(root: Path, out: list[Violation], policy: Any, policy_text: str) -> int:
    """Each ``automerge.enabled_repositories`` entry needs >= 1 recorded required check (Requirement 14.4).

    The gate cannot ask GitHub (it is offline), so the maintainer's configuration check
    (Requirement 22.9) is recorded in ``REQUIRED_CHECKS_PATH`` as
    ``{"required_checks": {"owner/repo": <count>}}``. Returns the number of files read.
    """
    enabled = [f"{r.owner}/{r.name}" for r in policy.automerge_enabled_repositories]
    if not enabled:
        return 0
    scanned = 0
    counts: dict[str, Any] = {}
    if (root / REQUIRED_CHECKS_PATH).is_file():
        _, data = _load_json(root, REQUIRED_CHECKS_PATH, 0)
        scanned = 1
        raw = data.get("required_checks")
        if isinstance(raw, dict):
            counts = {str(k).lower(): v for k, v in raw.items()}
    for repo in enabled:
        value = counts.get(repo.lower())
        if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
            continue
        reason = "has no entry" if value is None else f"records {value!r}"
        out.append(
            Violation(
                POLICY_PATH,
                _line(policy_text, "enabled_repositories"),
                "required_checks",
                f"{repo} is in automerge.enabled_repositories but {REQUIRED_CHECKS_PATH} {reason}; "
                "a required status check count of 1 or more must be confirmed first",
            )
        )
    return scanned


def _check_package_managers(root: Path, out: list[Violation], want: int) -> int:
    """Compare package-manager waits with the Policy_File; return files read."""
    scanned = 0

    def read(name: str) -> str | None:
        nonlocal scanned
        path = root / name
        if not path.is_file():
            return None
        scanned += 1
        return _read(root, name, scanned)

    npmrc = read(".npmrc")
    pnpm = read("pnpm-workspace.yaml")
    uses_pnpm = pnpm is not None or (root / "pnpm-lock.yaml").is_file()
    uses_npm_family = (root / "package.json").is_file()
    npm_found = pnpm_found = False
    if npmrc is not None:
        for number, row in enumerate(npmrc.split("\n"), start=1):
            excluded = re.match(r"^\s*min-release-age-exclude(?:\[\])?\s*=\s*(\S.*)$", row)
            if excluded:
                _LOG.warning(
                    ".npmrc:%d min-release-age-exclude is set (%s): remove the exclusion once the "
                    "security fix it was made for is merged",
                    number,
                    excluded.group(1).strip(),
                )
            match = re.match(r"^\s*min-release-age\s*=\s*(\S+)", row)
            if match:
                npm_found = True
                if not match.group(1).isdigit() or int(match.group(1)) != want:
                    out.append(
                        Violation(
                            ".npmrc",
                            number,
                            "mismatch",
                            f"min-release-age is {match.group(1)}; Policy_File wants {want} (days)",
                        )
                    )
    if pnpm is not None:
        for number, row in enumerate(pnpm.split("\n"), start=1):
            match = re.match(r"^minimumReleaseAge\s*:\s*(\S+)", row)
            if match:
                pnpm_found = True
                if not match.group(1).isdigit() or int(match.group(1)) != want * 1440:
                    out.append(
                        Violation(
                            "pnpm-workspace.yaml",
                            number,
                            "mismatch",
                            f"minimumReleaseAge is {match.group(1)}; Policy_File wants {want * 1440} (minutes)",
                        )
                    )
    if uses_npm_family and not (pnpm_found if uses_pnpm else npm_found):
        name = "pnpm-workspace.yaml minimumReleaseAge" if uses_pnpm else ".npmrc min-release-age"
        out.append(Violation("package.json", 1, "missing", f"{name} is not set (Policy_File wants {want} days)"))
    pyproject = read("pyproject.toml")
    uv_table: dict[str, Any] | None = None
    if pyproject is not None:
        try:
            tool = tomllib.loads(pyproject).get("tool", {})
        except tomllib.TOMLDecodeError as exc:
            raise Unparseable("pyproject.toml", f"not valid TOML: {exc}", scanned=scanned) from exc
        if isinstance(tool, dict) and isinstance(tool.get("uv"), dict):
            uv_table = tool["uv"]
    if uv_table is not None or (root / "uv.lock").is_file():
        value = (uv_table or {}).get("exclude-newer")
        line = next((i for i, r in enumerate((pyproject or "").split("\n"), start=1) if "exclude-newer" in r), 1)
        _check_days(out, "pyproject.toml", line, "tool.uv.exclude-newer", value, want)
    return scanned


def _repo_config_candidates(root: Path, scanned: int) -> list[str]:
    """Return the config files that exist, in Renovate's order (``package.json`` only with a ``renovate`` key)."""
    found = [rel for rel in REPO_CONFIG_PATHS if (root / rel).is_file()]
    if (root / PACKAGE_JSON_PATH).is_file():
        _, package = _load_json(root, PACKAGE_JSON_PATH, scanned)
        if "renovate" in package:
            found.append(PACKAGE_JSON_PATH)
    return found


def _check_repo_config_file(root: Path, out: list[Violation], policy: Any, scanned: int) -> int:
    """Check the one config file Renovate reads, and fail when the choice is not clear or not readable.

    Args:
        root: The repository root.
        out: Violations are appended here.
        policy: The parsed Policy_File.
        scanned: Files read so far.

    Returns:
        The updated count of files read.

    Raises:
        Unparseable: A file whose format the gate parses strictly is not valid JSON.
    """
    found = _repo_config_candidates(root, scanned)
    if not found:
        return scanned
    rel = found[0]
    if len(found) > 1:
        out.append(
            Violation(
                rel,
                1,
                "multiple_config",
                f"Renovate reads {rel} and ignores {', '.join(found[1:])}; keep one config file so what the gate "
                "checks is what Renovate uses",
            )
        )
    if rel == PACKAGE_JSON_PATH:
        text, package = _load_json(root, rel, scanned)
        scanned += 1
        section = package["renovate"]
        if not isinstance(section, dict):
            out.append(
                Violation(rel, _line(text, "renovate"), "unsupported_config", "the renovate section is not an object")
            )
            return scanned
        _check_repo_config(out, rel, text, section, policy, _recorded_preset(policy))
        return scanned
    if rel in _STRICT_JSON_CONFIGS:
        text, data = _load_json(root, rel, scanned)
    else:
        text = _read(root, rel, scanned)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        if not isinstance(data, dict):
            scanned += 1
            out.append(
                Violation(
                    rel,
                    1,
                    "unsupported_config",
                    "Renovate reads this file but the gate parses only JSON, so its content is unchecked; "
                    "write it as plain JSON or use renovate.json",
                )
            )
            return scanned
    scanned += 1
    _check_repo_config(out, rel, text, data, policy, _recorded_preset(policy))
    return scanned


def check(root: Path) -> Report:
    """Check the Renovate presets, the repository's Renovate config and package-manager waits.

    Args:
        root: The repository root, or a directory that plays its role.

    Returns:
        A report with one violation per finding.

    Raises:
        Unparseable: The Policy_File or a Renovate file is absent, unreadable or invalid.
    """
    use_supply_chain_package()
    from supply_chain.policy import PolicyError, parse_policy  # noqa: PLC0415

    scanned = 0
    policy_text = _read(root, POLICY_PATH, scanned)
    scanned += 1
    try:
        policy = parse_policy(policy_text)
    except PolicyError as exc:
        detail = f"Policy_File is invalid ({len(exc.issues)} issue(s)); the values to compare with are unknown. Run the policy subcommand"
        if any(issue.kind == "invalid_json" for issue in exc.issues):
            raise Unparseable(POLICY_PATH, detail, scanned=scanned) from exc
        return Report(violations=[Violation(POLICY_PATH, 1, "policy", detail)], scanned=scanned)
    out: list[Violation] = []
    granted: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = []
    if (root / PRESET_PATH).is_file():  # a Spoke has no preset file; it references the Hub's
        text, data = _load_json(root, PRESET_PATH, scanned)
        scanned += 1
        granted += _check_preset(out, PRESET_PATH, text, data, policy, base=True)
    if (root / AUTOMERGE_PRESET_PATH).is_file():
        text, data = _load_json(root, AUTOMERGE_PRESET_PATH, scanned)
        scanned += 1
        granted += _check_preset(out, AUTOMERGE_PRESET_PATH, text, data, policy, base=False)
    if granted or (root / AUTOMERGE_PRESET_PATH).is_file():
        want_rules = {
            (r.manager, tuple(sorted(r.dep_types)), tuple(sorted(r.update_types))) for r in policy.automerge_include
        }
        have = set(granted)
        if have != want_rules:
            out.append(
                Violation(
                    AUTOMERGE_PRESET_PATH if (root / AUTOMERGE_PRESET_PATH).is_file() else PRESET_PATH,
                    1,
                    "automerge",
                    f"automerge rules {sorted(have)} differ from Policy_File automerge.include {sorted(want_rules)}",
                )
            )
    scanned += _check_required_checks(root, out, policy, policy_text)
    scanned = _check_repo_config_file(root, out, policy, scanned)
    scanned += _check_package_managers(root, out, policy.package_manager_wait)
    return Report(violations=out, scanned=scanned)
