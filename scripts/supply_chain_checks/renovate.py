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
* a reference to the Hub preset carries a tag or a 40-digit commit SHA;
* package-manager waits (npm ``min-release-age``, pnpm ``minimumReleaseAge``, uv
  ``exclude-newer``) equal ``package_manager_wait.default_days`` where the repository uses
  that tool. ``pip --uploaded-prior-to`` takes an absolute time and is not compared.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

from supply_chain_checks._common import Report, Unparseable, Violation, use_supply_chain_package

PRESET_PATH = "renovate/supply-chain.json"
AUTOMERGE_PRESET_PATH = "renovate/supply-chain-automerge.json"
POLICY_PATH = "docs/agent/supply-chain-policy.json"
REQUIRED_CHECKS_PATH = "docs/agent/automerge-required-checks.json"
REPO_CONFIG_PATHS = ("renovate.json", ".github/renovate.json", ".renovaterc.json")
HUB_PREFIX = "Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook"
FORBIDDEN_REPO_KEYS = ("minimumReleaseAge", "automerge", "platformAutomerge", "internalChecksFilter")

_DAYS = re.compile(r"^\s*(-?\d+)\s*days?\s*$")
_PRESET_REF = re.compile(r"^github>[^/>]+/[^/>]+//renovate/(supply-chain(?:-automerge)?)(?:#(.*))?$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_TAG = re.compile(r"^[A-Za-z0-9._-]*\d+\.\d+\.\d+[A-Za-z0-9._-]*$")


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
    return any(n.startswith(HUB_PREFIX) for n in names) and rule.get("automerge") is False


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


def _check_repo_config(out: list[Violation], rel: str, text: str, data: dict[str, Any], policy: Any) -> None:
    for key in FORBIDDEN_REPO_KEYS:
        if key in data:
            out.append(
                Violation(
                    rel, _line(text, key), "override", f"{key} belongs to the preset; do not set it in the repository"
                )
            )
    for rule in _rules(data):
        for key in FORBIDDEN_REPO_KEYS:
            if key in rule:
                out.append(
                    Violation(rel, _line(text, key), "override", f"packageRules sets {key}; do not override the preset")
                )
    alerts = data.get("vulnerabilityAlerts")
    if isinstance(alerts, dict) and alerts.get("automerge") is True:
        out.append(
            Violation(
                rel,
                _line(text, "automerge", _line(text, "vulnerabilityAlerts")),
                "automerge",
                "vulnerabilityAlerts.automerge must be false",
            )
        )
    for ref in _as_list(data.get("extends")):
        if not isinstance(ref, str):
            continue
        match = _PRESET_REF.match(ref)
        if not match:
            continue
        line = _line(text, "extends")
        for index, row in enumerate(text.split("\n"), start=1):
            if ref in row:
                line = index
        pin = match.group(2)
        if not pin:
            out.append(Violation(rel, line, "reference", f"{ref!r} has no tag or SHA"))
        elif not (_SHA.match(pin) or _TAG.match(pin)):
            out.append(Violation(rel, line, "reference", f"{ref!r} is neither a tag nor a 40-digit SHA"))
        if match.group(1) == "supply-chain-automerge" and not policy.automerge_enabled_repositories:
            out.append(
                Violation(
                    rel, line, "automerge", "automerge preset referenced while automerge.enabled_repositories is empty"
                )
            )


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
    for rel in REPO_CONFIG_PATHS:
        if (root / rel).is_file():
            text, data = _load_json(root, rel, scanned)
            scanned += 1
            _check_repo_config(out, rel, text, data, policy)
            break
    scanned += _check_package_managers(root, out, policy.package_manager_wait.default)
    return Report(violations=out, scanned=scanned)
