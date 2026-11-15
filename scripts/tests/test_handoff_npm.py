"""``npm`` in change mode: fixed forms only, and an environment that keeps npm inside the run (task 5.56).

Allowed: ``npm install --package-lock-only --ignore-scripts``, ``npm ci --ignore-scripts``, ``npm ls``.
Not allowed: ``npm exec``, ``npx``, ``npm run``, any other argument, ``--prefix``, a path, a registry, a global install.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
from handoff import agent_policy, command

GUARD = "python3 /home/x/.private/handoff/agents/guard-wrapper.py /home/x/.kiro/hooks/scripts/pre_tool_dispatch.py"
HOME = "/Users/example"

ALLOWED_LINES = (
    "npm install --package-lock-only --ignore-scripts",
    "npm ci --ignore-scripts",
    "npm ls",
)
FORBIDDEN_LINES = (
    "npm install",
    "npm install --package-lock-only",
    "npm install --ignore-scripts",
    "npm ci",
    "npm install --package-lock-only --ignore-scripts left-pad",
    "npm install --package-lock-only --ignore-scripts --prefix /tmp/x",
    "npm install --package-lock-only --ignore-scripts --prefix x",
    "npm install --package-lock-only --ignore-scripts --registry http://127.0.0.1:1/",
    "npm install --package-lock-only --ignore-scripts --userconfig /tmp/x",
    "npm install --package-lock-only --ignore-scripts -g",
    "npm install --package-lock-only --ignore-scripts; id",
    "npm install --package-lock-only --ignore-scripts && id",
    "npm install --package-lock-only --ignore-scripts $(id)",
    "npm install left-pad",
    "npm install -g left-pad",
    "npm install ../x",
    "npm install file:/etc",
    "npm install git+https://127.0.0.1/x.git",
    "npm ci --ignore-scripts --prefix /tmp/x",
    "npm ci --ignore-scripts --cache /tmp/x",
    "npm ci --ignore-scripts --script-shell /bin/sh",
    "npm ci --ignore-scripts --foreground-scripts",
    "npm ls --prefix /",
    "npm ls --all",
    "npm ls ../x",
    "npm exec id",
    "npm exec -- id",
    "npm x id",
    "npx id",
    "npx --yes cowsay",
    "npm run build",
    "npm run-script test",
    "npm test",
    "npm start",
    "npm init x",
    "npm create x",
    "npm config set registry http://127.0.0.1:1/",
    "npm set registry http://127.0.0.1:1/",
    "npm publish",
    "npm login",
    "npm adduser",
    "npm token create",
    "npm pack",
    "npm link",
    "npm rebuild",
    "npm cache clean --force",
    "npm explore x",
    "npm --prefix /tmp/x ls",
    "npm --prefix x ls",
    "npm -C x ls",
    "npm -g ls",
    "npm --registry http://127.0.0.1:1/ ci --ignore-scripts",
    "npm --userconfig /tmp/x ls",
    "npm --workspaces ls",
    "/usr/local/bin/npm ls",
    "./node_modules/.bin/npm ls",
    "node_modules/.bin/x",
)


def change_config() -> dict[str, Any]:
    """A change-mode configuration that meets the policy."""
    return agent_policy.build_agent_config("change", name="handoff-change", guard_command=GUARD)


def shell() -> dict[str, Any]:
    """The ``toolsSettings.shell`` of the built change configuration."""
    return change_config()["toolsSettings"]["shell"]


def matches(entries: list[str], line: str) -> bool:
    """A full match, as ``kiro-cli`` reads an entry of ``allowedCommands`` or ``deniedCommands``."""
    return any(re.fullmatch(entry, line) for entry in entries)


def problems(document: dict[str, Any]) -> list[tuple[str, str]]:
    """The failed checks of the approval."""
    return agent_policy.settings_problems(document, [*document["tools"], *document["allowedTools"]], home=HOME)


@pytest.mark.parametrize("line", ALLOWED_LINES)
def test_the_fixed_npm_forms_are_allowed(line: str) -> None:
    """A control: the three forms a lockfile update needs pass, so the refusals below are not a refusal of everything."""
    assert matches(shell()["allowedCommands"], line)
    assert not matches(shell()["deniedCommands"], line)


@pytest.mark.parametrize("line", FORBIDDEN_LINES)
def test_no_other_npm_line_is_allowed(line: str) -> None:
    """Each line leaves the three forms by one argument, option, subcommand or path."""
    assert not matches(shell()["allowedCommands"], line)


DENIED_BY_NAME = (
    "npm exec id",
    "npm exec -- id",
    "npm x id",
    "npx id",
    "npx --yes cowsay",
    "npm run build",
    "npm run-script test",
    "npm test",
    "npm start",
    "npm init x",
    "npm create x",
    "npm config set registry http://127.0.0.1:1/",
    "npm set registry http://127.0.0.1:1/",
    "npm publish",
    "npm login",
    "npm adduser",
    "npm token create",
    "npm pack",
    "npm link",
    "npm rebuild",
    "npm cache clean --force",
    "npm explore x",
    "npm install --package-lock-only --ignore-scripts --prefix /tmp/x",
    "npm install --package-lock-only --ignore-scripts --registry http://127.0.0.1:1/",
    "npm install --package-lock-only --ignore-scripts --userconfig /tmp/x",
    "npm install --package-lock-only --ignore-scripts -g",
    "npm ci --ignore-scripts --prefix /tmp/x",
    "npm ci --ignore-scripts --cache /tmp/x",
    "npm ci --ignore-scripts --script-shell /bin/sh",
    "npm ci --ignore-scripts --foreground-scripts",
    "npm ls --prefix /",
    "npm --prefix /tmp/x ls",
    "npm -C x ls",
    "npm -g ls",
    "npm --registry http://127.0.0.1:1/ ci --ignore-scripts",
    "npm --workspaces ls",
)


@pytest.mark.parametrize("line", DENIED_BY_NAME)
def test_the_npm_lines_that_start_code_or_move_npm_are_denied_by_name(line: str) -> None:
    """``deniedCommands`` is applied before the allow list, so these are denied by name as well as not allowed."""
    assert matches(shell()["deniedCommands"], line), line


@pytest.mark.parametrize("line", ["npm install left-pad", "npm run build"])
def test_the_policy_probes_npm_lines_against_a_weakened_entry(line: str) -> None:
    """A maintainer-added entry that lets an npm line through fails the approval."""
    for entry in (r"npm install(?: [a-z-]+)?", r"npm run [a-z]+"):
        document = change_config()
        document["toolsSettings"]["shell"]["allowedCommands"].append(entry)
        if re.fullmatch(entry, line):
            assert "toolsSettings.shell.allowedCommands" in {check for check, _ in problems(document)}


@pytest.mark.parametrize(
    "entry",
    [
        r"npm install(?: [a-z-]+)*",
        r"npm install --package-lock-only(?: --ignore-scripts)?",
        r"npm ci",
        r"npm run [a-z]+",
        r"npm exec [a-z]+",
        r"npx [a-z]+",
        r"npm ls(?: --prefix [a-z/]+)?",
        r"npm install --package-lock-only --ignore-scripts --prefix [a-z/]+",
        r"npm config set registry http://127\.0\.0\.1:1/",
    ],
)
def test_a_weakened_npm_entry_is_refused_by_the_approval(entry: str) -> None:
    """The entry is a valid pattern with no wildcard, yet it reaches a probe line: the approval must fail."""
    document = change_config()
    document["toolsSettings"]["shell"]["allowedCommands"].append(entry)
    assert "toolsSettings.shell.allowedCommands" in {check for check, _ in problems(document)}


def test_the_built_configuration_still_meets_the_policy() -> None:
    """The approval of the configuration with the npm forms."""
    assert problems(change_config()) == []


def test_the_approval_requires_the_npm_denies() -> None:
    """Without the denial of ``npx``, ``npm exec`` and the npm options, the approval names them."""
    document = change_config()
    document["toolsSettings"]["shell"]["deniedCommands"] = [
        entry
        for entry in document["toolsSettings"]["shell"]["deniedCommands"]
        if "npm" not in entry and "npx" not in entry
    ]
    found = dict(problems(document))["toolsSettings.shell.deniedCommands"]
    for line in ("npx id", "npm exec id", "npm install --package-lock-only --ignore-scripts --prefix /tmp/x"):
        assert line in found


def test_the_v3_rules_allow_the_three_literals_and_deny_the_rest() -> None:
    """CLI V3: the three lines are literal allow rules; exec, npx, run, config and the options are denied."""
    document = change_config()
    rules = [r for r in document["permissions"]["rules"] if r["capability"] == "shell"]
    allow = [m for r in rules if r["effect"] == "allow" for m in r["match"]]
    deny = [m for r in rules if r["effect"] == "deny" for m in r["match"]]
    for line in ALLOWED_LINES:
        assert line in allow
    for line in (
        "npm exec id",
        "npx id",
        "npm run x",
        "npm config set a b",
        "npm ci --ignore-scripts --prefix /x",
        "npm -g ls",
    ):
        assert any(agent_policy._glob_matches([pattern], line) for pattern in deny), line
    assert not any(agent_policy._glob_matches([pattern], "npm ls") for pattern in deny)
    assert not any(agent_policy._glob_matches([pattern], "npm ci --ignore-scripts") for pattern in deny)


def test_the_v3_approval_requires_the_npm_denies() -> None:
    """Remove the V3 deny rules: the approval names ``npm exec``."""
    document = change_config()
    document["permissions"]["rules"] = [
        r for r in document["permissions"]["rules"] if not (r["capability"] == "shell" and r["effect"] == "deny")
    ]
    assert "npm exec id" in dict(problems(document))["permissions.rules.shell"]


# --- the environment of the run -------------------------------------------------------------------


def child(parent: dict[str, str], tmp: str = "/tmp/handoff-child-x") -> dict[str, str]:
    """``command.child_env`` with the paths of a run."""
    return command.child_env(
        parent,
        push_url=f"{tmp}/no-such-remote",
        gh_config_dir=f"{tmp}/gh",
        aws_empty_file=f"{tmp}/aws-empty",
        npm_cache_dir=f"{tmp}/npm-cache",
    )


def test_npm_gets_a_cache_below_the_run_and_no_user_configuration() -> None:
    """The cache is in the run's temporary directory (writable also under an allow list); the configuration files are empty."""
    env = child({"PATH": "/usr/bin"})
    assert env["npm_config_cache"] == "/tmp/handoff-child-x/npm-cache"
    assert env["npm_config_userconfig"] == env["npm_config_globalconfig"] == "/tmp/handoff-child-x/aws-empty"
    assert env["npm_config_ignore_scripts"] == "true"
    assert env["npm_config_registry"] == "https://registry.npmjs.org/"
    assert env["npm_config_audit"] == env["npm_config_fund"] == env["npm_config_update_notifier"] == "false"


@pytest.mark.parametrize(
    "name",
    [
        "npm_config_registry",
        "NPM_CONFIG_REGISTRY",
        "npm_config_prefix",
        "NPM_CONFIG_//x:_authToken",
        "Npm_Config_Cache",
    ],
)
def test_the_parents_npm_configuration_does_not_reach_the_run(name: str) -> None:
    """An environment variable of the parent cannot move the registry, the prefix or the cache."""
    env = child({name: "http://127.0.0.1:1/"})
    assert "http://127.0.0.1:1/" not in env.values()
    assert name not in env or name.startswith("npm_config_")  # the lower-case names are the harness's own


def test_without_a_cache_directory_the_environment_is_what_it_was() -> None:
    """The parameter is optional: a caller that does not run npm gets no npm variable."""
    env = command.child_env({"PATH": "/usr/bin"}, push_url="/t/n", gh_config_dir="/t/g", aws_empty_file="/t/a")
    assert not [key for key in env if key.lower().startswith("npm_config_")]


# --- the dialect of kiro-cli's regular expressions (task 5.56, the selftest of 2026-11-16) ----------------------


def all_shell_entries() -> list[str]:
    """Every regular expression of ``toolsSettings.shell`` in the built change configuration."""
    return [*shell()["allowedCommands"], *shell()["deniedCommands"]]


def test_no_built_entry_uses_a_construct_that_kiro_cli_cannot_read() -> None:
    """A look-around or a back-reference made ``kiro-cli`` 2.32.0 refuse ``git add README.md`` in the selftest."""
    for entry in all_shell_entries():
        assert agent_policy._dialect_problem(entry) is None, entry


@pytest.mark.parametrize(
    "entry",
    [r"npm .*(?<= )-g.*", r"npm .*(?<! )-g.*", r"npm (?=x).*", r"npm (?!x).*", r"(a)\1", r"(?P<n>a)(?P=n)"],
)
@pytest.mark.parametrize("key", ["allowedCommands", "deniedCommands"])
def test_an_entry_that_kiro_cli_cannot_read_fails_the_approval(entry: str, key: str) -> None:
    """Python's ``re`` reads these, ``kiro-cli`` does not: the approval must name them."""
    document = change_config()
    document["toolsSettings"]["shell"][key].append(entry)
    assert f"toolsSettings.shell.{key}" in {check for check, _ in problems(document)}


def test_the_option_deny_still_matches_short_global_options() -> None:
    """The rewrite without look-behind keeps ``-g`` and ``-C`` denied and leaves the three forms alone."""
    for line in ("npm -g ls", "npm -C x ls", "npm install --package-lock-only --ignore-scripts -g", "npm ls -g"):
        assert matches(shell()["deniedCommands"], line), line
    for line in ALLOWED_LINES:
        assert not matches(shell()["deniedCommands"], line), line
