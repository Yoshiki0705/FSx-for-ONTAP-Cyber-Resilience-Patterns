"""Tests of the ``toolsSettings`` that the approval of an agent configuration requires (T4-01).

The configuration that was approved before had ``toolsSettings: {}``: its ``shell`` and ``write`` reached every
path and command of the user. The first test below is that configuration; it must not be approved. The others
take one setting away from a configuration that passes, and each must fail by itself.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any

import pytest
from handoff import agent_policy
from hypothesis import given, settings
from hypothesis import strategies as st

GUARD = "python3 /home/x/.private/handoff/agents/guard-wrapper.py /home/x/.kiro/hooks/scripts/pre_tool_dispatch.py"


def change_config() -> dict[str, Any]:
    """A change-mode configuration that meets the policy."""
    return agent_policy.build_agent_config("change", name="handoff-change", guard_command=GUARD)


def problems(document: dict[str, Any]) -> list[tuple[str, str]]:
    """The failed checks for the tools that the document lists."""
    return agent_policy.settings_problems(document, [*document["tools"], *document["allowedTools"]])


def test_the_configuration_that_was_approved_before_is_refused() -> None:
    """``toolsSettings: {}`` with ``fs_read``, ``fs_write`` and ``shell``: every restriction is missing."""
    document = {
        "tools": ["fs_read", "fs_write", "shell"],
        "allowedTools": ["fs_read", "fs_write", "shell"],
        "toolsSettings": {},
    }
    assert {check for check, _ in problems(document)} == {
        "allowedTools",
        "toolsSettings.write",
        "toolsSettings.read",
        "toolsSettings.shell",
        "permissions.rules",
    }


@pytest.mark.parametrize("mode", ["change", "query"])
def test_the_built_configurations_meet_the_policy(mode: str) -> None:
    """What this module builds passes its own check, and carries the two guards in change mode."""
    document = agent_policy.build_agent_config(
        mode, name=f"handoff-{mode}", guard_command=GUARD if mode == "change" else None
    )
    assert problems(document) == []
    assert document["mcpServers"] == {} and document["includeMcpJson"] is False
    assert json.loads(json.dumps(document)) == document
    assert ("hooks" in document) is (mode == "change")


def test_a_query_configuration_needs_the_read_restrictions_only() -> None:
    """Query mode lists ``fs_read`` only, so write and shell settings are not asked for."""
    document = agent_policy.build_agent_config("query", name="handoff-query")
    assert [tool for tool in document["tools"]] == ["fs_read"]
    assert "write" not in document["toolsSettings"] and "shell" not in document["toolsSettings"]


@pytest.mark.parametrize("path", agent_policy.WRITE_DENIED_PATHS)
def test_each_write_denied_path_is_required(path: str) -> None:
    """Dropping one entry of ``write.deniedPaths`` fails the check."""
    document = change_config()
    document["toolsSettings"]["write"]["deniedPaths"].remove(path)
    assert [check for check, _ in problems(document)] == ["toolsSettings.write.deniedPaths"]


@pytest.mark.parametrize("path", agent_policy.READ_DENIED_PATHS)
def test_each_read_denied_path_is_required(path: str) -> None:
    """Dropping one entry of ``read.deniedPaths`` fails the check."""
    document = change_config()
    document["toolsSettings"]["read"]["deniedPaths"].remove(path)
    assert [check for check, _ in problems(document)] == ["toolsSettings.read.deniedPaths"]


@pytest.mark.parametrize(
    ("mutate", "check"),
    [
        (lambda s: s.update(denyByDefault=False), "toolsSettings.shell.denyByDefault"),
        (lambda s: s.pop("denyByDefault"), "toolsSettings.shell.denyByDefault"),
        (lambda s: s.update(autoAllowReadonly=True), "toolsSettings.shell.autoAllowReadonly"),
        (lambda s: s["allowedCommands"].append("curl .*"), "toolsSettings.shell.allowedCommands"),
        (lambda s: s["allowedCommands"].append("gh .*"), "toolsSettings.shell.allowedCommands"),
        (lambda s: s["allowedCommands"].append("aws .*"), "toolsSettings.shell.allowedCommands"),
        (lambda s: s["allowedCommands"].append("bash -c .*"), "toolsSettings.shell.allowedCommands"),
        (lambda s: s["allowedCommands"].append("python3? .*"), "toolsSettings.shell.allowedCommands"),
        (lambda s: s["allowedCommands"].append("git .*"), "toolsSettings.shell.allowedCommands"),
        (lambda s: s["allowedCommands"].append(".*"), "toolsSettings.shell.allowedCommands"),
        (lambda s: s["allowedCommands"].append("cat .*"), "toolsSettings.shell.allowedCommands"),
        (lambda s: s.update(deniedCommands=[]), "toolsSettings.shell.deniedCommands"),
        (lambda s: s["deniedCommands"].pop(0), "toolsSettings.shell.deniedCommands"),
        (lambda s: s.update(allowedCommands="make test"), "toolsSettings.shell.allowedCommands"),
        (lambda s: s["allowedCommands"].append("("), "toolsSettings.shell.allowedCommands"),
    ],
)
def test_each_shell_restriction_is_required(mutate: Any, check: str) -> None:
    """One weakened shell setting fails with its own check (and the others stay quiet)."""
    document = change_config()
    mutate(document["toolsSettings"]["shell"])
    assert check in {name for name, _ in problems(document)}


def test_a_write_tool_needs_allowed_paths_below_the_working_directory() -> None:
    """``write.allowedPaths`` that reaches ``~`` or the root is refused, and so is a missing list."""
    document = change_config()
    document["toolsSettings"]["write"]["allowedPaths"] = ["~/Projects", "./**"]
    assert [check for check, _ in problems(document)] == ["toolsSettings.write.allowedPaths"]
    del document["toolsSettings"]["write"]["allowedPaths"]
    assert [check for check, _ in problems(document)] == ["toolsSettings.write.allowedPaths"]


def test_settings_under_an_alias_name_do_not_count() -> None:
    """The policy reads the canonical names ``write``, ``read`` and ``shell`` only."""
    document = change_config()
    settings = document["toolsSettings"]
    document["toolsSettings"] = {
        "fs_write": settings["write"],
        "fs_read": settings["read"],
        "execute_bash": settings["shell"],
    }
    assert {"toolsSettings.write", "toolsSettings.read", "toolsSettings.shell"} <= {
        check for check, _ in problems(document)
    }


def test_a_tool_that_is_not_listed_asks_for_no_setting() -> None:
    """Without ``shell`` in the tools, a missing ``shell`` section is not a problem."""
    document = change_config()
    document["tools"] = document["allowedTools"] = ["fs_read"]
    del document["toolsSettings"]["shell"], document["toolsSettings"]["write"]
    document["permissions"] = {"rules": document["permissions"]["rules"][:2]}
    assert problems(document) == []


def test_the_policy_does_not_change_its_input() -> None:
    """The check reads; it does not repair."""
    document = change_config()
    before = copy.deepcopy(document)
    problems(document)
    assert document == before


def test_the_built_allowed_commands_let_the_verification_commands_through_and_stop_the_rest() -> None:
    """A positive control: the allowed list matches ``make test`` and ``git status``, and no forbidden line."""
    import re

    shell = change_config()["toolsSettings"]["shell"]
    allowed = [re.compile(entry) for entry in shell["allowedCommands"]]
    denied = [re.compile(entry) for entry in shell["deniedCommands"]]
    for line in ("make test", "git status --short", 'git commit -m "message"', "python3 scripts/check.py"):
        assert any(entry.fullmatch(line) for entry in allowed), line
    for line in (
        "curl http://127.0.0.1:1/",
        "git push origin HEAD",
        "git config alias.x !id",
        "gh auth token",
        "python3 -c print(1)",
    ):
        assert not any(entry.fullmatch(line) for entry in allowed), line
        assert any(entry.fullmatch(line) for entry in denied), line


# --------------------------------------------------------------------------------------------
# R2-01: the allowed commands are fixed forms; an allowed command cannot leave the worktree
# --------------------------------------------------------------------------------------------

HOME = "/Users/example"

#: The lines of the review (T4-R2-01) that the approved configuration let through: a read of the credential
#: directories and of a file outside the worktree, and a write outside it, each by a command that was allowed.
REVIEW_ATTACKS = (
    f"grep -r AKIA {HOME}/.aws",
    f"ls {HOME}/.ssh",
    "cat ./../../../.ssh/id_rsa",
    f"git diff --no-index /dev/null {HOME}/.aws/credentials",
    f"git show --output={HOME}/.zshrc HEAD",
    "git log --output=/tmp/x",
)

#: The ``allowedCommands`` that the configuration had before R2-01.
OLD_ALLOWED = (
    r"git (?:status|diff|log|show|rev-parse|add|commit|ls-files)(?: [^;&|`$<>]*)?",
    r"make [a-z0-9_-]+",
    r"python3? [A-Za-z0-9_./-]+\.py(?: [A-Za-z0-9_./=:,@-]+)*",
    r"grep [^;&|`$<>]*",
    r"ls(?: [^;&|`$<>~]*)?",
    r"cat \./[^;&|`$<>~]*",
)


def test_every_line_of_the_review_matched_the_allowed_commands_of_before() -> None:
    """The control of the test above: with the old list, each of the six lines is allowed, so the test would fail on it."""
    for line in REVIEW_ATTACKS:
        assert full_matches(list(OLD_ALLOWED), line), line


def allowed_entries() -> list[str]:
    """The ``allowedCommands`` of the built change configuration."""
    return list(change_config()["toolsSettings"]["shell"]["allowedCommands"])


def full_matches(entries: list[str], line: str) -> bool:
    """Whether ``kiro-cli`` would read an entry as matching ``line``: a full match."""
    return any(re.fullmatch(entry, line) for entry in entries)


@pytest.mark.parametrize("line", REVIEW_ATTACKS)
def test_no_built_allowed_command_matches_a_line_of_the_review(line: str) -> None:
    """The six lines that the review ran against the built configuration are not allowed any more."""
    assert not full_matches(allowed_entries(), line)


def test_the_old_allowed_commands_are_refused_by_the_approval() -> None:
    """The ``allowedCommands`` of before R2-01 fail the approval, each entry by itself and with the attack lines named."""
    for entry in OLD_ALLOWED:
        if entry.startswith(("make", "python")):
            continue
        document = change_config()
        document["toolsSettings"]["shell"]["allowedCommands"] = [entry]
        found = [
            detail
            for check, detail in agent_policy.settings_problems(
                document, [*document["tools"], *document["allowedTools"]], home=HOME
            )
            if check == "toolsSettings.shell.allowedCommands"
        ]
        assert found, entry
    document = change_config()
    document["toolsSettings"]["shell"]["allowedCommands"] = list(OLD_ALLOWED)
    assert any(
        "adversarial" in detail
        for _check, detail in agent_policy.settings_problems(
            document, [*document["tools"], *document["allowedTools"]], home=HOME
        )
    )


@pytest.mark.parametrize(
    "entry",
    [
        r"grep .*",
        r"git diff .*",
        r"cat \./.*",
        r"ls .*",
        r"git (?:log|show)(?: [^;&|`$<>]*)?",
        r"git diff [^;&|`$<>]*",
        r"cat \./[^;&|`$<>~]*",
        r"git show \S+",
        r"git show [ -~]+",
        r"git show [a-z./]+",
        r"make .+",
        r"git status(?: .+)?",
        r"python3 [^ ]+\.py",
    ],
)
def test_a_weakened_allowed_command_is_refused(entry: str) -> None:
    """Adding one wildcard entry to the built list fails the approval (the mutations the review tried)."""
    document = change_config()
    document["toolsSettings"]["shell"]["allowedCommands"].append(entry)
    found = [
        check
        for check, _ in agent_policy.settings_problems(
            document, [*document["tools"], *document["allowedTools"]], home=HOME
        )
    ]
    assert "toolsSettings.shell.allowedCommands" in found


def test_the_built_allowed_commands_hold_no_wildcard_and_match_no_adversarial_line() -> None:
    """The enumeration itself: every probe line against every built entry, with the home of the approver."""
    entries = allowed_entries()
    assert not any(".*" in entry or ".+" in entry or "[^" in entry or "\\S" in entry for entry in entries)
    lines = agent_policy._probe_lines(HOME)
    assert len(lines) > 1500
    assert [line for line in lines if full_matches(entries, line)] == []


def test_the_adversarial_lines_name_the_home_of_the_approver() -> None:
    """The home is put in the lines, so that an entry that allows that very directory is found."""
    lines = agent_policy._probe_lines("/home/someone")
    assert "cat /home/someone/.aws/credentials" in lines
    assert "git diff --stat /home/someone/.ssh" in lines


@pytest.mark.parametrize(
    "line",
    [
        "git status",
        "git status --short",
        "git diff --stat docs/ja/x.md",
        "git log --oneline",
        "git show HEAD",
        "git add -A",
        "git add docs/ja/x.md scripts/a.py",
        'git commit -m "feat: add a thing"',
        'git commit --allow-empty -q -m "handoff-selftest-t1-0123456789abcdef 192.0.2.1"',
        "git rev-parse --short HEAD",
        "make test",
        "python3 scripts/check_x.py",
    ],
)
def test_the_fixed_forms_still_allow_the_work_of_a_change_item(line: str) -> None:
    """A control: what a change item does is allowed, so that a pass of the checks above is not a refusal of everything."""
    assert full_matches(allowed_entries(), line)


_ALPHABET = st.sampled_from(list("abcxyz019_-./~$ ;&|<>`'\"*?=:,"))


@settings(max_examples=400, deadline=None)
@given(
    prefix=st.sampled_from(
        ["git status", "git diff", "git log", "git show", "git add", "make", "python3", "git commit -m"]
    ),
    tail=st.text(alphabet=_ALPHABET, min_size=0, max_size=24),
)
def test_a_line_that_an_allowed_command_matches_names_no_path_outside_the_worktree(prefix: str, tail: str) -> None:
    """Property: whatever the tail, a matched line has no word that is absolute, home-relative, ``..``-bearing,
    an option that is not listed, or a shell metacharacter outside the quotes of a commit message."""
    line = f"{prefix} {tail}"
    if not full_matches(allowed_entries(), line):
        return
    unquoted = re.sub(r'"[^"]*"', '""', line)
    assert not set(unquoted) & set("~$;&|<>`'\\*?")
    for word in unquoted.split():
        assert not word.startswith(("/", "~"))
        assert ".." not in word
        if word.startswith("-"):
            assert word in {
                "-m",
                "-A",
                "-q",
                "-p",
                "--stat",
                "--name-only",
                "--name-status",
                "--oneline",
                "--no-color",
                "--cached",
                "--short",
                "--allow-empty",
            }


def test_the_wildcard_check_reads_the_pattern_and_not_its_text() -> None:
    """``\\.*`` (a dot, then any number of dots) is not the wildcard ``.*``; the dot as an escaped character is fine."""
    assert agent_policy._wildcard_problem(r"git status \.\.") is None
    assert agent_policy._wildcard_problem(r"git status .*") is not None
    assert agent_policy._wildcard_problem(r"git status [^a]") is not None
    assert agent_policy._wildcard_problem(r"git status [a-z/]") is not None
    assert agent_policy._wildcard_problem(r"git status [ -~]") is not None
    assert agent_policy._wildcard_problem(r"git status (?:a|.)") is not None
    assert agent_policy._wildcard_problem(r"git status [a-z0-9_-]+") is None


# --------------------------------------------------------------------------------------------
# R2-03: the limits are stated for CLI V3 (permissions.rules) as well as for 2.x (toolsSettings)
# --------------------------------------------------------------------------------------------


def rules(document: dict[str, Any]) -> list[dict[str, Any]]:
    """The ``permissions.rules`` of a document."""
    return document["permissions"]["rules"]


def test_the_built_configuration_states_every_limit_in_permissions_rules() -> None:
    """Deny rules for the write paths, the read paths and the dangerous shell lines, and allow rules that are literal."""
    document = change_config()
    denied = {
        (rule["capability"], entry) for rule in rules(document) if rule["effect"] == "deny" for entry in rule["match"]
    }
    for path in agent_policy.WRITE_DENIED_PATHS:
        assert ("fs_write", path) in denied
    for path in agent_policy.READ_DENIED_PATHS:
        assert ("fs_read", path) in denied
    for rule in rules(document):
        if rule["effect"] == "allow" and rule["capability"] == "shell":
            assert not any("*" in entry for entry in rule["match"])
        if rule["effect"] == "allow" and rule["capability"] in ("fs_read", "fs_write"):
            assert all(entry.startswith("./") for entry in rule["match"])


def test_permissions_rules_are_required_even_when_tools_settings_pass() -> None:
    """CLI V3 ignores ``toolsSettings``: a configuration with only that is not approved."""
    document = change_config()
    del document["permissions"]
    assert "permissions.rules" in {check for check, _ in problems(document)}


@pytest.mark.parametrize("path", agent_policy.WRITE_DENIED_PATHS)
def test_each_write_deny_of_permissions_rules_is_required(path: str) -> None:
    """Dropping one path from the ``fs_write`` deny rule fails the check."""
    document = change_config()
    for rule in rules(document):
        if rule["capability"] == "fs_write" and rule["effect"] == "deny":
            rule["match"].remove(path)
    assert [check for check, _ in problems(document)] == ["permissions.rules.fs_write"]


@pytest.mark.parametrize("path", agent_policy.READ_DENIED_PATHS)
def test_each_read_deny_of_permissions_rules_is_required(path: str) -> None:
    """Dropping one path from the ``fs_read`` deny rule fails the check."""
    document = change_config()
    for rule in rules(document):
        if rule["capability"] == "fs_read" and rule["effect"] == "deny":
            rule["match"].remove(path)
    assert [check for check, _ in problems(document)] == ["permissions.rules.fs_read"]


def test_the_shell_deny_rules_of_permissions_must_match_each_dangerous_line() -> None:
    """Without the shell deny rule, every line of the required list is reported; with ``cat*`` gone, the reader is."""
    document = change_config()
    document["permissions"]["rules"] = [
        rule for rule in rules(document) if not (rule["capability"] == "shell" and rule["effect"] == "deny")
    ]
    found = dict(problems(document))
    assert "cat /home/u/.aws/credentials" in found["permissions.rules.shell"]
    document = change_config()
    for rule in rules(document):
        if rule["capability"] == "shell" and rule["effect"] == "deny":
            rule["match"].remove("cat*")
    assert "cat /home/u/.aws/credentials" in dict(problems(document))["permissions.rules.shell"]


@pytest.mark.parametrize(
    "rule",
    [
        {"capability": "shell", "match": ["git *"], "effect": "allow"},
        {"capability": "shell", "match": ["git diff*"], "effect": "allow"},
        {"capability": "fs_write", "match": ["~/Projects/**"], "effect": "allow"},
        {"capability": "fs_read", "match": ["**"], "effect": "allow"},
        {"capability": "fs_read", "effect": "allow"},
        {"capability": "all", "effect": "allow"},
        {"capability": "filesystem", "match": ["./**"], "effect": "allow"},
        {"capability": "mcp", "match": ["x/*"], "effect": "allow"},
    ],
)
def test_a_broad_allow_rule_of_permissions_is_refused(rule: dict[str, Any]) -> None:
    """A shell allow with a glob, a path outside ``./``, no ``match`` and a meta-capability all fail the approval."""
    document = change_config()
    rules(document).append(rule)
    assert any(check.startswith("permissions.rules") for check, _ in problems(document))


def test_the_query_configuration_states_the_read_limits_in_permissions_rules() -> None:
    """Query mode has the read allow and deny rules, and no write or shell rule."""
    document = agent_policy.build_agent_config("query", name="handoff-query")
    assert {rule["capability"] for rule in rules(document)} == {"fs_read"}
    assert problems(document) == []


@pytest.mark.parametrize("mode", ["change", "query"])
def test_the_built_configurations_trust_the_read_tool_only(mode: str) -> None:
    """``allowedTools`` holds ``fs_read`` alone, so ``kiro-cli`` applies ``allowedPaths`` and ``denyByDefault``.

    With ``shell`` and ``fs_write`` in ``allowedTools``, ``kiro-cli`` 2.32.0 ran ``uname -s > file`` and wrote
    ``../outside.txt`` (selftest T7 and T8, 2026-11-15); with ``fs_read`` alone it refused both.
    """
    document = agent_policy.build_agent_config(
        mode, name=f"handoff-{mode}", guard_command=GUARD if mode == "change" else None
    )
    assert document["allowedTools"] == ["fs_read"]
    assert document["tools"] == (["fs_read", "fs_write", "shell"] if mode == "change" else ["fs_read"])


@pytest.mark.parametrize("trusted", ["fs_write", "shell", "write", "execute_bash"])
def test_a_write_or_shell_tool_in_allowed_tools_is_refused(trusted: str) -> None:
    """A trusted write or shell tool skips the checks that ``allowedPaths`` and ``denyByDefault`` make."""
    document = change_config()
    document["allowedTools"] = ["fs_read", trusted]
    assert "allowedTools" in {check for check, _ in agent_policy.settings_problems(document, [*document["tools"], trusted])}
