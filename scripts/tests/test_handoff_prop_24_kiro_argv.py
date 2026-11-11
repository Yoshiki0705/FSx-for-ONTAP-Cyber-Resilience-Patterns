"""Property 24: the ``kiro-cli`` argv stays within the tool ceiling, and is not built without its limits.

Task 1.14 of the phase 4 spec. The property (design, Correctness Properties) validates
Requirements 28.7, 28.14, 28.15 and 28.17:

- ``command.build_kiro_argv`` refuses, with ``CommandError`` and no argv, when
  ``timeout_seconds`` or ``max_concurrency`` is missing or not an integer of 1 or more, and when
  a change item has no ``guards_active`` selftest.
- An argv it returns starts with ``[kiro_cli, "chat", "--no-interactive"]`` and ends with the
  prompt as one element. Its one trust option is ``--trust-tools=`` with the item's own tools,
  all in the ceiling of the item's mode (``fs_read`` alone for a query item), or
  ``--trust-all-tools`` for a change item whose ``trust_all`` has a reason, an approval time and
  an approval record. ``-a`` never appears. Both hold for the whole argv, the prompt's place
  included, so a prompt such as ``-a`` (:data:`OPTION_PROMPTS`) must be refused.
- ``git push`` and ``gh pr create`` appear only in ``command.build_publish_plan``, and there only
  for items that the approval lists and that succeeded. No command of ``build_git_plan`` and no
  option of ``build_kiro_argv`` is ``push`` or ``gh``. Every item of the manifest may have a
  usable pull-request spec, listed or not, so that the approval and the state decide.

How the property is read, following the record of task 1.9: ``kiro_cli`` in the argv is
``normalize_path(config.kiro_cli, home)``. ``bool`` is not an integer of 1 or more (the Data
Models make both limits integers of 1 or more), so ``True`` is refused. "``fs_read`` alone for a
query item" rules out ``--trust-all-tools`` for one too; a valid manifest never gives a query
item a ``trust_all``. The pull-request argv also has ``--title`` and ``--repo``; only the branch
it names is checked here.

Inputs. Configurations, manifests and statuses come from ``strategies.handoff``. An example of
the first test draws one configuration, one query item and one change item, and builds one case
for each scenario of :data:`SCENARIOS`: no defect, one defect, or several. A planted defect is
invalid by construction, and a case without one must be built, so neither ``filter`` nor
``assume`` is needed. The limits take the values of ``CONFIG_DEFECTS`` with ``MISSING`` read as
``None``, as a ``HandoffConfig`` built without ``parse_config`` can hold them, and the other
values of :func:`bad_limits`. An example of the second test draws one manifest, status, approval
and set of pull-request specs (:func:`publish_cases`).

Counts. Each test function runs its search in an inner function and then checks that the
examples the property is about were drawn (:data:`KIRO_KINDS`, :data:`PUBLISH_KINDS`). A search
in which no argv was built, or no plan had a step, fails instead of passing vacuously. So does a
search in which no item left out as ``not_approved`` or ``not_succeeded`` would have been
published had the approval listed it, or had it succeeded: the plan is built again with that
one change to find out. Every value is synthetic.
"""

from __future__ import annotations

import dataclasses
import posixpath
from collections import Counter
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Final

from handoff import command, state
from handoff.config import MODES, HandoffConfig, normalize_path
from handoff.evaluate import GUARDS_ACTIVE, UNCONFIRMED
from handoff.manifest import Item, Manifest, TrustAll
from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy
from strategies import handoff as handoff_strategies

#: The home directory of every configuration of ``strategies.handoff``.
HOME: Final = handoff_strategies.HOME

#: ``handoff_dir`` of the publish plans: this repository's ``.private/handoff``.
HANDOFF_DIR: Final = handoff_strategies.THIS_REPO_TREE + "/.private/handoff"

#: The words that make an argv a push or a pull-request command.
PUBLISH_WORDS: Final = frozenset({"push", "gh"})

#: Tool names that no ceiling of ``strategies.handoff`` holds, among them tools that could push or
#: call AWS.
OUTSIDE_TOOLS: Final = ("execute_bash", "use_aws", "@example-mcp/create_pull_request", "@example-mcp/push_files")

#: Names that ``kiro-cli`` reads as two tools. ``parse_config`` accepts any non-empty string in a
#: ceiling, so a configuration can hold one; split at the comma, neither half is in the ceiling.
COMMA_TOOLS: Final = ("fs_read,execute_bash", "fs_write,use_aws")

#: Names that are not one tool name: two joined, a pattern, blank, padded, two words, two lines.
ODD_TOOLS: Final = ("fs_read,fs_write", "*", "fs_*", "", " fs_read", "fs read", "fs_read\n")

#: Modes that are not modes.
BAD_MODES: Final = ("Query", "CHANGE", "publish", "manual", "", "change ")

#: Selftest results other than ``guards_active``.
BAD_SELFTESTS: Final[tuple[str | None, ...]] = (
    UNCONFIRMED,
    None,
    "GUARDS_ACTIVE",
    "guards_active ",
    "guards-active",
    "",
)

#: ``kiro_cli`` values that are not absolute after ``~`` expansion, or blank.
BAD_KIRO_CLI: Final = ("kiro-cli", "bin/kiro-cli", "./kiro-cli", "~other/bin/kiro-cli", "", "   ")

#: Agent names that read as options, or that are not of the agent-name form.
WEIRD_AGENTS: Final = ("-a", "--trust-all-tools", "--trust-tools=execute_bash", "agent name", "handoff/change")

#: Prompts that can be the last argv element although they look like words of a command.
TRICKY_PROMPTS: Final = (
    "push",
    "gh",
    "chat",
    "git push origin handoff/example",
    "gh pr create --draft --base main",
    "do not pass -a or --trust-all-tools",
    "line one\n--trust-all-tools\n-a",
    "$(touch x) `id` 'single' \"double\" \\ ; | & > <",
    " a leading space",
    "## 1. 対象リポジトリ\n\n本文",
)

#: Prompts that ``kiro-cli`` would read as a trust option if one were the last argv element:
#: ``-a``, ``--trust-all-tools``, and ``--trust-tools=`` with tools outside every ceiling.
OPTION_PROMPTS: Final = ("-a", "--trust-all-tools", "--trust-tools=execute_bash", "--trust-tools=fs_read,use_aws")

#: Prompts that ``build_kiro_argv`` refuses: blank, a leading ``-``, NUL, a lone surrogate.
BAD_PROMPTS: Final = (
    "",
    " ",
    "\t\n",
    "\u3000",
    "-",
    "-a",
    "--trust-all-tools",
    "--agent",
    "- 箇条書きで始まる本文",
    "本文\x00の途中",
    "\ud800",
    "末尾\udfff",
)

#: The mode each defect needs, or ``None`` for either mode.
DEFECT_MODES: Final[Mapping[str, str | None]] = MappingProxyType(
    {
        "timeout_seconds": None,
        "max_concurrency": None,
        "selftest": "change",
        "tools_outside": "change",
        "tools_form": "change",
        "tools_shape": "change",
        "query_tools": "query",
        "trust_all_incomplete": "change",
        "query_trust_all": "query",
        "mode": None,
        "prompt": None,
        "kiro_cli": None,
        "agent": None,
    }
)

#: The scenarios without a defect, and the mode of each.
VALID_SCENARIOS: Final[Mapping[str, str]] = MappingProxyType(
    {"valid_query": "query", "valid_change": "change", "valid_change_trust_all": "change"}
)

#: The scenarios of one example of :func:`kiro_batches`, each built once from the example's
#: configuration and items. A defect alone is a scenario of its own, so that each check of
#: ``build_kiro_argv`` is the only one that can refuse some case of every example; ``several``
#: plants two or three defects that fit one mode.
SCENARIOS: Final[tuple[str, ...]] = (*VALID_SCENARIOS, *DEFECT_MODES, "several", "several")

#: The kinds of example that the search of :func:`test_property_24_kiro_argv` must draw.
KIRO_KINDS: Final = ("returned:query", "returned:change", "returned:trust_all", "refused:limit", "refused:selftest")

#: The kinds of example that the search of the publish test must draw. ``would_publish:*``: an
#: item left out only because the approval does not list it, or only because it has not
#: succeeded.
PUBLISH_KINDS: Final = (
    "steps",
    "excluded:not_approved",
    "excluded:not_succeeded",
    "would_publish:if_listed",
    "would_publish:if_succeeded",
)

#: The prompt of the ``kiro-cli`` argvs built in the publish test.
PROMPT: Final = "合成の Handoff_Prompt。git push と gh pr create は行わない。"

_EPOCH: Final = datetime(2026, 1, 1, tzinfo=timezone.utc)
_TRUST_ALL_PARTS: Final = ("reason", "approved_at", "approved_in")
_TRUST_ALL_REASONS: Final = ("the generator of this item asks for every tool", "生成の手順が確認なしの実行を求める")
_PROMPT_CHARACTERS: Final = st.characters(exclude_categories=("Cs",), exclude_characters="\x00")
_PROMPT_STARTS: Final = st.characters(exclude_categories=("Cs", "Cc", "Zs", "Zl", "Zp"), exclude_characters="-")
_HEX_DIGITS: Final = "0123456789abcdef"

#: The transitions that take an item from each state to ``succeeded``.
_TO_SUCCEEDED: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        state.QUEUED: (state.RUNNING, state.SUCCEEDED),
        state.RUNNING: (state.SUCCEEDED,),
        state.FAILED: (state.QUEUED, state.RUNNING, state.SUCCEEDED),
        state.NEEDS_HUMAN: (state.QUEUED, state.RUNNING, state.SUCCEEDED),
        state.SUCCEEDED: (),
    }
)

#: Changes that make a pull-request spec unusable.
_BAD_PULL_REQUEST_FIELDS: Final = (
    {"github_repo": "example-owner"},
    {"github_repo": "-x/example-hub"},
    {"title": ""},
    {"title": "-x"},
    {"title": "two\nlines"},
    {"body_file": HOME + "/.aws/credentials"},
    {"body_file": "pr-body.md"},
)


# --------------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------------


def is_limit(value: object) -> bool:
    """Whether a value is an integer of 1 or more. ``bool`` is not one.

    Args:
        value: The value of ``timeout_seconds`` or ``max_concurrency``.

    Returns:
        True for an ``int`` (not a ``bool``) of 1 or more.
    """
    return type(value) is int and value >= 1


def has_all_three(trust_all: TrustAll | None) -> bool:
    """Whether a ``trust_all`` has a reason, an approval time and an approval record, none blank.

    Args:
        trust_all: The item's ``trust_all``.

    Returns:
        True when all three parts are non-blank strings.
    """
    if trust_all is None:
        return False
    parts = [getattr(trust_all, part) for part in _TRUST_ALL_PARTS]
    return all(isinstance(part, str) and bool(part.strip()) for part in parts)


def positionals(options: Collection[str]) -> list[str]:
    """Return the elements of the options that are not an option or the value of ``--agent``.

    Args:
        options: The argv elements between ``--no-interactive`` and the prompt.

    Returns:
        The elements that ``kiro-cli`` would read as positional arguments, in order.
    """
    found: list[str] = []
    value_next = False
    for option in options:
        if value_next:
            value_next = False
        elif option == command.AGENT_OPTION:
            value_next = True
        elif not option.startswith("-"):
            found.append(option)
    return found


def publish_words(argv: tuple[str, ...]) -> set[str]:
    """Return the words of an argv that make it a push or a pull-request command.

    Args:
        argv: An argv, without the prompt of a ``kiro-cli`` argv.

    Returns:
        ``push`` and ``gh`` where an element is one of them, and ``gh`` when the program is ``gh``.
    """
    words = {word for word in argv if word in PUBLISH_WORDS}
    if argv and posixpath.basename(argv[0]) == "gh":
        words.add("gh")
    return words


def branch_names(argv: tuple[str, ...]) -> list[str]:
    """Return the elements of an argv that name a handoff branch.

    Args:
        argv: A push or pull-request argv.

    Returns:
        Each element that starts with ``handoff/``, in order.
    """
    return [word for word in argv if word.startswith(command.BRANCH_PREFIX)]


def require_kinds(seen: Counter[str], kinds: Collection[str]) -> None:
    """Fail unless each kind of example was drawn at least once.

    Args:
        seen: How many examples of each kind the search drew.
        kinds: The kinds that must be there.
    """
    missing = [kind for kind in kinds if seen[kind] == 0]
    assert not missing, f"the search drew no example of {missing}; counts: {dict(sorted(seen.items()))}"


# --------------------------------------------------------------------------------------------
# Strategies for build_kiro_argv
# --------------------------------------------------------------------------------------------


def _planted_values(key: str) -> tuple[object, ...]:
    """Return the values of ``CONFIG_DEFECTS`` for one key, with ``MISSING`` read as ``None``."""
    return tuple(
        None if defect.value is handoff_strategies.MISSING else defect.value
        for defect in handoff_strategies.CONFIG_DEFECTS
        if defect.key == key
    )


def bad_limits(key: str) -> SearchStrategy[object]:
    """Draw a value of ``timeout_seconds`` or ``max_concurrency`` that is not an integer of 1 or more.

    Args:
        key: ``timeout_seconds`` or ``max_concurrency``.

    Returns:
        A strategy of the values of ``CONFIG_DEFECTS`` for the key (``None`` for ``MISSING``),
        0, booleans, negative integers, floats of 1 or more and integers of 1 or more written
        as strings. 0 has a branch of its own: ``integers(max_value=0)`` seldom draws it.
    """
    return st.one_of(
        st.sampled_from(_planted_values(key)),
        st.just(0),
        st.booleans(),
        st.integers(max_value=-1),
        st.floats(min_value=1.0, max_value=1e9),
        st.integers(1, 10**6).map(str),
    )


def _one_in(count: int) -> SearchStrategy[bool]:
    """Draw ``True`` in about one draw of ``count``."""
    return st.integers(1, count).map(lambda drawn: drawn == 1)


@st.composite
def complete_trust_alls(draw: st.DrawFn) -> TrustAll:
    """Draw a ``trust_all`` with all three parts, in the form ``parse_manifest`` accepts."""
    moment = _EPOCH + timedelta(seconds=draw(st.integers(0, 10**8)))
    return TrustAll(
        reason=draw(st.sampled_from(_TRUST_ALL_REASONS)),
        approved_at=state.format_timestamp(moment),
        approved_in=".private/tasks/" + draw(handoff_strategies.item_ids()) + ".md",
    )


@st.composite
def incomplete_trust_alls(draw: st.DrawFn) -> TrustAll:
    """Draw a ``trust_all`` with one to three of its parts blank."""
    complete = draw(complete_trust_alls())
    blank = draw(st.lists(st.sampled_from(_TRUST_ALL_PARTS), min_size=1, max_size=3, unique=True))
    return dataclasses.replace(complete, **{part: draw(st.sampled_from(("", " ", "\t"))) for part in blank})


def good_prompts() -> SearchStrategy[str]:
    """Draw a prompt that can be the last argv element: not blank, no leading ``-``, no NUL."""
    free = st.builds(str.__add__, _PROMPT_STARTS, st.text(_PROMPT_CHARACTERS, max_size=40))
    return st.sampled_from(TRICKY_PROMPTS) | free


def bad_prompts() -> SearchStrategy[str]:
    """Draw a prompt that ``build_kiro_argv`` refuses: blank, a leading ``-``, NUL or a lone surrogate.

    :data:`OPTION_PROMPTS` has a branch of its own, so that the checks on the whole argv in
    :func:`check_kiro_case` meet them in most searches.
    """
    blank = st.text(st.sampled_from(" \t\n\r\u3000\u2028"), max_size=4)
    dashed = st.text(_PROMPT_CHARACTERS, max_size=20).map("-".__add__)
    with_nul = st.builds(
        lambda head, tail: head + "\x00" + tail,
        st.text(_PROMPT_CHARACTERS, max_size=10),
        st.text(_PROMPT_CHARACTERS, max_size=10),
    )
    return st.one_of(st.sampled_from(BAD_PROMPTS), st.sampled_from(OPTION_PROMPTS), blank, dashed, with_nul)


def _inserted(draw: st.DrawFn, tools: tuple[str, ...], name: str) -> tuple[str, ...]:
    """Insert a tool name at a drawn position."""
    position = draw(st.integers(0, len(tools)))
    return (*tools[:position], name, *tools[position:])


def _wider_tools(ceiling: Collection[str]) -> SearchStrategy[str]:
    """Draw a tool name of ``TOOL_NAMES`` or :data:`OUTSIDE_TOOLS` that is not in a ceiling."""
    return st.sampled_from(sorted(set(handoff_strategies.TOOL_NAMES + OUTSIDE_TOOLS) - set(ceiling)))


@dataclass(frozen=True)
class KiroCase:
    """The arguments of one ``build_kiro_argv`` call, and what was planted in them.

    Attributes:
        config: The configuration, built with ``dataclasses.replace`` from a checked one.
        item: The item, built the same way from an item of a checked manifest.
        prompt: The prompt.
        selftest_result: The ``selftest_result`` argument.
        approved_agents: The ``approved_agents`` argument.
        scenario: A key of :data:`VALID_SCENARIOS` or :data:`DEFECT_MODES`, or ``several``.
        planted: The defects planted, keys of :data:`DEFECT_MODES`. Empty for a valid scenario.
        changed_limits: ``worktrees_root`` and ``min_free_disk_gb`` when a value of
            ``CONFIG_DEFECTS`` replaced them. Property 24 does not say what they do to the argv,
            so a case with one need not be built.
    """

    config: HandoffConfig
    item: Item
    prompt: str
    selftest_result: str | None
    approved_agents: frozenset[str]
    scenario: str
    planted: frozenset[str]
    changed_limits: tuple[str, ...]


@st.composite
def kiro_batches(draw: st.DrawFn) -> tuple[KiroCase, ...]:
    """Draw one :class:`KiroCase` per scenario of :data:`SCENARIOS`, from one configuration.

    The configuration comes from ``configs()``, and one query item and one change item from
    ``manifests(config=...)`` with one item each. Each case then changes copies of them.
    """
    config_case = draw(handoff_strategies.configs())
    items: dict[str, Item] = {}
    for mode in MODES:
        case = draw(handoff_strategies.manifests(config=config_case, max_items=1, modes=(mode,)))
        if case.manifest is None:
            raise AssertionError("manifests() drew a cyclic manifest without cyclic=True")
        items[mode] = case.manifest.items[0]
    config = config_case.config
    if config is None:
        raise AssertionError("configs() drew an invalid configuration without valid=False")
    return tuple(draw(_kiro_cases(config, items, scenario)) for scenario in SCENARIOS)


@st.composite
def _kiro_cases(draw: st.DrawFn, config: HandoffConfig, items: Mapping[str, Item], scenario: str) -> KiroCase:
    """Draw the :class:`KiroCase` of one scenario from a checked configuration and items."""
    if scenario in VALID_SCENARIOS:
        mode, planted = VALID_SCENARIOS[scenario], set()
    elif scenario == "several":
        mode = draw(st.sampled_from(MODES))
        fitting = [defect for defect, needs in DEFECT_MODES.items() if needs in (None, mode)]
        planted = set(draw(st.lists(st.sampled_from(fitting), min_size=2, max_size=3, unique=True)))
    else:
        needs = DEFECT_MODES[scenario]
        mode = needs if needs is not None else draw(st.sampled_from(MODES))
        planted = {scenario}
    item = items[mode]

    ceilings = {name: tuple(tools) for name, tools in config.mode_tool_ceiling.items()}
    tools = item.trust_tools
    trust_all = item.trust_all
    if mode == "change":
        if scenario == "valid_change":
            trust_all = None
        elif scenario == "valid_change_trust_all":
            trust_all = draw(complete_trust_alls())
        else:
            trust_all = draw(st.none() | complete_trust_alls())
    if "tools_outside" in planted:
        tools = _inserted(draw, tools, draw(_wider_tools(ceilings["change"])))
    if "tools_form" in planted:
        if draw(st.booleans()):
            odd = draw(st.sampled_from(COMMA_TOOLS))
            ceilings["change"] = (*ceilings["change"], odd)
        else:
            odd = draw(st.sampled_from(ODD_TOOLS))
        tools = _inserted(draw, tools, odd)
    if "tools_shape" in planted:
        tools = () if draw(st.booleans()) else _inserted(draw, tools, draw(st.sampled_from(tools)))
    if "trust_all_incomplete" in planted:
        trust_all = draw(incomplete_trust_alls())
    if mode == "query":
        if "query_tools" in planted:
            wider = draw(_wider_tools(("fs_read",)))
            ceilings["query"] = draw(st.sampled_from((("fs_read", wider), (wider, "fs_read"))))
            choices = (
                ("fs_read", wider),
                (wider, "fs_read"),
                (wider,),
                (),
                ("fs_read", "fs_read"),
                ("fs_read,fs_write",),
            )
            tools = draw(st.sampled_from(choices))
        elif draw(st.booleans()):
            ceilings["query"] = ("fs_read", draw(_wider_tools(("fs_read",))))
        if "query_trust_all" in planted:
            trust_all = draw(complete_trust_alls() | incomplete_trust_alls())

    agents = dict(config.agents)
    approved = set(draw(st.sets(st.sampled_from(handoff_strategies.AGENT_NAMES + WEIRD_AGENTS))))
    if "agent" in planted:
        weird = draw(st.sampled_from(WEIRD_AGENTS))
        agents[mode] = weird
        approved.add(weird)

    def limit(key: str, current: int) -> object:
        if key in planted:
            return draw(bad_limits(key))
        return draw(st.just(current) | st.integers(1, 10**9))

    changed: list[str] = []
    replaced: dict[str, object] = {}
    for key in ("worktrees_root", "min_free_disk_gb"):
        if draw(_one_in(10)):
            replaced[key] = draw(st.sampled_from(_planted_values(key)))
            changed.append(key)

    if "selftest" in planted:
        selftest: str | None = draw(st.sampled_from(BAD_SELFTESTS))
    elif mode == "change":
        selftest = GUARDS_ACTIVE
    else:
        selftest = draw(st.sampled_from((GUARDS_ACTIVE, *BAD_SELFTESTS)))

    built_config = dataclasses.replace(
        config,
        kiro_cli=draw(st.sampled_from(BAD_KIRO_CLI)) if "kiro_cli" in planted else config.kiro_cli,
        timeout_seconds=limit("timeout_seconds", config.timeout_seconds),
        max_concurrency=limit("max_concurrency", config.max_concurrency),
        mode_tool_ceiling=MappingProxyType(ceilings),
        agents=MappingProxyType(agents),
        **replaced,
    )
    built_item = dataclasses.replace(
        item,
        mode=draw(st.sampled_from(BAD_MODES)) if "mode" in planted else mode,
        trust_tools=tools,
        trust_all=trust_all,
    )
    return KiroCase(
        config=built_config,
        item=built_item,
        prompt=draw(bad_prompts()) if "prompt" in planted else draw(good_prompts()),
        selftest_result=selftest,
        approved_agents=frozenset(approved),
        scenario=scenario,
        planted=frozenset(planted),
        changed_limits=tuple(changed),
    )


# --------------------------------------------------------------------------------------------
# Property 24, build_kiro_argv
# --------------------------------------------------------------------------------------------


def check_kiro_case(case: KiroCase) -> tuple[str, ...]:
    """Check Property 24 on one ``build_kiro_argv`` call.

    Args:
        case: The arguments and what was planted in them.

    Returns:
        The kinds of the example, for the counts of :data:`KIRO_KINDS`.
    """
    config, item, prompt = case.config, case.item, case.prompt
    must_refuse = [key for key in ("timeout_seconds", "max_concurrency") if not is_limit(getattr(config, key))]
    if item.mode == "change" and case.selftest_result != GUARDS_ACTIVE:
        must_refuse.append("selftest")
    try:
        invocation = command.build_kiro_argv(
            config,
            item,
            prompt,
            home=HOME,
            selftest_result=case.selftest_result,
            approved_agents=case.approved_agents,
        )
    except command.CommandError as error:
        codes = {issue.code for issue in error.issues}
        unnamed = [code for code in must_refuse if code not in codes]
        assert not unnamed, f"refused without naming {unnamed}; the issues were {sorted(codes)}"
        assert case.planted or case.changed_limits, f"refused a case without a defect: {error}"
        kinds = ["refused"]
        if codes & {"timeout_seconds", "max_concurrency"}:
            kinds.append("refused:limit")
        if "selftest" in codes:
            kinds.append("refused:selftest")
        return tuple(kinds)

    assert not must_refuse, f"built an argv although {must_refuse} must refuse it: {invocation.argv!r}"
    argv = invocation.argv
    try:
        program = normalize_path(config.kiro_cli, HOME)
    except ValueError as exc:
        raise AssertionError(f"built an argv for kiro_cli {config.kiro_cli!r}: {exc}") from exc
    assert argv[:3] == (program, "chat", "--no-interactive"), argv
    assert argv[-1] == prompt, "the prompt is not the last element, whole"
    options = argv[3:-1]
    assert positionals(options) == [], f"positional arguments besides the prompt: {positionals(options)}"
    # The whole argv, the prompt's place included: a prompt "-a" would be read as the option.
    assert "-a" not in argv, argv
    trust_all_options = [o for o in argv if o == "--trust-all-tools" or o.startswith("--trust-all-tools=")]
    trust_tools_options = [o for o in argv if o.startswith("--trust-tools")]
    assert len(trust_all_options) + len(trust_tools_options) == 1, f"not one trust option: {argv}"
    assert item.mode in MODES, f"built an argv for the mode {item.mode!r}, which has no ceiling"
    if trust_all_options:
        assert item.mode == "change", f"a query item trusts fs_read only, got {options}"
        assert has_all_three(item.trust_all), f"--trust-all-tools without a complete trust_all: {item.trust_all}"
    else:
        (option,) = trust_tools_options
        assert option.startswith("--trust-tools="), option
        names = option[len("--trust-tools=") :].split(",")
        ceiling = config.mode_tool_ceiling[item.mode]
        assert set(names) <= set(ceiling), f"{names} not within the {item.mode} ceiling {ceiling}"
        if item.mode == "query":
            assert names == ["fs_read"], f"a query item trusts fs_read only, got {names}"
        assert names == list(item.trust_tools), f"not the item's own list {item.trust_tools}: {names}"
    assert not publish_words(argv[:-1]), argv
    assert invocation.timeout_seconds == config.timeout_seconds

    kinds = ["returned", f"returned:{item.mode}"]
    if trust_all_options:
        kinds.append("returned:trust_all")
    if command.AGENT_OPTION in options:
        kinds.append("returned:agent")
    return tuple(kinds)


# Feature: cyber-resilience-phase4-supply-chain, Property 24: kiro-cli の argv は許可一覧の上限を超えず、設定が欠ければ組み立てられない
def test_property_24_kiro_argv() -> None:
    """``build_kiro_argv`` refuses without its limits or a selftest, and builds only argvs within the ceiling.

    For any configuration, item, prompt, selftest result and set of approved agents of
    :func:`kiro_batches`: a missing or invalid ``timeout_seconds`` or ``max_concurrency``, and a
    change item without ``guards_active``, give ``CommandError`` naming them; a case without a
    planted defect gives an argv; and every argv has the form of :func:`check_kiro_case`. Each
    example checks one case per scenario of :data:`SCENARIOS`.

    **Validates: Requirements 28.7, 28.14, 28.15, 28.17**
    """
    seen: Counter[str] = Counter()

    @settings(max_examples=100, deadline=None)
    @given(kiro_batches())
    def check(batch: tuple[KiroCase, ...]) -> None:
        for case in batch:
            seen.update(check_kiro_case(case))

    check()
    require_kinds(seen, KIRO_KINDS)


# --------------------------------------------------------------------------------------------
# Property 24, the publish plan
# --------------------------------------------------------------------------------------------


def _moment(text: str) -> datetime:
    """Read a timestamp of ``status.json``."""
    return datetime.strptime(text, state.TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)


def _moved_to_succeeded(status: state.StatusDoc, item_id: str, gaps: Collection[timedelta]) -> state.StatusDoc:
    """Move one item of a status to ``succeeded`` along allowed transitions, later than its history.

    Args:
        status: The status. It is not changed.
        item_id: An item of the status.
        gaps: The time from one transition to the next, one per transition of
            :data:`_TO_SUCCEEDED`, the first counted from the item's last transition.

    Returns:
        A new status in which the item is ``succeeded``.
    """
    record = status["items"][item_id]
    moment = _moment(record["history"][-1]["at"]) if record["history"] else _EPOCH
    for target, gap in zip(_TO_SUCCEEDED[record["state"]], gaps, strict=True):
        moment += gap
        status = state.transition(status, item_id, target, at=state.format_timestamp(moment), reason="test_run")
    return status


@st.composite
def _succeeded(draw: st.DrawFn, status: state.StatusDoc, item_id: str) -> state.StatusDoc:
    """Move one item of a status to ``succeeded``, with drawn gaps (see :func:`_moved_to_succeeded`)."""
    count = len(_TO_SUCCEEDED[status["items"][item_id]["state"]])
    gaps = [timedelta(seconds=draw(st.integers(1, 10**7))) for _ in range(count)]
    return _moved_to_succeeded(status, item_id, gaps)


def _pull_request(item: Item) -> command.PullRequestSpec:
    """Build a usable pull-request spec for an item."""
    return command.PullRequestSpec(
        github_repo=f"example-owner/{item.repo}",
        title=f"docs: hand off {item.id}",
        body_file=f"{HANDOFF_DIR}/{item.repo}/{item.id}/pr-body.md",
    )


@dataclass(frozen=True)
class PublishCase:
    """The arguments of one ``build_publish_plan`` call.

    Attributes:
        config: A checked configuration.
        manifest: A checked manifest of two to six items, of both modes or of change items only.
        status: A status with a record for every item and up to one record outside the manifest.
        approval: The approval: items of the status and IDs that nothing has, in a drawn order.
        pull_requests: A spec for most items of the manifest, listed in the approval or not, a
            few of them unusable. A usable spec does not make an unlisted item publishable.
        base_sha: A SHA for the git plans of the manifest's items.
    """

    config: HandoffConfig
    manifest: Manifest
    status: state.StatusDoc
    approval: command.PublishApproval
    pull_requests: Mapping[str, command.PullRequestSpec]
    base_sha: str


@st.composite
def publish_cases(draw: st.DrawFn) -> PublishCase:
    """Draw a :class:`PublishCase`."""
    # Half of the manifests have change items only, so that more items can be published.
    modes = draw(st.sampled_from((MODES, ("change",))))
    case = draw(handoff_strategies.manifests(min_items=2, max_items=6, max_files=2, max_refs=1, modes=modes))
    if case.manifest is None:
        raise AssertionError("manifests() drew a cyclic manifest without cyclic=True")
    status = draw(handoff_strategies.statuses(ids=case.ids, max_outside=1))
    ids = sorted(status["items"])
    # One draw per item for moving it to succeeded (one in three; statuses() makes a fifth
    # succeeded already) and one for listing it, independent of each other, so that listed and
    # unlisted items, succeeded or not, are all common.
    for item_id in ids:
        if draw(_one_in(3)):
            status = draw(_succeeded(status, item_id))
    for item_id in draw(st.lists(st.sampled_from(ids), max_size=1)):
        status["items"][item_id]["published"] = {"approved_at": None, "pr": draw(st.integers(1, 9_999))}

    listed = [item_id for item_id in ids if draw(st.booleans())]
    listed += draw(st.lists(st.sampled_from(("unknown-1", "unknown-2")), max_size=2, unique=True))
    listed = draw(st.permutations(listed)) if listed else [draw(st.sampled_from([*ids, "unknown-1"]))]
    far = st.integers(0, 10**7).map(
        lambda seconds: datetime(2031, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    )
    within = st.integers(0, 10**8).map(lambda seconds: _EPOCH + timedelta(seconds=seconds))
    approval = command.PublishApproval(
        # Mostly after every transition: an approval within the history leaves items out as
        # succeeded_after_approval, which Property 24 does not cover.
        approved_at=state.format_timestamp(draw(within if draw(_one_in(5)) else far)),
        item_ids=tuple(listed),
        approved_in=".private/handoff/approvals/" + draw(handoff_strategies.item_ids()) + ".md",
    )

    pull_requests: dict[str, command.PullRequestSpec] = {}
    for item in case.manifest.items:
        kind = draw(st.sampled_from(("usable",) * 10 + ("unusable", "none")))
        if kind == "usable":
            pull_requests[item.id] = _pull_request(item)
        elif kind == "unusable":
            pull_requests[item.id] = dataclasses.replace(
                _pull_request(item), **draw(st.sampled_from(_BAD_PULL_REQUEST_FIELDS))
            )
    return PublishCase(
        config=case.config,
        manifest=case.manifest,
        status=status,
        approval=approval,
        pull_requests=MappingProxyType(pull_requests),
        base_sha=draw(st.text(_HEX_DIGITS, min_size=40, max_size=40)),
    )


def check_publish_case(case: PublishCase) -> tuple[str, ...]:
    """Check the publish part of Property 24 on one plan and on the other builders' argvs.

    Args:
        case: The arguments.

    Returns:
        The kinds of the example, for the counts of :data:`PUBLISH_KINDS`.
    """
    plan = command.build_publish_plan(
        case.config,
        case.manifest,
        case.status,
        case.approval,
        pull_requests=case.pull_requests,
        handoff_dir=HANDOFF_DIR,
    )
    listed = set(case.approval.item_ids)
    records = case.status["items"]
    stepped = [step.item_id for step in plan.steps]
    assert len(stepped) == len(set(stepped)), f"an item has two steps: {stepped}"
    for step in plan.steps:
        assert step.item_id in listed, f"{step.item_id} is published without being listed in the approval"
        assert step.item_id in records, f"{step.item_id} is published without a status record"
        assert (
            records[step.item_id]["state"] == state.SUCCEEDED
        ), f"{step.item_id} is published in state {records[step.item_id]['state']}"
        branch = command.BRANCH_PREFIX + step.item_id
        push = step.push.argv
        assert posixpath.basename(push[0]) == "git" and "push" in push, push
        assert branch_names(push) == [branch], push
        pull_request = step.pull_request.argv
        assert pull_request[:3] == ("gh", "pr", "create"), pull_request
        assert branch_names(pull_request) == [branch], pull_request

    for item in case.manifest.items:
        for git in command.build_git_plan(case.config, item).commands(case.base_sha):
            assert git.argv[0] == "git" and not publish_words(git.argv), git.argv
        invocation = command.build_kiro_argv(
            case.config,
            item,
            PROMPT,
            home=HOME,
            selftest_result=GUARDS_ACTIVE,
            approved_agents=frozenset(handoff_strategies.AGENT_NAMES),
        )
        assert not publish_words(invocation.argv[:-1]), invocation.argv

    kinds = ["steps"] if plan.steps else []
    kinds += sorted({f"excluded:{exclusion.reason}" for exclusion in plan.excluded})
    unlisted = [x.item_id for x in plan.excluded if x.reason == "not_approved" and x.item_id in case.manifest.by_id]
    if unlisted:
        wider = dataclasses.replace(case.approval, item_ids=(*case.approval.item_ids, *unlisted))
        if _stepped(case, approval=wider) & set(unlisted):
            kinds.append("would_publish:if_listed")
    for item_id in [x.item_id for x in plan.excluded if x.reason == "not_succeeded"]:
        one_second = [timedelta(seconds=1)] * len(_TO_SUCCEEDED[records[item_id]["state"]])
        if item_id in _stepped(case, status=_moved_to_succeeded(case.status, item_id, one_second)):
            kinds.append("would_publish:if_succeeded")
            break
    return tuple(kinds)


def _stepped(
    case: PublishCase,
    *,
    approval: command.PublishApproval | None = None,
    status: state.StatusDoc | None = None,
) -> set[str]:
    """Build the plan of a case again with another approval or status, and return the items it publishes.

    Args:
        case: The arguments.
        approval: The approval to use instead of the case's.
        status: The status to use instead of the case's.

    Returns:
        The item IDs of the plan's steps.
    """
    plan = command.build_publish_plan(
        case.config,
        case.manifest,
        case.status if status is None else status,
        case.approval if approval is None else approval,
        pull_requests=case.pull_requests,
        handoff_dir=HANDOFF_DIR,
    )
    return {step.item_id for step in plan.steps}


# Feature: cyber-resilience-phase4-supply-chain, Property 24: kiro-cli の argv は許可一覧の上限を超えず、設定が欠ければ組み立てられない
def test_property_24_push_and_pull_request_only_in_the_publish_plan() -> None:
    """Push and pull-request argvs appear only in the publish plan, for listed items that succeeded.

    For any configuration, manifest, status, approval and pull-request specs of
    :func:`publish_cases`, every step of ``build_publish_plan`` is for an item that the approval
    lists and that is ``succeeded``, and names only that item's branch; no command of
    ``build_git_plan`` and no option of ``build_kiro_argv`` for the manifest's items is ``push``
    or ``gh``. The search must also draw items that the plan leaves out only for the listing or
    only for the state (:data:`PUBLISH_KINDS`).

    **Validates: Requirements 28.7, 28.14, 28.15, 28.17**
    """
    seen: Counter[str] = Counter()

    @settings(max_examples=100, deadline=None)
    @given(publish_cases())
    def check(case: PublishCase) -> None:
        seen.update(check_publish_case(case))

    check()
    require_kinds(seen, PUBLISH_KINDS)
