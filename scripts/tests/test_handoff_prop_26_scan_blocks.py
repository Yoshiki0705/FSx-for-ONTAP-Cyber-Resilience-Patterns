"""Property 26: a body in which the deny-term scan finds something is not passed on.

Task 1.16 of the phase 4 spec (design, Correctness Properties, Property 26), which validates
Requirements 28.23, 23.7 and 24.1. For any template variables, with deny terms, 12-digit
numbers, private and public IPv4 addresses, paths of the ``/Users/<name>`` form and case
numbers mixed in at any position:

1. When ``scan.check`` finds something in the drawn body, the item goes to ``needs-human`` and
   no argv is built for it.
2. The body of an item that moves from ``queued`` to ``running`` has no finding.
3. A body whose only such strings are the placeholders ``123456789012``, ``10.0.x.x`` and
   ``<management-ip>`` has no finding.

How the property is read. ``prompt.render`` scans the body it draws, and
``command.build_kiro_invocation``, the runner's builder of a ``kiro-cli`` run, takes the
``RenderedPrompt``: it refuses a held prompt with ``CommandError`` (code ``prompt_held``) and
otherwise returns what ``command.build_kiro_argv`` builds from the body. So:

- (1): the findings of ``render`` are ``scan.check`` of the whole body with the caller's deny
  terms. When there is one, the hold reasons hold ``prompt_scan_findings``, ``needs_human`` is
  true, ``build_kiro_invocation`` refuses, and ``state.transition`` takes the item from
  ``queued`` to ``needs-human`` with ``RenderedPrompt.history_reason``.
- (2): the prompt of every argv that ``build_kiro_invocation`` returns has no finding. Moving
  the item to ``running`` is the runner's step (task 2.3); the integration test of task 2.4
  ties that transition to the argv.
- (3): with nothing planted, the body has no finding and no hold reason, and the argv is
  built. Every change body lists the three placeholders in section 9, and the drawn values put
  them at any position of the slots.

Oracles. ``prompt_vars()`` plants kinds in the values of one item and says which; the body of
that item must have exactly those kinds, and the bodies of the other items, whose templates
use no variable, none. ``scan.check`` called here on the drawn body is the oracle for
``render``: a ``render`` that skipped the scan, scanned part of the body or dropped the deny
terms would differ from it. The hold reasons and the size limit are those of task 1.8.

Two functions check the property. The first draws its variables from ``prompt_vars()``: half
of the examples plant nothing and half plant a non-empty subset of the six kinds. The second
writes one two-word deny term, a Latin word and a katakana word, in one of the spellings that
the scan folds onto it (task 1.7: upper, lower and swapped case, full-width letters,
half-width katakana, NFD, other white space between the words) at any character position of
a value. ``prompt_vars()`` writes a deny term as written, in upper case, in full-width letters
or inside a word only, and only some of its examples plant one.

No input is filtered or assumed away. ``hypothesis.event`` reports the planted kinds, the
slots they went to, the examples with nothing planted, the spellings and positions of the
second function, and the held and launched bodies (``pytest --hypothesis-show-statistics``).
Every value is synthetic; see the docstring of ``strategies/handoff.py``.

The two tests after the property tests check the refusals of ``build_kiro_invocation`` that
the property does not reach: a prompt drawn for another item, and a body over the size limit
in which the scan finds nothing.
"""

from __future__ import annotations

import dataclasses
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

import pytest
from handoff import command, manifest, prompt, scan, state
from handoff.evaluate import GUARDS_ACTIVE
from hypothesis import event, given, settings
from hypothesis import strategies as st
from strategies import handoff as handoff_strategies

#: The placeholders of Requirement 24.1 that a body may hold without a finding.
PLACEHOLDERS: Final[tuple[str, ...]] = ("123456789012", "10.0.x.x", "<management-ip>")

#: The hold reasons of ``prompt.RenderedPrompt`` (task 1.8): the body is over the size limit, and
#: the scan found something. A held prompt lists them in this order.
TOO_LONG: Final = "prompt_too_long"
SCAN_FINDINGS: Final = "prompt_scan_findings"

#: Most UTF-8 bytes of a body that is passed on: the 100 KB of design section 20, counted as
#: 100 KiB in task 1.8.
MAX_BODY_BYTES: Final = 100 * 1024

#: When the transitions of the examples happen. The property does not depend on the clock.
AT: Final = "2026-11-11T00:00:00Z"

#: The slot that a variable goes to, by the item's mode and the variable's ``placement``.
SLOT_NAMES: Final[Mapping[tuple[str, int], str]] = MappingProxyType(
    {("change", 0): "purpose", ("change", 1): "completion", ("query", 0): "purpose", ("query", 1): "questions"}
)

#: The letters of the Latin word and the katakana of the katakana word of a two-word deny term.
#: The words start with ``Zq`` and ``ヅ``, as the deny terms of ``prompt_vars()`` do; no filler
#: text of ``strategies/handoff.py`` holds either start, so a term is found only where it is
#: written. These katakana cannot spell ``ケース``.
TERM_LETTERS: Final = "aeilnoruvwy"
TERM_KANA: Final = "ラミネオカベタイノ"

#: The half-width form of each katakana of a term. NFKC maps each back.
HALF_WIDTH_KANA: Final[Mapping[str, str]] = MappingProxyType(
    {"ヅ": "ﾂﾞ", "ラ": "ﾗ", "ミ": "ﾐ", "ネ": "ﾈ", "オ": "ｵ", "カ": "ｶ", "ベ": "ﾍﾞ", "タ": "ﾀ", "イ": "ｲ", "ノ": "ﾉ"}
)


def full_width(text: str) -> str:
    """Write the printable ASCII characters of a text in full-width form, and spaces as U+3000.

    Args:
        text: The text.

    Returns:
        The text in full-width form.
    """
    return "".join(
        chr(ord(char) + 0xFEE0) if "!" <= char <= "~" else "\u3000" if char == " " else char for char in text
    )


#: How the second property function writes a term, by name. The scan folds each onto the term
#: (task 1.7: case folding, NFKC, and each run of white space read as one space). Each run of
#: white space between the words is a spelling of its own, so that the draw of the spelling
#: also picks the run.
SPELLINGS: Final[Mapping[str, Callable[[str], str]]] = MappingProxyType(
    {
        "as written": lambda term: term,
        "upper case": str.upper,
        "lower case": str.lower,
        "swapped case": str.swapcase,
        "full-width letters": full_width,
        "full-width upper case": lambda term: full_width(term.upper()),
        "half-width katakana": lambda term: "".join(HALF_WIDTH_KANA.get(char, char) for char in term),
        "NFD": lambda term: unicodedata.normalize("NFD", term),
        "two spaces": lambda term: term.replace(" ", "  "),
        "a tab": lambda term: term.replace(" ", "\t"),
        "a full-width space": lambda term: term.replace(" ", "\u3000"),
        "spaces around a full-width space": lambda term: term.replace(" ", " \u3000 "),
        "a tab and a full-width space": lambda term: term.replace(" ", "\t\u3000"),
    }
)


@dataclass(frozen=True)
class Example:
    """What one example renders: a manifest and the other arguments of ``prompt.render``.

    Attributes:
        case: The manifest and its configuration. The item :attr:`target` has the variables of
            :attr:`prompt_vars` and a template that uses them; the others have no variables.
        target: The ID of the item with the variables.
        prompt_vars: The variables, the kinds planted in them, and the deny terms.
        confirmed: The refs confirmed on their repository's default branch (IN-2).
        uncommitted: The uncommitted count of each item's target repository, by item ID.
    """

    case: handoff_strategies.ManifestCase
    target: str
    prompt_vars: handoff_strategies.PromptVars
    confirmed: frozenset[manifest.RequiredRef]
    uncommitted: Mapping[str, int]

    @property
    def checked(self) -> manifest.Manifest:
        """The checked manifest."""
        return checked_manifest(self.case)


def checked_manifest(case: handoff_strategies.ManifestCase) -> manifest.Manifest:
    """Return the checked manifest of a case that ``manifests()`` drew without a cycle.

    Args:
        case: The case.

    Returns:
        The manifest that ``parse_manifest`` returned.
    """
    if case.manifest is None:
        raise AssertionError("manifests() without cyclic=True returns a checked manifest")
    return case.manifest


@st.composite
def examples(draw: st.DrawFn) -> Example:
    """Draw the inputs of one example.

    Half of the examples plant nothing, so that their bodies hold no string of the property
    other than the placeholders; the others plant one to six of the kinds.

    Args:
        draw: The hypothesis draw function.

    Returns:
        The inputs.
    """
    case = draw(handoff_strategies.manifests())
    target = draw(st.sampled_from(case.ids))
    kinds = st.frozensets(st.sampled_from(handoff_strategies.PLANTABLE_KINDS), min_size=1)
    planted = draw(kinds) if draw(st.booleans()) else frozenset()
    variables = draw(handoff_strategies.prompt_vars(planted=planted))
    case = case.with_prompt_vars(target, variables)
    confirmed = draw(handoff_strategies.confirmed_refs(checked_manifest(case)))
    uncommitted = {item_id: draw(st.integers(0, 3)) for item_id in case.ids}
    return Example(case, target, variables, confirmed, MappingProxyType(uncommitted))


@dataclass(frozen=True)
class SpelledExample:
    """An example of the second property function, and how its deny term was written.

    Attributes:
        example: The example. Its ``prompt_vars`` plant ``deny_term`` only: the term, last in
            ``deny_terms``, written in one value of variables in which nothing else is planted.
        spelling: The name of the spelling, a key of :data:`SPELLINGS`.
        position: Where the written term went in the value: its start, its end, inside a token
            (no white space on either side), or next to white space.
        slot: The slot of the value.
        next_to_placeholder: Whether a placeholder ends right before the term or starts right
            after it.
    """

    example: Example
    spelling: str
    position: str
    slot: str
    next_to_placeholder: bool


@st.composite
def two_word_terms(draw: st.DrawFn) -> str:
    """Draw a deny term of a Latin word and a katakana word, in either order, joined by a space.

    Args:
        draw: The hypothesis draw function.

    Returns:
        The term.
    """
    latin = "Zq" + draw(st.text(TERM_LETTERS, min_size=3, max_size=7))
    kana = "ヅ" + draw(st.text(TERM_KANA, min_size=2, max_size=4))
    return f"{latin} {kana}" if draw(st.booleans()) else f"{kana} {latin}"


@st.composite
def spelled_examples(draw: st.DrawFn) -> SpelledExample:
    """Draw an example whose variables hold one deny term, in a drawn spelling, at any position.

    The variables come from ``prompt_vars()`` with nothing planted (placeholders included), and
    the written term is inserted at a drawn character position of one drawn value.

    Args:
        draw: The hypothesis draw function.

    Returns:
        The example and how its term was written.
    """
    case = draw(handoff_strategies.manifests(max_items=3))
    target = draw(st.sampled_from(case.ids))
    clean = draw(handoff_strategies.prompt_vars(planted=frozenset(), min_vars=1))
    term = draw(two_word_terms())
    spelling = draw(st.sampled_from(tuple(SPELLINGS)))
    written = SPELLINGS[spelling](term)
    index = draw(st.integers(0, len(clean.vars) - 1))
    key = tuple(clean.vars)[index]
    value = clean.vars[key]
    at = draw(st.integers(0, len(value)))
    variables = handoff_strategies.PromptVars(
        vars={**clean.vars, key: value[:at] + written + value[at:]},
        deny_terms=(*clean.deny_terms, term),
        planted=frozenset({"deny_term"}),
        placement=clean.placement,
    )
    case = case.with_prompt_vars(target, variables)
    checked = checked_manifest(case)
    confirmed = draw(handoff_strategies.confirmed_refs(checked))
    uncommitted = {item_id: draw(st.integers(0, 3)) for item_id in case.ids}
    before, after = value[:at], value[at:]
    if not before:
        position = "start of the value"
    elif not after:
        position = "end of the value"
    elif before[-1].isspace() or after[0].isspace():
        position = "next to white space"
    else:
        position = "inside a token"
    return SpelledExample(
        example=Example(case, target, variables, confirmed, MappingProxyType(uncommitted)),
        spelling=spelling,
        position=position,
        slot=SLOT_NAMES[checked.by_id[target].mode, clean.placement[index]],
        next_to_placeholder=any(before.endswith(p) or after.startswith(p) for p in PLACEHOLDERS),
    )


def draw_prompt(
    case: handoff_strategies.ManifestCase,
    item_id: str,
    *,
    uncommitted: int,
    confirmed: frozenset[manifest.RequiredRef],
    deny_terms: tuple[str, ...],
) -> prompt.RenderedPrompt:
    """Render one item as the runner would.

    Args:
        case: The manifest and its configuration.
        item_id: The item.
        uncommitted: The uncommitted count of the item's target repository.
        confirmed: The confirmed refs.
        deny_terms: The deny terms for the scan.

    Returns:
        The rendered prompt.
    """
    return prompt.render(
        checked_manifest(case),
        item_id,
        config=case.config,
        template_text=case.template_text(item_id),
        uncommitted_count=uncommitted,
        confirmed_refs=confirmed,
        home=case.config_case.home,
        deny_terms=deny_terms,
    )


def launch(
    case: handoff_strategies.ManifestCase, item: manifest.Item, rendered: prompt.RenderedPrompt
) -> command.KiroInvocation:
    """Build the ``kiro-cli`` run of an item as the runner would: selftest passed, no agent approved.

    Args:
        case: The manifest and its configuration.
        item: The item.
        rendered: Its rendered prompt.

    Returns:
        The invocation of ``build_kiro_invocation``.
    """
    return command.build_kiro_invocation(
        case.config,
        item,
        rendered,
        home=case.config_case.home,
        selftest_result=GUARDS_ACTIVE,
        approved_agents=frozenset(),
    )


def shapes(example: Example) -> set[str]:
    """Name the shapes of an example that the property depends on, for ``hypothesis.event``.

    The shapes are the target's mode, each planted kind, two or more kinds in one body, the
    slot of each value that holds a planted piece, a planted piece and a placeholder in one
    value, and, for the examples with nothing planted, how many of the three placeholders the
    values hold and whether section 9 lists them (a change item).

    Args:
        example: The example.

    Returns:
        The shapes of the example.
    """
    variables = example.prompt_vars
    mode = example.checked.by_id[example.target].mode
    found = {f"target: {mode}"}
    if variables.planted:
        found.update(f"planted: {kind}" for kind in variables.planted)
        if len(variables.planted) >= 2:
            found.add("planted: two or more kinds")
    else:
        present = [p for p in PLACEHOLDERS if any(p in value for value in variables.vars.values())]
        found.add(f"planted: nothing, placeholders in the values: {len(present)} of {len(PLACEHOLDERS)}")
        if mode == "change":
            found.add("planted: nothing, section 9 lists the placeholders")
    for value, slot in zip(variables.vars.values(), variables.placement, strict=True):
        if scan.check(value, variables.deny_terms):
            found.add(f"planted piece in slot: {SLOT_NAMES[mode, slot]}")
            if any(p in value for p in PLACEHOLDERS):
                found.add("planted piece and a placeholder in one value")
    return found


def check_item(example: Example, item: manifest.Item) -> str:
    """Check Property 26 on one item of an example.

    Args:
        example: The example.
        item: One of its items.

    Returns:
        ``held`` or ``launched``.
    """
    case = example.case
    terms = example.prompt_vars.deny_terms
    rendered = draw_prompt(
        case, item.id, uncommitted=example.uncommitted[item.id], confirmed=example.confirmed, deny_terms=terms
    )
    body = rendered.body
    findings = scan.check(body, terms)
    assert list(rendered.findings) == findings, "the findings of render are not scan.check of the body with the terms"
    planted = example.prompt_vars.planted if item.id == example.target else frozenset()
    found = {finding.kind for finding in findings}
    assert found == planted, f"planted {sorted(planted)}, found {sorted(found)}"
    holds = ((TOO_LONG,) if len(body.encode("utf-8")) > MAX_BODY_BYTES else ()) + ((SCAN_FINDINGS,) if findings else ())
    assert rendered.hold_reasons == holds
    assert rendered.needs_human is bool(holds)

    if holds:
        with pytest.raises(command.CommandError) as caught:
            launch(case, item, rendered)
        assert [issue.code for issue in caught.value.issues] == ["prompt_held"]
        reason = rendered.history_reason
        assert reason is not None and reason.split(", ") == list(holds)
        queued = state.add_item(state.empty_status(), item.id)
        record = state.transition(queued, item.id, state.NEEDS_HUMAN, at=AT, reason=reason)["items"][item.id]
        assert record["state"] == state.NEEDS_HUMAN
        assert record["history"] == [{"from": state.QUEUED, "to": state.NEEDS_HUMAN, "at": AT, "reason": reason}]
        return "held"

    invocation = launch(case, item, rendered)
    assert invocation == command.build_kiro_argv(
        case.config,
        item,
        body,
        home=case.config_case.home,
        selftest_result=GUARDS_ACTIVE,
        approved_agents=frozenset(),
    )
    assert invocation.argv[-1] == body
    assert scan.check(invocation.argv[-1], terms) == []
    return "launched"


# Feature: cyber-resilience-phase4-supply-chain, Property 26: 拒否語を含む本文は渡されない
@settings(max_examples=100, deadline=None)
@given(examples())
def test_property_26_a_body_with_a_scan_finding_gets_no_argv(example: Example) -> None:
    """A body with a scan finding is held and gets no argv; a body with placeholders only is passed on.

    For every item of the example: the findings of ``render`` are ``scan.check`` of the body
    with the deny terms, and their kinds are exactly the planted ones (none for the items
    without variables). The hold reasons follow the findings and the size limit. A held prompt
    makes ``build_kiro_invocation`` refuse with ``prompt_held`` alone, and ``state.transition``
    takes it from ``queued`` to ``needs-human`` with its ``history_reason``. A prompt that is
    not held gets the run of ``build_kiro_argv``, whose last argv element is the body, with no
    finding.

    **Validates: Requirements 28.23, 23.7, 24.1**
    """
    for name in sorted(shapes(example)):
        event(name)
    for item in example.checked.items:
        outcome = check_item(example, item)
        event(f"{'target' if item.id == example.target else 'other item'}: {outcome}")


# Feature: cyber-resilience-phase4-supply-chain, Property 26: 拒否語を含む本文は渡されない
@settings(max_examples=100, deadline=None)
@given(spelled_examples())
def test_property_26_a_deny_term_in_any_spelling_and_position_gets_no_argv(spelled: SpelledExample) -> None:
    """A deny term written in any spelling that the scan folds, at any position, holds the body.

    The same checks as the first function, for variables that hold one two-word deny term in a
    drawn spelling at a drawn character position, and nothing else: the target's body is held
    with ``deny_term`` as its only kind and gets no argv, and the other items' bodies are passed
    on.

    **Validates: Requirements 28.23, 23.7, 24.1**
    """
    example = spelled.example
    event(f"spelling: {spelled.spelling}")
    event(f"position: {spelled.position}")
    event(f"slot: {spelled.slot}")
    if spelled.next_to_placeholder:
        event("position: next to a placeholder")
    for item in example.checked.items:
        outcome = check_item(example, item)
        event(f"{'target' if item.id == example.target else 'other item'}: {outcome}")


@pytest.mark.parametrize("field", ["item_id", "repo", "mode"])
@settings(max_examples=10, deadline=None)
@given(data=st.data())
def test_build_kiro_invocation_refuses_a_prompt_drawn_for_another_item(field: str, data: st.DataObject) -> None:
    """A prompt whose item ID, repository or mode is not the item's gets no argv.

    The same prompt, unchanged, is passed on, so the refusal comes from the changed field.

    Args:
        field: The field of the rendered prompt to change.
        data: The hypothesis data object.
    """
    case = data.draw(handoff_strategies.manifests(max_items=2))
    item = data.draw(st.sampled_from(checked_manifest(case).items))
    rendered = draw_prompt(case, item.id, uncommitted=0, confirmed=frozenset(), deny_terms=())
    assert launch(case, item, rendered).argv[-1] == rendered.body
    changed = {
        "item_id": dataclasses.replace(rendered, item_id=item.id + "-x"),
        "repo": dataclasses.replace(rendered, repo=item.repo + "-x"),
        "mode": dataclasses.replace(rendered, mode="query" if item.mode == "change" else "change"),
    }[field]
    with pytest.raises(command.CommandError) as caught:
        launch(case, item, changed)
    assert [issue.code for issue in caught.value.issues] == ["prompt"]


@settings(max_examples=5, deadline=None)
@given(handoff_strategies.manifests(max_items=1))
def test_build_kiro_invocation_holds_a_body_over_the_size_limit(case: handoff_strategies.ManifestCase) -> None:
    """A body over 100 KiB in which the scan finds nothing is held as well, and gets no argv.

    ``build_kiro_argv`` checks the form of a prompt string, not its size, and builds an argv from
    the same body; the hold reason of ``render`` keeps it back.

    Args:
        case: A manifest with one item.
    """
    (item,) = checked_manifest(case).items
    long_value = "長" * (MAX_BODY_BYTES // len("長".encode()) + 1)
    variables = handoff_strategies.PromptVars(
        vars={"long": long_value}, deny_terms=(), planted=frozenset(), placement=(0,)
    )
    case = case.with_prompt_vars(item.id, variables)
    item = checked_manifest(case).by_id[item.id]
    rendered = draw_prompt(case, item.id, uncommitted=0, confirmed=frozenset(), deny_terms=())
    assert rendered.findings == ()
    assert len(rendered.body.encode("utf-8")) > MAX_BODY_BYTES
    assert rendered.hold_reasons == (TOO_LONG,)
    alone = command.build_kiro_argv(
        case.config,
        item,
        rendered.body,
        home=case.config_case.home,
        selftest_result=GUARDS_ACTIVE,
        approved_agents=frozenset(),
    )
    assert alone.argv[-1] == rendered.body
    with pytest.raises(command.CommandError) as caught:
        launch(case, item, rendered)
    assert [issue.code for issue in caught.value.issues] == ["prompt_held"]
