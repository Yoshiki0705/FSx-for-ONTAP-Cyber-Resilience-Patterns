"""Property 27: a drawn Handoff_Prompt has every required section and guesses no unconfirmed ref.

Task 1.17 of the phase 4 spec (design, Correctness Properties, Property 27). Each example draws a
manifest from ``manifests()`` (up to :data:`MAX_FILES` declared files per change item), template
variables from ``prompt_vars()`` for one of its items (Japanese words, symbols, full-width forms,
placeholders, tokens that would be headings or fences at a line start, and planted scan
material), a split of the refs into confirmed and unconfirmed from ``confirmed_refs()``, and an
uncommitted count per item. Every item is rendered with ``prompt.render`` and its body is read
back as Markdown: the level-1 and level-2 headings outside code fences, then each section's
lines.

``provided_refs`` of ``manifests()`` is drawn too. With ``False``, an item can hold an
unconfirmed ref of its own repository and no dependency in that repository. Section 5 cannot
name the Handoff that confirms such a ref (Requirement 23.5), so ``prompt.render`` must refuse
exactly those items, with one ``reference`` issue per such ref, and draw every other item.

The expected outline is written here from design section 17 (:data:`DESIGN_TITLES`) and the two
query sections of task 1.8 (:data:`QUERY_TITLES`), not taken from ``prompt``, so a section that
``prompt`` stops drawing, or drops from ``section_headings`` as well, fails the test. The other
oracles are the item itself (files, refs, dependencies, commands), ``executor.choose`` for
section 10, the template's slots read with ``string.Template`` for sections 2, 7 and 12, and the
fixed words of the requirements (:data:`PUBLIC_OUTPUT_TERMS`, :data:`FORBIDDEN_TERMS`) and of
the design (:data:`NONE_TEXT`, :data:`NOT_APPLICABLE_TEXT`, :data:`UNCONFIRMED_TEXT`,
:data:`ANSWER_INSTRUCTION`).

No input is filtered or assumed away. The test reports the shapes it met with
``hypothesis.event`` (see :func:`_shapes`; ``pytest --hypothesis-show-statistics`` prints how
many examples had each). Every value is synthetic; see the docstring of
``strategies/handoff.py``.
"""

from __future__ import annotations

import re
import shlex
import string
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

import pytest
from handoff import executor, manifest, prompt
from hypothesis import event, given, settings
from hypothesis import strategies as st
from strategies import handoff as handoff_strategies

#: The section titles of design section 17, in order. The comment names the requirement that
#: each section meets.
DESIGN_TITLES: Final[tuple[str, ...]] = (
    "対象リポジトリ",  # 23.2
    "変更の目的",  # 23.2
    "作成・変更するファイル",  # 23.2
    "参照する Renovate_Preset と Reusable_Workflow",  # 23.2, 23.5
    "先に完了している必要がある Handoff",  # 23.2, 23.5
    "着手前の確認",  # 23.6
    "完了条件",  # 23.2, 23.3
    "検証コマンド",  # 23.2, 23.3
    "公開物の注意",  # 23.7
    "実行者と理由",  # 28.3
    "行わない操作",  # 28.14
)

#: The sections that a query prompt has after section 11: the questions and how to answer them.
QUERY_TITLES: Final[tuple[str, ...]] = ("問いの一覧", "答え方")

#: The sections that do not apply to a query item (design section 17).
QUERY_NOT_APPLICABLE: Final[tuple[int, ...]] = (3, 4, 7, 8)

#: The body of section 5 when there is no dependency (Requirement 23.2), and of sections 4 and 8
#: when there is no ref or command.
NONE_TEXT: Final = "なし"

#: The body of a section that does not apply to a query item (design section 17).
NOT_APPLICABLE_TEXT: Final = "該当なし"

#: What an unconfirmed ref shows instead of a value (design section 17, Requirement 23.5).
UNCONFIRMED_TEXT: Final = "未確定。先に Hub の Handoff を完了すること"

#: The instruction that a query prompt gives for its answers (design section 17).
ANSWER_INSTRUCTION: Final = "答えに、読んだ既存の記録のパスを添える"

#: What section 9 keeps out of commits, PR text and files (Requirement 23.7).
PUBLIC_OUTPUT_TERMS: Final[tuple[str, ...]] = (
    "人名",
    "ペルソナ名",
    "AWS アカウント ID",
    "内部 IP アドレス",
    "サポートケース番号",
)

#: The operations that section 11 forbids (Requirement 28.14).
FORBIDDEN_TERMS: Final[tuple[str, ...]] = (
    "push",
    "PR の作成",
    "マージ",
    "ブランチの削除",
    "AWS の課金が発生する操作",
    "不可逆な操作",
)

#: Most declared files of a drawn change item, and the count from which an event reports it as
#: having many files.
MAX_FILES: Final = 64
MANY_FILES: Final = 10

_ATX_HEADING: Final = re.compile(r" {0,3}(#{1,6})(?:[ \t]|$)")
_SETEXT_UNDERLINE: Final = re.compile(r" {0,3}(?:=+|-+)[ \t]*$")
_FENCE: Final = re.compile(r" {0,3}(`{3,}|~{3,})(.*)$")
_CODE_SPAN: Final = re.compile(r"(`+)(.+?)(?<!`)\1(?!`)")
_REF_LINE: Final = re.compile(r"- 参照 (\d+)（([^）]*)）: (.*)")
_DEPENDENCY_REST: Final = re.compile(r"（([^）]*)）(.*)")
_ROW_LINE: Final = re.compile(r"- 行 (\d+): (.*)")
_HEX_RUN: Final = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40,}(?![0-9A-Fa-f])")
_SLOT_MARKER: Final = re.compile(r"<!-- slot: ([a-z][a-z0-9_]*) -->")
#: The characters that a tag name or a SHA may hold (``manifest.RequiredRef``). A ref name next
#: to one of them is part of a longer name, such as ``x-v1.2.3`` inside ``x-v1.2.34``.
_REF_NAME_CHARS: Final = "A-Za-z0-9._/-"


@dataclass(frozen=True)
class RenderInputs:
    """What one example renders: a manifest and the other arguments of ``prompt.render``.

    Attributes:
        case: The manifest and its configuration. One item has the variables of
            :attr:`prompt_vars` and a template that uses them; the others have no variables.
        prompt_vars: The variables and the deny terms.
        confirmed: The refs confirmed on their repository's default branch (IN-2).
        uncommitted: The uncommitted count of each item's target repository, by item ID.
    """

    case: handoff_strategies.ManifestCase
    prompt_vars: handoff_strategies.PromptVars
    confirmed: frozenset[manifest.RequiredRef]
    uncommitted: Mapping[str, int]

    @property
    def checked(self) -> manifest.Manifest:
        """The checked manifest."""
        checked = self.case.manifest
        if checked is None:
            raise AssertionError("manifests() without cyclic=True returns a checked manifest")
        return checked


@st.composite
def _render_inputs(draw: st.DrawFn) -> RenderInputs:
    """Draw the inputs of one example.

    ``provided_refs`` of ``manifests()`` is drawn: with ``False``, an item can have an
    unconfirmed ref of its own repository and no dependency in that repository.

    Args:
        draw: The hypothesis draw function.

    Returns:
        The inputs.
    """
    case = draw(handoff_strategies.manifests(max_files=MAX_FILES, provided_refs=draw(st.booleans())))
    planted = draw(st.sampled_from(case.ids))
    variables = draw(handoff_strategies.prompt_vars())
    case = case.with_prompt_vars(planted, variables)
    if case.manifest is None:
        raise AssertionError("manifests() without cyclic=True returns a checked manifest")
    confirmed = draw(handoff_strategies.confirmed_refs(case.manifest))
    uncommitted = {item_id: draw(st.integers(0, 5)) for item_id in case.ids}
    return RenderInputs(case, variables, confirmed, MappingProxyType(uncommitted))


def _render(inputs: RenderInputs, item_id: str) -> prompt.RenderedPrompt:
    """Render one item of an example as the harness would.

    Args:
        inputs: The example.
        item_id: The item.

    Returns:
        The rendered prompt.
    """
    case = inputs.case
    return prompt.render(
        inputs.checked,
        item_id,
        config=case.config,
        template_text=case.template_text(item_id),
        uncommitted_count=inputs.uncommitted[item_id],
        confirmed_refs=inputs.confirmed,
        home=case.config_case.home,
        deny_terms=inputs.prompt_vars.deny_terms,
    )


def _orphans(
    item: manifest.Item, by_id: Mapping[str, manifest.Item], confirmed: frozenset[manifest.RequiredRef]
) -> tuple[manifest.RequiredRef, ...]:
    """The unconfirmed refs of an item with no dependency in the ref's repository.

    Args:
        item: The item.
        by_id: The manifest's items by ID.
        confirmed: The confirmed refs.

    Returns:
        The refs, in the order of ``requires_refs``.
    """
    repos = {by_id[dependency].repo for dependency in item.depends_on}
    return tuple(ref for ref in item.requires_refs if ref not in confirmed and ref.repo not in repos)


def _shapes(inputs: RenderInputs) -> set[str]:
    """Name the shapes of an example that the test depends on, for ``hypothesis.event``.

    The shapes are each mode, items with and without dependencies, change items without refs,
    confirmed and unconfirmed refs (also both in one item, and unconfirmed refs of the item's
    own repository), unconfirmed refs that no dependency confirms (the items to refuse), items
    with :data:`MANY_FILES` or more files, row 3 of the executor table, and variables in a slot.

    Args:
        inputs: The example.

    Returns:
        The shapes that at least one item of the example has.
    """
    by_id = inputs.checked.by_id
    found: set[str] = set()
    for item in inputs.checked.items:
        confirmed = [ref for ref in item.requires_refs if ref in inputs.confirmed]
        unconfirmed = [ref for ref in item.requires_refs if ref not in inputs.confirmed]
        found.add(f"mode: {item.mode}")
        found.add("dependencies: some" if item.depends_on else "dependencies: none")
        if item.mode == "change" and not item.requires_refs:
            found.add("refs: none in a change item")
        if confirmed:
            found.add("refs: confirmed")
        if unconfirmed:
            found.add("refs: unconfirmed")
        if confirmed and unconfirmed:
            found.add("refs: confirmed and unconfirmed in one item")
        if any(ref.repo == item.repo for ref in unconfirmed):
            found.add("refs: unconfirmed, of the item's own repository")
        if _orphans(item, by_id, inputs.confirmed):
            found.add("refs: unconfirmed, with no confirming dependency")
        if len(item.declared_files) >= MANY_FILES:
            found.add(f"files: {MANY_FILES} or more")
        if inputs.uncommitted[item.id] > 0:
            found.add("executor: row 3 applies")
    if inputs.prompt_vars.vars:
        found.add("vars: a value in a slot")
    return found


def _design_headings(mode: str) -> list[str]:
    """The section headings of design section 17 for a mode, as ``## <n>. <title>``.

    Args:
        mode: ``query`` or ``change``.

    Returns:
        Sections 1 to 11, and 12 and 13 for ``query``.
    """
    titles = DESIGN_TITLES + (QUERY_TITLES if mode == "query" else ())
    return [f"## {number}. {title}" for number, title in enumerate(titles, 1)]


def _trimmed(lines: Sequence[str]) -> list[str]:
    """Drop the blank lines at the start and the end.

    Args:
        lines: Lines without line breaks.

    Returns:
        The lines that remain.
    """
    start, end = 0, len(lines)
    while start < end and not lines[start].strip():
        start += 1
    while end > start and not lines[end - 1].strip():
        end -= 1
    return list(lines[start:end])


def _outline(lines: Sequence[str]) -> list[tuple[int, str]]:
    """Find the lines that Markdown reads as level-1 or level-2 headings.

    A fence opens at a line of three or more backticks or tildes after up to three spaces (an
    info string after backticks holds no backtick) and closes at a line of the same character,
    at least as long, with nothing else. Outside fences, an ATX heading of level 1 or 2 counts,
    and so does a line of only ``=`` or only ``-`` right after a text line (a setext underline).

    Args:
        lines: The body's lines.

    Returns:
        ``(index, line)`` of each such line, in order.
    """
    found: list[tuple[int, str]] = []
    fence: tuple[str, int] | None = None
    after_text = False
    for index, line in enumerate(lines):
        marker = _FENCE.match(line)
        if fence is not None:
            if (
                marker is not None
                and marker.group(1)[0] == fence[0]
                and len(marker.group(1)) >= fence[1]
                and not marker.group(2).strip()
            ):
                fence = None
            after_text = False
            continue
        if marker is not None and not (marker.group(1)[0] == "`" and "`" in marker.group(2)):
            fence = (marker.group(1)[0], len(marker.group(1)))
            after_text = False
            continue
        heading = _ATX_HEADING.match(line)
        if heading is not None:
            if len(heading.group(1)) <= 2:
                found.append((index, line))
            after_text = False
        elif after_text and _SETEXT_UNDERLINE.match(line):
            found.append((index, line))
            after_text = False
        else:
            after_text = bool(line.strip())
    assert fence is None, "a code fence is left open at the end of the body"
    return found


def _sections(body: str, item: manifest.Item) -> dict[int, list[str]]:
    """Check the outline of a body and split it into its sections.

    Args:
        body: The rendered body.
        item: The item it was rendered for.

    Returns:
        The lines of each section after its heading, without the blank lines at either end, by
        section number.
    """
    lines = body.split("\n")
    headings = _outline(lines)
    expected = [f"# Handoff: {item.repo}", *_design_headings(item.mode)]
    assert [line for _, line in headings] == expected
    assert tuple(expected[1:]) == prompt.section_headings(item.mode)
    starts = [index for index, _ in headings]
    assert starts[0] == 0 and not _trimmed(lines[1 : starts[1]]), "the title is not alone at the top"
    sections: dict[int, list[str]] = {}
    for number, (start, end) in enumerate(zip(starts[1:], [*starts[2:], len(lines)], strict=True), 1):
        sections[number] = _trimmed(lines[start + 1 : end])
        assert sections[number], f"section {number} has no text"
    return sections


def _unspan(text: str) -> tuple[str, str]:
    """Split the Markdown code span at the start of a text from the rest.

    Args:
        text: Text that starts with a code span.

    Returns:
        The content of the span, as CommonMark reads it, and the text after the span.
    """
    match = _CODE_SPAN.match(text)
    assert match is not None, "a code span was expected"
    content = match.group(2)
    if content.startswith(" ") and content.endswith(" ") and content.strip():
        content = content[1:-1]
    return content, text[match.end() :]


def _slot_lines(template: str, name: str, values: Mapping[str, object]) -> list[str]:
    """Read one slot of a template and substitute the item's variables, as design section 17 says.

    Args:
        template: The template text.
        name: The slot name.
        values: The item's ``vars``.

    Returns:
        The slot's lines without blank lines at either end, after ``string.Template``
        substitution. Empty when the template has no such slot.
    """
    slots: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in template.splitlines():
        marker = _SLOT_MARKER.fullmatch(line.rstrip())
        if marker is not None:
            current = slots.setdefault(marker.group(1), [])
        elif current is not None:
            current.append(line)
    lines = _trimmed(slots.get(name, []))
    return string.Template("\n".join(lines)).substitute(values).split("\n") if lines else []


def _check_refs(lines: Sequence[str], item: manifest.Item, confirmed: frozenset[manifest.RequiredRef]) -> None:
    """Section 4 of a change item: one line per ref, a value only when the ref is confirmed.

    Args:
        lines: The lines of section 4.
        item: The item.
        confirmed: The confirmed refs.
    """
    if not item.requires_refs:
        assert list(lines) == [NONE_TEXT]
        return
    matches = [match for line in lines if (match := _REF_LINE.fullmatch(line)) is not None]
    assert [int(match.group(1)) for match in matches] == list(range(1, len(item.requires_refs) + 1))
    for match, ref in zip(matches, item.requires_refs, strict=True):
        assert match.group(2).startswith(ref.repo + " ")
        if ref in confirmed:
            assert _unspan(match.group(3)) == (ref.name, "")
        else:
            assert match.group(3) == UNCONFIRMED_TEXT
            assert ref.name not in match.group(0)
            assert _HEX_RUN.search(match.group(0)) is None


def _check_dependencies(
    lines: Sequence[str],
    item: manifest.Item,
    by_id: Mapping[str, manifest.Item],
    unconfirmed: Sequence[manifest.RequiredRef],
    providers: Sequence[str],
) -> None:
    """Section 5: every dependency with its repository, those that confirm a ref marked as such.

    Args:
        lines: The lines of section 5.
        item: The item.
        by_id: The manifest's items by ID.
        unconfirmed: The item's unconfirmed refs.
        providers: The dependencies in the repository of an unconfirmed ref, in order.
    """
    if not item.depends_on:
        assert list(lines) == [NONE_TEXT]
        return
    entries: list[tuple[str, str, str]] = []
    for line in lines:
        assert line.startswith("- ")
        dependency, rest = _unspan(line[2:])
        match = _DEPENDENCY_REST.fullmatch(rest)
        assert match is not None
        entries.append((dependency, match.group(1), match.group(2)))
    assert [dependency for dependency, _, _ in entries] == list(item.depends_on)
    assert all(repo == by_id[dependency].repo for dependency, repo, _ in entries)
    marked = [dependency for dependency, _, note in entries if note]
    assert marked == list(providers)
    assert all("未確定" in note for _, _, note in entries if note)
    assert all(any(by_id[dependency].repo == ref.repo for dependency in marked) for ref in unconfirmed)


def _check_executor(lines: Sequence[str], item: manifest.Item, count: int, rendered: prompt.RenderedPrompt) -> None:
    """Section 10: the executor, and every row of the executor table that applies, with its details.

    Args:
        lines: The lines of section 10.
        item: The item.
        count: The uncommitted count passed to ``prompt.render``.
        rendered: The rendered prompt.
    """
    choice = executor.choose(item.executor_attrs(uncommitted_count=count))
    assert rendered.executor_choice == choice
    assert lines[0].startswith(f"実行者: {choice.executor.label}")
    rows = [(index, match) for index, line in enumerate(lines) if (match := _ROW_LINE.fullmatch(line)) is not None]
    assert [int(match.group(1)) for _, match in rows] == list(choice.rows)
    ends = [index for index, _ in rows[1:]] + [len(lines)]
    for (index, match), end, reason in zip(rows, ends, choice.reasons, strict=True):
        assert reason.condition in match.group(2)
        details = lines[index + 1 : end]
        assert len(details) == len(reason.details)
        for line, entry in zip(details, reason.details, strict=True):
            assert line.startswith("  - ") and entry in line


def _check_no_guessed_ref(
    body: str, confirmed: Sequence[manifest.RequiredRef], unconfirmed: Sequence[manifest.RequiredRef]
) -> None:
    """No unconfirmed ref name and no 40-digit hexadecimal string other than a confirmed SHA.

    The drawn values never hold a tag of the ``-v<n>.<n>.<n>`` form or a run of 40 hexadecimal
    digits (``strategies/handoff.py``), so any such text in the body came from a ref. A name is
    looked for as a whole name, not next to a character of :data:`_REF_NAME_CHARS`. A name that
    an unconfirmed ref shares with a confirmed one is written for the confirmed one.

    Args:
        body: The rendered body.
        confirmed: The item's confirmed refs.
        unconfirmed: The item's unconfirmed refs.
    """
    confirmed_names = {ref.name for ref in confirmed}
    for ref in unconfirmed:
        if ref.name not in confirmed_names:
            name = re.compile(rf"(?<![{_REF_NAME_CHARS}]){re.escape(ref.name)}(?![{_REF_NAME_CHARS}])")
            assert name.search(body) is None
    assert set(_HEX_RUN.findall(body)) <= {ref.name for ref in confirmed if ref.kind == "sha"}


def _check_prompt(inputs: RenderInputs, item: manifest.Item, rendered: prompt.RenderedPrompt) -> None:
    """Check one rendered body against Property 27.

    Args:
        inputs: The example.
        item: The item rendered.
        rendered: What ``prompt.render`` returned for it.
    """
    by_id = inputs.checked.by_id
    confirmed = tuple(ref for ref in item.requires_refs if ref in inputs.confirmed)
    unconfirmed = tuple(ref for ref in item.requires_refs if ref not in inputs.confirmed)
    repos = {ref.repo for ref in unconfirmed}
    providers = tuple(dependency for dependency in item.depends_on if by_id[dependency].repo in repos)
    assert rendered.unconfirmed_refs == unconfirmed
    assert rendered.ref_providers == providers

    sections = _sections(rendered.body, item)
    text = {number: "\n".join(lines) for number, lines in sections.items()}
    template = inputs.case.template_text(item.id)
    branch = f"handoff/{item.id}"

    assert item.repo in text[1]
    assert sections[2] == _slot_lines(template, "purpose", item.vars)
    _check_dependencies(sections[5], item, by_id, unconfirmed, providers)
    assert "git branch --show-current" in text[6] and "git status --porcelain" in text[6]
    assert any("未コミットの変更" in line and "停止して保守者に報告" in line for line in sections[6])
    assert all(term in text[9] for term in PUBLIC_OUTPUT_TERMS)
    _check_executor(sections[10], item, inputs.uncommitted[item.id], rendered)
    assert all(term in text[11] for term in FORBIDDEN_TERMS)

    if item.mode == "query":
        for number in QUERY_NOT_APPLICABLE:
            assert sections[number] == [NOT_APPLICABLE_TEXT], number
        assert sections[12] == _slot_lines(template, "questions", item.vars)
        assert ANSWER_INSTRUCTION in text[13]
    else:
        assert branch in text[6] and branch in text[11]
        files = [_unspan(line[2:]) for line in sections[3] if line.startswith("- ")]
        assert files == [(path, "") for path in item.declared_files]
        _check_refs(sections[4], item, inputs.confirmed)
        assert branch in text[7] and "git status --porcelain" in text[7]
        assert not item.verify_commands or "終了コード 0" in text[7]
        completion = _slot_lines(template, "completion", item.vars)
        assert not completion or sections[7][-len(completion) :] == completion
        if item.verify_commands:
            commands = [_unspan(line[2:])[0] for line in sections[8] if line.startswith("- ")]
            assert commands == [shlex.join(command.cmd) for command in item.verify_commands]
        else:
            assert sections[8] == [NONE_TEXT]
    _check_no_guessed_ref(rendered.body, confirmed, unconfirmed)


# Feature: cyber-resilience-phase4-supply-chain, Property 27: 描いた本文は必須の節をすべて持ち、未確定の参照を推測で埋めない
@settings(max_examples=100, deadline=None)
@given(_render_inputs())
def test_rendered_prompts_have_every_section_and_guess_no_unconfirmed_ref(inputs: RenderInputs) -> None:
    """Every item renders to a body with every required section and no guessed ref, or is refused.

    An item is refused exactly when an unconfirmed ref has no dependency in the ref's repository:
    ``prompt.render`` raises ``PromptError`` with one ``reference`` issue per such ref, since
    section 5 could not name the Handoff that confirms it.

    **Validates: Requirements 23.2, 23.3, 23.5, 23.6, 23.7, 28.3, 28.14**
    """
    for shape in sorted(_shapes(inputs)):
        event(shape)
    by_id = inputs.checked.by_id
    for item in inputs.checked.items:
        orphans = _orphans(item, by_id, inputs.confirmed)
        if not orphans:
            _check_prompt(inputs, item, _render(inputs, item.id))
            continue
        with pytest.raises(prompt.PromptError) as caught:
            _render(inputs, item.id)
        assert [(issue.where, issue.kind) for issue in caught.value.issues] == [("item", "reference")] * len(orphans)


#: Wording of the query-only answer section (task 5.7): the paths are asked for, the ``base_sha`` is recorded by the
#: harness, and "該当なし" is no proof that nothing was missed.
QUERY_ONLY_PHRASES: Final[tuple[str, ...]] = (
    "`base_sha` はハーネスが記録",
    "取りこぼしがない根拠",
    "spoke_knowledge.py",
)
#: What a query prompt must not ask for: a commit SHA that a shell-less worker cannot get (design section 20).
SHA_REQUESTS: Final[tuple[str, ...]] = ("SHA を添える", "SHA を挙げ", "SHA を書")


# Feature: cyber-resilience-phase4-supply-chain, Property 27: 描いた本文は必須の節をすべて持ち、未確定の参照を推測で埋めない
@settings(max_examples=100, deadline=None)
@given(_render_inputs())
def test_a_query_prompt_asks_for_paths_not_shas_and_a_change_prompt_is_unchanged(inputs: RenderInputs) -> None:
    """Section 13 of a query item asks for paths, leaves ``base_sha`` to the harness and does not trust "該当なし".

    A change item's body has none of these sentences.

    **Validates: Requirements 28.1, 28.2**
    """
    checked = 0
    for item in inputs.checked.items:
        if _orphans(item, inputs.checked.by_id, inputs.confirmed):
            continue
        body = _render(inputs, item.id).body
        checked += 1
        event(item.mode)
        if item.mode == "query":
            assert ANSWER_INSTRUCTION in body
            assert all(phrase in body for phrase in QUERY_ONLY_PHRASES)
        else:
            assert not any(phrase in body for phrase in QUERY_ONLY_PHRASES)
        assert not any(request in body for request in SHA_REQUESTS)
    event(f"rendered={min(checked, 1)}")
