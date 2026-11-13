"""Property 19 of the phase 4 spec: the classification of reference forms.

Task 11.7 (Requirements 13.2, 13.7, 15.2, 15.5, 16.2 and 16.6). Property 19 reads: for any
``uses:`` reference and any preset reference, the classifier calls a third-party Action and a
Reusable_Workflow pinned only when the ref is a 40-digit hexadecimal SHA, and a preset pinned
only when the ref is a tag or a 40-digit SHA. A branch name, a short SHA and a missing ref are
unpinned. A local reference (``./``) and an Action of the caller's own owner are out of scope.

The expected answer of every case is fixed by how the case is built (the ref category that
the generator draws), never by calling the classifier.

Entry points under test (both are module-private, because the public ``check`` reads a whole
repository tree and a property over 100 refs should not write 100 trees):

* ``pinning._workflow`` for the ``uses:`` lines of a workflow file;
* ``renovate._check_repo_config`` for ``extends`` entries that name the Hub preset.

The test functions:

- :func:`test_property_19_uses_classification` checks the Actions and Reusable_Workflow part.
- :func:`test_property_19_preset_classification` checks the preset part.
- :func:`test_property_19_inputs_reach_every_shape` runs both checks on drawn inputs with a
  fixed seed (``derandomize=True``) and fails when a shape stops appearing, so the property
  tests cannot pass vacuously.

Reading of the property that the code does not follow word for word: while
``HUB_SHA_REQUIRED`` is ``False`` (the Q-16 interim rule), a Reusable_Workflow ref is pinned
when it is a SHA or any ref that is not empty and not a branch name, so a short SHA passes.
The strict reading (SHA only) is checked with ``hub_sha=True``; the interim rule is checked on
the refs both readings agree on (a SHA, a branch name, no ref).
"""

from __future__ import annotations

import json
from collections import Counter
from types import SimpleNamespace

from hypothesis import event, given, settings
from hypothesis import strategies as st
from supply_chain_checks import pinning, renovate

# Feature: cyber-resilience-phase4-supply-chain, Property 19: 参照の形の分類

HEX = "0123456789abcdef"
LOWER_ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"
#: Owners of the caller's repositories (case-insensitive) in the drawn workflows.
OWNERS = frozenset({"yoshiki0705", "example-org"})
HUB_REPO = "yoshiki0705/fsx-for-ontap-adoption-playbook"
BRANCH_NAMES = ("main", "master", "head", "develop", "trunk")
OTHER_UNPINNED = ("feature/x", "release-1", "v1", "v1.2.3", "latest", "stable")

# --- ref generators; each returns (category, text) ------------------------------------------


@st.composite
def _version(draw: st.DrawFn, *, strict: bool = True) -> tuple[str, str]:
    """Draw a ``uses:`` version; the category says whether it is a 40-digit SHA.

    With ``strict=False`` only the forms on which the Q-16 interim Hub rule and the strict
    reading agree are drawn.
    """
    kinds = ["sha40", "sha40-upper", "branch", "omitted", "empty-at"]
    if strict:
        kinds += ["short-sha", "long-sha", "non-hex-40", "other"]
    kind = draw(st.sampled_from(kinds))
    if kind == "sha40":
        return kind, draw(st.text(HEX, min_size=40, max_size=40))
    if kind == "sha40-upper":
        return kind, draw(st.text(HEX, min_size=40, max_size=40)).upper()
    if kind == "short-sha":
        return kind, draw(st.text(HEX, min_size=1, max_size=39))
    if kind == "long-sha":
        return kind, draw(st.text(HEX, min_size=41, max_size=64))
    if kind == "non-hex-40":
        body = draw(st.text(HEX, min_size=39, max_size=39))
        cut = draw(st.integers(min_value=0, max_value=39))
        return kind, body[:cut] + draw(st.sampled_from("gxz-")) + body[cut:]
    if kind == "branch":
        name = draw(st.sampled_from(BRANCH_NAMES))
        return kind, draw(st.sampled_from([name, name.upper(), name.capitalize()]))
    if kind == "other":
        return kind, draw(st.sampled_from(OTHER_UNPINNED))
    return kind, ""


def _is_sha(category: str) -> bool:
    return category in ("sha40", "sha40-upper")


@st.composite
def _uses_case(draw: st.DrawFn) -> tuple[str, str, str, bool]:
    """Draw ``(shape, workflow line, expected, hub_sha)``; expected is pinned/unpinned/exempt."""
    shape = draw(st.sampled_from(["local", "own-owner", "third-party", "hub"]))
    hub_sha = draw(st.booleans())
    subpath = draw(st.sampled_from(["", "", "/sub/dir", "/.github/workflows/x.yml"]))
    if shape == "local":
        tail = draw(st.text(LOWER_ALNUM + "-_./", min_size=0, max_size=20))
        return shape, f"./{tail}", "exempt", hub_sha
    category, version = draw(_version(strict=hub_sha or shape != "hub"))
    at = "" if category == "omitted" else f"@{version}"
    if shape == "own-owner":
        owner = draw(st.sampled_from(sorted(OWNERS)))
        owner = draw(st.sampled_from([owner, owner.upper(), owner.capitalize()]))
        repo = draw(st.text(LOWER_ALNUM, min_size=1, max_size=12))
        return shape, f"{owner}/{repo}{subpath}{at}", "exempt", hub_sha
    if shape == "third-party":
        owner = "ext" + draw(st.text(LOWER_ALNUM + "-", min_size=1, max_size=12))
        repo = draw(st.text(LOWER_ALNUM, min_size=1, max_size=12))
        expected = "pinned" if _is_sha(category) else "unpinned"
        return shape, f"{owner}/{repo}{subpath}{at}", expected, hub_sha
    hub = draw(st.sampled_from([HUB_REPO, "Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook"]))
    ref = f"{hub}/.github/workflows/reusable.yml{at}"
    return shape, ref, "pinned" if _is_sha(category) else "unpinned", hub_sha


@st.composite
def _workflow_line(draw: st.DrawFn, ref: str) -> str:
    """Wrap a ref in a workflow step line (dash, quotes and a trailing comment vary)."""
    key = draw(st.sampled_from(["      - uses: ", "        uses: "]))
    quote = draw(st.sampled_from(["", "'", '"']))
    comment = draw(st.sampled_from(["", "  # v1.2.3", " # pinned"]))
    return f"{key}{quote}{ref}{quote}{comment}"


def _check_uses(shape: str, ref: str, expected: str, hub_sha: bool, line: str) -> None:
    found = pinning._workflow(".github/workflows/ci.yml", line + "\n", OWNERS, hub_sha)
    if expected in ("pinned", "exempt"):
        assert found == [], f"{shape} {ref!r} must not be reported: {found}"
        return
    kind = "unpinned-reusable" if shape == "hub" else "unpinned-action"
    assert [(v.kind, v.line, v.path) for v in found] == [
        (kind, 1, ".github/workflows/ci.yml")
    ], f"{shape} {ref!r} must be reported once as {kind}: {found}"
    assert ref.split("@")[0] in found[0].detail


@settings(max_examples=200, deadline=None)
@given(data=st.data())
def test_property_19_uses_classification(data: st.DataObject) -> None:
    """A third-party Action and a Reusable_Workflow are pinned only by a 40-digit SHA.

    **Validates: Requirements 13.2, 13.7, 15.2, 16.2**
    """
    shape, ref, expected, hub_sha = data.draw(_uses_case())
    line = data.draw(_workflow_line(ref))
    event(f"uses {shape} {expected}")
    _check_uses(shape, ref, expected, hub_sha, line)


# --- preset references ------------------------------------------------------------------


@st.composite
def _preset_case(draw: st.DrawFn) -> tuple[str, str, str]:
    """Draw ``(category, extends entry, expected)`` for a Hub preset reference."""
    name = draw(st.sampled_from(["supply-chain", "supply-chain"]))
    base = f"github>example-org/example-hub//renovate/{name}"
    kind = draw(
        st.sampled_from(
            ["tag", "tag-suffix", "sha40", "none", "empty-hash", "branch", "short-sha", "long-sha", "non-hex-40"]
        )
    )
    if kind == "tag":
        major, minor, patch = (draw(st.integers(min_value=0, max_value=99)) for _ in range(3))
        return kind, f"{base}#v{major}.{minor}.{patch}", "pinned"
    if kind == "tag-suffix":
        major, minor, patch = (draw(st.integers(min_value=0, max_value=99)) for _ in range(3))
        suffix = draw(st.sampled_from(["-rc.1", "-beta", ".post1"]))
        return kind, f"{base}#{major}.{minor}.{patch}{suffix}", "pinned"
    if kind == "sha40":
        return kind, f"{base}#{draw(st.text(HEX, min_size=40, max_size=40))}", "pinned"
    if kind == "none":
        return kind, base, "unpinned"
    if kind == "empty-hash":
        return kind, f"{base}#", "unpinned"
    if kind == "branch":
        return kind, f"{base}#{draw(st.sampled_from(BRANCH_NAMES))}", "unpinned"
    if kind == "short-sha":
        return kind, f"{base}#{draw(st.text(HEX, min_size=1, max_size=39))}", "unpinned"
    if kind == "long-sha":
        return kind, f"{base}#{draw(st.text(HEX, min_size=41, max_size=64))}", "unpinned"
    body = draw(st.text(HEX, min_size=39, max_size=39))
    cut = draw(st.integers(min_value=0, max_value=39))
    return kind, f"{base}#{body[:cut]}{draw(st.sampled_from('gxz'))}{body[cut:]}", "unpinned"


def _check_preset(kind: str, entry: str, expected: str) -> None:
    config = {"extends": ["config:recommended", entry]}
    text = json.dumps(config, indent=2)
    policy = SimpleNamespace(automerge_enabled_repositories=())
    found: list = []
    renovate._check_repo_config(found, ".github/renovate.json", text, config, policy)
    if expected == "pinned":
        assert found == [], f"{kind} {entry!r} must not be reported: {found}"
        return
    assert [v.kind for v in found] == ["reference"], f"{kind} {entry!r} must be reported once: {found}"
    assert found[0].path == ".github/renovate.json"
    assert found[0].line == 4  # the line of the entry in the indented JSON above


@settings(max_examples=200, deadline=None)
@given(case=_preset_case())
def test_property_19_preset_classification(case: tuple[str, str, str]) -> None:
    """A preset reference is pinned only by a tag or a 40-digit SHA.

    **Validates: Requirements 15.2, 15.5, 16.6**
    """
    kind, entry, expected = case
    event(f"preset {kind} {expected}")
    _check_preset(kind, entry, expected)


# --- the generators reach every shape ---------------------------------------------------

USES_SHAPES = {
    (shape, expected)
    for shape, expected in (
        ("local", "exempt"),
        ("own-owner", "exempt"),
        ("third-party", "pinned"),
        ("third-party", "unpinned"),
        ("hub", "pinned"),
        ("hub", "unpinned"),
    )
}
PRESET_KINDS = {
    "tag",
    "tag-suffix",
    "sha40",
    "none",
    "empty-hash",
    "branch",
    "short-sha",
    "long-sha",
    "non-hex-40",
}


def test_property_19_inputs_reach_every_shape() -> None:
    """Run both checks on 300 drawn inputs with a fixed seed and count the shapes.

    Fails when a shape of the property stops appearing, so a generator that went narrow
    cannot leave the property tests passing without testing anything.
    """
    uses: Counter[tuple[str, str]] = Counter()
    categories: Counter[str] = Counter()
    presets: Counter[str] = Counter()

    @settings(max_examples=300, deadline=None, derandomize=True)
    @given(data=st.data())
    def run(data: st.DataObject) -> None:
        shape, ref, expected, hub_sha = data.draw(_uses_case())
        line = data.draw(_workflow_line(ref))
        _check_uses(shape, ref, expected, hub_sha, line)
        uses[(shape, expected)] += 1
        if shape in ("third-party", "hub"):
            categories["with-ref" if "@" in ref else "no-ref"] += 1
            categories["hub-strict" if hub_sha else "hub-interim"] += shape == "hub"
        kind, entry, expectation = data.draw(_preset_case())
        _check_preset(kind, entry, expectation)
        presets[kind] += 1

    run()
    assert set(uses) == USES_SHAPES, uses
    assert all(count >= 10 for count in uses.values()), uses
    assert set(presets) == PRESET_KINDS, presets
    assert all(count >= 10 for count in presets.values()), presets
    assert categories["no-ref"] >= 10 and categories["with-ref"] >= 10, categories
    assert categories["hub-strict"] >= 10 and categories["hub-interim"] >= 10, categories
