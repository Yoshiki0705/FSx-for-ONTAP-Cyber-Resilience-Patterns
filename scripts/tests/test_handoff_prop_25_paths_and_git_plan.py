"""Property 25: the cwd and the harness's files stay in their own places, and the git plan overwrites no tree.

Task 1.15 of the phase 4 spec. The property (design, Correctness Properties) validates
Requirements 23.4, 28.5, 28.6 and 28.22, in three parts:

1. For a configuration that ``config.parse_config`` accepts, the cwd of an item, which is the
   worktree of ``command.build_git_plan`` and the working directory of
   ``command.build_kiro_argv``, is strictly below ``worktrees_root`` and does not overlap a
   protected path: a main working tree of ``repos``, a main working tree that the caller adds
   (this repository's own), or the IDE session worktree directory.
2. The git plan holds exactly ``fetch --no-tags origin main``, ``ls-remote origin
   refs/heads/main``, ``rev-parse refs/remotes/origin/main`` and ``worktree add``, with
   ``-b handoff/<id>`` for a change item and ``--detach`` for a query item, and the SHA it is
   given; each one is ``git -C <main> ...`` run in the item's main working tree, and no element
   is ``checkout``, ``restore``, ``stash``, ``reset``, ``clean`` or ``switch`` or starts with
   ``--force``. ``worktree add`` refuses a value that is not 40 lowercase hexadecimal digits,
   so the SHA in the command is always an explicit one.
3. ``command.handoff_files`` puts the Handoff_Prompt, the Handoff_Report and the status file
   strictly below the ``.private/handoff`` directory it is given, and gives no path for any
   other directory.

How the property is read:

- "Normalized" follows the rule written in ``handoff.config``: ``~`` expanded,
  ``posixpath.normpath``, and names compared without letter case and Unicode normalization
  (NFD, case fold, NFD), as a case-insensitive APFS volume compares them. The test applies the
  rule with its own code (:func:`lexical`, :func:`components`) instead of ``config.is_within``,
  so that a fault in the comparison of ``config`` cannot hide itself. Symbolic links are out of
  scope: following them is the runner's task (record of task 1.2).
- The property names a cwd that equals a protected path or lies inside one. The test also
  fails a cwd that contains one, as ``GitPlan.worktree`` promises and the record of task 1.9
  reasons: no path strictly below a ``worktrees_root`` that overlaps no protected path can
  overlap one.
- "For any item ID" is read over every item of a drawn manifest, and a protected path is now
  and then planted at the cwd of one of the items (:func:`dangers`): a ``worktrees_root`` that
  contains such a path must be refused, since that item would land in it.
- ``build_git_plan`` and ``build_kiro_argv`` must not refuse an item that passed
  ``parse_manifest`` under a configuration that passed ``parse_config``.
- The layout ``<worktrees_root>/<repo>/<id>`` is not checked: the property says only where the
  cwd lies.
- In part 3, a directory is "this repository's ``.private/handoff/``" when the last two
  components of its ``normpath`` are exactly ``.private`` and ``handoff``; which repository it
  belongs to is the runner's to decide. Paths are compared after ``normpath`` and without
  folding, since ``handoff_files`` joins strings and folds nothing. A refusal must come from an
  odd argument: ``CommandError`` from the repository, the ID or the Sync_Point, ``ValueError``
  or ``TypeError`` from ``handoff_dir``.

Inputs. An example of the first test draws a valid configuration from ``configs()`` (the base)
and a manifest for it, then a family of related paths (``related_paths()``), one of which
becomes ``worktrees_root``, now and then with an accented name added. Each protected path comes
from the members of the family that do not meet the root, from a path near the root that does
not nest with it (:func:`near_misses`) or from the base; in about three examples of ten, one of
them is a planted overlap with the root instead (:func:`dangers`), mostly in another letter case
or Unicode normalization. Near and planted paths are written again in up to two spellings
(:func:`respellings`); the family holds other spellings already. The configuration with these
paths goes to ``parse_config``; the test checks the items under it when it is accepted, and
always under the base configuration. An example of the second test draws a directory, a
repository name, an item ID and a Sync_Point, each either of its valid form or an odd value, and
in about one example of three exactly one of the last three climbs (:func:`file_cases`).

Counts. Neither test uses ``filter`` or ``assume``. Each names the shapes of its example with
``hypothesis.event`` (shown by ``--hypothesis-show-statistics``): for the first, whether the
drawn configuration was accepted, and which spellings it held (a shared string prefix without
nesting, a trailing slash, ``..``, another letter case, another Unicode normalization), and for
a refused one, how the root overlapped. Every value is synthetic.
"""

from __future__ import annotations

import copy
import posixpath
import string
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import combinations
from typing import Any, Final

from handoff import command
from handoff.config import ConfigError, HandoffConfig, parse_config
from handoff.evaluate import GUARDS_ACTIVE
from handoff.manifest import SYNC_POINTS, Item, parse_manifest
from hypothesis import event, given, settings
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy
from strategies import handoff as handoff_strategies

#: The home directory of every configuration of ``strategies.handoff``.
HOME: Final = handoff_strategies.HOME

#: The git subcommands that Property 25 names: they overwrite a working tree, the index or a stash.
FORBIDDEN_SUBCOMMANDS: Final = frozenset({"checkout", "restore", "stash", "reset", "clean", "switch"})

#: Every git option that starts with this forces something (``--force``, ``--force-with-lease``).
FORCE_PREFIX: Final = "--force"

#: The prompt of the ``kiro-cli`` invocations. Only their working directory is read here.
PROMPT: Final = "合成の Handoff_Prompt。cwd だけを確かめる。"

#: Directory names for derived paths: the components of ``PATH_COMPONENTS`` that name one.
PATH_NAMES: Final = tuple(part for part in handoff_strategies.PATH_COMPONENTS if part not in ("..", ".", ""))

#: The names of :data:`PATH_NAMES` whose NFC and NFD forms differ (``café`` in both forms, upper
#: case too). A root ends with one now and then, so that a planted overlap can differ from it in
#: Unicode normalization only.
ACCENTED_NAMES: Final = tuple(
    name for name in PATH_NAMES if unicodedata.normalize("NFC", name) != unicodedata.normalize("NFD", name)
)

#: How :func:`respelled` writes a path again, each time naming the same directory.
SPELLINGS: Final = (
    *("trailing slash", "dot dot", "dot", "double slash", "tilde"),
    *("swapped case", "nfd", "nfc", "other normalization"),
)

#: Where a protected path of :func:`path_cases` comes from when it is not the planted overlap,
#: repeated to weigh the draw.
SOURCES: Final = ("family", "family", "near", "near", "base")

#: In how many examples of ten :func:`path_cases` plants one overlap with the root.
PLANTED_IN_TEN: Final = 3

#: How :func:`dangers` makes a path that overlaps the root: the root itself, its parent, the
#: directory of one item's repository, one item's cwd, or a directory below that cwd.
DANGERS: Final = ("same", "ancestor", "repo", "cwd", "below cwd")

#: The first spelling of a planted overlap; ``None`` keeps the path as built. Letter case and
#: Unicode normalization come first, so that an overlap seen only after folding is common.
DANGER_SPELLINGS: Final = ("swapped case", "swapped case", "other normalization", "other normalization", None)

#: Values that ``worktree add`` must refuse: refs and SHAs of another form (see :func:`bad_refs`).
BAD_REFS: Final = ("origin/main", "refs/remotes/origin/main", "main", "HEAD", "FETCH_HEAD", "")

#: The digits of a SHA.
HEX_DIGITS: Final = "0123456789abcdef"

#: Characters of a repository name of the manifest's form.
REPO_CHARACTERS: Final = string.ascii_letters + string.digits + "._-"

#: Strings that, joined to a directory, can name a path outside it. Which ones do depends on how
#: deep the argument sits: an item ID is two components below ``.private/handoff``, so ``..``
#: alone keeps its report inside.
CLIMBING_TEXTS: Final = ("..", "../x", "../..", "../../x", "x/../..", "/", "/etc", "/x/.private/handoff")

#: Strings that are not a repository name, an item ID or a Sync_Point of the manifest's forms,
#: or are only some of them.
ODD_TEXTS: Final = (
    *("", ".", "...", "a/b", "x/..", "~", "~/x", "a\x00b", "a\nb", "日本語", "café", " x", "x y", "a\\b"),
    *("A", "a--b", "-a", "a-", "Rollout", "rollout ", "sync", "f"),
)

#: Values of the wrong Python type.
ODD_TYPES: Final = (None, 7, b"x")

#: The fields of a :class:`FileCase` besides ``handoff_dir``.
FILE_FIELDS: Final = ("repo", "item_id", "sync_point")


# --------------------------------------------------------------------------------------------
# The test's own reading of "normalized"
# --------------------------------------------------------------------------------------------


def lexical(path: str) -> str:
    """Write a path as the configuration reads it, without folding.

    ``~`` alone or before ``/`` becomes :data:`HOME`, and ``posixpath.normpath`` drops a
    trailing slash, ``.`` and repeated slashes and resolves ``..``; two leading slashes become
    one. Written here from the rule in the docstring of ``handoff.config``.

    Args:
        path: An absolute path, or one that starts with ``~``.

    Returns:
        The absolute path, letter case and Unicode form kept.
    """
    if path == "~" or path.startswith("~/"):
        path = HOME + path[1:]
    return "/" + posixpath.normpath(path).lstrip("/")


def components(path: str, *, case: bool = True, unicode: bool = True) -> tuple[str, ...]:
    """Split a path into the names a case-insensitive APFS volume compares.

    Args:
        path: An absolute path, or one that starts with ``~``.
        case: Fold letter case.
        unicode: Fold the Unicode normalization (NFD before and after the case fold).

    Returns:
        The components of :func:`lexical`, folded as asked.
    """
    text = lexical(path)
    if unicode:
        text = unicodedata.normalize("NFD", text)
    if case:
        text = text.casefold()
        if unicode:
            text = unicodedata.normalize("NFD", text)
    return tuple(part for part in text.split("/") if part)


def within(path: str, parent: str, *, case: bool = True, unicode: bool = True) -> bool:
    """Whether ``path`` is ``parent`` or lies below it, compared by :func:`components`."""
    inner = components(path, case=case, unicode=unicode)
    outer = components(parent, case=case, unicode=unicode)
    return inner[: len(outer)] == outer


def relation(path: str, other: str, *, case: bool = True, unicode: bool = True) -> str | None:
    """Say how ``path`` meets ``other``: ``equals``, ``is inside``, ``contains``, or ``None``."""
    if within(path, other, case=case, unicode=unicode):
        return "equals" if within(other, path, case=case, unicode=unicode) else "is inside"
    if within(other, path, case=case, unicode=unicode):
        return "contains"
    return None


def strictly_below(path: str, parent: str) -> bool:
    """Whether ``path`` lies below ``parent`` and is not ``parent`` itself."""
    return within(path, parent) and len(components(path)) > len(components(parent))


def shares_string_prefix(a: str, b: str) -> bool:
    """Whether one folded path is a string prefix of the other although they do not nest (``/a/b``, ``/a/bc``)."""
    first, second = "/".join(components(a)), "/".join(components(b))
    return first != second and (first.startswith(second) or second.startswith(first)) and relation(a, b) is None


def shared_spelling(a: str, b: str) -> str | None:
    """Tell how the folded components that two paths share are written differently.

    Returns:
        ``another Unicode normalization`` when the shared components differ only in NFC and NFD,
        ``another letter case`` when they differ otherwise, ``None`` when nothing is shared or
        the shared components are written alike.
    """
    first, second = components(a), components(b)
    shared = 0
    while shared < min(len(first), len(second)) and first[shared] == second[shared]:
        shared += 1
    if not shared:
        return None
    if components(a, case=False, unicode=False)[:shared] == components(b, case=False, unicode=False)[:shared]:
        return None
    if components(a, case=False)[:shared] == components(b, case=False)[:shared]:
        return "another Unicode normalization"
    return "another letter case"


def exact_parts(path: str) -> tuple[str, ...]:
    """The components of ``posixpath.normpath(path)``, without folding."""
    return tuple(part for part in posixpath.normpath(path).split("/") if part)


def is_private_handoff(path: object) -> bool:
    """Whether a value is an absolute path whose last two components are ``.private`` and ``handoff``."""
    return type(path) is str and path.startswith("/") and exact_parts(path)[-2:] == (".private", "handoff")


def exactly_below(path: str, parent: str) -> bool:
    """Whether ``path`` lies below ``parent`` after ``normpath``, compared without folding, and is not ``parent``."""
    inner, outer = exact_parts(path), exact_parts(parent)
    return len(inner) > len(outer) and inner[: len(outer)] == outer


# --------------------------------------------------------------------------------------------
# Strategies for parts 1 and 2
# --------------------------------------------------------------------------------------------


def respelled(path: str, how: str) -> str:
    """Write a path again so that it names the same directory under the folded comparison.

    Args:
        path: An absolute path, or one that starts with ``~``.
        how: One of :data:`SPELLINGS`.

    Returns:
        The path in the new spelling. ``handoff.config.normalize_path`` accepts it.
    """
    if how == "trailing slash":
        return path[:-1] if path.endswith("/") and len(path) > 1 else path + "/"
    if how == "dot dot":
        return path.rstrip("/") + "/x/.."
    if how == "dot":
        return path.rstrip("/") + "/."
    if how == "double slash":
        return path.replace("/", "//", 1) if "/" in path else path + "//"
    if how == "tilde":
        if path == HOME or path.startswith(HOME + "/"):
            return "~" + path[len(HOME) :]
        if path == "~" or path.startswith("~/"):
            return HOME + path[1:]
        return path
    if how == "swapped case":
        return path.swapcase()
    if how == "other normalization":
        decomposed = unicodedata.normalize("NFD", path)
        return decomposed if decomposed != path else unicodedata.normalize("NFC", path)
    return unicodedata.normalize(how.upper(), path)


@st.composite
def respellings(draw: st.DrawFn, path: str) -> str:
    """Write a path in zero to two spellings of :data:`SPELLINGS`, applied in turn."""
    for how in draw(st.lists(st.sampled_from(SPELLINGS), max_size=2)):
        path = respelled(path, how)
    return path


@st.composite
def near_misses(draw: st.DrawFn, root: str) -> str:
    """Draw a path that shares a string prefix or a parent with ``root`` and does not nest with it.

    The last component of the root gets a ``c`` (``/a/b`` to ``/a/bc``), loses its last
    character (``/a/bc`` to ``/a/b``), or is replaced by another name; the result is then
    respelled. A replacement name that folds to the same name gives an overlap after all; that
    happens now and then and is left to ``parse_config``.
    """
    normal = lexical(root)
    head, _, last = normal.rpartition("/")
    kinds = ["longer", *(["shorter"] if len(last) > 1 else []), *(["sibling"] if last else [])]
    kind = draw(st.sampled_from(kinds))
    if kind == "longer":
        path = normal + "c"
    elif kind == "shorter":
        path = normal[:-1]
    else:
        path = head + "/" + draw(st.sampled_from(PATH_NAMES))
    return draw(respellings(path))


@st.composite
def dangers(draw: st.DrawFn, root: str, items: Sequence[Item]) -> tuple[str, str]:
    """Draw a path that overlaps ``root``, respelled, and say which kind of :data:`DANGERS` it is.

    ``repo``, ``cwd`` and ``below cwd`` use one of ``items``: the directory of its repository
    (the name in its own letter case, swapped or upper case), its cwd, or a directory below the
    cwd. A configuration with such a protected path must be refused; if it were accepted, that
    item's cwd would overlap the path.
    """
    normal = lexical(root)
    kind = draw(st.sampled_from(DANGERS))
    if kind == "same":
        path = normal
    elif kind == "ancestor":
        path = posixpath.dirname(normal)
    else:
        item = draw(st.sampled_from(items))
        repo = draw(st.sampled_from((item.repo, item.repo.swapcase(), item.repo.upper())))
        path = normal.rstrip("/") + "/" + repo
        if kind != "repo":
            path += "/" + item.id
        if kind == "below cwd":
            path += "/" + draw(st.sampled_from(PATH_NAMES))
    first = draw(st.sampled_from(DANGER_SPELLINGS))
    if first is not None:
        path = respelled(path, first)
    return kind, draw(respellings(path))


def bad_refs(sha: str) -> SearchStrategy[str]:
    """Draw a value that is not 40 lowercase hexadecimal digits: a ref name, or a SHA of another form."""
    upper = sha.upper() if sha.upper() != sha else "A" + sha[1:]
    return st.sampled_from((*BAD_REFS, sha[:7], sha[:39], sha + "0", upper, " " + sha, "-" + sha[1:]))


@dataclass(frozen=True)
class PathCase:
    """One example of the first test.

    Attributes:
        base: The valid configuration of ``configs()`` that the manifest was drawn for.
        manifest_raw: The decoded manifest of ``manifests(config=base)``.
        raw: ``base.raw`` with ``worktrees_root`` and every ``main_tree`` replaced.
        extra_main_trees: The ``extra_main_trees`` argument for ``raw``.
        session_worktrees_dir: The ``session_worktrees_dir`` argument for ``raw``.
        sources: For each protected path of ``raw``, its role and where it came from
            (``family``, ``near``, ``base`` or ``danger: <kind>``).
        sha: The SHA for ``worktree add``.
        bad_ref: A value that ``worktree add`` must refuse.
    """

    base: handoff_strategies.ConfigCase
    manifest_raw: dict[str, Any]
    raw: dict[str, Any]
    extra_main_trees: tuple[str, ...]
    session_worktrees_dir: str
    sources: tuple[tuple[str, str], ...]
    sha: str
    bad_ref: str


@st.composite
def path_cases(draw: st.DrawFn) -> PathCase:
    """Draw a :class:`PathCase`: a base configuration, its manifest, and the drawn paths."""
    base = draw(handoff_strategies.configs())
    manifest_case = draw(handoff_strategies.manifests(config=base, max_items=4, max_files=1, max_refs=1))
    if manifest_case.manifest is None:
        raise AssertionError("manifests() drew a cyclic manifest without cyclic=True")
    items = manifest_case.manifest.items
    names = sorted(base.raw["repos"])
    family = draw(handoff_strategies.related_paths(min_size=3, max_size=len(names) + 4))
    root = draw(st.sampled_from(family))
    if draw(st.integers(1, 3)) == 1:
        root = root.rstrip("/") + "/" + draw(st.sampled_from(ACCENTED_NAMES))
    # Members of the family that do not meet the root, by the test's own comparison. Choosing
    # among them keeps most configurations acceptable; the planted overlap and the base paths
    # still give refused ones.
    apart = [path for path in family if relation(path, root) is None]
    count = draw(st.integers(1, 2))
    roles = [
        *(f"main tree of {name}" for name in names),
        *(f"caller tree {index + 1}" for index in range(count)),
        "session directory",
    ]
    planted = draw(st.sampled_from(roles)) if draw(st.integers(1, 10)) <= PLANTED_IN_TEN else None
    sources: list[tuple[str, str]] = []

    def protected(role: str, base_value: str) -> str:
        if role == planted:
            kind, path = draw(dangers(root, items))
            sources.append((role, f"danger: {kind}"))
            return path
        source = draw(st.sampled_from(SOURCES))
        if source == "family" and apart:
            path = draw(st.sampled_from(apart))
        elif source == "base":
            path = base_value
        else:
            source = "near"
            path = draw(near_misses(root))
        sources.append((role, source))
        return path

    raw = copy.deepcopy(base.raw)
    raw["worktrees_root"] = root
    for name in names:
        raw["repos"][name]["main_tree"] = protected(f"main tree of {name}", base.raw["repos"][name]["main_tree"])
    extra = tuple(
        protected(f"caller tree {index + 1}", base.extra_main_trees[index % len(base.extra_main_trees)])
        for index in range(count)
    )
    session = protected("session directory", base.session_worktrees_dir)
    sha = draw(st.text(HEX_DIGITS, min_size=40, max_size=40))
    return PathCase(
        base=base,
        manifest_raw=manifest_case.raw,
        raw=raw,
        extra_main_trees=extra,
        session_worktrees_dir=session,
        sources=tuple(sources),
        sha=sha,
        bad_ref=draw(bad_refs(sha)),
    )


# --------------------------------------------------------------------------------------------
# Parts 1 and 2
# --------------------------------------------------------------------------------------------


def protected_paths(raw: dict[str, Any], extra: Sequence[str], session: str) -> list[tuple[str, str]]:
    """List every protected path given to ``parse_config``, with its role, as written."""
    found = [(f"main working tree of {name}", entry["main_tree"]) for name, entry in sorted(raw["repos"].items())]
    found += [("main working tree given by the caller", tree) for tree in extra]
    found.append(("IDE session worktree directory", session))
    return found


def features(root: str, protected: Sequence[tuple[str, str]]) -> set[str]:
    """Name the spellings that the paths of an accepted configuration hold, for the events."""
    found: set[str] = set()
    for path in (root, *(path for _, path in protected)):
        parts = path.split("/")
        if len(path) > 1 and path.endswith("/"):
            found.add("a path with a trailing slash")
        if ".." in parts:
            found.add("a path with ..")
        if "." in parts:
            found.add("a path with .")
        if "//" in path:
            found.add("a path with //")
        if path.startswith("~"):
            found.add("a path with ~")
    named = [("root", root), *protected]
    for (role, first), (_, second) in combinations(named, 2):
        pair = "the root and a protected path" if role == "root" else "two protected paths"
        if shares_string_prefix(first, second):
            found.add(f"{pair}: a shared string prefix without nesting")
        if role != "root" and relation(first, second) is not None:
            found.add(f"{pair}: nested or the same")
        spelling = shared_spelling(first, second)
        if spelling is not None:
            found.add(f"{pair}: a shared part in {spelling}")
    return found


def check_item(
    config: HandoffConfig,
    item: Item,
    *,
    root: str,
    protected: Sequence[tuple[str, str]],
    main_tree: str,
    sha: str,
    bad_ref: str,
) -> set[str]:
    """Check parts 1 and 2 of Property 25 for one item under one accepted configuration.

    Args:
        config: The configuration, accepted by ``parse_config``.
        item: An item that passed ``parse_manifest`` under ``config``.
        root: ``worktrees_root`` as written.
        protected: Every protected path given to ``parse_config``, as written, with its role.
        main_tree: The item's main working tree, by :func:`lexical`.
        sha: A SHA for ``worktree add``.
        bad_ref: A value that ``worktree add`` must refuse.

    Returns:
        The shapes of the item, for the events.
    """
    try:
        plan = command.build_git_plan(config, item)
        invocation = command.build_kiro_argv(
            config, item, PROMPT, home=HOME, selftest_result=GUARDS_ACTIVE, approved_agents=frozenset()
        )
    except command.CommandError as error:
        raise AssertionError(
            f"refused {item.id} of {item.repo}, which passed parse_manifest under a configuration that passed "
            f"parse_config: {error}"
        ) from error
    cwd = plan.worktree
    assert invocation.cwd == cwd, f"kiro-cli would run in {invocation.cwd}, not in the worktree {cwd}"

    # Part 1: where the cwd lies.
    assert strictly_below(cwd, root), f"the cwd {cwd} is not strictly below worktrees_root {root}"
    for role, path in protected:
        met = relation(cwd, path)
        assert met is None, f"the cwd {cwd} {met} the {role} {path}"

    # Part 2: what the git plan runs.
    commands = plan.commands(sha)
    for git in commands:
        forbidden = [word for word in git.argv if word in FORBIDDEN_SUBCOMMANDS or word.startswith(FORCE_PREFIX)]
        assert not forbidden, f"the git plan holds {forbidden}: {git.argv}"
    assert commands == (
        plan.fetch,
        plan.ls_remote,
        plan.rev_parse,
        plan.worktree_add(sha),
    ), "commands() is not the commands that the runner takes one by one"
    if item.mode == "change":
        add: tuple[str, ...] = ("worktree", "add", "-b", command.BRANCH_PREFIX + item.id, cwd, sha)
    else:
        add = ("worktree", "add", "--detach", cwd, sha)
    expected = (
        ("fetch", "--no-tags", "origin", "main"),
        ("ls-remote", "origin", "refs/heads/main"),
        ("rev-parse", "refs/remotes/origin/main"),
        add,
    )
    assert len(commands) == len(expected), f"the git plan has {len(commands)} commands: {[c.argv for c in commands]}"
    for git, rest in zip(commands, expected, strict=True):
        assert git.argv == ("git", "-C", main_tree, *rest), f"expected git -C {main_tree} {rest}, got {git.argv}"
        assert git.cwd == main_tree, f"{git.argv} runs in {git.cwd}, not in the main working tree {main_tree}"
    try:
        loose = plan.worktree_add(bad_ref)
    except command.CommandError:
        pass
    else:
        raise AssertionError(f"worktree add took {bad_ref!r}, which is not an explicit SHA: {loose.argv}")

    shapes = {f"a {item.mode} item"}
    if any(shares_string_prefix(cwd, path) for _, path in protected):
        shapes.add("a cwd and a protected path with a shared string prefix")
    return shapes


def check_configuration(
    label: str,
    config: HandoffConfig,
    raw: dict[str, Any],
    extra: Sequence[str],
    session: str,
    case: PathCase,
) -> set[str]:
    """Check parts 1 and 2 for every item of the case's manifest under one accepted configuration.

    Args:
        label: ``base`` or ``drawn``, the prefix of the shapes.
        config: The configuration, accepted by ``parse_config``.
        raw: Its decoded ``config.json``.
        extra: The ``extra_main_trees`` it was checked with.
        session: The ``session_worktrees_dir`` it was checked with.
        case: The example, for the manifest and the SHAs.

    Returns:
        The shapes, each prefixed with ``label``, for the events.
    """
    root = raw["worktrees_root"]
    protected = protected_paths(raw, extra, session)
    checked = parse_manifest(case.manifest_raw, config=config)
    shapes = {"accepted", *features(root, protected)}
    for item in checked.items:
        shapes |= check_item(
            config,
            item,
            root=root,
            protected=protected,
            main_tree=lexical(raw["repos"][item.repo]["main_tree"]),
            sha=case.sha,
            bad_ref=case.bad_ref,
        )
    return {f"{label}: {shape}" for shape in shapes}


def refusal_shapes(case: PathCase) -> set[str]:
    """Name how the root of a refused configuration overlaps its protected paths, for the events.

    An overlap is ``seen without folding`` when the components of :func:`lexical` already show
    it, ``seen only after NFD`` when only the Unicode fold shows it, and ``seen only after case
    folding`` otherwise.
    """
    root = case.raw["worktrees_root"]
    shapes: set[str] = set()
    for _, path in protected_paths(case.raw, case.extra_main_trees, case.session_worktrees_dir):
        met = relation(root, path)
        if met is None:
            continue
        if relation(root, path, case=False, unicode=False) is not None:
            seen = "seen without folding"
        elif relation(root, path, case=False) is not None:
            seen = "seen only after NFD"
        else:
            seen = "seen only after case folding"
        shapes.add(f"drawn: refused, the root {met} a protected path, {seen}")
    return shapes or {"drawn: refused without an overlap that the test sees"}


# Feature: cyber-resilience-phase4-supply-chain, Property 25: cwd と書き込み先は専用の場所に限られ、git の計画は作業ツリーを上書きしない
@settings(max_examples=200, deadline=None)
@given(path_cases())
def test_property_25_cwd_stays_below_the_root_and_git_only_adds_a_worktree(case: PathCase) -> None:
    """Every cwd lies strictly below ``worktrees_root`` and off every protected path; git fetches and adds a worktree only.

    For the base configuration and, when ``parse_config`` accepts it, the configuration with the
    drawn paths, every item of the manifest gets a git plan and a ``kiro-cli`` invocation, and
    :func:`check_item` checks parts 1 and 2 of Property 25 on them.

    **Validates: Requirements 23.4, 28.5, 28.6, 28.22**
    """
    base = case.base
    if base.config is None:
        raise AssertionError("configs() drew an invalid configuration without valid=False")
    shapes = check_configuration("base", base.config, base.raw, base.extra_main_trees, base.session_worktrees_dir, case)
    try:
        drawn = parse_config(
            case.raw,
            home=HOME,
            extra_main_trees=case.extra_main_trees,
            session_worktrees_dir=case.session_worktrees_dir,
        )
    except ConfigError:
        shapes |= refusal_shapes(case)
    else:
        shapes |= check_configuration("drawn", drawn, case.raw, case.extra_main_trees, case.session_worktrees_dir, case)
    for role, source in case.sources:
        if source.startswith("danger"):
            shapes.add(f"planted {source} as the {role}")
    for shape in sorted(shapes):
        event(shape)


# --------------------------------------------------------------------------------------------
# Part 3
# --------------------------------------------------------------------------------------------


def handoff_dirs() -> SearchStrategy[str]:
    """Draw a ``.private/handoff`` directory: absolute, in normal form, below this repository or a drawn path."""
    trees = st.just(handoff_strategies.THIS_REPO_TREE) | handoff_strategies.paths().map(lexical)
    return trees.map(lambda tree: tree.rstrip("/") + "/.private/handoff")


def odd_handoff_dirs() -> SearchStrategy[Any]:
    """Draw a value that is not a ``.private/handoff`` directory in normal form, or of the wrong type."""
    respelled_dirs = handoff_dirs().flatmap(
        lambda path: st.sampled_from(
            (
                path + "/",
                path + "/.",
                path + "/x/..",
                path[1:],
                path + "/sub",
                posixpath.dirname(path),
                path.replace("/.private/", "/.Private/"),
                path.replace("/.private/", "/private/"),
                path + "s",
                "/" + path,
            )
        )
    )
    return respelled_dirs | st.sampled_from((None, 7, b"/x/.private/handoff", ".private/handoff", "", "/"))


def odd_values() -> SearchStrategy[Any]:
    """Draw a value for a repository name, an item ID or a Sync_Point that is odd or of the wrong type.

    :data:`CLIMBING_TEXTS` has two branches of the five, so that a value that would climb out of
    ``.private/handoff`` meets valid other arguments in most searches.
    """
    climbing = st.sampled_from(CLIMBING_TEXTS)
    return st.one_of(
        climbing,
        climbing,
        st.sampled_from(ODD_TEXTS),
        st.text(st.sampled_from("./~-_aZ09\x00\n日é"), max_size=6) | st.just("a" * 65),
        st.sampled_from(ODD_TYPES),
    )


def repo_names() -> SearchStrategy[str]:
    """Draw a repository name of the manifest's form: ASCII letters, digits, ``.``, ``_``, ``-``, not ``.`` or ``..``."""
    drawn = st.text(REPO_CHARACTERS, min_size=1, max_size=24).map(
        lambda name: name + "x" if name in (".", "..") else name
    )
    return drawn | st.sampled_from(handoff_strategies.REPO_NAMES)


@dataclass(frozen=True)
class FileCase:
    """One example of the second test.

    Attributes:
        handoff_dir: The ``handoff_dir`` argument.
        repo: The ``repo`` argument.
        item_id: The ``item_id`` argument.
        sync_point: The ``sync_point`` argument.
        odd: The arguments drawn from the odd values (``handoff_dir`` and :data:`FILE_FIELDS`).
            An odd draw can still be valid, such as ``...`` for a repository.
    """

    handoff_dir: Any
    repo: Any
    item_id: Any
    sync_point: Any
    odd: frozenset[str]


@st.composite
def file_cases(draw: st.DrawFn) -> FileCase:
    """Draw a :class:`FileCase`: each argument of its valid form in most draws, odd in the others.

    In about one example of three, one of :data:`FILE_FIELDS` is a value of
    :data:`CLIMBING_TEXTS` and every other argument is valid, so that the check of that argument
    is the only one that can refuse it, and a missing check shows as a path outside
    ``.private/handoff``.
    """
    odd: set[str] = set()
    focus = draw(st.sampled_from(FILE_FIELDS)) if draw(st.integers(1, 3)) == 1 else None

    def pick(name: str, valid: SearchStrategy[Any], other: SearchStrategy[Any], one_in: int) -> Any:
        if focus is not None:
            if name != focus:
                return draw(valid)
            odd.add(name)
            return draw(st.sampled_from(CLIMBING_TEXTS))
        if draw(st.integers(1, one_in)) == 1:
            odd.add(name)
            return draw(other)
        return draw(valid)

    handoff_dir = pick("handoff_dir", handoff_dirs(), odd_handoff_dirs(), 5)
    repo = pick("repo", repo_names(), odd_values(), 3)
    item_id = pick("item_id", handoff_strategies.item_ids(), odd_values(), 3)
    # rollout three times in eight, so that its prompt, the one directly below .private/handoff,
    # is common.
    sync_point = pick("sync_point", st.sampled_from((*SYNC_POINTS, "rollout", "rollout")), odd_values(), 3)
    return FileCase(handoff_dir, repo, item_id, sync_point, frozenset(odd))


def climbs(value: object) -> bool:
    """Whether a value, joined to a directory, could name a path outside it."""
    return isinstance(value, str) and (value.startswith("/") or ".." in value.split("/"))


# Feature: cyber-resilience-phase4-supply-chain, Property 25: cwd と書き込み先は専用の場所に限られ、git の計画は作業ツリーを上書きしない
@settings(max_examples=300, deadline=None)
@given(file_cases())
def test_property_25_handoff_files_stay_below_private_handoff(case: FileCase) -> None:
    """The Handoff_Prompt, the Handoff_Report and the status file lie strictly below the given ``.private/handoff``.

    ``handoff_files`` either refuses the arguments or returns three paths strictly below
    ``handoff_dir``, after ``normpath``, and then ``handoff_dir`` is a ``.private/handoff``
    directory. It refuses with ``CommandError`` only when the repository, the ID or the
    Sync_Point is odd, and with ``ValueError`` or ``TypeError`` only when ``handoff_dir`` is: a
    valid argument is never the reason for a refusal.

    **Validates: Requirements 23.4, 28.5, 28.6, 28.22**
    """
    for name in sorted(case.odd):
        climbing = name in FILE_FIELDS and climbs(getattr(case, name))
        event(f"odd {name}" + (" that could climb out" if climbing else ""))
    try:
        files = command.handoff_files(
            case.handoff_dir, repo=case.repo, item_id=case.item_id, sync_point=case.sync_point
        )
    except command.CommandError as error:
        assert case.odd & set(
            FILE_FIELDS
        ), f"refused a repository, an ID and a Sync_Point of their valid forms: {error}"
        event(f"refused: {error.history_reason}")
        return
    except (TypeError, ValueError) as error:
        assert "handoff_dir" in case.odd, f"refused a handoff_dir of its valid form: {error!r}"
        event(f"refused: handoff_dir ({type(error).__name__})")
        return
    assert is_private_handoff(
        case.handoff_dir
    ), f"gave paths for {case.handoff_dir!r}, which is not a .private/handoff directory: {files}"
    for name in ("status", "report", "prompt"):
        path = getattr(files, name)
        assert type(path) is str and path.startswith("/"), f"the {name} path is not an absolute path: {path!r}"
        assert exactly_below(
            path, case.handoff_dir
        ), f"the {name} path {path!r} is not strictly below {case.handoff_dir}"
    event(
        "returned: a rollout prompt"
        if case.sync_point == command.ROLLOUT_SYNC_POINT
        else "returned: a Sync_Point prompt"
    )
    for name in sorted(case.odd & set(FILE_FIELDS)):
        event(f"returned for an odd {name}")
