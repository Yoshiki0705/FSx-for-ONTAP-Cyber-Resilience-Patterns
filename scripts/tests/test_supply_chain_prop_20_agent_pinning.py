"""Property 20: the verdict on a pinned or unpinned agent component.

Task 11.10 of the phase 4 spec (design, Correctness Properties, Property 20), which validates
Requirements 6.1, 6.2, 6.4 and 6.8. For any package name and version string put into a command
line (``uvx``, ``npx -y``, ``pipx run``, ``dnx``, ``docker run``, or the ``command`` and
``args`` of an MCP server):

1. A form pinned to an exact version (``@1.2.3``, ``==1.2.3``) or to a digest
   (``@sha256:<64 hex digits>``) is not reported.
2. ``@latest``, an omitted version, a range and a ``latest`` or missing image tag are reported
   with the file path, the line number and the component name.
3. An image with a tag but no digest is reported only where the image is an MCP server
   (Requirement 6.4); in a plain command line it is a pin.

How the property is read. A command is drawn once as an argument vector (``Cmd``) with the
verdict that the design gives for it. It is then placed in a document at a drawn depth: a
fenced block or inline code of Markdown, a shell script, a Makefile recipe, a workflow, the
JSON argument of ``claude mcp add-json``, an ``mcpServers`` file (under three table keys and
four file names) or the front matter of an agent file. The oracle is the expected verdict of
the ``Cmd`` and the line the document builder wrote it on; ``scan_file`` and ``check`` must agree
on name, version, problem, path and line. A scanner that skipped a runner, a document kind or
a version form would differ from it.

The bin rule (a bare ``npx <name>`` is pinned when the nearest ``package.json`` declares the
name at an exact version and a lock file sits beside it) is the second property. Its oracle is
the layout of the files the case writes, not ``PackageIndex``.

Nothing is filtered or assumed away. ``hypothesis.event`` reports the form, the document kind
and the verdict of each example (``pytest --hypothesis-show-statistics``). The last test draws
from the same strategies with ``derandomize=True`` and checks that every form appears in every
document kind and that every verdict is reached, so the check does not depend on a seed.

Known gap, kept out of the strategies. The scanner treats a spec that holds ``<`` as a
placeholder (``<name>``) and skips it, so a range with an upper bound that is quoted on a
command line or written in the ``args`` of an MCP server (``'ruff<2'``, ``ruff>=1,<2``,
``pkg@<=2.0.0``) is not reported. The generators therefore draw ranges without ``<``, and
``test_a_range_with_an_upper_bound_is_reported`` states the property for the missing forms. It is
``xfail(strict=True)``: it passes the day the scanner reports them, and then fails until the
marker is removed.

Every value is synthetic.
"""

from __future__ import annotations

import json
import shlex
import string
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml
from hypothesis import HealthCheck, event, given, settings
from hypothesis import strategies as st
from supply_chain_checks import agent_components as ac

_HEALTH = [HealthCheck.too_slow, HealthCheck.data_too_large, HealthCheck.large_base_example]

# ---------------------------------------------------------------- values

_WORD = st.text(alphabet=string.ascii_lowercase + string.digits, min_size=1, max_size=6)
#: Always holds a hyphen, so a name is never a runner name such as ``npx``.
_HYPHENATED = st.builds("{}-{}".format, _WORD, _WORD)
_NPM_NAME = st.builds("{}{}".format, st.sampled_from(["", "@scope/", "@org-x/"]), _HYPHENATED)
_TRIPLE = st.tuples(st.integers(0, 99), st.integers(0, 99), st.integers(0, 99)).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}")
_NPM_EXACT = st.builds("{}{}".format, _TRIPLE, st.sampled_from(["", "-rc.1", "-beta", "+build5"]))
_PY_EXACT = st.builds("{}{}".format, _TRIPLE, st.sampled_from(["", "rc1", ".post1", "a2"]))
_NUGET_NAME = st.builds(
    lambda a, b: f"{a.capitalize()}.{b.capitalize()}",
    st.text(alphabet=string.ascii_lowercase, min_size=2, max_size=6),
    st.text(alphabet=string.ascii_lowercase, min_size=2, max_size=6),
)
_NUGET_EXACT = st.builds(
    lambda parts, pre: ".".join(map(str, parts)) + pre,
    st.lists(st.integers(0, 99), min_size=2, max_size=4),
    st.sampled_from(["", "-preview.1"]),
)
_HEX64 = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)
_IMAGE = st.builds("{}{}/{}".format, st.sampled_from(["", "ghcr.io/", "docker.io/"]), _WORD, _HYPHENATED)
_EXTRAS = st.sampled_from(["", "[extra]", "[a,b]"])
_TRAILING = st.sampled_from([(), ("--stdio",), ("serve", "--port", "8080")])
_NPM_RANGE = st.one_of(
    st.builds("{}{}".format, st.sampled_from(["^", "~", ">=", ">"]), _NPM_EXACT),
    st.sampled_from(["*", "x", "1.x", "1.2.x", "1", "1.2"]),
    st.builds("{} - {}".format, _NPM_EXACT, _NPM_EXACT),
)
_PY_RANGE = st.one_of(
    st.builds("{}{}".format, st.sampled_from([">=", ">", "~=", "!="]), _TRIPLE),
    st.builds(lambda a, b: f">={a},!={b}", _TRIPLE, _TRIPLE),
    st.builds("==%d.*".__mod__, st.integers(0, 99)),
)
_NUGET_RANGE = st.sampled_from(["*", "1.*", "[1.0,2.0)", "(,2.0]", "[1.0,)"])


@dataclass(frozen=True)
class Cmd:
    """A drawn command with the verdict the design gives for it.

    Attributes:
        form: Label of the runner and the way the version is written.
        argv: The argument vector, ``argv[0]`` the command.
        name: The component name that must be reported.
        version: The version as it must be recorded.
        plain: The expected ``problem`` in a command line (``None`` for a pin).
        mcp: The expected ``problem`` where the command is an MCP server.
    """

    form: str
    argv: tuple[str, ...]
    name: str
    version: str
    plain: str | None
    mcp: str | None


def _npm(draw: st.DrawFn, pinned: bool) -> tuple[str, str, str, str | None]:
    """Return ``(name, spec, version, problem)`` for an npm-style package."""
    name = draw(_NPM_NAME)
    if pinned:
        version = draw(_NPM_EXACT)
        return name, f"{name}@{version}", version, None
    kind = draw(st.sampled_from(["latest", "range", "tag", "omitted"]))
    if kind == "latest":
        return name, f"{name}@latest", "latest", "latest"
    if kind == "range":
        version = draw(_NPM_RANGE)
        return name, f"{name}@{version}", version, "range"
    if kind == "tag":
        version = draw(st.sampled_from(["next", "beta", "canary"]))
        return name, f"{name}@{version}", version, "unpinned"
    return name, name, ac.UNSPECIFIED, "unpinned"


def _python(draw: st.DrawFn, pinned: bool) -> tuple[str, str, str, str | None]:
    """Return ``(name, spec, version, problem)`` for a PyPI-style package."""
    name = draw(_HYPHENATED)
    extras = draw(_EXTRAS)
    head = f"{name}{extras}"
    if pinned:
        version = draw(_PY_EXACT)
        return name, head + draw(st.sampled_from(["==", "@"])) + version, version, None
    kind = draw(st.sampled_from(["latest", "range", "omitted"]))
    if kind == "latest":
        return name, f"{head}@latest", "latest", "latest"
    if kind == "range":
        version = draw(_PY_RANGE)
        return name, head + version, version, "range"
    return name, head, ac.UNSPECIFIED, "unpinned"


@st.composite
def _npm_cmd(draw: st.DrawFn, pinned: bool) -> Cmd:
    name, spec, version, problem = _npm(draw, pinned)
    form = draw(st.sampled_from(["npx", "npx-p", "npx-package-eq", "bunx"]))
    trailing = draw(_TRAILING)
    if form == "npx":
        flags = draw(st.sampled_from([(), ("-y",), ("--yes",), ("--registry", "https://registry.example.com")]))
        argv = ("npx", *flags, spec, *trailing)
    elif form == "npx-p":
        argv = ("npx", *draw(st.sampled_from([(), ("-y",)])), "-p", spec, "tool", *trailing)
    elif form == "npx-package-eq":
        argv = ("npx", f"--package={spec}", "tool", *trailing)
    else:
        argv = ("bunx", spec, *trailing)
    return Cmd(form, argv, name, version, problem, problem)


@st.composite
def _python_cmd(draw: st.DrawFn, pinned: bool) -> Cmd:
    name, spec, version, problem = _python(draw, pinned)
    form = draw(st.sampled_from(["uvx", "uvx-from", "uvx-from-eq", "pipx", "pipx-spec"]))
    pre = draw(st.sampled_from([(), ("--python", "3.12")]))
    trailing = draw(_TRAILING)
    if form == "uvx":
        argv = ("uvx", *pre, spec, *trailing)
    elif form == "uvx-from":
        argv = ("uvx", *pre, "--from", spec, "tool", *trailing)
    elif form == "uvx-from-eq":
        argv = ("uvx", *pre, f"--from={spec}", "tool", *trailing)
    elif form == "pipx":
        argv = ("pipx", "run", *pre, spec, *trailing)
    else:
        argv = ("pipx", "run", *pre, "--spec", spec, "tool", *trailing)
    return Cmd(form, argv, name, version, problem, problem)


@st.composite
def _dnx_cmd(draw: st.DrawFn, pinned: bool) -> Cmd:
    name = draw(_NUGET_NAME)
    yes = draw(st.sampled_from([(), ("--yes",)]))
    if pinned:
        version = draw(_NUGET_EXACT)
        form = draw(st.sampled_from(["dnx-version", "dnx-positional", "dnx-at"]))
        argv = {
            "dnx-version": ("dnx", name, "--version", version, *yes),
            "dnx-positional": ("dnx", *yes, name, version),
            "dnx-at": ("dnx", f"{name}@{version}", *yes),
        }[form]
        return Cmd(form, argv, name, version, None, None)
    kind = draw(st.sampled_from(["latest-at", "latest-flag", "range", "omitted"]))
    if kind == "latest-at":
        return Cmd("dnx-at", ("dnx", f"{name}@latest", *yes), name, "latest", "latest", "latest")
    if kind == "latest-flag":
        return Cmd("dnx-version", ("dnx", name, "--version", "latest", *yes), name, "latest", "latest", "latest")
    if kind == "range":
        version = draw(_NUGET_RANGE)
        return Cmd("dnx-version", ("dnx", name, "--version", version, *yes), name, version, "range", "range")
    return Cmd("dnx-positional", ("dnx", *yes, name), name, ac.UNSPECIFIED, "unpinned", "unpinned")


@st.composite
def _docker_cmd(draw: st.DrawFn, kind: str) -> Cmd:
    """Draw ``docker run``. ``kind`` is ``digest``, ``latest``, ``omitted`` or ``tag``."""
    image = draw(_IMAGE)
    opts = draw(
        st.sampled_from(
            [
                (),
                ("-i", "--rm"),
                ("--rm", "-e", "TOKEN"),
                ("-i", "--name", "srv-1", "-v", "/data:/data"),
                ("-e", "KEY=value"),
            ]
        )
    )
    trailing = draw(st.sampled_from([(), ("--stdio",)]))
    if kind == "digest":
        digest = f"sha256:{draw(_HEX64)}"
        ref, version, plain, mcp = f"{image}@{digest}", digest, None, None
    elif kind == "latest":
        ref, version, plain, mcp = f"{image}:latest", "latest", "latest", "latest"
    elif kind == "tag":
        version = draw(st.sampled_from(["1.2.3", "v1", "stable", "2024-01"]))
        ref, plain, mcp = f"{image}:{version}", None, "digest"
    else:
        ref, version, plain, mcp = image, ac.UNSPECIFIED, "unpinned", "unpinned"
    return Cmd("docker", ("docker", "run", *opts, ref, *trailing), image, version, plain, mcp)


@st.composite
def pinned_cmds(draw: st.DrawFn) -> Cmd:
    """A command pinned to an exact version or a digest."""
    return draw(st.one_of(_npm_cmd(True), _python_cmd(True), _dnx_cmd(True), _docker_cmd("digest")))


@st.composite
def unpinned_cmds(draw: st.DrawFn) -> Cmd:
    """A command with ``latest``, no version, or a range."""
    return draw(
        st.one_of(
            _npm_cmd(False),
            _python_cmd(False),
            _dnx_cmd(False),
            _docker_cmd("latest"),
            _docker_cmd("omitted"),
        )
    )


# ---------------------------------------------------------------- documents


@dataclass(frozen=True)
class Doc:
    """A file that holds one command, and where.

    Attributes:
        ctx: Label of the document kind.
        path: Path relative to the root.
        text: The file's text.
        line: The 1-based line on which the verdict must be reported.
        mcp: Whether the command is an MCP server (an image then needs a digest).
        server: The MCP server name, or ``None`` when the entry has none.
    """

    ctx: str
    path: str
    text: str
    line: int
    mcp: bool
    server: str | None


CONTEXTS = ("md_fence", "md_inline", "shell", "make", "workflow", "add_json", "mcp_json", "front_matter")


def _shell_line(argv: tuple[str, ...]) -> str:
    return " ".join(shlex.quote(token) for token in argv)


def _entry(argv: tuple[str, ...], with_env: bool) -> dict[str, object]:
    entry: dict[str, object] = {"command": argv[0], "args": list(argv[1:])}
    if with_env:
        entry["env"] = {"EXAMPLE_KEY": "example"}
    return entry


@st.composite
def docs(draw: st.DrawFn, argv: tuple[str, ...]) -> Doc:
    """Place ``argv`` in a document of a drawn kind, after a drawn number of other lines."""
    ctx = draw(st.sampled_from(CONTEXTS))
    pad = draw(st.integers(0, 4))
    prefix = draw(st.sampled_from(["", "sudo ", "FOO=bar ", "$ ", "- "]))
    line = prefix + _shell_line(argv)
    prose = [f"Paragraph {i}" for i in range(pad)]
    if ctx == "md_fence":
        lang = draw(st.sampled_from(["bash", "sh", "console", ""]))
        text = "\n".join([*prose, f"```{lang}", line, "```", ""])
        return Doc(ctx, "docs/guide.md", text, pad + 2, False, None)
    if ctx == "md_inline":
        text = "\n".join([*prose, f"Run `{line}` to start.", ""])
        return Doc(ctx, "docs/guide.md", text, pad + 1, False, None)
    if ctx == "shell":
        text = "\n".join(["#!/bin/sh", *["# note"] * pad, line, ""])
        return Doc(ctx, "scripts/run.sh", text, pad + 2, False, None)
    if ctx == "make":
        text = "\n".join(["all:", *["\t@echo ok"] * pad, f"\t@{line}", ""])
        return Doc(ctx, "Makefile", text, pad + 2, False, None)
    if ctx == "workflow":
        steps = ["      - run: echo ok"] * pad
        text = "\n".join(["jobs:", "  build:", "    steps:", *steps, f"      - run: {line}", ""])
        return Doc(ctx, ".github/workflows/ci.yml", text, pad + 4, False, None)
    if ctx == "add_json":
        spec = shlex.quote(json.dumps(_entry(argv, draw(st.booleans()))))
        text = "\n".join([*prose, "```bash", f"claude mcp add-json srv-x {spec}", "```", ""])
        return Doc(ctx, "docs/guide.md", text, pad + 2, True, None)
    server = "srv-" + draw(_WORD)
    entry = _entry(argv, draw(st.booleans()))
    others: dict[str, object] = {f"remote-{i}": {"url": f"https://example.com/mcp/{i}"} for i in range(pad)}
    table = {**others, server: entry}
    if ctx == "mcp_json":
        key = draw(st.sampled_from(["mcpServers", "servers", "context_servers"]))
        path = draw(st.sampled_from([".mcp.json", "mcp.json", ".kiro/settings/mcp.json", ".cursor/mcp.json"]))
        return Doc(ctx, path, json.dumps({key: table}, indent=2) + "\n", 3 + 3 * pad, True, server)
    front = yaml.safe_dump({"name": "reviewer", "mcpServers": table}, sort_keys=False, width=10**6)
    first = next(i for i, text_line in enumerate(front.splitlines()) if text_line.strip() == f"{server}:")
    path = draw(st.sampled_from([".kiro/agents/reviewer.md", "docs/agents/reviewer.md"]))
    return Doc(ctx, path, f"---\n{front}---\n# Agent\n", first + 2, True, server)


@dataclass(frozen=True)
class Case:
    """A command, the document that holds it and the verdict that must come out."""

    cmd: Cmd
    doc: Doc

    @property
    def expected(self) -> str | None:
        """The ``problem`` the design gives for this command in this document."""
        return self.cmd.mcp if self.doc.mcp else self.cmd.plain


@st.composite
def cases(draw: st.DrawFn, source: st.SearchStrategy[Cmd]) -> Case:
    cmd = draw(source)
    return Case(cmd, draw(docs(cmd.argv)))


def _check_case(case: Case) -> None:
    """Assert that ``scan_file`` and ``check`` give the verdict of ``case`` at its location."""
    cmd, doc = case.cmd, case.doc
    expected = case.expected
    event(f"form={cmd.form}")
    event(f"document={doc.ctx}")
    event(f"verdict={expected}")
    found = ac.scan_file(doc.path, doc.text)
    mine = [c for c in found if doc.server is None or c.server == doc.server]
    assert len(mine) == 1, (doc.text, found)
    got = mine[0]
    assert (got.name, got.version, got.problem, got.path, got.line) == (
        cmd.name,
        cmd.version,
        expected,
        doc.path,
        doc.line,
    ), doc.text
    assert [c for c in found if c.problem] == ([got] if expected else []), doc.text
    with tempfile.TemporaryDirectory(prefix="ac-prop20-") as tmp:
        target = Path(tmp) / doc.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(doc.text, encoding="utf-8")
        report = ac.check(Path(tmp))
    assert report.scanned == 1
    if expected is None:
        assert report.violations == []
        return
    assert len(report.violations) == 1, report.violations
    violation = report.violations[0]
    assert (violation.path, violation.line, violation.kind) == (doc.path, doc.line, expected)
    assert cmd.name in violation.detail
    assert violation.format().startswith(f"{doc.path}:{doc.line}: {expected}: ")


# ---------------------------------------------------------------- properties

_ANY_CASE = st.one_of(
    cases(pinned_cmds()),
    cases(unpinned_cmds()),
    cases(_docker_cmd("tag")),
)


# Feature: cyber-resilience-phase4-supply-chain, Property 20: エージェント構成要素の固定の判定
@settings(max_examples=200, deadline=None, suppress_health_check=_HEALTH)
@given(case=cases(pinned_cmds()))
def test_pinned_forms_are_not_reported(case: Case) -> None:
    """A version or digest pin is recorded as the component and raises no violation.

    **Validates: Requirements 6.1, 6.2, 6.4, 6.8**
    """
    assert case.expected is None
    _check_case(case)


# Feature: cyber-resilience-phase4-supply-chain, Property 20: エージェント構成要素の固定の判定
@settings(max_examples=200, deadline=None, suppress_health_check=_HEALTH)
@given(case=cases(unpinned_cmds()))
def test_unpinned_forms_are_reported_with_path_line_and_name(case: Case) -> None:
    """``latest``, no version and a range give exactly one violation, at the right line.

    **Validates: Requirements 6.1, 6.2, 6.4, 6.8**
    """
    assert case.expected is not None
    _check_case(case)


# Feature: cyber-resilience-phase4-supply-chain, Property 20: エージェント構成要素の固定の判定
@settings(max_examples=100, deadline=None, suppress_health_check=_HEALTH)
@given(case=cases(_docker_cmd("tag")))
def test_a_tagged_image_needs_a_digest_only_as_an_mcp_server(case: Case) -> None:
    """A tag is a pin in a command line and is reported (``digest``) for an MCP server.

    **Validates: Requirements 6.4**
    """
    assert case.expected == ("digest" if case.doc.mcp else None)
    _check_case(case)


_UPPER_BOUND = [
    ("uvx 'ruff<2'", "ruff"),
    ("uvx 'ruff>=1,<2'", "ruff"),
    ("npx 'pkg@<=2.0.0'", "pkg"),
]


@pytest.mark.xfail(strict=True, reason="a spec that holds '<' is skipped as a placeholder")
@pytest.mark.parametrize(("line", "name"), _UPPER_BOUND)
def test_a_range_with_an_upper_bound_is_reported(line: str, name: str) -> None:
    """A quoted range with ``<`` is a range, not a placeholder.

    **Validates: Requirements 6.1, 6.2**
    """
    found = ac.scan_command_line(line, "docs/guide.md", 1, "install-step", ac.EMPTY_INDEX)
    assert [(c.name, c.problem) for c in found] == [(name, "range")]


# ---------------------------------------------------------------- the bin rule

_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb")
_SCENARIOS = (
    "locked",
    "no_lock",
    "range_declared",
    "lock_in_parent",
    "sibling",
    "nearest_wins",
    "explicit_latest",
    "uvx_ignores",
)


def _join(*parts: str) -> str:
    return "/".join(p for p in parts if p)


@dataclass(frozen=True)
class BinCase:
    """Files, one script and the verdict that must come out for it."""

    scenario: str
    files: dict[str, str]
    script: str
    text: str
    name: str
    version: str
    problem: str | None
    scope: str


@st.composite
def bin_cases(draw: st.DrawFn) -> BinCase:
    """Lay out ``package.json`` and lock files around a script that runs a bare ``npx``."""
    scenario = draw(st.sampled_from(_SCENARIOS))
    pkg = draw(_NPM_NAME)
    v1, v2 = draw(_NPM_EXACT), draw(_NPM_EXACT)
    lock = draw(st.sampled_from(_LOCKS))
    table = draw(st.sampled_from(["dependencies", "devDependencies"]))
    runner = draw(st.sampled_from(["npx", "bunx"]))
    segs = draw(st.lists(_WORD, min_size=0, max_size=2))
    deep = draw(st.lists(_WORD, min_size=0, max_size=2))
    root = _join("app-dir", *segs)
    files: dict[str, str] = {}

    def declare(directory: str, version: str, locked: bool, lock_dir: str | None = None) -> None:
        files[_join(directory, "package.json")] = json.dumps({table: {pkg: version}})
        if locked:
            files[_join(directory if lock_dir is None else lock_dir, lock)] = ""

    script_dir = root
    command = f"{runner} -y {pkg}"
    name, version, problem, scope = pkg, ac.UNSPECIFIED, "unpinned", "none"
    if scenario == "locked":
        declare(root, v1, True)
        version, problem, scope = v1, None, "dependency-tree"
    elif scenario == "no_lock":
        declare(root, v1, False)
    elif scenario == "range_declared":
        declare(root, "^" + v1, True)
    elif scenario == "lock_in_parent":
        declare(root, v1, True, lock_dir=_join(*root.split("/")[:-1]))
    elif scenario == "sibling":
        declare("zz-sibling", v1, True)
    elif scenario == "nearest_wins":
        child = _join(root, "child")
        declare(root, v1, True)
        files[_join(child, "package.json")] = json.dumps({table: {pkg: v2}})
        files[_join(child, lock)] = ""
        script_dir = child
        version, problem, scope = v2, None, "dependency-tree"
    elif scenario == "explicit_latest":
        declare(root, v1, True)
        command = f"{runner} -y {pkg}@latest"
        version, problem = "latest", "latest"
    else:
        declare(root, v1, True)
        name = pkg.split("/")[-1]
        command = f"uvx {name}"
    script = _join(script_dir, *deep, "run.sh")
    return BinCase(scenario, files, script, f"{command}\n", name, version, problem, scope)


# Feature: cyber-resilience-phase4-supply-chain, Property 20: エージェント構成要素の固定の判定
@settings(max_examples=200, deadline=None, suppress_health_check=_HEALTH)
@given(case=bin_cases())
def test_a_bare_npx_is_pinned_only_by_a_locked_exact_declaration_above_it(case: BinCase) -> None:
    """The bin rule pins a bare ``npx <name>`` only when the layout of the files says so.

    The declaring ``package.json`` must be in the script's directory or above it, give an exact
    version, and have a lock file in the same directory. The nearest declaration wins. An
    explicit ``@latest`` and a non-npm runner are not helped by the declaration.

    **Validates: Requirements 6.1, 6.2, 6.8**
    """
    event(f"scenario={case.scenario}")
    event(f"verdict={case.problem}")
    index = ac.build_index(sorted(case.files), case.files.__getitem__)
    found = ac.scan_file(case.script, case.text, index)
    assert len(found) == 1, (case, found)
    got = found[0]
    assert (got.name, got.version, got.problem, got.pin_scope, got.path, got.line) == (
        case.name,
        case.version,
        case.problem,
        case.scope,
        case.script,
        1,
    ), case


# ---------------------------------------------------------------- reach


def test_the_strategies_reach_every_form_document_and_verdict() -> None:
    """With a fixed seed, every form, every document kind and every verdict is drawn.

    The check does not depend on chance: ``derandomize=True`` makes the examples a function of
    the test, so a form or a document kind that the draw never reached shows as a failure here
    every time. Each document kind must hold both a pinned and an unpinned command, and each
    form must appear in both an MCP and a plain document. Hypothesis does not draw the pairs
    of form and document kind evenly, so the pairs are not required.
    """
    forms: set[str] = set()
    by_document: set[tuple[str, bool]] = set()
    by_form: set[tuple[str, bool]] = set()
    verdicts: set[str | None] = set()

    @settings(max_examples=3000, deadline=None, derandomize=True, database=None, suppress_health_check=_HEALTH)
    @given(case=_ANY_CASE)
    def collect(case: Case) -> None:
        forms.add(case.cmd.form)
        by_document.add((case.doc.ctx, case.expected is None))
        by_form.add((case.cmd.form, case.doc.mcp))
        verdicts.add(case.expected)

    collect()
    all_forms = {
        "npx", "npx-p", "npx-package-eq", "bunx", "uvx", "uvx-from", "uvx-from-eq", "pipx", "pipx-spec",
        "dnx-version", "dnx-positional", "dnx-at", "docker",
    }  # fmt: skip
    assert forms == all_forms
    assert by_document == {(c, pinned) for c in CONTEXTS for pinned in (True, False)}
    assert by_form == {(f, mcp) for f in all_forms for mcp in (True, False)}
    assert verdicts == {None, "latest", "range", "unpinned", "digest"}
