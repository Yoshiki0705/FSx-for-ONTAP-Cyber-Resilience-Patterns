"""``agent-components`` subcommand: unpinned MCP servers, agent settings and install steps.

Checks (design section 10, Requirements 6.1 to 6.8):

* Files come from ``git ls-files`` when ``root`` is a repository (a fixture directory without
  ``.git`` is walked instead). ``scripts/tests/fixtures/`` is skipped when ``root`` is a
  repository, because those files are the deliberately bad inputs of the gates.
* A step first turns structure into "command and arguments": ``mcpServers`` of JSON files,
  of Markdown ``json`` / ``yaml`` blocks and of ``.kiro/agents/*.md`` front matter, and the JSON
  argument of ``claude mcp add-json``. Command lines (fenced blocks, inline code of Markdown,
  ``*.sh``, ``Makefile``, ``*.yml``) are then tokenised, and a package runner at command
  position is judged.
* Runners: ``npx`` / ``bunx`` (``-y``, ``--yes``, ``-p``), ``uvx`` (``--from``), ``pipx run``
  (``--spec``), ``dnx``. Kinds of violation: ``latest``, ``range``, ``unpinned``, and
  ``digest`` (an MCP ``docker run`` image with a tag but no ``@sha256:`` digest).
* A package that the nearest ``package.json`` declares with an exact version, next to a
  lock file, counts as pinned (its pin scope is the dependency tree).
* Lines that refer to a path under ``~/.kiro`` are not recorded. A server given only by
  ``url`` has the version "該当なし" and is never unpinned.
* A named MCP file (``mcp.json``, ``.mcp.json``, ``mcp-config.json``, ``plugin.json``) that is
  not valid JSON is ``Unparseable`` (exit code 2). So is a JSON / YAML block, an agent-settings
  JSON file or a front matter that mentions ``mcpServers`` or ``"command"`` and cannot be
  parsed, and a file that is not UTF-8.

Limits: the bin name of a package is not known statically, so ``npx tsc`` is judged by the
name ``tsc``. ``sh -c "..."`` strings inside prose are not parsed. External instructions
(prompts, rules, Skills, Powers) and model IDs are not detected (Requirement 6.7).

``docs/agent/agent-components.json`` is generated, not edited. Regenerate it with
``python3 scripts/supply_chain_checks/agent_components.py --write``.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, NamedTuple

import yaml

if __name__ == "__main__":  # run as a script: make ``supply_chain_checks`` importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from supply_chain_checks._common import REPO_ROOT, Report, Unparseable, Violation

INVENTORY_PATH = "docs/agent/agent-components.json"
#: Tracked paths under this prefix are the gates' own bad inputs.
FIXTURE_PREFIX = "scripts/tests/fixtures/"
NOT_APPLICABLE = "該当なし"
UNSPECIFIED = "未指定"

MCP_FILE_NAMES = ("mcp.json", ".mcp.json", "mcp-config.json", "plugin.json")
_AGENT_PATH = re.compile(r"(?:^|/)\.(?:kiro|cursor|amazonq|claude)/|(?:^|/)\.github/copilot-|(?:^|/)AGENTS\.md$")
_SERVER_KEYS = ("mcpServers", "servers", "context_servers")
_LOCK_FILES = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb")
_HOME_KIRO = re.compile(r"(?:~|\$HOME|\$\{HOME\})/\.kiro\b")

_NPM_EXACT = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_PY_EXACT = re.compile(r"^[0-9][0-9A-Za-z.+!_-]*$")
_NUGET_EXACT = re.compile(r"^\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z.-]+)?$")
_SHA40 = re.compile(r"[#@][0-9a-f]{40}\b")
_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
_PY_SPEC = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$")
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_WRAPPERS = frozenset({"sudo", "exec", "time", "nohup", "env", "then", "do", "else"})
_PUNCT = frozenset("();<>|&")
_JSON_HINT = re.compile(r'mcpServers|"command"|"args"')
_INLINE_CODE = re.compile(r"`([^`\n]+)`")

#: Options that take a value, by runner; the value is not the package.
_VALUE_FLAGS = {
    "npx": frozenset({"-c", "--call", "--registry", "--cache", "--userconfig", "--prefix", "--node-options"}),
    "uvx": frozenset(
        {"--with", "--python", "-p", "--index", "--index-url", "--extra-index-url", "--default-index", "--env-file"}
        | {"--directory", "--project", "--constraint", "-c", "--with-requirements", "--from", "--with-editable"}
    ),
    "pipx": frozenset({"--python", "--pip-args", "--spec", "--index-url"}),
    "dnx": frozenset({"--source", "--add-source", "--configfile", "--interactive", "--version"}),
}
_DOCKER_VALUE_FLAGS = frozenset(
    {"-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "--network", "--net", "--entrypoint", "-w"}
    | {"--workdir", "-u", "--user", "--mount", "--label", "-l", "--env-file", "--add-host", "--platform", "--pull"}
    | {"-m", "--memory", "--cpus", "--hostname", "-h", "--cap-add", "--cap-drop", "--device", "--tmpfs"}
)


class Component(NamedTuple):
    """One entry of the inventory.

    Attributes:
        kind: ``mcp-server``, ``agent-config`` or ``install-step``.
        name: Package or image name; the server name when no package is run.
        path: File the entry comes from, relative to the root.
        line: 1-based line number.
        executor: ``npx``, ``uvx``, ``docker``, ``remote``, and so on.
        version: The pinned version or digest, a range as written, ``未指定`` or ``該当なし``.
        problem: ``latest``, ``range``, ``unpinned``, ``digest``, or ``None`` when fine.
        pin_scope: ``top-level``, ``dependency-tree``, ``none`` or ``該当なし``.
        server: The MCP server name, when there is one.
    """

    kind: str
    name: str
    path: str
    line: int
    executor: str
    version: str
    problem: str | None
    pin_scope: str
    server: str | None = None

    def violation(self) -> Violation:
        """Return the finding for an unpinned component."""
        what = {
            "latest": "tracks the latest release",
            "range": "version is a range",
            "unpinned": "has no pinned version",
            "digest": "image has a tag but no @sha256 digest",
        }[self.problem or "unpinned"]
        return Violation(self.path, self.line, self.problem or "unpinned", f"{self.executor} {self.name}: {what}")


class PackageIndex(NamedTuple):
    """Exact-version declarations of the tracked ``package.json`` files.

    Attributes:
        declared: Directory (``""`` for the root) to the exact-version dependencies there.
        locked: Directories that hold a lock file next to ``package.json``.
    """

    declared: dict[str, dict[str, str]]
    locked: frozenset[str]

    def lookup(self, path: str, package: str) -> str | None:
        """Return the exact version the nearest declaring ``package.json`` gives, or ``None``."""
        directory = PurePosixPath(path).parent
        while True:
            key = "" if str(directory) == "." else str(directory)
            version = self.declared.get(key, {}).get(package)
            if version is not None and key in self.locked:
                return version
            if not key:
                return None
            directory = directory.parent


EMPTY_INDEX = PackageIndex({}, frozenset())


# ---------------------------------------------------------------- version judgement


# A placeholder is a word closed by ">" (``<version>``); "<" followed by a digit or "=" is a comparison.
_PLACEHOLDER = re.compile(r"<[A-Za-z_][^<>]*>")


def _is_local_or_placeholder(spec: str) -> bool:
    return (
        not spec
        or spec in {".", ".."}
        or spec.startswith(("./", "../", "/", "~", "file:", "[", "{"))
        or any(c in spec for c in "${")
        or _PLACEHOLDER.search(spec) is not None
    )


def _judge_npm(spec: str) -> tuple[str, str, str | None, str] | None:
    """Judge an npm-style spec. Returns ``(name, version, problem, scope)`` or ``None`` to skip."""
    if _is_local_or_placeholder(spec):
        return None
    if "://" in spec or spec.startswith(("git+", "github:", "gitlab:", "bitbucket:", "git@")):
        match = _SHA40.search(spec)
        return spec, match.group(0)[1:] if match else UNSPECIFIED, None if match else "unpinned", "top-level"
    at = spec.find("@", 1) if spec.startswith("@") else spec.find("@")
    name, version = (spec, None) if at == -1 else (spec[:at], spec[at + 1 :])
    if version is None:
        return name, UNSPECIFIED, "unpinned", "none"
    if _NPM_EXACT.match(version):
        return name, version, None, "top-level"
    if version == "latest":
        return name, version, "latest", "none"
    if version == "" or re.fullmatch(r"[\dxX*.]+", version) or any(c in version for c in "^~><*|") or " - " in version:
        return name, version, "range", "none"
    return name, version, "unpinned", "none"


def _judge_python(spec: str) -> tuple[str, str, str | None, str] | None:
    """Judge a PyPI-style spec (``pkg==1.2.3``, ``pkg@1.2.3``, ``pkg>=1``)."""
    if _is_local_or_placeholder(spec):
        return None
    if "://" in spec or spec.startswith("git+"):
        match = _SHA40.search(spec)
        return spec, match.group(0)[1:] if match else UNSPECIFIED, None if match else "unpinned", "top-level"
    match = _PY_SPEC.match(spec)
    if not match:
        return None
    name, rest = match.group(1), match.group(3).strip()
    if not rest:
        return name, UNSPECIFIED, "unpinned", "none"
    if rest.startswith("@"):
        version = rest[1:].strip()
        if version == "latest":
            return name, version, "latest", "none"
        exact = bool(_PY_EXACT.match(version)) and "*" not in version
        return name, version, None if exact else "range", "top-level" if exact else "none"
    if rest.startswith("==") and not rest.startswith("==="):
        version = rest[2:].strip()
        if _PY_EXACT.match(version) and "*" not in version:
            return name, version, None, "top-level"
    return name, rest, "range", "none"


def _judge_nuget(name: str, version: str | None) -> tuple[str, str, str | None, str]:
    if version is None:
        return name, UNSPECIFIED, "unpinned", "none"
    if _NUGET_EXACT.match(version):
        return name, version, None, "top-level"
    if version == "latest":
        return name, version, "latest", "none"
    return name, version, "range", "none"


def _judge_image(ref: str, require_digest: bool) -> tuple[str, str, str | None, str] | None:
    """Judge a container image reference."""
    if not ref or any(c in ref for c in "${<"):
        return None
    if _DIGEST.search(ref):
        return ref.split("@", 1)[0], ref.split("@", 1)[1], None, "top-level"
    if "@" in ref:
        return ref.split("@", 1)[0], ref.split("@", 1)[1], "unpinned", "none"
    last = ref.rsplit("/", 1)[-1]
    if ":" not in last:
        return ref, UNSPECIFIED, "unpinned", "none"
    name, tag = ref.rsplit(":", 1)
    if tag == "latest":
        return name, tag, "latest", "none"
    if require_digest:
        return name, tag, "digest", "none"
    return name, tag, None, "top-level"


# ---------------------------------------------------------------- command parsing


def _tokenize(line: str) -> list[str] | None:
    """Split a command line into tokens, keeping ``&&``, ``;``, ``|`` and ``(`` as tokens."""
    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:
        return None


def _segments(tokens: Sequence[str]) -> list[list[str]]:
    """Split tokens at separators and drop a leading wrapper or ``NAME=value``."""
    result: list[list[str]] = []
    current: list[str] = []
    for token in [*tokens, ";"]:
        if token == "--" or (token and set(token) <= _PUNCT):
            if current:
                result.append(current)
            current = []
        else:
            current.append(token)
    cleaned = []
    for seg in result:
        while seg and (_ENV_ASSIGN.match(seg[0]) or seg[0] in _WRAPPERS or seg[0] == "$"):
            seg = seg[1:]
        if seg:
            cleaned.append(seg)
    return cleaned


def _run_spec(tokens: Sequence[str], start: int, runner: str) -> tuple[str | None, str | None]:
    """Find the package spec after the runner at ``start``. Returns ``(spec, version_flag)``."""
    flags = _VALUE_FLAGS.get(runner, _VALUE_FLAGS["npx"])
    spec: str | None = None
    version: str | None = None
    first_positional: str | None = None
    j = start + 1
    if runner == "pipx":
        j += 1
    while j < len(tokens):
        tok = tokens[j]
        name, eq, value = tok.partition("=")
        if runner in {"npx", "bunx"} and tok in {"-p", "--package"} and j + 1 < len(tokens):
            return tokens[j + 1], None
        if runner in {"npx", "bunx"} and name == "--package" and eq:
            return value, None
        if runner == "uvx" and name == "--from":
            spec = value if eq else (tokens[j + 1] if j + 1 < len(tokens) else None)
            j += 1 if eq else 2
            continue
        if runner == "pipx" and name == "--spec":
            spec = value if eq else (tokens[j + 1] if j + 1 < len(tokens) else None)
            j += 1 if eq else 2
            continue
        if runner == "dnx" and name == "--version":
            version = value if eq else (tokens[j + 1] if j + 1 < len(tokens) else None)
            j += 1 if eq else 2
            continue
        if tok.startswith("-"):
            j += 1 if eq or tok not in flags else 2
            continue
        if runner != "dnx":
            first_positional = tok
            break
        # dnx: ``dnx <package> [<version>] [--version <v>] [--yes]``; options may follow the package
        if first_positional is None:
            first_positional = tok
        elif version is None and _NUGET_EXACT.match(tok):
            version = tok
        j += 1
    return (spec or first_positional), version


def _component_from_run(
    runner: str,
    spec: str,
    version_flag: str | None,
    path: str,
    line: int,
    kind: str,
    server: str | None,
    index: PackageIndex,
) -> Component | None:
    if runner == "dnx":
        if _is_local_or_placeholder(spec):
            return None
        name, _, at = spec.partition("@")
        judged: tuple[str, str, str | None, str] | None = _judge_nuget(name, version_flag or at or None)
    elif runner in {"uvx", "pipx"}:
        judged = _judge_python(spec)
    else:
        judged = _judge_npm(spec)
        if judged is not None and judged[2] == "unpinned" and judged[1] == UNSPECIFIED and runner in {"npx", "bunx"}:
            declared = index.lookup(path, judged[0])
            if declared is not None:
                judged = (judged[0], declared, None, "dependency-tree")
    if judged is None:
        return None
    name, version, problem, scope = judged
    return Component(kind, name, path, line, runner, version, problem, scope, server)


def _scan_tokens(
    tokens: Sequence[str],
    path: str,
    line: int,
    kind: str,
    server: str | None,
    mcp: bool,
    index: PackageIndex,
    anywhere: bool,
) -> list[Component]:
    """Judge every package runner and ``docker run`` in one command's tokens."""
    found: list[Component] = []
    for i, token in enumerate(tokens):
        if not anywhere and i != 0:
            break
        base = PurePosixPath(token).name
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        comp: Component | None = None
        if base in {"npx", "bunx", "uvx", "dnx"} or (base == "pipx" and nxt == "run"):
            spec, version_flag = _run_spec(tokens, i, base)
            if spec:
                comp = _component_from_run(base, spec, version_flag, path, line, kind, server, index)
        elif base == "docker" and nxt == "run":
            comp = _docker_component(tokens, i, path, line, kind, server, mcp)
        if comp is not None:
            found.append(comp)
    return found


def _docker_component(
    tokens: Sequence[str], start: int, path: str, line: int, kind: str, server: str | None, mcp: bool
) -> Component | None:
    j = start + 2
    while j < len(tokens):
        tok = tokens[j]
        if tok.startswith("-"):
            j += 1 if "=" in tok or tok not in _DOCKER_VALUE_FLAGS else 2
            continue
        judged = _judge_image(tok, require_digest=mcp)
        if judged is None:
            return None
        name, version, problem, scope = judged
        return Component(kind, name, path, line, "docker", version, problem, scope, server)
    return None


_PREFIXES = (
    re.compile(r"^\s*(?:-\s+)?run:\s*[|>]?[-+]?\s*"),
    re.compile(r"^\s*(?:[$>]\s+)"),
    re.compile(r"^\s*-\s+"),
)


def _clean_line(line: str, make_recipe: bool) -> str:
    text = line.strip()
    if make_recipe:
        text = text.lstrip("@+-").strip()
    for prefix in _PREFIXES:
        text = prefix.sub("", text, count=1)
    return text.strip()


def scan_command_line(
    line: str, path: str, lineno: int, kind: str, index: PackageIndex, *, make_recipe: bool = False
) -> list[Component]:
    """Judge one logical command line.

    Args:
        line: The text of the line.
        path: File path, for the result.
        lineno: 1-based line number.
        kind: The inventory kind the result gets.
        index: ``package.json`` declarations for the bin rule.
        make_recipe: True for a Makefile recipe line.

    Returns:
        The components found; empty for a comment, a line that refers to ``~/.kiro``, or no runner.

    Raises:
        Unparseable: The line calls ``add-json`` with an argument that is not valid JSON.
    """
    text = _clean_line(line, make_recipe)
    if not text or text.startswith("#") or _HOME_KIRO.search(text):
        return []
    tokens = _tokenize(text)
    if tokens is None:
        if "add-json" in text:
            raise Unparseable(path, f"line {lineno}: the add-json command line cannot be tokenised")
        tokens = text.split()
    mcp = "mcp" in tokens or "add-json" in tokens
    found: list[Component] = []
    for token in tokens:
        if token.startswith("{") and "add-json" in tokens:
            try:
                spec = json.loads(token)
            except ValueError as exc:
                raise Unparseable(path, f"line {lineno}: the add-json argument is not valid JSON") from exc
            if isinstance(spec, dict):
                found.extend(server_components("add-json", spec, path, lineno, "mcp-server", index))
    for seg in _segments(tokens):
        found.extend(_scan_tokens(seg, path, lineno, kind, None, mcp, index, anywhere=False))
    return found


def server_components(
    name: str, spec: dict[str, Any], path: str, line: int, kind: str, index: PackageIndex
) -> list[Component]:
    """Turn one ``mcpServers`` entry into components.

    Args:
        name: The server's key.
        spec: The entry (``command`` / ``args`` or ``url``).
        path: Source file.
        line: 1-based line of the entry.
        kind: The inventory kind.
        index: ``package.json`` declarations.

    Returns:
        A component per runner found. A ``url`` server gives one with version ``該当なし``.
        An entry that refers to ``~/.kiro`` gives none.
    """
    command = spec.get("command")
    if not isinstance(command, str) or not command:
        if isinstance(spec.get("url"), str) or isinstance(spec.get("serverUrl"), str):
            return [Component(kind, name, path, line, "remote", NOT_APPLICABLE, None, NOT_APPLICABLE, name)]
        return []
    args = spec.get("args", [])
    if isinstance(args, str):
        args = shlex.split(args)
    tokens = [command, *(str(a) for a in args if not isinstance(a, (dict, list)))]
    if any(_HOME_KIRO.search(t) for t in tokens):
        return []
    base = PurePosixPath(command).name
    if base in {"sh", "bash", "zsh"} and "-c" in tokens[1:]:
        script = tokens[tokens.index("-c") + 1] if tokens.index("-c") + 1 < len(tokens) else ""
        inner = scan_command_line(script, path, line, kind, index)
        return [c._replace(server=name) for c in inner]
    found = _scan_tokens(tokens, path, line, kind, name, True, index, anywhere=True)
    if not found:
        return [Component(kind, name, path, line, base, NOT_APPLICABLE, None, NOT_APPLICABLE, name)]
    return found


# ---------------------------------------------------------------- structure extraction


def find_servers(data: Any) -> list[tuple[str, dict[str, Any]]]:
    """Return ``(name, entry)`` for every server table (``mcpServers`` and friends) in ``data``."""
    found: list[tuple[str, dict[str, Any]]] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if key in _SERVER_KEYS and isinstance(value, dict):
                found.extend((str(n), s) for n, s in value.items() if isinstance(s, dict))
            else:
                found.extend(find_servers(value))
    elif isinstance(data, list):
        for item in data:
            found.extend(find_servers(item))
    return found


def _line_of(text: str, needle: str, default: int = 1) -> int:
    pos = text.find(needle)
    return default if pos < 0 else text.count("\n", 0, pos) + 1


def _lenient_json(text: str) -> Any:
    """Parse JSON that may carry ``//`` comment lines and trailing commas."""
    cleaned = "\n".join(ln for ln in text.splitlines() if not ln.strip().startswith("//"))
    cleaned = re.sub(r",(\s*[}\]])", r"\1", cleaned)
    return json.loads(cleaned)


def _servers_from_data(
    data: Any, text: str, path: str, base_line: int, kind: str, index: PackageIndex
) -> list[Component]:
    found: list[Component] = []
    for name, spec in find_servers(data):
        offset = _line_of(text, json.dumps(name), 0) or _line_of(text, f"{name}:", 1)
        line = base_line + offset - 1
        found.extend(server_components(name, spec, path, line, kind, index))
    return found


def _hook_commands(data: Any, skip: set[int]) -> list[str]:
    out: list[str] = []
    if isinstance(data, dict):
        if id(data) in skip:
            return out
        for key, value in data.items():
            if key == "command" and isinstance(value, str):
                out.append(value)
            else:
                out.extend(_hook_commands(value, skip))
    elif isinstance(data, list):
        for item in data:
            out.extend(_hook_commands(item, skip))
    return out


def _logical_lines(lines: Sequence[tuple[int, str]]) -> list[tuple[int, str]]:
    """Join lines that end in a backslash; the line number is the first line's."""
    out: list[tuple[int, str]] = []
    pending: tuple[int, str] | None = None
    for no, text in lines:
        if pending is not None:
            text = pending[1] + " " + text.strip()
            no = pending[0]
            pending = None
        if text.rstrip().endswith("\\"):
            pending = (no, text.rstrip()[:-1])
        else:
            out.append((no, text))
    if pending is not None:
        out.append(pending)
    return out


_IMAGE_KEY = re.compile(r"""^\s*(?:-\s+)?image:\s*["']?([^\s"'#]+)""")
_FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.IGNORECASE)


def _scan_lines(
    lines: Sequence[tuple[int, str]],
    path: str,
    kind: str,
    index: PackageIndex,
    *,
    make: bool,
    yaml_like: bool,
    dockerfile: bool,
) -> list[Component]:
    found: list[Component] = []
    stages: set[str] = set()
    for no, text in _logical_lines(lines):
        if _HOME_KIRO.search(text):
            continue
        if yaml_like:
            match = _IMAGE_KEY.match(text)
            if match:
                judged = _judge_image(match.group(1), require_digest=False)
                if judged:
                    found.append(Component(kind, judged[0], path, no, "image", judged[1], judged[2], judged[3]))
                continue
        if dockerfile:
            match = _FROM.match(text)
            if match:
                ref = match.group(1)
                if ref.lower() != "scratch" and ref not in stages:
                    judged = _judge_image(ref, require_digest=False)
                    if judged:
                        found.append(Component(kind, judged[0], path, no, "from", judged[1], judged[2], judged[3]))
                if match.group(2):
                    stages.add(match.group(2))
                continue
        found.extend(scan_command_line(text, path, no, kind, index, make_recipe=make and text.startswith("\t")))
    return found


def _split_markdown(text: str) -> tuple[str, int, list[tuple[str, int, list[tuple[int, str]]]], list[tuple[int, str]]]:
    """Split Markdown into front matter, fenced blocks and prose lines.

    Returns:
        ``(front matter text, its first line, [(lang, first line, [(no, text)])], prose lines)``.
    """
    lines = text.split("\n")
    front, front_start, start = "", 1, 0
    if lines and lines[0].strip() == "---":
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                front, front_start, start = "\n".join(lines[1:i]), 2, i + 1
                break
    blocks: list[tuple[str, int, list[tuple[int, str]]]] = []
    prose: list[tuple[int, str]] = []
    fence: tuple[str, int] | None = None
    lang, first, body = "", 0, []
    for no in range(start, len(lines)):
        raw = lines[no]
        stripped = raw.strip()
        if fence is None:
            marker = re.match(r"^(`{3,}|~{3,})\s*([\w+-]*)", stripped)
            if marker:
                fence, lang, first, body = (
                    (marker.group(1)[0], len(marker.group(1))),
                    marker.group(2).lower(),
                    no + 1,
                    [],
                )
            else:
                prose.append((no + 1, raw))
        elif stripped.startswith(fence[0] * fence[1]) and not stripped.strip(fence[0]):
            blocks.append((lang, first, body))
            fence = None
        else:
            body.append((no + 1, raw))
    if fence is not None:
        blocks.append((lang, first, body))
    return front, front_start, blocks, prose


def _yaml_or_fail(text: str, path: str, where: str) -> Any:
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise Unparseable(path, f"{where} cannot be parsed as YAML: {type(exc).__name__}") from exc


def _scan_markdown(text: str, path: str, kind: str, index: PackageIndex) -> list[Component]:
    front, front_start, blocks, prose = _split_markdown(text)
    found: list[Component] = []
    if "mcpServers" in front:
        data = _yaml_or_fail(front, path, "the front matter")
        found.extend(_servers_from_data(data, front, path, front_start, "mcp-server", index))
    for lang, first, body in blocks:
        block_text = "\n".join(t for _, t in body)
        if lang in {"json", "jsonc", "json5"}:
            try:
                data = _lenient_json(block_text)
            except ValueError as exc:
                if _JSON_HINT.search(block_text):
                    raise Unparseable(path, f"the {lang} block at line {first} cannot be parsed as JSON") from exc
                continue
            found.extend(_servers_from_data(data, block_text, path, first + 1, "mcp-server", index))
            continue
        if lang in {"yaml", "yml"} and "mcpServers" in block_text:
            data = _yaml_or_fail(block_text, path, f"the yaml block at line {first}")
            found.extend(_servers_from_data(data, block_text, path, first + 1, "mcp-server", index))
        found.extend(
            _scan_lines(
                body,
                path,
                kind,
                index,
                make=False,
                yaml_like=lang in {"yaml", "yml"},
                dockerfile=lang in {"dockerfile", "docker"},
            )
        )
    for no, raw in prose:
        for span in _INLINE_CODE.findall(raw):
            found.extend(scan_command_line(span, path, no, kind, index))
    return found


def _scan_json_agent(text: str, path: str, index: PackageIndex, strict: bool) -> list[Component]:
    try:
        data = _lenient_json(text)
    except ValueError as exc:
        if strict or _JSON_HINT.search(text):
            raise Unparseable(path, "the file cannot be parsed as JSON") from exc
        return []
    servers = find_servers(data)
    found = _servers_from_data(data, text, path, 1, "mcp-server", index)
    for command in _hook_commands(data, {id(s) for _, s in servers}):
        found.extend(
            scan_command_line(command, path, _line_of(text, json.dumps(command)[1:-1][:40]), "agent-config", index)
        )
    return found


def scan_file(path: str, text: str, index: PackageIndex = EMPTY_INDEX) -> list[Component]:
    """Find the components of one tracked file.

    Args:
        path: Path relative to the root, with ``/`` separators.
        text: The file's text.
        index: ``package.json`` declarations.

    Returns:
        The components, judged. Empty for a file that is not a target.

    Raises:
        Unparseable: A structure that must be parsed cannot be.
    """
    name = PurePosixPath(path).name
    suffix = PurePosixPath(path).suffix.lower()
    is_agent = bool(_AGENT_PATH.search(path))
    kind = "agent-config" if is_agent else "install-step"
    if name in MCP_FILE_NAMES:
        return _scan_json_agent(text, path, index, strict=True)
    if suffix in {".json", ".hook"} and is_agent:
        return _scan_json_agent(text, path, index, strict=False)
    if suffix in {".md", ".mdc"}:
        return _scan_markdown(text, path, kind, index)
    is_make = name == "Makefile" or suffix == ".mk"
    if suffix in {".yml", ".yaml"} and "mcpServers" in text:
        data = _yaml_or_fail(text, path, "the file")
        found = _servers_from_data(data, text, path, 1, "mcp-server", index)
        return found + _scan_text(text, path, kind, index, make=False, yaml_like=True)
    if suffix == ".sh" or is_make or suffix in {".yml", ".yaml"}:
        return _scan_text(text, path, kind, index, make=is_make, yaml_like=suffix in {".yml", ".yaml"})
    if is_agent and suffix in {"", ".txt"}:
        return _scan_text(text, path, kind, index, make=False, yaml_like=False)
    return []


def _scan_text(text: str, path: str, kind: str, index: PackageIndex, *, make: bool, yaml_like: bool) -> list[Component]:
    lines = list(enumerate(text.split("\n"), start=1))
    return _scan_lines(lines, path, kind, index, make=make, yaml_like=yaml_like, dockerfile=False)


def is_target(path: str) -> bool:
    """Tell whether a tracked path is one the subcommand reads."""
    name = PurePosixPath(path).name
    suffix = PurePosixPath(path).suffix.lower()
    if name in MCP_FILE_NAMES or suffix in {".md", ".mdc", ".sh", ".mk", ".yml", ".yaml"} or name == "Makefile":
        return True
    return bool(_AGENT_PATH.search(path)) and suffix in {".json", ".hook", "", ".txt"}


# ---------------------------------------------------------------- I/O


def _tracked_files(root: Path) -> list[str]:
    """List the files to read: ``git ls-files`` in a repository, a walk otherwise."""
    if (root / ".git").exists():
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True, timeout=60
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise Unparseable(".", f"git ls-files failed: {type(exc).__name__}") from exc
        names = [n for n in proc.stdout.decode("utf-8", "replace").split("\0") if n]
        names = [n for n in names if not n.startswith(FIXTURE_PREFIX)]
    else:
        names = [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and ".git" not in p.parts]
    return sorted(n for n in names if (root / n).is_file())


def _read(root: Path, rel: str, scanned: int) -> str:
    try:
        return (root / rel).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else type(exc).__name__
        raise Unparseable(rel, f"cannot read the file: {reason}", scanned=scanned) from exc


def build_index(files: Sequence[str], read: Callable[[str], str]) -> PackageIndex:
    """Collect exact-version declarations of tracked ``package.json`` files and their lock files."""
    declared: dict[str, dict[str, str]] = {}
    tracked = set(files)
    locked = set()
    for rel in files:
        if PurePosixPath(rel).name != "package.json":
            continue
        directory = "" if str(PurePosixPath(rel).parent) == "." else str(PurePosixPath(rel).parent)
        try:
            data = json.loads(read(rel))
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        deps: dict[str, str] = {}
        for table in ("dependencies", "devDependencies"):
            entries = data.get(table)
            if isinstance(entries, dict):
                deps.update({k: v for k, v in entries.items() if isinstance(v, str) and _NPM_EXACT.match(v)})
        declared[directory] = deps
        if any((f"{directory}/{lock}" if directory else lock) in tracked for lock in _LOCK_FILES):
            locked.add(directory)
    return PackageIndex(declared, frozenset(locked))


def collect(root: Path) -> tuple[list[Component], int]:
    """Scan the tracked files of ``root``.

    Args:
        root: The repository root, or a fixture directory.

    Returns:
        ``(components sorted by path and line, number of files read)``.

    Raises:
        Unparseable: A file cannot be read or a structure cannot be parsed.
    """
    files = _tracked_files(root)
    cache: dict[str, str] = {}

    def read(rel: str) -> str:
        if rel not in cache:
            cache[rel] = _read(root, rel, 0)
        return cache[rel]

    index = build_index(files, read)
    components: list[Component] = []
    scanned = 0
    for rel in files:
        if not is_target(rel):
            continue
        text = _read(root, rel, scanned)
        scanned += 1
        try:
            components.extend(scan_file(rel, text, index))
        except Unparseable as exc:
            raise Unparseable(exc.path, exc.detail, scanned=scanned) from exc
    components.sort(key=lambda c: (c.path, c.line, c.name))
    return components, scanned


def check(root: Path) -> Report:
    """Run the gate: every unpinned component is a violation.

    Args:
        root: The repository root, or a fixture directory playing its role.

    Returns:
        The report. ``scanned`` counts the target files read.
    """
    components, scanned = collect(root)
    return Report([c.violation() for c in components if c.problem], scanned)


def build_inventory(root: Path, now: datetime | None = None) -> dict[str, Any]:
    """Build the content of ``docs/agent/agent-components.json``.

    Args:
        root: The repository root.
        now: The generation time; the current time when ``None``.

    Returns:
        A JSON-serialisable dict with ``generated_at`` and ``commit_sha``.
    """
    components, scanned = collect(root)
    try:
        sha = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, check=True, text=True, timeout=60
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        sha = "unknown"
    stamp = (now or datetime.now(UTC)).replace(microsecond=0).isoformat()
    return {
        "description": (
            "Generated file. Do not edit by hand. Inventory of MCP servers, agent settings and install steps "
            "that tracked files recommend, with the pinned version of each (Requirement 6). Regenerate with "
            "`python3 scripts/supply_chain_checks/agent_components.py --write`. The gate is "
            "`python3 scripts/check_supply_chain.py agent-components`."
        ),
        "generated_at": stamp,
        "commit_sha": sha,
        "files_scanned": scanned,
        "unpinned_count": sum(1 for c in components if c.problem),
        "components": [{k: v for k, v in c._asdict().items() if v is not None} for c in components],
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Write ``docs/agent/agent-components.json`` (``--write``).

    Args:
        argv: Arguments after the program name.

    Returns:
        0 on success, 2 when an input cannot be read.
    """
    parser = argparse.ArgumentParser(description="Generate the agent component inventory.")
    parser.add_argument("--write", action="store_true", required=True, help="write docs/agent/agent-components.json")
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)
    try:
        inventory = build_inventory(args.root)
    except Unparseable as exc:
        sys.stderr.write(f"{exc.path}: unparseable: {exc.detail}\n")
        return 2
    target = args.root / INVENTORY_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(inventory, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(f"wrote {INVENTORY_PATH}: {len(inventory['components'])} component(s)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
