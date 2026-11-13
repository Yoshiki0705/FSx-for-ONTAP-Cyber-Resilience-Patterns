"""``pinning`` subcommand: exact pins for production dependencies, Actions, tools and images.

Requirement 13 (and 16.2, 16.6). The check reads files only; it never touches the network
(whether a pinned SHA exists on GitHub is a separate target, task 11.14).

What it checks, per finding kind:

* ``range``: a production dependency whose spec is not a single exact version. Python needs
  ``==X.Y.Z`` (``===``, wildcards, ``>=``, ``~=``, a bare name are all ranges); npm needs an
  exact version with no operator, ``latest``, ``x`` component, ``||`` or `` - `` range.
* ``undeterminable``: ``file:``, ``git+``, URL and path specs. They have no version string, so
  they count as failures (design section 9).
* ``unpinned-action``: a third-party ``uses:`` that is not a 40-character commit SHA.
* ``unpinned-reusable``: a Hub Reusable_Workflow reference; see ``HUB_SHA_REQUIRED``.
* ``unpinned-image``: ``docker://``, ``image:`` and ``docker run`` images without ``@sha256:``.
* ``unpinned-tool``: a supply-chain tool (``TOOLS``) installed at ``latest``/a branch/no version.
* ``mismatch``: one dependency declared with different version strings in files that are
  installed together (the same directory, or linked by ``-r``). Lambdas deployed separately
  live in different directories and are not compared (Requirement 13.4).

Production scope (design section 9): ``requirements*.txt`` (not ``-dev``/``-test``) with the
files it includes through ``-r``, ``[project].dependencies`` of ``pyproject.toml``, and
``dependencies`` of ``package.json``. A file with a directory component listed in the
Policy_File's ``dependency_scope.non_production_paths`` (for example ``tests/``) is not
production. Each entry matches as a run of directory components at any depth, so
``tests/`` also covers ``shared/tests/``. ``requirements-dev.txt`` is therefore never checked
for ranges (``pydot>=2.0.0`` is not a finding).

Optional criteria (Requirement 13.9: hash-checked installs, lockfile installs, npm
``strict-allow-scripts`` and ``allowScripts``, pnpm ``blockExoticSubdeps``) are reported as
warnings through :func:`optional_findings` and the module logger. They never change the exit
code.

Not covered, on purpose: .NET, Terraform and Dockerfile ``FROM`` digests (Requirement 13.1,
candidates for a second stage); tools other than ``TOOLS``.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import tomllib
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import NamedTuple

from supply_chain_checks._common import Report, Unparseable, Violation, use_supply_chain_package

POLICY_PATH = "docs/agent/supply-chain-policy.json"

#: The Hub repository whose Reusable_Workflows the Spokes call (design D-9).
HUB_REPOSITORY = "yoshiki0705/fsx-for-ontap-adoption-playbook"

#: Requirement 16.9 / Q-16. ``False`` until the pilot (task 19.3) has shown that a SHA
#: reference to the Hub resolves; then change it to ``True``. While ``False``, a Hub
#: Reusable_Workflow may be referenced by tag. A branch name or no ref still fails.
HUB_SHA_REQUIRED = False

#: Tools of Requirement 13.3 (SBOM_Generator and Aggregator).
TOOLS = ("syft", "trivy", "osv-scanner", "grype")

_SKIP_DIRS_PREFIX = "."
_SKIP_DIRS = frozenset({"node_modules", "__pycache__", "cdk.out", "venv", "site-packages"})
_BRANCH_REFS = frozenset({"main", "master", "head", "develop", "trunk"})
_SHA40 = re.compile(r"^[0-9a-fA-F]{40}$")
_DIGEST = re.compile(r"@sha256:[0-9a-fA-F]{64}\b")
_PY_EXACT = re.compile(r"^==\s*([0-9][0-9A-Za-z.!+_-]*)$")
_NPM_EXACT = re.compile(r"^v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_NPM_OPAQUE = ("file:", "git+", "git:", "git@", "github:", "http:", "https:", "link:", "workspace:", "npm:", "portal:")
_PY_OPAQUE = ("@", "git+", "http:", "https:", "file:", "./", "../", "/", "svn+", "hg+", "bzr+")
_USES = re.compile(r"^\s*(?:-\s+)?uses:\s*['\"]?([^\s'\"#]+)")
_IMAGE_KEY = re.compile(r"^\s*(?:-\s+)?image:\s*['\"]?([^\s'\"#]+)")
_DOCKER_RUN = re.compile(r"\bdocker\s+(?:container\s+)?run\b(.*)")
_TOOL_WORD = re.compile(r"(?<![\w.-])(" + "|".join(re.escape(t) for t in TOOLS) + r")(?!\w)", re.IGNORECASE)
_TOOL_UNPINNED = re.compile(r"(@latest\b|@main\b|@master\b|:latest\b|[=\s]latest\b)", re.IGNORECASE)
_PIP_TOOL = re.compile(r"\bpip3?\s+install\b[^\n]*?\b(" + "|".join(re.escape(t) for t in TOOLS) + r")\b(?!==)", re.I)
_DOCKER_VALUE_FLAGS = frozenset(
    "-e -v -p -w -u -l -h -m --name --env --volume --publish --workdir --user --entrypoint --network "
    "--label --platform --mount --env-file --cidfile --hostname --add-host --memory --cpus --pull "
    "--restart --cap-add --cap-drop --device --group-add --log-driver --security-opt".split()
)
_PIP_SKIP_OPTIONS = ("-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--trusted-host", "--no-binary")
_LOG = logging.getLogger(__name__)


class Decl(NamedTuple):
    """One production dependency declaration."""

    ecosystem: str  # "py" or "npm"
    name: str
    spec: str
    path: str
    line: int


def _norm(name: str, ecosystem: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "py" else name


def _classify_py(spec: str) -> str | None:
    """Return ``None`` for an exact pin, else the finding kind."""
    if spec.startswith(_PY_OPAQUE):
        return "undeterminable"
    return None if _PY_EXACT.match(spec) else "range"


def _classify_npm(spec: str) -> str | None:
    """Return ``None`` for an exact pin, else the finding kind."""
    if spec.startswith(_NPM_OPAQUE) or spec.startswith(("./", "../", "/", "~/")):
        return "undeterminable"
    return None if _NPM_EXACT.match(spec) else "range"


def _read(root: Path, rel: str, scanned: int) -> str:
    try:
        return (root / rel).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else type(exc).__name__
        raise Unparseable(rel, f"cannot read the file: {reason}", scanned=scanned) from exc


def _scope(root: Path) -> tuple[tuple[tuple[str, ...], ...], frozenset[str]]:
    """Read the non-production paths and the owners of the target repositories."""
    owners = {HUB_REPOSITORY.split("/")[0]}
    target = root / POLICY_PATH
    if not target.is_file():
        return (), frozenset(owners)
    use_supply_chain_package()
    from supply_chain.policy import PolicyError, parse_policy  # noqa: PLC0415

    text = _read(root, POLICY_PATH, 0)
    try:
        policy = parse_policy(text)
    except PolicyError:
        # The ``policy`` subcommand reports the defect (exit 1); do not turn it into exit 2 here.
        _LOG.warning(
            "%s is invalid; no path is excluded from the pinning check (see the policy subcommand)", POLICY_PATH
        )
        return (), frozenset(owners)
    owners |= {repo.owner.lower() for repo in policy.target_repositories}
    paths = tuple(tuple(p for p in PurePosixPath(raw).parts if p != "/") for raw in policy.non_production_paths)
    return paths, frozenset(owners)


def _in_non_production(rel: str, patterns: tuple[tuple[str, ...], ...]) -> bool:
    dirs = PurePosixPath(rel).parts[:-1]
    for pattern in patterns:
        n = len(pattern)
        if n and any(dirs[i : i + n] == pattern for i in range(len(dirs) - n + 1)):
            return True
    return False


def _walk(root: Path) -> list[str]:
    found: list[str] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(
            d for d in dirs if (not d.startswith(_SKIP_DIRS_PREFIX) or d == ".github") and d not in _SKIP_DIRS
        )
        base = Path(current).relative_to(root)
        found.extend((base / f).as_posix() for f in sorted(files))
    return found


def _is_production_name(rel: str) -> str | None:
    """Return the ecosystem file kind for a manifest name, or ``None``."""
    name = PurePosixPath(rel).name
    if name == "package.json":
        return "package.json"
    if name == "pyproject.toml":
        return "pyproject.toml"
    if re.fullmatch(r"requirements[^/]*\.txt", name) and not re.search(r"dev|test", name, re.IGNORECASE):
        return "requirements"
    return None


# --- manifests ----------------------------------------------------------------------------


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join ``\\`` continuations and drop comments; return ``(first line number, text)``."""
    out: list[tuple[int, str]] = []
    pending: str | None = None
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        line = re.sub(r"(^|\s)#.*$", "", raw).rstrip()
        if pending is None:
            start = number
            pending = ""
        cont = line.endswith("\\")
        pending += (line[:-1] if cont else line) + " "
        if not cont:
            if pending.strip():
                out.append((start, pending.strip()))
            pending = None
    if pending and pending.strip():
        out.append((start, pending.strip()))
    return out


_REQ = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?P<rest>.*)$")


def _parse_requirement(entry: str) -> tuple[str, str] | None:
    """Split a requirement into ``(name, spec)``; ``None`` when it has no name."""
    entry = re.sub(r"\s--hash=\S+", "", entry)
    entry = entry.split(";", 1)[0].strip()
    if entry.startswith(_PY_OPAQUE):
        return entry.split("#egg=")[-1] if "#egg=" in entry else entry, entry
    match = _REQ.match(entry)
    if match is None:
        return None
    rest = match.group("rest").strip()
    if rest.startswith("@"):
        return match.group("name"), rest[1:].strip() or "@"
    return match.group("name"), rest.replace(" ", "")


def _requirements(
    root: Path, rel: str, seen: dict[str, None], decls: list[Decl], links: list[tuple[str, str]], odd: list[Violation]
) -> None:
    """Collect declarations of one requirements file and, recursively, of its ``-r`` targets."""
    if rel in seen:
        return
    seen[rel] = None
    text = _read(root, rel, len(seen) - 1)
    for line, entry in _logical_lines(text):
        if entry.startswith(("-r", "--requirement")):
            target = re.sub(r"^(-r|--requirement)[\s=]*", "", entry).strip()
            joined = os.path.normpath(str(PurePosixPath(rel).parent / target)).replace(os.sep, "/")
            if joined.startswith("..") or os.path.isabs(joined):
                raise Unparseable(rel, f"line {line}: -r target leaves the repository", scanned=len(seen))
            links.append((rel, joined))
            _requirements(root, joined, seen, decls, links, odd)
            continue
        if entry.startswith(("-e", "--editable")):
            odd.append(Violation(rel, line, "undeterminable", f"editable install `{entry}` has no version"))
            continue
        if entry.startswith("-"):
            continue
        parsed = _parse_requirement(entry)
        if parsed is None:
            odd.append(Violation(rel, line, "undeterminable", f"`{entry}` is not a requirement with a name"))
            continue
        decls.append(Decl("py", parsed[0], parsed[1], rel, line))


def _pyproject(root: Path, rel: str, scanned: int, decls: list[Decl]) -> None:
    text = _read(root, rel, scanned)
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise Unparseable(rel, f"not valid TOML: {exc}", scanned=scanned + 1) from exc
    project = data.get("project")
    deps = project.get("dependencies", []) if isinstance(project, dict) else []
    lines = text.splitlines()
    start = next((i for i, ln in enumerate(lines) if re.match(r"\s*dependencies\s*=", ln)), 0)
    for dep in deps if isinstance(deps, list) else []:
        if not isinstance(dep, str):
            continue
        parsed = _parse_requirement(dep)
        if parsed is None:
            continue
        line = next((i + 1 for i in range(start, len(lines)) if dep in lines[i]), start + 1)
        decls.append(Decl("py", parsed[0], parsed[1], rel, line))


def _package_json(root: Path, rel: str, scanned: int, decls: list[Decl]) -> None:
    text = _read(root, rel, scanned)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise Unparseable(rel, f"not valid JSON: {exc.msg} (line {exc.lineno})", scanned=scanned + 1) from exc
    deps = data.get("dependencies", {}) if isinstance(data, dict) else {}
    lines = text.splitlines()
    for name, spec in deps.items() if isinstance(deps, dict) else []:
        line = next((i + 1 for i, ln in enumerate(lines) if f'"{name}"' in ln), 1)
        decls.append(Decl("npm", name, spec if isinstance(spec, str) else repr(spec), rel, line))


def _collect(root: Path, files: list[str], patterns: tuple[tuple[str, ...], ...]):
    """Return ``(declarations, extra violations, links, files read)`` for production manifests."""
    seen: dict[str, None] = {}
    decls: list[Decl] = []
    links: list[tuple[str, str]] = []
    odd: list[Violation] = []
    for rel in files:
        kind = _is_production_name(rel)
        if kind is None or _in_non_production(rel, patterns):
            continue
        if kind == "requirements":
            _requirements(root, rel, seen, decls, links, odd)
        elif rel not in seen:
            seen[rel] = None
            if kind == "pyproject.toml":
                _pyproject(root, rel, len(seen) - 1, decls)
            else:
                _package_json(root, rel, len(seen) - 1, decls)
    return decls, odd, links, list(seen)


def _range_violations(decls: list[Decl]) -> list[Violation]:
    out: list[Violation] = []
    for d in decls:
        kind = (_classify_py if d.ecosystem == "py" else _classify_npm)(d.spec)
        if kind is not None:
            shown = d.spec or "(no version)"
            out.append(Violation(d.path, d.line, kind, f"{d.name}: `{shown}` is not an exact version"))
    return out


def _mismatch_violations(decls: list[Decl], links: list[tuple[str, str]]) -> list[Violation]:
    """Compare version strings of one dependency across files installed together."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        parent[find(a)] = find(b)

    by_dir: dict[tuple[str, str], str] = {}
    for d in decls:
        key = (d.ecosystem, str(PurePosixPath(d.path).parent))
        union(d.path, by_dir.setdefault(key, d.path))
    for a, b in links:
        union(a, b)
    groups: dict[tuple[str, str, str], list[Decl]] = defaultdict(list)
    for d in decls:
        if d.spec.startswith(_PY_OPAQUE + _NPM_OPAQUE):
            continue
        groups[(find(d.path), d.ecosystem, _norm(d.name, d.ecosystem))].append(d)
    out: list[Violation] = []
    for (_, _eco, name), members in sorted(groups.items()):
        versions = {_PY_EXACT.sub(r"\1", m.spec) if m.ecosystem == "py" else m.spec for m in members}
        if len(versions) > 1:
            first = min(members, key=lambda m: (m.path, m.line))
            where = ", ".join(
                f"{m.path}:{m.line} `{m.spec or '(none)'}`" for m in sorted(members, key=lambda m: (m.path, m.line))
            )
            out.append(Violation(first.path, first.line, "mismatch", f"{name} is declared differently: {where}"))
    return out


# --- workflows ----------------------------------------------------------------------------


def _image_violation(ref: str, rel: str, line: int, where: str) -> Violation | None:
    if "${{" in ref or ref.startswith("$"):
        return Violation(rel, line, "undeterminable", f"{where} `{ref}` is built at run time; pin it by digest")
    if _DIGEST.search(ref):
        return None
    return Violation(rel, line, "unpinned-image", f"{where} `{ref}` has no @sha256: digest")


def _docker_run_image(rest: str) -> str | None:
    try:
        tokens = shlex.split(rest, comments=True)
    except ValueError:
        tokens = rest.split()
    skip = False
    for token in tokens:
        if skip:
            skip = False
        elif token in _DOCKER_VALUE_FLAGS:
            skip = True
        elif not token.startswith("-"):
            return token
    return None


def _uses_violation(ref: str, rel: str, line: int, owners: frozenset[str], hub_sha: bool) -> Violation | None:
    if ref.startswith("./"):
        return None
    if ref.startswith("docker://"):
        return _image_violation(ref.removeprefix("docker://"), rel, line, "container image")
    target, _, version = ref.partition("@")
    owner = target.split("/", 1)[0].lower()
    repo = "/".join(target.split("/")[:2]).lower()
    if repo == HUB_REPOSITORY:
        if _SHA40.match(version) or (not hub_sha and version and version.lower() not in _BRANCH_REFS):
            return None
        need = "a 40-character SHA" if hub_sha else "a tag or a 40-character SHA"
        return Violation(rel, line, "unpinned-reusable", f"`{ref}`: the Hub Reusable_Workflow needs {need}")
    if owner in owners:
        return None
    if _SHA40.match(version):
        return None
    shown = ref if version else f"{ref} (no ref)"
    return Violation(rel, line, "unpinned-action", f"`{shown}` is not a 40-character commit SHA")


def _workflow(rel: str, text: str, owners: frozenset[str], hub_sha: bool) -> list[Violation]:
    out: list[Violation] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = re.sub(r"(^|\s)#.*$", "", raw)
        if not line.strip():
            continue
        found: Violation | None = None
        image_line = False
        if m := _USES.match(line):
            found = _uses_violation(m.group(1), rel, number, owners, hub_sha)
            image_line = m.group(1).startswith("docker://")
        elif m := _IMAGE_KEY.match(line):
            image_line = True
            found = _image_violation(m.group(1), rel, number, "container image")
        elif m := _DOCKER_RUN.search(line):
            image_line = True
            image = _docker_run_image(m.group(1))
            if image is not None:
                found = _image_violation(image, rel, number, "container image")
        if found is not None:
            out.append(found)
        if image_line or _USES.match(line):
            continue
        tool = _TOOL_WORD.search(line)
        if tool and (_TOOL_UNPINNED.search(line) or _PIP_TOOL.search(line)):
            out.append(
                Violation(rel, number, "unpinned-tool", f"{tool.group(1)} is not at an exact version: `{line.strip()}`")
            )
    return out


# --- optional criteria (Requirement 13.9) -------------------------------------------------


def optional_findings(root: Path) -> list[Violation]:
    """List the optional-criterion findings of Requirement 13.9 (never a failure).

    Checks hash-checked installs (``--hash`` entries, ``--require-hashes``), lockfile
    installs (``npm ci``), npm ``strict-allow-scripts=true`` and ``allowScripts``, and pnpm
    ``blockExoticSubdeps``. Whether to make them mandatory is decided after the pilot
    (task 19.3) from the count this returns.

    Args:
        root: The repository root.

    Returns:
        One entry per finding; empty when every optional criterion holds or does not apply.
    """
    patterns, _ = _scope(root)
    files = _walk(root)
    workflows = [f for f in files if re.fullmatch(r"\.github/workflows/[^/]+\.ya?ml", f)]
    wf_text = "\n".join(_read(root, f, 0) for f in workflows)
    found: list[Violation] = []
    for rel in files:
        kind = _is_production_name(rel)
        if kind is None or _in_non_production(rel, patterns):
            continue
        folder = PurePosixPath(rel).parent
        siblings = {PurePosixPath(f).name for f in files if PurePosixPath(f).parent == folder}
        if kind == "requirements":
            text = _read(root, rel, 0)
            entries = [(n, e) for n, e in _logical_lines(text) if not e.startswith("-")]
            if entries and not all("--hash=" in e for _, e in entries):
                found.append(
                    Violation(rel, entries[0][0], "no-hashes", "entries without --hash= (use --require-hashes)")
                )
        elif kind == "package.json":
            has_lock = bool(siblings & {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "npm-shrinkwrap.json"})
            if not has_lock:
                continue  # 13.9 applies only where a lockfile exists
            npmrc = _read(root, str(folder / ".npmrc"), 0) if ".npmrc" in siblings else ""
            if not re.search(r"^\s*strict-allow-scripts\s*=\s*true\b", npmrc, re.MULTILINE):
                found.append(
                    Violation(rel, 1, "no-strict-allow-scripts", "strict-allow-scripts=true is not set in .npmrc")
                )
            if "allowScripts" not in _read(root, rel, 0):
                found.append(Violation(rel, 1, "no-allow-scripts", "no allowScripts allow-list in package.json"))
            if "pnpm-lock.yaml" in siblings and "blockExoticSubdeps" not in npmrc + _read_if(root, folder, siblings):
                found.append(Violation(rel, 1, "no-block-exotic-subdeps", "pnpm blockExoticSubdeps is not set"))
    if re.search(r"\bnpm\s+(install|i)\b", wf_text) and not re.search(r"\bnpm\s+ci\b", wf_text):
        found.append(
            Violation(".github/workflows", 1, "no-lockfile-install", "npm install is used where npm ci is expected")
        )
    if re.search(r"\bpip3?\s+install\b[^\n]*-r\b", wf_text) and "--require-hashes" not in wf_text:
        found.append(Violation(".github/workflows", 1, "no-require-hashes", "pip install -r without --require-hashes"))
    return found


def _read_if(root: Path, folder: PurePosixPath, siblings: set[str]) -> str:
    name = "pnpm-workspace.yaml"
    return _read(root, str(folder / name), 0) if name in siblings else ""


# --- entry --------------------------------------------------------------------------------


def check(root: Path, *, hub_sha_required: bool | None = None) -> Report:
    """Check the pins of the repository under ``root``.

    Args:
        root: The repository root, or a directory that plays its role.
        hub_sha_required: Whether a Hub Reusable_Workflow must be a 40-character SHA.
            ``None`` uses :data:`HUB_SHA_REQUIRED`.

    Returns:
        A report with every finding (the check does not stop at the first) and the number of
        files read.

    Raises:
        Unparseable: A manifest, workflow or the Policy_File cannot be read or decoded.
    """
    hub_sha = HUB_SHA_REQUIRED if hub_sha_required is None else hub_sha_required
    patterns, owners = _scope(root)
    files = _walk(root)
    decls, violations, links, read = _collect(root, files, patterns)
    violations += _range_violations(decls)
    violations += _mismatch_violations(decls, links)
    scanned = len(read)
    for rel in (f for f in files if re.fullmatch(r"\.github/workflows/[^/]+\.ya?ml", f)):
        text = _read(root, rel, scanned)
        scanned += 1
        violations += _workflow(rel, text, owners, hub_sha)
    unique = {(v.path, v.line, v.kind, v.detail): v for v in violations}
    ordered = sorted(unique.values(), key=lambda v: (v.path, v.line, v.kind))
    try:
        warnings = optional_findings(root)
    except Unparseable:
        warnings = []
    for w in warnings:
        _LOG.warning("optional (13.9) %s", w.format())
    if warnings:
        _LOG.warning("pinning: %d optional (13.9) finding(s); they do not change the exit code", len(warnings))
    return Report(violations=ordered, scanned=scanned)
