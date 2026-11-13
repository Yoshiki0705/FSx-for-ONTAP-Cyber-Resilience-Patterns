"""cfn-guard must look at every CloudFormation template that cfn-lint looks at.

The Makefile ``guard`` target loops over ``templates/*.yaml`` and the CI step
passes ``data: 'templates/'``. ``cfn-lint`` is given ``templates/*.yaml`` and
``solutions/*/template.yaml``. A template that only the second list names is
never evaluated against ``security/guard-rules/``, and nothing says so: the
guard target ends each iteration with ``|| true``.

These tests derive every list at run time, from the Makefile, ``ci.yml`` and the
files on disk. No list of templates is written down here.

* The lint scope parsed from the Makefile (two recipes) and from ``ci.yml`` must
  agree, and must not be empty.
* Every CloudFormation template on disk should be inside the lint scope.
* The set of files the guard loop reaches should equal the lint scope.

Two of these fail today and are marked ``xfail(strict=True)``. Strict means a fix
turns them into a hard failure (XPASS), which forces removing the marker.

* ``test_guard_scope_covers_lint_scope``: the Makefile loop is one level only.
  Fixed by task 20.3, which changes the Makefile and ``ci.yml``.
* ``test_every_disk_template_is_in_lint_scope``: a template under
  ``shared/templates/`` is outside the cfn-lint scope as well. Decided at the
  task 20.2 checkpoint.

**Validates: Requirements 24.7, 24.8**
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_YAML_SUFFIXES = (".yaml", ".yml")
# Marks a CloudFormation (or SAM) template: a top-level key, not a mention in prose.
_CFN_MARKER = re.compile(r"^(AWSTemplateFormatVersion|Transform):", re.MULTILINE)
_SKIPPED_DIRS = {"node_modules", "fixtures", "__pycache__"}


def _expand(root: Path, patterns: list[str]) -> set[str]:
    """Expand glob patterns and directories to repository-relative file names.

    A directory pattern (trailing ``/``) means every YAML file below it, which
    is how ``cfn-guard validate --data <dir>`` reads a directory (assumed, see
    the record for task 20.2).
    """
    found: set[str] = set()
    for pattern in patterns:
        if pattern.endswith("/"):
            hits = [p for p in (root / pattern).rglob("*") if p.suffix in _YAML_SUFFIXES]
        else:
            hits = list(root.glob(pattern))
        found.update(p.relative_to(root).as_posix() for p in hits if p.is_file())
    return found


def _recipe(makefile_text: str, target: str) -> list[str]:
    """Return the tab-indented recipe lines of one Makefile target."""
    lines = makefile_text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(f"{target}:"))
    body: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("\t"):
            body.append(line.lstrip("\t"))
        elif line.strip() and not line.startswith("#"):
            break
    return body


def _lint_patterns(command_lines: list[str]) -> list[str]:
    """Return the template patterns passed to ``cfn-lint`` in the given lines."""
    patterns: list[str] = []
    for line in command_lines:
        match = re.search(r"cfn-lint\s+([^|;&]+)", line)
        if match:
            patterns += [t for t in match.group(1).split() if t.endswith(_YAML_SUFFIXES)]
    return patterns


def makefile_lint_patterns(makefile_text: str, target: str) -> list[str]:
    """Patterns the Makefile ``target`` hands to ``cfn-lint``."""
    return _lint_patterns(_recipe(makefile_text, target))


def ci_lint_patterns(ci_text: str) -> list[str]:
    """Patterns the ``run: cfn-lint ...`` step of ``ci.yml`` hands to ``cfn-lint``."""
    return _lint_patterns([line for line in ci_text.splitlines() if re.match(r"\s*run:\s*cfn-lint\s", line)])


def makefile_guard_patterns(makefile_text: str) -> list[str]:
    """Patterns the Makefile ``guard`` loop iterates over (``for x in <patterns>; do``)."""
    patterns: list[str] = []
    for line in _recipe(makefile_text, "guard"):
        match = re.search(r"for\s+\w+\s+in\s+([^;]+);\s*do", line)
        if match:
            patterns += match.group(1).split()
    return patterns


def ci_guard_patterns(ci_text: str) -> list[str]:
    """Paths the CI guard step reads (``data:`` of the cloudformation-guard action)."""
    return re.findall(r"^\s*data:\s*['\"]?([^'\"\s]+)['\"]?\s*$", ci_text, re.MULTILINE)


def disk_cfn_templates(root: Path) -> set[str]:
    """Every CloudFormation template under ``root``, found by content, not by name."""
    found: set[str] = set()
    for path in root.rglob("*"):
        parts = path.relative_to(root).parts
        if any(p.startswith(".") or p in _SKIPPED_DIRS for p in parts[:-1]):
            continue
        if path.is_file() and path.suffix in _YAML_SUFFIXES and _CFN_MARKER.search(path.read_text(encoding="utf-8")):
            found.add(path.relative_to(root).as_posix())
    return found


@pytest.fixture(scope="module")
def makefile_text() -> str:
    """The Makefile as text."""
    return (ROOT / "Makefile").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def ci_text() -> str:
    """The CI workflow as text."""
    return (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def lint_scope(makefile_text: str) -> set[str]:
    """Templates cfn-lint reads through the Makefile ``lint`` target."""
    return _expand(ROOT, makefile_lint_patterns(makefile_text, "lint"))


def test_lint_scope_is_derived_and_non_empty(lint_scope: set[str]) -> None:
    """The lint scope is non-empty and includes a template outside ``templates/``."""
    assert lint_scope, "no template found for the cfn-lint patterns in the Makefile"
    assert any(
        not p.startswith("templates/") for p in lint_scope
    ), "the lint scope has only templates/*.yaml; the solutions/*/template.yaml pattern was not read"


def test_lint_scope_agrees_across_makefile_and_ci(makefile_text: str, ci_text: str) -> None:
    """``make lint``, ``make test`` and the CI cfn-lint step name the same templates."""
    lint = _expand(ROOT, makefile_lint_patterns(makefile_text, "lint"))
    test = _expand(ROOT, makefile_lint_patterns(makefile_text, "test"))
    ci = _expand(ROOT, ci_lint_patterns(ci_text))
    assert lint == test == ci, {"lint": sorted(lint), "test": sorted(test), "ci": sorted(ci)}


@pytest.mark.xfail(
    strict=True,
    reason=(
        "shared/templates/demo-ad-environment.yaml is a CloudFormation template that cfn-lint "
        "is not given (task 20.2 checkpoint: add its pattern to lint, or record why it is excluded)"
    ),
)
def test_every_disk_template_is_in_lint_scope(lint_scope: set[str]) -> None:
    """Every CloudFormation template on disk is inside the cfn-lint scope."""
    missing = disk_cfn_templates(ROOT) - lint_scope
    assert not missing, f"CloudFormation templates cfn-lint does not read: {sorted(missing)}"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "the Makefile guard loop is `templates/*.yaml` only, so solutions/*/template.yaml is "
        "never evaluated (fixed by task 20.3, which changes the Makefile and ci.yml)"
    ),
)
def test_guard_scope_covers_lint_scope(makefile_text: str, lint_scope: set[str]) -> None:
    """The files the Makefile guard loop reaches include every file cfn-lint reads."""
    guard = _expand(ROOT, makefile_guard_patterns(makefile_text))
    assert guard, "no template found for the Makefile guard loop"
    assert guard >= lint_scope, f"cfn-lint reads but guard does not: {sorted(lint_scope - guard)}"


def test_ci_guard_reads_a_directory_that_holds_templates(ci_text: str) -> None:
    """The CI guard step names a data path (guards against the parser matching nothing)."""
    assert ci_guard_patterns(ci_text), "no `data:` input found for the cfn-guard step in ci.yml"


def test_helpers_see_what_they_should(tmp_path: Path) -> None:
    """The helpers tell a one-level loop from a two-level lint list (so the xfail is not vacuous)."""
    (tmp_path / "templates").mkdir()
    (tmp_path / "solutions" / "a").mkdir(parents=True)
    (tmp_path / "templates" / "t.yaml").write_text("AWSTemplateFormatVersion: x\n", encoding="utf-8")
    (tmp_path / "solutions" / "a" / "template.yaml").write_text(
        "Transform: AWS::Serverless-2016-10-31\n", encoding="utf-8"
    )
    (tmp_path / "solutions" / "a" / "other.yaml").write_text("key: value\n", encoding="utf-8")
    makefile = (
        "lint:\n\t$(VENV)/cfn-lint templates/*.yaml solutions/*/template.yaml || test $$? -le 12\n\n"
        "guard:\n\t@for t in templates/*.yaml; do \\\n\t\techo $$t; \\\n\tdone\n"
    )
    lint = _expand(tmp_path, makefile_lint_patterns(makefile, "lint"))
    guard = _expand(tmp_path, makefile_guard_patterns(makefile))
    assert lint == {"templates/t.yaml", "solutions/a/template.yaml"}
    assert guard == {"templates/t.yaml"}
    assert disk_cfn_templates(tmp_path) == lint
