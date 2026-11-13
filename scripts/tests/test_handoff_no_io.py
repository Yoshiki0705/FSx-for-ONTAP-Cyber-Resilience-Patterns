"""The Handoff_Harness pure core must not import a process or network module.

Requirement 28.24 puts the harness logic under pytest tests that do not use the network,
and design section 20 splits ``scripts/handoff/`` into a pure core and an I/O layer: only
``runner.py`` and ``cli.py`` may start processes or open connections. This file holds
that line for imports. Every other module of the package is parsed with ``ast``, and an
import whose first name is ``subprocess``, ``socket``, ``urllib``, ``http`` or
``requests`` is a violation, in each of the forms ``import x``, ``import x.y``,
``from x import y`` and ``from x.y import z``, at module level or inside a function.

The modules are listed from the directory at run time, recursively, so a new module is
checked without editing this file, and ``__init__.py`` counts as a module. An empty list
raises instead of returning no violations: a check that examined nothing must not read
as a clean package. The check is shown to catch each form by copying the real package
into a temporary directory, adding one forbidden import, and running the same function
on the copy.

Not detected here, and left to review: an import through ``importlib.import_module`` or
``__import__``; process creation through ``os`` (``os.system``, ``os.popen``, the
``exec*`` and ``spawn*`` functions); other network modules (``urllib3``, ``httpx``,
``ssl``, ``ftplib``); file reads and writes; and a forbidden module reached through
another import, such as a pure-core module importing ``handoff.runner``, or importing
``check_sensitive_patterns``, which imports ``subprocess`` itself.
"""

from __future__ import annotations

import ast
import shutil
from pathlib import Path
from typing import NamedTuple

import pytest

HANDOFF_DIR = Path(__file__).resolve().parents[1] / "handoff"

#: First names of the modules whose import counts as process or network I/O.
IO_MODULES = frozenset({"subprocess", "socket", "urllib", "http", "requests"})

#: The I/O layer, as POSIX paths relative to the package directory. A module with one of
#: these file names in a subdirectory is part of the pure core.
IO_LAYER = frozenset({"runner.py", "cli.py"})


class Violation(NamedTuple):
    """One import of an I/O module in the pure core.

    Attributes:
        module: POSIX path of the module, relative to the package directory.
        line: Line number of the import statement.
        imported: The dotted module name as written, for example ``urllib.request``.
    """

    module: str
    line: int
    imported: str


def pure_core_modules(package_dir: Path) -> list[Path]:
    """List the modules of a package that must not import an I/O module.

    Args:
        package_dir: Package directory, searched recursively.

    Returns:
        Every ``*.py`` file under ``package_dir`` except the I/O layer, sorted.
    """
    return sorted(
        path for path in package_dir.rglob("*.py") if path.relative_to(package_dir).as_posix() not in IO_LAYER
    )


def imported_modules(path: Path) -> list[tuple[int, str]]:
    """List the absolute imports of one module, wherever they appear in it.

    Args:
        path: The module file.

    Returns:
        ``(line, dotted name)`` for each name in an ``import`` statement and for the
        module of each ``from`` import, sorted. Relative imports (``from . import x``,
        ``from .x import y``) name a module of the same package and are not listed.
    """
    found: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
        if isinstance(node, ast.Import):
            found.extend((node.lineno, alias.name) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module is not None:
            found.append((node.lineno, node.module))
    return sorted(found)


def forbidden_imports(package_dir: Path) -> list[Violation]:
    """Find every import of an I/O module in the pure core of a package.

    Args:
        package_dir: The real package directory or a copy of it.

    Returns:
        The violations, ordered by module and line. An empty list means that at least
        one module was parsed and none of them imports an I/O module.

    Raises:
        ValueError: The directory holds no pure-core module, so nothing was checked.
    """
    modules = pure_core_modules(package_dir)
    if not modules:
        raise ValueError(f"no pure-core module under {package_dir}; checking nothing is not a pass")
    violations: list[Violation] = []
    for path in modules:
        relative = path.relative_to(package_dir).as_posix()
        for line, name in imported_modules(path):
            if name.split(".", 1)[0] in IO_MODULES:
                violations.append(Violation(relative, line, name))
    return violations


def _copy_package(tmp_path: Path) -> Path:
    """Copy the real package into a temporary directory, without bytecode caches.

    Args:
        tmp_path: Temporary directory of the test.

    Returns:
        The package directory of the copy.
    """
    copy = tmp_path / "handoff"
    shutil.copytree(HANDOFF_DIR, copy, ignore=shutil.ignore_patterns("__pycache__"))
    return copy


def _append(path: Path, text: str) -> int:
    """Append lines to a module of the copy.

    Args:
        path: The module file.
        text: Lines to add, without the final newline.

    Returns:
        The line number of the first added line.
    """
    source = path.read_text(encoding="utf-8")
    if source and not source.endswith("\n"):
        source += "\n"
    path.write_text(source + text + "\n", encoding="utf-8")
    return source.count("\n") + 1


def test_the_package_is_importable_by_name() -> None:
    """``conftest.py`` puts ``scripts/`` on ``sys.path``; ``handoff`` must resolve to this package."""
    import handoff

    assert Path(handoff.__file__).resolve() == HANDOFF_DIR / "__init__.py"


def test_the_pure_core_imports_no_io_module() -> None:
    """The rule, on the real package. Finding no module raises, so it cannot pass vacuously."""
    assert forbidden_imports(HANDOFF_DIR) == []


FORBIDDEN = [
    case
    for module in sorted(IO_MODULES)
    for case in (
        (f"import {module}", module),
        (f"import {module}.sub", f"{module}.sub"),
        (f"from {module} import name", module),
        (f"from {module}.sub import name", f"{module}.sub"),
    )
]


@pytest.mark.parametrize(("statement", "imported"), FORBIDDEN, ids=[statement for statement, _ in FORBIDDEN])
def test_one_forbidden_import_in_a_copy_is_reported(tmp_path: Path, statement: str, imported: str) -> None:
    """Each of the four forms, for each of the five modules, is reported at its line.

    The copy is only parsed, never imported, so the module names need not exist.
    """
    copy = _copy_package(tmp_path)
    assert forbidden_imports(copy) == []  # the copy starts as clean as the real package

    line = _append(copy / "__init__.py", statement)

    assert forbidden_imports(copy) == [Violation("__init__.py", line, imported)]


def test_an_import_inside_a_function_is_reported(tmp_path: Path) -> None:
    """A lazy import, a form this repository already uses for boto3, is still found."""
    copy = _copy_package(tmp_path)

    line = _append(copy / "__init__.py", "def _probe() -> None:\n    import subprocess")

    assert forbidden_imports(copy) == [Violation("__init__.py", line + 1, "subprocess")]


def test_only_the_io_layer_at_the_package_root_is_exempt(tmp_path: Path) -> None:
    """``runner.py`` and ``cli.py`` may import subprocess; the same file name one level down may not."""
    copy = _copy_package(tmp_path)
    for relative in ("runner.py", "cli.py", "nested/runner.py"):
        target = copy / relative
        target.parent.mkdir(exist_ok=True)
        target.write_text("import subprocess\n", encoding="utf-8")

    assert forbidden_imports(copy) == [Violation("nested/runner.py", 1, "subprocess")]


@pytest.mark.parametrize("files", [(), ("runner.py", "cli.py")], ids=["empty", "io-layer-only"])
def test_a_package_without_a_pure_core_module_raises(tmp_path: Path, files: tuple[str, ...]) -> None:
    """Zero modules found stops the check instead of returning an empty list of violations."""
    for name in files:
        (tmp_path / name).write_text("import subprocess\n", encoding="utf-8")

    with pytest.raises(ValueError, match="no pure-core module"):
        forbidden_imports(tmp_path)
