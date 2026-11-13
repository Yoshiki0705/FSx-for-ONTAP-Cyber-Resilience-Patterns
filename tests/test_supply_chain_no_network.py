"""The supply-chain pure core must not import network or cloud modules."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKAGE_DIR = Path(__file__).parent.parent / "solutions" / "supply-chain" / "supply_chain"
FORBIDDEN = frozenset({"urllib", "http", "socket", "requests", "boto3"})


def forbidden_imports(source: str) -> list[str]:
    """Returns forbidden top-level module names imported by ``source``.

    Args:
        source: Python source text.

    Returns:
        Sorted names from ``FORBIDDEN`` that the source imports, including
        imports inside functions and ``from x.y import z`` forms.
    """
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module]
        else:
            continue
        found.update(n.split(".")[0] for n in names if n.split(".")[0] in FORBIDDEN)
    return sorted(found)


def package_modules(package_dir: Path) -> list[Path]:
    """Lists ``*.py`` files under ``package_dir`` at run time."""
    return sorted(package_dir.rglob("*.py"))


def test_package_modules_are_found() -> None:
    """The scan must see at least one module, or it checks nothing."""
    assert package_modules(PACKAGE_DIR), f"no modules under {PACKAGE_DIR}"


def test_no_module_imports_network_or_cloud_clients() -> None:
    """No module of the package imports a forbidden module."""
    modules = package_modules(PACKAGE_DIR)
    assert modules
    violations = {
        str(path.relative_to(PACKAGE_DIR)): bad
        for path in modules
        if (bad := forbidden_imports(path.read_text(encoding="utf-8")))
    }
    assert violations == {}


@pytest.mark.parametrize("name", sorted(FORBIDDEN))
@pytest.mark.parametrize(
    "template",
    ["import {n}", "import {n}.sub", "from {n} import x", "from {n}.sub import x"],
)
def test_detector_catches_each_form(name: str, template: str) -> None:
    """The detector fails on every forbidden module and import form."""
    assert forbidden_imports(template.format(n=name)) == [name]


def test_detector_catches_import_inside_function() -> None:
    """A function-level import is still reported."""
    assert forbidden_imports("def f():\n    import socket\n") == ["socket"]


def test_detector_ignores_allowed_and_relative_imports() -> None:
    """Allowed modules and relative imports are not reported."""
    assert forbidden_imports("import json\nfrom . import models\n") == []


def test_scan_fails_on_temporary_bad_module(tmp_path: Path) -> None:
    """A temporary package with a bad module is reported; an empty one is empty."""
    (tmp_path / "ok.py").write_text("import json\n", encoding="utf-8")
    (tmp_path / "bad.py").write_text("import socket\n", encoding="utf-8")
    mods = package_modules(tmp_path)
    assert [p.name for p in mods] == ["bad.py", "ok.py"]
    bad = [p.name for p in mods if forbidden_imports(p.read_text(encoding="utf-8"))]
    assert bad == ["bad.py"]
    empty = tmp_path / "empty"
    empty.mkdir()
    assert package_modules(empty) == []
