"""Shared types of the supply-chain gate subcommands.

A subcommand is a module ``scripts/supply_chain_checks/<name>.py`` (``_`` in the file name
becomes ``-`` in the subcommand name) that defines ``check(root: Path) -> Report``. The entry
point ``scripts/check_supply_chain.py`` finds the modules at run time, so adding a
subcommand adds a file and edits nothing else.

``check`` reads files under ``root`` (the repository root, or a fixture directory that plays
its role) and returns a :class:`Report`. It raises :class:`Unparseable` when it cannot read
or decode an input; the entry point turns that into exit code 2.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

#: The checkout that holds this file. ``check`` reads the tree it is given as ``root``, but
#: imports the project's own packages from here.
REPO_ROOT = Path(__file__).resolve().parents[2]


def use_supply_chain_package() -> None:
    """Put ``solutions/supply-chain`` on ``sys.path`` so ``import supply_chain`` works."""
    path = str(REPO_ROOT / "solutions" / "supply-chain")
    if path not in sys.path:
        sys.path.insert(0, path)


@dataclass(frozen=True)
class Violation:
    """One finding, printed as ``path:line: kind: detail``.

    Attributes:
        path: File path relative to the checked root, with ``/`` separators.
        line: 1-based line number (1 when the location is not known).
        kind: Short category, for example ``range`` or ``missing``.
        detail: What is wrong.
    """

    path: str
    line: int
    kind: str
    detail: str

    def format(self) -> str:
        """Return the one-line form ``path:line: kind: detail``."""
        return f"{self.path}:{self.line}: {self.kind}: {self.detail}"


@dataclass
class Report:
    """The result of one ``check`` call.

    Attributes:
        violations: Every finding; a check does not stop at the first one.
        scanned: How many files the check read.
    """

    violations: list[Violation] = field(default_factory=list)
    scanned: int = 0


class Unparseable(Exception):
    """An input could not be read or decoded (exit code 2, not a violation).

    Attributes:
        path: File path relative to the checked root.
        detail: Why it could not be read.
        scanned: How many files were read before this one failed.
    """

    def __init__(self, path: str, detail: str, scanned: int = 0) -> None:
        super().__init__(f"{path}: {detail}")
        self.path = path
        self.detail = detail
        self.scanned = scanned
