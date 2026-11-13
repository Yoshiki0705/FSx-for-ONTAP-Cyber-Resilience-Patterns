#!/usr/bin/env python3
"""Entry point of the supply-chain gates.

    check_supply_chain.py                  run every subcommand
    check_supply_chain.py policy           run one subcommand
    check_supply_chain.py policy --selftest   prove that subcommand fails on its bad inputs
    check_supply_chain.py --selftest       prove it for every subcommand

Subcommands are the modules of ``scripts/supply_chain_checks/`` (see ``_common.py`` for the
interface). They are found by listing that directory at run time, so adding a subcommand
means adding a file; this entry point is not edited. A module ``agent_components.py`` is the
subcommand ``agent-components``.

Output is one line per violation, ``path:line: kind: detail``, then a summary line that
always says how many files were scanned, and says so when that is zero.

Exit codes: 0 clean, 1 a violation (or a failed selftest), 2 an input could not be read or
decoded, or a subcommand is broken. A run of several subcommands exits with the highest code.

``--selftest`` reads ``scripts/tests/fixtures/supply_chain/<name>/<case>/``. Each case is a
directory that plays the repository root. ``pass-*`` cases must exit 0 having scanned at
least one file. ``fail-*`` cases hold a file ``EXPECT`` whose first line is
``<exit code> <kind>``; the run must exit with that code and print a ``kind`` violation. A
subcommand with no ``pass-*`` or no ``fail-*`` case fails its selftest: a gate never seen to
fail is not evidence that it runs.
"""

from __future__ import annotations

import argparse
import importlib.util
import io
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import TextIO

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from supply_chain_checks._common import REPO_ROOT, Report, Unparseable  # noqa: E402

CHECKS_DIR = _SCRIPTS_DIR / "supply_chain_checks"
FIXTURES_DIR = _SCRIPTS_DIR / "tests" / "fixtures" / "supply_chain"


def discover(checks_dir: Path = CHECKS_DIR) -> dict[str, ModuleType]:
    """List the subcommands by importing every public module of ``checks_dir``.

    Args:
        checks_dir: The directory to list.

    Returns:
        Subcommand name to module, sorted by name. Files starting with ``_`` are skipped.

    Raises:
        ImportError: A module cannot be loaded, or has no callable ``check``.
    """
    found: dict[str, ModuleType] = {}
    for path in sorted(checks_dir.glob("[!_]*.py")):
        spec = importlib.util.spec_from_file_location(f"supply_chain_checks.{path.stem}", path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if not callable(getattr(module, "check", None)):
            raise ImportError(f"{path.name} has no check(root) function")
        found[path.stem.replace("_", "-")] = module
    return found


def run_one(name: str, module: ModuleType, root: Path, out: TextIO) -> tuple[int, int]:
    """Run one subcommand and print its lines.

    Args:
        name: The subcommand name, for the summary line.
        module: The module with ``check(root)``.
        root: The tree to check.
        out: Where the lines go.

    Returns:
        ``(exit code, files scanned)``.
    """
    try:
        report: Report = module.check(root)
    except Unparseable as exc:
        print(f"{exc.path}:1: unparseable: {exc.detail}", file=out)
        _summary(name, exc.scanned, 0, out)
        return 2, exc.scanned
    except Exception as exc:  # noqa: BLE001 - a broken subcommand must not look like a pass
        print(f"{name}: internal error: {type(exc).__name__}: {exc}", file=out)
        return 2, 0
    for violation in report.violations:
        print(violation.format(), file=out)
    _summary(name, report.scanned, len(report.violations), out)
    return (1 if report.violations else 0), report.scanned


def _summary(name: str, scanned: int, violations: int, out: TextIO) -> None:
    if scanned == 0:
        print(f"{name}: scanned 0 files (nothing was checked), {violations} violation(s)", file=out)
    else:
        print(f"{name}: scanned {scanned} file(s), {violations} violation(s)", file=out)


def selftest_one(name: str, module: ModuleType, fixtures_dir: Path, out: TextIO) -> int:
    """Check that a subcommand passes its good inputs and fails its bad ones.

    Args:
        name: The subcommand name.
        module: The module with ``check(root)``.
        fixtures_dir: The directory that holds ``<name>/<case>/``.
        out: Where the problems go.

    Returns:
        0 when every case behaves as its name says, 1 otherwise.
    """
    cases = sorted(p for p in (fixtures_dir / name).glob("*") if p.is_dir()) if (fixtures_dir / name).is_dir() else []
    problems: list[str] = []
    passes = [c for c in cases if c.name.startswith("pass-")]
    fails = [c for c in cases if c.name.startswith("fail-")]
    if not passes:
        problems.append("no pass-* fixture: a gate that always fails would look the same")
    if not fails:
        problems.append("no fail-* fixture: the gate has never been seen to fail")
    for case in passes:
        code, scanned = run_one(name, module, case, io.StringIO())
        if code != 0 or scanned < 1:
            problems.append(
                f"{case.name}: expected exit 0 with at least one file scanned, got exit {code}, {scanned} scanned"
            )
    for case in fails:
        problems.extend(_check_fail_case(name, module, case))
    if problems:
        for problem in problems:
            print(f"{name}: selftest FAILED: {problem}", file=out)
        return 1
    print(f"{name}: selftest ok ({len(fails)} failing input(s) fail, {len(passes)} good input(s) pass)", file=out)
    return 0


def _check_fail_case(name: str, module: ModuleType, case: Path) -> list[str]:
    expect = case / "EXPECT"
    try:
        code_text, kind = expect.read_text(encoding="utf-8").splitlines()[0].split()
        want_code = int(code_text)
    except (OSError, IndexError, ValueError):
        return [f"{case.name}: EXPECT must start with '<exit code> <kind>'"]
    buffer = io.StringIO()
    code, _ = run_one(name, module, case, buffer)
    if code != want_code:
        return [f"{case.name}: expected exit {want_code}, got {code}"]
    if f": {kind}:" not in buffer.getvalue():
        return [f"{case.name}: exit {code} but no '{kind}' line in the output"]
    return []


def main(
    argv: Sequence[str] | None = None,
    *,
    checks_dir: Path = CHECKS_DIR,
    fixtures_dir: Path = FIXTURES_DIR,
    default_root: Path = REPO_ROOT,
    out: TextIO | None = None,
) -> int:
    """Run the gates.

    Args:
        argv: Arguments after the program name; ``None`` reads ``sys.argv``.
        checks_dir: Where the subcommand modules are.
        fixtures_dir: Where the ``--selftest`` inputs are.
        default_root: The tree to check when ``--root`` is absent.
        out: Output stream; standard output when ``None``.

    Returns:
        The exit code.
    """
    out = out if out is not None else sys.stdout
    parser = argparse.ArgumentParser(prog="check_supply_chain.py", description=__doc__.split("\n")[0])
    parser.add_argument("subcommand", nargs="?", help="a subcommand name; omit to run all")
    parser.add_argument("--selftest", action="store_true", help="check the gate against its failing fixtures")
    parser.add_argument("--root", type=Path, default=default_root, help="tree to check (default: this repository)")
    args = parser.parse_args(argv)
    try:
        commands = discover(checks_dir)
    except Exception as exc:  # noqa: BLE001
        print(f"check_supply_chain: cannot load the subcommands: {type(exc).__name__}: {exc}", file=out)
        return 2
    if args.subcommand is not None:
        if args.subcommand not in commands:
            print(
                f"check_supply_chain: unknown subcommand {args.subcommand!r}; known: {', '.join(commands) or '(none)'}",
                file=out,
            )
            return 2
        commands = {args.subcommand: commands[args.subcommand]}
    if not commands:
        print("check_supply_chain: no subcommand found (nothing was checked)", file=out)
        return 2
    worst = 0
    for name, module in commands.items():
        if args.selftest:
            worst = max(worst, selftest_one(name, module, fixtures_dir, out))
        else:
            code, _ = run_one(name, module, args.root, out)
            worst = max(worst, code)
    return worst


if __name__ == "__main__":
    sys.exit(main())
