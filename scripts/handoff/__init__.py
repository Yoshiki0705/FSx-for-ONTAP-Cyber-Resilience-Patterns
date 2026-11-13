"""Handoff_Harness: pass a Handoff_Prompt to another repository's Kiro and track the result.

Layout (design section 20, "pure core and thin runner"):

- Pure core: every module of this package except ``runner.py`` and ``cli.py``. These
  modules do not start processes, do not use the network, and do not read or write
  files. Whatever they need from outside (file contents, deny-word lists, temporary
  paths, observations of a run) is passed to them as arguments by the I/O layer.
  ``scripts/tests/test_handoff_no_io.py`` enforces the import part of this rule: it
  parses each pure-core module with ``ast`` and fails on an import of ``subprocess``,
  ``socket``, ``urllib``, ``http`` or ``requests``. The rest of the rule rests on review.
- I/O layer: ``runner.py`` (lock, subprocess, worktrees, reports) and ``cli.py``
  (command-line entry point).

Import convention:

- The import root is ``scripts/``, and this package is imported as ``handoff``.
- Modules import each other with absolute imports only, for example
  ``from handoff import state`` or ``from handoff.state import transition``. Relative
  imports (``from . import state``) are not used, because they fail when ``cli.py`` is
  started as a file.
- pytest: ``scripts/tests/conftest.py`` puts ``scripts/`` on ``sys.path``, and the tests
  import ``handoff`` and its modules by name.
- Direct start: ``python3 scripts/handoff/cli.py <subcommand>`` with the repository root
  as the working directory (task 2.3). Python then puts ``scripts/handoff/`` at the front
  of ``sys.path``, which would make each sibling module importable a second time under a
  bare name (``import state``) as a separate module object, and would let a sibling
  module shadow a standard-library module of the same name. Before importing anything
  from this package, ``cli.py`` replaces that entry with ``scripts/``, and only when it
  was started as a file::

      if __package__ in (None, ""):
          _here = Path(__file__).resolve().parent
          sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != _here]
          sys.path.insert(0, str(_here.parent))

  Imported as ``handoff.cli`` (from the tests), ``cli.py`` leaves ``sys.path`` alone.
- No module other than ``cli.py`` changes ``sys.path``.
- With ``scripts/`` as the import root, a script next to this package is importable by
  its bare name, for example ``check_sensitive_patterns``.
"""

from __future__ import annotations
