"""Hypothesis strategies shared by the tests in ``scripts/tests/``.

pytest imports each test module of ``scripts/tests/`` with ``scripts/tests/`` at the front of
``sys.path`` (the default ``prepend`` import mode, for a test directory without
``__init__.py``), and ``scripts/tests/conftest.py`` adds ``scripts/``. A test therefore imports
a module of this package by name::

    from strategies import handoff as handoff_strategies

``tests/strategies/`` (task 9.1) will be a second top-level package named ``strategies``. The
two test trees run in separate pytest processes (``make check-evidence`` runs
``pytest scripts/tests/``, ``make test`` runs ``pytest tests/ shared/tests/``, and CI has one
step for each). A single process that collects both trees would import whichever package comes
first on ``sys.path``, so keep them in separate runs.
"""

from __future__ import annotations
