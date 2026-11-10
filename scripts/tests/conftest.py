"""pytest setup for the tests in ``scripts/tests/``.

Puts ``scripts/`` on ``sys.path`` so that the tests can import the Handoff_Harness
package by name, as ``handoff``. The import convention is in the docstring of
``scripts/handoff/__init__.py``.

The tests that were here before this file load the script under test by file path
(``importlib.util.spec_from_file_location``) or run it as a child process. Neither
consults this ``sys.path``, so this file does not change how they load. Only the pytest
process is affected: the environment handed to child processes, ``PYTHONPATH``
included, is left as it was.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS_DIR = str(Path(__file__).resolve().parent.parent)

if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)
