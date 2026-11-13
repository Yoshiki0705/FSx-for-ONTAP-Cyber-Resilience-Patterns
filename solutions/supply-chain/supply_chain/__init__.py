"""Pure core of the supply-chain aggregator.

Modules in this package do no network, file, or subprocess I/O. Tests put
``solutions/supply-chain`` on ``sys.path`` (see ``tests/conftest.py``) and
import with ``from supply_chain import models``.
"""

from __future__ import annotations
