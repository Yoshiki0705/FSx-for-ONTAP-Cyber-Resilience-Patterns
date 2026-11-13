"""Format adapters for the supply-chain Aggregator (I/O layer side).

An adapter turns one SBOM format into the format-independent ``Component``
list that the pure core in ``supply_chain`` accepts (design D-3, Q-10).
Adapters live outside ``supply_chain`` so a new format changes this package
only. Only the SPDX 2.3 JSON adapter exists; do not add others here without
a design change.
"""
