"""Patcher protocol — a unit that instruments a target library.

Patchers are intentionally minimal: they expose a ``module_name`` string so
the import hook knows when to invoke them, plus ``install`` and ``uninstall``
methods that wrap/unwrap functions on the loaded module.

We deliberately do NOT depend on ``wrapt`` here — concrete patchers may use
it, but the protocol stays library-free so that simple cases (a single
monkey-patch) need no extra dependency.
"""

from __future__ import annotations

from types import ModuleType
from typing import Protocol, runtime_checkable


@runtime_checkable
class Patcher(Protocol):
    """A patcher targets exactly one importable module."""

    module_name: str

    def install(self, module: ModuleType) -> None:
        """Apply instrumentation to a freshly-loaded ``module``."""
        ...

    def uninstall(self, module: ModuleType) -> None:
        """Reverse :meth:`install`. Must be idempotent."""
        ...
