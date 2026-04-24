"""PEP 451 MetaPathFinder that applies patchers when their target imports.

This is the canonical mechanism (used by ``ddtrace``, ``newrelic``, ``elastic-apm``)
because it handles the "library imported before instrumentation" case correctly:
we register the finder once at startup; whenever the target library is loaded
afterwards (or already in ``sys.modules``), the patcher runs exactly once.
"""

from __future__ import annotations

import contextlib
import importlib.util
import sys
from collections.abc import Sequence
from importlib.abc import Loader, MetaPathFinder
from importlib.machinery import ModuleSpec
from types import ModuleType

from pyperfguard.runtime_engine.patcher import Patcher


class _PatchingLoader(Loader):
    def __init__(self, inner: Loader, patcher: Patcher) -> None:
        self._inner = inner
        self._patcher = patcher

    def create_module(self, spec: ModuleSpec) -> ModuleType | None:
        if hasattr(self._inner, "create_module"):
            return self._inner.create_module(spec)
        return None

    def exec_module(self, module: ModuleType) -> None:
        self._inner.exec_module(module)
        try:
            self._patcher.install(module)
        except Exception as exc:
            print(
                f"[pyperfguard] patcher for {self._patcher.module_name!r} failed: {exc}",
                file=sys.stderr,
            )


class PyperfMetaPathFinder(MetaPathFinder):
    """Single shared finder; lookup is O(1) via the ``patchers_by_name`` dict."""

    def __init__(self) -> None:
        self._patchers: dict[str, Patcher] = {}
        self._installed: set[str] = set()

    def register(self, patcher: Patcher) -> None:
        self._patchers[patcher.module_name] = patcher
        # If the target was imported before us, patch it immediately.
        existing = sys.modules.get(patcher.module_name)
        if existing is not None and patcher.module_name not in self._installed:
            try:
                patcher.install(existing)
                self._installed.add(patcher.module_name)
            except Exception as exc:
                print(
                    f"[pyperfguard] retro-patch for {patcher.module_name!r} failed: {exc}",
                    file=sys.stderr,
                )

    def unregister(self, module_name: str) -> None:
        patcher = self._patchers.pop(module_name, None)
        if patcher is None:
            return
        existing = sys.modules.get(module_name)
        if existing is not None:
            with contextlib.suppress(Exception):
                patcher.uninstall(existing)
        self._installed.discard(module_name)

    def find_spec(
        self,
        fullname: str,
        path: Sequence[str] | None,
        target: ModuleType | None = None,
    ) -> ModuleSpec | None:
        if fullname not in self._patchers or fullname in self._installed:
            return None
        # Defer to other finders to locate the actual module, but wrap its loader.
        # We must avoid infinite recursion: skip ourselves while resolving.
        sys.meta_path.remove(self)
        try:
            spec = importlib.util.find_spec(fullname)
        finally:
            if self not in sys.meta_path:
                sys.meta_path.insert(0, self)
        if spec is None or spec.loader is None:
            return None
        spec.loader = _PatchingLoader(spec.loader, self._patchers[fullname])
        self._installed.add(fullname)
        return spec


_FINDER: PyperfMetaPathFinder | None = None


def install_finder() -> PyperfMetaPathFinder:
    """Insert the global finder into ``sys.meta_path`` (idempotent)."""
    global _FINDER
    if _FINDER is None:
        _FINDER = PyperfMetaPathFinder()
    if _FINDER not in sys.meta_path:
        sys.meta_path.insert(0, _FINDER)
    return _FINDER


def uninstall_finder() -> None:
    global _FINDER
    if _FINDER is not None and _FINDER in sys.meta_path:
        sys.meta_path.remove(_FINDER)


def get_finder() -> PyperfMetaPathFinder:
    return install_finder()
