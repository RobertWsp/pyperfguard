from __future__ import annotations

import sys
from types import ModuleType

import pytest

from pyperfguard.runtime_engine.import_hook import (
    install_finder,
    uninstall_finder,
)


@pytest.fixture
def finder():
    f = install_finder()
    yield f
    uninstall_finder()


class _RecordingPatcher:
    def __init__(self, name: str) -> None:
        self.module_name = name
        self.installed: list[ModuleType] = []
        self.uninstalled: list[ModuleType] = []

    def install(self, module: ModuleType) -> None:
        self.installed.append(module)
        module.__pyperfguard_patched__ = True  # type: ignore[attr-defined]

    def uninstall(self, module: ModuleType) -> None:
        self.uninstalled.append(module)


def test_finder_patches_module_when_imported_after_register(finder):
    # Use a stdlib module unlikely to be already imported in this process.
    target = "html.parser"
    sys.modules.pop(target, None)
    p = _RecordingPatcher(target)
    finder.register(p)
    import html.parser  # noqa: F401  (triggers the finder)

    assert len(p.installed) == 1
    assert getattr(sys.modules[target], "__pyperfguard_patched__", False) is True


def test_finder_patches_module_already_imported(finder):
    # html should already be imported by pytest itself.
    import html  # noqa: F401

    assert "html" in sys.modules
    p = _RecordingPatcher("html")
    finder.register(p)
    assert len(p.installed) == 1


def test_unregister_calls_uninstall(finder):
    import html  # noqa: F401

    p = _RecordingPatcher("html")
    finder.register(p)
    finder.unregister("html")
    assert len(p.uninstalled) == 1
