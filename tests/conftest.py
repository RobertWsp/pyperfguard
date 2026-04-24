from __future__ import annotations

import pytest

from pyperfguard.core.registry import Registry, reset_registry
from pyperfguard.runtime_engine.event_bus import reset_event_bus


@pytest.fixture(autouse=True)
def _isolate_globals():
    """Each test runs against fresh global state."""
    reset_registry()
    reset_event_bus()
    yield
    reset_registry()
    reset_event_bus()


@pytest.fixture
def fresh_registry() -> Registry:
    return Registry()
