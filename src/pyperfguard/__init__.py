"""pyperfguard — agnostic, pluggable Python performance & anti-pattern guard.

Public API surface (kept intentionally small and lazy-imported so that
``import pyperfguard`` stays cheap).
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from pyperfguard.core.finding import Finding, Fix, Location
from pyperfguard.core.rule import Rule, RuleScope
from pyperfguard.core.severity import Severity

if TYPE_CHECKING:
    from pyperfguard.core.config import Config
    from pyperfguard.core.registry import Registry
    from pyperfguard.runtime_engine.profile import ProfileSession

__all__ = [
    "Finding",
    "Fix",
    "Location",
    "Rule",
    "RuleScope",
    "Severity",
    "__version__",
    "analyze",
    "async_profile",
    "profile",
]

__version__ = "0.1.0"


def profile(
    name: str = "anonymous",
    detectors: Iterable[object] | None = None,
) -> ProfileSession:
    """Open a runtime profiling scope. Lazy-imported."""
    from pyperfguard.runtime_engine.profile import profile as _profile

    return _profile(name=name, detectors=detectors)


def async_profile(
    name: str = "anonymous",
    detectors: Iterable[object] | None = None,
) -> ProfileSession:
    """Open an async runtime profiling scope. Use with ``async with``. Lazy-imported."""
    from pyperfguard.runtime_engine.profile import async_profile as _async_profile

    return _async_profile(name=name, detectors=detectors)


def analyze(
    paths: Iterable[Path | str],
    *,
    config: Config | None = None,
    registry: Registry | None = None,
    discover: bool = True,
) -> list[Finding]:
    """Run the static AST engine. Lazy-imported."""
    from pyperfguard.ast_engine.runner import analyze as _analyze

    return _analyze(paths, config=config, registry=registry, discover=discover)
