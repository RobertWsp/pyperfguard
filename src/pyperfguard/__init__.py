"""pyperfguard — agnostic, pluggable Python performance & anti-pattern guard.

Public API surface (kept intentionally small and lazy-imported so that
``import pyperfguard`` stays cheap).
"""

from __future__ import annotations

from pyperfguard.core.finding import Finding, Fix, Location
from pyperfguard.core.rule import Rule, RuleScope
from pyperfguard.core.severity import Severity

__all__ = [
    "Finding",
    "Fix",
    "Location",
    "Rule",
    "RuleScope",
    "Severity",
    "profile",
    "async_profile",
    "analyze",
    "__version__",
]

__version__ = "0.1.0"


def profile(*args, **kwargs):
    """Open a runtime profiling scope. Lazy-imported."""
    from pyperfguard.runtime_engine.profile import profile as _profile

    return _profile(*args, **kwargs)


def async_profile(*args, **kwargs):
    """Open an async runtime profiling scope. Use with ``async with``. Lazy-imported."""
    from pyperfguard.runtime_engine.profile import async_profile as _async_profile

    return _async_profile(*args, **kwargs)


def analyze(*args, **kwargs):
    """Run the static AST engine. Lazy-imported."""
    from pyperfguard.ast_engine.runner import analyze as _analyze

    return _analyze(*args, **kwargs)
