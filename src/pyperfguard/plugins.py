"""Convenience facade over the registry's discovery + reporter selection."""

from __future__ import annotations

from pyperfguard.core.registry import Registry, get_registry


def bootstrap() -> Registry:
    """Discover all entry points and return the populated global registry."""
    reg = get_registry()
    reg.discover()
    return reg
