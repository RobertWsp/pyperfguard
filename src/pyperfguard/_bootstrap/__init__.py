"""Bootstrap package — auto-instrumentation entry point."""

from pyperfguard._bootstrap.bootstrap import auto_instrument, is_active

__all__ = ["auto_instrument", "is_active"]
