"""Generic DB-API 2.0 (PEP 249) patcher.

Any PEP 249 compliant driver exposes ``connect(**kwargs) → Connection`` and
``Connection.cursor() → Cursor``.  We wrap the module's ``connect`` function
with a factory that returns an instrumented ``Connection`` proxy.

Usage — wrap psycopg2::

    from pyperfguard.patchers.dbapi import wrap_connect
    import psycopg2
    wrap_connect(psycopg2, db_system="postgresql")

Or via the ``DBAPIPatcher``::

    patcher = DBAPIPatcher(target_module_name="psycopg2", db_system="postgresql")
    # Register it with the RuntimeEngine / MetaPathFinder.
"""

from __future__ import annotations

import functools
import time
from types import ModuleType
from typing import Any


class _InstrumentedCursor:
    """Transparent proxy around a real DBAPI cursor that emits QueryEvents."""

    def __init__(self, real: Any, db_system: str) -> None:
        self._real = real
        self._db_system = db_system

    def execute(self, operation: str, parameters: Any = None) -> Any:
        from pyperfguard.core.frame_utils import format_frames, walk_user_frames
        from pyperfguard.fingerprint.sql import fingerprint_hash, normalize
        from pyperfguard.runtime_engine.event_bus import get_event_bus
        from pyperfguard.runtime_engine.events import QueryEvent

        frames = walk_user_frames(skip=2, limit=6)
        cs_fp = hash(tuple(f.fingerprint() for f in frames)) if frames else None
        fp = fingerprint_hash(operation)
        stmt = normalize(operation)
        start = time.perf_counter()
        error: str | None = None
        try:
            if parameters is not None:
                return self._real.execute(operation, parameters)
            return self._real.execute(operation)
        except Exception as exc:
            error = str(exc)
            raise
        finally:
            duration = time.perf_counter() - start
            get_event_bus().emit(
                QueryEvent(
                    fingerprint=fp,
                    db_system=self._db_system,
                    statement=stmt,
                    duration_s=duration,
                    error=error,
                    call_site=cs_fp,
                    stack_frames=format_frames(frames),
                )
            )

    def executemany(self, operation: str, seq_of_parameters: Any) -> Any:
        if hasattr(self._real, "executemany"):
            return self._real.executemany(operation, seq_of_parameters)
        raise AttributeError("executemany not supported")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def __enter__(self) -> _InstrumentedCursor:
        return self

    def __exit__(self, *args: Any) -> Any:
        return self._real.__exit__(*args) if hasattr(self._real, "__exit__") else None


class _InstrumentedConnection:
    """Transparent proxy around a real DBAPI Connection."""

    def __init__(self, real: Any, db_system: str) -> None:
        self._real = real
        self._db_system = db_system

    def cursor(self, *args: Any, **kwargs: Any) -> _InstrumentedCursor:
        real_cursor = self._real.cursor(*args, **kwargs)
        return _InstrumentedCursor(real_cursor, self._db_system)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def __enter__(self) -> _InstrumentedConnection:
        return self

    def __exit__(self, *args: Any) -> Any:
        return self._real.__exit__(*args) if hasattr(self._real, "__exit__") else None


def wrap_connect(module: ModuleType, db_system: str = "sql") -> None:
    """Wrap ``module.connect`` in-place with instrumentation."""
    original = getattr(module, "connect")  # noqa: B009

    @functools.wraps(original)
    def patched_connect(*args: Any, **kwargs: Any) -> _InstrumentedConnection:
        real_conn = original(*args, **kwargs)
        return _InstrumentedConnection(real_conn, db_system)

    setattr(module, "connect", patched_connect)  # noqa: B010
    setattr(module, "_pyperfguard_original_connect", original)  # noqa: B010


def unwrap_connect(module: ModuleType) -> None:
    """Reverse ``wrap_connect`` (idempotent)."""
    original = getattr(module, "_pyperfguard_original_connect", None)
    if original is not None:
        setattr(module, "connect", original)  # noqa: B010
        try:
            delattr(module, "_pyperfguard_original_connect")
        except AttributeError:
            pass


class DBAPIPatcher:
    """Generic Patcher for any DB-API 2.0 driver."""

    def __init__(self, target_module_name: str, db_system: str = "sql") -> None:
        self.module_name = target_module_name
        self._db_system = db_system

    def install(self, module: ModuleType) -> None:
        if not hasattr(module, "connect"):
            return
        if hasattr(module, "_pyperfguard_original_connect"):
            return  # already instrumented
        wrap_connect(module, self._db_system)

    def uninstall(self, module: ModuleType) -> None:
        unwrap_connect(module)
