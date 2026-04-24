"""SQLAlchemy patcher.

Uses the official SQLAlchemy Core event system (class-level listeners) so
instrumentation applies to **every** Engine instance automatically:

    event.listen(Engine, "before_cursor_execute", fn)
    event.listen(Engine, "after_cursor_execute", fn)

This is the same mechanism used by OpenTelemetry's sqlalchemy instrumentation
and is the recommended approach in the SQLAlchemy docs.

Overhead: two dict lookups + monotonic clock read per query — negligible.
"""

from __future__ import annotations

import threading
import time
from types import ModuleType


class SQLAlchemyPatcher:
    """Instruments every SQLAlchemy ``Engine`` at class level."""

    module_name = "sqlalchemy"

    def __init__(self) -> None:
        self._installed = False
        # cursor-id → start timestamp; thread-local avoids collisions across threads.
        self._local = threading.local()

    # ----- Patcher protocol ------------------------------------------------

    def install(self, module: ModuleType) -> None:
        if self._installed:
            return
        try:
            import sqlalchemy.event as sa_event  # already in sys.modules
            from sqlalchemy.engine import Engine
        except ImportError:
            return
        sa_event.listen(Engine, "before_cursor_execute", self._before, named=True)
        sa_event.listen(Engine, "after_cursor_execute", self._after, named=True)
        sa_event.listen(Engine, "handle_error", self._on_error, named=True)
        self._installed = True

    def uninstall(self, module: ModuleType) -> None:
        if not self._installed:
            return
        try:
            import sqlalchemy.event as sa_event
            from sqlalchemy.engine import Engine

            sa_event.remove(Engine, "before_cursor_execute", self._before)
            sa_event.remove(Engine, "after_cursor_execute", self._after)
            sa_event.remove(Engine, "handle_error", self._on_error)
        except Exception:  # noqa: BLE001
            pass
        self._installed = False

    # ----- Event handlers --------------------------------------------------

    def _before(
        self, conn, cursor, statement, parameters, context, executemany, **_kw
    ) -> None:
        if not hasattr(self._local, "pending"):
            self._local.pending = {}
        self._local.pending[id(cursor)] = time.perf_counter()

    def _after(
        self, conn, cursor, statement, parameters, context, executemany, **_kw
    ) -> None:
        pending = getattr(self._local, "pending", {})
        start = pending.pop(id(cursor), None)
        duration = (time.perf_counter() - start) if start is not None else None

        from pyperfguard.core.frame_utils import format_frames, walk_user_frames
        from pyperfguard.fingerprint.sql import fingerprint_hash, normalize
        from pyperfguard.runtime_engine.event_bus import get_event_bus
        from pyperfguard.runtime_engine.events import QueryEvent

        frames = walk_user_frames(skip=4, limit=6)
        get_event_bus().emit(
            QueryEvent(
                fingerprint=fingerprint_hash(statement),
                db_system=_dialect_name(conn),
                statement=normalize(statement),
                duration_s=duration,
                call_site=hash(tuple(f.fingerprint() for f in frames)) if frames else None,
                stack_frames=format_frames(frames),
            )
        )

    def _on_error(self, exception_context, **_kw) -> None:
        cursor = getattr(exception_context, "cursor", None)
        if cursor is not None:
            pending = getattr(self._local, "pending", {})
            pending.pop(id(cursor), None)


def _dialect_name(conn: object) -> str:
    try:
        return conn.engine.dialect.name  # type: ignore[union-attr]
    except Exception:
        return "sql"
