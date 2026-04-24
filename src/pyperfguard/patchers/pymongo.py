"""PyMongo patcher.

Uses PyMongo's official ``monitoring.CommandListener`` API:
- ``started(event)``   — capture start time + fingerprint
- ``succeeded(event)`` — emit QueryEvent with duration
- ``failed(event)``    — emit QueryEvent with error

``pymongo.monitoring.register(listener)`` is a global, process-wide call.
PyMongo does not support un-registering listeners, so ``uninstall`` is a no-op
beyond an internal flag that makes the listener silently drop events.

Stack capture: MongoDB commands are sent from the *application thread*,
so ``sys._getframe`` captures the correct call stack in ``started``.
"""

from __future__ import annotations

import threading
import time
from types import ModuleType


class _PyPerfMongoListener:
    """Implements the pymongo CommandListener protocol."""

    def __init__(self) -> None:
        self._active = True
        self._pending: dict[int, tuple[str, str, tuple, int | None, float]] = {}
        # key: request_id → (fingerprint, collection, stack_frames, call_site, start)
        self._lock = threading.Lock()

    def deactivate(self) -> None:
        self._active = False

    def started(self, event: object) -> None:  # type: ignore[override]
        if not self._active:
            return
        from pyperfguard.core.frame_utils import format_frames, walk_user_frames
        from pyperfguard.fingerprint.mongo import fingerprint_hash, normalize

        command = getattr(event, "command", {})
        fp = fingerprint_hash(command)
        stmt = normalize(command)
        frames = walk_user_frames(skip=3, limit=6)
        cs_fp = hash(tuple(f.fingerprint() for f in frames)) if frames else None

        rid = getattr(event, "request_id", id(event))
        with self._lock:
            self._pending[rid] = (fp, stmt, format_frames(frames), cs_fp, time.perf_counter())

    def succeeded(self, event: object) -> None:  # type: ignore[override]
        if not self._active:
            return
        from pyperfguard.runtime_engine.event_bus import get_event_bus
        from pyperfguard.runtime_engine.events import QueryEvent

        rid = getattr(event, "request_id", None)
        with self._lock:
            entry = self._pending.pop(rid, None)
        if entry is None:
            return
        fp, stmt, frames, cs_fp, start = entry
        get_event_bus().emit(
            QueryEvent(
                fingerprint=fp,
                db_system="mongodb",
                statement=stmt,
                duration_s=time.perf_counter() - start,
                call_site=cs_fp,
                stack_frames=frames,
            )
        )

    def failed(self, event: object) -> None:  # type: ignore[override]
        if not self._active:
            return
        from pyperfguard.runtime_engine.event_bus import get_event_bus
        from pyperfguard.runtime_engine.events import QueryEvent

        rid = getattr(event, "request_id", None)
        with self._lock:
            entry = self._pending.pop(rid, None)
        if entry is None:
            return
        fp, stmt, frames, cs_fp, _ = entry
        failure = getattr(event, "failure", None)
        get_event_bus().emit(
            QueryEvent(
                fingerprint=fp,
                db_system="mongodb",
                statement=stmt,
                error=str(failure) if failure else "unknown",
                call_site=cs_fp,
                stack_frames=frames,
            )
        )


class PyMongoPatcher:
    """Registers a global PyMongo CommandListener at install time."""

    module_name = "pymongo"

    def __init__(self) -> None:
        self._listener: _PyPerfMongoListener | None = None

    def install(self, module: ModuleType) -> None:
        if self._listener is not None:
            return
        self._listener = _PyPerfMongoListener()
        try:
            module.monitoring.register(self._listener)
        except Exception:
            self._listener = None

    def uninstall(self, module: ModuleType) -> None:
        if self._listener is not None:
            self._listener.deactivate()
