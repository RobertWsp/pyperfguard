from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True, kw_only=True)
class Event:
    """Base runtime event emitted by any patcher into the EventBus."""

    kind: str
    fingerprint: str
    timestamp: float = field(default_factory=time.monotonic)
    call_site: int | None = None  # hash from frame_utils.call_site_fingerprint
    extra: tuple[tuple[str, Any], ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class QueryEvent(Event):
    """A database query emitted by a driver patcher.

    ``fingerprint`` holds the normalized query hash (from the fingerprint module).
    ``statement``   holds the human-readable normalized form.
    ``stack_frames`` holds formatted ``FrameRef.format()`` strings for display.
    """

    kind: str = "query"
    db_system: str = ""  # e.g. "postgresql", "cassandra", "mongodb"
    statement: str = ""
    duration_s: float | None = None
    rows: int | None = None
    error: str | None = None
    stack_frames: tuple[str, ...] = ()
