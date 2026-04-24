"""Event bus.

The bus does two things:

1. Records every emitted :class:`Event` into the *currently active scope*
   (looked up via :func:`current_scope`). If no scope is active, the event is
   dropped — runtime instrumentation is opt-in per call site.
2. Fans out events to registered subscribers (e.g. detectors that look at
   query streams to emit N+1 findings).

Subscribers are best-effort and isolated: an exception in one never affects
others or the recording path.
"""

from __future__ import annotations

import contextlib
import sys
import threading
from collections.abc import Callable

from pyperfguard.runtime_engine.events import Event
from pyperfguard.runtime_engine.scope import current_scope

Subscriber = Callable[[Event], None]


class EventBus:
    def __init__(self) -> None:
        self._subscribers: list[Subscriber] = []
        self._lock = threading.Lock()

    def subscribe(self, fn: Subscriber) -> None:
        with self._lock:
            self._subscribers.append(fn)

    def unsubscribe(self, fn: Subscriber) -> None:
        with self._lock, contextlib.suppress(ValueError):
            self._subscribers.remove(fn)

    def emit(self, event: Event) -> None:
        scope = current_scope()
        if scope is not None:
            scope.record(event)
        # Snapshot subscribers under lock; call them outside the lock.
        with self._lock:
            subs = list(self._subscribers)
        for sub in subs:
            try:
                sub(event)
            except Exception as exc:
                print(f"[pyperfguard] subscriber failed: {exc}", file=sys.stderr)


_BUS: EventBus | None = None


def get_event_bus() -> EventBus:
    global _BUS
    if _BUS is None:
        _BUS = EventBus()
    return _BUS


def reset_event_bus() -> None:
    """Test helper."""
    global _BUS
    _BUS = None
