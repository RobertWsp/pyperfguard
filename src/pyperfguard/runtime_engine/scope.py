"""Scope = unit of correlation for runtime events.

A scope is whatever boundary you want to detect anti-patterns *within*: a
request, a Celery task, an ``await`` chain, an explicit ``with profile():``
block. We propagate it via ``contextvars`` so it follows asyncio tasks
automatically (PEP 567).
"""

from __future__ import annotations

import contextvars
import threading
import time
import uuid
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field

from pyperfguard.runtime_engine.events import Event


@dataclass(slots=True)
class Scope:
    """In-memory bucket of events for one logical operation."""

    name: str = "anonymous"
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: float = field(default_factory=time.monotonic)
    _events: deque[Event] = field(default_factory=lambda: deque(maxlen=10_000))
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _overflow_count: int = field(default=0, repr=False)

    def record(self, event: Event) -> None:
        # ``deque.append`` is atomic under the GIL but we still take the lock
        # so detectors that consume the deque while it grows see a consistent
        # snapshot.
        with self._lock:
            if len(self._events) == self._events.maxlen:
                self._overflow_count += 1
                if self._overflow_count == 1:
                    import warnings

                    warnings.warn(
                        f"pyperfguard: scope '{self.name}' event buffer full "
                        f"(maxlen={self._events.maxlen}). Oldest events dropped; "
                        "N+1 detection may be incomplete.",
                        RuntimeWarning,
                        stacklevel=2,
                    )
            self._events.append(event)

    def overflow_count(self) -> int:
        """Number of events dropped due to buffer overflow."""
        return self._overflow_count

    def events(self) -> tuple[Event, ...]:
        with self._lock:
            return tuple(self._events)

    def event_count(self) -> int:
        return len(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()

    def filter(self, kind: str) -> Iterable[Event]:
        with self._lock:
            snap = tuple(self._events)
        return (e for e in snap if e.kind == kind)


_scope_var: contextvars.ContextVar[Scope | None] = contextvars.ContextVar(
    "pyperfguard_scope", default=None
)


def current_scope() -> Scope | None:
    return _scope_var.get()


def set_scope(scope: Scope | None) -> contextvars.Token[Scope | None]:
    """Bind ``scope`` to the current context. Caller must reset the token."""
    return _scope_var.set(scope)


def reset_scope(token: contextvars.Token[Scope | None]) -> None:
    _scope_var.reset(token)
