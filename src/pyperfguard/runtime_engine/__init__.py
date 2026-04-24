"""Runtime instrumentation engine.

The runtime engine collects events from patched libraries (DB drivers, HTTP
clients, asyncio) and groups them by *scope* (a request, a task, an explicit
``with profile():`` block). Detectors consume the events and emit
:class:`pyperfguard.core.finding.Finding` instances.
"""

from pyperfguard.runtime_engine.event_bus import EventBus, get_event_bus
from pyperfguard.runtime_engine.events import Event, QueryEvent
from pyperfguard.runtime_engine.patcher import Patcher
from pyperfguard.runtime_engine.profile import ProfileSession, profile
from pyperfguard.runtime_engine.scope import Scope, current_scope, set_scope

__all__ = [
    "Event",
    "EventBus",
    "Patcher",
    "ProfileSession",
    "QueryEvent",
    "Scope",
    "current_scope",
    "get_event_bus",
    "profile",
    "set_scope",
]
