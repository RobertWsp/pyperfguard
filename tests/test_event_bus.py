from __future__ import annotations

from pyperfguard.runtime_engine.event_bus import EventBus
from pyperfguard.runtime_engine.events import Event
from pyperfguard.runtime_engine.profile import profile


def test_emit_records_into_active_scope():
    bus = EventBus()
    with profile(name="t") as session:
        bus.emit(Event(kind="custom", fingerprint="abc"))
        bus.emit(Event(kind="custom", fingerprint="def"))
    events = session.scope.events()
    assert len(events) == 2
    assert {e.fingerprint for e in events} == {"abc", "def"}


def test_emit_without_scope_is_dropped():
    bus = EventBus()
    bus.emit(Event(kind="custom", fingerprint="abc"))  # no scope active — must not raise


def test_subscriber_called_for_every_event():
    bus = EventBus()
    received: list[Event] = []
    bus.subscribe(received.append)
    with profile(name="t"):
        bus.emit(Event(kind="x", fingerprint="1"))
        bus.emit(Event(kind="x", fingerprint="2"))
    assert len(received) == 2


def test_subscriber_isolation(capfd):
    bus = EventBus()

    def boom(_e: Event) -> None:
        raise RuntimeError("nope")

    received: list[Event] = []
    bus.subscribe(boom)
    bus.subscribe(received.append)
    with profile(name="t"):
        bus.emit(Event(kind="x", fingerprint="1"))
    assert len(received) == 1
    assert "subscriber failed" in capfd.readouterr().err


def test_unsubscribe():
    bus = EventBus()
    received: list[Event] = []
    bus.subscribe(received.append)
    bus.unsubscribe(received.append)
    with profile(name="t"):
        bus.emit(Event(kind="x", fingerprint="1"))
    assert received == []
