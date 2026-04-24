from __future__ import annotations

import asyncio

from pyperfguard.runtime_engine.events import Event
from pyperfguard.runtime_engine.profile import profile
from pyperfguard.runtime_engine.scope import current_scope


def test_profile_sets_and_clears_scope():
    assert current_scope() is None
    with profile(name="abc") as session:
        assert current_scope() is session.scope
    assert current_scope() is None


def test_scope_nesting_inner_takes_precedence():
    with profile(name="outer") as outer:
        with profile(name="inner") as inner:
            assert current_scope() is inner.scope
        assert current_scope() is outer.scope


def test_scope_propagates_to_asyncio_task():
    captured: list[str] = []

    async def child():
        scope = current_scope()
        if scope:
            captured.append(scope.name)

    async def runner():
        with profile(name="parent"):
            await asyncio.gather(child(), child())

    asyncio.run(runner())
    assert captured == ["parent", "parent"]


def test_scope_record_and_event_count():
    with profile(name="t") as session:
        session.scope.record(Event(kind="q", fingerprint="x"))
        session.scope.record(Event(kind="q", fingerprint="y"))
    assert session.scope.event_count() == 2
    by_kind = list(session.scope.filter("q"))
    assert len(by_kind) == 2


def test_scope_overflow_warns_once():
    import warnings

    from pyperfguard.runtime_engine.scope import Scope

    scope = Scope(name="overflow-test")
    maxlen = scope._events.maxlen
    assert maxlen is not None

    # Fill buffer to the brim first (no overflow yet)
    for i in range(maxlen):
        scope.record(Event(kind="q", fingerprint=str(i)))

    assert scope.overflow_count() == 0

    # Next record causes overflow — must warn exactly once
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        scope.record(Event(kind="q", fingerprint="overflow-1"))
        scope.record(Event(kind="q", fingerprint="overflow-2"))

    runtime_warns = [w for w in caught if issubclass(w.category, RuntimeWarning)]
    assert len(runtime_warns) == 1
    assert "buffer full" in str(runtime_warns[0].message).lower()
    assert scope.overflow_count() == 2


def test_scope_overflow_count_tracks_drops():
    from pyperfguard.runtime_engine.scope import Scope

    scope = Scope(name="count-test")
    maxlen = scope._events.maxlen
    assert maxlen is not None
    for i in range(maxlen + 5):
        scope.record(Event(kind="q", fingerprint=str(i)))
    assert scope.overflow_count() == 5


def test_detector_runs_on_exit():
    class CountDetector:
        def evaluate(self, scope):
            from pathlib import Path

            from pyperfguard.core.finding import Finding, Location
            from pyperfguard.core.severity import Severity

            if scope.event_count() >= 2:
                yield Finding(
                    rule_id="DET001",
                    message=f"saw {scope.event_count()} events",
                    severity=Severity.WARNING,
                    location=Location(path=Path("<runtime>"), start_line=0),
                    scope="runtime",
                )

    with profile(name="t", detectors=[CountDetector()]) as session:
        session.scope.record(Event(kind="q", fingerprint="a"))
        session.scope.record(Event(kind="q", fingerprint="b"))

    assert len(session.findings) == 1
    assert session.findings[0].rule_id == "DET001"
