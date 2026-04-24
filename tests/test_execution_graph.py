"""Tests for ExecutionGraphN1Detector — stack-aware cross-function N+1 detection."""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from pyperfguard.core.finding import Location
from pyperfguard.core.severity import Severity
from pyperfguard.detectors.execution_graph import ExecutionGraphN1Detector, _format_execution_chain
from pyperfguard.runtime_engine.events import QueryEvent
from pyperfguard.runtime_engine.scope import Scope


def _make_event(fingerprint: str, stack: tuple[str, ...], duration_s: float = 0.01) -> QueryEvent:
    return QueryEvent(
        fingerprint=fingerprint,
        db_system="cassandra",
        statement=f"SELECT * FROM t WHERE id = ?",
        duration_s=duration_s,
        call_site=hash(stack),
        stack_frames=stack,
    )


def _stack(*frames: str) -> tuple[str, ...]:
    """Build a fake stack: frames[0] = deepest (execute), frames[-1] = handler."""
    return frames


def test_n1_detected_above_threshold():
    scope = Scope(name="GET /contacts")
    stack_prefix = (
        "executor.py:42 in execute",
        "service.py:88 in get_contact",
        "router.py:12 in list_contacts",
    )
    for i in range(5):
        scope.record(_make_event("fp1", stack_prefix))

    detector = ExecutionGraphN1Detector(threshold=3)
    findings = detector.evaluate(scope)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN101"
    assert findings[0].severity == Severity.ERROR


def test_below_threshold_not_flagged():
    scope = Scope(name="GET /x")
    stack = ("executor.py:42 in execute", "service.py:10 in get",)
    for _ in range(2):
        scope.record(_make_event("fp2", stack))

    detector = ExecutionGraphN1Detector(threshold=3)
    findings = detector.evaluate(scope)
    assert findings == []


def test_different_stack_prefix_not_grouped():
    """Two different handlers calling the same function — NOT N+1."""
    scope = Scope(name="batch")
    stack_a = ("executor.py:42 in execute", "service.py:10 in get", "handler_a.py:5 in ep_a",)
    stack_b = ("executor.py:42 in execute", "service.py:10 in get", "handler_b.py:7 in ep_b",)
    for _ in range(3):
        scope.record(_make_event("fp3", stack_a))
        scope.record(_make_event("fp3", stack_b))

    detector = ExecutionGraphN1Detector(threshold=3)
    findings = detector.evaluate(scope)
    # Each group has 3 events but different prefixes → both flagged (or none if threshold higher)
    # Here each prefix appears 3 times — both flagged.
    assert len(findings) == 2


def test_same_fingerprint_different_prefix_not_grouped():
    """Same query template, different call paths → separate groups."""
    scope = Scope(name="mixed")
    for _ in range(4):
        scope.record(_make_event("fp4", ("exec.py:1 in execute", "svc.py:10 in method_a",)))
    for _ in range(4):
        scope.record(_make_event("fp4", ("exec.py:1 in execute", "svc.py:20 in method_b",)))

    detector = ExecutionGraphN1Detector(threshold=3)
    findings = detector.evaluate(scope)
    assert len(findings) == 2


def test_finding_contains_execution_chain():
    scope = Scope(name="GET /test")
    stack = (
        "executor.py:42 in execute",
        "service.py:50 in get_messages",
        "router.py:15 in list_conversations",
    )
    for _ in range(4):
        scope.record(_make_event("fp5", stack))

    detector = ExecutionGraphN1Detector(threshold=3)
    findings = detector.evaluate(scope)
    assert len(findings) == 1
    assert "list_conversations" in findings[0].message or "get_messages" in findings[0].message


def test_format_execution_chain():
    frames = (
        "executor.py:42 in execute",
        "service.py:50 in get_messages",
        "router.py:15 in list_conversations",
    )
    chain = _format_execution_chain(frames)
    # Should be outermost → innermost: list_conversations → get_messages → execute
    assert "list_conversations" in chain
    assert "get_messages" in chain
    assert "execute" in chain
    assert chain.index("list_conversations") < chain.index("execute")


def test_empty_scope_no_findings():
    scope = Scope(name="empty")
    detector = ExecutionGraphN1Detector(threshold=3)
    assert detector.evaluate(scope) == []


def test_db_system_filter():
    scope = Scope(name="mixed_db")
    cass_stack = ("exec.py:1 in execute", "svc.py:5 in fn",)
    sql_stack = ("sql.py:1 in execute", "svc.py:5 in fn",)

    for _ in range(5):
        scope.record(QueryEvent(
            fingerprint="cass_fp",
            db_system="cassandra",
            statement="SELECT ...",
            stack_frames=cass_stack,
        ))
    for _ in range(5):
        scope.record(QueryEvent(
            fingerprint="sql_fp",
            db_system="postgresql",
            statement="SELECT ...",
            stack_frames=sql_stack,
        ))

    detector = ExecutionGraphN1Detector(threshold=3, db_systems=frozenset({"cassandra"}))
    findings = detector.evaluate(scope)
    assert len(findings) == 1
    assert findings[0].extra["db_system"] == "cassandra"
