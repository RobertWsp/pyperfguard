from __future__ import annotations

import time

import pytest

from pyperfguard.core.severity import Severity
from pyperfguard.detectors.nplusone import NPlusOneDetector
from pyperfguard.runtime_engine.events import QueryEvent
from pyperfguard.runtime_engine.scope import Scope


def _make_event(fp: str, call_site: int = 1, db: str = "postgresql", dur: float = 0.001) -> QueryEvent:
    return QueryEvent(
        kind="query",
        fingerprint=fp,
        timestamp=time.time(),
        call_site=call_site,
        db_system=db,
        statement=f"SELECT * FROM t WHERE id = ?  -- fp={fp}",
        duration_s=dur,
    )


@pytest.fixture
def scope():
    return Scope(name="test-scope")


def test_no_findings_below_threshold(scope):
    det = NPlusOneDetector(threshold=5)
    for _ in range(4):
        scope.record(_make_event("fp1"))
    findings = list(det.evaluate(scope))
    assert findings == []


def test_fires_at_threshold(scope):
    det = NPlusOneDetector(threshold=5)
    for _ in range(5):
        scope.record(_make_event("fp1"))
    findings = list(det.evaluate(scope))
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN100"
    assert findings[0].severity is Severity.ERROR


def test_fires_above_threshold(scope):
    det = NPlusOneDetector(threshold=3)
    for _ in range(10):
        scope.record(_make_event("fp1"))
    findings = list(det.evaluate(scope))
    assert len(findings) == 1
    assert findings[0].extra["count"] == 10


def test_different_call_sites_not_nplusone(scope):
    det = NPlusOneDetector(threshold=3)
    # Same fingerprint but different call sites → not N+1
    for i in range(5):
        scope.record(_make_event("fp1", call_site=i))
    findings = list(det.evaluate(scope))
    assert findings == []


def test_different_fingerprints_separate_findings(scope):
    det = NPlusOneDetector(threshold=3)
    for _ in range(5):
        scope.record(_make_event("fp1", call_site=1))
    for _ in range(5):
        scope.record(_make_event("fp2", call_site=2))
    findings = list(det.evaluate(scope))
    assert len(findings) == 2


def test_db_system_filter(scope):
    det = NPlusOneDetector(threshold=3, db_systems=frozenset({"postgresql"}))
    for _ in range(5):
        scope.record(_make_event("fp1", db="cassandra"))
    findings = list(det.evaluate(scope))
    assert findings == []


def test_db_system_filter_matches(scope):
    det = NPlusOneDetector(threshold=3, db_systems=frozenset({"cassandra"}))
    for _ in range(5):
        scope.record(_make_event("fp1", db="cassandra"))
    findings = list(det.evaluate(scope))
    assert len(findings) == 1


def test_min_duration_filters_fast_queries(scope):
    det = NPlusOneDetector(threshold=3, min_duration_ms=1000.0)
    for _ in range(5):
        scope.record(_make_event("fp1", dur=0.001))  # 1ms each, total 5ms
    findings = list(det.evaluate(scope))
    assert findings == []


def test_min_duration_passes_slow_queries(scope):
    det = NPlusOneDetector(threshold=3, min_duration_ms=1.0)
    for _ in range(5):
        scope.record(_make_event("fp1", dur=1.0))  # 1s each, total 5000ms
    findings = list(det.evaluate(scope))
    assert len(findings) == 1


def test_finding_extra_contains_metadata(scope):
    det = NPlusOneDetector(threshold=3)
    for _ in range(5):
        scope.record(_make_event("fp1", db="postgresql"))
    findings = list(det.evaluate(scope))
    extra = findings[0].extra
    assert extra["count"] == 5
    assert extra["fingerprint"] == "fp1"
    assert extra["db_system"] == "postgresql"
    assert extra["scope_name"] == "test-scope"
    assert "total_ms" in extra


def test_empty_scope_no_findings(scope):
    det = NPlusOneDetector(threshold=3)
    assert list(det.evaluate(scope)) == []
