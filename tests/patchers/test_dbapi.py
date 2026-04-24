"""Tests for the generic DB-API 2.0 patcher.

We use sqlite3 (stdlib) as the real driver — no extra deps needed.
"""

from __future__ import annotations

import sqlite3
import types

import pytest

from pyperfguard.patchers.dbapi import DBAPIPatcher, unwrap_connect, wrap_connect
from pyperfguard.runtime_engine.event_bus import get_event_bus, reset_event_bus
from pyperfguard.runtime_engine.events import QueryEvent
from pyperfguard.runtime_engine.scope import Scope, set_scope


@pytest.fixture(autouse=True)
def _clean_bus():
    reset_event_bus()
    yield
    reset_event_bus()


@pytest.fixture
def fake_module():
    """Minimal module-like object with a connect function pointing to sqlite3."""
    m = types.ModuleType("fake_db")
    m.connect = sqlite3.connect
    return m


def test_wrap_stores_original(fake_module):
    wrap_connect(fake_module, "sqlite")
    assert hasattr(fake_module, "_pyperfguard_original_connect")
    assert fake_module._pyperfguard_original_connect is sqlite3.connect


def test_unwrap_restores_original(fake_module):
    wrap_connect(fake_module, "sqlite")
    unwrap_connect(fake_module)
    assert fake_module.connect is sqlite3.connect
    assert not hasattr(fake_module, "_pyperfguard_original_connect")


def test_unwrap_is_idempotent(fake_module):
    unwrap_connect(fake_module)  # no-op, should not raise


def test_instrumented_cursor_wraps_execute(fake_module):
    events: list[QueryEvent] = []
    get_event_bus().subscribe(lambda e: events.append(e) if isinstance(e, QueryEvent) else None)

    wrap_connect(fake_module, "sqlite")
    conn = fake_module.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
    cur.execute("INSERT INTO t VALUES (1)")

    assert len(events) == 2
    assert all(e.db_system == "sqlite" for e in events)
    assert all(e.fingerprint is not None for e in events)


def test_instrumented_cursor_records_to_scope(fake_module):
    scope = Scope(name="test")
    token = set_scope(scope)
    try:
        wrap_connect(fake_module, "sqlite")
        conn = fake_module.connect(":memory:")
        cur = conn.cursor()
        cur.execute("SELECT 1")
    finally:
        from pyperfguard.runtime_engine.scope import reset_scope
        reset_scope(token)

    q_events = [e for e in scope.events() if isinstance(e, QueryEvent)]
    assert len(q_events) == 1
    assert q_events[0].db_system == "sqlite"


def test_patcher_install_uninstall(fake_module):
    patcher = DBAPIPatcher(target_module_name="fake_db", db_system="sqlite")
    patcher.install(fake_module)
    assert hasattr(fake_module, "_pyperfguard_original_connect")
    patcher.uninstall(fake_module)
    assert not hasattr(fake_module, "_pyperfguard_original_connect")


def test_patcher_install_idempotent(fake_module):
    patcher = DBAPIPatcher(target_module_name="fake_db", db_system="sqlite")
    patcher.install(fake_module)
    original_patched = fake_module.connect
    patcher.install(fake_module)  # second install — should not double-wrap
    assert fake_module.connect is original_patched
    patcher.uninstall(fake_module)


def test_patcher_skips_module_without_connect():
    m = types.ModuleType("no_connect")
    patcher = DBAPIPatcher("no_connect", "x")
    patcher.install(m)  # should not raise


def test_cursor_passthrough_attributes(fake_module):
    wrap_connect(fake_module, "sqlite")
    conn = fake_module.connect(":memory:")
    cur = conn.cursor()
    cur.execute("SELECT 1")
    # fetchone proxied through __getattr__
    row = cur.fetchone()
    assert row == (1,)


def test_connection_passthrough_commit(fake_module):
    wrap_connect(fake_module, "sqlite")
    conn = fake_module.connect(":memory:")
    # commit is proxied through __getattr__
    conn.commit()  # should not raise
