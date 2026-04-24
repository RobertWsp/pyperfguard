"""Tests for PKN024: synchronous Cassandra session.execute() inside async def."""
from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.core.severity import Severity
from pyperfguard.rules.blocking_cassandra_in_async import BlockingCassandraInAsyncRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(BlockingCassandraInAsyncRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_session_execute_in_async_flagged():
    src = (
        "async def get(self, id):\n"
        "    result = self._session.execute(stmt, [id])\n"
        "    return result.one()\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN024"
    assert findings[0].severity == Severity.ERROR


def test_session_execute_in_sync_not_flagged():
    src = (
        "def get(self, id):\n"
        "    result = self._session.execute(stmt, [id])\n"
        "    return result.one()\n"
    )
    findings = _run(src)
    assert findings == []


def test_awaited_execute_not_flagged():
    # await executor.execute() is the correct pattern
    src = (
        "async def get(self, id):\n"
        "    result = await self._executor.execute(stmt, [id])\n"
        "    return result.one()\n"
    )
    findings = _run(src)
    assert findings == []


def test_session_execute_async_not_flagged():
    # execute_async() is the non-blocking API
    src = (
        "async def get(self, id):\n"
        "    future = self._session.execute_async(stmt, [id])\n"
        "    return future.result()\n"
    )
    findings = _run(src)
    assert findings == []


def test_plain_session_receiver_flagged():
    src = (
        "async def get(self, id):\n"
        "    result = session.execute(stmt, [id])\n"
        "    return result.one()\n"
    )
    findings = _run(src)
    assert len(findings) == 1


def test_cassandra_session_receiver_flagged():
    src = (
        "async def get(self):\n"
        "    return cassandra_session.execute(stmt)\n"
    )
    findings = _run(src)
    assert len(findings) == 1


def test_message_mentions_executor():
    src = (
        "async def get(self, id):\n"
        "    result = self._session.execute(stmt, [id])\n"
        "    return result.one()\n"
    )
    findings = _run(src)
    assert "executor" in findings[0].message.lower() or "event loop" in findings[0].message.lower()
