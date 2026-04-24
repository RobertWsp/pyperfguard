"""Tests for PKN025: sequential await calls in a loop that could use asyncio.gather."""
from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.core.severity import Severity
from pyperfguard.rules.sequential_awaits_in_loop import SequentialAwaitsInLoopRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(SequentialAwaitsInLoopRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_simple_sequential_await_in_loop_flagged():
    src = (
        "async def f(items):\n"
        "    results = []\n"
        "    for item in items:\n"
        "        result = await fetch(item)\n"
        "        results.append(result)\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN025"
    assert findings[0].severity == Severity.WARNING


def test_async_for_with_await_flagged():
    src = (
        "async def f(aiter):\n"
        "    async for item in aiter:\n"
        "        result = await process(item)\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN025"


def test_sync_function_not_flagged():
    # No async def — await is invalid in sync
    src = (
        "def f(items):\n"
        "    for item in items:\n"
        "        result = fetch(item)\n"
    )
    findings = _run(src)
    assert findings == []


def test_no_await_in_loop_not_flagged():
    src = (
        "async def f(items):\n"
        "    for item in items:\n"
        "        process(item)\n"
    )
    findings = _run(src)
    assert findings == []


def test_data_dependency_not_flagged():
    # Result of first await used in second — can't parallelize with gather.
    src = (
        "async def f(items):\n"
        "    for item in items:\n"
        "        page = await fetch_page(item)\n"
        "        result = await process(page)\n"
    )
    findings = _run(src)
    assert findings == []


def test_nested_loop_not_flagged():
    # Don't flag nested loops — gather inside gather is complex.
    src = (
        "async def f(rows):\n"
        "    for row in rows:\n"
        "        for item in row:\n"
        "            result = await fetch(item)\n"
    )
    findings = _run(src)
    assert findings == []


def test_message_mentions_gather():
    src = (
        "async def f(items):\n"
        "    for item in items:\n"
        "        result = await fetch(item)\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert "gather" in findings[0].message


def test_expr_await_in_loop_flagged():
    # Standalone `await call()` without assignment.
    src = (
        "async def f(items):\n"
        "    for item in items:\n"
        "        await notify(item)\n"
    )
    findings = _run(src)
    assert len(findings) == 1
