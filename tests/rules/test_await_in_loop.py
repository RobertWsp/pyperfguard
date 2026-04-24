from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.rules.await_in_loop import AwaitInLoopRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(AwaitInLoopRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_await_in_sync_for_flagged():
    src = (
        "async def fetch(ids):\n"
        "    results = []\n"
        "    for uid in ids:\n"
        "        user = await fetch_user(uid)\n"
        "        results.append(user)\n"
        "    return results\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN008"


def test_await_in_async_for_not_flagged():
    src = (
        "async def consume(stream):\n"
        "    async for item in stream:\n"
        "        result = await process(item)\n"
    )
    findings = _run(src)
    # async for is not a sync for loop — should NOT be flagged
    assert findings == []


def test_await_outside_loop_not_flagged():
    src = (
        "async def fetch_one():\n"
        "    return await db.get(1)\n"
    )
    findings = _run(src)
    assert findings == []


def test_await_in_non_async_function_not_flagged():
    # Syntactically invalid in Python — but if parsed, should not flag.
    # We test with async function to avoid SyntaxError.
    src = (
        "async def f(ids):\n"
        "    for uid in ids:\n"
        "        pass\n"
    )
    findings = _run(src)
    assert findings == []


def test_await_inside_gather_not_flagged():
    src = (
        "import asyncio\n"
        "async def fetch_all(ids):\n"
        "    return await asyncio.gather(*[fetch(uid) for uid in ids])\n"
    )
    findings = _run(src)
    assert findings == []


def test_await_in_while_loop_not_flagged():
    # PKN008 targets regular 'for' loops specifically (not 'while').
    # await in while is a common valid pattern (e.g. polling loops).
    src = (
        "async def poll():\n"
        "    while True:\n"
        "        data = await socket.recv()\n"
    )
    findings = _run(src)
    assert findings == []


def test_await_asyncio_sleep_in_loop_not_flagged():
    # Regression: `await asyncio.sleep(delay)` in a for loop is an intentional
    # rate-limiter / backoff pattern (common in scrapers, crawlers, retriers).
    src = (
        "import asyncio\n"
        "async def crawl(urls):\n"
        "    for url in urls:\n"
        "        result = await fetch(url)\n"
        "        await asyncio.sleep(0.5)\n"
    )
    findings = _run(src)
    # Only fetch() should be flagged, not sleep()
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN008"


def test_await_sleep_bare_import_not_flagged():
    # `from asyncio import sleep; await sleep(1)` — same pattern, different import style.
    src = (
        "from asyncio import sleep\n"
        "async def throttle(items):\n"
        "    for item in items:\n"
        "        await sleep(1)\n"
    )
    findings = _run(src)
    assert findings == []


def test_async_generator_not_flagged():
    # Regression: async generators (yield inside async def) produce items sequentially
    # by design — parallelising would break the generator contract.
    src = (
        "async def pages(session, page_count):\n"
        "    for page_num in range(page_count):\n"
        "        yield await session.get_page(page_num)\n"
    )
    findings = _run(src)
    assert findings == []


def test_sequential_stream_read_no_loop_var_not_flagged():
    # Regression: redis/aiohttp protocol parsers read N items sequentially
    # without using the loop variable as an argument.
    src = (
        "async def _read_array(self, length):\n"
        "    result = []\n"
        "    for _ in range(length):\n"
        "        obj = await self._read_response()\n"
        "        result.append(obj)\n"
        "    return result\n"
    )
    findings = _run(src)
    assert findings == []


def test_sequential_read_with_loop_var_still_flagged():
    # If the loop var IS used as an arg, it's likely an independent coroutine per item.
    src = (
        "async def fetch_all(self, ids):\n"
        "    for uid in ids:\n"
        "        result = await self.fetch(uid)\n"
    )
    findings = _run(src)
    assert len(findings) == 1
