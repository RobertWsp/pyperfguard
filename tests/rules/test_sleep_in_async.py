from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.rules.sleep_in_async import SleepInAsyncRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(SleepInAsyncRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_time_sleep_in_async_flagged():
    src = "import time\nasync def handler():\n    time.sleep(1)\n"
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN009"


def test_requests_get_in_async_flagged():
    src = "import requests\nasync def handler():\n    r = requests.get('http://example.com')\n"
    findings = _run(src)
    assert len(findings) == 1


def test_requests_post_in_async_flagged():
    src = "import requests\nasync def handler():\n    r = requests.post('http://example.com', data={})\n"
    findings = _run(src)
    assert len(findings) == 1


def test_time_sleep_in_sync_not_flagged():
    src = "import time\ndef worker():\n    time.sleep(1)\n"
    findings = _run(src)
    assert findings == []


def test_asyncio_sleep_not_flagged():
    src = "import asyncio\nasync def handler():\n    await asyncio.sleep(1)\n"
    findings = _run(src)
    assert findings == []


def test_aiohttp_not_flagged():
    src = (
        "import aiohttp\n"
        "async def handler():\n"
        "    async with aiohttp.ClientSession() as s:\n"
        "        r = await s.get('http://example.com')\n"
    )
    findings = _run(src)
    assert findings == []


def test_multiple_blocking_calls_multiple_findings():
    src = (
        "import time, requests\n"
        "async def handler():\n"
        "    time.sleep(1)\n"
        "    requests.get('http://x.com')\n"
    )
    findings = _run(src)
    assert len(findings) == 2
