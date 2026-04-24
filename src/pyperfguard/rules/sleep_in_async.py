"""PKN009 — blocking sleep / I/O calls inside an ``async def``.

    # BAD — blocks the entire event loop
    async def handler(request):
        time.sleep(1)          # blocks event loop thread
        requests.get("http://…")  # synchronous HTTP blocks event loop thread

    # GOOD
    async def handler(request):
        await asyncio.sleep(1)
        async with aiohttp.ClientSession() as s:
            await s.get("http://…")

The asyncio event loop runs on a single thread.  Any blocking call in a
coroutine pauses ALL other coroutines for the duration of the block, causing
latency spikes and timeouts.

Detected blocking patterns:
- ``time.sleep(…)`` → use ``await asyncio.sleep(…)``
- ``requests.get/post/put/delete/patch/head/request(…)``
  → use ``aiohttp``, ``httpx``, or wrap in ``asyncio.to_thread``
- ``urllib.request.urlopen(…)``
"""

from __future__ import annotations

import ast
from typing import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity

# (module_name_or_None, method_name) → replacement hint
_BLOCKING: dict[tuple[str | None, str], str] = {
    ("time", "sleep"): "``await asyncio.sleep(n)``",
    ("requests", "get"): "``async with aiohttp.ClientSession() as c: await c.get(url)``",
    ("requests", "post"): "``async with aiohttp.ClientSession() as c: await c.post(url, ...)``",
    ("requests", "put"): "use an async HTTP client (aiohttp, httpx)",
    ("requests", "delete"): "use an async HTTP client (aiohttp, httpx)",
    ("requests", "patch"): "use an async HTTP client (aiohttp, httpx)",
    ("requests", "head"): "use an async HTTP client (aiohttp, httpx)",
    ("requests", "request"): "use an async HTTP client (aiohttp, httpx)",
    ("urllib.request", "urlopen"): "use ``aiohttp`` or ``asyncio.to_thread``",
}


class SleepInAsyncRule:
    id = "PKN009"
    name = "blocking-call-in-async"
    severity = Severity.WARNING
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.Call,)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, ast.Call)
        if not ctx.in_async_function():
            return
        match = self._match_blocking(node)
        if match is None:
            return
        call_desc, replacement = match
        yield Finding.from_node(
            rule_id=self.id,
            message=(
                f"Blocking call ``{call_desc}`` inside ``async def`` blocks the event loop. "
                f"Use {replacement} instead."
            ),
            node=node,
            ctx=ctx,
            severity=self.severity,
            fix=Fix(description=f"Replace with {replacement}"),
        )

    @staticmethod
    def _match_blocking(node: ast.Call) -> tuple[str, str] | None:
        func = node.func
        if isinstance(func, ast.Attribute):
            attr = func.attr
            value = func.value
            if isinstance(value, ast.Name):
                key: tuple[str | None, str] = (value.id, attr)
                if key in _BLOCKING:
                    return f"{value.id}.{attr}()", _BLOCKING[key]
            if isinstance(value, ast.Attribute):
                # urllib.request.urlopen
                outer = getattr(value.value, "id", None)
                mid = value.attr
                if outer:
                    key2 = (f"{outer}.{mid}", attr)
                    if key2 in _BLOCKING:
                        return f"{outer}.{mid}.{attr}()", _BLOCKING[key2]
        return None
