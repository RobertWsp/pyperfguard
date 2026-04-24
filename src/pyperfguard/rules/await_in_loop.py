"""PKN008 — ``await`` inside a regular ``for`` loop (serializes async work).

    # BAD — N coroutines serialised
    async def fetch_users(ids):
        users = []
        for uid in ids:
            user = await fetch_user(uid)   # each waits for the previous
            users.append(user)
        return users

    # GOOD — N coroutines run concurrently
    async def fetch_users(ids):
        return await asyncio.gather(*[fetch_user(uid) for uid in ids])

    # ALSO GOOD (with backpressure)
    async def fetch_users(ids):
        sem = asyncio.Semaphore(50)
        async def bounded(uid):
            async with sem:
                return await fetch_user(uid)
        return await asyncio.gather(*[bounded(uid) for uid in ids])

A bare ``await`` inside a ``for`` loop is the async equivalent of the N+1
query problem: you pay the full round-trip latency for each item sequentially.
Use ``asyncio.gather`` (or ``asyncio.TaskGroup`` in 3.11+) to fan out
independent coroutines in parallel.

Note: ``async for`` loops over an async iterator are **not** flagged — they
are already the correct pattern for streaming data.
"""

from __future__ import annotations

import ast
from typing import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity


def _for_target_names(target: ast.AST) -> set[str]:
    names: set[str] = set()
    if isinstance(target, ast.Name):
        names.add(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            names |= _for_target_names(elt)
    return names


class AwaitInLoopRule:
    id = "PKN008"
    name = "await-in-sync-for-loop"
    severity = Severity.WARNING
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.Await,)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, ast.Await)
        # Only relevant inside an async function.
        if not ctx.in_async_function():
            return
        # Only flag if inside a *regular* for loop body (not async for).
        if not ctx.in_sync_for_loop():
            return
        # Async generators (async def + yield) produce items sequentially by design.
        if self._in_async_generator(ctx):
            return
        # Skip if the await is already the argument of asyncio.gather/TaskGroup.
        if self._inside_gather(ctx):
            return
        # await asyncio.sleep() in a loop is an intentional rate-limiter/backoff.
        if self._is_asyncio_sleep(node.value):
            return
        # Sequential protocol/stream reads don't use the loop variable as an arg
        # (e.g. `await conn.read_response()` in a loop to parse N items from a stream).
        # These coroutines are inherently ordered and can't be parallelised.
        if self._is_sequential_stream_read(node.value, ctx):
            return
        yield Finding.from_node(
            rule_id=self.id,
            message=(
                "``await`` inside a ``for`` loop serialises async work. "
                "Use ``asyncio.gather(*[coro(x) for x in xs])`` to run "
                "independent coroutines concurrently."
            ),
            node=node,
            ctx=ctx,
            severity=self.severity,
            fix=Fix(
                description=(
                    "Replace the loop with "
                    "``results = await asyncio.gather(*[coro(item) for item in items])``"
                )
            ),
        )

    @staticmethod
    def _in_async_generator(ctx: AstContext) -> bool:
        """Return True if we're inside an async generator (async def + yield).

        In async generators, sequential yielding is the contract — items must be
        produced in order and the caller controls consumption rate.
        """
        func = ctx.enclosing_function()
        if func is None:
            return False
        for child in ast.walk(func):
            if isinstance(child, ast.Yield):
                return True
        return False

    @staticmethod
    def _inside_gather(ctx: AstContext) -> bool:
        """Return True if any ancestor Call is asyncio.gather / TaskGroup."""
        for a in ctx.ancestors:
            if isinstance(a, ast.Call):
                func = a.func
                if isinstance(func, ast.Attribute) and func.attr in ("gather", "__aenter__"):
                    return True
                if isinstance(func, ast.Name) and func.id == "gather":
                    return True
        return False

    @staticmethod
    def _is_asyncio_sleep(expr: ast.AST) -> bool:
        """Return True for asyncio.sleep(...) — intentional rate-limiter pattern."""
        if not isinstance(expr, ast.Call):
            return False
        func = expr.func
        if isinstance(func, ast.Attribute) and func.attr == "sleep":
            return True
        if isinstance(func, ast.Name) and func.id == "sleep":
            return True
        return False

    @staticmethod
    def _is_sequential_stream_read(expr: ast.AST, ctx: AstContext) -> bool:
        """Return True when none of the call's arguments are the loop iteration variable.

        Protocol/stream parsers read N items sequentially with no dependency on the
        loop variable (e.g. ``await conn.read_response()``).  These can't be
        parallelised and should not be flagged as async N+1.
        """
        if not isinstance(expr, ast.Call):
            return False
        loop = ctx.enclosing_loop()
        if loop is None or not isinstance(loop, ast.For):
            return False
        loop_vars = _for_target_names(loop.target)
        if not loop_vars or loop_vars == {"_"}:
            # Unused loop var (_ pattern) → counting loop, not data-parallel
            return True
        # Collect Name ids used as direct positional or keyword args
        arg_names: set[str] = set()
        for arg in expr.args:
            if isinstance(arg, ast.Name):
                arg_names.add(arg.id)
        for kw in expr.keywords:
            if isinstance(kw.value, ast.Name):
                arg_names.add(kw.value.id)
        # If no loop variable appears as an argument, the call doesn't depend on
        # the current iteration value — likely sequential I/O, not N+1.
        return not bool(arg_names & loop_vars)
