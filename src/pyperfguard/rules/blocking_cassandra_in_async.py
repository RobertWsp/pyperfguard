"""PKN024 — synchronous Cassandra ``session.execute()`` inside an ``async def``.

    # BAD — blocks the asyncio event loop for the duration of the network round-trip
    async def get_contact(self, contact_id: UUID):
        result = self._session.execute(self._get_stmt, [contact_id])
        return result.one()

    # GOOD — run in executor to avoid blocking the event loop
    async def get_contact(self, contact_id: UUID):
        result = await self._executor.execute(self._get_stmt, [contact_id])
        return result.one()

The official ``cassandra-driver`` is synchronous.  Calling ``session.execute()``
directly inside an ``async def`` blocks the event loop thread for the full
latency of the Cassandra round-trip — typically 1–5 ms, but up to 100 ms+
under load — preventing other coroutines from running during that window.

The standard pattern in the user's stack is ``CassandraExecutor`` which wraps
``session.execute_async()`` (or ``loop.run_in_executor``) and exposes an
awaitable interface.

This rule detects the raw ``session.execute()`` / ``self._session.execute()``
call made **without** ``await`` inside an ``async def``.

Note: ``session.execute_async()`` is NOT flagged — it is the correct non-blocking
API (though typically wrapped in an async executor).
"""

from __future__ import annotations

import ast
from typing import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity

# Method names that are synchronous and block the event loop.
_BLOCKING_METHODS = frozenset({"execute", "execute_concurrent", "execute_concurrent_with_args"})

# Receiver names that indicate a raw Cassandra session (not an async executor).
_SESSION_RECEIVERS = frozenset(
    {
        "session",
        "_session",
        "cassandra_session",
        "_cassandra_session",
        "cluster_session",
    }
)


class BlockingCassandraInAsyncRule:
    id = "PKN024"
    name = "blocking-cassandra-in-async"
    severity = Severity.ERROR
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.Call,)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, ast.Call)
        if not ctx.in_async_function():
            return
        if not self._is_blocking_cassandra_call(node):
            return
        # Must NOT already be awaited (parent is an Await node).
        if self._is_awaited(ctx):
            return

        func = node.func
        assert isinstance(func, ast.Attribute)
        receiver_src = ctx.source_segment(func.value) or "session"

        yield Finding.from_node(
            rule_id=self.id,
            message=(
                f"``{receiver_src}.{func.attr}()`` is a synchronous Cassandra call "
                "inside an ``async def``. It blocks the event loop for the entire "
                "network round-trip. Use ``await executor.execute(...)`` or "
                "``await asyncio.get_event_loop().run_in_executor(None, ...)`` instead."
            ),
            node=node,
            ctx=ctx,
            severity=self.severity,
            fix=Fix(
                description=(
                    "Wrap in a CassandraExecutor and use ``await executor.execute(stmt, params)``."
                )
            ),
        )

    @staticmethod
    def _is_blocking_cassandra_call(call: ast.Call) -> bool:
        func = call.func
        if not isinstance(func, ast.Attribute):
            return False
        if func.attr not in _BLOCKING_METHODS:
            return False
        receiver = func.value
        if isinstance(receiver, ast.Name):
            return receiver.id in _SESSION_RECEIVERS
        if isinstance(receiver, ast.Attribute):
            return receiver.attr in _SESSION_RECEIVERS
        return False

    @staticmethod
    def _is_awaited(ctx: AstContext) -> bool:
        parent = ctx.parent_node()
        return isinstance(parent, ast.Await)
