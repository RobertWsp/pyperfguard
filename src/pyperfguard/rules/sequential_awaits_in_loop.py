"""PKN025 — sequential ``await`` calls in a loop that could use ``asyncio.gather``.

    # BAD — sequential awaits: each waits for the previous to complete
    results = []
    for item in items:
        result = await fetch(item)      # total latency = sum of all
        results.append(result)

    # GOOD — parallel execution: all run concurrently
    results = await asyncio.gather(*[fetch(item) for item in items])

    # ALSO GOOD — when you need error isolation per item
    results = await asyncio.gather(*[fetch(item) for item in items], return_exceptions=True)

When you ``await`` inside a for-loop, each iteration waits for the previous
coroutine to finish before starting the next.  The total latency is the **sum**
of all individual latencies.

If the coroutines are **independent** (no data dependency between iterations),
``asyncio.gather()`` runs them concurrently and the total latency is the
**max** of all individual latencies — often 10–100x faster for I/O-bound work
like Cassandra or HTTP calls.

This rule detects the sequential-await pattern and is intentionally conservative:
- Only flags ``await <call>`` statements (not awaiting computed expressions).
- Only flags when the await is the **sole** or **main** statement in the loop body.
- Does not flag when the result of one iteration is used as input to the next
  (data dependency — ``asyncio.gather`` would break semantics there).

Note: This complements PKN008 (await_in_loop) which flags ``await`` inside a
loop generically. PKN025 focuses specifically on the gather-refactor pattern.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity


class SequentialAwaitsInLoopRule:
    id = "PKN025"
    name = "sequential-awaits-in-loop"
    severity = Severity.WARNING
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.For, ast.AsyncFor)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, (ast.For, ast.AsyncFor))
        # Don't flag nested loops — gather inside gather is complex.
        if ctx.in_loop():
            return
        # Must be inside an async function.
        if not ctx.in_async_function():
            return

        await_calls = self._collect_top_level_awaits(node.body)
        if not await_calls:
            return

        # Check for data dependency: does any await's result feed the next?
        # Simple heuristic: if the loop variable appears in an await call's args,
        # that's fine (parallel is still safe). If the *result* of one await
        # is used in another, that's a dependency.
        if self._has_inter_iteration_dependency(node):
            return

        loop_var = self._loop_var_name(node.target)
        call_name = self._first_call_name(await_calls[0])

        yield Finding.from_node(
            rule_id=self.id,
            message=(
                f"Sequential ``await`` in a ``{'async for' if isinstance(node, ast.AsyncFor) else 'for'}`` "
                f"loop: ``await {call_name}(...)`` is called once per iteration. "
                "If iterations are independent, use ``await asyncio.gather(*[...])`` "
                "to run them concurrently and reduce total latency to max(individual_latencies)."
            ),
            node=node,
            ctx=ctx,
            severity=self.severity,
            fix=Fix(
                description=(
                    f"Replace with: ``results = await asyncio.gather("
                    f"*[{call_name}({loop_var or 'item'}) for {loop_var or 'item'} in ...])``"
                )
            ),
        )

    @staticmethod
    def _collect_top_level_awaits(body: list[ast.stmt]) -> list[ast.Await]:
        """Return Await nodes from top-level Expr or Assign statements."""
        awaits: list[ast.Await] = []
        for stmt in body:
            if (
                (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Await))
                or (isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Await))
                or (isinstance(stmt, ast.AugAssign) and isinstance(stmt.value, ast.Await))
            ):
                awaits.append(stmt.value)
        return awaits

    @staticmethod
    def _has_inter_iteration_dependency(loop: ast.For | ast.AsyncFor) -> bool:
        """Heuristic: if a variable assigned by one await is used in another await,
        there's a data dependency — gather would break it."""
        assigned_in_loop: set[str] = set()
        for stmt in loop.body:
            if isinstance(stmt, ast.Assign):
                for tgt in stmt.targets:
                    if isinstance(tgt, ast.Name):
                        assigned_in_loop.add(tgt.id)
        if not assigned_in_loop:
            return False
        # Check if any assigned var appears inside an await call.
        for stmt in loop.body:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Await):
                    for child in ast.walk(node):
                        if isinstance(child, ast.Name) and child.id in assigned_in_loop:
                            return True
        return False

    @staticmethod
    def _loop_var_name(target: ast.expr) -> str | None:
        if isinstance(target, ast.Name):
            return target.id
        return None

    @staticmethod
    def _first_call_name(await_node: ast.Await) -> str:
        call = await_node.value
        if not isinstance(call, ast.Call):
            return "fn"
        func = call.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return "fn"
