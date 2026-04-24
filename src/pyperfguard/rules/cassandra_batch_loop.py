"""PKN013 — ``BatchStatement.add()`` called inside a loop (potential multi-partition batch).

    # BAD — multi-partition batch stresses the coordinator
    batch = BatchStatement(batch_type=BatchType.UNLOGGED)
    for row in rows:          # rows span many partition keys
        batch.add(insert_stmt, (row.id, row.data))
    session.execute(batch)

    # GOOD — parallel per-partition queries, token-aware routing
    execute_concurrent_with_args(session, insert_stmt,
                                 [(r.id, r.data) for r in rows],
                                 concurrency=50)

``BatchStatement`` in Cassandra is **not** a performance optimisation for
multi-partition writes (unlike SQL bulk INSERT).  Each sub-statement in a batch
is sent to all partition replicas and the coordinator collects acknowledgements.
For multi-partition batches this is strictly slower than individual parallel
writes and creates a SPOF on the coordinator.

Batches are only a correctness tool (atomic visibility on a *single* partition)
or a tiny latency win when all statements share the same partition key.

Detection heuristic: ``.add()`` call inside a loop on a variable whose name
contains "batch" or is known to be a ``BatchStatement``.

LOGGED batches are flagged at INFO level — they serve an atomicity purpose but
carry the same coordinator overhead. UNLOGGED batches are flagged at WARNING.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity


class CassandraBatchLoopRule:
    id = "PKN013"
    name = "cassandra-batch-in-loop"
    severity = Severity.WARNING
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.Call,)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, ast.Call)
        if not ctx.in_loop():
            return
        if not self._is_batch_add(node):
            return

        func = node.func
        assert isinstance(func, ast.Attribute)
        receiver = func.value
        batch_var = receiver.id if isinstance(receiver, ast.Name) else None
        batch_type = self._resolve_batch_type(batch_var, ctx) if batch_var else None

        if batch_type == "LOGGED":
            yield Finding.from_node(
                rule_id=self.id,
                message=(
                    "LOGGED ``BatchStatement.add()`` called inside a loop. "
                    "LOGGED batches provide atomicity but still incur coordinator overhead "
                    "for multi-partition writes. If atomicity across rows is the goal, "
                    "this may be intentional. If performance is the goal, use "
                    "``execute_concurrent_with_args`` with individual writes instead."
                ),
                node=node,
                ctx=ctx,
                severity=Severity.INFO,
                fix=Fix(
                    description=(
                        "For performance: replace with "
                        "``cassandra.concurrent.execute_concurrent_with_args``."
                    )
                ),
            )
        else:
            yield Finding.from_node(
                rule_id=self.id,
                message=(
                    "``BatchStatement.add()`` called inside a loop. "
                    "Multi-partition UNLOGGED batches are slower than parallel individual "
                    "writes and add coordinator pressure. "
                    "Use ``execute_concurrent_with_args(session, stmt, params, concurrency=50)`` instead."
                ),
                node=node,
                ctx=ctx,
                severity=self.severity,
                fix=Fix(
                    description=(
                        "Replace the batch loop with "
                        "``cassandra.concurrent.execute_concurrent_with_args``."
                    )
                ),
            )

    @staticmethod
    def _is_batch_add(node: ast.Call) -> bool:
        func = node.func
        if not isinstance(func, ast.Attribute):
            return False
        if func.attr != "add":
            return False
        # Heuristic: receiver name contains "batch"
        receiver = func.value
        return bool(isinstance(receiver, ast.Name) and "batch" in receiver.id.lower())

    @staticmethod
    def _resolve_batch_type(batch_var: str, ctx: AstContext) -> str | None:
        """Scan the enclosing function for `batch_var = BatchStatement(...)` and return batch type.

        Returns "LOGGED", "UNLOGGED", "COUNTER", or None (unknown/not found).
        """
        func = ctx.enclosing_function()
        scope: ast.AST = func if func is not None else ctx.module
        for stmt in ast.walk(scope):
            if not isinstance(stmt, ast.Assign):
                continue
            for target in stmt.targets:
                if not (isinstance(target, ast.Name) and target.id == batch_var):
                    continue
                if not isinstance(stmt.value, ast.Call):
                    continue
                call = stmt.value
                # Check positional arg: BatchStatement(BatchType.UNLOGGED)
                if call.args:
                    arg = call.args[0]
                    if isinstance(arg, ast.Attribute):
                        return arg.attr.upper()
                # Check keyword arg: BatchStatement(batch_type=BatchType.LOGGED)
                for kw in call.keywords:
                    if kw.arg == "batch_type" and isinstance(kw.value, ast.Attribute):
                        return kw.value.attr.upper()
        return None
