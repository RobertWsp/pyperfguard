"""PKN011 — ``session.prepare()`` called inside a loop.

    # BAD
    for uid in user_ids:
        stmt = session.prepare("SELECT * FROM users WHERE id = ?")  # round-trip per call
        session.execute(stmt, [uid])

    # GOOD
    stmt = session.prepare("SELECT * FROM users WHERE id = ?")  # prepared once
    for uid in user_ids:
        session.execute(stmt, [uid])

``Session.prepare()`` sends a PREPARE request to the Cassandra coordinator,
waits for a response, and returns a ``PreparedStatement``.  Calling it in a
loop causes one unnecessary network round-trip per iteration.

The driver caches prepared statements by MD5 (client-side), so repeated calls
with the same CQL string are deduplicated — but this only works when the CQL
string is a literal constant.  f-string or dynamically-built CQL strings
bypass the cache and can exhaust the server-side prepared statement cache.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity


class CassandraPrepareLoopRule:
    id = "PKN011"
    name = "cassandra-prepare-in-loop"
    severity = Severity.WARNING
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.Call,)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, ast.Call)
        if not ctx.in_loop():
            return
        if not self._is_prepare_call(node):
            return
        yield Finding.from_node(
            rule_id=self.id,
            message=(
                "``session.prepare()`` called inside a loop causes one network "
                "round-trip per iteration. Prepare statements once at startup "
                "or class-level and reuse the ``PreparedStatement``."
            ),
            node=node,
            ctx=ctx,
            severity=self.severity,
            fix=Fix(description="Move ``stmt = session.prepare(...)`` outside the loop."),
        )

    @staticmethod
    def _is_prepare_call(node: ast.Call) -> bool:
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "prepare"):
            return False
        # Only flag prepare() when the first arg is a string (CQL query).
        # Two-Phase Commit `transaction.prepare()` has no string argument.
        if not node.args:
            return False
        first_arg = node.args[0]
        return isinstance(first_arg, (ast.Constant, ast.JoinedStr, ast.BinOp))
