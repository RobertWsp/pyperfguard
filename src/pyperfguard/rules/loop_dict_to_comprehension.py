"""PKN021 — manual dict construction with for-loop (PERF403 equivalent).

    # BAD — explicit dict-build loop is slower and more verbose
    result = {}
    for k, v in pairs:
        result[k] = transform(v)

    # GOOD — dict comprehension is 1.2–1.5x faster
    result = {k: transform(v) for k, v in pairs}

Dict comprehensions use the dedicated ``MAP_ADD`` bytecode which avoids the
per-iteration ``__setitem__`` attribute lookup that the explicit loop incurs.

Detection heuristic:
- ``result[key] = value`` is the **only** statement in a ``for`` loop body.
- ``result = {}`` (or ``result: dict = {}``) appears as the **immediately
  preceding statement** in the same scope.
- The loop has no ``else`` clause.
- The loop body has no conditional logic.
- Not inside a nested loop (dict comprehension nesting is less readable).
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity


class LoopDictToComprehensionRule:
    id = "PKN021"
    name = "loop-dict-to-comprehension"
    severity = Severity.INFO
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.For,)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, ast.For)
        # Don't flag nested loops.
        if ctx.in_loop():
            return
        # No else clause.
        if node.orelse:
            return
        # Body must be a single statement.
        if len(node.body) != 1:
            return
        stmt = node.body[0]
        # Must be `result[key] = value` — a subscript assignment.
        if not isinstance(stmt, ast.Assign):
            return
        if len(stmt.targets) != 1:
            return
        target = stmt.targets[0]
        if not isinstance(target, ast.Subscript):
            return
        # Receiver must be a simple Name.
        receiver = target.value
        if not isinstance(receiver, ast.Name):
            return
        dict_var = receiver.id
        # Find immediately preceding `dict_var = {}` statement.
        if not self._has_preceding_empty_dict(dict_var, node, ctx):
            return
        yield Finding.from_node(
            rule_id=self.id,
            message=(
                f"``{dict_var} = {{}}; for ...: {dict_var}[key] = value`` can be "
                "replaced with a dict comprehension. "
                "Dict comprehensions use the dedicated ``MAP_ADD`` bytecode and "
                "avoid the per-iteration ``__setitem__`` lookup overhead."
            ),
            node=node,
            ctx=ctx,
            severity=self.severity,
            fix=Fix(description=f"Replace with ``{dict_var} = {{key: value for ... in ...}}``."),
        )

    @staticmethod
    def _has_preceding_empty_dict(var: str, for_node: ast.For, ctx: AstContext) -> bool:
        """Return True if the statement immediately before for_node is ``var = {}``."""
        parent_body: list[ast.stmt] | None = None
        for ancestor in reversed(ctx.ancestors):
            body = getattr(ancestor, "body", None)
            if isinstance(body, list) and for_node in body:
                parent_body = body
                break
        if parent_body is None:
            return False
        idx = parent_body.index(for_node)
        if idx == 0:
            return False
        prev = parent_body[idx - 1]
        # `var = {}`
        if isinstance(prev, ast.Assign):
            for tgt in prev.targets:
                if isinstance(tgt, ast.Name) and tgt.id == var:
                    if isinstance(prev.value, ast.Dict) and not prev.value.keys:
                        return True
        # `var: dict = {}` or `var: Dict[K, V] = {}`
        if isinstance(prev, ast.AnnAssign):
            tgt = prev.target
            if isinstance(tgt, ast.Name) and tgt.id == var:
                if isinstance(prev.value, ast.Dict) and not prev.value.keys:
                    return True
        return False
