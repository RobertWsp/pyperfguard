"""PKN019 — manual list construction with for-loop and ``.append()`` (PERF401).

    # BAD — explicit append loop is slower and less Pythonic
    result = []
    for item in items:
        result.append(transform(item))

    # GOOD — list comprehension is 1.3–2x faster
    result = [transform(item) for item in items]

List comprehensions are faster than equivalent for-loop + append() patterns:

1. **No per-iteration attribute lookup**: ``list.append`` must be resolved
   on every iteration in a loop; the comprehension uses a dedicated
   ``LIST_APPEND`` bytecode with no attribute lookup.
2. **Optimized bytecode**: CPython generates specialised bytecode for
   comprehensions that avoids the overhead of a generic function call.
3. **Clarity**: The comprehension expresses intent in a single expression.

Detection heuristic:
- ``result.append(expr)`` is the **only** statement in a ``for`` loop body.
- ``result = []`` (or ``result: list = []``) appears as the **immediately
  preceding statement** in the same scope.
- The loop has no ``else`` clause.
- The loop body has no conditional logic (``if``/``break``/``continue``).

Note: Loops with conditions (``if`` guards) should use a comprehension with
a filter expression: ``[f(x) for x in xs if cond(x)]``.
"""

from __future__ import annotations

import ast
from typing import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity


class LoopAppendToComprehensionRule:
    id = "PKN019"
    name = "loop-append-to-comprehension"
    severity = Severity.INFO
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.For,)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, ast.For)
        # Don't flag nested loops — comprehension nesting is less readable.
        if ctx.in_loop():
            return
        # Must have no else clause.
        if node.orelse:
            return
        # Body must be a single expression statement — the .append() call.
        if len(node.body) != 1 or not isinstance(node.body[0], ast.Expr):
            return
        call_expr = node.body[0].value
        if not isinstance(call_expr, ast.Call):
            return
        # Must be <name>.append(<expr>) — receiver is a simple Name.
        target_var = self._append_target(call_expr)
        if target_var is None:
            return
        # Must have exactly one positional argument (the value being appended).
        if len(call_expr.args) != 1 or call_expr.keywords or call_expr.starargs if hasattr(call_expr, 'starargs') else call_expr.keywords:
            return
        # Find immediately preceding statement in parent body.
        if not self._has_preceding_empty_list(target_var, node, ctx):
            return
        yield Finding.from_node(
            rule_id=self.id,
            message=(
                f"``{target_var} = []; for ...: {target_var}.append(...)`` can be "
                "replaced with a list comprehension. "
                "List comprehensions are 1.3–2x faster because they avoid repeated "
                "``list.append`` attribute lookup and use optimised ``LIST_APPEND`` bytecode."
            ),
            node=node,
            ctx=ctx,
            severity=self.severity,
            fix=Fix(
                description=f"Replace with ``{target_var} = [expr for ... in ...]``."
            ),
        )

    @staticmethod
    def _append_target(call: ast.Call) -> str | None:
        """Return receiver variable name if call is `name.append(...)`, else None."""
        func = call.func
        if not isinstance(func, ast.Attribute):
            return None
        if func.attr != "append":
            return None
        receiver = func.value
        if not isinstance(receiver, ast.Name):
            return None
        return receiver.id

    @staticmethod
    def _has_preceding_empty_list(var: str, for_node: ast.For, ctx: AstContext) -> bool:
        """Return True if the statement immediately before for_node in its scope body
        is ``var = []`` or ``var: list = []``."""
        # Find the parent body containing this For node.
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
        # `var = []`
        if isinstance(prev, ast.Assign):
            for tgt in prev.targets:
                if isinstance(tgt, ast.Name) and tgt.id == var:
                    if isinstance(prev.value, ast.List) and not prev.value.elts:
                        return True
        # `var: list = []` or `var: List[T] = []`
        if isinstance(prev, ast.AnnAssign):
            tgt = prev.target
            if isinstance(tgt, ast.Name) and tgt.id == var:
                if isinstance(prev.value, ast.List) and not prev.value.elts:
                    return True
        return False
