"""PKN003 — string concatenation inside a loop (O(n²) complexity).

    # BAD
    result = ""
    for s in parts:
        result += s      # creates a new string object every iteration

    # GOOD
    result = "".join(parts)

CPython allocates a new string on every ``+=`` in a loop, making this O(n²)
for the total work done. Python's ``str.join`` is O(n).
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity


class StringConcatLoopRule:
    id = "PKN003"
    name = "string-concat-loop"
    severity = Severity.WARNING
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.AugAssign,)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, ast.AugAssign)
        if not ctx.in_loop():
            return
        if not isinstance(node.op, ast.Add):
            return
        # Value being appended must look like a string expression.
        if not self._looks_like_string(node.value):
            return
        yield Finding.from_node(
            rule_id=self.id,
            message=(
                "String concatenation with ``+=`` inside a loop is O(n²). "
                "Collect parts in a list and use ``''.join(parts)`` after the loop."
            ),
            node=node,
            ctx=ctx,
            severity=self.severity,
            fix=Fix(
                description=(
                    "Replace ``result += s`` loop with: "
                    "``parts = []; for ...: parts.append(s); result = ''.join(parts)``"
                )
            ),
        )

    @staticmethod
    def _looks_like_string(node: ast.AST) -> bool:
        # Definitive: string literal or f-string.
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return True
        if isinstance(node, ast.JoinedStr):
            return True
        # BinOp where at least one side is definitively a string — e.g. "prefix" + var.
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left_str = isinstance(node.left, (ast.Constant, ast.JoinedStr)) and (
                not isinstance(node.left, ast.Constant) or isinstance(node.left.value, str)
            )
            right_str = isinstance(node.right, (ast.Constant, ast.JoinedStr)) and (
                not isinstance(node.right, ast.Constant) or isinstance(node.right.value, str)
            )
            if left_str or right_str:
                return True
        # Do NOT flag bare Name / Call / Subscript / Attribute — without type inference
        # we cannot distinguish numeric accumulation (total += n) from string concat.
        # This trades recall for precision: avoids false positives on int/bytes/float.
        return False
