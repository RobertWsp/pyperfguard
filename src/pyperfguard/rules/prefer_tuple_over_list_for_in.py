"""PKN022 — constant list literal as ``in``/``not in`` target (W8301-like).

    # BAD — list literal is re-evaluated and heap-allocated on every pass
    if x in [1, 2, 3]:         ...
    if role in ["admin", "staff", "super"]:  ...

    # GOOD — tuple is a single constant folded by CPython's peephole optimizer
    if x in (1, 2, 3):         ...
    if role in ("admin", "staff", "super"):  ...

CPython's peephole optimizer (and bytecode compiler since 3.2) stores tuple
literals that contain only constant elements as a single ``LOAD_CONST`` opcode.
A list literal, by contrast, requires ``BUILD_LIST`` every time — a heap
allocation — even when its contents never change.

The fix is trivial: replace ``[a, b, c]`` with ``(a, b, c)`` on the right-hand
side of an ``in``/``not in`` check.  There is no semantic difference for the
membership test.

This rule only flags list literals where **every element is a constant** (int,
float, str, bytes, bool, ``None``, ellipsis) to avoid false positives on lists
that deliberately include non-constant expressions.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity

# AST node types that are valid constant leaves.
_CONSTANT_TYPES = (ast.Constant,)


def _is_constant(node: ast.AST) -> bool:
    """Return True if node represents an immutable literal constant."""
    if isinstance(node, ast.Constant):
        return True
    # Negative numeric literals are represented as UnaryOp(USub, Constant).
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        return isinstance(node.operand, ast.Constant)
    return False


class PreferTupleOverListForInRule:
    id = "PKN022"
    name = "prefer-tuple-over-list-for-in"
    severity = Severity.INFO
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.Compare,)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, ast.Compare)
        if len(node.ops) != 1:
            return
        if not isinstance(node.ops[0], (ast.In, ast.NotIn)):
            return
        comparator = node.comparators[0]
        # Must be a list literal (not a set, tuple, variable, etc.).
        if not isinstance(comparator, ast.List):
            return
        # All elements must be constant — otherwise the list may be intentional.
        if not comparator.elts:
            return
        if not all(_is_constant(e) for e in comparator.elts):
            return

        op_str = "in" if isinstance(node.ops[0], ast.In) else "not in"
        list_src = ctx.source_segment(comparator) or "[...]"

        yield Finding.from_node(
            rule_id=self.id,
            message=(
                f"``{op_str} {list_src}`` uses a list literal that is heap-allocated "
                "on every evaluation. Replace with a tuple so CPython stores it as a "
                "single ``LOAD_CONST`` opcode with no allocation."
            ),
            node=comparator,
            ctx=ctx,
            severity=self.severity,
            fix=Fix(description=(f"Replace ``{list_src}`` with ``({list_src[1:-1]})``.")),
        )
