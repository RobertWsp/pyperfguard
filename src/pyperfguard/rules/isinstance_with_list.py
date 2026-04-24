"""PKN023 — ``isinstance()`` called with a list instead of a tuple.

    # BAD — list is heap-allocated on every call; also a TypeError in Python < 3.10
    if isinstance(x, [int, str, float]):  ...

    # GOOD — tuple is a single LOAD_CONST; correct in all Python versions
    if isinstance(x, (int, str, float)):  ...

CPython's ``isinstance()`` builtin accepts a tuple of types as its second
argument.  Passing a list works since Python 3.10 (via PEP 604 changes) but:

1. A list literal is heap-allocated on **every call** — ``BUILD_LIST`` + GC.
2. A tuple of constants is folded to a single ``LOAD_CONST`` by the bytecode
   compiler — zero allocation.
3. Using a list breaks compatibility with Python < 3.10.

This rule only flags list literals where **every element is a Name or
Attribute** (type references).  Complex expressions in the list are not flagged
to avoid false positives.
"""

from __future__ import annotations

import ast
from typing import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity


def _is_type_ref(node: ast.AST) -> bool:
    """True if node looks like a type reference (Name or dotted Attribute)."""
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.Attribute):
        return _is_type_ref(node.value)
    return False


class IsinstanceWithListRule:
    id = "PKN023"
    name = "isinstance-with-list"
    severity = Severity.WARNING
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.Call,)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, ast.Call)
        if not self._is_isinstance_call(node):
            return
        if len(node.args) < 2:
            return
        second_arg = node.args[1]
        if not isinstance(second_arg, ast.List):
            return
        if not second_arg.elts:
            return
        # All elements must look like type references.
        if not all(_is_type_ref(e) for e in second_arg.elts):
            return

        list_src = ctx.source_segment(second_arg) or "[...]"
        inner = list_src[1:-1]  # strip [ ]

        yield Finding.from_node(
            rule_id=self.id,
            message=(
                f"``isinstance(x, {list_src})`` passes a list which is heap-allocated "
                "on every call. Use a tuple ``isinstance(x, (...))`` instead — "
                "CPython stores constant-element tuples as a single ``LOAD_CONST``."
            ),
            node=second_arg,
            ctx=ctx,
            severity=self.severity,
            fix=Fix(
                description=f"Replace ``{list_src}`` with ``({inner},)``."
            ),
        )

    @staticmethod
    def _is_isinstance_call(node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Name) and func.id == "isinstance":
            return True
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "isinstance"
            and isinstance(func.value, ast.Name)
            and func.value.id == "builtins"
        ):
            return True
        return False
