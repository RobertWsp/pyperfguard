"""PKN005 — ``re.compile()`` called inside a loop.

    # BAD
    for s in strings:
        pattern = re.compile(r'\\d+')   # compiled every iteration
        if pattern.match(s): ...

    # GOOD
    _PATTERN = re.compile(r'\\d+')       # compiled once at module level
    for s in strings:
        if _PATTERN.match(s): ...

Compiling a regex is not free: it involves parsing the pattern, building an
NFA, and caching.  While CPython caches the last ~512 compiled patterns, this
cache is global and can be evicted by other code.  Compile once, reuse often.
"""

from __future__ import annotations

import ast
from typing import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity


class RecompileInLoopRule:
    id = "PKN005"
    name = "recompile-in-loop"
    severity = Severity.WARNING
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.Call,)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, ast.Call)
        if not ctx.in_loop():
            return
        if not self._is_re_compile(node):
            return
        yield Finding.from_node(
            rule_id=self.id,
            message=(
                "``re.compile()`` called inside a loop. "
                "Move the compiled pattern to module scope or a class attribute."
            ),
            node=node,
            ctx=ctx,
            severity=self.severity,
            fix=Fix(
                description="Extract ``pattern = re.compile(...)`` to module/class level."
            ),
        )

    @staticmethod
    def _is_re_compile(node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "compile":
            if isinstance(func.value, ast.Name) and func.value.id == "re":
                return True
        return False
