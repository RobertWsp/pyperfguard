"""PKN006 — ``copy.deepcopy()`` called inside a loop.

    # BAD
    for row in rows:
        state = copy.deepcopy(template)   # very slow; copies entire object graph
        state['id'] = row.id
        process(state)

    # GOOD (when only top-level dict keys differ)
    for row in rows:
        state = {**template, 'id': row.id}

``copy.deepcopy`` is notoriously slow: it recurses the entire object graph,
handles cycles, calls ``__deepcopy__``/__reduce__ hooks, etc.  A real-world
regression: pendulum's deepcopy went from 27 µs to 27 ms after a refactor —
1000× slower, triggered by an inadvertent deepcopy in a loop.

If you need a fresh mutable copy, prefer ``copy.copy()`` (shallow) or
``{**template}`` / ``dataclasses.replace()`` when appropriate.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity


class DeepcopyInLoopRule:
    id = "PKN006"
    name = "deepcopy-in-loop"
    severity = Severity.WARNING
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.Call,)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, ast.Call)
        if not ctx.in_loop():
            return
        if not self._is_deepcopy(node):
            return
        yield Finding.from_node(
            rule_id=self.id,
            message=(
                "``copy.deepcopy()`` inside a loop is very slow — it traverses "
                "the entire object graph on each iteration. "
                "Consider ``copy.copy()``, ``{**template}``, or ``dataclasses.replace()``."
            ),
            node=node,
            ctx=ctx,
            severity=self.severity,
            fix=Fix(
                description=(
                    "Use a shallow copy (``copy.copy``), dict unpacking (``{**d}``), "
                    "or ``dataclasses.replace()`` if deep copy is not actually needed."
                )
            ),
        )

    @staticmethod
    def _is_deepcopy(node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "deepcopy":
            if isinstance(func.value, ast.Name) and func.value.id == "copy":
                return True
        return bool(isinstance(func, ast.Name) and func.id == "deepcopy")
