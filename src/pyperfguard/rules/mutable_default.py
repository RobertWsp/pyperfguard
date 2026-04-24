from __future__ import annotations

import ast
from typing import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity

# Calls whose default values build a fresh mutable container (still shared
# across invocations because the call runs once at def-time).
_MUTABLE_BUILDER_NAMES: frozenset[str] = frozenset({
    "list", "dict", "set", "bytearray", "deque", "defaultdict", "OrderedDict", "Counter",
})


class MutableDefaultRule:
    id = "PKN001"
    name = "mutable-default-argument"
    severity = Severity.WARNING
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.FunctionDef, ast.AsyncFunctionDef)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        # @overload stubs are never called at runtime — their defaults are for
        # type-checkers only and the shared-state bug cannot manifest.
        if self._has_overload_decorator(node):
            return
        defaults = list(node.args.defaults) + list(node.args.kw_defaults)
        for default in defaults:
            if default is None:
                continue
            if self._is_mutable_default(default):
                yield Finding.from_node(
                    rule_id=self.id,
                    message=(
                        f"Function '{node.name}' uses a mutable default argument. "
                        "Defaults are evaluated once at def time and shared across calls."
                    ),
                    node=default,
                    ctx=ctx,
                    severity=self.severity,
                    fix=Fix(
                        description="Use ``None`` as default and create the container inside the function body.",
                    ),
                )

    @staticmethod
    def _has_overload_decorator(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for dec in func.decorator_list:
            if isinstance(dec, ast.Name) and dec.id == "overload":
                return True
            if isinstance(dec, ast.Attribute) and dec.attr == "overload":
                return True
        return False

    @staticmethod
    def _is_mutable_default(node: ast.AST) -> bool:
        if isinstance(node, (ast.List, ast.Dict, ast.Set)):
            return True
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in _MUTABLE_BUILDER_NAMES:
                return True
            if isinstance(func, ast.Attribute) and func.attr in _MUTABLE_BUILDER_NAMES:
                return True
        return False
