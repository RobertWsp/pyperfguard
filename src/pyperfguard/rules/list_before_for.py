"""PKN015 — ``list()`` wrapping an iterable immediately before a ``for`` loop.

    # BAD — materialises entire iterable into a list when only iterating once
    for x in list(generator_or_queryset):
        process(x)

    # GOOD — iterate directly
    for x in generator_or_queryset:
        process(x)

The only reason to wrap an iterable with ``list()`` before a ``for`` loop is
to allow mutation of the source *during* iteration (e.g. ``for k in list(d):
del d[k]``).  In all other cases, the ``list()`` call materialises the entire
sequence into memory unnecessarily, increasing peak memory usage and adding
an O(n) copy overhead.

Severity: INFO — mutation-during-iteration is a legitimate pattern.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity


class ListBeforeForRule:
    id = "PKN015"
    name = "list-before-for"
    severity = Severity.INFO
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.For,)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, ast.For)
        iter_expr = node.iter
        if not self._is_list_wrap(iter_expr):
            return
        # If the loop body mutates the wrapped iterable, list() is necessary.
        if self._body_mutates_iterable(node):
            return
        yield Finding.from_node(
            rule_id=self.id,
            message=(
                "``list()`` wraps an iterable in a ``for`` loop. "
                "This materialises the entire sequence unnecessarily. "
                "Iterate directly unless you need to modify the source during iteration."
            ),
            node=iter_expr,
            ctx=ctx,
            severity=self.severity,
            fix=Fix(
                description=(
                    "Remove the ``list()`` wrapper: ``for x in list(seq):`` → ``for x in seq:``"
                )
            ),
        )

    @staticmethod
    def _attr_chain(node: ast.AST) -> tuple[str, ...]:
        """Return a dotted-name tuple for an attribute chain: a.b.c → ('a','b','c')."""
        if isinstance(node, ast.Name):
            return (node.id,)
        if isinstance(node, ast.Attribute):
            parent = ListBeforeForRule._attr_chain(node.value)
            if parent:
                return (*parent, node.attr)
        return ()

    @staticmethod
    def _body_mutates_iterable(for_node: ast.For) -> bool:
        """Return True if the loop body contains mutation operations on the wrapped arg.

        Handles both simple names (`list(d)`) and attribute chains (`list(self.items)`).
        Special case: `list(self)` — iterating a collection class over itself; assumed mutable.
        """
        iter_call = for_node.iter
        if not isinstance(iter_call, ast.Call) or not iter_call.args:
            return False
        wrapped = iter_call.args[0]

        # list(self) — class acting as its own collection; mutations via self.method() inevitable
        if isinstance(wrapped, ast.Name) and wrapped.id == "self":
            return True

        iterable_chain = ListBeforeForRule._attr_chain(wrapped)
        if not iterable_chain:
            return False

        _MUTATING_METHODS = frozenset(
            {
                "remove",
                "pop",
                "discard",
                "clear",
                "update",
                "append",
                "insert",
                "extend",
                "uninstall_member",
                "delete",
                "drop",
            }
        )

        for node in ast.walk(ast.Module(body=for_node.body, type_ignores=[])):
            # del d[k]  /  del self.items[k]
            if isinstance(node, ast.Delete):
                for target in node.targets:
                    if isinstance(target, ast.Subscript):
                        if ListBeforeForRule._attr_chain(target.value) == iterable_chain:
                            return True
                    if ListBeforeForRule._attr_chain(target) == iterable_chain:
                        return True
            # d[k] = v  /  self.items[k] = v
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Subscript):
                        if ListBeforeForRule._attr_chain(target.value) == iterable_chain:
                            return True
            # d.remove(x)  /  self.items.remove(x)  /  self.uninstall_member(key)
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr in _MUTATING_METHODS:
                    obj_chain = ListBeforeForRule._attr_chain(func.value)
                    # Direct call on iterable: d.remove(x)
                    if obj_chain == iterable_chain:
                        return True
                    # Call on parent that owns iterable: self.uninstall_member(key)
                    # when iterable is list(self.originals)
                    if obj_chain and iterable_chain and obj_chain[0] == iterable_chain[0]:
                        return True
        return False

    @staticmethod
    def _is_list_wrap(expr: ast.AST) -> bool:
        if not isinstance(expr, ast.Call):
            return False
        func = expr.func
        if not (isinstance(func, ast.Name) and func.id == "list"):
            return False
        if not (len(expr.args) == 1 and not expr.keywords):
            return False
        # list(d.items()) / list(d.keys()) / list(d.values()) is a legitimate
        # pattern for mutating a dict while iterating — do not flag it.
        arg = expr.args[0]
        return not (
            isinstance(arg, ast.Call)
            and isinstance(arg.func, ast.Attribute)
            and arg.func.attr in ("items", "keys", "values")
            and not arg.args
            and not arg.keywords
        )
