"""PKN020 — unnecessary iterable construction for the ``in`` operator (PERF201).

    # BAD — constructs a full list/tuple just for O(n) membership test
    if x in list(d.keys()):   ...
    if x in list(items):      ...
    if x in sorted(items):    ...
    if x in reversed(items):  ...
    if x in tuple(items):     ...

    # GOOD — iterate the original iterable directly
    if x in d.keys():   ...
    if x in items:      ...
    if x in items:      ...

    # BEST for large sequences — O(1) hash lookup
    if x in set(items): ...

CPython must allocate and populate the full list/tuple before executing the
``in`` operator.  For ``sorted()`` the overhead is even larger: O(n log n)
sort just to do an O(n) linear scan.  The original iterable is almost always
iterable as-is, making the wrapping call redundant.

``set(iterable)`` is explicitly excluded from this rule: converting to a set
changes the average complexity from O(n) to O(1) and is often the *correct*
optimisation, especially in loops.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity

# Functions whose sole effect here is to build an unnecessary sequence.
_REDUNDANT_WRAPPERS = frozenset({"list", "tuple", "sorted", "reversed"})


class UnnecessaryIterableForInRule:
    id = "PKN020"
    name = "unnecessary-iterable-for-in"
    severity = Severity.WARNING
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.Compare,)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, ast.Compare)
        # We want `x in <call>(...)` patterns — one comparator, op is In/NotIn.
        if len(node.ops) != 1:
            return
        if not isinstance(node.ops[0], (ast.In, ast.NotIn)):
            return
        comparator = node.comparators[0]
        if not isinstance(comparator, ast.Call):
            return

        wrapper = self._call_name(comparator)
        if wrapper not in _REDUNDANT_WRAPPERS:
            return
        # Must wrap at least one positional arg (the source iterable).
        if not comparator.args:
            return

        op_str = "in" if isinstance(node.ops[0], ast.In) else "not in"
        inner_src = ctx.source_segment(comparator.args[0]) or "iterable"
        full_src = ctx.source_segment(comparator) or f"{wrapper}({inner_src})"

        if wrapper == "sorted":
            message = (
                f"``{op_str} {full_src}`` sorts the sequence O(n log n) just "
                f"to perform an O(n) membership scan. "
                f"Use ``{op_str} {inner_src}`` for an equivalent linear scan, "
                f"or ``{op_str} set({inner_src})`` for O(1) lookup."
            )
            fix_desc = f"Replace ``{full_src}`` with ``{inner_src}`` (or ``set({inner_src})`` for O(1) lookup)."
        else:
            message = (
                f"``{op_str} {full_src}`` allocates an unnecessary "
                f"{'list' if wrapper in ('list', 'sorted') else wrapper} just for a membership test. "
                f"Use ``{op_str} {inner_src}`` directly."
            )
            fix_desc = f"Replace ``{full_src}`` with ``{inner_src}``."

        yield Finding.from_node(
            rule_id=self.id,
            message=message,
            node=node,
            ctx=ctx,
            severity=self.severity,
            fix=Fix(description=fix_desc),
        )

    @staticmethod
    def _call_name(call: ast.Call) -> str | None:
        """Return the bare function name for simple calls like ``list(x)``."""
        func = call.func
        if isinstance(func, ast.Name):
            return func.id
        # Also handle `builtins.list(x)` style (rare, but possible).
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.value.id == "builtins":
                return func.attr
        return None
