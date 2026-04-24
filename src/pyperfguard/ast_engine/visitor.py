from __future__ import annotations

import ast
from collections.abc import Iterable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyperfguard.ast_engine.context import AstContext
    from pyperfguard.core.finding import Finding
    from pyperfguard.core.registry import Registry


class PyperfVisitor(ast.NodeVisitor):
    """Single-pass visitor that dispatches each node to interested rules.

    Rules opt into node types via :attr:`Rule.node_types`; the registry
    indexes them so dispatch is O(rules-for-this-type), not O(all-rules).
    The ``ctx.ancestors`` stack is maintained so rules can ask "am I in
    a loop?" without re-walking the tree.
    """

    def __init__(self, registry: Registry, ctx: AstContext) -> None:
        self.registry = registry
        self.ctx = ctx
        self.findings: list[Finding] = []

    def visit(self, node: ast.AST) -> None:
        self._dispatch(node)
        self.ctx.ancestors.append(node)
        try:
            for fname, value in ast.iter_fields(node):
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, ast.AST):
                            self.ctx.field_path.append((node, fname))
                            try:
                                self.visit(item)
                            finally:
                                self.ctx.field_path.pop()
                elif isinstance(value, ast.AST):
                    self.ctx.field_path.append((node, fname))
                    try:
                        self.visit(value)
                    finally:
                        self.ctx.field_path.pop()
        finally:
            self.ctx.ancestors.pop()

    def _dispatch(self, node: ast.AST) -> None:
        rules = self.registry.ast_rules_for(node)
        if not rules:
            return
        for rule in rules:
            try:
                emitted: Iterable[Finding] = rule.check(node, self.ctx)
                for f in emitted:
                    if not self.ctx.is_suppressed(f.location.start_line, f.rule_id):
                        self.findings.append(f)
            except Exception as exc:
                # A buggy rule must never abort the analysis of an entire file.
                import sys

                print(
                    f"[pyperfguard] rule {rule.id!r} crashed on "
                    f"{self.ctx.path}:{getattr(node, 'lineno', '?')}: {exc}",
                    file=sys.stderr,
                )
