from __future__ import annotations

import ast
import re
from collections.abc import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity

_ALLOW_FILTERING_RE = re.compile(r"\bALLOW\s+FILTERING\b", re.IGNORECASE)


class AllowFilteringRule:
    """Flag CQL queries containing ``ALLOW FILTERING``.

    This is a near-zero-false-positive Cassandra anti-pattern: it tells the
    coordinator to scan partitions sequentially. Performance degrades silently
    as data grows.
    """

    id = "PKN010"
    name = "cassandra-allow-filtering"
    severity = Severity.ERROR
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.Constant, ast.JoinedStr)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        # Constant children of a JoinedStr are already covered when the
        # JoinedStr itself is visited — skip them to avoid duplicate findings.
        if isinstance(node, ast.Constant) and isinstance(ctx.parent_node(), ast.JoinedStr):
            return
        text = self._extract_string(node)
        if not text:
            return
        if _ALLOW_FILTERING_RE.search(text):
            yield Finding.from_node(
                rule_id=self.id,
                message=(
                    "CQL query contains ``ALLOW FILTERING``. "
                    "This forces a full-partition scan and degrades non-linearly with data growth. "
                    "Redesign the data model or add a secondary index."
                ),
                node=node,
                ctx=ctx,
                severity=self.severity,
                fix=Fix(
                    description=(
                        "Denormalize: create a query-first table keyed by the filtered column, "
                        "or use a SASI/secondary index if cardinality allows."
                    ),
                ),
                extra={"matched_phrase": "ALLOW FILTERING"},
            )

    @staticmethod
    def _extract_string(node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            # f-string: concatenate the literal parts; ignore interpolations.
            parts: list[str] = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
            return "".join(parts) if parts else None
        return None
