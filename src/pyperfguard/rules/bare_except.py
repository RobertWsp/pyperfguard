from __future__ import annotations

import ast
from typing import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity


class BareExceptRule:
    id = "PKN002"
    name = "bare-except"
    severity = Severity.WARNING
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.ExceptHandler,)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, ast.ExceptHandler)
        if node.type is None:
            yield Finding.from_node(
                rule_id=self.id,
                message=(
                    "Bare ``except:`` swallows BaseException (KeyboardInterrupt, SystemExit). "
                    "Catch ``Exception`` or a specific subclass."
                ),
                node=node,
                ctx=ctx,
                severity=self.severity,
                fix=Fix(description="Use ``except Exception:`` or a more specific exception type."),
            )
