from __future__ import annotations

import ast
from enum import Enum
from typing import TYPE_CHECKING, Iterable, Protocol, runtime_checkable

from pyperfguard.core.severity import Severity

if TYPE_CHECKING:
    from pyperfguard.ast_engine.context import AstContext
    from pyperfguard.core.finding import Finding


class RuleScope(str, Enum):
    AST = "ast"
    RUNTIME = "runtime"


@runtime_checkable
class Rule(Protocol):
    """Plugin contract for both AST and runtime checks.

    Attributes
    ----------
    id : str
        Stable, short identifier (e.g. ``"PKN001"``). Used for ``select``/``ignore``.
    name : str
        Human-readable kebab-case name (e.g. ``"mutable-default-argument"``).
    severity : Severity
        Default severity. Users may override per-rule via config.
    scope : RuleScope
        ``AST`` for static checks, ``RUNTIME`` for live event consumers.
    node_types : tuple[type[ast.AST], ...]
        For AST rules: which node types the visitor should dispatch.
        Empty tuple = receives all nodes (fallback).
    """

    id: str
    name: str
    severity: Severity
    scope: RuleScope
    node_types: tuple[type[ast.AST], ...]

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        """Examine ``node`` and yield zero or more :class:`Finding`."""
        ...
