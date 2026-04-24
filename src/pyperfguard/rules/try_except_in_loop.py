"""PKN016 — ``try/except`` inside a loop (per-iteration exception overhead).

    # BAD — exception machinery is set up and torn down every iteration
    for item in items:
        try:
            result = process(item)
        except ValueError:
            handle_error(item)

    # GOOD — move try/except outside when all items can fail together
    try:
        for item in items:
            result = process(item)
    except ValueError:
        handle_error(item)

    # ACCEPTABLE — per-item error handling (skip/continue), flag as INFO
    for item in items:
        try:
            process(item)
        except ValueError:
            continue

Python's exception handling has measurable overhead on EVERY iteration, even
when no exception is raised. Setting up the try block and installing the
exception handler cost a few bytecodes per pass.

When the loop processes many items (>1000) and the exception is rarely raised,
moving ``try/except`` outside the loop gives a meaningful speedup. When you
genuinely need per-item error isolation (``continue``/``break`` on failure),
the pattern is necessary but still worth being aware of.
"""

from __future__ import annotations

import ast
from typing import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity


class TryExceptInLoopRule:
    id = "PKN016"
    name = "try-except-in-loop"
    severity = Severity.INFO
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.Try,)

    # Catching Exception/BaseException broadly in a loop is the most egregious case:
    # it swallows all errors AND adds overhead. Other specific types are often EAFP.
    _BROAD_EXCEPTIONS = frozenset({"Exception", "BaseException"})

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, ast.Try)
        if not ctx.in_loop():
            return
        # Try/except nested inside another try/except — already isolated, skip.
        if self._in_try_except(ctx):
            return
        severity = self._classify_severity(node, self._BROAD_EXCEPTIONS)
        yield Finding.from_node(
            rule_id=self.id,
            message=self._build_message(node, self._BROAD_EXCEPTIONS),
            node=node,
            ctx=ctx,
            severity=severity,
            fix=Fix(
                description=(
                    "Move ``try/except`` outside the loop when per-item isolation is not needed. "
                    "If you must handle each item individually, consider a helper function."
                )
            ),
        )

    @staticmethod
    def _in_try_except(ctx: AstContext) -> bool:
        """True if the Try node is already nested inside another try/except."""
        return any(isinstance(a, ast.Try) for a in ctx.ancestors)

    @staticmethod
    def _classify_severity(node: ast.Try, broad: frozenset[str]) -> Severity:
        """Return WARNING only for broad catch (Exception/BaseException) without continue/break.

        Specific-exception EAFP patterns (KeyError, ValueError, etc.) are INFO — they are
        idiomatic Python and the overhead is small in Python 3.11+.
        """
        has_continue_or_break = any(
            isinstance(stmt, (ast.Continue, ast.Break))
            for handler in node.handlers
            for stmt in handler.body
        )
        if has_continue_or_break:
            return Severity.INFO
        # Check if any handler catches a broad exception type.
        for handler in node.handlers:
            if handler.type is None:
                return Severity.INFO  # bare except: already flagged by PKN002
            if isinstance(handler.type, ast.Name) and handler.type.id in broad:
                return Severity.WARNING
            if isinstance(handler.type, ast.Tuple):
                for elt in handler.type.elts:
                    if isinstance(elt, ast.Name) and elt.id in broad:
                        return Severity.WARNING
        return Severity.INFO

    @staticmethod
    def _build_message(node: ast.Try, broad: frozenset[str]) -> str:
        has_continue_or_break = any(
            isinstance(stmt, (ast.Continue, ast.Break))
            for handler in node.handlers
            for stmt in handler.body
        )
        if has_continue_or_break:
            return (
                "``try/except`` inside a loop with ``continue``/``break``. "
                "Per-item error isolation is acceptable here, but the exception "
                "setup overhead is paid on every iteration regardless."
            )
        for handler in node.handlers:
            exc_name = handler.type.id if isinstance(handler.type, ast.Name) else None
            if exc_name in broad:
                return (
                    f"Broad ``except {exc_name}:`` inside a loop catches all errors per "
                    "iteration and adds overhead on every pass even when no exception occurs. "
                    "If the exception is unexpected, move the ``try/except`` outside the loop. "
                    "If it's expected frequently, handle it more specifically."
                )
        return (
            "``try/except`` inside a loop. "
            "Exception handling overhead is paid on every iteration even when no "
            "exception is raised. If all items can succeed or fail together, move "
            "the ``try/except`` outside the loop."
        )
