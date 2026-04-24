"""PKN004 — ``open()`` called inside a loop.

    # BAD
    for line in lines:
        with open("log.txt", "a") as f:   # opens and closes every iteration
            f.write(line)

    # GOOD
    with open("log.txt", "a") as f:
        for line in lines:
            f.write(line)

Each ``open`` call performs at least one syscall (open/close).  Opening the
same file inside a hot loop is almost always unintentional and measurably
slower, especially on network filesystems.
"""

from __future__ import annotations

import ast
from typing import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity

_OPEN_NAMES = frozenset({"open", "io.open", "codecs.open"})


def _for_target_names(target: ast.AST) -> set[str]:
    """Collect all Name ids from a for-loop target (handles tuple unpacking)."""
    names: set[str] = set()
    if isinstance(target, ast.Name):
        names.add(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            names |= _for_target_names(elt)
    return names


class OpenInLoopRule:
    id = "PKN004"
    name = "open-in-loop"
    severity = Severity.WARNING
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.With, ast.AsyncWith)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, (ast.With, ast.AsyncWith))
        if not ctx.in_loop():
            return
        for item in node.items:
            if not self._is_open_call(item.context_expr):
                continue
            call = item.context_expr
            assert isinstance(call, ast.Call)
            # `open(p)` where `p` is the for-loop iteration variable is the
            # canonical pattern for processing different files — not an anti-pattern.
            if self._arg_is_loop_var(call, ctx):
                continue
            yield Finding.from_node(
                rule_id=self.id,
                message=(
                    "``open()`` called inside a loop. "
                    "Move the file open outside the loop and write/read inside it."
                ),
                node=call,
                ctx=ctx,
                severity=self.severity,
                fix=Fix(
                    description="Hoist ``open(...)`` outside the loop body."
                ),
            )
            return  # one finding per With, avoid duplicates

    @staticmethod
    def _is_open_call(expr: ast.AST) -> bool:
        if not isinstance(expr, ast.Call):
            return False
        func = expr.func
        if isinstance(func, ast.Name):
            return func.id == "open"
        if isinstance(func, ast.Attribute):
            return func.attr == "open"
        return False

    @staticmethod
    def _arg_is_loop_var(call: ast.Call, ctx: AstContext) -> bool:
        """Return True when any Name in open()'s first arg is the loop iteration variable.

        Handles both direct use (`open(path)`) and transitive use
        (`open(os.path.join(tmpdir, path))`), where `path` is the loop variable.
        """
        if not call.args:
            return False
        first_arg = call.args[0]
        loop = ctx.enclosing_loop()
        if loop is None or not isinstance(loop, (ast.For, ast.AsyncFor)):
            return False
        loop_vars = _for_target_names(loop.target)
        if not loop_vars:
            return False
        for node in ast.walk(first_arg):
            if isinstance(node, ast.Name) and node.id in loop_vars:
                return True
        return False
