"""PKN018 — lambda / nested function inside a loop captures loop variable by reference.

    # BAD — i is late-bound; all closures see the last value of i
    handlers = []
    for i in range(5):
        handlers.append(lambda: i)

    handlers[0]()  # Returns 4, not 0 — surprising!

    # GOOD — bind i as a default argument (early binding)
    handlers = []
    for i in range(5):
        handlers.append(lambda i=i: i)

    handlers[0]()  # Returns 0 — correct

    # GOOD — use functools.partial or a factory function
    import functools
    handlers = [functools.partial(process, i) for i in range(5)]

When a ``lambda`` or ``def`` is created inside a ``for`` loop body, any
reference to the loop variable inside it is **late-bound**: the closure
captures the variable *name*, not its current *value*.

When the closure is eventually called (after the loop ends), it reads whatever
value the loop variable holds at that moment — typically the last value from
the final iteration.

This is almost always unintentional. The fix is to capture the current value
via a default argument: ``lambda x=x: x``.

Only lambdas / functions that **both** (a) are defined inside a ``for`` loop
and (b) reference the loop iteration variable as a free variable (not as a
parameter or default) are flagged.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity


def _for_target_names(target: ast.AST) -> set[str]:
    """Collect all Name ids from a for-loop target (handles tuple unpacking)."""
    names: set[str] = set()
    if isinstance(target, ast.Name):
        names.add(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            names |= _for_target_names(elt)
    return names


def _lambda_param_names(node: ast.Lambda | ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Collect all parameter names (args, kwonlyargs, defaults keys)."""
    args = node.args
    names: set[str] = set()
    for arg in (*args.args, *args.posonlyargs, *args.kwonlyargs):
        names.add(arg.arg)
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names


def _free_names_in(node: ast.AST, bound: set[str]) -> set[str]:
    """Return Names used in node that are NOT in the bound set."""
    free: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id not in bound:
            free.add(child.id)
    return free


class LateBindingClosureRule:
    id = "PKN018"
    name = "late-binding-closure"
    severity = Severity.WARNING
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef))
        # Must be inside a for loop body (not while — while loops don't have named variables).
        loop = ctx.enclosing_loop()
        if loop is None or not isinstance(loop, ast.For):
            return
        loop_vars = _for_target_names(loop.target)
        if not loop_vars:
            return
        # Collect names bound by this closure's own parameters.
        own_params = _lambda_param_names(node)
        # Walk the body for free references to loop variables.
        if isinstance(node, ast.Lambda):
            body_node: ast.AST = node.body
        else:
            body_node = ast.Module(body=node.body, type_ignores=[])
        late_bound = loop_vars & _free_names_in(body_node, own_params)
        if not late_bound:
            return
        is_lambda = isinstance(node, ast.Lambda)
        kind = "Lambda" if is_lambda else "Function"
        varnames = ", ".join(f"``{v}``" for v in sorted(late_bound))
        if is_lambda:
            fix_examples = ", ".join(f"``lambda {v}={v}: ...``" for v in sorted(late_bound))
        else:
            fix_examples = ", ".join(f"``def f({v}={v}): ...``" for v in sorted(late_bound))
        yield Finding.from_node(
            rule_id=self.id,
            message=(
                f"{kind} inside a loop captures loop variable {varnames} by reference "
                "(late binding). When called after the loop, it sees the last value of "
                f"the variable, not the value at definition time. Fix: {fix_examples}."
            ),
            node=node,
            ctx=ctx,
            severity=self.severity,
            fix=Fix(
                description=(
                    "Bind the loop variable as a default argument: "
                    "``lambda x=x: x`` (or ``def f(x=x): ...``) captures the current "
                    "value, not a reference."
                )
            ),
        )
