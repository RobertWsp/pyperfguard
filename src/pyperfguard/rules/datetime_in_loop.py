"""PKN007 — ``datetime.now()`` / ``datetime.utcnow()`` / ``time.time()`` in a loop.

    # BAD
    for item in items:
        item.stamp = datetime.now()   # timezone lookup every iteration

    # GOOD
    now = datetime.now()
    for item in items:
        item.stamp = now

These calls are not free: ``datetime.now(tz)`` performs a timezone lookup
(libc call), and ``time.time()`` does a syscall.  If the timestamp does not
need sub-loop resolution, capture it once before the loop.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity

_NOW_ATTRS = frozenset({"now", "utcnow", "today"})

# monotonic/perf_counter/process_time are ALWAYS legitimate in loops — they measure
# elapsed time per-iteration (e.g. remaining = timeout - time.monotonic()). Only
# time.time() is flagged since it's often used as a fixed "now" that could be hoisted.
_TIME_ATTRS = frozenset({"time"})

# Variable name fragments that signal "this is a loop-timing reference, not a shared stamp".
# e.g. start_time, begin_ts, t0, tick — but NOT: now, ts, stamp, created_at.
_TIMING_VAR_FRAGMENTS = frozenset({"start", "begin", "t0", "tick", "ref"})


class DatetimeInLoopRule:
    id = "PKN007"
    name = "datetime-in-loop"
    severity = Severity.INFO
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.Call,)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, ast.Call)
        if not ctx.in_loop():
            return
        if not self._is_time_call(node):
            return
        # time.time() used as `time.time() - ref` or `ref - time.time()` measures
        # elapsed time per iteration — the same legitimate use case as monotonic().
        if self._is_elapsed_time_expr(node, ctx):
            return
        # `start_time = time.time()` — assigned to a timing-reference variable.
        if self._is_timing_assignment(node, ctx):
            return
        # `if datetime.now() < deadline:` — deadline check needs fresh time each iteration.
        if self._is_deadline_check(node, ctx):
            return
        yield Finding.from_node(
            rule_id=self.id,
            message=(
                "Timestamp call inside a loop. "
                "If the same timestamp can be used for every iteration, "
                "capture it once before the loop."
            ),
            node=node,
            ctx=ctx,
            severity=self.severity,
            fix=Fix(
                description="Move ``now = datetime.now()`` / ``t = time.time()`` before the loop."
            ),
        )

    @staticmethod
    def _is_elapsed_time_expr(node: ast.Call, ctx: AstContext) -> bool:
        """Return True if the call is the operand of a subtraction (elapsed time)."""
        parent = ctx.parent_node()
        return isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.Sub)

    @staticmethod
    def _is_timing_assignment(node: ast.Call, ctx: AstContext) -> bool:
        """Return True for `start_time = time.time()` — assigned to a timing variable.

        Variable names containing 'start', 'begin', 't0', 'tick', 'ref' (case-insensitive)
        are naming-convention markers for elapsed-time measurement, not shared timestamps.
        """
        parent = ctx.parent_node()
        if not isinstance(parent, ast.Assign):
            return False
        for target in parent.targets:
            if isinstance(target, ast.Name):
                name = target.id.lower()
                if any(frag in name for frag in _TIMING_VAR_FRAGMENTS):
                    return True
        return False

    @staticmethod
    def _is_deadline_check(node: ast.Call, ctx: AstContext) -> bool:
        """Return True for `if time.time() < deadline:` — the timestamp is the LEFT operand.

        When the timestamp call is the LEFT side of a comparison (the thing being measured),
        the code is asking 'has the deadline passed yet?' and needs a fresh value each iteration.
        Contrast with the right-side case: `if item.ts < datetime.now():` where the same
        `now` could be captured once before the loop.
        """
        parent = ctx.parent_node()
        return isinstance(parent, ast.Compare) and parent.left is node

    @staticmethod
    def _is_time_call(node: ast.Call) -> bool:
        func = node.func
        if not isinstance(func, ast.Attribute):
            return False
        attr = func.attr
        if attr in _NOW_ATTRS:
            # datetime.now() / datetime.datetime.now()
            return True
        if attr in _TIME_ATTRS:
            # time.time() / time.monotonic() …
            if isinstance(func.value, ast.Name) and func.value.id == "time":
                return True
        return False
