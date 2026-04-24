from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.finding import Finding, Location
from pyperfguard.core.registry import Registry
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity


class _LoopWatcher:
    """Yields a Finding for any Call inside a loop. Tests that ancestors stack works."""

    id = "TST001"
    name = "loop-watcher"
    severity = Severity.WARNING
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.Call,)

    def check(self, node, ctx):
        if ctx.in_loop():
            yield Finding(
                rule_id=self.id,
                message="call inside loop",
                severity=self.severity,
                location=Location.from_node(ctx.path, node),
            )


class _Crashy:
    id = "TST002"
    name = "crashy"
    severity = Severity.ERROR
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.Module,)

    def check(self, node, ctx):
        raise RuntimeError("boom")


def _ctx(src: str):
    return AstContext(path=Path("test.py"), source=src, module=ast.parse(src))


def test_visitor_detects_call_inside_for():
    reg = Registry()
    reg.register_rule(_LoopWatcher())
    src = "for i in range(3):\n    foo(i)\n"
    ctx = _ctx(src)
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    assert len(v.findings) == 1
    assert v.findings[0].rule_id == "TST001"


def test_visitor_does_not_flag_call_outside_loop():
    reg = Registry()
    reg.register_rule(_LoopWatcher())
    src = "foo(1)\n"
    ctx = _ctx(src)
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    assert v.findings == []


def test_visitor_isolates_crashing_rule(capfd):
    reg = Registry()
    reg.register_rule(_Crashy())
    src = "x = 1\n"
    ctx = _ctx(src)
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)  # must not raise
    err = capfd.readouterr().err
    assert "TST002" in err and "crashed" in err


def test_noqa_bare_suppresses_all_rules():
    """``# noqa`` on a finding's line suppresses regardless of rule id."""
    reg = Registry()
    reg.register_rule(_LoopWatcher())
    src = "for i in range(3):\n    foo(i)  # noqa\n"
    ctx = _ctx(src)
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    assert v.findings == []


def test_noqa_specific_rule_suppresses():
    """``# noqa: TST001`` suppresses TST001 only."""
    reg = Registry()
    reg.register_rule(_LoopWatcher())
    src = "for i in range(3):\n    foo(i)  # noqa: TST001\n"
    ctx = _ctx(src)
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    assert v.findings == []


def test_noqa_different_rule_does_not_suppress():
    """``# noqa: TST999`` leaves TST001 findings intact."""
    reg = Registry()
    reg.register_rule(_LoopWatcher())
    src = "for i in range(3):\n    foo(i)  # noqa: TST999\n"
    ctx = _ctx(src)
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    assert len(v.findings) == 1


def test_noqa_multiple_codes_suppresses_targeted():
    """``# noqa: TST001, TST002`` suppresses both."""
    reg = Registry()
    reg.register_rule(_LoopWatcher())
    src = "for i in range(3):\n    foo(i)  # noqa: TST001, TST999\n"
    ctx = _ctx(src)
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    assert v.findings == []


def test_in_async_function_helper():
    src = (
        "async def a():\n"
        "    foo()\n"
        "def b():\n"
        "    foo()\n"
    )
    captured: list[bool] = []

    class Probe:
        id = "PRB001"
        name = "probe"
        severity = Severity.INFO
        scope = RuleScope.AST
        node_types = (ast.Call,)

        def check(self, node, ctx):
            captured.append(ctx.in_async_function())
            return ()

    reg = Registry()
    reg.register_rule(Probe())
    ctx = _ctx(src)
    PyperfVisitor(reg, ctx).visit(ctx.module)
    assert captured == [True, False]
