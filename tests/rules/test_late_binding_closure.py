"""Tests for PKN018: late-binding closure in a loop."""
from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.core.severity import Severity
from pyperfguard.rules.late_binding_closure import LateBindingClosureRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(LateBindingClosureRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_lambda_capturing_loop_var_flagged():
    src = (
        "handlers = []\n"
        "for i in range(5):\n"
        "    handlers.append(lambda: i)\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN018"
    assert findings[0].severity == Severity.WARNING


def test_lambda_with_default_arg_not_flagged():
    # Correct early-binding pattern: i=i captures value.
    src = (
        "handlers = []\n"
        "for i in range(5):\n"
        "    handlers.append(lambda i=i: i)\n"
    )
    findings = _run(src)
    assert findings == []


def test_lambda_not_using_loop_var_not_flagged():
    # Lambda doesn't reference the loop variable at all.
    src = (
        "fns = []\n"
        "for i in range(5):\n"
        "    fns.append(lambda x: x * 2)\n"
    )
    findings = _run(src)
    assert findings == []


def test_lambda_with_loop_var_as_param_not_flagged():
    # i is the lambda's own parameter (not a free variable).
    src = (
        "fns = []\n"
        "for i in range(5):\n"
        "    fns.append(lambda i: i * 2)\n"
    )
    findings = _run(src)
    assert findings == []


def test_lambda_outside_loop_not_flagged():
    src = "fn = lambda x: x * 2\n"
    findings = _run(src)
    assert findings == []


def test_lambda_in_while_loop_not_flagged():
    # While loops don't have a named iteration variable to capture.
    src = (
        "fns = []\n"
        "while items:\n"
        "    item = items.pop()\n"
        "    fns.append(lambda: item)\n"
    )
    findings = _run(src)
    # While loops: no named for-target variable, so not flagged by this rule.
    assert findings == []


def test_lambda_capturing_outer_var_not_flagged():
    # Lambda captures an outer non-loop variable — not a late-binding bug.
    src = (
        "multiplier = 3\n"
        "fns = []\n"
        "for i in range(5):\n"
        "    fns.append(lambda x: x * multiplier)\n"
    )
    findings = _run(src)
    assert findings == []


def test_lambda_capturing_multiple_loop_vars_flagged():
    # Tuple unpacking: both k and v are loop variables.
    src = (
        "fns = []\n"
        "for k, v in pairs:\n"
        "    fns.append(lambda: (k, v))\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert "k" in findings[0].message or "v" in findings[0].message


def test_lambda_partial_capture_flagged():
    # Lambda uses loop var i, but also takes other params — still flagged for i.
    src = (
        "fns = []\n"
        "for i in range(5):\n"
        "    fns.append(lambda x, y: x + y + i)\n"
    )
    findings = _run(src)
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# PKN018 — nested def (not just lambda)
# ---------------------------------------------------------------------------

def test_def_capturing_loop_var_flagged():
    src = (
        "handlers = []\n"
        "for i in range(5):\n"
        "    def handler():\n"
        "        return i\n"
        "    handlers.append(handler)\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN018"
    assert "Function" in findings[0].message


def test_async_def_capturing_loop_var_flagged():
    src = (
        "handlers = []\n"
        "for i in range(5):\n"
        "    async def handler():\n"
        "        return i\n"
        "    handlers.append(handler)\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN018"


def test_def_with_loop_var_as_default_not_flagged():
    src = (
        "handlers = []\n"
        "for i in range(5):\n"
        "    def handler(i=i):\n"
        "        return i\n"
        "    handlers.append(handler)\n"
    )
    findings = _run(src)
    assert findings == []


def test_def_not_using_loop_var_not_flagged():
    src = (
        "handlers = []\n"
        "for i in range(5):\n"
        "    def handler(x):\n"
        "        return x * 2\n"
        "    handlers.append(handler)\n"
    )
    findings = _run(src)
    assert findings == []


def test_def_outside_loop_not_flagged():
    src = (
        "def handler():\n"
        "    return 42\n"
    )
    findings = _run(src)
    assert findings == []


def test_noqa_suppresses_pkn018():
    src = (
        "fns = []\n"
        "for i in range(5):\n"
        "    fns.append(lambda: i)  # noqa: PKN018\n"
    )
    findings = _run(src)
    assert findings == []
