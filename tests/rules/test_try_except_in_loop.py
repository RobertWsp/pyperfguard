"""Tests for PKN016: try/except inside a loop."""
from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.core.severity import Severity
from pyperfguard.rules.try_except_in_loop import TryExceptInLoopRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(TryExceptInLoopRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_try_except_specific_error_in_for_loop_flagged_as_info():
    # Specific exception (ValueError) = EAFP pattern → INFO severity.
    src = (
        "for item in items:\n"
        "    try:\n"
        "        process(item)\n"
        "    except ValueError:\n"
        "        handle(item)\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN016"
    assert findings[0].severity == Severity.INFO


def test_try_except_broad_exception_in_loop_flagged_as_warning():
    # Broad exception (Exception) = performance anti-pattern → WARNING severity.
    src = (
        "for item in items:\n"
        "    try:\n"
        "        process(item)\n"
        "    except Exception:\n"
        "        handle(item)\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN016"
    assert findings[0].severity == Severity.WARNING


def test_try_except_in_while_loop_flagged():
    src = (
        "while running:\n"
        "    try:\n"
        "        result = fetch()\n"
        "    except TimeoutError:\n"
        "        pass\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN016"


def test_try_except_outside_loop_not_flagged():
    src = (
        "try:\n"
        "    for item in items:\n"
        "        process(item)\n"
        "except ValueError:\n"
        "    handle()\n"
    )
    findings = _run(src)
    assert findings == []


def test_try_continue_in_loop_flagged_as_info():
    # Per-item isolation with continue — acceptable but still has overhead.
    src = (
        "for item in items:\n"
        "    try:\n"
        "        process(item)\n"
        "    except ValueError:\n"
        "        continue\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO


def test_try_break_in_loop_flagged_as_info():
    src = (
        "for item in items:\n"
        "    try:\n"
        "        result = risky(item)\n"
        "    except RuntimeError:\n"
        "        break\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO


def test_nested_try_except_in_loop_not_double_flagged():
    # try-except nested inside another try-except — only flag the outer one.
    src = (
        "for item in items:\n"
        "    try:\n"
        "        try:\n"
        "            risky(item)\n"
        "        except IOError:\n"
        "            pass\n"
        "    except ValueError:\n"
        "        handle(item)\n"
    )
    findings = _run(src)
    # The inner Try is nested inside the outer Try, so only the outer is flagged.
    assert len(findings) == 1


def test_no_try_except_not_flagged():
    src = "for item in items:\n    process(item)\n"
    findings = _run(src)
    assert findings == []


def test_try_except_in_async_for_loop_flagged():
    src = (
        "async def f():\n"
        "    async for item in aiter:\n"
        "        try:\n"
        "            await process(item)\n"
        "        except Exception:\n"
        "            pass\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN016"
