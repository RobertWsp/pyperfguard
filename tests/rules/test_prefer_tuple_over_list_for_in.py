"""Tests for PKN022: prefer tuple over list literal for ``in`` operator."""
from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.core.severity import Severity
from pyperfguard.rules.prefer_tuple_over_list_for_in import PreferTupleOverListForInRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(PreferTupleOverListForInRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_int_list_flagged():
    src = "if x in [1, 2, 3]: pass\n"
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN022"
    assert findings[0].severity == Severity.INFO


def test_string_list_flagged():
    src = 'if role in ["admin", "staff", "super"]: pass\n'
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN022"


def test_not_in_list_flagged():
    src = "if x not in [1, 2, 3]: pass\n"
    findings = _run(src)
    assert len(findings) == 1


def test_mixed_constant_types_flagged():
    src = "if x in [1, 'a', None, True]: pass\n"
    findings = _run(src)
    assert len(findings) == 1


def test_negative_number_flagged():
    src = "if x in [-1, -2, -3]: pass\n"
    findings = _run(src)
    assert len(findings) == 1


def test_tuple_literal_not_flagged():
    src = "if x in (1, 2, 3): pass\n"
    findings = _run(src)
    assert findings == []


def test_set_literal_not_flagged():
    src = "if x in {1, 2, 3}: pass\n"
    findings = _run(src)
    assert findings == []


def test_variable_not_flagged():
    src = "if x in items: pass\n"
    findings = _run(src)
    assert findings == []


def test_list_with_non_constant_not_flagged():
    # Contains a variable — not all constants.
    src = "if x in [a, 2, 3]: pass\n"
    findings = _run(src)
    assert findings == []


def test_list_with_call_not_flagged():
    src = "if x in [foo(), 2, 3]: pass\n"
    findings = _run(src)
    assert findings == []


def test_empty_list_not_flagged():
    # Empty list is always falsy — no meaningful optimisation.
    src = "if x in []: pass\n"
    findings = _run(src)
    assert findings == []


def test_message_mentions_load_const():
    src = "if x in [1, 2, 3]: pass\n"
    findings = _run(src)
    assert "LOAD_CONST" in findings[0].message or "tuple" in findings[0].message
