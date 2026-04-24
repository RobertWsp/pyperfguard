"""Tests for PKN023: isinstance() called with a list instead of a tuple."""

from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.core.severity import Severity
from pyperfguard.rules.isinstance_with_list import IsinstanceWithListRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(IsinstanceWithListRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_isinstance_with_list_flagged():
    src = "if isinstance(x, [int, str]): pass\n"
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN023"
    assert findings[0].severity == Severity.WARNING


def test_isinstance_with_dotted_type_flagged():
    src = "if isinstance(x, [os.PathLike, str]): pass\n"
    findings = _run(src)
    assert len(findings) == 1


def test_isinstance_with_tuple_not_flagged():
    src = "if isinstance(x, (int, str)): pass\n"
    findings = _run(src)
    assert findings == []


def test_isinstance_with_single_type_not_flagged():
    src = "if isinstance(x, int): pass\n"
    findings = _run(src)
    assert findings == []


def test_isinstance_with_non_type_in_list_not_flagged():
    # List contains a call — not a bare type ref.
    src = "if isinstance(x, [get_type(), str]): pass\n"
    findings = _run(src)
    assert findings == []


def test_isinstance_with_constant_in_list_not_flagged():
    # Constant values — not type references.
    src = "if isinstance(x, [1, 2]): pass\n"
    findings = _run(src)
    assert findings == []


def test_isinstance_with_empty_list_not_flagged():
    src = "if isinstance(x, []): pass\n"
    findings = _run(src)
    assert findings == []


def test_not_isinstance_call_not_flagged():
    src = "result = sorted([3, 1, 2])\n"
    findings = _run(src)
    assert findings == []


def test_message_mentions_tuple():
    src = "if isinstance(x, [int, str]): pass\n"
    findings = _run(src)
    assert "tuple" in findings[0].message or "LOAD_CONST" in findings[0].message


def test_isinstance_single_type_in_list_flagged():
    # Even a single-element list is heap-allocated unnecessarily.
    src = "if isinstance(x, [int]): pass\n"
    findings = _run(src)
    assert len(findings) == 1
