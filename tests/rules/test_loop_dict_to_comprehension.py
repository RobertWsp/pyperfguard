"""Tests for PKN021: manual dict construction with for-loop."""
from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.core.severity import Severity
from pyperfguard.rules.loop_dict_to_comprehension import LoopDictToComprehensionRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(LoopDictToComprehensionRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_simple_dict_build_loop_flagged():
    src = (
        "result = {}\n"
        "for k, v in pairs:\n"
        "    result[k] = v\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN021"
    assert findings[0].severity == Severity.INFO


def test_dict_build_with_transform_flagged():
    src = (
        "result = {}\n"
        "for k, v in pairs:\n"
        "    result[k] = transform(v)\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN021"


def test_annotated_empty_dict_flagged():
    src = (
        "result: dict = {}\n"
        "for k, v in pairs:\n"
        "    result[k] = v\n"
    )
    findings = _run(src)
    assert len(findings) == 1


def test_non_empty_dict_before_loop_not_flagged():
    src = (
        "result = {initial_key: initial_val}\n"
        "for k, v in pairs:\n"
        "    result[k] = v\n"
    )
    findings = _run(src)
    assert findings == []


def test_different_var_not_flagged():
    src = (
        "other = {}\n"
        "for k, v in pairs:\n"
        "    result[k] = v\n"
    )
    findings = _run(src)
    assert findings == []


def test_loop_with_multiple_statements_not_flagged():
    src = (
        "result = {}\n"
        "for k, v in pairs:\n"
        "    processed = transform(v)\n"
        "    result[k] = processed\n"
    )
    findings = _run(src)
    assert findings == []


def test_loop_with_else_not_flagged():
    src = (
        "result = {}\n"
        "for k, v in pairs:\n"
        "    result[k] = v\n"
        "else:\n"
        "    result['sentinel'] = None\n"
    )
    findings = _run(src)
    assert findings == []


def test_nested_loop_not_flagged():
    src = (
        "for row in rows:\n"
        "    result = {}\n"
        "    for k, v in row:\n"
        "        result[k] = v\n"
    )
    findings = _run(src)
    assert findings == []


def test_list_assign_not_flagged():
    # result[k] = v but result = [] — this is list assignment, not dict.
    src = (
        "result = []\n"
        "for k, v in pairs:\n"
        "    result[k] = v\n"
    )
    findings = _run(src)
    assert findings == []


def test_append_loop_not_flagged_by_dict_rule():
    # The list-append rule handles this, not the dict rule.
    src = (
        "result = []\n"
        "for item in items:\n"
        "    result.append(item)\n"
    )
    findings = _run(src)
    assert findings == []


def test_gap_between_dict_and_loop_not_flagged():
    src = (
        "result = {}\n"
        "x = 1\n"
        "for k, v in pairs:\n"
        "    result[k] = v\n"
    )
    findings = _run(src)
    assert findings == []


def test_no_preceding_dict_not_flagged():
    src = (
        "def process(result, pairs):\n"
        "    for k, v in pairs:\n"
        "        result[k] = v\n"
    )
    findings = _run(src)
    assert findings == []
