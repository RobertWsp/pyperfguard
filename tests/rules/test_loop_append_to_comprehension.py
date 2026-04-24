"""Tests for PKN019: manual list construction with for-loop + .append()."""

from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.core.severity import Severity
from pyperfguard.rules.loop_append_to_comprehension import LoopAppendToComprehensionRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(LoopAppendToComprehensionRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_simple_append_loop_flagged():
    src = "result = []\nfor item in items:\n    result.append(item.value)\n"
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN019"
    assert findings[0].severity == Severity.INFO


def test_append_loop_inside_function_flagged():
    src = (
        "def process(items):\n"
        "    result = []\n"
        "    for item in items:\n"
        "        result.append(transform(item))\n"
        "    return result\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN019"


def test_annotated_empty_list_flagged():
    # `result: list = []` also matches.
    src = "result: list = []\nfor item in items:\n    result.append(item)\n"
    findings = _run(src)
    assert len(findings) == 1


def test_loop_with_multiple_statements_not_flagged():
    # Body has more than one statement — can't convert to simple comprehension.
    src = (
        "result = []\n"
        "for item in items:\n"
        "    processed = transform(item)\n"
        "    result.append(processed)\n"
    )
    findings = _run(src)
    assert findings == []


def test_loop_with_condition_not_flagged():
    # Body has an if-guard — filterable comprehension but different pattern.
    src = "result = []\nfor item in items:\n    if item.active:\n        result.append(item)\n"
    findings = _run(src)
    assert findings == []


def test_non_empty_list_before_loop_not_flagged():
    # The preceding list is not empty — not a simple builder pattern.
    src = "result = [initial]\nfor item in items:\n    result.append(item.value)\n"
    findings = _run(src)
    assert findings == []


def test_different_var_before_loop_not_flagged():
    # The empty list is a different variable than what's being appended to.
    src = "other = []\nfor item in items:\n    result.append(item)\n"
    findings = _run(src)
    assert findings == []


def test_loop_with_else_clause_not_flagged():
    # Loops with else clauses can't be trivially converted.
    src = (
        "result = []\n"
        "for item in items:\n"
        "    result.append(item)\n"
        "else:\n"
        "    result.append(sentinel)\n"
    )
    findings = _run(src)
    assert findings == []


def test_nested_loop_not_flagged():
    # Nested loops — inner append not flagged to avoid complex comprehension.
    src = (
        "def f():\n"
        "    for x in rows:\n"
        "        result = []\n"
        "        for y in x:\n"
        "            result.append(y)\n"
    )
    findings = _run(src)
    assert findings == []


def test_append_to_self_attribute_not_flagged():
    # `self.results.append(x)` — receiver is not a simple Name.
    src = "self.results = []\nfor item in items:\n    self.results.append(item)\n"
    findings = _run(src)
    assert findings == []


def test_no_preceding_empty_list_not_flagged():
    # Append loop but no preceding empty list assignment in scope.
    src = "def process(result, items):\n    for item in items:\n        result.append(item)\n"
    findings = _run(src)
    assert findings == []


def test_gap_between_assignment_and_loop_not_flagged():
    # Something between the `= []` and the for loop — not immediately preceding.
    src = "result = []\nx = 1\nfor item in items:\n    result.append(item)\n"
    findings = _run(src)
    assert findings == []
