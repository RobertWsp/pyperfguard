"""Tests for PKN020: unnecessary iterable construction for the ``in`` operator."""

from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.core.severity import Severity
from pyperfguard.rules.unnecessary_iterable_for_in import UnnecessaryIterableForInRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(UnnecessaryIterableForInRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_in_list_of_iterable_flagged():
    src = "if x in list(items): pass\n"
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN020"
    assert findings[0].severity == Severity.WARNING


def test_in_tuple_of_iterable_flagged():
    src = "if x in tuple(items): pass\n"
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN020"


def test_in_sorted_flagged():
    src = "if x in sorted(items): pass\n"
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN020"


def test_in_reversed_flagged():
    src = "if x in reversed(items): pass\n"
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN020"


def test_not_in_list_flagged():
    src = "if x not in list(items): pass\n"
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN020"


def test_in_set_not_flagged():
    # set() is an optimisation (O(1) lookup) — not a smell.
    src = "if x in set(items): pass\n"
    findings = _run(src)
    assert findings == []


def test_in_plain_list_literal_not_flagged():
    src = "if x in [1, 2, 3]: pass\n"
    findings = _run(src)
    assert findings == []


def test_in_dict_keys_list_flagged():
    src = "if key in list(d.keys()): pass\n"
    findings = _run(src)
    assert len(findings) == 1


def test_in_dict_keys_no_list_not_flagged():
    src = "if key in d.keys(): pass\n"
    findings = _run(src)
    assert findings == []


def test_chained_compare_not_flagged():
    # `a < x < b` has two ops — rule requires exactly one op.
    src = "result = 1 < x < 10\n"
    findings = _run(src)
    assert findings == []


def test_in_variable_not_flagged():
    src = "if x in items: pass\n"
    findings = _run(src)
    assert findings == []


def test_message_mentions_sorted_fix():
    src = "if x in sorted(items): pass\n"
    findings = _run(src)
    assert len(findings) == 1
    assert "set(" in findings[0].message or "sorted" in findings[0].message
