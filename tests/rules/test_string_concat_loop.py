from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.rules.string_concat_loop import StringConcatLoopRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(StringConcatLoopRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_string_concat_with_variable_not_flagged():
    # Bare Name RHS — without type inference we can't confirm it's a string.
    # Precision over recall: avoid false positives on numeric accumulation.
    src = "result = ''\nfor s in parts:\n    result += s\n"
    findings = _run(src)
    assert findings == []


def test_string_concat_with_literal_flagged():
    src = "result = ''\nfor s in parts:\n    result += 'suffix'\n"
    findings = _run(src)
    assert len(findings) == 1


def test_string_concat_with_fstring_flagged():
    src = "result = ''\nfor s in parts:\n    result += f'{s}!'\n"
    findings = _run(src)
    assert len(findings) == 1


def test_int_literal_augassign_not_flagged():
    # Only literal integers are definitively non-string at the AST level.
    src = "total = 0\nfor n in nums:\n    total += 1\n"
    findings = _run(src)
    assert findings == []


def test_variable_augassign_in_loop_not_flagged():
    # Without type inference, bare Name RHS is not flagged (could be int/float).
    src = "total = 0\nfor n in nums:\n    total += n\n"
    findings = _run(src)
    assert findings == []


def test_concat_outside_loop_not_flagged():
    src = "result = 'a' + 'b'\n"
    findings = _run(src)
    assert findings == []


def test_while_loop_flagged():
    src = "result = ''\nwhile condition:\n    result += ' suffix'\n"
    findings = _run(src)
    assert len(findings) == 1


def test_nested_loop_flagged_once():
    src = "r = ''\nfor x in xs:\n    for y in ys:\n        r += '!'\n"
    # The innermost augassign is in a loop body
    findings = _run(src)
    assert len(findings) == 1
