from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.rules.allow_filtering import AllowFilteringRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(AllowFilteringRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_allow_filtering_flagged_in_string_literal():
    src = "session.execute('SELECT * FROM t WHERE x = 1 ALLOW FILTERING')\n"
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN010"
    assert findings[0].extra["matched_phrase"] == "ALLOW FILTERING"


def test_case_insensitive():
    src = "q = 'select * from t allow filtering'\n"
    assert len(_run(src)) == 1


def test_fstring_with_literal_part_flagged():
    src = "q = f'SELECT * FROM t WHERE id={x} ALLOW FILTERING'\n"
    assert len(_run(src)) == 1


def test_unrelated_string_not_flagged():
    src = "msg = 'hello world'\n"
    assert _run(src) == []


def test_phrase_must_be_word_bounded():
    # "ALLOW_FILTERING" (underscore) shouldn't match — different identifier.
    src = "x = 'ALLOW_FILTERING'\n"
    assert _run(src) == []
