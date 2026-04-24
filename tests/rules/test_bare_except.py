from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.rules.bare_except import BareExceptRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(BareExceptRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_bare_except_flagged():
    src = (
        "try:\n"
        "    f()\n"
        "except:\n"
        "    pass\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN002"


def test_typed_except_not_flagged():
    src = (
        "try:\n"
        "    f()\n"
        "except ValueError:\n"
        "    pass\n"
    )
    assert _run(src) == []


def test_exception_base_not_flagged():
    src = (
        "try:\n"
        "    f()\n"
        "except Exception:\n"
        "    pass\n"
    )
    assert _run(src) == []
