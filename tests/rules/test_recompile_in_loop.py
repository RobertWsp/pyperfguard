from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.rules.recompile_in_loop import RecompileInLoopRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(RecompileInLoopRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_re_compile_in_loop_flagged():
    src = "import re\nfor s in strings:\n    pat = re.compile(r'\\d+')\n    pat.match(s)\n"
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN005"


def test_re_compile_outside_loop_not_flagged():
    src = "import re\npat = re.compile(r'\\d+')\n"
    findings = _run(src)
    assert findings == []


def test_other_method_in_loop_not_flagged():
    src = "import re\nfor s in strings:\n    re.match(r'\\d+', s)\n"
    findings = _run(src)
    assert findings == []


def test_compile_in_while_loop_flagged():
    src = "import re\nwhile items:\n    p = re.compile('x')\n    items.pop()\n"
    findings = _run(src)
    assert len(findings) == 1
