from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.rules.deepcopy_in_loop import DeepcopyInLoopRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(DeepcopyInLoopRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_copy_deepcopy_in_loop_flagged():
    src = "import copy\nfor item in items:\n    c = copy.deepcopy(item)\n"
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN006"


def test_direct_deepcopy_in_loop_flagged():
    src = "from copy import deepcopy\nfor item in items:\n    c = deepcopy(item)\n"
    findings = _run(src)
    assert len(findings) == 1


def test_deepcopy_outside_loop_not_flagged():
    src = "import copy\nresult = copy.deepcopy(data)\n"
    findings = _run(src)
    assert findings == []


def test_copy_copy_not_flagged():
    src = "import copy\nfor item in items:\n    c = copy.copy(item)\n"
    findings = _run(src)
    assert findings == []
