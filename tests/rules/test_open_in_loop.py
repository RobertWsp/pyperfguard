from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.rules.open_in_loop import OpenInLoopRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(OpenInLoopRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_open_same_file_in_loop_flagged():
    # Opening the SAME file (string literal) on every iteration is the anti-pattern.
    src = "for line in lines:\n    with open('log.txt', 'a') as fp:\n        fp.write(line)\n"
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN004"


def test_open_loop_var_not_flagged():
    # `open(f)` where `f` is the iteration variable — opening DIFFERENT files.
    # This is the correct pattern for processing a collection of files.
    src = "for f in files:\n    with open(f) as fp:\n        data = fp.read()\n"
    findings = _run(src)
    assert findings == []


def test_open_outside_loop_not_flagged():
    src = "with open('file.txt') as fp:\n    data = fp.read()\n"
    findings = _run(src)
    assert findings == []


def test_open_in_while_loop_flagged():
    src = "while items:\n    with open(items.pop()) as fp:\n        pass\n"
    findings = _run(src)
    assert len(findings) == 1


def test_other_context_manager_in_loop_not_flagged():
    src = "for x in xs:\n    with lock:\n        pass\n"
    findings = _run(src)
    assert findings == []


def test_async_with_open_same_file_in_loop_flagged():
    # Same file constant every iteration — anti-pattern.
    src = "async def f():\n    for _ in items:\n        async with open('data.txt') as fp:\n            pass\n"
    findings = _run(src)
    assert len(findings) == 1


def test_async_with_open_loop_var_not_flagged():
    # Different file per iteration via loop variable — legitimate.
    src = "async def f():\n    for p in paths:\n        async with open(p) as fp:\n            pass\n"
    findings = _run(src)
    assert findings == []


def test_open_computed_path_in_loop_flagged():
    # open(computed_constant) where constant is not the loop var — still flagged.
    src = "config = 'app.cfg'\nfor item in items:\n    with open(config) as fp:\n        pass\n"
    findings = _run(src)
    assert len(findings) == 1


def test_open_join_with_loop_var_not_flagged():
    # Regression: `open(os.path.join(tmpdir, filename))` where `filename` is the
    # loop variable — transitive loop-var check must exclude this.
    src = (
        "import os\n"
        "for filename in files:\n"
        "    with open(os.path.join(tmpdir, filename)) as fp:\n"
        "        data = fp.read()\n"
    )
    findings = _run(src)
    assert findings == []


def test_open_join_without_loop_var_flagged():
    # `open(os.path.join(SHARED_DIR, SAME_FILE))` — no loop var in path → flagged.
    src = (
        "import os\n"
        "for item in items:\n"
        "    with open(os.path.join(SHARED_DIR, 'config.txt')) as fp:\n"
        "        pass\n"
    )
    findings = _run(src)
    assert len(findings) == 1


def test_open_join_nested_loop_var_not_flagged():
    # `open(os.path.join(base, subdir, fname))` — fname is the loop var.
    src = (
        "import os\n"
        "for fname in fnames:\n"
        "    with open(os.path.join(base, subdir, fname)) as fp:\n"
        "        pass\n"
    )
    findings = _run(src)
    assert findings == []
