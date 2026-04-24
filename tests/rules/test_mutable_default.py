from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.rules.mutable_default import MutableDefaultRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(MutableDefaultRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_list_default_flagged():
    findings = _run("def f(x=[]): ...\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN001"


def test_dict_and_set_defaults_flagged():
    findings = _run("def f(a={}, b=set()): ...\n")
    assert {f.rule_id for f in findings} == {"PKN001"}
    assert len(findings) == 2


def test_list_call_default_flagged():
    findings = _run("def f(x=list()): ...\n")
    assert len(findings) == 1


def test_none_default_not_flagged():
    findings = _run("def f(x=None): ...\n")
    assert findings == []


def test_immutable_defaults_not_flagged():
    findings = _run("def f(a=1, b='x', c=(1,2), d=frozenset()): ...\n")
    assert findings == []


def test_async_function_also_flagged():
    findings = _run("async def f(x={}): ...\n")
    assert len(findings) == 1


def test_kwonly_default_flagged():
    findings = _run("def f(*, x=[]): ...\n")
    assert len(findings) == 1


def test_overload_decorator_not_flagged():
    # Regression: redis-py uses @overload stubs with mutable defaults for type-checking.
    # @overload functions are never called at runtime — no shared-state bug can occur.
    src = (
        "from typing import overload\n"
        "@overload\n"
        "def client_list(self, client_id: list = []) -> list: ...\n"
    )
    findings = _run(src)
    assert findings == []


def test_typing_overload_attribute_not_flagged():
    # `@typing.overload` form
    src = "import typing\n@typing.overload\ndef f(x: list = []) -> list: ...\n"
    findings = _run(src)
    assert findings == []


def test_overload_only_excludes_decorated_function():
    # Non-overload function with same signature should still be flagged.
    src = (
        "from typing import overload\n"
        "@overload\n"
        "def f(x: list = []) -> list: ...\n"
        "def f(x: list = []) -> list:\n"  # actual impl — FLAGGED
        "    return x\n"
    )
    findings = _run(src)
    assert len(findings) == 1  # only the non-overload impl
