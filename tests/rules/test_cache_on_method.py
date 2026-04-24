"""Tests for PKN017: @lru_cache / @cache on instance method (memory leak)."""

from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.core.severity import Severity
from pyperfguard.rules.cache_on_method import CacheOnMethodRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(CacheOnMethodRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_lru_cache_on_instance_method_flagged():
    src = (
        "import functools\n"
        "class Processor:\n"
        "    @functools.lru_cache(maxsize=128)\n"
        "    def compute(self, x: int) -> int:\n"
        "        return x ** 2\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN017"
    assert findings[0].severity == Severity.WARNING


def test_cache_on_instance_method_flagged():
    src = (
        "from functools import cache\n"
        "class MyClass:\n"
        "    @cache\n"
        "    def expensive(self, key):\n"
        "        return compute(key)\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN017"


def test_lru_cache_bare_on_method_flagged():
    # @lru_cache without call (used as @lru_cache)
    src = (
        "from functools import lru_cache\n"
        "class MyClass:\n"
        "    @lru_cache\n"
        "    def method(self, x):\n"
        "        return x\n"
    )
    findings = _run(src)
    assert len(findings) == 1


def test_lru_cache_on_module_level_function_not_flagged():
    # Module-level function — no self, no memory leak.
    src = (
        "from functools import lru_cache\n"
        "@lru_cache(maxsize=None)\n"
        "def compute(x: int) -> int:\n"
        "    return x ** 2\n"
    )
    findings = _run(src)
    assert findings == []


def test_cached_property_on_method_not_flagged():
    # @cached_property is the CORRECT pattern — stores value on instance.
    src = (
        "import functools\n"
        "class MyClass:\n"
        "    @functools.cached_property\n"
        "    def value(self):\n"
        "        return expensive()\n"
    )
    findings = _run(src)
    assert findings == []


def test_staticmethod_with_lru_cache_not_flagged():
    # @staticmethod + @lru_cache is fine — no self.
    src = (
        "from functools import lru_cache\n"
        "class MyClass:\n"
        "    @staticmethod\n"
        "    @lru_cache\n"
        "    def compute(x):\n"
        "        return x * 2\n"
    )
    findings = _run(src)
    assert findings == []


def test_classmethod_with_lru_cache_not_flagged():
    # @classmethod — cls reference doesn't prevent GC in the same way.
    src = (
        "from functools import lru_cache\n"
        "class MyClass:\n"
        "    @classmethod\n"
        "    @lru_cache\n"
        "    def create(cls, x):\n"
        "        return cls(x)\n"
    )
    findings = _run(src)
    assert findings == []


def test_nested_function_with_cache_not_flagged():
    # Function defined inside a method (not a class method itself).
    src = (
        "from functools import lru_cache\n"
        "class MyClass:\n"
        "    def outer(self):\n"
        "        @lru_cache\n"
        "        def inner(x):\n"
        "            return x ** 2\n"
        "        return inner\n"
    )
    findings = _run(src)
    assert findings == []


def test_method_without_cache_not_flagged():
    src = "class MyClass:\n    def compute(self, x):\n        return x ** 2\n"
    findings = _run(src)
    assert findings == []


def test_async_method_with_cache_flagged():
    src = (
        "from functools import lru_cache\n"
        "class AsyncProcessor:\n"
        "    @lru_cache\n"
        "    async def fetch(self, key):\n"
        "        return await db.get(key)\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN017"
