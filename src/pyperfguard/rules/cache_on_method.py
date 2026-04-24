"""PKN017 — ``@lru_cache`` / ``@cache`` on an instance method (memory leak).

    # BAD — self is part of the cache key → prevents garbage collection
    class Processor:
        @functools.lru_cache(maxsize=128)
        def compute(self, x: int) -> int:
            return x ** 2

    # GOOD — use functools.cached_property for zero-arg derived attributes
    class Processor:
        @functools.cached_property
        def value(self) -> int:
            return expensive_computation()

    # GOOD — cache at module/function level (no self reference)
    @functools.lru_cache(maxsize=128)
    def compute(x: int) -> int:
        return x ** 2

    # GOOD — explicit weakref-based cache pattern
    class Processor:
        _cache: dict = {}
        def compute(self, x: int) -> int:
            if x not in self._cache:
                self._cache[x] = x ** 2
            return self._cache[x]

When ``@lru_cache`` or ``@cache`` decorates an **instance method**, ``self``
becomes part of the cache key. This means:

1. The cache holds a **strong reference** to every ``self`` that has been
   passed as an argument.
2. The instance cannot be garbage-collected as long as it remains in the cache.
3. If new instances are created frequently (e.g. per-request objects in a web
   framework), the cache grows without bound → **memory leak**.

Safe alternatives:
- ``@functools.cached_property`` — stores the value on the instance itself,
  gets cleaned up when the instance is collected.
- Move the cached function to module level and pass only the relevant data.
- Use a ``weakref.WeakValueDictionary`` as a backing store.
"""

from __future__ import annotations

import ast
from typing import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity

_CACHE_DECORATORS = frozenset({"lru_cache", "cache"})


class CacheOnMethodRule:
    id = "PKN017"
    name = "cache-on-method"
    severity = Severity.WARNING
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.FunctionDef, ast.AsyncFunctionDef)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        # Must be an instance method (inside a class body, first param is self).
        if not self._is_instance_method(node, ctx):
            return
        # Must have a caching decorator.
        dec_node = self._find_cache_decorator(node)
        if dec_node is None:
            return
        yield Finding.from_node(
            rule_id=self.id,
            message=(
                f"``@{self._decorator_name(dec_node)}`` on an instance method creates a "
                "memory leak: ``self`` is part of the cache key, preventing garbage "
                "collection of instances. Use ``@functools.cached_property`` for "
                "derived attributes, or move the cached function to module level."
            ),
            node=dec_node,
            ctx=ctx,
            severity=self.severity,
            fix=Fix(
                description=(
                    "Replace with ``@functools.cached_property`` (for attribute-style access) "
                    "or move to a module-level ``@lru_cache`` function."
                )
            ),
        )

    @staticmethod
    def _is_instance_method(func: ast.FunctionDef | ast.AsyncFunctionDef, ctx: AstContext) -> bool:
        """True if func is inside a class body and its first parameter is 'self'."""
        # Must be directly inside a class (immediate enclosing non-func ancestor is ClassDef).
        for ancestor in reversed(ctx.ancestors):
            if isinstance(ancestor, ast.ClassDef):
                break
            if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return False  # nested function, not a method
        else:
            return False  # no class ancestor

        # Must not be a staticmethod or classmethod.
        for dec in func.decorator_list:
            name = _decorator_base_name(dec)
            if name in ("staticmethod", "classmethod"):
                return False

        # First argument must be self (or cls would be filtered above).
        args = func.args
        if not args.args:
            return False
        return args.args[0].arg == "self"

    @staticmethod
    def _find_cache_decorator(func: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.AST | None:
        """Return the lru_cache/cache decorator node, or None."""
        for dec in func.decorator_list:
            name = _decorator_base_name(dec)
            if name in _CACHE_DECORATORS:
                return dec
        return None

    @staticmethod
    def _decorator_name(dec: ast.AST) -> str:
        """Return a human-readable name for the decorator."""
        if isinstance(dec, ast.Name):
            return dec.id
        if isinstance(dec, ast.Attribute):
            return f"{dec.value.id if isinstance(dec.value, ast.Name) else '...'}.{dec.attr}"
        if isinstance(dec, ast.Call):
            inner = dec.func
            if isinstance(inner, ast.Name):
                return inner.id
            if isinstance(inner, ast.Attribute):
                return f"...{inner.attr}"
        return "cache"


def _decorator_base_name(dec: ast.AST) -> str:
    """Extract the base name from a decorator (Name, Attribute, or Call)."""
    if isinstance(dec, ast.Name):
        return dec.id
    if isinstance(dec, ast.Attribute):
        return dec.attr
    if isinstance(dec, ast.Call):
        return _decorator_base_name(dec.func)
    return ""
