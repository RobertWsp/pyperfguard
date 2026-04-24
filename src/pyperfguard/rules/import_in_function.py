"""PKN014 — heavy-module import inside a function body.

    # BAD — ~200-500ms import on first call, surprising to callers
    def handler(request):
        import pandas as pd       # first call is slow
        return pd.DataFrame(request.rows)

    # GOOD — import at module top-level (once, at startup)
    import pandas as pd
    def handler(request):
        return pd.DataFrame(request.rows)

Importing a module has a one-time cost (parsing, execution, caching).
When the import statement is inside a function that is called at runtime
(e.g. an HTTP handler, a Celery task), the first call triggers the import
latency unexpectedly, adding hundreds of milliseconds to that specific request.

Legitimate exceptions (not flagged — patterns where lazy import is intentional):
- Optional dependency guards: ``try: import X except ImportError: X = None``
- CLI lazy loading: ``__name__ == '__main__'`` context
- TYPE_CHECKING guards: ``if TYPE_CHECKING: import X``

Severity: INFO — lazy imports inside functions are sometimes intentional for
optional dependencies or circular import avoidance.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity

# Decorators that imply the function is called at most once (lazy init pattern).
# Imports inside these are intentional: the cost is paid once and cached.
_CACHING_DECORATORS = frozenset({"cached_property", "lru_cache", "cache"})

# Modules known to have significant import time (heuristic list).
_HEAVY_MODULES = frozenset(
    {
        "pandas",
        "numpy",
        "tensorflow",
        "torch",
        "sklearn",
        "scipy",
        "matplotlib",
        "cv2",
        "PIL",
        "spacy",
        "nltk",
        "transformers",
        "boto3",
        "botocore",
        "pyspark",
        "dask",
        "numba",
        "sqlalchemy",
        "django",
        "flask",
        "fastapi",
    }
)


class ImportInFunctionRule:
    id = "PKN014"
    name = "heavy-import-in-function"
    severity = Severity.INFO
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.Import, ast.ImportFrom)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, (ast.Import, ast.ImportFrom))
        if not ctx.in_function():
            return
        if self._in_try_except(ctx):
            return  # optional-dependency guard
        func = ctx.enclosing_function()
        if func is not None and self._has_caching_decorator(func):
            return  # cached_property / lru_cache — called once, cost amortised
        module_names = self._extract_names(node)
        heavy = [
            n
            for n in module_names
            if n.split(".")[0] in _HEAVY_MODULES and not self._is_self_import(n.split(".")[0], ctx)
        ]
        if not heavy:
            return
        for name in heavy:
            yield Finding.from_node(
                rule_id=self.id,
                message=(
                    f"Import of heavy module ``{name}`` inside a function body. "
                    "The first call will trigger the full import latency. "
                    "Move to module level or guard with ``TYPE_CHECKING``."
                ),
                node=node,
                ctx=ctx,
                severity=self.severity,
                fix=Fix(description=f"Move ``import {name}`` to module top-level."),
            )

    @staticmethod
    def _extract_names(node: ast.AST) -> list[str]:
        if isinstance(node, ast.Import):
            return [alias.name for alias in node.names]
        if isinstance(node, ast.ImportFrom) and node.module:
            return [node.module]
        return []

    @staticmethod
    def _is_self_import(module_root: str, ctx: AstContext) -> bool:
        """Return True when the file lives inside the package it's importing from.

        Django's own source in ``django/`` importing ``from django.conf import X``
        is a well-known circular-import avoidance pattern, not a performance bug.
        """
        return module_root in ctx.path.parts

    @staticmethod
    def _has_caching_decorator(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for dec in func.decorator_list:
            if isinstance(dec, ast.Name) and dec.id in _CACHING_DECORATORS:
                return True
            if isinstance(dec, ast.Attribute) and dec.attr in _CACHING_DECORATORS:
                return True
            if isinstance(dec, ast.Call):
                inner = dec.func
                if isinstance(inner, ast.Name) and inner.id in _CACHING_DECORATORS:
                    return True
                if isinstance(inner, ast.Attribute) and inner.attr in _CACHING_DECORATORS:
                    return True
        return False

    @staticmethod
    def _in_try_except(ctx: AstContext) -> bool:
        """Return True if the import is directly inside a try/except block."""
        # ast.TryStar (try/except*) exists only on Python 3.11+.
        _try_star = getattr(ast, "TryStar", None)
        return any(
            isinstance(a, ast.Try) or (_try_star is not None and isinstance(a, _try_star))
            for a in ctx.ancestors
        )
