from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class AstContext:
    """Per-file context passed to every rule during the AST walk.

    Two parallel stacks are maintained by :class:`PyperfVisitor`:

    - ``ancestors`` — nodes from module root down to (excluding) the current node.
    - ``field_path`` — ``(parent, field_name)`` pairs so rules can ask *which
      field* of the parent they're visiting.  This is what makes
      :meth:`in_loop` semantically correct: the iterable expression of a
      ``for`` statement is **not** inside the loop body.
    """

    path: Path
    source: str
    module: ast.Module
    ancestors: list[ast.AST] = field(default_factory=list)
    field_path: list[tuple[ast.AST, str]] = field(default_factory=list)

    # ----- Source helpers --------------------------------------------------

    def source_segment(self, node: ast.AST, max_chars: int = 200) -> str | None:
        """Return the source text for *node*, truncated to ``max_chars``."""
        try:
            seg = ast.get_source_segment(self.source, node)
        except Exception:
            return None
        if seg is None:
            return None
        seg = seg.strip()
        if len(seg) > max_chars:
            seg = seg[: max_chars - 3] + "..."
        return seg

    # ----- Scope helpers ---------------------------------------------------

    def parent_node(self) -> ast.AST | None:
        return self.ancestors[-1] if self.ancestors else None

    def in_loop(self) -> bool:
        """True if the current node is inside a loop *body* (For, AsyncFor, While)."""
        for parent, fname in self.field_path:
            if isinstance(parent, (ast.For, ast.AsyncFor, ast.While)) and fname in (
                "body",
                "orelse",
            ):
                return True
        return False

    def in_sync_for_loop(self) -> bool:
        """True if inside a regular ``for`` body (not ``async for``, not ``while``)."""
        for parent, fname in self.field_path:
            if isinstance(parent, ast.For) and fname in ("body", "orelse"):
                return True
        return False

    def in_async_for_loop(self) -> bool:
        """True if inside an ``async for`` body."""
        for parent, fname in self.field_path:
            if isinstance(parent, ast.AsyncFor) and fname in ("body", "orelse"):
                return True
        return False

    def enclosing_loop(self) -> ast.AST | None:
        """Return the innermost enclosing loop node, or ``None``."""
        for parent, fname in reversed(self.field_path):
            if isinstance(parent, (ast.For, ast.AsyncFor, ast.While)) and fname in (
                "body",
                "orelse",
            ):
                return parent
        return None

    def in_async_function(self) -> bool:
        """True if the current node is lexically inside an ``async def``."""
        for a in reversed(self.ancestors):
            if isinstance(a, ast.AsyncFunctionDef):
                return True
            if isinstance(a, (ast.FunctionDef, ast.Lambda, ast.ClassDef)):
                return False
        return False

    def enclosing_function(self) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        for a in reversed(self.ancestors):
            if isinstance(a, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return a
        return None

    def in_function(self) -> bool:
        """True if inside any function (sync or async)."""
        for a in reversed(self.ancestors):
            if isinstance(a, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return True
        return False

    def in_comprehension(self) -> bool:
        """True if inside a list/set/dict comprehension or generator expression."""
        return any(
            isinstance(a, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp))
            for a in self.ancestors
        )

    # ----- Suppression helpers ---------------------------------------------

    def is_suppressed(self, line: int | None, rule_id: str) -> bool:
        """True if the source line has ``# noqa: PKN018`` or bare ``# noqa``.

        Bare ``# noqa`` suppresses all rules. ``# noqa: PKN001, PKN002``
        suppresses only the listed rule IDs.
        """
        if line is None:
            return False
        lines = self.source.splitlines()
        if line < 1 or line > len(lines):
            return False
        src_line = lines[line - 1]
        idx = src_line.find("# noqa")
        if idx == -1:
            return False
        remainder = src_line[idx + len("# noqa") :].lstrip()
        if not remainder or remainder[0] != ":":
            return True  # bare
        codes_str = remainder[1:].split("#")[0]
        codes = {c.strip() for c in codes_str.split(",")}
        return rule_id in codes
