from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pyperfguard.core.severity import Severity

if TYPE_CHECKING:
    from pyperfguard.ast_engine.context import AstContext

# Single-char severity codes for compact output.
SEV_CODE: dict[Severity, str] = {
    Severity.ERROR: "E",
    Severity.WARNING: "W",
    Severity.INFO: "I",
    Severity.HINT: "H",
}

_RST_BACKTICK = re.compile(r"``([^`]*)``")


def _first_sentence(text: str, max_len: int = 120) -> str:
    """Return first sentence of *text*, RST backticks stripped, truncated."""
    text = _RST_BACKTICK.sub(r"\1", text).strip()
    end = text.find(". ")
    if end != -1:
        text = text[: end + 1]
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return text


def rel_path(path: Path, cwd: Path | None = None) -> str:
    """Return *path* relative to *cwd* (default: ``Path.cwd()``), or absolute."""
    base = cwd or Path.cwd()
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


@dataclass(frozen=True, slots=True)
class Location:
    """File/line/column span. Compatible with PEP 657 end positions."""

    path: Path
    start_line: int
    start_col: int = 0
    end_line: int | None = None
    end_col: int | None = None

    @classmethod
    def from_node(cls, path: Path, node: ast.AST) -> Location:
        return cls(
            path=path,
            start_line=getattr(node, "lineno", 1),
            start_col=getattr(node, "col_offset", 0),
            end_line=getattr(node, "end_lineno", None),
            end_col=getattr(node, "end_col_offset", None),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "start_line": self.start_line,
            "start_col": self.start_col,
            "end_line": self.end_line,
            "end_col": self.end_col,
        }


@dataclass(frozen=True, slots=True)
class Fix:
    """Optional autofix attached to a Finding."""

    description: str
    replacement: str | None = None
    location: Location | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    """Unified output produced by both AST and runtime engines."""

    rule_id: str
    message: str
    severity: Severity
    location: Location
    scope: str = "ast"  # "ast" | "runtime"
    snippet: str | None = None
    stack: tuple[str, ...] = ()  # only for runtime findings
    fix: Fix | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    # Optional short message for compact/LLM output. When set, reporters use
    # this instead of deriving a first-sentence from the full message.
    short_message: str | None = None

    @classmethod
    def from_node(
        cls,
        rule_id: str,
        message: str,
        node: ast.AST,
        ctx: AstContext,
        severity: Severity = Severity.WARNING,
        *,
        snippet: str | None = None,
        fix: Fix | None = None,
        extra: dict[str, Any] | None = None,
        short_message: str | None = None,
    ) -> Finding:
        return cls(
            rule_id=rule_id,
            message=message,
            severity=severity,
            location=Location.from_node(ctx.path, node),
            scope="ast",
            snippet=snippet or ctx.source_segment(node),
            fix=fix,
            extra=extra or {},
            short_message=short_message,
        )

    def compact_message(self) -> str:
        """Return the best available short message for compact output."""
        return self.short_message or _first_sentence(self.message)

    def as_compact_dict(self, cwd: Path | None = None) -> dict[str, Any]:
        """Return a minimal dict for compact/LLM-optimised JSON output.

        Intentionally excludes: schema metadata, scope, stack, extra, fix
        descriptions (redundant with msg), snippets (agent reads file via
        path+line), and null/empty fields.
        """
        return {
            "rule_id": self.rule_id,
            "sev": SEV_CODE[self.severity],
            "file": rel_path(self.location.path, cwd),
            "line": self.location.start_line,
            "col": self.location.start_col + 1,
            "msg": self.compact_message(),
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity.value,
            "location": self.location.as_dict(),
            "scope": self.scope,
            "snippet": self.snippet,
            "stack": list(self.stack),
            "fix": (
                {
                    "description": self.fix.description,
                    "replacement": self.fix.replacement,
                    "location": self.fix.location.as_dict() if self.fix.location else None,
                }
                if self.fix
                else None
            ),
            "extra": self.extra,
        }
