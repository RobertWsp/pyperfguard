from __future__ import annotations

import ast
import fnmatch
import logging
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.config import Config
from pyperfguard.core.finding import Finding
from pyperfguard.core.registry import Registry, get_registry

_log = logging.getLogger(__name__)


@dataclass(slots=True)
class AstEngine:
    """Run static analysis over a tree of Python files."""

    registry: Registry
    config: Config

    def run(self, paths: Iterable[Path]) -> list[Finding]:
        findings: list[Finding] = []
        active_registry = self._build_filtered_registry()

        # Pass 1: per-file visitor (PKN001-PKN025). Cache parsed results so
        # Pass 2 (CallGraph) can reuse them without re-reading files from disk.
        parsed: dict[Path, tuple[ast.Module, str]] = {}
        for file in self._iter_files(paths):
            try:
                source = file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                _log.debug("pyperfguard: skipping %s: %s", file, exc)
                continue
            try:
                module = ast.parse(source, filename=str(file), type_comments=True)
            except SyntaxError as exc:
                _log.debug("pyperfguard: skipping %s (SyntaxError): %s", file, exc)
                continue
            parsed[file] = (module, source)
            ctx = AstContext(path=file, source=source, module=module)
            visitor = PyperfVisitor(registry=active_registry, ctx=ctx)
            visitor.visit(module)
            findings.extend(visitor.findings)

        # Pass 2: inter-procedural CallGraph (PKN102) — runs only when PKN102 is
        # not excluded by select/ignore config so we skip the work when unneeded.
        if parsed and self._is_rule_active("PKN102"):
            from pyperfguard.ast_engine.call_graph import CallGraph

            cg = CallGraph()
            for file, (module, source) in parsed.items():
                cg.add_module(file, module, source)
            cg.compute()
            findings.extend(cg.n1_findings())

        return findings

    # ----- internals -------------------------------------------------------

    def _build_filtered_registry(self) -> Registry:
        """Return a transient Registry containing only the selected rules."""
        selected = self.registry.select(
            include=self.config.select or None,
            exclude=self.config.ignore or None,
        )
        sub = Registry()
        for rule in selected:
            sub.register_rule(rule)
        return sub

    def _is_rule_active(self, rule_id: str) -> bool:
        """True when rule_id passes the select/ignore filters from config."""
        cfg = self.config
        if cfg.select and not any(rule_id.startswith(p) for p in cfg.select):
            return False
        return not (cfg.ignore and any(rule_id.startswith(p) for p in cfg.ignore))

    def _iter_files(self, paths: Iterable[Path]) -> Iterator[Path]:
        seen: set[Path] = set()
        for root in paths:
            root = root.resolve()
            if root.is_file():
                if root.suffix == ".py" and root not in seen and not self._excluded(root):
                    seen.add(root)
                    yield root
                continue
            if not root.is_dir():
                continue
            for file in root.rglob("*.py"):
                file = file.resolve()
                if file in seen or self._excluded(file):
                    continue
                seen.add(file)
                yield file

    def _excluded(self, path: Path) -> bool:
        s = str(path)
        return any(fnmatch.fnmatch(s, pat) for pat in self.config.exclude)


def analyze(
    paths: Iterable[Path | str],
    *,
    config: Config | None = None,
    registry: Registry | None = None,
    discover: bool = True,
) -> list[Finding]:
    """Convenience entry point used by the CLI and the public API."""
    cfg = config or Config.load()
    reg = registry or get_registry()
    if discover:
        reg.discover()
    engine = AstEngine(registry=reg, config=cfg)
    return engine.run([Path(p) for p in paths])
