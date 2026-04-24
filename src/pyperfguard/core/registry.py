from __future__ import annotations

import ast
import importlib.metadata
from collections import defaultdict
from collections.abc import Iterable
from typing import cast

from pyperfguard.core.rule import Rule, RuleScope
from pyperfguard.runtime_engine.patcher import Patcher

_RULES_GROUP = "pyperfguard.rules"
_REPORTERS_GROUP = "pyperfguard.reporters"
_PATCHERS_GROUP = "pyperfguard.patchers"


class Registry:
    """Singleton-ish registry of rules, reporters and patchers.

    Rules can be added programmatically via :meth:`register_rule`, or discovered
    automatically through ``importlib.metadata`` entry points (call
    :meth:`discover` to load them).
    """

    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}
        self._rules_by_node_type: dict[type[ast.AST], list[Rule]] = defaultdict(list)
        self._catch_all_rules: list[Rule] = []
        self._reporters: dict[str, type] = {}
        self._patchers: dict[str, Patcher] = {}
        self._discovered = False

    # ----- Rules ------------------------------------------------------------

    def register_rule(self, rule: Rule) -> None:
        if not isinstance(rule, Rule):
            raise TypeError(f"Object {rule!r} does not satisfy the Rule protocol")
        if rule.id in self._rules:
            return  # idempotent
        self._rules[rule.id] = rule
        if rule.scope is RuleScope.AST:
            if not rule.node_types:
                self._catch_all_rules.append(rule)
            else:
                for nt in rule.node_types:
                    self._rules_by_node_type[nt].append(rule)

    def rules(self) -> list[Rule]:
        return list(self._rules.values())

    def ast_rules_for(self, node: ast.AST) -> Iterable[Rule]:
        # Direct match (node type). MRO lookup is unnecessary because ast nodes
        # are leaf types in practice — the visitor dispatches by exact type.
        rules = self._rules_by_node_type.get(type(node), ())
        if self._catch_all_rules:
            return [*rules, *self._catch_all_rules]
        return rules

    def select(
        self, *, include: list[str] | None = None, exclude: list[str] | None = None
    ) -> list[Rule]:
        """Return rules filtered by id-prefix include/exclude lists."""
        result = []
        for rule in self._rules.values():
            if include and not any(rule.id.startswith(p) for p in include):
                continue
            if exclude and any(rule.id.startswith(p) for p in exclude):
                continue
            result.append(rule)
        return result

    # ----- Reporters --------------------------------------------------------

    def register_reporter(self, name: str, cls: type) -> None:
        self._reporters[name] = cls

    def reporter(self, name: str) -> type:
        if name not in self._reporters:
            raise KeyError(f"Unknown reporter: {name!r}. Known: {sorted(self._reporters)}")
        return self._reporters[name]

    def reporter_names(self) -> list[str]:
        return sorted(self._reporters)

    # ----- Patchers ---------------------------------------------------------

    def register_patcher(self, name: str, obj: Patcher) -> None:
        self._patchers[name] = obj

    def patchers(self) -> dict[str, Patcher]:
        return dict(self._patchers)

    # ----- Discovery --------------------------------------------------------

    def discover(self, *, force: bool = False) -> None:
        """Load rules/reporters/patchers from ``importlib.metadata`` entry points."""
        if self._discovered and not force:
            return
        for ep in importlib.metadata.entry_points(group=_RULES_GROUP):
            try:
                rule_cls = ep.load()
                self.register_rule(rule_cls())
            except Exception as exc:
                _warn(f"Failed to load rule {ep.name!r}: {exc}")
        for ep in importlib.metadata.entry_points(group=_REPORTERS_GROUP):
            try:
                self.register_reporter(ep.name, ep.load())
            except Exception as exc:
                _warn(f"Failed to load reporter {ep.name!r}: {exc}")
        for ep in importlib.metadata.entry_points(group=_PATCHERS_GROUP):
            try:
                self.register_patcher(ep.name, cast(Patcher, ep.load()()))
            except Exception as exc:
                _warn(f"Failed to load patcher {ep.name!r}: {exc}")
        self._discovered = True


def _warn(msg: str) -> None:
    import sys

    print(f"[pyperfguard] {msg}", file=sys.stderr)


_REGISTRY: Registry | None = None


def get_registry() -> Registry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = Registry()
    return _REGISTRY


def reset_registry() -> None:
    """Test helper — clears the global registry."""
    global _REGISTRY
    _REGISTRY = None
