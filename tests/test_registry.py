from __future__ import annotations

import ast

from pyperfguard.core.registry import Registry
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity


class _DummyRule:
    id = "DUM001"
    name = "dummy"
    severity = Severity.INFO
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.Call,)

    def check(self, node, ctx):
        return ()


class _CatchAllRule:
    id = "DUM002"
    name = "catch-all"
    severity = Severity.HINT
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = ()

    def check(self, node, ctx):
        return ()


def test_register_and_lookup_by_node_type(fresh_registry: Registry):
    rule = _DummyRule()
    fresh_registry.register_rule(rule)
    matched = list(fresh_registry.ast_rules_for(ast.Call(func=ast.Name(id="x"), args=[], keywords=[])))
    assert rule in matched


def test_register_idempotent(fresh_registry: Registry):
    fresh_registry.register_rule(_DummyRule())
    fresh_registry.register_rule(_DummyRule())  # second call should be a no-op for same id
    assert len(fresh_registry.rules()) == 1


def test_select_filter(fresh_registry: Registry):
    fresh_registry.register_rule(_DummyRule())
    fresh_registry.register_rule(_CatchAllRule())
    assert {r.id for r in fresh_registry.select(include=["DUM001"])} == {"DUM001"}
    assert {r.id for r in fresh_registry.select(exclude=["DUM00"])} == set()
    assert {r.id for r in fresh_registry.select(include=["DUM"], exclude=["DUM002"])} == {"DUM001"}


def test_catch_all_rule_matches_any_node(fresh_registry: Registry):
    catch = _CatchAllRule()
    fresh_registry.register_rule(catch)
    matched = list(fresh_registry.ast_rules_for(ast.Pass()))
    assert catch in matched


def test_register_rule_rejects_non_protocol(fresh_registry: Registry):
    import pytest

    class NotARule:
        pass

    with pytest.raises(TypeError):
        fresh_registry.register_rule(NotARule())  # type: ignore[arg-type]
