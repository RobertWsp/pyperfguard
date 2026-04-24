from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix, Location
from pyperfguard.core.severity import Severity


def test_location_from_node_uses_pep657_end_positions():
    src = "x = 1 + 2\n"
    mod = ast.parse(src)
    expr = mod.body[0]  # Assign
    loc = Location.from_node(Path("a.py"), expr)
    assert loc.path == Path("a.py")
    assert loc.start_line == 1
    assert loc.end_line == 1
    assert loc.end_col is not None and loc.end_col >= loc.start_col


def test_finding_from_node_includes_snippet():
    src = "def foo(x=[]): pass\n"
    mod = ast.parse(src)
    func = mod.body[0]
    ctx = AstContext(path=Path("a.py"), source=src, module=mod)
    f = Finding.from_node("PKN001", "msg", func, ctx, severity=Severity.WARNING)
    assert f.rule_id == "PKN001"
    assert f.severity is Severity.WARNING
    assert f.scope == "ast"
    assert f.snippet is not None and "def foo" in f.snippet


def test_finding_as_dict_round_trip_keys():
    src = "x = 1\n"
    mod = ast.parse(src)
    ctx = AstContext(path=Path("a.py"), source=src, module=mod)
    f = Finding.from_node(
        "PKN999",
        "test",
        mod.body[0],
        ctx,
        severity=Severity.ERROR,
        fix=Fix(description="do this"),
        extra={"k": "v"},
    )
    d = f.as_dict()
    assert d["rule_id"] == "PKN999"
    assert d["severity"] == "error"
    assert d["fix"] == {"description": "do this", "replacement": None, "location": None}
    assert d["extra"] == {"k": "v"}


def test_severity_sarif_levels():
    assert Severity.ERROR.sarif_level == "error"
    assert Severity.WARNING.sarif_level == "warning"
    assert Severity.INFO.sarif_level == "note"
    assert Severity.HINT.sarif_level == "note"
