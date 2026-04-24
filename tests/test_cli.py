from __future__ import annotations

import json
from pathlib import Path

from pyperfguard.cli import main


def test_cli_rules_lists_builtin(capsys):
    rc = main(["rules"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PKN001" in out and "PKN002" in out and "PKN010" in out


def test_cli_reporters_lists(capsys):
    rc = main(["reporters"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "terminal" in out and "json" in out and "sarif" in out


def test_cli_analyze_terminal_no_findings(tmp_path: Path, capsys):
    (tmp_path / "ok.py").write_text("def f(x=None): pass\n")
    rc = main(["analyze", str(tmp_path), "--format", "terminal"])
    assert rc == 0
    assert "no findings" in capsys.readouterr().out


def test_cli_analyze_json_emits_finding(tmp_path: Path, capsys):
    (tmp_path / "bad.py").write_text("def f(x=[]): pass\n")
    rc = main(["analyze", str(tmp_path), "--format", "json"])
    assert rc == 0  # PKN001 is a warning, not error
    out = capsys.readouterr().out
    doc = json.loads(out)
    # compact mode: rule_id key is preserved for compatibility
    assert any(f["rule_id"] == "PKN001" for f in doc["findings"])
    # compact mode: sev short code, no schema metadata
    assert "version" not in doc
    assert doc["findings"][0]["sev"] == "W"


def test_cli_analyze_json_verbose_emits_full_schema(tmp_path: Path, capsys):
    (tmp_path / "bad.py").write_text("def f(x=[]): pass\n")
    rc = main(["analyze", str(tmp_path), "--format", "json", "--verbose"])
    assert rc == 0
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["version"] == "1"
    assert any(f["rule_id"] == "PKN001" for f in doc["findings"])


def test_cli_exit_code_for_errors(tmp_path: Path, capsys):
    (tmp_path / "bad.py").write_text("session.execute('SELECT x ALLOW FILTERING')\n")
    rc = main(["analyze", str(tmp_path), "--format", "terminal"])
    assert rc == 1  # PKN010 is severity=ERROR


def test_cli_exit_zero_overrides(tmp_path: Path, capsys):
    (tmp_path / "bad.py").write_text("session.execute('SELECT x ALLOW FILTERING')\n")
    rc = main(["analyze", str(tmp_path), "--format", "terminal", "--exit-zero"])
    assert rc == 0


def test_cli_select_filter(tmp_path: Path, capsys):
    (tmp_path / "x.py").write_text("def f(x=[]): pass\nsession.execute('ALLOW FILTERING')\n")
    rc = main(["analyze", str(tmp_path), "--format", "json", "--select", "PKN010"])
    assert rc == 1
    doc = json.loads(capsys.readouterr().out)
    rule_ids = {f["rule_id"] for f in doc["findings"]}
    assert rule_ids == {"PKN010"}
