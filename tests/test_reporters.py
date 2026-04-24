from __future__ import annotations

import io
import json
from pathlib import Path

from pyperfguard.core.finding import Finding, Location
from pyperfguard.core.severity import Severity
from pyperfguard.reporters.json_out import JsonReporter
from pyperfguard.reporters.sarif import SarifReporter
from pyperfguard.reporters.terminal import TerminalReporter


def _f(
    rule_id: str = "PKN001",
    path: str = "a.py",
    line: int = 1,
    sev=Severity.WARNING,
    short_message: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        message="Function 'x' uses a mutable default argument. Defaults are evaluated once.",
        severity=sev,
        location=Location(path=Path(path), start_line=line, start_col=0, end_line=line, end_col=5),
        snippet="def x(): pass",
        short_message=short_message,
    )


# ---------------------------------------------------------------------------
# TerminalReporter — compact (default)
# ---------------------------------------------------------------------------


def test_terminal_no_findings_prints_ok():
    buf = io.StringIO()
    TerminalReporter(stream=buf, color=False).report([])
    assert "no findings" in buf.getvalue()


def test_terminal_compact_single_line_per_finding():
    buf = io.StringIO()
    TerminalReporter(stream=buf, color=False).report([_f(), _f("PKN002", sev=Severity.ERROR)])
    lines = [
        line for line in buf.getvalue().splitlines() if line.strip() and "findings" not in line
    ]
    # Compact: one line per finding (no multi-line snippet/fix)
    assert len(lines) == 2


def test_terminal_compact_shows_rule_and_severity_code():
    buf = io.StringIO()
    TerminalReporter(stream=buf, color=False).report([_f()])
    out = buf.getvalue()
    assert "PKN001[W]" in out


def test_terminal_compact_no_snippet():
    buf = io.StringIO()
    TerminalReporter(stream=buf, color=False).report([_f()])
    # Snippet text should not appear in compact mode
    assert "def x(): pass" not in buf.getvalue()


def test_terminal_compact_uses_short_message_when_set():
    f = _f(short_message="mutable default in x")
    buf = io.StringIO()
    TerminalReporter(stream=buf, color=False).report([f])
    assert "mutable default in x" in buf.getvalue()


def test_terminal_compact_first_sentence_fallback():
    buf = io.StringIO()
    TerminalReporter(stream=buf, color=False).report([_f()])
    out = buf.getvalue()
    # Should show first sentence without RST backticks, without the second sentence
    assert "mutable default argument" in out
    # Second sentence should be trimmed
    assert "Defaults are evaluated once." not in out


def test_terminal_compact_summary_uses_codes():
    buf = io.StringIO()
    TerminalReporter(stream=buf, color=False).report([_f(), _f("PKN002", sev=Severity.ERROR)])
    out = buf.getvalue()
    assert "2 findings" in out
    assert "1W" in out
    assert "1E" in out


def test_terminal_verbose_shows_snippet():
    buf = io.StringIO()
    TerminalReporter(stream=buf, color=False, verbose=True).report([_f()])
    assert "def x(): pass" in buf.getvalue()


def test_terminal_verbose_shows_full_message():
    buf = io.StringIO()
    TerminalReporter(stream=buf, color=False, verbose=True).report([_f()])
    out = buf.getvalue()
    assert "Defaults are evaluated once." in out


def test_terminal_verbose_summary_uses_full_words():
    buf = io.StringIO()
    TerminalReporter(stream=buf, color=False, verbose=True).report([_f()])
    out = buf.getvalue()
    assert "warning" in out
    assert "1 findings" in out or "1 finding" in out


def test_terminal_lists_findings_with_summary():
    buf = io.StringIO()
    TerminalReporter(stream=buf, color=False).report([_f(), _f("PKN002", sev=Severity.ERROR)])
    out = buf.getvalue()
    assert "PKN001" in out and "PKN002" in out
    assert "2 findings" in out


# ---------------------------------------------------------------------------
# JsonReporter — compact (default)
# ---------------------------------------------------------------------------


def test_json_compact_emits_well_formed_doc():
    buf = io.StringIO()
    JsonReporter(stream=buf).report([_f()])
    doc = json.loads(buf.getvalue())
    assert "findings" in doc
    assert "version" not in doc  # compact: no schema metadata
    assert "schema" not in doc
    f = doc["findings"][0]
    assert f["rule_id"] == "PKN001"
    assert f["sev"] == "W"
    assert "file" in f
    assert "line" in f
    assert "msg" in f


def test_json_compact_no_nulls():
    buf = io.StringIO()
    JsonReporter(stream=buf).report([_f()])
    doc = json.loads(buf.getvalue())
    f = doc["findings"][0]
    # Compact must not include null/empty fields
    assert "scope" not in f
    assert "stack" not in f
    assert "extra" not in f


def test_json_compact_relative_path():
    # Use a path that IS under cwd so rel_path() can relativize it.
    cwd = Path.cwd()
    sub = cwd / "src" / "app.py"
    f = Finding(
        rule_id="PKN001",
        message="msg. Second sentence.",
        severity=Severity.WARNING,
        location=Location(path=sub, start_line=1, start_col=0),
    )
    buf = io.StringIO()
    JsonReporter(stream=buf).report([f])
    doc = json.loads(buf.getvalue())
    file_val = doc["findings"][0]["file"]
    # Should be relative: "src/app.py" not the full absolute path
    assert file_val == "src/app.py"


def test_json_compact_uses_short_message():
    f = _f(short_message="mutable default in x")
    buf = io.StringIO()
    JsonReporter(stream=buf).report([f])
    doc = json.loads(buf.getvalue())
    assert doc["findings"][0]["msg"] == "mutable default in x"


def test_json_compact_no_indent_when_not_tty():
    buf = io.StringIO()
    JsonReporter(stream=buf).report([_f()])
    raw = buf.getvalue()
    # Compact (no indent) → no leading spaces
    assert "\n  " not in raw


def test_json_verbose_emits_full_schema():
    buf = io.StringIO()
    JsonReporter(stream=buf, verbose=True).report([_f()])
    doc = json.loads(buf.getvalue())
    assert doc["version"] == "1"
    assert "schema" in doc
    f = doc["findings"][0]
    assert f["rule_id"] == "PKN001"
    assert "message" in f
    assert "severity" in f
    assert "location" in f


def test_json_verbose_includes_snippet():
    buf = io.StringIO()
    JsonReporter(stream=buf, verbose=True).report([_f()])
    doc = json.loads(buf.getvalue())
    assert doc["findings"][0]["snippet"] == "def x(): pass"


# ---------------------------------------------------------------------------
# SarifReporter (unchanged semantics — always verbose/full)
# ---------------------------------------------------------------------------


def test_sarif_doc_shape():
    buf = io.StringIO()
    SarifReporter(stream=buf).report([_f(), _f("PKN001"), _f("PKN010", sev=Severity.ERROR)])
    doc = json.loads(buf.getvalue())
    assert doc["version"] == "2.1.0"
    assert "runs" in doc and len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "pyperfguard"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {"PKN001", "PKN010"}
    assert len(run["results"]) == 3
    for result in run["results"]:
        assert 0 <= result["ruleIndex"] < len(run["tool"]["driver"]["rules"])
        assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == result["ruleId"]


def test_sarif_levels_mapping():
    buf = io.StringIO()
    SarifReporter(stream=buf).report(
        [
            _f("R1", sev=Severity.ERROR),
            _f("R2", sev=Severity.WARNING),
            _f("R3", sev=Severity.INFO),
        ]
    )
    doc = json.loads(buf.getvalue())
    levels = sorted(r["level"] for r in doc["runs"][0]["results"])
    assert levels == ["error", "note", "warning"]


def test_sarif_accepts_verbose_kwarg():
    buf = io.StringIO()
    # Must not raise
    SarifReporter(stream=buf, verbose=True).report([_f()])
    doc = json.loads(buf.getvalue())
    assert doc["version"] == "2.1.0"
