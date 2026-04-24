from __future__ import annotations

from pathlib import Path

from pyperfguard.ast_engine.runner import analyze
from pyperfguard.core.config import Config
from pyperfguard.core.registry import Registry
from pyperfguard.rules.allow_filtering import AllowFilteringRule
from pyperfguard.rules.bare_except import BareExceptRule
from pyperfguard.rules.mutable_default import MutableDefaultRule


def _make_registry() -> Registry:
    reg = Registry()
    reg.register_rule(MutableDefaultRule())
    reg.register_rule(BareExceptRule())
    reg.register_rule(AllowFilteringRule())
    return reg


def test_runner_walks_directory(tmp_path: Path):
    (tmp_path / "ok.py").write_text("def f(x=None): pass\n")
    (tmp_path / "bad.py").write_text("def f(x=[]): pass\n")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "more.py").write_text("session.execute('SELECT * FROM t ALLOW FILTERING')\n")

    findings = analyze([tmp_path], registry=_make_registry(), config=Config(), discover=False)
    rule_ids = {f.rule_id for f in findings}
    assert {"PKN001", "PKN010"} <= rule_ids


def test_runner_handles_single_file(tmp_path: Path):
    p = tmp_path / "x.py"
    p.write_text("def f(x=[]): ...\n")
    findings = analyze([p], registry=_make_registry(), config=Config(), discover=False)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN001"


def test_runner_skips_unparseable(tmp_path: Path):
    (tmp_path / "broken.py").write_text("def f(:\n")  # SyntaxError
    findings = analyze([tmp_path], registry=_make_registry(), config=Config(), discover=False)
    assert findings == []


def test_runner_excludes_via_config(tmp_path: Path):
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "x.py").write_text("def f(x=[]): ...\n")
    cfg = Config()
    cfg.exclude = ["**/build/**"]
    findings = analyze([tmp_path], registry=_make_registry(), config=cfg, discover=False)
    assert findings == []


def test_runner_skips_unreadable_file(tmp_path: Path):
    """OSError on file read → skip silently, no crash, no findings."""
    import stat

    p = tmp_path / "unreadable.py"
    p.write_text("def f(x=[]): pass\n")
    # Remove read permission
    p.chmod(0o000)
    try:
        findings = analyze([tmp_path], registry=_make_registry(), config=Config(), discover=False)
        assert all(f.location.path != p for f in findings)
    finally:
        p.chmod(stat.S_IRUSR | stat.S_IWUSR)


def test_runner_skips_unicode_error(tmp_path: Path):
    """Non-UTF-8 binary file → skip silently, no crash."""
    p = tmp_path / "binary.py"
    p.write_bytes(b"\xff\xfe" + b"def f(x=[]): pass\n")
    findings = analyze([tmp_path], registry=_make_registry(), config=Config(), discover=False)
    assert all(f.location.path != p for f in findings)


def test_runner_debug_logs_skipped_file(tmp_path: Path, caplog):
    """Debug log emitted when file is skipped due to SyntaxError."""
    import logging

    p = tmp_path / "broken.py"
    p.write_text("def f(:\n")
    with caplog.at_level(logging.DEBUG, logger="pyperfguard.ast_engine.runner"):
        analyze([tmp_path], registry=_make_registry(), config=Config(), discover=False)
    assert any("SyntaxError" in r.message for r in caplog.records)


def test_runner_select_filter(tmp_path: Path):
    p = tmp_path / "x.py"
    p.write_text("def f(x=[]): pass\ntry:\n    g()\nexcept:\n    pass\n")
    cfg = Config(select=["PKN001"])
    findings = analyze([p], registry=_make_registry(), config=cfg, discover=False)
    assert {f.rule_id for f in findings} == {"PKN001"}
