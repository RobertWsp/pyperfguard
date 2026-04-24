"""End-to-end AST analysis tests against realistic fixture files.

Each fixture is analyzed with the full rule set loaded from entry points.
Tests assert on the exact set of rule IDs emitted, JSON/SARIF output
validity, filter flags, and exit-code semantics.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from pyperfguard import analyze
from pyperfguard.core.config import Config
from pyperfguard.core.severity import Severity
from pyperfguard.reporters.json_out import JsonReporter
from pyperfguard.reporters.sarif import SarifReporter

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rule_ids(fixture_name: str, config: Config | None = None) -> set[str]:
    path = FIXTURES / fixture_name
    findings = analyze([path], config=config)
    return {f.rule_id for f in findings}


def _findings(fixture_name: str, config: Config | None = None):
    path = FIXTURES / fixture_name
    return analyze([path], config=config)


# ---------------------------------------------------------------------------
# Per-fixture expectations
# ---------------------------------------------------------------------------


class TestDjangoViews:
    """django_views.py — N+1 ORM patterns, mutable defaults, bare excepts, blocking async."""

    EXPECTED_RULES = {"PKN001", "PKN002", "PKN003", "PKN009", "PKN019"}

    def test_expected_rules_present(self):
        assert _rule_ids("django_views.py") == self.EXPECTED_RULES

    def test_mutable_default_count(self):
        findings = _findings("django_views.py")
        pkn001 = [f for f in findings if f.rule_id == "PKN001"]
        assert len(pkn001) == 2, f"Expected 2 PKN001, got {len(pkn001)}"

    def test_bare_except_count(self):
        findings = _findings("django_views.py")
        pkn002 = [f for f in findings if f.rule_id == "PKN002"]
        assert len(pkn002) == 2

    def test_string_concat_count(self):
        findings = _findings("django_views.py")
        pkn003 = [f for f in findings if f.rule_id == "PKN003"]
        assert len(pkn003) == 2

    def test_blocking_async_count(self):
        findings = _findings("django_views.py")
        pkn009 = [f for f in findings if f.rule_id == "PKN009"]
        assert len(pkn009) == 3

    def test_no_unexpected_rules(self):
        unexpected = _rule_ids("django_views.py") - self.EXPECTED_RULES
        assert not unexpected, f"Unexpected rules: {unexpected}"


class TestDataPipeline:
    """data_pipeline.py — string concat, deepcopy, re.compile, datetime, heavy import."""

    EXPECTED_RULES = {"PKN003", "PKN005", "PKN006", "PKN007", "PKN014"}

    def test_expected_rules_present(self):
        assert _rule_ids("data_pipeline.py") == self.EXPECTED_RULES

    def test_recompile_in_loop_count(self):
        findings = _findings("data_pipeline.py")
        assert len([f for f in findings if f.rule_id == "PKN005"]) == 2

    def test_deepcopy_in_loop_count(self):
        findings = _findings("data_pipeline.py")
        assert len([f for f in findings if f.rule_id == "PKN006"]) == 2

    def test_datetime_in_loop_count(self):
        findings = _findings("data_pipeline.py")
        assert len([f for f in findings if f.rule_id == "PKN007"]) >= 2

    def test_heavy_import_count(self):
        findings = _findings("data_pipeline.py")
        assert len([f for f in findings if f.rule_id == "PKN014"]) == 2

    def test_no_unexpected_rules(self):
        unexpected = _rule_ids("data_pipeline.py") - self.EXPECTED_RULES
        assert not unexpected, f"Unexpected rules: {unexpected}"


class TestCassandraService:
    """cassandra_service.py — ALLOW FILTERING, prepare-in-loop, IN query, batch loop."""

    EXPECTED_RULES = {"PKN010", "PKN011", "PKN012", "PKN013", "PKN102"}

    def test_expected_rules_present(self):
        assert _rule_ids("cassandra_service.py") == self.EXPECTED_RULES

    def test_allow_filtering_count(self):
        findings = _findings("cassandra_service.py")
        pkn010 = [f for f in findings if f.rule_id == "PKN010"]
        assert len(pkn010) >= 3

    def test_allow_filtering_severity_is_error(self):
        findings = _findings("cassandra_service.py")
        for f in findings:
            if f.rule_id == "PKN010":
                assert f.severity is Severity.ERROR

    def test_prepare_in_loop_count(self):
        findings = _findings("cassandra_service.py")
        assert len([f for f in findings if f.rule_id == "PKN011"]) == 2

    def test_in_query_count(self):
        findings = _findings("cassandra_service.py")
        assert len([f for f in findings if f.rule_id == "PKN012"]) == 2

    def test_batch_add_in_loop_count(self):
        findings = _findings("cassandra_service.py")
        assert len([f for f in findings if f.rule_id == "PKN013"]) == 2

    def test_no_unexpected_rules(self):
        unexpected = _rule_ids("cassandra_service.py") - self.EXPECTED_RULES
        assert not unexpected, f"Unexpected rules: {unexpected}"


class TestAsyncApi:
    """async_api.py — await in for loop, blocking calls in async def."""

    EXPECTED_RULES = {"PKN008", "PKN009", "PKN025"}

    def test_expected_rules_present(self):
        assert _rule_ids("async_api.py") == self.EXPECTED_RULES

    def test_await_in_loop_count(self):
        findings = _findings("async_api.py")
        pkn008 = [f for f in findings if f.rule_id == "PKN008"]
        assert len(pkn008) >= 4

    def test_blocking_in_async_count(self):
        findings = _findings("async_api.py")
        pkn009 = [f for f in findings if f.rule_id == "PKN009"]
        assert len(pkn009) >= 3

    def test_no_unexpected_rules(self):
        unexpected = _rule_ids("async_api.py") - self.EXPECTED_RULES
        assert not unexpected, f"Unexpected rules: {unexpected}"


class TestCleanCode:
    """clean_code.py — well-written production code, should produce ZERO findings."""

    def test_zero_findings(self):
        findings = _findings("clean_code.py")
        if findings:
            details = "\n".join(
                f"  {f.rule_id} @ line {f.location.start_line}: {f.message[:80]}" for f in findings
            )
            pytest.fail(f"Expected zero findings, got:\n{details}")

    def test_no_pknxxx_rules(self):
        assert _rule_ids("clean_code.py") == set()


# ---------------------------------------------------------------------------
# Output format tests
# ---------------------------------------------------------------------------


class TestJsonOutput:
    def test_json_compact_round_trip(self):
        """Default (compact) mode: minimal keys, no schema metadata."""
        findings = _findings("django_views.py")
        buf = io.StringIO()
        JsonReporter(stream=buf).report(findings)

        payload = json.loads(buf.getvalue())
        assert "version" not in payload  # compact: no schema metadata
        assert "findings" in payload
        assert isinstance(payload["findings"], list)
        assert len(payload["findings"]) == len(findings)

    def test_json_compact_finding_schema(self):
        """Compact findings use short keys optimised for LLM consumption."""
        findings = _findings("django_views.py")
        buf = io.StringIO()
        JsonReporter(stream=buf).report(findings)

        payload = json.loads(buf.getvalue())
        for item in payload["findings"]:
            assert "rule_id" in item  # rule_id preserved for compatibility
            assert "sev" in item  # short severity code: W/E/I/H
            assert "file" in item  # relative path
            assert "line" in item
            assert "msg" in item  # short message

    def test_json_verbose_round_trip(self):
        """Verbose mode: full schema compatible with external tooling."""
        findings = _findings("django_views.py")
        buf = io.StringIO()
        JsonReporter(stream=buf, verbose=True).report(findings)

        payload = json.loads(buf.getvalue())
        assert payload["version"] == "1"
        assert "findings" in payload
        assert isinstance(payload["findings"], list)
        assert len(payload["findings"]) == len(findings)

    def test_json_verbose_finding_schema(self):
        """Verbose findings have full location, message, severity fields."""
        findings = _findings("django_views.py")
        buf = io.StringIO()
        JsonReporter(stream=buf, verbose=True).report(findings)

        payload = json.loads(buf.getvalue())
        for item in payload["findings"]:
            assert "rule_id" in item
            assert "message" in item
            assert "severity" in item
            assert "location" in item
            loc = item["location"]
            assert "path" in loc
            assert "start_line" in loc

    def test_json_empty_findings(self):
        findings = _findings("clean_code.py")
        buf = io.StringIO()
        JsonReporter(stream=buf).report(findings)
        payload = json.loads(buf.getvalue())
        assert payload["findings"] == []


class TestSarifOutput:
    def test_sarif_schema_version(self):
        findings = _findings("django_views.py")
        buf = io.StringIO()
        SarifReporter(stream=buf).report(findings)

        doc = json.loads(buf.getvalue())
        assert doc["version"] == "2.1.0"
        assert "$schema" in doc

    def test_sarif_has_runs(self):
        findings = _findings("django_views.py")
        buf = io.StringIO()
        SarifReporter(stream=buf).report(findings)

        doc = json.loads(buf.getvalue())
        runs = doc.get("runs", [])
        assert len(runs) == 1
        run = runs[0]
        assert "tool" in run
        assert "results" in run

    def test_sarif_tool_name(self):
        findings = _findings("django_views.py")
        buf = io.StringIO()
        SarifReporter(stream=buf).report(findings)

        doc = json.loads(buf.getvalue())
        driver = doc["runs"][0]["tool"]["driver"]
        assert driver["name"] == "pyperfguard"

    def test_sarif_rule_definitions(self):
        findings = _findings("cassandra_service.py")
        buf = io.StringIO()
        SarifReporter(stream=buf).report(findings)

        doc = json.loads(buf.getvalue())
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert "PKN010" in rule_ids

    def test_sarif_results_have_locations(self):
        findings = _findings("django_views.py")
        buf = io.StringIO()
        SarifReporter(stream=buf).report(findings)

        doc = json.loads(buf.getvalue())
        for result in doc["runs"][0]["results"]:
            assert "locations" in result
            assert len(result["locations"]) >= 1

    def test_sarif_error_level_for_pkn010(self):
        findings = _findings("cassandra_service.py")
        buf = io.StringIO()
        SarifReporter(stream=buf).report(findings)

        doc = json.loads(buf.getvalue())
        error_results = [r for r in doc["runs"][0]["results"] if r["ruleId"] == "PKN010"]
        assert error_results, "Expected PKN010 results in SARIF"
        for r in error_results:
            assert r["level"] == "error"


# ---------------------------------------------------------------------------
# Config: --select / --ignore filter tests
# ---------------------------------------------------------------------------


class TestConfigFilters:
    def test_select_only_pkn001(self):
        cfg = Config.from_dict({"select": ["PKN001"]})
        findings = _findings("django_views.py", config=cfg)
        rule_ids = {f.rule_id for f in findings}
        assert rule_ids == {"PKN001"}

    def test_select_pkn010_cassandra(self):
        cfg = Config.from_dict({"select": ["PKN010"]})
        findings = _findings("cassandra_service.py", config=cfg)
        assert all(f.rule_id == "PKN010" for f in findings)
        assert len(findings) >= 3

    def test_ignore_pkn001(self):
        cfg = Config.from_dict({"select": ["PKN"], "ignore": ["PKN001"]})
        findings = _findings("django_views.py", config=cfg)
        assert not any(f.rule_id == "PKN001" for f in findings)
        assert any(f.rule_id == "PKN002" for f in findings)

    def test_ignore_multiple_rules(self):
        cfg = Config.from_dict({"select": ["PKN"], "ignore": ["PKN001", "PKN002"]})
        findings = _findings("django_views.py", config=cfg)
        assert not any(f.rule_id in ("PKN001", "PKN002") for f in findings)

    def test_select_cassandra_prefix(self):
        cfg = Config.from_dict({"select": ["PKN010", "PKN011", "PKN012", "PKN013"]})
        findings = _findings("cassandra_service.py", config=cfg)
        rule_ids = {f.rule_id for f in findings}
        assert rule_ids == {"PKN010", "PKN011", "PKN012", "PKN013"}

    def test_select_nonexistent_rule(self):
        cfg = Config.from_dict({"select": ["PKN999"]})
        findings = _findings("django_views.py", config=cfg)
        assert findings == []

    def test_empty_select_defaults_to_pkn_prefix(self):
        # default Config selects ["PKN"]
        cfg = Config()
        findings = _findings("django_views.py", config=cfg)
        assert len(findings) > 0


# ---------------------------------------------------------------------------
# Exit-code semantics (severity-based)
# ---------------------------------------------------------------------------


class TestSeverityExitCode:
    """PKN010 is ERROR — files with ALLOW FILTERING should signal exit code 1."""

    def test_cassandra_has_error_severity(self):
        findings = _findings("cassandra_service.py")
        has_error = any(f.severity is Severity.ERROR for f in findings)
        assert has_error, "Expected at least one ERROR finding in cassandra_service"

    def test_clean_code_has_no_error_severity(self):
        findings = _findings("clean_code.py")
        has_error = any(f.severity is Severity.ERROR for f in findings)
        assert not has_error

    def test_django_views_no_error_severity(self):
        """django_views only has WARNING/INFO rules — no ERROR."""
        findings = _findings("django_views.py")
        severities = {f.severity for f in findings}
        assert Severity.ERROR not in severities

    def test_exit_code_logic(self):
        """Simulate CLI exit code: 1 if any ERROR finding, 0 otherwise."""

        def compute_exit_code(findings) -> int:
            return 1 if any(f.severity is Severity.ERROR for f in findings) else 0

        assert compute_exit_code(_findings("cassandra_service.py")) == 1
        assert compute_exit_code(_findings("clean_code.py")) == 0
        assert compute_exit_code(_findings("django_views.py")) == 0

    def test_all_fixtures_combined_has_error(self):
        all_findings = []
        for name in ["django_views.py", "data_pipeline.py", "cassandra_service.py", "async_api.py"]:
            all_findings.extend(_findings(name))
        has_error = any(f.severity is Severity.ERROR for f in all_findings)
        assert has_error


# ---------------------------------------------------------------------------
# Cross-file analysis
# ---------------------------------------------------------------------------


class TestDirectoryAnalysis:
    def test_analyze_fixtures_directory(self):
        """Analyzing the fixtures dir should collect all anti-patterns."""
        findings = analyze([FIXTURES])
        rule_ids = {f.rule_id for f in findings}
        # All expected rule families must appear
        assert "PKN001" in rule_ids
        assert "PKN010" in rule_ids
        assert "PKN008" in rule_ids
        assert "PKN014" in rule_ids

    def test_analyze_directory_does_not_flag_clean_code(self):
        """clean_code.py must not contribute any findings even in bulk analysis."""
        findings = analyze([FIXTURES])
        clean_path = str(FIXTURES / "clean_code.py")
        clean_findings = [f for f in findings if str(f.location.path) == clean_path]
        assert clean_findings == []
