"""Minimal SARIF 2.1.0 reporter.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
We emit the subset GitHub Code Scanning consumes: a single ``run`` with one
``tool``, one ``results`` array, and rule definitions in ``tool.driver.rules``.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Iterable, TextIO

from pyperfguard import __version__
from pyperfguard.core.finding import Finding


class SarifReporter:
    SCHEMA_URI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.json"
    VERSION = "2.1.0"

    def __init__(
        self,
        stream: TextIO | None = None,
        indent: int | None = 2,
        verbose: bool = False,
    ) -> None:
        self.stream = stream or sys.stdout
        self.indent = indent

    def report(self, findings: Iterable[Finding]) -> None:
        findings_list = list(findings)
        rule_index: dict[str, int] = {}
        rules: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []

        for f in findings_list:
            if f.rule_id not in rule_index:
                rule_index[f.rule_id] = len(rules)
                rules.append(
                    {
                        "id": f.rule_id,
                        "shortDescription": {"text": f.rule_id},
                        "defaultConfiguration": {"level": f.severity.sarif_level},
                    }
                )
            results.append(self._result(f, rule_index[f.rule_id]))

        doc = {
            "$schema": self.SCHEMA_URI,
            "version": self.VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "pyperfguard",
                            "version": __version__,
                            "informationUri": "https://pyperfguard.dev",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }
        json.dump(doc, self.stream, indent=self.indent, default=str)
        self.stream.write("\n")

    def _result(self, f: Finding, rule_idx: int) -> dict[str, Any]:
        region: dict[str, Any] = {
            "startLine": f.location.start_line,
            "startColumn": f.location.start_col + 1,
        }
        if f.location.end_line is not None:
            region["endLine"] = f.location.end_line
        if f.location.end_col is not None:
            region["endColumn"] = f.location.end_col + 1
        if f.snippet:
            region["snippet"] = {"text": f.snippet}
        return {
            "ruleId": f.rule_id,
            "ruleIndex": rule_idx,
            "level": f.severity.sarif_level,
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(f.location.path)},
                        "region": region,
                    }
                }
            ],
        }
