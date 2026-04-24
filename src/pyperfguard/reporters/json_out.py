from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import TextIO

from pyperfguard.core.finding import Finding


class JsonReporter:
    """JSON reporter.

    **Default (compact)** — minimal keys, relative paths, short messages, no
    nulls or empty collections.  Schema::

        {
          "findings": [
            {
              "rule_id": "PKN102",
              "sev": "W",
              "file": "order/utils.py",
              "line": 456,
              "col": 5,
              "msg": "N+1 in add_gift_cards_to_order: calls set_gift_card_user() per for-loop iter",
              "fix": "batch or prefetch_related"  // only when present
            }
          ]
        }

    **Verbose** (``verbose=True`` / ``--verbose``) — full schema with all
    fields, pretty-printed, absolute paths.  Compatible with the original
    schema used by external tools and the SARIF reporter.
    """

    schema_version = "1"

    def __init__(
        self,
        stream: TextIO | None = None,
        indent: int | None = None,
        verbose: bool = False,
    ) -> None:
        self.stream = stream or sys.stdout
        self.verbose = verbose
        self.indent: int | None
        if indent is not None:
            self.indent = indent
        elif verbose or (hasattr(self.stream, "isatty") and self.stream.isatty()):
            self.indent = 2
        else:
            self.indent = None

    def report(self, findings: Iterable[Finding]) -> None:
        findings_list = list(findings)
        cwd = Path.cwd()

        if self.verbose:
            payload = {
                "schema": "https://pyperfguard.dev/schema/findings",
                "version": self.schema_version,
                "findings": [f.as_dict() for f in findings_list],
            }
        else:
            payload = {
                "findings": [f.as_compact_dict(cwd) for f in findings_list],
            }

        json.dump(payload, self.stream, indent=self.indent, default=str)
        self.stream.write("\n")
