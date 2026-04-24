from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    HINT = "hint"

    @property
    def sarif_level(self) -> str:
        # SARIF 2.1.0 valid values: none | note | warning | error
        return {
            Severity.ERROR: "error",
            Severity.WARNING: "warning",
            Severity.INFO: "note",
            Severity.HINT: "note",
        }[self]
